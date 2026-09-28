package com.example.lock

import android.content.Context
import android.os.Build
import android.os.Environment
import android.util.Log
import com.example.lock.crypto.EngineType
import com.example.lock.crypto.MaxEngineAdapter
import com.example.lock.crypto.lightEncryptionManager
import com.example.lock.crypto.Lock
import com.example.lock.safe_delete.PurgeOptions
import com.example.lock.safe_delete.SecureDelete
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.security.SecureRandom
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class EncryptionProcessor(private val context: Context) {

    companion object {
        const val MODE_JUST_FILES = 1
        const val MODE_JUST_ZIP = 2
        const val MODE_FILES_AND_ZIP = 3
        const val TARGET_FOLDER_NAME = "ENC"
        const val LOG_TAG = "LOCK_AUDIT"
        private const val BUFFER_SIZE = 65536
    }

    fun execute(
        files: List<File>,
        password: CharArray,
        mode: Int,
        engineType: EngineType = EngineType.MAX,
        secondEngineType: EngineType = EngineType.MAX,
        deleteAfterEncryption: Boolean,
        isDualPassword: Boolean = false,
        secondPassword: CharArray? = null,
        onProgress: ((Int, String) -> Unit)? = null
    ) {
        if (files.isEmpty()) throw IllegalArgumentException("No files provided")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                throw SecurityException("All Files Access permission required")
            }
        }
        val targetDir = File(Environment.getExternalStorageDirectory(), TARGET_FOLDER_NAME)
        if (!targetDir.exists() && !targetDir.mkdirs()) {
            throw IOException("Could not create $TARGET_FOLDER_NAME")
        }

        val validFiles = files.filter { it.exists() && it.isFile }
        if (validFiles.isEmpty()) {
            Log.e(LOG_TAG, "No existing files to encrypt. paths=${files.map { it.absolutePath }}")
            throw IOException("No valid files to encrypt (source path missing)")
        }

        var effectiveSecondEngine = secondEngineType
        if (isDualPassword && effectiveSecondEngine == engineType) {
            val values = EngineType.values()
            val idx = values.indexOf(engineType)
            effectiveSecondEngine = values[(idx + 1) % values.size]
            Log.d(LOG_TAG, "Dual engine auto-rotated: $engineType -> $effectiveSecondEngine")
        }

        Log.d(
            LOG_TAG,
            "execute start count=${validFiles.size} engine=$engineType secondEngine=$effectiveSecondEngine mode=$mode dual=$isDualPassword target=${targetDir.absolutePath}"
        )

        val isZipMode = mode == MODE_JUST_ZIP

        val totalBytes = validFiles.sumOf { it.length() }.coerceAtLeast(1L)
        var bytesDoneBefore = 0L

        if (!isZipMode) {
            for (file in validFiles) {
                var outFile: File? = null
                val fileBytes = file.length()
                val baseBytes = bytesDoneBefore
                val toGlobal: (Int) -> Int = { p ->
                    val processedBytes = (fileBytes * p.toLong()) / 100L
                    ((baseBytes + processedBytes) * 100L / totalBytes).toInt().coerceIn(0, 100)
                }
                try {
                    Log.d(LOG_TAG, "Encrypting ${file.absolutePath} size=${file.length()} engine=$engineType")
                    outFile = if (!isDualPassword) {
                        runSingleEncryption(file, targetDir, password, engineType) { p ->
                            onProgress?.invoke(toGlobal(p), "Encrypting ${file.name}... $p%")
                        }
                    } else {
                        val secondPass = if (secondPassword == null || secondPassword.isEmpty()) password else secondPassword
                        runDualEncryption(file, targetDir, password, secondPass, engineType, effectiveSecondEngine) { p ->
                            onProgress?.invoke(toGlobal(p), "Dual ${file.name}... $p%")
                        }
                    }
                    Log.d(LOG_TAG, "Encrypted output: ${outFile.absolutePath} size=${outFile.length()}")
                    bytesDoneBefore += fileBytes
                    onProgress?.invoke(toGlobal(100), "Completed ${file.name}")
                    if (deleteAfterEncryption) secureDelete(file)
                } catch (e: Exception) {
                    outFile?.let { if (it.exists()) secureDelete(it) }
                    throw e
                }
            }
        } else {
            val tempEncryptedFiles = ArrayList<File>()
            var tempZip: File? = null
            try {
                for (file in validFiles) {
                    Log.d(LOG_TAG, "ZIP-mode encrypting ${file.absolutePath} size=${file.length()} engine=$engineType")
                    val fileBytes = file.length()
                    val baseBytes = bytesDoneBefore
                    val toPhase: (Int) -> Int = { p ->
                        val processedBytes = (fileBytes * p.toLong()) / 100L
                        ((baseBytes + processedBytes) * 30L / totalBytes).toInt().coerceIn(0, 30)
                    }
                    val encFile = if (!isDualPassword) {
                        runSingleEncryption(file, context.cacheDir, password, engineType) { p ->
                            onProgress?.invoke(toPhase(p), "Encrypting ${file.name}... $p%")
                        }
                    } else {
                        val secondPass = if (secondPassword == null || secondPassword.isEmpty()) password else secondPassword
                        runDualEncryption(file, context.cacheDir, password, secondPass, engineType, effectiveSecondEngine) { p ->
                            onProgress?.invoke(toPhase(p), "Dual ${file.name}... $p%")
                        }
                    }
                    bytesDoneBefore += fileBytes
                    tempEncryptedFiles.add(encFile)
                }

                if (tempEncryptedFiles.isEmpty()) {
                    throw IOException("No encrypted files produced for ZIP mode")
                }

                onProgress?.invoke(40, "Creating ZIP of encrypted files...")
                tempZip = File(context.cacheDir, EngineType.randomName() + ".zip")
                createZip(tempEncryptedFiles, tempZip)

                onProgress?.invoke(70, "Encrypting ZIP to .zip.enc...")
                val finalZipEnc = if (!isDualPassword) {
                    runSingleEncryption(tempZip, targetDir, password, engineType) { p ->
                        onProgress?.invoke(70 + (p * 30 / 100), "Encrypting ZIP... $p%")
                    }
                } else {
                    val secondPass = if (secondPassword == null || secondPassword.isEmpty()) password else secondPassword
                    runDualEncryption(tempZip, targetDir, password, secondPass, engineType, effectiveSecondEngine) { p ->
                        onProgress?.invoke(70 + (p * 30 / 100), "Encrypting ZIP... $p%")
                    }
                }

                val finalWithZipExt = File(targetDir, finalZipEnc.nameWithoutExtension + ".zip.enc")
                if (!finalZipEnc.renameTo(finalWithZipExt)) {
                    finalZipEnc.copyTo(finalWithZipExt, overwrite = true)
                    secureDelete(finalZipEnc)
                }

                Log.d(LOG_TAG, "ZIP.ENC created: ${finalWithZipExt.absolutePath} size=${finalWithZipExt.length()}")
                onProgress?.invoke(100, "ZIP.ENC created: ${finalWithZipExt.name}")

                if (deleteAfterEncryption) {
                    secureDeleteAll(validFiles)
                }
            } finally {
                for (tmp in tempEncryptedFiles) secureDeleteTemp(tmp)
                tempZip?.let { secureDeleteTemp(it) }
            }
        }
    }

    private fun runSingleEncryption(
        inputFile: File,
        outputDir: File,
        password: CharArray,
        engineType: EngineType,
        onProgress: ((Int) -> Unit)? = null
    ): File {
        return when (engineType) {
            EngineType.MAX -> {
                val copy = password.copyOf()
                try {
                    val total = inputFile.length()
                    val out = MaxEngineAdapter.getInstance(context).encryptFile(
                        inputFile = inputFile,
                        outputDirectory = outputDir,
                        password = copy,
                        onProgress = { processed ->
                            if (total > 0L) {
                                onProgress?.invoke(
                                    ((processed * 100L) / total).toInt().coerceIn(0, 100)
                                )
                            }
                        }
                    )
                    onProgress?.invoke(100)
                    out
                } finally {
                    java.util.Arrays.fill(copy, '\u0000')
                }
            }
            EngineType.MEDIUM -> {
                val passBytes = password.concatToString().toByteArray(Charsets.UTF_8)
                val outFile = File(outputDir, EngineType.generateFileName(engineType))
                try {
                    Lock.encrypt(inputFile, outFile, passBytes)
                } finally {
                    java.util.Arrays.fill(passBytes, 0)
                }
                outFile
            }
            EngineType.EASY -> lightEncryptionManager().encryptFile(inputFile, outputDir, password.copyOf()) { snap: lightEncryptionManager.ProgressSnapshot ->
                onProgress?.invoke(snap.percent)
            }
        }
    }

    private fun runDualEncryption(
        inputFile: File,
        outputDir: File,
        firstPassword: CharArray,
        secondPassword: CharArray,
        engineType: EngineType,
        secondEngineType: EngineType,
        onProgress: ((Int) -> Unit)? = null
    ): File {
        val firstPassBytes = firstPassword.concatToString().toByteArray(Charsets.UTF_8)
        val secondPassBytes = secondPassword.concatToString().toByteArray(Charsets.UTF_8)
        var firstLayerFile: File? = null
        try {
            firstLayerFile = when (engineType) {
                EngineType.MAX -> {
                    val copy = firstPassword.copyOf()
                    try {
                        val total = inputFile.length()
                        val tmp = MaxEngineAdapter.getInstance(context).encryptFile(
                            inputFile = inputFile,
                            outputDirectory = context.cacheDir,
                            password = copy,
                            onProgress = { processed ->
                                if (total > 0L) {
                                    onProgress?.invoke(
                                        (((processed * 100L) / total) / 2L).toInt().coerceIn(0, 50)
                                    )
                                }
                            }
                        )
                        onProgress?.invoke(50)
                        tmp
                    } finally {
                        java.util.Arrays.fill(copy, '\u0000')
                    }
                }
                EngineType.MEDIUM -> {
                    val tmp = File(context.cacheDir, EngineType.generateFileName(engineType))
                    Lock.encrypt(inputFile, tmp, firstPassBytes)
                    tmp
                }
                EngineType.EASY -> lightEncryptionManager().encryptFile(inputFile, context.cacheDir, firstPassword.copyOf()) { snap: lightEncryptionManager.ProgressSnapshot ->
                    onProgress?.invoke(snap.percent / 2)
                }
            }

            val secondLayerFile = when (secondEngineType) {
                EngineType.MAX -> {
                    val copy = secondPassword.copyOf()
                    try {
                        val total = firstLayerFile.length()
                        val out = MaxEngineAdapter.getInstance(context).encryptFile(
                            inputFile = firstLayerFile,
                            outputDirectory = outputDir,
                            password = copy,
                            onProgress = { processed ->
                                if (total > 0L) {
                                    onProgress?.invoke(
                                        (50L + ((processed * 100L) / total) / 2L).toInt().coerceIn(0, 100)
                                    )
                                }
                            }
                        )
                        onProgress?.invoke(100)
                        out
                    } finally {
                        java.util.Arrays.fill(copy, '\u0000')
                    }
                }
                EngineType.MEDIUM -> {
                    val out = File(outputDir, EngineType.generateFileName(secondEngineType))
                    Lock.encrypt(firstLayerFile, out, secondPassBytes)
                    out
                }
                EngineType.EASY -> lightEncryptionManager().encryptFile(firstLayerFile, outputDir, secondPassword.copyOf()) { snap: lightEncryptionManager.ProgressSnapshot ->
                    onProgress?.invoke(50 + snap.percent / 2)
                }
            }
            return secondLayerFile
        } finally {
            firstLayerFile?.let { if (it.exists()) secureDeleteTemp(it) }
            java.util.Arrays.fill(firstPassBytes, 0)
            java.util.Arrays.fill(secondPassBytes, 0)
        }
    }

    private fun createZip(files: List<File>, zipFile: File) {
        if (zipFile.exists()) secureDeleteTemp(zipFile)
        ZipOutputStream(zipFile.outputStream().buffered(BUFFER_SIZE)).use { zipOut ->
            val buffer = ByteArray(BUFFER_SIZE)
            for (file in files) {
                if (file.exists() && file.isFile) {
                    val entry = ZipEntry(file.name)
                    zipOut.putNextEntry(entry)
                    file.inputStream().buffered(BUFFER_SIZE).use { input ->
                        var bytesRead: Int
                        while (input.read(buffer).also { bytesRead = it } != -1) {
                            zipOut.write(buffer, 0, bytesRead)
                        }
                    }
                    zipOut.closeEntry()
                }
            }
            zipOut.flush()
        }
    }

    private fun secureDelete(file: File) {
        secureDeleteAll(listOf(file))
    }

    private fun secureDeleteAll(files: List<File>) {
        val existing = files.filter { it.exists() }
        if (existing.isEmpty()) return
        try {
            val report = SecureDelete.purgeFiles(context, existing, PurgeOptions.MILITARY)
            Log.d(LOG_TAG, "secure purge: destroyed=${report.successCount}/${existing.size} bytes=${report.totalBytesShredded}")
            for (file in existing) {
                if (file.exists()) legacySecureDelete(file)
            }
        } catch (t: Throwable) {
            Log.w(LOG_TAG, "secure purge failed: ${t.javaClass.simpleName}; using fallback")
            for (file in existing) legacySecureDelete(file)
        }
    }

    private fun secureDeleteTemp(file: File) {
        if (!file.exists()) return
        try {
            SecureDelete.purgeFiles(
                context,
                listOf(file),
                PurgeOptions.MILITARY.copy(purgeThumbnails = false, scanTrashPaths = false)
            )
            if (file.exists()) legacySecureDelete(file)
        } catch (t: Throwable) {
            legacySecureDelete(file)
        }
    }

    private fun legacySecureDelete(file: File) {
        try {
            if (file.isFile) {
                val len = file.length()
                if (len > 0) {
                    RandomAccessFile(file, "rws").use { raf ->
                        val buffer = ByteArray(BUFFER_SIZE)
                        val rnd = SecureRandom()
                        var remaining = len
                        while (remaining > 0) {
                            rnd.nextBytes(buffer)
                            val toWrite = minOf(remaining, buffer.size.toLong()).toInt()
                            raf.write(buffer, 0, toWrite)
                            remaining -= toWrite
                        }
                    }
                }
                file.delete()
            }
        } catch (_: Exception) {
            file.delete()
        }
    }
}
