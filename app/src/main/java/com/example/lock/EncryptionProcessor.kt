package com.example.lock

import android.content.Context
import android.os.Build
import android.os.Environment
import android.util.Log
import com.example.lock.crypto.EncryptionManager
import com.example.lock.crypto.EngineType
import com.example.lock.crypto.LightEncryptionManager
import com.example.lock.crypto.Lock
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
        if (validFiles.isEmpty()) return

        val isZipMode = mode == MODE_JUST_ZIP

        if (!isZipMode) {
            for ((index, file) in validFiles.withIndex()) {
                var outFile: File? = null
                try {
                    outFile = if (!isDualPassword) {
                        runSingleEncryption(file, targetDir, password, engineType) { p ->
                            val base = (index * 100) / validFiles.size
                            val portion = p / validFiles.size
                            onProgress?.invoke((base + portion).coerceIn(0, 100), "Encrypting ${file.name}... $p%")
                        }
                    } else {
                        val secondPass = if (secondPassword == null || secondPassword.isEmpty()) password else secondPassword
                        runDualEncryption(file, targetDir, password, secondPass, engineType, secondEngineType) { p ->
                            val base = (index * 100) / validFiles.size
                            val portion = p / validFiles.size
                            onProgress?.invoke((base + portion).coerceIn(0, 100), "Dual ${file.name}... $p%")
                        }
                    }
                    onProgress?.invoke(((index + 1) * 100 / validFiles.size).coerceIn(0, 100), "Completed ${file.name}")
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
                for ((index, file) in validFiles.withIndex()) {
                    val encFile = if (!isDualPassword) {
                        runSingleEncryption(file, context.cacheDir, password, engineType) { p ->
                            val phase = (index * 30) / validFiles.size + (p / (3 * validFiles.size))
                            onProgress?.invoke(phase.coerceIn(0, 100), "Encrypting ${file.name}... $p%")
                        }
                    } else {
                        val secondPass = if (secondPassword == null || secondPassword.isEmpty()) password else secondPassword
                        runDualEncryption(file, context.cacheDir, password, secondPass, engineType, secondEngineType) { p ->
                            val phase = (index * 30) / validFiles.size + (p / (3 * validFiles.size))
                            onProgress?.invoke(phase.coerceIn(0, 100), "Dual ${file.name}... $p%")
                        }
                    }
                    tempEncryptedFiles.add(encFile)
                }

                if (tempEncryptedFiles.isEmpty()) return

                onProgress?.invoke(40, "Creating ZIP of encrypted files...")
                tempZip = File(context.cacheDir, EngineType.randomName() + ".zip")
                createZip(tempEncryptedFiles, tempZip)

                onProgress?.invoke(70, "Encrypting ZIP to .zip.enc...")
                val finalZipEnc = runSingleEncryption(tempZip, targetDir, password, engineType) { p ->
                    onProgress?.invoke(70 + (p * 30 / 100), "Encrypting ZIP... $p%")
                }

                val finalWithZipExt = File(targetDir, finalZipEnc.nameWithoutExtension + ".zip.enc")
                if (!finalZipEnc.renameTo(finalWithZipExt)) {
                    finalZipEnc.copyTo(finalWithZipExt, overwrite = true)
                    finalZipEnc.delete()
                }

                onProgress?.invoke(100, "ZIP.ENC created: ${finalWithZipExt.name}")

                if (deleteAfterEncryption) {
                    for (f in validFiles) secureDelete(f)
                }
            } finally {
                for (tmp in tempEncryptedFiles) secureDelete(tmp)
                tempZip?.let { secureDelete(it) }
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
            EngineType.MAX -> EncryptionManager().encryptFile(inputFile, outputDir, password.copyOf()) { snap: EncryptionManager.ProgressSnapshot ->
                onProgress?.invoke(snap.percent)
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
            EngineType.EASY -> LightEncryptionManager().encryptFile(inputFile, outputDir, password.copyOf()) { snap: LightEncryptionManager.ProgressSnapshot ->
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
                EngineType.MAX -> EncryptionManager().encryptFile(inputFile, context.cacheDir, firstPassword.copyOf()) { snap: EncryptionManager.ProgressSnapshot ->
                    onProgress?.invoke(snap.percent / 2)
                }
                EngineType.MEDIUM -> {
                    val tmp = File(context.cacheDir, EngineType.generateFileName(engineType))
                    Lock.encrypt(inputFile, tmp, firstPassBytes)
                    tmp
                }
                EngineType.EASY -> LightEncryptionManager().encryptFile(inputFile, context.cacheDir, firstPassword.copyOf()) { snap: LightEncryptionManager.ProgressSnapshot ->
                    onProgress?.invoke(snap.percent / 2)
                }
            }

            val secondLayerFile = when (secondEngineType) {
                EngineType.MAX -> EncryptionManager().encryptFile(firstLayerFile, outputDir, secondPassword.copyOf()) { snap: EncryptionManager.ProgressSnapshot ->
                    onProgress?.invoke(50 + snap.percent / 2)
                }
                EngineType.MEDIUM -> {
                    val out = File(outputDir, EngineType.generateFileName(secondEngineType))
                    Lock.encrypt(firstLayerFile, out, secondPassBytes)
                    out
                }
                EngineType.EASY -> LightEncryptionManager().encryptFile(firstLayerFile, outputDir, secondPassword.copyOf()) { snap: LightEncryptionManager.ProgressSnapshot ->
                    onProgress?.invoke(50 + snap.percent / 2)
                }
            }
            return secondLayerFile
        } finally {
            firstLayerFile?.let { if (it.exists()) secureDelete(it) }
            java.util.Arrays.fill(firstPassBytes, 0)
            java.util.Arrays.fill(secondPassBytes, 0)
        }
    }

    private fun createZip(files: List<File>, zipFile: File) {
        if (zipFile.exists()) secureDelete(zipFile)
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
        if (!file.exists()) return
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
