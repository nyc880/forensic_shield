package com.example.lock

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Environment
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.lock.crypto.EncryptionManager
import com.example.lock.crypto.SecureMetadataStripper
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

class ProcessingActivity : AppCompatActivity() {

    private lateinit var progressBar: ProgressBar
    private lateinit var statusText: TextView
    private lateinit var percentText: TextView
    private lateinit var stageText: TextView
    private lateinit var btnDone: MaterialButton

    private var currentMode: String = "ENCRYPT"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_processing)

        progressBar = findViewById(R.id.progressBar)
        statusText = findViewById(R.id.statusText)
        percentText = findViewById(R.id.percentText)
        stageText = findViewById(R.id.stageText)
        btnDone = findViewById(R.id.btnDone)

        currentMode = intent.getStringExtra("MODE") ?: "ENCRYPT"

        val files = intent.getStringArrayListExtra("FILES") ?: arrayListOf()
        val password = intent.getStringExtra("PASSWORD") ?: ""
        val secondZipPassword = intent.getStringExtra("SECOND_ZIP_PASSWORD") ?: ""
        val secondDecryptPassword = intent.getStringExtra("SECOND_DECRYPT_PASSWORD") ?: ""
        val encryptionType = intent.getStringExtra("ENC_TYPE") ?: "JUST_FILES"
        val deleteAfter = intent.getBooleanExtra("DELETE_AFTER", false)

        setInitialProcessingState()

        btnDone.setOnClickListener {
            val mainIntent = Intent(this, MainActivity::class.java)
            mainIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            startActivity(mainIntent)
            finish()
        }

        executeTask(
            mode = currentMode,
            filePaths = files,
            password = password,
            secondZipPassword = secondZipPassword,
            secondDecryptPassword = secondDecryptPassword,
            encType = encryptionType,
            deleteAfter = deleteAfter
        )
    }

    private fun setInitialProcessingState() {
        progressBar.visibility = View.VISIBLE
        progressBar.isIndeterminate = false
        progressBar.max = 100
        progressBar.progress = 0

        btnDone.visibility = View.GONE
        percentText.visibility = View.VISIBLE
        stageText.visibility = View.VISIBLE

        statusText.text = when (currentMode) {
            "ENCRYPT" -> "Encrypting......"
            "DECRYPT" -> "Decrypting......"
            "METADATA_PURGE" -> "Stripping Metadata..."
            else -> "Processing..."
        }

        statusText.setTextColor(Color.parseColor("#FF1744"))
        percentText.text = "0%"
        stageText.text = "Please wait"
    }

    private fun executeTask(
        mode: String,
        filePaths: ArrayList<String>,
        password: String,
        secondZipPassword: String,
        secondDecryptPassword: String,
        encType: String,
        deleteAfter: Boolean
    ) {
        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    updateStageOnMainThread("Please wait")

                    when (mode) {
                        "ENCRYPT" -> performEncryption(filePaths, password, secondZipPassword, encType, deleteAfter)
                        "DECRYPT" -> performDecryption(filePaths, password, secondDecryptPassword)
                        "METADATA_PURGE" -> performMetadataPurge(filePaths)
                        else -> false
                    }
                }

                if (result) {
                    showSuccess()
                } else {
                    showError("Operation failed.")
                }
            } catch (e: Exception) {
                showError(e.message ?: "An unexpected error occurred.")
            }
        }
    }

    private suspend fun updateStageOnMainThread(text: String) {
        withContext(Dispatchers.Main) {
            stageText.text = text
        }
    }

    private suspend fun updateProgressOnMainThread(percent: Int) {
        withContext(Dispatchers.Main) {
            progressBar.progress = percent.coerceIn(0, 100)
            percentText.text = "${percent.coerceIn(0, 100)}%"
        }
    }

    private fun performEncryption(
        filePaths: ArrayList<String>,
        password: String,
        secondZipPassword: String,
        encType: String,
        deleteAfter: Boolean
    ): Boolean {
        val files = filePaths.map { File(it) }.filter { it.exists() && it.isFile }
        if (files.isEmpty()) return false

        val mode = when (encType) {
            "JUST_FILES" -> EncryptionProcessor.MODE_JUST_FILES
            "JUST_ZIP" -> EncryptionProcessor.MODE_JUST_ZIP
            "ZIP_FILES" -> EncryptionProcessor.MODE_FILES_AND_ZIP

            "DOUBLE_ZIP_JUST_ZIP" -> EncryptionProcessor.MODE_JUST_ZIP
            "DOUBLE_ZIP_FILES_AND_ZIP" -> EncryptionProcessor.MODE_FILES_AND_ZIP

            "DOUBLE_ZIP" -> EncryptionProcessor.MODE_FILES_AND_ZIP

            else -> EncryptionProcessor.MODE_JUST_FILES
        }

        val doubleZip = encType == "DOUBLE_ZIP" ||
                encType == "DOUBLE_ZIP_JUST_ZIP" ||
                encType == "DOUBLE_ZIP_FILES_AND_ZIP"

        return try {
            val processor = EncryptionProcessor(this)

            processor.execute(
                files = files,
                password = password.toCharArray(),
                mode = mode,
                deleteAfterEncryption = deleteAfter,
                doubleZip = doubleZip,
                secondZipPassword = secondZipPassword.toCharArray(),
                onProgress = { snapshot, _ ->
                    lifecycleScope.launch {
                        updateProgressOnMainThread(snapshot.percent)
                    }
                }
            )

            true
        } catch (_: Exception) {
            false
        }
    }

    private fun performDecryption(
        filePaths: ArrayList<String>,
        password: String,
        secondDecryptPassword: String
    ): Boolean {
        val validFiles = filePaths.map { File(it) }.filter { it.exists() && it.isFile }
        if (validFiles.isEmpty()) return false

        val decDir = File(Environment.getExternalStorageDirectory(), "DEC")
        if (!decDir.exists()) {
            decDir.mkdirs()
        }

        val workDir = File(cacheDir, "decrypt_work_${System.currentTimeMillis()}")
        if (!workDir.exists()) {
            workDir.mkdirs()
        }

        var allSuccess = true
        var completedFiles = 0
        val totalFiles = validFiles.size

        try {
            for (inputFile in validFiles) {
                try {
                    lifecycleScope.launch {
                        updateStageOnMainThread("Decrypting ${inputFile.name}")
                    }

                    if (secondDecryptPassword.isNotBlank()) {
                        decryptDoubleLayerFlow(
                            inputFile = inputFile,
                            firstPassword = password,
                            secondPassword = secondDecryptPassword,
                            finalOutputDirectory = decDir,
                            workDirectory = workDir,
                            completedFiles = completedFiles,
                            totalFiles = totalFiles
                        )
                    } else {
                        decryptSingleFlow(
                            inputFile = inputFile,
                            password = password,
                            finalOutputDirectory = decDir,
                            workDirectory = workDir,
                            completedFiles = completedFiles,
                            totalFiles = totalFiles
                        )
                    }

                    completedFiles++

                    lifecycleScope.launch {
                        updateProgressOnMainThread(((completedFiles * 100) / totalFiles).coerceIn(0, 100))
                    }
                } catch (_: Exception) {
                    allSuccess = false
                }
            }
        } finally {
            deleteRecursivelySafe(workDir)
        }

        return allSuccess
    }

    private fun decryptSingleFlow(
        inputFile: File,
        password: String,
        finalOutputDirectory: File,
        workDirectory: File,
        completedFiles: Int,
        totalFiles: Int
    ) {
        val manager = EncryptionManager()

        val decryptedFile = manager.decryptFile(
            inputFile = inputFile,
            outputDirectory = workDirectory,
            password = password.toCharArray(),
            onProgress = { snapshot ->
                val base = (completedFiles * 100) / totalFiles
                val portion = snapshot.percent / totalFiles
                val overall = (base + portion).coerceIn(0, 100)

                lifecycleScope.launch {
                    updateProgressOnMainThread(overall)
                }
            }
        )

        handleDecryptedArtifact(
            artifact = decryptedFile,
            passwordForNestedEncryptedFiles = password,
            finalOutputDirectory = finalOutputDirectory,
            workDirectory = workDirectory,
            depth = 0
        )
    }

    private fun decryptDoubleLayerFlow(
        inputFile: File,
        firstPassword: String,
        secondPassword: String,
        finalOutputDirectory: File,
        workDirectory: File,
        completedFiles: Int,
        totalFiles: Int
    ) {
        val manager = EncryptionManager()

        val outerDecryptedFile = manager.decryptFile(
            inputFile = inputFile,
            outputDirectory = workDirectory,
            password = secondPassword.toCharArray(),
            onProgress = { snapshot ->
                val base = (completedFiles * 100) / totalFiles
                val portion = (snapshot.percent / 2) / totalFiles
                val overall = (base + portion).coerceIn(0, 100)

                lifecycleScope.launch {
                    updateProgressOnMainThread(overall)
                }
            }
        )

        handleDecryptedArtifact(
            artifact = outerDecryptedFile,
            passwordForNestedEncryptedFiles = firstPassword,
            finalOutputDirectory = finalOutputDirectory,
            workDirectory = workDirectory,
            depth = 0
        )
    }

    private fun handleDecryptedArtifact(
        artifact: File,
        passwordForNestedEncryptedFiles: String,
        finalOutputDirectory: File,
        workDirectory: File,
        depth: Int
    ) {
        if (depth > 8) {
            moveFileToDirectory(artifact, finalOutputDirectory)
            return
        }

        if (!artifact.exists()) return

        if (artifact.isDirectory) {
            val children = artifact.listFiles()?.toList().orEmpty()

            if (children.isEmpty()) {
                artifact.delete()
                return
            }

            for (child in children) {
                handleDecryptedArtifact(
                    artifact = child,
                    passwordForNestedEncryptedFiles = passwordForNestedEncryptedFiles,
                    finalOutputDirectory = finalOutputDirectory,
                    workDirectory = workDirectory,
                    depth = depth + 1
                )
            }

            artifact.delete()
            return
        }

        if (isZipFile(artifact)) {
            lifecycleScope.launch {
                updateStageOnMainThread("Auto extracting ${artifact.name}")
            }

            val extractDir = File(workDirectory, "extract_${System.nanoTime()}")
            extractDir.mkdirs()

            extractZip(
                zipFile = artifact,
                outputDirectory = extractDir
            )

            artifact.delete()

            val extractedFiles = extractDir.listFiles()?.toList().orEmpty()

            for (file in extractedFiles) {
                handleDecryptedArtifact(
                    artifact = file,
                    passwordForNestedEncryptedFiles = passwordForNestedEncryptedFiles,
                    finalOutputDirectory = finalOutputDirectory,
                    workDirectory = workDirectory,
                    depth = depth + 1
                )
            }

            extractDir.delete()
            return
        }

        if (isEncryptedFile(artifact)) {
            lifecycleScope.launch {
                updateStageOnMainThread("Decrypting inner layer")
            }

            val manager = EncryptionManager()

            val innerDecrypted = manager.decryptFile(
                inputFile = artifact,
                outputDirectory = workDirectory,
                password = passwordForNestedEncryptedFiles.toCharArray()
            )

            artifact.delete()

            handleDecryptedArtifact(
                artifact = innerDecrypted,
                passwordForNestedEncryptedFiles = passwordForNestedEncryptedFiles,
                finalOutputDirectory = finalOutputDirectory,
                workDirectory = workDirectory,
                depth = depth + 1
            )

            return
        }

        moveFileToDirectory(artifact, finalOutputDirectory)
    }

    private fun isEncryptedFile(file: File): Boolean {
        return file.isFile && file.extension.lowercase(Locale.getDefault()) == "enc"
    }

    private fun isZipFile(file: File): Boolean {
        if (!file.exists() || !file.isFile || file.length() < 4L) return false

        val lowerName = file.name.lowercase(Locale.getDefault())
        if (lowerName.endsWith(".zip")) return true

        return try {
            FileInputStream(file).use { input ->
                val signature = ByteArray(4)
                val read = input.read(signature)

                read == 4 &&
                        signature[0] == 0x50.toByte() &&
                        signature[1] == 0x4B.toByte() &&
                        (
                                signature[2] == 0x03.toByte() ||
                                        signature[2] == 0x05.toByte() ||
                                        signature[2] == 0x07.toByte()
                                ) &&
                        (
                                signature[3] == 0x04.toByte() ||
                                        signature[3] == 0x06.toByte() ||
                                        signature[3] == 0x08.toByte()
                                )
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun extractZip(
        zipFile: File,
        outputDirectory: File
    ) {
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs()
        }

        val canonicalOutputPath = outputDirectory.canonicalPath + File.separator

        ZipInputStream(FileInputStream(zipFile).buffered()).use { zipInput ->
            while (true) {
                val currentEntry: ZipEntry = zipInput.nextEntry ?: break

                val outFile = File(outputDirectory, currentEntry.name)
                val canonicalOutFilePath = outFile.canonicalPath

                if (!canonicalOutFilePath.startsWith(canonicalOutputPath)) {
                    zipInput.closeEntry()
                    continue
                }

                if (currentEntry.isDirectory) {
                    outFile.mkdirs()
                } else {
                    outFile.parentFile?.mkdirs()

                    val finalFile = createNonConflictingFile(
                        directory = outFile.parentFile ?: outputDirectory,
                        preferredName = outFile.name
                    )

                    FileOutputStream(finalFile).use { output ->
                        zipInput.copyTo(output)
                    }
                }

                zipInput.closeEntry()
            }
        }
    }

    private fun moveFileToDirectory(
        sourceFile: File,
        outputDirectory: File
    ): File {
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs()
        }

        val targetFile = createNonConflictingFile(
            directory = outputDirectory,
            preferredName = sourceFile.name
        )

        return try {
            if (sourceFile.renameTo(targetFile)) {
                targetFile
            } else {
                FileInputStream(sourceFile).use { input ->
                    FileOutputStream(targetFile).use { output ->
                        input.copyTo(output)
                    }
                }
                sourceFile.delete()
                targetFile
            }
        } catch (e: Exception) {
            targetFile.delete()
            throw e
        }
    }

    private fun createNonConflictingFile(
        directory: File,
        preferredName: String
    ): File {
        if (!directory.exists()) {
            directory.mkdirs()
        }

        val safeName = sanitizeFileName(preferredName)
        var candidate = File(directory, safeName)

        if (!candidate.exists()) {
            return candidate
        }

        val dotIndex = safeName.lastIndexOf('.')
        val baseName: String
        val extension: String

        if (dotIndex > 0) {
            baseName = safeName.substring(0, dotIndex)
            extension = safeName.substring(dotIndex)
        } else {
            baseName = safeName
            extension = ""
        }

        var counter = 1
        while (counter < 10_000) {
            candidate = File(directory, "$baseName ($counter)$extension")

            if (!candidate.exists()) {
                return candidate
            }

            counter++
        }

        return File(directory, "${System.currentTimeMillis()}_$safeName")
    }

    private fun sanitizeFileName(fileName: String): String {
        val safe = fileName
            .replace('\u0000', '_')
            .replace('/', '_')
            .replace('\\', '_')
            .trim()

        return if (safe.isBlank() || safe == "." || safe == "..") {
            "restored_${System.currentTimeMillis()}"
        } else {
            safe
        }
    }

    private fun deleteRecursivelySafe(targetFile: File): Boolean {
        return try {
            if (targetFile.isDirectory) {
                targetFile.listFiles()?.forEach { child ->
                    deleteRecursivelySafe(child)
                }
            }

            targetFile.delete()
        } catch (_: Exception) {
            false
        }
    }

    private fun showSuccess() {
        progressBar.visibility = View.GONE
        statusText.setTextColor(Color.parseColor("#00FF66"))

        statusText.text = when (currentMode) {
            "ENCRYPT" -> "Encryption Operation Completed Successfully"
            "DECRYPT" -> "Decryption Operation Completed Successfully"
            "METADATA_PURGE" -> "Metadata Stripped Successfully"
            else -> "Operation Completed"
        }

        percentText.text = "100%"

        stageText.text = when (currentMode) {
            "ENCRYPT" -> "Files saved inside the ENC"
            "METADATA_PURGE" -> "Files saved inside NO meta folder"
            else -> "Files saved inside the DEC"
        }

        btnDone.visibility = View.VISIBLE
        btnDone.text = "DONE"
    }

    private fun showError(msg: String) {
        progressBar.visibility = View.GONE
        statusText.setTextColor(Color.parseColor("#FF3D00"))
        statusText.text = "Error"
        stageText.text = msg
        btnDone.visibility = View.VISIBLE
        btnDone.text = "BACK"
    }

    private suspend fun performMetadataPurge(filePaths: ArrayList<String>): Boolean {
        var completed = 0
        val total = filePaths.size
        val root = android.os.Environment.getExternalStorageDirectory()
        val noMetaDir = java.io.File(root, "NO meta")

        if (!noMetaDir.exists()) {
            noMetaDir.mkdirs()
        }

        var allSuccess = true
        for (path in filePaths) {
            val inputFile = java.io.File(path)
            if (!inputFile.exists()) continue

            updateStageOnMainThread("Stripping: ${inputFile.name}")
            val outputFile = java.io.File(noMetaDir, "CLEAN_" + inputFile.name)

            try {
                val success = when {
                    path.lowercase().endsWith(".jpg") || path.lowercase().endsWith(".jpeg") || path.lowercase().endsWith(".png") -> {
                        SecureMetadataStripper.stripImage(java.io.FileInputStream(inputFile), java.io.FileOutputStream(outputFile))
                    }
                    path.lowercase().endsWith(".mp4") || path.lowercase().endsWith(".mp3") || path.lowercase().endsWith(".m4a") -> {
                        SecureMetadataStripper.stripMedia(inputFile.absolutePath, outputFile.absolutePath)
                    }
                    path.lowercase().endsWith(".pdf") -> {
                        SecureMetadataStripper.stripPdf(inputFile, java.io.FileOutputStream(outputFile))
                    }
                    else -> false
                }
                if (!success) allSuccess = false
            } catch (e: Exception) {
                allSuccess = false
            }

            completed++
            updateProgressOnMainThread((completed * 100) / total)
        }
        return allSuccess
    }

}