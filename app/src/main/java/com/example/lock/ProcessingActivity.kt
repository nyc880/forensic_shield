package com.example.lock

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Environment
import android.util.Log
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.lock.crypto.EncryptionManager
import com.example.lock.crypto.EngineType
import com.example.lock.crypto.LightEncryptionManager
import com.example.lock.crypto.Lock
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

class ProcessingActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "ProcessingActivity_DEBUG"
    }

    private lateinit var progressBar: ProgressBar
    private lateinit var statusText: TextView
    private lateinit var percentText: TextView
    private lateinit var stageText: TextView
    private lateinit var btnDone: MaterialButton
    private lateinit var btnCancel: MaterialButton

    private var currentMode: String = "ENCRYPT"
    private var taskJob: Job? = null
    @Volatile private var isCancelledFlag: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_processing)

        progressBar = bind("progressBar")
        statusText = bind("statusText")
        percentText = bind("percentText")
        stageText = bind("stageText")
        btnDone = bind("btnDone")
        btnCancel = bind("btnCancel")

        currentMode = intent.getStringExtra("MODE") ?: "ENCRYPT"
        Log.d(TAG, "onCreate initialized with mode: $currentMode")

        val files = intent.getStringArrayListExtra("FILES") ?: arrayListOf()
        val password = intent.getStringExtra("PASSWORD") ?: ""
        val secondPassword = intent.getStringExtra("SECOND_PASSWORD") ?: ""
        val secondDecryptPassword = intent.getStringExtra("SECOND_DECRYPT_PASSWORD") ?: ""
        val encryptionType = intent.getStringExtra("ENC_TYPE") ?: "JUST_FILES"
        val engineTypeStr = intent.getStringExtra("ENGINE_TYPE") ?: "MAX"
        val secondEngineTypeStr = intent.getStringExtra("SECOND_ENGINE_TYPE") ?: engineTypeStr
        val isDual = intent.getBooleanExtra("IS_DUAL_PASSWORD", false)
        val deleteAfter = intent.getBooleanExtra("DELETE_AFTER", false)

        Log.d(TAG, "Received file count: ${files.size}, isDual: $isDual, engineType: $engineTypeStr")

        setInitialProcessingState()

        btnCancel.setOnClickListener {
            isCancelledFlag = true
            taskJob?.cancel()
            showCancelled()
        }

        btnDone.setOnClickListener {
            if (currentMode == "DECRYPT" && btnDone.text.toString() == "BACK") {
                finish()
                return@setOnClickListener
            }
            val mainIntent = Intent(this, MainActivity::class.java)
            mainIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            startActivity(mainIntent)
            finish()
        }

        executeTask(
            mode = currentMode,
            filePaths = files,
            password = password,
            secondPassword = secondPassword,
            secondDecryptPassword = secondDecryptPassword,
            encType = encryptionType,
            engineTypeStr = engineTypeStr,
            secondEngineTypeStr = secondEngineTypeStr,
            isDual = isDual,
            deleteAfter = deleteAfter
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T : View> bind(name: String): T {
        val id = resources.getIdentifier(name, "id", packageName)
        check(id != 0) { "Missing layout id: $name in activity_processing.xml" }
        return findViewById(id) as T
    }

    private fun setInitialProcessingState() {
        progressBar.visibility = View.VISIBLE
        progressBar.isIndeterminate = false
        progressBar.max = 100
        progressBar.progress = 0
        btnCancel.visibility = View.VISIBLE
        btnDone.visibility = View.GONE
        percentText.visibility = View.VISIBLE
        stageText.visibility = View.VISIBLE
        statusText.text = when (currentMode) {
            "ENCRYPT" -> "Encrypting......"
            "DECRYPT" -> "Decrypting......"
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
        secondPassword: String,
        secondDecryptPassword: String,
        encType: String,
        engineTypeStr: String,
        secondEngineTypeStr: String,
        isDual: Boolean,
        deleteAfter: Boolean
    ) {
        Log.d(TAG, "executeTask started for mode: $mode")
        taskJob = lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    updateStageOnMainThread("Please wait")
                    if (isCancelledFlag) return@withContext false
                    when (mode) {
                        "ENCRYPT" -> performEncryption(filePaths, password, secondPassword, encType, engineTypeStr, secondEngineTypeStr, isDual, deleteAfter)
                        "DECRYPT" -> performDecryption(filePaths, password, secondDecryptPassword)
                        else -> {
                            Log.w(TAG, "Unknown mode encountered: $mode")
                            false
                        }
                    }
                }
                Log.d(TAG, "executeTask finished with result: $result")
                if (isCancelledFlag) {
                    showCancelled()
                } else if (result) {
                    val isEphemeral = intent.getBooleanExtra("IS_EPHEMERAL", false)
                    if (isEphemeral) finish() else showSuccess()
                } else {
                    showError("Operation failed.")
                }
            } catch (e: Exception) {
                Log.e(TAG, "executeTask exception caught: ${e.message}", e)
                if (e is CancellationException || isCancelledFlag) {
                    showCancelled()
                } else {
                    showError(e.message ?: "An unexpected error occurred.")
                }
            }
        }
    }

    private suspend fun updateStageOnMainThread(text: String) {
        withContext(Dispatchers.Main) { stageText.text = text }
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
        secondPassword: String,
        encType: String,
        engineTypeStr: String,
        secondEngineTypeStr: String,
        isDual: Boolean,
        deleteAfter: Boolean
    ): Boolean {
        Log.d(TAG, "performEncryption started")
        val files = filePaths.map { File(it) }.filter { it.exists() && it.isFile }
        if (files.isEmpty()) {
            Log.w(TAG, "performEncryption: No valid files found.")
            return false
        }

        val mode = when (encType) {
            "JUST_FILES" -> EncryptionProcessor.MODE_JUST_FILES
            "JUST_ZIP" -> EncryptionProcessor.MODE_JUST_ZIP
            "FILES_AND_ZIP" -> EncryptionProcessor.MODE_FILES_AND_ZIP
            else -> EncryptionProcessor.MODE_JUST_FILES
        }

        val engineType = EngineType.fromString(engineTypeStr)
        val secondEngineType = EngineType.fromString(secondEngineTypeStr)

        return try {
            val processor = EncryptionProcessor(this)
            processor.execute(
                files = files,
                password = password.toCharArray(),
                mode = mode,
                engineType = engineType,
                secondEngineType = secondEngineType,
                deleteAfterEncryption = deleteAfter,
                isDualPassword = isDual,
                secondPassword = if (secondPassword.isNotEmpty()) secondPassword.toCharArray() else null,
                onProgress = { percent, _ ->
                    if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                    lifecycleScope.launch { updateProgressOnMainThread(percent) }
                }
            )
            Log.d(TAG, "performEncryption completed successfully.")
            true
        } catch (e: Exception) {
            if (e is CancellationException || isCancelledFlag) throw e
            Log.e(TAG, "Encryption error: ${e.message}", e)
            throw Exception("Encryption failed: ${e.message}", e)
        }
    }

    private fun performDecryption(
        filePaths: ArrayList<String>,
        password: String,
        secondDecryptPassword: String
    ): Boolean {
        Log.d(TAG, "performDecryption started with ${filePaths.size} paths")
        val validFiles = filePaths.map { File(it) }.filter { it.exists() && it.isFile }
        if (validFiles.isEmpty()) {
            Log.e(TAG, "performDecryption: No valid files found for decryption.")
            throw Exception("No valid files found for decryption.")
        }

        val isEphemeral = intent.getBooleanExtra("IS_EPHEMERAL", false)
        val decDir = if (isEphemeral) cacheDir else File(Environment.getExternalStorageDirectory(), "DEC")
        if (!decDir.exists()) decDir.mkdirs()

        val workDir = File(cacheDir, "decrypt_work_${System.currentTimeMillis()}")
        if (!workDir.exists()) workDir.mkdirs()

        var allSuccess = true
        var completedFiles = 0
        val totalFiles = validFiles.size

        try {
            for (inputFile in validFiles) {
                if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")

                try {
                    Log.d(TAG, "Processing file for decryption: ${inputFile.absolutePath}, size: ${inputFile.length()}")
                    lifecycleScope.launch { updateStageOnMainThread("Decrypting ${inputFile.name}") }

                    if (secondDecryptPassword.isNotBlank()) {
                        Log.d(TAG, "Routing to decryptDualLayerFlow")
                        decryptDualLayerFlow(
                            inputFile = inputFile,
                            firstPassword = password,
                            secondPassword = secondDecryptPassword,
                            finalOutputDirectory = decDir,
                            workDirectory = workDir,
                            completedFiles = completedFiles,
                            totalFiles = totalFiles
                        )
                    } else {
                        Log.d(TAG, "Routing to decryptSingleFlow")
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
                    lifecycleScope.launch { updateProgressOnMainThread(((completedFiles * 100) / totalFiles).coerceIn(0, 100)) }
                } catch (e: Exception) {
                    if (e is CancellationException || isCancelledFlag) throw e
                    allSuccess = false
                    Log.e(TAG, "Failed to decrypt file ${inputFile.name}: ${e.message}", e)
                    throw Exception("Failed to decrypt ${inputFile.name}: ${e.message}", e)
                }
            }
        } finally {
            deleteRecursivelySafe(workDir)
            Log.d(TAG, "Work directory cleaned up.")
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
        if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
        val engineType = EngineType.detectFromFile(inputFile) ?: EngineType.MAX
        Log.d(TAG, "decryptSingleFlow detected EngineType: $engineType for file: ${inputFile.name}")

        val decryptedFile: File = when (engineType) {
            EngineType.MAX -> {
                Log.d(TAG, "Using MAX engine for decryption")
                EncryptionManager().decryptFile(
                    inputFile = inputFile,
                    outputDirectory = workDirectory,
                    password = password.toCharArray(),
                    onProgress = { snap: EncryptionManager.ProgressSnapshot ->
                        if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                        val base = (completedFiles * 100) / totalFiles
                        val portion = snap.percent / totalFiles
                        lifecycleScope.launch { updateProgressOnMainThread((base + portion).coerceIn(0, 100)) }
                    }
                )
            }
            EngineType.MEDIUM -> {
                Log.d(TAG, "Using MEDIUM engine for decryption")
                if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                decryptWithLockSingle(inputFile, workDirectory, password)
            }
            EngineType.EASY -> {
                Log.d(TAG, "Using EASY (LightEncryptionManager) engine for decryption")
                try {
                    LightEncryptionManager().decryptFile(
                        inputFile = inputFile,
                        outputDirectory = workDirectory,
                        password = password.toCharArray(),
                        isCancelled = { isCancelledFlag },
                        onProgress = { snap: LightEncryptionManager.ProgressSnapshot ->
                            val base = (completedFiles * 100) / totalFiles
                            val portion = snap.percent / totalFiles
                            lifecycleScope.launch { updateProgressOnMainThread((base + portion).coerceIn(0, 100)) }
                        }
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "LightEncryptionManager decryption threw exception: ${e.message}", e)
                    throw e
                }
            }
        }

        Log.d(TAG, "decryptSingleFlow finished. Artifact produced: ${decryptedFile.absolutePath}")
        handleDecryptedArtifact(decryptedFile, password, finalOutputDirectory, workDirectory, 0)
    }

    private fun decryptDualLayerFlow(
        inputFile: File,
        firstPassword: String,
        secondPassword: String,
        finalOutputDirectory: File,
        workDirectory: File,
        completedFiles: Int,
        totalFiles: Int
    ) {
        if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
        val outerEngineType = EngineType.detectFromFile(inputFile) ?: EngineType.MAX
        Log.d(TAG, "decryptDualLayerFlow detected outer EngineType: $outerEngineType for file: ${inputFile.name}")

        val outerDecryptedFile: File = when (outerEngineType) {
            EngineType.MAX -> {
                EncryptionManager().decryptFile(
                    inputFile = inputFile,
                    outputDirectory = workDirectory,
                    password = secondPassword.toCharArray(),
                    onProgress = { snap: EncryptionManager.ProgressSnapshot ->
                        if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                        val base = (completedFiles * 100) / totalFiles
                        val portion = (snap.percent / 2) / totalFiles
                        lifecycleScope.launch { updateProgressOnMainThread((base + portion).coerceIn(0, 100)) }
                    }
                )
            }
            EngineType.MEDIUM -> {
                if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                decryptWithLockDualOuter(inputFile, workDirectory, firstPassword, secondPassword)
            }
            EngineType.EASY -> {
                LightEncryptionManager().decryptFile(
                    inputFile = inputFile,
                    outputDirectory = workDirectory,
                    password = secondPassword.toCharArray(),
                    isCancelled = { isCancelledFlag },
                    onProgress = { snap: LightEncryptionManager.ProgressSnapshot ->
                        val base = (completedFiles * 100) / totalFiles
                        val portion = (snap.percent / 2) / totalFiles
                        lifecycleScope.launch { updateProgressOnMainThread((base + portion).coerceIn(0, 100)) }
                    }
                )
            }
        }

        handleDecryptedArtifact(outerDecryptedFile, firstPassword, finalOutputDirectory, workDirectory, 0)
    }

    private fun decryptWithLockSingle(inputFile: File, workDir: File, password: String): File {
        val passBytes = password.toByteArray(Charsets.UTF_8)
        val tmpOut = File(workDir, "lock_dec_${System.nanoTime()}.tmp")
        try {
            Lock.decrypt(inputFile, tmpOut, passBytes)
            val originalName = try {
                Lock.peekOriginalName(inputFile, passBytes)
            } catch (_: Exception) { null }
            val finalName = if (!originalName.isNullOrBlank()) originalName else inputFile.nameWithoutExtension
            val result = createNonConflictingFile(workDir, finalName)
            if (!tmpOut.renameTo(result)) {
                FileInputStream(tmpOut).use { i -> FileOutputStream(result).use { o -> i.copyTo(o) } }
                tmpOut.delete()
            }
            return result
        } finally {
            tmpOut.delete()
            java.util.Arrays.fill(passBytes, 0)
            Lock.wipe(passBytes)
        }
    }

    private fun decryptWithLockDualOuter(
        inputFile: File,
        workDir: File,
        firstPassword: String,
        secondPassword: String
    ): File {
        val pass1 = firstPassword.toByteArray(Charsets.UTF_8)
        val pass2 = secondPassword.toByteArray(Charsets.UTF_8)
        val tmpOut = File(workDir, "lock_dual_${System.nanoTime()}.tmp")
        try {
            Lock.decrypt(inputFile, tmpOut, pass1, pass2)
            val originalName = try {
                Lock.peekOriginalName(inputFile, pass1)
            } catch (_: Exception) { null }
            val finalName = if (!originalName.isNullOrBlank()) originalName else tmpOut.name
            val result = createNonConflictingFile(workDir, finalName)
            if (!tmpOut.renameTo(result)) {
                FileInputStream(tmpOut).use { i -> FileOutputStream(result).use { o -> i.copyTo(o) } }
                tmpOut.delete()
            }
            return result
        } finally {
            tmpOut.delete()
            java.util.Arrays.fill(pass1, 0)
            java.util.Arrays.fill(pass2, 0)
            Lock.wipe(pass1)
            Lock.wipe(pass2)
        }
    }

    private fun handleDecryptedArtifact(
        artifact: File,
        passwordForNestedEncryptedFiles: String,
        finalOutputDirectory: File,
        workDirectory: File,
        depth: Int
    ) {
        if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
        Log.d(TAG, "handleDecryptedArtifact at depth $depth for artifact: ${artifact.absolutePath}, isDirectory: ${artifact.isDirectory}")
        if (depth > 8) {
            Log.w(TAG, "Max depth exceeded in handleDecryptedArtifact. Moving as-is.")
            val savedFile = moveFileToDirectory(artifact, finalOutputDirectory)
            if (intent.getBooleanExtra("IS_EPHEMERAL", false)) {
                lifecycleScope.launch(Dispatchers.Main) { openEphemeralFile(savedFile) }
            }
            return
        }
        if (!artifact.exists()) {
            Log.w(TAG, "handleDecryptedArtifact: artifact does not exist.")
            return
        }

        if (artifact.isDirectory) {
            val children = artifact.listFiles()?.toList().orEmpty()
            if (children.isEmpty()) { artifact.delete(); return }
            for (child in children) {
                if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                handleDecryptedArtifact(child, passwordForNestedEncryptedFiles, finalOutputDirectory, workDirectory, depth + 1)
            }
            artifact.delete()
            return
        }

        if (isZipFile(artifact)) {
            Log.d(TAG, "Artifact is a ZIP file, extracting...")
            lifecycleScope.launch { updateStageOnMainThread("Auto extracting ${artifact.name}") }
            val extractDir = File(workDirectory, "extract_${System.nanoTime()}")
            extractDir.mkdirs()
            extractZip(artifact, extractDir)
            artifact.delete()
            val extractedFiles = extractDir.listFiles()?.toList().orEmpty()
            for (file in extractedFiles) {
                if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                handleDecryptedArtifact(file, passwordForNestedEncryptedFiles, finalOutputDirectory, workDirectory, depth + 1)
            }
            extractDir.delete()
            return
        }

        if (isEncryptedFile(artifact)) {
            Log.d(TAG, "Artifact is a nested encrypted file, decrypting inner layer...")
            lifecycleScope.launch { updateStageOnMainThread("Decrypting inner layer") }
            val innerEngineType = EngineType.detectFromFile(artifact) ?: EngineType.MAX
            val innerDecrypted: File = when (innerEngineType) {
                EngineType.MAX -> EncryptionManager().decryptFile(artifact, workDirectory, passwordForNestedEncryptedFiles.toCharArray())
                EngineType.MEDIUM -> decryptWithLockSingle(artifact, workDirectory, passwordForNestedEncryptedFiles)
                EngineType.EASY -> LightEncryptionManager().decryptFile(artifact, workDirectory, passwordForNestedEncryptedFiles.toCharArray(), isCancelled = { isCancelledFlag })
            }
            artifact.delete()
            handleDecryptedArtifact(innerDecrypted, passwordForNestedEncryptedFiles, finalOutputDirectory, workDirectory, depth + 1)
            return
        }

        val savedFile = moveFileToDirectory(artifact, finalOutputDirectory)
        Log.d(TAG, "Final artifact saved to: ${savedFile.absolutePath}")
        if (intent.getBooleanExtra("IS_EPHEMERAL", false)) {
            lifecycleScope.launch(Dispatchers.Main) { openEphemeralFile(savedFile) }
        }
    }

    private fun isEncryptedFile(file: File): Boolean {
        return EngineType.detectFromFile(file) != null
    }

    private fun isZipFile(file: File): Boolean {
        if (!file.exists() || !file.isFile || file.length() < 4L) return false
        val lowerName = file.name.lowercase(Locale.getDefault())
        if (lowerName.endsWith(".zip")) return true
        return try {
            FileInputStream(file).use { input ->
                val sig = ByteArray(4)
                val read = input.read(sig)
                read == 4 && sig[0] == 0x50.toByte() && sig[1] == 0x4B.toByte()
            }
        } catch (_: Exception) { false }
    }

    private fun extractZip(zipFile: File, outputDirectory: File) {
        if (!outputDirectory.exists()) outputDirectory.mkdirs()
        val canonicalOutputPath = outputDirectory.canonicalPath + File.separator
        ZipInputStream(FileInputStream(zipFile).buffered()).use { zipInput ->
            while (true) {
                if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                val entry: ZipEntry = zipInput.nextEntry ?: break
                val outFile = File(outputDirectory, entry.name)
                if (!outFile.canonicalPath.startsWith(canonicalOutputPath)) { zipInput.closeEntry(); continue }
                if (entry.isDirectory) outFile.mkdirs()
                else {
                    outFile.parentFile?.mkdirs()
                    val finalFile = createNonConflictingFile(outFile.parentFile ?: outputDirectory, outFile.name)
                    FileOutputStream(finalFile).use { output -> zipInput.copyTo(output) }
                }
                zipInput.closeEntry()
            }
        }
    }

    private fun moveFileToDirectory(sourceFile: File, outputDirectory: File): File {
        if (!outputDirectory.exists()) outputDirectory.mkdirs()
        val targetFile = createNonConflictingFile(outputDirectory, sourceFile.name)
        return try {
            if (sourceFile.renameTo(targetFile)) targetFile
            else {
                FileInputStream(sourceFile).use { input ->
                    FileOutputStream(targetFile).use { output -> input.copyTo(output) }
                }
                sourceFile.delete()
                targetFile
            }
        } catch (e: Exception) { targetFile.delete(); throw e }
    }

    private fun createNonConflictingFile(directory: File, preferredName: String): File {
        if (!directory.exists()) directory.mkdirs()
        val safeName = preferredName.replace('\u0000', '_').replace('/', '_').replace('\\', '_').trim()
        var candidate = File(directory, safeName)
        if (!candidate.exists()) return candidate
        val dotIndex = safeName.lastIndexOf('.')
        val baseName = if (dotIndex > 0) safeName.substring(0, dotIndex) else safeName
        val ext = if (dotIndex > 0) safeName.substring(dotIndex) else ""
        var counter = 1
        while (counter < 10000) {
            candidate = File(directory, "$baseName ($counter)$ext")
            if (!candidate.exists()) return candidate
            counter++
        }
        return File(directory, "${System.currentTimeMillis()}_$safeName")
    }

    private fun deleteRecursivelySafe(targetFile: File): Boolean {
        return try {
            if (targetFile.isDirectory) targetFile.listFiles()?.forEach { deleteRecursivelySafe(it) }
            targetFile.delete()
        } catch (_: Exception) { false }
    }

    private fun showSuccess() {
        progressBar.visibility = View.GONE
        btnCancel.visibility = View.GONE
        statusText.setTextColor(Color.parseColor("#00FF66"))
        statusText.text = if (currentMode == "ENCRYPT") "Encryption Completed Successfully" else "Decryption Completed Successfully"
        percentText.text = "100%"
        stageText.text = if (currentMode == "ENCRYPT") "Files saved inside the ENC" else "Files saved inside the DEC"
        btnDone.visibility = View.VISIBLE
        btnDone.text = "DONE"
    }

    private fun showError(msg: String) {
        progressBar.visibility = View.GONE
        btnCancel.visibility = View.GONE
        statusText.setTextColor(Color.parseColor("#FF3D00"))
        statusText.text = "Error"
        stageText.text = msg
        btnDone.visibility = View.VISIBLE
        btnDone.text = "BACK"
    }

    private fun showCancelled() {
        progressBar.visibility = View.GONE
        btnCancel.visibility = View.GONE
        statusText.setTextColor(Color.parseColor("#FF3D00"))
        statusText.text = "Cancelled"
        stageText.text = "Operation was cancelled by user."
        percentText.visibility = View.GONE
        btnDone.visibility = View.VISIBLE
        btnDone.text = "BACK"
    }

    private fun openEphemeralFile(file: File) {
        try {
            val intent = Intent(this, FilePreviewActivity::class.java).apply {
                putExtra("file_path", file.absolutePath)
                putExtra("crypto_mode", "VIEW_ONLY")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error launching preview: ${e.message}", e)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isCancelledFlag = true
        taskJob?.cancel()
    }
}
