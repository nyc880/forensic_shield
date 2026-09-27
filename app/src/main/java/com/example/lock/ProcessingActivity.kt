package com.example.lock

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Paint
import android.media.MediaScannerConnection
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.util.Log
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.lock.crypto.EngineType
import com.example.lock.crypto.LightEncryptionManager
import com.example.lock.crypto.Lock
import com.example.lock.crypto.MaxEngineAdapter
import com.example.lock.file_manager.FilePreviewActivity
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collect
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
        private const val METADATA_TAG = "MetadataPurge_DEBUG"
        private val outputNameRandom = java.security.SecureRandom()
    }

    private lateinit var progressBar: ProgressBar
    private lateinit var statusText: TextView
    private lateinit var percentText: TextView
    private lateinit var stageText: TextView
    private lateinit var btnDone: MaterialButton
    private lateinit var btnCancel: MaterialButton

    private var currentMode: String = "ENCRYPT"
    private var taskJob: Job? = null
    private var safeDeleteRequested: Boolean = false
    private val metadataReportItems = arrayListOf<String>()
    private var metadataSelectedCount = 0
    private var metadataVerifiedCount = 0
    private var metadataAlreadyCleanCount = 0
    private var metadataPartialCount = 0
    private var metadataRefusedCount = 0
    private var metadataFailedCount = 0

    private var isCancelledFlag: Boolean
        get() = CryptoWorkState.isCancelled
        set(value) { if (value) CryptoWorkState.requestCancel() }

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
        safeDeleteRequested = intent.getBooleanExtra("SAFE_DELETE_ORIGINAL", false)

        Log.d(TAG, "Received file count: ${files.size}, isDual: $isDual, engineType: $engineTypeStr")
        Log.d(METADATA_TAG, "safeDeleteRequested=$safeDeleteRequested")

        setInitialProcessingState()
        requestNotificationPermissionIfNeeded()

        btnCancel.setOnClickListener {
            CryptoWorkState.requestCancel()
            showCancelled()
        }

        btnDone.setOnClickListener {
            if ((currentMode == "DECRYPT" || currentMode == "METADATA_PURGE") && btnDone.text.toString() == "BACK") {
                finish()
                return@setOnClickListener
            }
            val mainIntent = Intent(this, MainActivity::class.java)
            mainIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            startActivity(mainIntent)
            finish()
        }

        if (CryptoWorkState.status.value == CryptoWorkState.Status.RUNNING) {
            observeRunningWork()
            return
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
            "METADATA_PURGE" -> "Purging Metadata..."
            else -> "Processing..."
        }
        statusText.setTextColor(Color.parseColor("#FF1744"))
        percentText.text = "0%"
        stageText.text = "Please wait"
    }

    @SuppressLint("NewApi")
    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
        if (granted) return
        requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 9001)
    }

    private fun observeRunningWork() {
        lifecycleScope.launch {
            CryptoWorkState.progress.collect { percent ->
                if (isFinishing || isDestroyed) return@collect
                progressBar.progress = percent.coerceIn(0, 100)
                percentText.text = "${percent.coerceIn(0, 100)}%"
            }
        }
        lifecycleScope.launch {
            CryptoWorkState.status.collect { status ->
                if (isFinishing || isDestroyed) return@collect
                when (status) {
                    CryptoWorkState.Status.SUCCEEDED -> showSuccess()
                    CryptoWorkState.Status.FAILED -> showError(CryptoWorkState.message.value)
                    CryptoWorkState.Status.CANCELLED -> showCancelled()
                    CryptoWorkState.Status.RUNNING,
                    CryptoWorkState.Status.IDLE -> Unit
                }
            }
        }
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
        if (mode == "METADATA_PURGE") resetMetadataReport()
        CryptoWorkState.start()
        startService(Intent(this, CryptoForegroundService::class.java))
        taskJob = CryptoWorkState.launchWork {
            try {
                val result = withContext(Dispatchers.IO) {
                    updateStageOnMainThread("Please wait")
                    if (isCancelledFlag) return@withContext false
                    when (mode) {
                        "ENCRYPT" -> performEncryption(filePaths, password, secondPassword, encType, engineTypeStr, secondEngineTypeStr, isDual, deleteAfter)
                        "DECRYPT" -> performDecryption(filePaths, password, secondDecryptPassword)
                        "METADATA_PURGE" -> performMetadataPurge(filePaths)
                        else -> {
                            Log.w(TAG, "Unknown mode encountered: $mode")
                            false
                        }
                    }
                }
                Log.d(TAG, "executeTask finished with result: $result")
                if (isCancelledFlag) {
                    CryptoWorkState.markCancelled()
                } else if (result) {
                    CryptoWorkState.succeed()
                } else {
                    CryptoWorkState.fail("Operation failed.")
                }
                val isEphemeral = intent.getBooleanExtra("IS_EPHEMERAL", false)
                runOnUiThread {
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    if (isCancelledFlag) {
                        showCancelled()
                    } else if (result) {
                        if (isEphemeral) finish() else showSuccess()
                    } else {
                        showError("Operation failed.")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "executeTask exception caught: ${e.message}", e)
                val wasCancelled = e is CancellationException || isCancelledFlag
                val message = e.message ?: "An unexpected error occurred."
                if (wasCancelled) CryptoWorkState.markCancelled() else CryptoWorkState.fail(message)
                runOnUiThread {
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    if (wasCancelled) showCancelled() else showError(message)
                }
            } finally {
                stopService(Intent(this@ProcessingActivity, CryptoForegroundService::class.java))
            }
        }
    }

    private fun updateStageOnMainThread(text: String) {
        CryptoWorkState.setStage(text)
        runOnUiThread {
            if (isFinishing || isDestroyed) return@runOnUiThread
            stageText.text = text
        }
    }

    private fun updateProgressOnMainThread(percent: Int) {
        val clamped = percent.coerceIn(0, 100)
        CryptoWorkState.setProgress(clamped)
        runOnUiThread {
            if (isFinishing || isDestroyed) return@runOnUiThread
            progressBar.progress = clamped
            percentText.text = "$clamped%"
        }
    }

    private fun performMetadataPurge(filePaths: ArrayList<String>): Boolean {
        Log.d(METADATA_TAG, "metadata operation started")
        Log.d(
            METADATA_TAG,
            "engine=com.example.lock.metadata.MetadataPurgeProcessor " +
                    "version=${com.example.lock.metadata.MetadataPurgeProcessor.version}"
        )
        Log.d(METADATA_TAG, "requested file count=${filePaths.size}")
        Log.d(METADATA_TAG, "output directory=${metadataOutputDirectory().absolutePath}")
        Log.d(METADATA_TAG, "safeDeleteRequested=$safeDeleteRequested")

        val files = filePaths
            .map { File(it) }
            .filter { it.exists() && it.isFile }

        metadataSelectedCount = files.size
        if (files.isEmpty()) {
            Log.e(METADATA_TAG, "no valid files found")
            return false
        }

        val outputDirectory = metadataOutputDirectory()
        if (!outputDirectory.exists() && !outputDirectory.mkdirs()) {
            Log.e(METADATA_TAG, "could not create output directory=${outputDirectory.absolutePath}")
            files.forEach { metadataReportItems.add(buildFailureReportItem(it, "Output directory could not be created")) }
            metadataFailedCount = files.size
            return false
        }
        if (!outputDirectory.isDirectory || !outputDirectory.canWrite()) {
            Log.e(METADATA_TAG, "output directory is not writable=${outputDirectory.absolutePath}")
            files.forEach { metadataReportItems.add(buildFailureReportItem(it, "Output directory is not writable")) }
            metadataFailedCount = files.size
            return false
        }

        val totalFiles = files.size
        var completedFiles = 0
        var allSecure = true

        for (file in files) {
            if (isCancelledFlag) {
                throw CancellationException("Operation cancelled by user.")
            }

            var stagedFile: File? = null
            try {
                Log.d(
                    METADATA_TAG,
                    "source path=${file.absolutePath} size=${file.length()} bytes"
                )

                val options = com.example.lock.metadata.PurgeOptions.maximumPrivacy(
                    onStage = { stage, _ ->
                        Log.d(
                            METADATA_TAG,
                            "stage file=${file.name} stage=$stage"
                        )
                        updateStageOnMainThread("${file.name}: $stage")
                    },
                    onProgress = { bytesDone, bytesTotal ->
                        val fileProgress = if (bytesTotal > 0L) {
                            (bytesDone.toDouble() / bytesTotal.toDouble()).coerceIn(0.0, 1.0)
                        } else {
                            0.0
                        }
                        val overallProgress = (
                                ((completedFiles.toDouble() + fileProgress) / totalFiles.toDouble()) * 100.0
                                ).toInt().coerceIn(0, 100)

                        Log.v(
                            METADATA_TAG,
                            "progress file=${file.name} bytesDone=$bytesDone " +
                                    "bytesTotal=$bytesTotal overall=$overallProgress%"
                        )
                        updateProgressOnMainThread(overallProgress)
                    },
                    isCancelled = { isCancelledFlag }
                ).copy(randomNameLength = 10)

                val before = com.example.lock.metadata.MetadataPurgeProcessor.inspect(file, options)
                logInspection("before", before, file.absolutePath)

                updateStageOnMainThread("Preparing ${file.name}")
                stagedFile = createMetadataStagingCopy(file, outputDirectory)
                Log.d(
                    METADATA_TAG,
                    "staging copy source=${file.name} path=${stagedFile.absolutePath}"
                )

                val rawReport = com.example.lock.metadata.MetadataPurgeProcessor.purge(stagedFile, options)
                val renamedOutput = rawReport.outputFile?.let { output ->
                    if (output.exists() && output.isFile) {
                        renameOutputToNumeric10(output)
                    } else {
                        null
                    }
                }
                val report = if (rawReport.outputFile != null && renamedOutput != null) {
                    rawReport.copy(outputFile = renamedOutput)
                } else {
                    rawReport
                }
                logPurgeReport(report, file)

                val output = report.outputFile
                if (output != null && output.exists() && output.isFile) {
                    scanOutputFile(output)
                    val after = com.example.lock.metadata.MetadataPurgeProcessor.inspect(output, options)
                    logInspection("after", after, output.absolutePath)
                } else {
                    Log.w(
                        METADATA_TAG,
                        "output file is missing for source=${file.absolutePath}"
                    )
                }
                val safeDeleteResult = when {
                    !safeDeleteRequested -> MetadataSafeDeleteResult(
                        success = true,
                        report = null,
                        message = "not requested"
                    )
                    !report.securityComplete || output == null -> MetadataSafeDeleteResult(
                        success = false,
                        report = null,
                        message = "not executed because the cleaned output was not verified"
                    )
                    else -> secureDeleteOriginal(file)
                }
                val originalDeleteResult = safeDeleteResult.success

                updateMetadataCounters(report, originalDeleteResult)
                metadataReportItems.add(
                    buildMetadataReportItem(
                        original = file,
                        report = report,
                        before = before,
                        originalDeleteResult = originalDeleteResult,
                        safeDeleteResult = safeDeleteResult
                    )
                )

                if (!report.securityComplete || !report.succeeded ||
                    !originalDeleteResult
                ) {
                    allSecure = false
                }

                completedFiles++
                updateProgressOnMainThread((completedFiles * 100) / totalFiles)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                allSecure = false
                metadataFailedCount++
                metadataReportItems.add(buildFailureReportItem(file, e.message ?: e.javaClass.simpleName))
                Log.e(
                    METADATA_TAG,
                    "exception while purging file=${file.absolutePath}: ${e.message}",
                    e
                )
                completedFiles++
                updateProgressOnMainThread((completedFiles * 100) / totalFiles)
            } finally {
                stagedFile?.let { staged ->
                    if (staged.exists()) {
                        com.example.lock.metadata.SecureDelete.wipeQuietly(staged, 1)
                    }
                }
            }
        }

        Log.d(
            METADATA_TAG,
            "metadata operation finished allSecure=$allSecure " +
                    "completedFiles=$completedFiles totalFiles=$totalFiles " +
                    "outputDirectory=${outputDirectory.absolutePath}"
        )
        return allSecure
    }

    private fun metadataOutputDirectory(): File {
        return File(Environment.getExternalStorageDirectory(), "no-meta")
    }

    private fun createMetadataStagingCopy(source: File, outputDirectory: File): File {
        val extension = source.extension.ifBlank { "bin" }
        val staging = File.createTempFile(".metadata_input_", ".$extension", outputDirectory)
        source.copyTo(staging, overwrite = true)
        return staging
    }

    private fun renameOutputToNumeric10(output: File): File {
        val directory = output.parentFile ?: return output
        val extension = output.extension
        repeat(128) {
            val digits = buildString {
                append(('1'.code + outputNameRandom.nextInt(9)).toChar())
                repeat(9) {
                    append(('0'.code + outputNameRandom.nextInt(10)).toChar())
                }
            }
            val candidateName = if (extension.isEmpty()) digits else "$digits.$extension"
            val candidate = File(directory, candidateName)
            if (candidate.exists()) return@repeat
            if (output.renameTo(candidate)) return candidate
            try {
                output.copyTo(candidate, overwrite = false)
                if (output.delete()) return candidate
            } catch (_: Exception) {
            }
        }
        Log.w(
            METADATA_TAG,
            "could not rename output to a 10 digit filename path=${output.absolutePath}"
        )
        return output
    }

    private fun scanOutputFile(output: File) {
        MediaScannerConnection.scanFile(
            applicationContext,
            arrayOf(output.absolutePath),
            null
        ) { scannedPath, uri ->
            Log.d(
                METADATA_TAG,
                "media scan path=$scannedPath uri=$uri"
            )
        }
    }

    private fun secureDeleteOriginal(file: File): MetadataSafeDeleteResult {
        return try {
            val cancellationToken = object : com.example.lock.safe_delete.CancellationToken {
                override val isCancelled: Boolean
                    get() = isCancelledFlag
            }
            val result = MetadataSafeDeleteBridge.secureDelete(
                context = this@ProcessingActivity,
                file = file,
                cancellationToken = cancellationToken
            )
            Log.d(
                METADATA_TAG,
                "safe delete result file=${file.absolutePath} " +
                        "success=${result.success} message=${result.message} " +
                        "summary=${result.report?.summaryLine()}"
            )
            result
        } catch (e: Exception) {
            Log.e(
                METADATA_TAG,
                "safe delete exception file=${file.absolutePath}: ${e.message}",
                e
            )
            MetadataSafeDeleteResult(
                success = false,
                report = null,
                message = e.message ?: e.javaClass.simpleName
            )
        }
    }

    private fun resetMetadataReport() {
        metadataReportItems.clear()
        metadataSelectedCount = 0
        metadataVerifiedCount = 0
        metadataAlreadyCleanCount = 0
        metadataPartialCount = 0
        metadataRefusedCount = 0
        metadataFailedCount = 0
    }

    private fun updateMetadataCounters(
        report: com.example.lock.metadata.PurgeReport,
        originalDeleteResult: Boolean
    ) {
        when (report.status) {
            com.example.lock.metadata.PurgeStatus.SUCCESS -> {
                if (report.securityComplete && originalDeleteResult) metadataVerifiedCount++
                else metadataFailedCount++
            }
            com.example.lock.metadata.PurgeStatus.ALREADY_CLEAN -> metadataAlreadyCleanCount++
            com.example.lock.metadata.PurgeStatus.PARTIAL -> metadataPartialCount++
            com.example.lock.metadata.PurgeStatus.REFUSED -> metadataRefusedCount++
            com.example.lock.metadata.PurgeStatus.FAILED,
            com.example.lock.metadata.PurgeStatus.UNSUPPORTED_FORMAT -> metadataFailedCount++
        }
    }

    private fun buildMetadataReportItem(
        original: File,
        report: com.example.lock.metadata.PurgeReport,
        before: com.example.lock.metadata.InspectionResult,
        originalDeleteResult: Boolean,
        safeDeleteResult: MetadataSafeDeleteResult
    ): String {
        val removedLabels = report.removed
            .map { simpleMetadataLabel(it.kind.name) }
            .distinct()
        val removed = if (removedLabels.isEmpty()) {
            "No removable metadata found"
        } else {
            removedLabels.joinToString("\n") { "- $it" }
        }
        val output = report.outputFile?.absolutePath ?: "None"
        val originalState = when {
            safeDeleteRequested && originalDeleteResult -> "Securely deleted"
            safeDeleteRequested -> "Safe delete failed; original preserved"
            else -> "Preserved"
        }
        return buildString {
            appendLine(original.name)
            appendLine("Format: ${report.format.displayName}")
            appendLine("Removed metadata:")
            appendLine(removed)
            appendLine("Output: $output")
            appendLine("Original: $originalState")
            if (safeDeleteRequested) {
                appendLine("Secure delete: ${safeDeleteResult.message}")
            }
        }.trimEnd()
    }

    private fun simpleMetadataLabel(kind: String): String {
        return when (kind) {
            "GPS" -> "GPS location"
            "DEVICE_IDENTITY", "SERIAL_NUMBER", "MAKER_NOTE" -> "Camera or device information"
            "OWNER_IDENTITY", "AUTHOR" -> "Owner or author information"
            "TIMESTAMP" -> "Date and time information"
            "SOFTWARE" -> "Software information"
            "THUMBNAIL" -> "Embedded thumbnail"
            "UNIQUE_ID" -> "Unique identifier"
            "XMP" -> "XMP metadata"
            "IPTC" -> "IPTC metadata"
            "EXIF" -> "EXIF metadata"
            "ICC_PROFILE" -> "Color profile"
            "AUDIO_TAGS" -> "Audio tags"
            "VIDEO_TAGS" -> "Video tags"
            "DOCUMENT_PROPERTY" -> "Document properties"
            "REVISION_ID" -> "Revision information"
            "EMBEDDED_FILE" -> "Embedded data"
            "PATH_LEAK" -> "File path information"
            "PROVENANCE" -> "Provenance information"
            "ENCODING_MARKER" -> "Encoding marker"
            "ZIP_STRUCTURE" -> "Archive metadata"
            "UNVERIFIED_MEMBER" -> "Unverified embedded member"
            else -> "Other metadata"
        }
    }

    private fun buildFailureReportItem(file: File, message: String): String {
        return buildString {
            appendLine(file.name)
            appendLine("Status: FAILED")
            appendLine("No clean output was created")
            appendLine("Original: Preserved")
            appendLine("Reason: $message")
        }.trimEnd()
    }

    private fun logInspection(
        phase: String,
        inspection: com.example.lock.metadata.InspectionResult,
        displayPath: String = inspection.file.absolutePath
    ) {
        Log.d(
            METADATA_TAG,
            "inspection phase=$phase " +
                    "file=$displayPath " +
                    "format=${inspection.format} " +
                    "subtype=${inspection.subtype} " +
                    "scannerAvailable=${inspection.scannerAvailable} " +
                    "riskScore=${inspection.riskScore} " +
                    "findingCount=${inspection.findings.size} " +
                    "error=${inspection.error}"
        )

        inspection.findings.forEachIndexed { index, finding ->
            Log.d(
                METADATA_TAG,
                "inspection phase=$phase finding[$index] " +
                        "kind=${finding.kind} detail=${finding.detail} " +
                        "location=${finding.location}"
            )
        }
    }

    private fun logPurgeReport(
        report: com.example.lock.metadata.PurgeReport,
        original: File
    ) {
        Log.d(
            METADATA_TAG,
            "report original=${original.absolutePath} " +
                    "engineSource=${report.sourceFile.absolutePath} " +
                    "output=${report.outputFile?.absolutePath} " +
                    "format=${report.format} " +
                    "subtype=${report.subtype} " +
                    "strategy=${report.strategy} " +
                    "status=${report.status} " +
                    "assurance=${report.assurance} " +
                    "structureValid=${report.structureValid} " +
                    "verifiedClean=${report.verifiedClean} " +
                    "outputVerified=${report.outputVerified} " +
                    "sourceRetired=${report.sourceRetired} " +
                    "originalWiped=${report.originalWiped} " +
                    "securityComplete=${report.securityComplete} " +
                    "bytesBefore=${report.bytesBefore} " +
                    "bytesAfter=${report.bytesAfter} " +
                    "bytesSaved=${report.bytesSaved} " +
                    "message=${report.message}"
        )

        report.removed.forEachIndexed { index, finding ->
            Log.d(
                METADATA_TAG,
                "removed[$index] kind=${finding.kind} detail=${finding.detail} " +
                        "location=${finding.location}"
            )
        }

        report.residual.forEachIndexed { index, finding ->
            Log.w(
                METADATA_TAG,
                "residual[$index] kind=${finding.kind} detail=${finding.detail} " +
                        "location=${finding.location}"
            )
        }

        report.residualRequired.forEachIndexed { index, finding ->
            Log.d(
                METADATA_TAG,
                "residualRequired[$index] kind=${finding.kind} " +
                        "detail=${finding.detail} location=${finding.location}"
            )
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
            Log.d(
                TAG,
                "Starting engine encryption. engine=$engineType files=${files.size} mode=$mode deleteAfter=$deleteAfter"
            )
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
                    updateProgressOnMainThread(percent)
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
                    updateStageOnMainThread("Decrypting ${inputFile.name}")

                    if (secondDecryptPassword.isNotBlank()) {
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
                    updateProgressOnMainThread(((completedFiles * 100) / totalFiles).coerceIn(0, 100))
                } catch (e: Exception) {
                    if (e is CancellationException || isCancelledFlag) throw e
                    if (e is com.example.lock.enc.OperationCancelledException) {
                        throw CancellationException("Operation cancelled by user.")
                    }
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

        val decryptedFile: File = when (engineType) {
            EngineType.MAX -> {
                if (EngineType.isLegacyMaxContainer(inputFile)) {
                    throw SecurityException("Legacy MAX container (v11) is not supported after engine migration.")
                }
                val passChars = password.toCharArray()
                try {
                    val adapter = MaxEngineAdapter.getInstance(this@ProcessingActivity)
                    decryptWithProgress(
                        adapter = adapter,
                        inputFile = inputFile,
                        outputDirectory = workDirectory,
                        password = passChars,
                        basePercent = (completedFiles * 100) / totalFiles,
                        sharePercent = 100 / totalFiles
                    )
                } finally {
                    java.util.Arrays.fill(passChars, '\u0000')
                }
            }
            EngineType.MEDIUM -> {
                if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                decryptWithLockSingle(inputFile, workDirectory, password)
            }
            EngineType.EASY -> {
                LightEncryptionManager().decryptFile(
                    inputFile = inputFile,
                    outputDirectory = workDirectory,
                    password = password.toCharArray(),
                    isCancelled = { isCancelledFlag },
                    onProgress = { snap: LightEncryptionManager.ProgressSnapshot ->
                        val base = (completedFiles * 100) / totalFiles
                        val portion = snap.percent / totalFiles
                        updateProgressOnMainThread((base + portion).coerceIn(0, 100))
                    }
                )
            }
        }

        handleDecryptedArtifact(decryptedFile, password, finalOutputDirectory, workDirectory, 0, null)
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

        val outerDecryptedFile: File = when (outerEngineType) {
            EngineType.MAX -> {
                if (EngineType.isLegacyMaxContainer(inputFile)) {
                    throw SecurityException("Legacy MAX container (v11) is not supported after engine migration.")
                }
                val passChars = secondPassword.toCharArray()
                try {
                    val adapter = MaxEngineAdapter.getInstance(this@ProcessingActivity)
                    decryptWithProgress(
                        adapter = adapter,
                        inputFile = inputFile,
                        outputDirectory = workDirectory,
                        password = passChars,
                        basePercent = (completedFiles * 100) / totalFiles,
                        sharePercent = 100 / totalFiles
                    )
                } finally {
                    java.util.Arrays.fill(passChars, '\u0000')
                }
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
                        updateProgressOnMainThread((base + portion).coerceIn(0, 100))
                    }
                )
            }
        }

        handleDecryptedArtifact(outerDecryptedFile, firstPassword, finalOutputDirectory, workDirectory, 0, secondPassword)
    }

    private fun decryptWithProgress(
        adapter: MaxEngineAdapter,
        inputFile: File,
        outputDirectory: File,
        password: CharArray,
        basePercent: Int,
        sharePercent: Int
    ): File {
        val total = inputFile.length()
        return adapter.decryptFile(
            inputFile = inputFile,
            outputDirectory = outputDirectory,
            password = password,
            onProgress = { processed ->
                if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                if (total > 0L) {
                    val done = ((processed * 100L) / total).toInt().coerceIn(0, 100)
                    val percent = basePercent + (done * sharePercent) / 100
                    updateProgressOnMainThread(percent.coerceIn(0, 100))
                }
            },
            isCancelled = { isCancelledFlag }
        )
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

    private fun decryptSingleLayer(file: File, password: String, workDir: File): File {
        val engine = EngineType.detectFromFile(file) ?: EngineType.MAX
        return when (engine) {
            EngineType.MAX -> {
                if (EngineType.isLegacyMaxContainer(file)) {
                    throw SecurityException("Legacy MAX container (v11) is not supported after engine migration.")
                }
                val chars = password.toCharArray()
                try {
                    val adapter = MaxEngineAdapter.getInstance(this@ProcessingActivity)
                    decryptWithProgress(adapter, file, workDir, chars, 0, 100)
                } finally {
                    java.util.Arrays.fill(chars, '\u0000')
                }
            }
            EngineType.MEDIUM -> decryptWithLockSingle(file, workDir, password)
            EngineType.EASY -> LightEncryptionManager().decryptFile(file, workDir, password.toCharArray(), isCancelled = { isCancelledFlag })
        }
    }

    private fun handleDecryptedArtifact(
        artifact: File,
        primaryPassword: String,
        finalOutputDirectory: File,
        workDirectory: File,
        depth: Int,
        secondPassword: String? = null
    ) {
        if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
        if (depth > 8) {
            val savedFile = moveFileToDirectory(artifact, finalOutputDirectory)
            if (intent.getBooleanExtra("IS_EPHEMERAL", false)) {
                lifecycleScope.launch(Dispatchers.Main) { openEphemeralFile(savedFile) }
            }
            return
        }
        if (!artifact.exists()) return
        if (artifact.isDirectory) {
            val children = artifact.listFiles()?.toList().orEmpty()
            if (children.isEmpty()) { artifact.delete(); return }
            for (child in children) {
                if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                handleDecryptedArtifact(child, primaryPassword, finalOutputDirectory, workDirectory, depth + 1, secondPassword)
            }
            artifact.delete()
            return
        }
        if (isZipFile(artifact)) {
            updateStageOnMainThread("Auto extracting ${artifact.name}")
            val extractDir = File(workDirectory, "extract_${System.nanoTime()}")
            extractDir.mkdirs()
            extractZip(artifact, extractDir)
            artifact.delete()
            val extractedFiles = extractDir.listFiles()?.toList().orEmpty()
            for (file in extractedFiles) {
                if (isCancelledFlag) throw CancellationException("Operation cancelled by user.")
                handleDecryptedArtifact(file, primaryPassword, finalOutputDirectory, workDirectory, depth + 1, secondPassword)
            }
            extractDir.delete()
            return
        }
        if (isEncryptedFile(artifact)) {
            updateStageOnMainThread("Decrypting inner layer")
            val innerDecrypted: File = if (!secondPassword.isNullOrBlank()) {
                var outerTemp: File? = null
                try {
                    outerTemp = decryptSingleLayer(artifact, secondPassword, workDirectory)
                    if (isEncryptedFile(outerTemp)) {
                        val innerFile = decryptSingleLayer(outerTemp, primaryPassword, workDirectory)
                        outerTemp.delete()
                        innerFile
                    } else outerTemp
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    outerTemp?.let { if (it.exists()) try { it.delete() } catch (_: Exception) {} }
                    decryptSingleLayer(artifact, primaryPassword, workDirectory)
                }
            } else {
                decryptSingleLayer(artifact, primaryPassword, workDirectory)
            }
            artifact.delete()
            handleDecryptedArtifact(innerDecrypted, primaryPassword, finalOutputDirectory, workDirectory, depth + 1, secondPassword)
            return
        }
        val savedFile = moveFileToDirectory(artifact, finalOutputDirectory)
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

    private fun buildMetadataSummary(): String {
        return buildString {
            appendLine("Metadata purge report")
            appendLine()
            appendLine("Selected: $metadataSelectedCount")
            appendLine("Verified: $metadataVerifiedCount")
            appendLine("Already clean: $metadataAlreadyCleanCount")
            appendLine("Partial: $metadataPartialCount")
            appendLine("Refused: $metadataRefusedCount")
            appendLine("Failed: $metadataFailedCount")
            appendLine("Output directory: ${metadataOutputDirectory().absolutePath}")
            appendLine("Original files: ${if (safeDeleteRequested) "safe delete requested" else "preserved"}")
        }.trimEnd()
    }

    private fun openMetadataReport() {
        if (metadataReportItems.isEmpty()) return
        val reportIntent = Intent(this, MetadataReportActivity::class.java).apply {
            putExtra("REPORT_SUMMARY", buildMetadataSummary())
            putStringArrayListExtra("REPORT_ITEMS", ArrayList(metadataReportItems))
        }
        startActivity(reportIntent)
    }

    private fun configureMetadataReportLink() {
        stageText.text = "SHOW REPORTS"
        stageText.setTextColor(Color.parseColor("#C9A85F"))
        stageText.paintFlags = stageText.paintFlags or Paint.UNDERLINE_TEXT_FLAG
        stageText.isClickable = true
        stageText.setOnClickListener { openMetadataReport() }
    }

    private fun showSuccess() {
        progressBar.visibility = View.GONE
        btnCancel.visibility = View.GONE
        statusText.setTextColor(Color.parseColor("#00FF66"))
        statusText.text = when (currentMode) {
            "ENCRYPT" -> "Encryption Completed Successfully"
            "DECRYPT" -> "Decryption Completed Successfully"
            "METADATA_PURGE" -> "Metadata Purged Successfully"
            else -> "Completed Successfully"
        }
        percentText.text = "100%"
        stageText.text = when (currentMode) {
            "ENCRYPT" -> "Files saved inside the ENC"
            "DECRYPT" -> "Files saved inside the DEC"
            "METADATA_PURGE" -> "Metadata successfully removed from files"
            else -> "Done"
        }
        if (currentMode == "METADATA_PURGE") configureMetadataReportLink()
        btnDone.visibility = View.VISIBLE
        btnDone.text = "DONE"
    }

    private fun showError(msg: String) {
        progressBar.visibility = View.GONE
        btnCancel.visibility = View.GONE
        statusText.setTextColor(Color.parseColor("#FF3D00"))
        statusText.text = "Error"
        stageText.text = msg
        if (currentMode == "METADATA_PURGE" && metadataReportItems.isNotEmpty()) {
            configureMetadataReportLink()
        }
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

}
