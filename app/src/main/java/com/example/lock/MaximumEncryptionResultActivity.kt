package com.example.lock

import android.content.ClipData
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

class MaximumEncryptionResultActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_TEMP_FILE_PATH = "com.example.lock.EXTRA_TEMP_FILE_PATH"
        const val EXTRA_FILE_NAME = "com.example.lock.EXTRA_FILE_NAME"
    }

    private var tempFile: File? = null
    private var fileName: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContentView(R.layout.activity_maximum_encryption_result)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                cleanupTempFile()
                SafeExit.performSafeExit(this@MaximumEncryptionResultActivity)
            }
        })

        val path = intent.getStringExtra(EXTRA_TEMP_FILE_PATH)
        fileName = intent.getStringExtra(EXTRA_FILE_NAME)

        if (path.isNullOrEmpty() || fileName.isNullOrEmpty()) {
            Toast.makeText(this, "Encrypted file is missing", Toast.LENGTH_LONG).show()
            SafeExit.performSafeExit(this)
            return
        }

        tempFile = File(path)
        if (tempFile?.exists() != true || tempFile?.length() == 0L) {
            Toast.makeText(this, "Encrypted file is not readable", Toast.LENGTH_LONG).show()
            SafeExit.performSafeExit(this)
            return
        }

        initViews()
    }

    private fun initViews() {
        findViewById<TextView>(R.id.txtResultFileName).text = fileName

        findViewById<Button>(R.id.btnResultShare).setOnClickListener {
            shareEncryptedFile()
        }

        findViewById<Button>(R.id.btnResultSave).setOnClickListener {
            saveEncryptedFileToDevice()
        }

        findViewById<Button>(R.id.btnResultSafeExit).setOnClickListener {
            cleanupTempFile()
            SafeExit.performSafeExit(this)
        }
    }

    private fun shareEncryptedFile() {
        val file = tempFile
        if (file == null || !file.exists()) {
            Toast.makeText(this, "Encrypted file is missing", Toast.LENGTH_LONG).show()
            return
        }

        try {
            val contentUri: Uri = FileProvider.getUriForFile(
                this,
                "${packageName}.fileprovider",
                file
            )

            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_STREAM, contentUri)
                putExtra(Intent.EXTRA_TITLE, file.name)
                putExtra(Intent.EXTRA_SUBJECT, file.name)
                clipData = ClipData.newUri(contentResolver, file.name, contentUri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }

            startActivity(Intent.createChooser(intent, "Share encrypted file via"))
        } catch (e: Exception) {
            Toast.makeText(this, "Share failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun saveEncryptedFileToDevice() {
        val sourceFile = tempFile
        val targetName = fileName

        if (sourceFile == null || !sourceFile.exists() || targetName.isNullOrEmpty()) {
            Toast.makeText(this, "Encrypted file is missing", Toast.LENGTH_LONG).show()
            return
        }

        try {
            val rootDir = Environment.getExternalStorageDirectory()
            val encDir = File(rootDir, "ENC/text ENC")
            if (!encDir.exists()) {
                val created = encDir.mkdirs()
                if (!created) {
                    Toast.makeText(this, "Could not create text ENC folder", Toast.LENGTH_LONG).show()
                    return
                }
            }

            val outputFile = File(encDir, targetName)

            FileInputStream(sourceFile).use { input ->
                FileOutputStream(outputFile).use { output ->
                    input.copyTo(output)
                    output.flush()
                }
            }

            Toast.makeText(
                this,
                "Saved to: ${outputFile.absolutePath}",
                Toast.LENGTH_LONG
            ).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Save failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun cleanupTempFile() {
        try {
            tempFile?.delete()
        } catch (_: Exception) {
        }
        tempFile = null
    }

    override fun onDestroy() {
        if (isFinishing) {
            cleanupTempFile()
        }
        super.onDestroy()
    }
}