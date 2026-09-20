package com.example.lock.text_encrypt

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.example.lock.R
import com.example.lock.SafeExit
import java.io.File

class MaximumDecryptionResultActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_TEMP_FILE_PATH = "com.example.lock.EXTRA_TEMP_FILE_PATH"
        const val EXTRA_FILE_NAME = "com.example.lock.EXTRA_FILE_NAME"
    }

    private var tempFile: File? = null
    private var txtDecryptedOutput: EditText? = null
    private var btnCopy: Button? = null
    private var btnNeonExit: Button? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContentView(R.layout.activity_decryption_result)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                cleanupTempFile()
                SafeExit.performSafeExit(this@MaximumDecryptionResultActivity)
            }
        })

        val path = intent.getStringExtra(EXTRA_TEMP_FILE_PATH)

        if (path.isNullOrEmpty()) {
            Toast.makeText(this, "Decrypted file path is missing", Toast.LENGTH_LONG).show()
            SafeExit.performSafeExit(this)
            return
        }

        tempFile = File(path)
        if (tempFile?.exists() != true || tempFile?.length() == 0L) {
            Toast.makeText(this, "Decrypted file is not readable", Toast.LENGTH_LONG).show()
            SafeExit.performSafeExit(this)
            return
        }

        initViews()
        loadDecryptedContent()
    }

    private fun initViews() {
        txtDecryptedOutput = findViewById(R.id.txtDecryptedOutput)
        btnCopy = findViewById(R.id.btnCopy)
        btnNeonExit = findViewById(R.id.btnNeonExit)

        btnCopy?.setOnClickListener {
            val textToCopy = txtDecryptedOutput?.text?.toString() ?: ""
            if (textToCopy.isNotEmpty()) {
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("Decrypted Output", textToCopy)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Nothing to copy", Toast.LENGTH_SHORT).show()
            }
        }

        btnNeonExit?.setOnClickListener {
            cleanupTempFile()
            SafeExit.performSafeExit(this)
        }
    }

    private fun loadDecryptedContent() {
        try {
            val content = tempFile?.readText(Charsets.UTF_8) ?: ""
            txtDecryptedOutput?.setText(content)
        } catch (e: Exception) {
            Toast.makeText(this, "Error reading decrypted content: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
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