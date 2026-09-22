package com.example.lock

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.lock.crypto.MaxTextEncryptionEngine
import com.example.lock.crypto.MediumShortEncryptionEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DecryptionHandlerActivity : AppCompatActivity() {

    private var targetFileUri: Uri? = null
    private var cipheredPayload: ByteArray? = null

    private val UI_STATE_INPUT = 1
    private val UI_STATE_RESULT = 2

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                cleanupAndSafeExit()
            }
        })
        handleIncomingIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        cleanupSensitiveState()
        handleIncomingIntent(intent)
    }

    private fun handleIncomingIntent(incomingIntent: Intent?) {
        switchToStateLayout(UI_STATE_INPUT)
        targetFileUri = resolveIncomingUri(incomingIntent)
        if (targetFileUri == null) {
            Toast.makeText(
                this,
                "Critical: Missing Input Stream Target File",
                Toast.LENGTH_LONG
            ).show()
            cleanupAndSafeExit()
            return
        }
        tryTakePersistableReadPermission(incomingIntent, targetFileUri!!)
        findViewById<Button>(R.id.btnDecrypt).setOnClickListener {
            executeDecryptionSequence()
        }
    }

    private fun resolveIncomingUri(incomingIntent: Intent?): Uri? {
        if (incomingIntent == null) return null
        incomingIntent.data?.let {
            return it
        }
        @Suppress("DEPRECATION")
        val streamUri: Uri? = incomingIntent.getParcelableExtra(Intent.EXTRA_STREAM)
        if (streamUri != null) {
            return streamUri
        }
        val clipData = incomingIntent.clipData
        if (clipData != null && clipData.itemCount > 0) {
            clipData.getItemAt(0)?.uri?.let {
                return it
            }
        }
        return null
    }

    private fun tryTakePersistableReadPermission(incomingIntent: Intent?, uri: Uri) {
        if (incomingIntent == null) return
        val hasReadGrant =
            (incomingIntent.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION) != 0
        val hasPersistableGrant =
            (incomingIntent.flags and Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION) != 0
        if (hasReadGrant && hasPersistableGrant) {
            try {
                contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } catch (_: Exception) {
            }
        }
    }

    private fun executeDecryptionSequence() {
        val passwordField = findViewById<EditText>(R.id.passwordInput)
        val plainPasswordText = passwordField.text.toString()
        if (plainPasswordText.isEmpty()) {
            passwordField.error = "Required Field"
            return
        }
        val passwordChars = plainPasswordText.toCharArray()
        passwordField.text.clear()
        setDecryptLoading(true)
        lifecycleScope.launch {
            var decryptedCharsForUi: CharArray? = null
            try {
                val currentUri = targetFileUri
                if (currentUri == null) {
                    Toast.makeText(
                        this@DecryptionHandlerActivity,
                        "Missing file Uri",
                        Toast.LENGTH_LONG
                    ).show()
                    return@launch
                }
                val payload = withContext(Dispatchers.IO) {
                    readEncryptedPayload(currentUri)
                }
                if (payload == null) {
                    Toast.makeText(
                        this@DecryptionHandlerActivity,
                        "Stream Data Empty or Unreadable",
                        Toast.LENGTH_LONG
                    ).show()
                    return@launch
                }
                val fileText = payload.first
                cipheredPayload = payload.second
                val success = withContext(Dispatchers.IO) {
                    tryMediumThenMax(fileText, payload.second, passwordChars) { decryptedChars ->
                        decryptedCharsForUi = decryptedChars
                    }
                }
                if (!success) {
                    Toast.makeText(
                        this@DecryptionHandlerActivity,
                        "Wrong password, try again",
                        Toast.LENGTH_LONG
                    ).show()
                    return@launch
                }
                val output = decryptedCharsForUi
                if (output == null || output.isEmpty()) {
                    Toast.makeText(
                        this@DecryptionHandlerActivity,
                        "Decryption Failed",
                        Toast.LENGTH_LONG
                    ).show()
                    return@launch
                }
                displayDecryptedContent(output)
            } catch (_: Exception) {
                Toast.makeText(
                    this@DecryptionHandlerActivity,
                    "Decryption Interrupted: Bad Credentials or Package Tampered",
                    Toast.LENGTH_LONG
                ).show()
            } finally {
                passwordChars.fill('\u0000')
                decryptedCharsForUi?.fill('\u0000')
                cipheredPayload?.fill(0)
                cipheredPayload = null
                setDecryptLoading(false)
                try {
                    findViewById<EditText>(R.id.passwordInput)?.requestFocus()
                } catch (_: Exception) {
                }
            }
        }
    }

    private fun tryMediumThenMax(
        fileText: String,
        decodedBytes: ByteArray,
        passwordChars: CharArray,
        onSuccess: (CharArray) -> Unit
    ): Boolean {
        val mediumPassword = passwordChars.copyOf()
        try {
            val mediumResult = MediumShortEncryptionEngine().decrypt(fileText, mediumPassword)
            if (!mediumResult.isNullOrEmpty()) {
                onSuccess(mediumResult.toCharArray())
                return true
            }
        } catch (_: Exception) {
        } finally {
            mediumPassword.fill('\u0000')
        }
        val maxPassword = passwordChars.copyOf()
        try {
            val ok = MaxTextEncryptionEngine().decryptAndConsume(decodedBytes, maxPassword) { decryptedChars ->
                onSuccess(decryptedChars.copyOf())
                decryptedChars.fill('\u0000')
            }
            if (ok) return true
        } catch (_: Exception) {
        } finally {
            maxPassword.fill('\u0000')
        }
        return false
    }

    private fun setDecryptLoading(isLoading: Boolean) {
        try {
            val passwordField = findViewById<EditText>(R.id.passwordInput)
            val decryptButton = findViewById<Button>(R.id.btnDecrypt)
            val progressBar = findViewById<ProgressBar>(R.id.decryptionProgressBar)
            val statusText = findViewById<TextView>(R.id.txtDecryptingStatus)
            passwordField.isEnabled = !isLoading
            decryptButton.isEnabled = !isLoading
            progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
            statusText.visibility = if (isLoading) View.VISIBLE else View.GONE
        } catch (_: Exception) {
        }
    }

    private fun readEncryptedPayload(uri: Uri): Pair<String, ByteArray>? {
        val fileBytes = contentResolver.openInputStream(uri)?.use { stream ->
            stream.readBytes()
        } ?: return null
        if (fileBytes.isEmpty()) return null
        val fileText = fileBytes.toString(Charsets.UTF_8).trim()
        if (fileText.isEmpty()) return null
        var decoded: ByteArray? = null
        try {
            decoded = Base64.decode(
                fileText,
                Base64.URL_SAFE or Base64.NO_WRAP
            )
        } catch (_: Exception) {
            try {
                decoded = Base64.decode(
                    fileText,
                    Base64.DEFAULT
                )
            } catch (_: Exception) {
                decoded = null
            }
        }
        if (decoded == null || decoded.isEmpty()) {
            decoded = fileBytes
        }
        return Pair(fileText, decoded)
    }

    private fun displayDecryptedContent(decryptedChars: CharArray) {
        switchToStateLayout(UI_STATE_RESULT)
        val outputBox = findViewById<EditText>(R.id.txtDecryptedOutput)
        outputBox.setText(decryptedChars, 0, decryptedChars.size)
        outputBox.keyListener = null
        outputBox.isFocusable = false
        outputBox.isFocusableInTouchMode = false
        try {
            findViewById<Button>(R.id.btnCopy)?.setOnClickListener {
                val textToCopy = outputBox.text?.toString() ?: ""
                if (textToCopy.isNotEmpty()) {
                    val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                    clipboard.setPrimaryClip(ClipData.newPlainText("Decrypted Output", textToCopy))
                    Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Nothing to copy", Toast.LENGTH_SHORT).show()
                }
            }
        } catch (_: Exception) {
        }
        findViewById<Button>(R.id.btnNeonExit).setOnClickListener {
            cleanupAndSafeExit()
        }
    }

    private fun switchToStateLayout(state: Int) {
        if (state == UI_STATE_INPUT) {
            setContentView(R.layout.activity_decryption_handler)
        } else if (state == UI_STATE_RESULT) {
            setContentView(R.layout.activity_decryption_result)
        }
    }

    private fun cleanupSensitiveState() {
        try {
            findViewById<EditText>(R.id.passwordInput)?.text?.clear()
        } catch (_: Exception) {
        }
        try {
            findViewById<EditText>(R.id.txtDecryptedOutput)?.text?.clear()
        } catch (_: Exception) {
        }
        cipheredPayload?.fill(0)
        cipheredPayload = null
        targetFileUri = null
    }

    private fun cleanupAndSafeExit() {
        cleanupSensitiveState()
        SafeExit.performSafeExit(this)
    }

    override fun onDestroy() {
        cleanupSensitiveState()
        super.onDestroy()
    }
}
