package com.example.lock

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.view.WindowManager
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.EditText
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.lock.crypto.MaxTextEncryptionEngine
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

        // Anti screenshot / anti screen recording for the whole activity lifecycle.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // Hardware/software Back button must perform secure cleanup.
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

        // Keep read access if the sender/document-provider allows it.
        tryTakePersistableReadPermission(incomingIntent, targetFileUri!!)

        findViewById<Button>(R.id.btnDecrypt).setOnClickListener {
            executeDecryptionSequence()
        }
    }

    private fun resolveIncomingUri(incomingIntent: Intent?): Uri? {
        if (incomingIntent == null) return null

        // ACTION_VIEW from Android Open With / Telegram / file managers.
        incomingIntent.data?.let {
            return it
        }

        // ACTION_SEND from share sheets.
        @Suppress("DEPRECATION")
        val streamUri: Uri? = incomingIntent.getParcelableExtra(Intent.EXTRA_STREAM)

        if (streamUri != null) {
            return streamUri
        }

        // Some apps put the Uri in ClipData instead of data/EXTRA_STREAM.
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
                // Many messengers give only temporary read permission; that is normal.
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

                cipheredPayload = withContext(Dispatchers.IO) {
                    readAndNormalizeEncryptedPayload(currentUri)
                }

                val encryptedBytes = cipheredPayload

                if (encryptedBytes == null || encryptedBytes.isEmpty()) {
                    Toast.makeText(
                        this@DecryptionHandlerActivity,
                        "Stream Data Empty or Unreadable",
                        Toast.LENGTH_LONG
                    ).show()

                    return@launch
                }

                withContext(Dispatchers.IO) {
                    val engine = MaxTextEncryptionEngine()

                    engine.decryptAndConsume(encryptedBytes, passwordChars) { decryptedChars ->
                        decryptedCharsForUi = decryptedChars.copyOf()
                        decryptedChars.fill('\u0000')
                    }
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
            }
        }
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

    private fun readAndNormalizeEncryptedPayload(uri: Uri): ByteArray? {
        val fileBytes = contentResolver.openInputStream(uri)?.use { stream ->
            stream.readBytes()
        } ?: return null

        if (fileBytes.isEmpty()) return null

        /*
         * TextEncryptionActivity writes Maximum-mode output as Base64 text into .enc.txt.
         * MaxTextEncryptionEngine.decryptAndConsume needs the decoded binary container.
         */
        val fileText = fileBytes.toString(Charsets.UTF_8).trim()

        if (fileText.isNotEmpty()) {
            try {
                return Base64.decode(
                    fileText,
                    Base64.URL_SAFE or Base64.NO_WRAP
                )
            } catch (_: Exception) {
                try {
                    return Base64.decode(
                        fileText,
                        Base64.DEFAULT
                    )
                } catch (_: Exception) {
                    // If a future exporter writes raw binary instead of Base64, fall through.
                }
            }
        }

        return fileBytes
    }

    private fun displayDecryptedContent(decryptedChars: CharArray) {
        switchToStateLayout(UI_STATE_RESULT)

        val outputBox = findViewById<EditText>(R.id.txtDecryptedOutput)

        outputBox.setText(decryptedChars, 0, decryptedChars.size)
        outputBox.keyListener = null
        outputBox.isFocusable = false
        outputBox.isFocusableInTouchMode = false

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