package com.example.lock

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.lock.crypto.MaxTextEncryptionEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.SecureRandom

class MaximumEncryptionProcessingActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MaximumEncryptionProcessing"

        private val payloadLock = Any()
        private var pendingPlainText: CharArray? = null
        private var pendingPassword: CharArray? = null

        fun setPayload(plainText: CharArray, password: CharArray) {
            synchronized(payloadLock) {
                pendingPlainText?.fill('\u0000')
                pendingPassword?.fill('\u0000')

                pendingPlainText = plainText.copyOf()
                pendingPassword = password.copyOf()
            }
        }

        private fun consumePayload(): Pair<CharArray, CharArray>? {
            synchronized(payloadLock) {
                val plain = pendingPlainText
                val pass = pendingPassword

                pendingPlainText = null
                pendingPassword = null

                if (plain == null || pass == null) return null
                return Pair(plain, pass)
            }
        }

        private fun clearPayload() {
            synchronized(payloadLock) {
                pendingPlainText?.fill('\u0000')
                pendingPassword?.fill('\u0000')
                pendingPlainText = null
                pendingPassword = null
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContentView(R.layout.activity_maximum_encryption_processing)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                clearPayload()
                SafeExit.performSafeExit(this@MaximumEncryptionProcessingActivity)
            }
        })

        startEncryptionProcess()
    }

    private fun startEncryptionProcess() {
        lifecycleScope.launch(Dispatchers.IO) {
            val payload = consumePayload()

            if (payload == null) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@MaximumEncryptionProcessingActivity,
                        "Missing encryption payload",
                        Toast.LENGTH_LONG
                    ).show()
                    SafeExit.performSafeExit(this@MaximumEncryptionProcessingActivity)
                }
                return@launch
            }

            val plainChars = payload.first
            val passwordChars = payload.second

            var encryptedBytes: ByteArray? = null
            var encodedBytes: ByteArray? = null
            var tempFile: File? = null

            try {
                Log.i(TAG, "[PROCESSING] Maximum encryption started")

                val engine = MaxTextEncryptionEngine()
                encryptedBytes = engine.encrypt(plainChars, passwordChars)

                encodedBytes = Base64.encode(
                    encryptedBytes,
                    Base64.URL_SAFE or Base64.NO_WRAP
                )

                tempFile = createTemporaryEncryptedFile(encodedBytes)

                withContext(Dispatchers.Main) {
                    if (!isFinishing && !isDestroyed) {
                        val intent = Intent(
                            this@MaximumEncryptionProcessingActivity,
                            MaximumEncryptionResultActivity::class.java
                        ).apply {
                            putExtra(MaximumEncryptionResultActivity.EXTRA_TEMP_FILE_PATH, tempFile.absolutePath)
                            putExtra(MaximumEncryptionResultActivity.EXTRA_FILE_NAME, tempFile.name)
                        }

                        startActivity(intent)
                        finish()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "[PROCESSING] Maximum encryption failed", e)

                try {
                    tempFile?.delete()
                } catch (_: Exception) {
                }

                withContext(Dispatchers.Main) {
                    if (!isFinishing && !isDestroyed) {
                        Toast.makeText(
                            this@MaximumEncryptionProcessingActivity,
                            "Encryption failed: ${e.message}",
                            Toast.LENGTH_LONG
                        ).show()
                        finish()
                    }
                }
            } finally {
                plainChars.fill('\u0000')
                passwordChars.fill('\u0000')
                encryptedBytes?.fill(0)
                encodedBytes?.fill(0)
                clearPayload()
            }
        }
    }

    private fun createTemporaryEncryptedFile(encodedPayload: ByteArray): File {
        val tempFile = File(cacheDir, generateRandomFileName10())

        FileOutputStream(tempFile).use { outputStream ->
            outputStream.write(encodedPayload)
            outputStream.flush()
        }

        return tempFile
    }

    private fun generateRandomFileName10(): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        val random = SecureRandom()
        val builder = StringBuilder(10)

        repeat(10) {
            builder.append(alphabet[random.nextInt(alphabet.length)])
        }

        return builder.toString() + ".enc.txt"
    }

    override fun onDestroy() {
        if (isFinishing) {
            clearPayload()
        }
        super.onDestroy()
    }
}
