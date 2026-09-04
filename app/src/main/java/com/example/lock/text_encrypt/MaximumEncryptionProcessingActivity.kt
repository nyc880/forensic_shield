package com.example.lock.text_encrypt

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.lock.R
import com.example.lock.crypto.MaxTextEncryptionEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.GeneralSecurityException
import java.security.SecureRandom

class MaximumEncryptionProcessingActivity : AppCompatActivity() {

    /*
     * =================================================================================
     *  CONFIGURATIONS & VARIABLES TABLE
     * =================================================================================
     *  | Variable Name            | Type     | Default Value        | Description                          |
     *  |--------------------------|----------|----------------------|--------------------------------------|
     *  | TAG                      | String   | "MaxEncProcessing"   | Logging tag for Logcat debugging     |
     *  | RANDOM_FILE_NAME_LENGTH  | Int      | 10                   | Length of random generated temp file |
     *  | TEMP_FILE_EXTENSION      | String   | ".enc.txt"           | Extension for output temporary file  |
     *  | CHAR_ALPHABET            | String   | "A-Za-z0-9..."       | Characters used for random file name |
     * =================================================================================
     */
    companion object {
        private const val TAG = "MaxEncProcessing"
        private const val RANDOM_FILE_NAME_LENGTH = 10
        private const val TEMP_FILE_EXTENSION = ".enc.txt"
        private const val CHAR_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

        private val payloadLock = Any()
        private var pendingPlainText: CharArray? = null
        private var pendingPassword: CharArray? = null
        private var pendingIsDecrypt: Boolean = false
        private var isPayloadConsumed: Boolean = false

        fun setPayload(plainText: CharArray, password: CharArray, isDecrypt: Boolean = false) {
            synchronized(payloadLock) {
                pendingPlainText?.fill('\u0000')
                pendingPassword?.fill('\u0000')

                pendingPlainText = plainText.copyOf()
                pendingPassword = password.copyOf()
                pendingIsDecrypt = isDecrypt
                isPayloadConsumed = false
                Log.d(TAG, "[PAYLOAD_SET] Payload updated. Length: ${plainText.size}, isDecrypt: $isDecrypt")
            }
        }

        fun getPendingIsDecrypt(): Boolean {
            synchronized(payloadLock) {
                return pendingIsDecrypt
            }
        }

        private data class Payload(
            val text: CharArray,
            val password: CharArray,
            val isDecrypt: Boolean
        )

        private fun consumePayload(): Payload? {
            synchronized(payloadLock) {
                if (isPayloadConsumed) {
                    Log.w(TAG, "[PAYLOAD_CONSUME] Payload was already consumed previously")
                    return null
                }

                val plain = pendingPlainText
                val pass = pendingPassword
                val isDec = pendingIsDecrypt

                if (plain == null || pass == null) {
                    Log.w(TAG, "[PAYLOAD_CONSUME] Payload is null or incomplete")
                    return null
                }

                isPayloadConsumed = true
                Log.d(TAG, "[PAYLOAD_CONSUME] Payload successfully retrieved for execution")
                return Payload(plain, pass, isDec)
            }
        }

        fun clearPayload() {
            synchronized(payloadLock) {
                pendingPlainText?.fill('\u0000')
                pendingPassword?.fill('\u0000')
                pendingPlainText = null
                pendingPassword = null
                pendingIsDecrypt = false
                isPayloadConsumed = false
                Log.d(TAG, "[PAYLOAD_CLEAR] Payload wiped safely from memory")
            }
        }
    }

    private var isProcessingStarted = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        val isDecrypt = getPendingIsDecrypt()
        Log.d(TAG, "[ON_CREATE] Processing Activity started. Mode: isDecrypt = $isDecrypt")

        if (isDecrypt) {
            setContentView(R.layout.activity_maximum_decryption_processing)
        } else {
            setContentView(R.layout.activity_maximum_encryption_processing)
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                Log.d(TAG, "[BACK_PRESSED] User cancelled process. Returning safely.")
                clearPayload()
                finish()
            }
        })

        if (savedInstanceState == null && !isProcessingStarted) {
            isProcessingStarted = true
            startCryptoProcess()
        }
    }

    private fun startCryptoProcess() {
        lifecycleScope.launch(Dispatchers.IO) {
            Log.d(TAG, "[START_PROCESS] Launching crypto thread")
            val payload = consumePayload()

            if (payload == null) {
                Log.e(TAG, "[ERROR] Payload is missing or already processed. Aborting activity.")
                withContext(Dispatchers.Main) {
                    if (!isFinishing && !isDestroyed) {
                        Toast.makeText(
                            this@MaximumEncryptionProcessingActivity,
                            "Missing encryption/decryption payload. Please try again.",
                            Toast.LENGTH_LONG
                        ).show()
                        finish()
                    }
                }
                return@launch
            }

            val inputChars = payload.text
            val passwordChars = payload.password
            val isDecrypt = payload.isDecrypt

            Log.d(
                TAG,
                "[PAYLOAD_INFO] Input length: ${inputChars.size}, Password length: ${passwordChars.size}, Mode: ${if (isDecrypt) "Decryption" else "Encryption"}"
            )

            var encryptedBytes: ByteArray? = null
            var encodedBytes: ByteArray? = null
            var tempFile: File? = null

            try {
                val engine = MaxTextEncryptionEngine()

                if (isDecrypt) {
                    Log.i(TAG, "[PROCESSING] Starting Decryption Process...")

                    val rawInputString = String(inputChars).trim()
                    encryptedBytes = try {
                        Base64.decode(rawInputString, Base64.URL_SAFE or Base64.DEFAULT)
                    } catch (e: Exception) {
                        Log.e(TAG, "[DECRYPT_ERROR] Base64 decoding failed", e)
                        throw IllegalArgumentException("Invalid Base64 encrypted input format", e)
                    }

                    var decryptedResultChars: CharArray? = null

                    engine.decryptAndConsume(encryptedBytes, passwordChars) { decryptedChars ->
                        decryptedResultChars = decryptedChars.copyOf()
                    }

                    val finalResult = decryptedResultChars
                    if (finalResult == null) {
                        Log.e(TAG, "[DECRYPT_ERROR] Incorrect password or corrupted data.")
                        throw GeneralSecurityException("Decryption failed. Incorrect password or corrupted payload.")
                    }

                    val resultBytes = String(finalResult).toByteArray(Charsets.UTF_8)
                    try {
                        tempFile = createTemporaryFile(resultBytes)
                    } finally {
                        resultBytes.fill(0)
                        finalResult.fill('\u0000')
                        decryptedResultChars?.fill('\u0000')
                    }

                } else {
                    Log.i(TAG, "[PROCESSING] Starting Encryption Process...")

                    encryptedBytes = engine.encrypt(inputChars, passwordChars)
                    encodedBytes = Base64.encode(
                        encryptedBytes,
                        Base64.URL_SAFE or Base64.NO_WRAP
                    )

                    tempFile = createTemporaryFile(encodedBytes)
                }

                val targetFile = tempFile
                if (targetFile == null || !targetFile.exists()) {
                    throw IllegalStateException("Failed to create temporary output file.")
                }

                Log.i(TAG, "[SUCCESS] Operation complete. Temporary file ready: ${targetFile.absolutePath}")

                withContext(Dispatchers.Main) {
                    if (!isFinishing && !isDestroyed) {
                        val targetActivityClass = if (isDecrypt) {
                            MaximumDecryptionResultActivity::class.java
                        } else {
                            MaximumEncryptionResultActivity::class.java
                        }

                        val intent = Intent(
                            this@MaximumEncryptionProcessingActivity,
                            targetActivityClass
                        ).apply {
                            putExtra(MaximumEncryptionResultActivity.EXTRA_TEMP_FILE_PATH, targetFile.absolutePath)
                            putExtra(MaximumEncryptionResultActivity.EXTRA_FILE_NAME, targetFile.name)
                        }

                        startActivity(intent)
                        finish()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "[PROCESSING_FAILED] Exception during crypto operation", e)

                try {
                    tempFile?.delete()
                } catch (cleanupEx: Exception) {
                    Log.w(TAG, "[CLEANUP_WARN] Failed to delete temp file", cleanupEx)
                }

                withContext(Dispatchers.Main) {
                    if (!isFinishing && !isDestroyed) {
                        val actionName = if (isDecrypt) "Decryption" else "Encryption"
                        Toast.makeText(
                            this@MaximumEncryptionProcessingActivity,
                            "$actionName failed: ${e.localizedMessage}",
                            Toast.LENGTH_LONG
                        ).show()
                        finish()
                    }
                }
            } finally {
                Log.d(TAG, "[SECURE_CLEANUP] Wiping sensitive data buffers from RAM.")
                inputChars.fill('\u0000')
                passwordChars.fill('\u0000')
                encryptedBytes?.fill(0)
                encodedBytes?.fill(0)
                clearPayload()
                System.gc()
            }
        }
    }

    private fun createTemporaryFile(payloadBytes: ByteArray): File {
        val tempFile = File(cacheDir, generateRandomFileName())

        FileOutputStream(tempFile).use { outputStream ->
            outputStream.write(payloadBytes)
            outputStream.flush()
        }

        return tempFile
    }

    private fun generateRandomFileName(): String {
        val random = SecureRandom()
        val builder = StringBuilder(RANDOM_FILE_NAME_LENGTH)

        repeat(RANDOM_FILE_NAME_LENGTH) {
            builder.append(CHAR_ALPHABET[random.nextInt(CHAR_ALPHABET.length)])
        }

        return builder.toString() + TEMP_FILE_EXTENSION
    }

    override fun onDestroy() {
        Log.d(TAG, "[ON_DESTROY] Activity destroyed.")
        super.onDestroy()
    }
}