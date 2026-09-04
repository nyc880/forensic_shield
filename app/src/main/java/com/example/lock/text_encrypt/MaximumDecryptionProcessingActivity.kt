package com.example.lock.text_encrypt

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.lock.DecryptionResultActivity
import com.example.lock.crypto.MaxTextEncryptionEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MaximumDecryptionProcessingActivity : AppCompatActivity() {

    private lateinit var tvStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layoutId = resources.getIdentifier("activity_maximum_encryption_processing", "layout", packageName)
        setContentView(layoutId)

        val tvStatusId = resources.getIdentifier("tvStatus", "id", packageName)
        tvStatus = findViewById(tvStatusId)
        tvStatus.text = "Decrypting... Please wait"

        val ciphertext = intent.getStringExtra("EXTRA_CIPHERTEXT")
        val password = intent.getStringExtra("EXTRA_PASSWORD")

        if (ciphertext.isNullOrEmpty() || password.isNullOrEmpty()) {
            Toast.makeText(this, "Invalid payload or credentials", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        executeDecryption(ciphertext, password)
    }

    private fun executeDecryption(ciphertext: String, password: String) {
        lifecycleScope.launch(Dispatchers.Default) {
            try {
                // Decode Base64 ciphertext into ByteArray and convert password to CharArray
                val packetBytes = Base64.decode(ciphertext, Base64.DEFAULT)
                val passwordChars = password.toCharArray()

                // Instantiate the MaxTextEncryptionEngine class
                val engine = MaxTextEncryptionEngine()

                var isDecrypted = false

                // Call the suspend function with callback consumer
                engine.decryptAndConsume(packetBytes, passwordChars) { decryptedChars ->
                    isDecrypted = true
                    val decryptedText = String(decryptedChars)

                    lifecycleScope.launch(Dispatchers.Main) {
                        val nextIntent = Intent(
                            this@MaximumDecryptionProcessingActivity,
                            DecryptionResultActivity::class.java
                        )
                        nextIntent.putExtra("EXTRA_DECRYPTED_TEXT", decryptedText)
                        startActivity(nextIntent)
                        finish()
                    }
                }

                // If consumer was not called, decryption failed or HMAC was invalid
                if (!isDecrypted) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(
                            this@MaximumDecryptionProcessingActivity,
                            "Decryption failed: Key incorrect or data corrupted.",
                            Toast.LENGTH_LONG
                        ).show()
                        finish()
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@MaximumDecryptionProcessingActivity,
                        "Decryption Error: ${e.localizedMessage}",
                        Toast.LENGTH_LONG
                    ).show()
                    finish()
                }
            }
        }
    }
}