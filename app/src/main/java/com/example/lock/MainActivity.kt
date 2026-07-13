package com.example.lock

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import com.google.android.material.card.MaterialCardView

class MainActivity : AppCompatActivity() {

    private lateinit var encryptBtn: MaterialCardView
    private lateinit var decryptBtn: MaterialCardView
    private lateinit var safeDeleteBtn: MaterialCardView
    private lateinit var textEncryptBtn: MaterialCardView
    private lateinit var metadataBtn: MaterialCardView
    private lateinit var safeExitBtn: MaterialCardView

    override fun onCreate(savedInstanceState: Bundle?) {
        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true)

        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        encryptBtn = findViewById(R.id.encrypt_btn)
        decryptBtn = findViewById(R.id.decrypt_btn)
        safeDeleteBtn = findViewById(R.id.safe_delete_btn)
        textEncryptBtn = findViewById(R.id.text_encrypt_btn)
        metadataBtn = findViewById(R.id.metadata_btn)
        safeExitBtn = findViewById(R.id.safe_exit_btn)

        encryptBtn.setOnClickListener {
            val intent = Intent(this, FileBrowserActivity::class.java)
            intent.putExtra("crypto_mode", "ENCRYPT")
            startActivity(intent)
        }

        decryptBtn.setOnClickListener {
            val intent = Intent(this, FileBrowserActivity::class.java)
            intent.putExtra("crypto_mode", "DECRYPT")
            startActivity(intent)
        }

        safeDeleteBtn.setOnClickListener {
            val intent = Intent(this, FileBrowserActivity::class.java)
            intent.putExtra("crypto_mode", "SAFE_DELETE")
            startActivity(intent)
        }

        textEncryptBtn.setOnClickListener {
            val intent = Intent(this, TextEncryptionActivity::class.java)
            startActivity(intent)
        }

        metadataBtn.setOnClickListener {
            val intent = Intent(this, FileBrowserActivity::class.java)
            intent.putExtra("crypto_mode", "METADATA")
            startActivity(intent)
        }

        safeExitBtn.setOnClickListener {
            SafeExit.performSafeExit(this)
        }
    }
}