package com.example.lock

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class DecryptionResultActivity : AppCompatActivity() {

    private lateinit var tvResult: TextView
    private lateinit var btnCopy: Button
    private lateinit var btnClose: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layoutId = resources.getIdentifier("activity_decryption_result", "layout", packageName)
        setContentView(layoutId)

        initViews()

        val decryptedText = intent.getStringExtra("EXTRA_DECRYPTED_TEXT") ?: ""
        tvResult.text = decryptedText

        setupListeners(decryptedText)
    }

    private fun initViews() {
        val tvResultId = resources.getIdentifier("tvResultText", "id", packageName)
        val btnCopyId = resources.getIdentifier("btnCopy", "id", packageName)
        val btnCloseId = resources.getIdentifier("btnClose", "id", packageName)

        tvResult = findViewById(tvResultId)
        btnCopy = findViewById(btnCopyId)
        btnClose = findViewById(btnCloseId)
    }

    private fun setupListeners(resultText: String) {
        btnCopy.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Decrypted Output", resultText)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show()
        }

        btnClose.setOnClickListener {
            finish()
        }
    }
}