package com.example.lock

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.EditText
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.card.MaterialCardView

class MaximumTextEncryptionActivity : AppCompatActivity() {

    private lateinit var mainTextBox: EditText
    private lateinit var inputPassword: EditText
    private lateinit var btnPaste: android.widget.Button
    private lateinit var btnClear: android.widget.Button
    private lateinit var btnEncrypt: MaterialCardView

    private lateinit var rbMediumShort: RadioButton
    private lateinit var rbMaximum: RadioButton
    private lateinit var rgMaximumAction: RadioGroup
    private lateinit var rbMaxEncrypt: RadioButton
    private lateinit var rbMaxDecrypt: RadioButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContentView(R.layout.activity_maximum_text_encryption)

        initViews()
        setupInitialState()
        setupListeners()
    }

    private fun initViews() {
        mainTextBox = findViewById(R.id.main_text_box)
        inputPassword = findViewById(R.id.input_password)
        btnPaste = findViewById(R.id.btn_paste)
        btnClear = findViewById(R.id.btn_clear)
        btnEncrypt = findViewById(R.id.btn_encrypt)

        rbMediumShort = findViewById(R.id.rb_medium_short)
        rbMaximum = findViewById(R.id.rb_maximum)
        rgMaximumAction = findViewById(R.id.rg_maximum_action)
        rbMaxEncrypt = findViewById(R.id.rb_max_encrypt)
        rbMaxDecrypt = findViewById(R.id.rb_max_decrypt)
    }

    private fun setupInitialState() {
        rbMaximum.isChecked = true
        rbMaxEncrypt.isChecked = true
    }

    private fun setupListeners() {
        rbMediumShort.setOnClickListener {
            cleanupSensitiveState()
            finish()
        }

        rbMaximum.setOnClickListener {
            rbMaximum.isChecked = true
        }

        rgMaximumAction.setOnCheckedChangeListener { _, checkedId ->
            if (checkedId == R.id.rb_max_decrypt) {
                Toast.makeText(
                    this,
                    "Maximum decrypt screen will be added later",
                    Toast.LENGTH_SHORT
                ).show()

                rbMaxEncrypt.isChecked = true
            }
        }

        btnClear.setOnClickListener {
            mainTextBox.text?.clear()
            inputPassword.text?.clear()
            Toast.makeText(this, "Memory and UI cleared", Toast.LENGTH_SHORT).show()
        }

        btnPaste.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            if (clipboard.hasPrimaryClip() && (clipboard.primaryClip?.itemCount ?: 0) > 0) {
                val pastedText = clipboard.primaryClip
                    ?.getItemAt(0)
                    ?.coerceToText(this)
                    ?.toString()

                if (!pastedText.isNullOrEmpty()) {
                    mainTextBox.setText(pastedText)
                }
            } else {
                Toast.makeText(this, "Clipboard is empty", Toast.LENGTH_SHORT).show()
            }
        }

        btnEncrypt.setOnClickListener {
            routeToMaximumProcessingScreen()
        }
    }

    private fun routeToMaximumProcessingScreen() {
        val targetText = mainTextBox.text?.toString() ?: ""
        val passwordText = inputPassword.text?.toString() ?: ""

        if (targetText.isEmpty()) {
            Toast.makeText(this, "Text field cannot be empty", Toast.LENGTH_SHORT).show()
            return
        }

        if (passwordText.isEmpty()) {
            inputPassword.error = "Password required"
            return
        }

        val plainChars = targetText.toCharArray()
        val passwordChars = passwordText.toCharArray()

        try {
            MaximumEncryptionProcessingActivity.setPayload(plainChars, passwordChars)

            mainTextBox.text?.clear()
            inputPassword.text?.clear()

            val intent = Intent(this, MaximumEncryptionProcessingActivity::class.java)
            startActivity(intent)
            finish()
        } finally {
            plainChars.fill('\u0000')
            passwordChars.fill('\u0000')
        }
    }

    private fun cleanupSensitiveState() {
        try {
            mainTextBox.text?.clear()
        } catch (_: Exception) {
        }

        try {
            inputPassword.text?.clear()
        } catch (_: Exception) {
        }
    }

    override fun onDestroy() {
        cleanupSensitiveState()
        super.onDestroy()
    }
}
