package com.example.lock.text_encrypt

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.WindowManager
import android.widget.Button
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.card.MaterialCardView
import com.google.android.material.textfield.TextInputEditText

class MaximumTextDecryptionActivity : AppCompatActivity() {

    private var txtSelectedFile: TextView? = null
    private var btnBrowseFile: Button? = null
    private var btnClearFile: Button? = null
    private var inputPassword: TextInputEditText? = null
    private var btnDecryptAction: MaterialCardView? = null

    private var rbMediumShort: RadioButton? = null
    private var rbMaximum: RadioButton? = null
    private var rgMaximumAction: RadioGroup? = null
    private var rbMaxEncrypt: RadioButton? = null
    private var rbMaxDecrypt: RadioButton? = null

    private var selectedFileContent: String? = null

    private val selectFileLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let { fileUri ->
            try {
                contentResolver.openInputStream(fileUri)?.use { inputStream ->
                    selectedFileContent = inputStream.bufferedReader().use { it.readText() }
                }
                val fileName = getFileName(fileUri) ?: "Selected File"
                txtSelectedFile?.text = fileName
            } catch (e: Exception) {
                Toast.makeText(this, "Error reading file: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun getResId(name: String, type: String = "id"): Int {
        return resources.getIdentifier(name, type, packageName)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContentView(getResId("activity_maximum_text_decryption", "layout"))

        initViews()
        setupInitialState()
        setupListeners()
    }

    private fun initViews() {
        txtSelectedFile = findViewById(getResId("txt_selected_file"))
        btnBrowseFile = findViewById(getResId("btn_browse_file"))
        btnClearFile = findViewById(getResId("btn_clear_file"))
        inputPassword = findViewById(getResId("input_password"))
        btnDecryptAction = findViewById(getResId("btn_decrypt_action"))

        rbMediumShort = findViewById(getResId("rb_medium_short"))
        rbMaximum = findViewById(getResId("rb_maximum"))
        rgMaximumAction = findViewById(getResId("rg_maximum_action"))
        rbMaxEncrypt = findViewById(getResId("rb_max_encrypt"))
        rbMaxDecrypt = findViewById(getResId("rb_max_decrypt"))
    }

    private fun setupInitialState() {
        rbMaximum?.isChecked = true
        rbMaxDecrypt?.isChecked = true
    }

    private fun setupListeners() {
        rbMediumShort?.setOnClickListener {
            cleanupSensitiveState()
            finish()
        }

        rbMaximum?.setOnClickListener {
            rbMaximum?.isChecked = true
        }

        rgMaximumAction?.setOnCheckedChangeListener { _, checkedId ->
            if (checkedId == getResId("rb_max_encrypt")) {
                val intent = Intent(this, MaximumTextEncryptionActivity::class.java)
                startActivity(intent)
                finish()
            }
        }

        btnBrowseFile?.setOnClickListener {
            selectFileLauncher.launch(
                arrayOf(
                    "text/*",
                    "application/json",
                    "application/pdf"
                )
            )
        }

        btnClearFile?.setOnClickListener {
            cleanupSensitiveState()
            Toast.makeText(this, "Cleared file and password", Toast.LENGTH_SHORT).show()
        }

        btnDecryptAction?.setOnClickListener {
            routeToMaximumProcessingScreen()
        }
    }

    private fun routeToMaximumProcessingScreen() {
        val targetText = selectedFileContent
        val passwordText = inputPassword?.text?.toString() ?: ""

        if (targetText.isNullOrEmpty()) {
            Toast.makeText(this, "Please select a file first", Toast.LENGTH_SHORT).show()
            return
        }

        if (passwordText.isEmpty()) {
            inputPassword?.error = "Password required"
            return
        }

        try {
            val textChars = targetText.toCharArray()
            val passChars = passwordText.toCharArray()

            MaximumEncryptionProcessingActivity.setPayload(
                plainText = textChars,
                password = passChars,
                isDecrypt = true
            )

            textChars.fill('\u0000')
            passChars.fill('\u0000')

            cleanupSensitiveState()

            val intent = Intent(this, MaximumEncryptionProcessingActivity::class.java)
            startActivity(intent)
            finish()
        } catch (e: Exception) {
            Toast.makeText(this, "Error: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun getFileName(uri: Uri): String? {
        var result: String? = null
        if (uri.scheme == "content") {
            val cursor = contentResolver.query(uri, null, null, null, null)
            cursor?.use {
                if (it.moveToFirst()) {
                    val index = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (index != -1) {
                        result = it.getString(index)
                    }
                }
            }
        }
        if (result == null) {
            result = uri.path
            val cut = result?.lastIndexOf('/') ?: -1
            if (cut != -1) {
                result = result?.substring(cut + 1)
            }
        }
        return result
    }

    private fun cleanupSensitiveState() {
        selectedFileContent = null
        txtSelectedFile?.text = "No .enc.txt file selected"
        try {
            inputPassword?.text?.clear()
        } catch (_: Exception) {
        }
    }

    override fun onDestroy() {
        cleanupSensitiveState()
        super.onDestroy()
    }
}