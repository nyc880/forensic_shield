package com.example.lock

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

class EncryptionSettingsActivity : AppCompatActivity() {

    private lateinit var rootView: View
    private lateinit var tilPassword: TextInputLayout
    private lateinit var tilEngineDropdown: TextInputLayout
    private lateinit var tilSecondPassword: TextInputLayout

    private lateinit var passwordInput: TextInputEditText
    private lateinit var dropdownEngine: AutoCompleteTextView
    private lateinit var secondPasswordInput: TextInputEditText

    private lateinit var dualPasswordCheckBox: MaterialCheckBox
    private lateinit var justZipCheckBox: MaterialCheckBox
    private lateinit var deleteCheckBox: MaterialCheckBox
    private lateinit var startBtn: Button

    enum class EngineType(val display: String, val colorHex: String, val bgHex: String) {
        MAX("max encryption (AES-256 + CHACHA20)", "#FF1744", "#26FF1744"),
        MEDIUM("medium encryption (AES-256)", "#FF9800", "#26FF9800"),
        EASY("easy encryption (CHACHA20)", "#64B5F6", "#2664B5F6")
    }

    private var selectedEngine = EngineType.MAX

    private fun <T : View> bind(idName: String): T {
        val id = resources.getIdentifier(idName, "id", packageName)
        if (id == 0) throw IllegalStateException("Missing id: $idName")
        return findViewById(id)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_encryption_settings)

        rootView = findViewById(android.R.id.content)

        tilPassword = bind("til_password")
        tilEngineDropdown = bind("til_engine_dropdown")
        tilSecondPassword = bind("til_second_password")

        passwordInput = bind("et_password")
        dropdownEngine = bind("dropdown_engine")
        secondPasswordInput = bind("et_second_password")

        dualPasswordCheckBox = bind("cb_dual_password")
        justZipCheckBox = bind("cb_just_zip")
        deleteCheckBox = bind("cb_delete_after")
        startBtn = bind("btn_start")

        val selectedFiles = intent.getStringArrayListExtra("SELECTED_FILES") ?: arrayListOf()

        setupEngineDropdown()
        setupDualPasswordToggle()
        setupHideKeyboardOnBackgroundTap()

        startBtn.setOnClickListener {
            hideKeyboard()
            val password = passwordInput.text?.toString()?.trim().orEmpty()
            val secondPassword = secondPasswordInput.text?.toString()?.trim().orEmpty()

            tilPassword.error = null
            tilSecondPassword.error = null

            if (password.isEmpty()) {
                tilPassword.error = "Please enter password"
                passwordInput.requestFocus()
                return@setOnClickListener
            }
            if (password.length < 4) {
                tilPassword.error = "Password too short (min 4)"
                return@setOnClickListener
            }

            if (dualPasswordCheckBox.isChecked) {
                if (secondPassword.isEmpty()) {
                    tilSecondPassword.error = "Please enter second password"
                    secondPasswordInput.requestFocus()
                    return@setOnClickListener
                }
                if (secondPassword == password) {
                    tilSecondPassword.error = "Second password must be different"
                    return@setOnClickListener
                }
                if (secondPassword.length < 4) {
                    tilSecondPassword.error = "Second password too short"
                    return@setOnClickListener
                }
            }

            val encType = if (justZipCheckBox.isChecked) "JUST_ZIP" else "JUST_FILES"

            val intent = Intent(this, ProcessingActivity::class.java)
            intent.putExtra("MODE", "ENCRYPT")
            intent.putStringArrayListExtra("FILES", selectedFiles)
            intent.putExtra("PASSWORD", password)
            intent.putExtra("SECOND_PASSWORD", if (dualPasswordCheckBox.isChecked) secondPassword else "")
            intent.putExtra("IS_DUAL_PASSWORD", dualPasswordCheckBox.isChecked)
            intent.putExtra("ENGINE_TYPE", selectedEngine.name)
            intent.putExtra("ENC_TYPE", encType)
            intent.putExtra("DELETE_AFTER", deleteCheckBox.isChecked)
            startActivity(intent)
            finish()
        }
    }

    private fun setupEngineDropdown() {
        val items = EngineType.values().map { it.display }
        val adapter = ArrayAdapter(this, android.R.layout.simple_dropdown_item_1line, items)
        dropdownEngine.setAdapter(adapter)

        dropdownEngine.setText(selectedEngine.display, false)
        applyEngineColor(selectedEngine)

        dropdownEngine.setOnItemClickListener { _, _, position, _ ->
            selectedEngine = EngineType.values()[position]
            applyEngineColor(selectedEngine)
        }
    }

    private fun applyEngineColor(type: EngineType) {
        val color = Color.parseColor(type.colorHex)
        val bgColor = Color.parseColor(type.bgHex)

        dropdownEngine.setTextColor(color)
        tilEngineDropdown.boxStrokeColor = color
        tilEngineDropdown.setBoxBackgroundColorStateList(android.content.res.ColorStateList.valueOf(bgColor))
        tilEngineDropdown.setEndIconTintList(android.content.res.ColorStateList.valueOf(color))
    }

    private fun setupDualPasswordToggle() {
        dualPasswordCheckBox.setOnCheckedChangeListener { _, isChecked ->
            tilSecondPassword.visibility = if (isChecked) View.VISIBLE else View.GONE
            if (!isChecked) {
                secondPasswordInput.text?.clear()
                tilSecondPassword.error = null
            }
        }
    }

    private fun setupHideKeyboardOnBackgroundTap() {
        rootView.setOnTouchListener { _, event ->
            if (event.action == MotionEvent.ACTION_DOWN) {
                currentFocus?.clearFocus()
                hideKeyboard()
            }
            false
        }
    }

    private fun hideKeyboard() {
        val imm = getSystemService(INPUT_METHOD_SERVICE) as? InputMethodManager
        val view = currentFocus ?: rootView
        imm?.hideSoftInputFromWindow(view.windowToken, 0)
    }
}
