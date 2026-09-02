package com.example.lock

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.CheckBox
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText

class DecryptionSettingsActivity : AppCompatActivity() {

    private lateinit var rootView: View
    private lateinit var passwordInput: TextInputEditText
    private lateinit var secondPasswordInput: TextInputEditText
    private lateinit var startBtn: MaterialButton
    private lateinit var checkEphemeral: CheckBox

    private fun <T : View> bindId(idName: String): T {
        val id = resources.getIdentifier(idName, "id", packageName)
        if (id == 0) {
            throw IllegalStateException("Missing view id: $idName")
        }
        return findViewById(id)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_decryption_settings)

        rootView = bindId("root_decryption_settings")
        passwordInput = bindId("password_input")
        secondPasswordInput = bindId("second_password_input")
        startBtn = bindId("btn_start_decrypt")
        checkEphemeral = bindId("check_ephemeral")

        val selectedFiles = intent.getStringArrayListExtra("SELECTED_FILES") ?: arrayListOf()

        setupHideKeyboardOnBackgroundTap()

        startBtn.setOnClickListener {
            hideKeyboard()

            val password = passwordInput.text?.toString()?.trim().orEmpty()
            val secondPassword = secondPasswordInput.text?.toString()?.trim().orEmpty()

            if (password.isEmpty()) {
                Toast.makeText(this, "Please enter password", Toast.LENGTH_SHORT).show()
                passwordInput.requestFocus()
                return@setOnClickListener
            }

            val decryptIntent = Intent(this, ProcessingActivity::class.java)
            decryptIntent.putExtra("MODE", "DECRYPT")
            decryptIntent.putStringArrayListExtra("FILES", selectedFiles)
            decryptIntent.putExtra("PASSWORD", password)
            decryptIntent.putExtra("SECOND_DECRYPT_PASSWORD", secondPassword)
            decryptIntent.putExtra("IS_EPHEMERAL", checkEphemeral.isChecked)
            startActivity(decryptIntent)
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
        val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
        val view = currentFocus ?: rootView
        imm?.hideSoftInputFromWindow(view.windowToken, 0)
    }
}
