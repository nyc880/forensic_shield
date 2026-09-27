package com.example.lock

import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Rect
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity
import com.example.lock.ProcessingActivity
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

class EncryptionSettingsActivity : AppCompatActivity() {

    private lateinit var rootView: View
    private lateinit var tilPassword: TextInputLayout
    private lateinit var tilEngineDropdown: TextInputLayout
    private lateinit var tilSecondPassword: TextInputLayout
    private var tilSecondEngineDropdown: TextInputLayout? = null

    private lateinit var passwordInput: TextInputEditText
    private lateinit var dropdownEngine: AutoCompleteTextView
    private var dropdownSecondEngine: AutoCompleteTextView? = null
    private lateinit var secondPasswordInput: TextInputEditText

    private lateinit var dualPasswordCheckBox: MaterialCheckBox
    private lateinit var justZipCheckBox: MaterialCheckBox
    private lateinit var deleteCheckBox: MaterialCheckBox
    private lateinit var startBtn: Button

    private var isKeyboardOpen = false

    enum class EngineType(val display: String, val colorHex: String, val bgHex: String) {
        MAX("MAX encryption", "#FF1744", "#26FF1744"),
        MEDIUM("MEDIUM encryption", "#FF9800", "#26FF9800"),
        EASY("FAST encryption", "#64B5F6", "#2664B5F6")
    }

    private var selectedEngine = EngineType.MAX
    private var selectedSecondEngine = EngineType.MEDIUM

    private fun <T : View> bind(idName: String): T {
        val id = resources.getIdentifier(idName, "id", packageName)
        if (id == 0) throw IllegalStateException("Missing id: $idName")
        return findViewById(id)
    }

    private fun <T : View> bindOptional(idName: String): T? {
        val id = resources.getIdentifier(idName, "id", packageName)
        if (id == 0) return null
        return findViewById(id)
    }

    private fun nextEngine(current: EngineType): EngineType {
        val values = EngineType.values()
        val idx = values.indexOf(current)
        return values[(idx + 1) % values.size]
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_encryption_settings)

        rootView = findViewById(android.R.id.content)

        tilPassword = bind("til_password")
        tilEngineDropdown = bind("til_engine_dropdown")
        tilSecondPassword = bind("til_second_password")
        tilSecondEngineDropdown = bindOptional("til_second_engine_dropdown")

        passwordInput = bind("et_password")
        dropdownEngine = bind("dropdown_engine")
        dropdownSecondEngine = bindOptional("dropdown_second_engine")
        secondPasswordInput = bind("et_second_password")

        dualPasswordCheckBox = bind("cb_dual_password")
        justZipCheckBox = bind("cb_just_zip")
        deleteCheckBox = bind("cb_delete_after")
        startBtn = bind("btn_start")

        val selectedFiles = intent.getStringArrayListExtra("SELECTED_FILES") ?: arrayListOf()

        setupEngineDropdown()
        setupSecondEngineDropdown()
        setupDualPasswordToggle()
        setupKeyboardCloseListener()

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
            }

            val encType = if (justZipCheckBox.isChecked) "JUST_ZIP" else "JUST_FILES"

            val secondEngineToUse = if (dualPasswordCheckBox.isChecked) {
                if (dropdownSecondEngine != null && tilSecondEngineDropdown?.visibility == View.VISIBLE) {
                    selectedSecondEngine
                } else {
                    var auto = nextEngine(selectedEngine)
                    if (auto == selectedEngine) auto = EngineType.values().first { it != selectedEngine }
                    auto
                }
            } else {
                selectedEngine
            }

            if (dualPasswordCheckBox.isChecked && secondEngineToUse == selectedEngine) {
                val auto = nextEngine(selectedEngine)
                selectedSecondEngine = auto
            }

            val finalSecondEngine = if (dualPasswordCheckBox.isChecked) {
                if (dropdownSecondEngine != null && tilSecondEngineDropdown?.visibility == View.VISIBLE) selectedSecondEngine else nextEngine(selectedEngine)
            } else selectedEngine

            val intent = Intent(this, ProcessingActivity::class.java)
            intent.putExtra("MODE", "ENCRYPT")
            intent.putStringArrayListExtra("FILES", selectedFiles)
            intent.putExtra("PASSWORD", password)
            intent.putExtra("SECOND_PASSWORD", if (dualPasswordCheckBox.isChecked) secondPassword else "")
            intent.putExtra("IS_DUAL_PASSWORD", dualPasswordCheckBox.isChecked)
            intent.putExtra("ENGINE_TYPE", selectedEngine.name)
            intent.putExtra("SECOND_ENGINE_TYPE", finalSecondEngine.name)
            intent.putExtra("ENC_TYPE", encType)
            intent.putExtra("DELETE_AFTER", deleteCheckBox.isChecked)
            startActivity(intent)
            finish()
        }
    }

    override fun dispatchTouchEvent(ev: MotionEvent?): Boolean {
        if (ev?.action == MotionEvent.ACTION_DOWN) {
            val v = currentFocus
            if (v is TextInputEditText || v is AutoCompleteTextView) {
                val outRect = Rect()
                v.getGlobalVisibleRect(outRect)
                if (!outRect.contains(ev.rawX.toInt(), ev.rawY.toInt())) {
                    v.clearFocus()
                    hideKeyboard()
                }
            }
        }
        return super.dispatchTouchEvent(ev)
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
            if (dualPasswordCheckBox.isChecked && dropdownSecondEngine == null) {
                selectedSecondEngine = nextEngine(selectedEngine)
            }
            if (dropdownSecondEngine != null) {
                updateSecondEngineOptions()
            }
        }
    }

    private fun setupSecondEngineDropdown() {
        val dd = dropdownSecondEngine ?: return
        val til = tilSecondEngineDropdown ?: return
        val items = EngineType.values().map { it.display }
        val adapter = ArrayAdapter(this, android.R.layout.simple_dropdown_item_1line, items)
        dd.setAdapter(adapter)
        selectedSecondEngine = nextEngine(selectedEngine)
        dd.setText(selectedSecondEngine.display, false)
        applySecondEngineColor(selectedSecondEngine)
        dd.setOnItemClickListener { _, _, position, _ ->
            selectedSecondEngine = EngineType.values()[position]
            applySecondEngineColor(selectedSecondEngine)
        }
        til.visibility = if (dualPasswordCheckBox.isChecked) View.VISIBLE else View.GONE
    }

    private fun updateSecondEngineOptions() {
        val dd = dropdownSecondEngine ?: return
        if (selectedSecondEngine == selectedEngine) {
            selectedSecondEngine = nextEngine(selectedEngine)
            dd.setText(selectedSecondEngine.display, false)
            applySecondEngineColor(selectedSecondEngine)
        }
    }

    private fun applyEngineColor(type: EngineType) {
        val color = Color.parseColor(type.colorHex)
        val bgColor = Color.parseColor(type.bgHex)
        val colorState = ColorStateList.valueOf(color)
        val bgState = ColorStateList.valueOf(bgColor)

        dropdownEngine.setTextColor(color)
        tilEngineDropdown.boxStrokeColor = color
        tilEngineDropdown.setBoxBackgroundColorStateList(bgState)
        tilEngineDropdown.setEndIconTintList(colorState)

        tilPassword.boxStrokeColor = color
        tilPassword.setBoxBackgroundColorStateList(bgState)
        tilPassword.hintTextColor = colorState
        tilPassword.defaultHintTextColor = colorState
        tilPassword.setEndIconTintList(colorState)
    }

    private fun applySecondEngineColor(type: EngineType) {
        val dd = dropdownSecondEngine ?: return
        val til = tilSecondEngineDropdown ?: return
        val color = Color.parseColor(type.colorHex)
        val bgColor = Color.parseColor(type.bgHex)
        val colorState = ColorStateList.valueOf(color)
        val bgState = ColorStateList.valueOf(bgColor)
        dd.setTextColor(color)
        til.boxStrokeColor = color
        til.setBoxBackgroundColorStateList(bgState)
        til.setEndIconTintList(colorState)
    }

    private fun setupDualPasswordToggle() {
        dualPasswordCheckBox.setOnCheckedChangeListener { _, isChecked ->
            tilSecondPassword.visibility = if (isChecked) View.VISIBLE else View.GONE
            tilSecondEngineDropdown?.visibility = if (isChecked) View.VISIBLE else View.GONE
            if (!isChecked) {
                secondPasswordInput.text?.clear()
                tilSecondPassword.error = null
            } else {
                if (dropdownSecondEngine == null) {
                    selectedSecondEngine = nextEngine(selectedEngine)
                } else {
                    updateSecondEngineOptions()
                }
            }
        }
    }

    private fun setupKeyboardCloseListener() {
        rootView.viewTreeObserver.addOnGlobalLayoutListener {
            val r = Rect()
            rootView.getWindowVisibleDisplayFrame(r)
            val screenHeight = rootView.rootView.height
            val keypadHeight = screenHeight - r.bottom
            val isOpen = keypadHeight > screenHeight * 0.15
            if (isKeyboardOpen && !isOpen) {
                currentFocus?.clearFocus()
            }
            isKeyboardOpen = isOpen
        }
    }

    private fun hideKeyboard() {
        val imm = getSystemService(INPUT_METHOD_SERVICE) as? InputMethodManager
        val view = currentFocus ?: rootView
        imm?.hideSoftInputFromWindow(view.windowToken, 0)
    }
}
