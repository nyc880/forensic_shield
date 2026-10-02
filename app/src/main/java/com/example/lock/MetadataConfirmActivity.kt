package com.example.lock

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.switchmaterial.SwitchMaterial
import com.example.lock.R

class MetadataConfirmActivity : AppCompatActivity() {

    private lateinit var titleText: TextView
    private lateinit var warningText: TextView
    private lateinit var filesCountText: TextView
    private lateinit var safeDeleteSwitch: SwitchMaterial
    private lateinit var btnCancel: MaterialButton
    private lateinit var btnConfirm: MaterialButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_metadata_confirm)

        titleText = findViewById(R.id.title_text)
        warningText = findViewById(R.id.warning_text)
        filesCountText = findViewById(R.id.files_count_text)
        safeDeleteSwitch = findViewById(R.id.switch_safe_delete)
        btnCancel = findViewById(R.id.btn_cancel)
        btnConfirm = findViewById(R.id.btn_confirm_delete)

        val selectedFiles = intent.getStringArrayListExtra("SELECTED_FILES") ?: arrayListOf()
        val count = selectedFiles.size

        titleText.text = "METADATA PURGE"
        titleText.setTextColor(Color.parseColor("#C9A85F"))

        warningText.text = "A cleaned copy will be written to (no-meta) folder."
        filesCountText.text = "Selected files: $count"

        safeDeleteSwitch.isChecked = false
        safeDeleteSwitch.isEnabled = true
        safeDeleteSwitch.text = "Safe delete original files"

        btnConfirm.text = "CREATE CLEAN COPIES"
        safeDeleteSwitch.setOnCheckedChangeListener { _, checked ->
            btnConfirm.text = if (checked) {
                "CREATE AND SECURELY DELETE"
            } else {
                "CREATE CLEAN COPIES"
            }
        }
        btnConfirm.setBackgroundColor(Color.parseColor("#FF9800"))
        btnConfirm.setTextColor(Color.BLACK)

        btnCancel.setOnClickListener {
            finish()
        }

        btnConfirm.setOnClickListener {
            val processingIntent = Intent(this, ProcessingActivity::class.java)
            processingIntent.putExtra("MODE", "METADATA_PURGE")
            processingIntent.putStringArrayListExtra("FILES", selectedFiles)
            processingIntent.putExtra("SAFE_DELETE_ORIGINAL", safeDeleteSwitch.isChecked)
            startActivity(processingIntent)
            finish()
        }
    }
}
