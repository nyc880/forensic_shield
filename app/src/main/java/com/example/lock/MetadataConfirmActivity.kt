package com.example.lock

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.example.lock.R

class MetadataConfirmActivity : AppCompatActivity() {

    private lateinit var titleText: TextView
    private lateinit var warningText: TextView
    private lateinit var filesCountText: TextView
    private lateinit var btnCancel: MaterialButton
    private lateinit var btnConfirm: MaterialButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_safe_delete_confirm)

        titleText = findViewById(R.id.title_text)
        warningText = findViewById(R.id.warning_text)
        filesCountText = findViewById(R.id.files_count_text)
        btnCancel = findViewById(R.id.btn_cancel)
        btnConfirm = findViewById(R.id.btn_confirm_delete)

        // Read from "SELECTED_FILES" (passed from Browser/Preview)
        val selectedFiles = intent.getStringArrayListExtra("SELECTED_FILES") ?: arrayListOf()
        val count = selectedFiles.size

        titleText.text = "METADATA PURGE"
        titleText.setTextColor(Color.parseColor("#C9A85F"))

        warningText.text = "This will reconstruct the selected files to remove all tracking information, GPS traces, and device identifiers."
        filesCountText.text = "Selected files: $count"

        btnConfirm.text = "YES, PURGE METADATA"
        btnConfirm.setBackgroundColor(Color.parseColor("#FF9800"))
        btnConfirm.setTextColor(Color.BLACK)

        btnCancel.setOnClickListener {
            finish()
        }

        btnConfirm.setOnClickListener {
            val intent = Intent(this, ProcessingActivity::class.java)
            intent.putExtra("MODE", "METADATA_PURGE")
            // Pass to ProcessingActivity as "FILES"
            intent.putStringArrayListExtra("FILES", selectedFiles)
            startActivity(intent)
            finish()
        }
    }
}
