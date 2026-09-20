package com.example.lock.safe_delete

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.example.lock.R
import com.google.android.material.button.MaterialButton

class SafeDeleteConfirmActivity : AppCompatActivity() {

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

        val selectedFiles = intent.getStringArrayListExtra("SELECTED_FILES") ?: arrayListOf()
        val count = selectedFiles.size

        titleText.text = "FINAL WARNING"
        titleText.setTextColor(Color.parseColor("#FF3D00"))

        warningText.text = "Are you sure?\nThese files will be deleted forever and cannot be recovered."
        filesCountText.text = "Selected files: $count"

        btnCancel.setOnClickListener {
            finish()
        }

        btnConfirm.setOnClickListener {
            val intent = Intent(this, SafeDeleteActivity::class.java)
            intent.putStringArrayListExtra("SELECTED_FILES", selectedFiles)
            startActivity(intent)
            finish()
        }
    }
}