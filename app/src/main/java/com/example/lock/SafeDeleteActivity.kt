package com.example.lock

import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.math.roundToInt

class SafeDeleteActivity : AppCompatActivity() {

    private lateinit var progressBar: ProgressBar
    private lateinit var statusText: TextView
    private lateinit var percentText: TextView
    private lateinit var stageText: TextView
    private lateinit var btnDone: MaterialButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_processing)

        progressBar = findViewById(R.id.progressBar)
        statusText = findViewById(R.id.statusText)
        percentText = findViewById(R.id.percentText)
        stageText = findViewById(R.id.stageText)
        btnDone = findViewById(R.id.btnDone)

        val files = intent.getStringArrayListExtra("SELECTED_FILES") ?: arrayListOf()

        setInitialState()

        btnDone.setOnClickListener {
            val mainIntent = Intent(this, MainActivity::class.java)
            mainIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            startActivity(mainIntent)
            finish()
        }

        executeSafeDelete(files)
    }

    private fun setInitialState() {
        progressBar.visibility = View.VISIBLE
        btnDone.visibility = View.GONE
        stageText.visibility = View.VISIBLE
        percentText.visibility = View.VISIBLE

        progressBar.isIndeterminate = false
        progressBar.max = 100
        progressBar.progress = 0
        percentText.text = "0%"

        statusText.text = "Secure Deleting......"
        statusText.setTextColor(Color.parseColor("#FF1744"))
        stageText.text = "Preparing secure wipe..."
    }

    private fun executeSafeDelete(filePaths: ArrayList<String>) {
        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    val targets = filePaths
                        .map { File(it) }
                        .filter { it.exists() }

                    if (targets.isEmpty()) {
                        false
                    } else {
                        val deletePlan = buildDeletePlan(targets)

                        if (deletePlan.isEmpty()) {
                            false
                        } else {
                            var allSuccess = true
                            val total = deletePlan.size

                            deletePlan.forEachIndexed { index, target ->
                                updateProgress(
                                    processed = index,
                                    total = total,
                                    stage = "Secure deleting ${target.name}..."
                                )

                                val success = safeDeleteTarget(target)

                                if (!success) {
                                    allSuccess = false
                                }

                                updateProgress(
                                    processed = index + 1,
                                    total = total,
                                    stage = "Secure deleting ${target.name}..."
                                )
                            }
                            allSuccess
                        }
                    }
                }

                if (result) {
                    showSuccess()
                } else {
                    showError("Some files could not be securely deleted")
                }

            } catch (e: Exception) {
                showError("Error during secure deletion: ${e.message}")
            }
        }
    }

    private fun buildDeletePlan(files: List<File>): List<File> {
        val plan = mutableListOf<File>()

        for (file in files) {
            if (file.isDirectory) {
                file.walkBottomUp().forEach { child ->
                    plan.add(child)
                }
            } else {
                plan.add(file)
            }
        }
        return plan
    }

    private fun safeDeleteTarget(target: File): Boolean {
        return try {
            if (target.isDirectory) {
                target.delete()
                !target.exists()
            } else {
                val uri = Uri.fromFile(target)
                val sanitized = NistPurgeEngine.sanitizeOriginalFile(this, uri)
                val metaSanitized = MetadataSanitizer.sanitizeMediaStoreAfterDelete(this, target)
                sanitized && metaSanitized && !target.exists()
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun updateProgress(processed: Int, total: Int, stage: String) {
        val percent = if (total <= 0) {
            0
        } else {
            ((processed.toDouble() / total.toDouble()) * 100.0).roundToInt()
        }

        runOnThread {
            progressBar.progress = percent.coerceIn(0, 100)
            percentText.text = "${percent.coerceIn(0, 100)}%"
            stageText.text = stage
        }
    }

    private fun runOnThread(block: () -> Unit) {
        runOnUiThread(block)
    }

    private fun showSuccess() {
        progressBar.visibility = View.GONE
        statusText.setTextColor(Color.parseColor("#00FF66"))
        statusText.text = "Secure Deletion Completed Successfully"
        percentText.text = "100%"
        stageText.text = "Completed successfully"
        btnDone.visibility = View.VISIBLE
        btnDone.text = "DONE"
    }

    private fun showError(msg: String) {
        progressBar.visibility = View.GONE
        statusText.setTextColor(Color.parseColor("#FF3D00"))
        statusText.text = "Error"
        stageText.text = msg
        btnDone.visibility = View.VISIBLE
        btnDone.text = "BACK"
    }
}