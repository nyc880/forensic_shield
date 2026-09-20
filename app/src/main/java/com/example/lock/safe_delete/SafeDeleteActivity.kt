package com.example.lock.safe_delete

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.lock.MainActivity
import com.example.lock.R
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

    private val failedTargets = mutableListOf<String>()

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
                    val deletePlan = buildDeletePlan(filePaths.map { File(it) })

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
                                failedTargets.add(target.name)
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

                if (result) {
                    showSuccess()
                } else {
                    showError(buildErrorMessage())
                }

            } catch (e: Exception) {
                showError("Error during secure deletion: ${e.message}")
            }
        }
    }

    /**
     * Keeps top-level user selections intact; directories are handled
     * recursively by SecureDelete.deleteTree.
     */
    private fun buildDeletePlan(files: List<File>): List<File> {
        return files.filter { it.exists() }
    }

    private fun safeDeleteTarget(target: File): Boolean {
        return try {
            if (target.isDirectory) {
                SecureDelete.deleteTree(this, target)
            } else {
                // Report API: the engine logs overwrite / verify / delete / gone
                // under the "SecureDeleteEngine" tag for each file.
                SecureDelete.deleteFileWithReport(this, target).success
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun buildErrorMessage(): String {
        if (failedTargets.isEmpty()) return "Some files could not be securely deleted"
        val shown = failedTargets.take(5).joinToString(", ")
        val extra = if (failedTargets.size > 5) " (+${failedTargets.size - 5} more)" else ""
        return "Not fully deleted: $shown$extra"
    }

    private fun updateProgress(processed: Int, total: Int, stage: String) {
        val percent = if (total <= 0) {
            0
        } else {
            ((processed.toDouble() / total.toDouble()) * 100.0).roundToInt()
        }

        runOnUiThread {
            progressBar.progress = percent.coerceIn(0, 100)
            percentText.text = "${percent.coerceIn(0, 100)}%"
            stageText.text = stage
        }
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
