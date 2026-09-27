package com.example.lock

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MetadataReportActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_metadata_report)

        val summaryText = findViewById<TextView>(R.id.report_summary)
        val itemsContainer = findViewById<LinearLayout>(R.id.report_items)
        val items = intent.getStringArrayListExtra("REPORT_ITEMS") ?: arrayListOf()

        summaryText.text = intent.getStringExtra("REPORT_SUMMARY") ?: "Metadata purge report"

        items.forEachIndexed { index, item ->
            val itemText = TextView(this).apply {
                text = item
                setTextColor(Color.WHITE)
                textSize = 15f
                setPadding(0, 18, 0, 18)
                setTextIsSelectable(true)
            }
            itemsContainer.addView(itemText)

            if (index < items.lastIndex) {
                val divider = View(this).apply {
                    setBackgroundColor(Color.rgb(70, 70, 70))
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        1
                    )
                }
                itemsContainer.addView(divider)
            }
        }
    }
}
