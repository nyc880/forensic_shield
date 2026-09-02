/*
| Variable Name             | Type             | Description                                                        |
|---------------------------|------------------|--------------------------------------------------------------------|
| encryptBtn                | MaterialCardView | Navigation trigger to open FileBrowserActivity in ENCRYPT mode     |
| decryptBtn                | MaterialCardView | Navigation trigger to open FileBrowserActivity in DECRYPT mode     |
| safeDeleteBtn             | MaterialCardView | Navigation trigger to open FileBrowserActivity in SAFE_DELETE mode |
| textEncryptBtn            | MaterialCardView | Navigation trigger to open TextEncryptionActivity                  |
| metadataBtn               | MaterialCardView | Navigation trigger to open FileBrowserActivity in METADATA mode   |
| safeExitBtn               | MaterialCardView | Triggers the safe exit operation                                   |
*/

package com.example.lock

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import com.google.android.material.card.MaterialCardView
import java.io.File
import java.io.FileOutputStream
import java.util.ArrayList

class MainActivity : AppCompatActivity() {

    private lateinit var encryptBtn: MaterialCardView
    private lateinit var decryptBtn: MaterialCardView
    private lateinit var safeDeleteBtn: MaterialCardView
    private lateinit var textEncryptBtn: MaterialCardView
    private lateinit var metadataBtn: MaterialCardView
    private lateinit var safeExitBtn: MaterialCardView

    override fun onCreate(savedInstanceState: Bundle?) {
        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true)

        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        encryptBtn = findViewById(R.id.encrypt_btn)
        decryptBtn = findViewById(R.id.decrypt_btn)
        safeDeleteBtn = findViewById(R.id.safe_delete_btn)
        textEncryptBtn = findViewById(R.id.text_encrypt_btn)
        metadataBtn = findViewById(R.id.metadata_btn)
        safeExitBtn = findViewById(R.id.safe_exit_btn)

        encryptBtn.setOnClickListener {
            val intent = Intent(this, FileBrowserActivity::class.java)
            intent.putExtra("crypto_mode", "ENCRYPT")
            startActivity(intent)
        }

        decryptBtn.setOnClickListener {
            val intent = Intent(this, FileBrowserActivity::class.java)
            intent.putExtra("crypto_mode", "DECRYPT")
            startActivity(intent)
        }

        safeDeleteBtn.setOnClickListener {
            val intent = Intent(this, FileBrowserActivity::class.java)
            intent.putExtra("crypto_mode", "SAFE_DELETE")
            startActivity(intent)
        }

        textEncryptBtn.setOnClickListener {
            val intent = Intent(this, TextEncryptionActivity::class.java)
            startActivity(intent)
        }

        metadataBtn.setOnClickListener {
            val intent = Intent(this, FileBrowserActivity::class.java)
            intent.putExtra("crypto_mode", "METADATA")
            startActivity(intent)
        }

        safeExitBtn.setOnClickListener {
            SafeExit.performSafeExit(this)
        }

        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val data: Uri? = intent?.data
        if (intent?.action == Intent.ACTION_VIEW && data != null) {
            val filePath = getPathFromUri(data)
            if (filePath != null && filePath.endsWith(".enc", ignoreCase = true)) {
                val decryptIntent = Intent(this, DecryptionSettingsActivity::class.java)
                val fileList = ArrayList<String>()
                fileList.add(filePath)
                decryptIntent.putStringArrayListExtra("SELECTED_FILES", fileList)
                startActivity(decryptIntent)
            }
        }
    }

    private fun getPathFromUri(uri: Uri): String? {
        if (uri.scheme == "file") {
            return uri.path
        } else if (uri.scheme == "content") {
            try {
                var fileName = "temp_received.enc"
                contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIndex != -1 && cursor.moveToFirst()) {
                        val name = cursor.getString(nameIndex)
                        if (!name.isNullOrBlank()) {
                            fileName = name
                        }
                    }
                }

                val tempFile = File(cacheDir, fileName)
                contentResolver.openInputStream(uri)?.use { inputStream ->
                    FileOutputStream(tempFile).use { outputStream ->
                        inputStream.copyTo(outputStream)
                    }
                }
                return tempFile.absolutePath
            } catch (e: Exception) {
                android.util.Log.e("TITAN_ERROR", "Error resolving content URI to temp file: ${e.message}", e)
            }
        }
        return uri.path
    }
}