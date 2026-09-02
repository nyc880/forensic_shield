package com.example.lock

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import java.security.SecureRandom
import java.io.File
import java.io.FileOutputStream

import com.example.lock.crypto.MediumShortEncryptionEngine
import com.example.lock.crypto.MaxTextEncryptionEngine

class TextEncryptionActivity : AppCompatActivity() {

    private val TAG = "TextCryptoActivityDiagnostics"

    private lateinit var mainTextBox: EditText
    private lateinit var inputPassword: EditText
    private lateinit var btnCopy: Button
    private lateinit var btnPaste: Button
    private lateinit var btnClear: Button
    private lateinit var btnShare: MaterialCardView
    private lateinit var btnEncrypt: MaterialCardView
    private lateinit var btnDecrypt: MaterialCardView
    private lateinit var btnSave: MaterialCardView
    private lateinit var btnImport: MaterialCardView

    private lateinit var rgEncryptionTier: RadioGroup
    private lateinit var rbMediumShort: RadioButton
    private lateinit var rbMaximum: RadioButton

    private lateinit var mediumShortEngine: MediumShortEncryptionEngine
    private lateinit var maxEngine: MaxTextEncryptionEngine

    private lateinit var filePickerLauncher: ActivityResultLauncher<Intent>

    private var importedPayload: String? = null
    private var pendingEncryptedPayload: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_text_encryption)

        Log.d(TAG, "[LIFECYCLE] onCreate invoked")

        mediumShortEngine = MediumShortEncryptionEngine()
        maxEngine = MaxTextEncryptionEngine()

        initViews()
        initFilePicker()
        setupListeners()
    }

    private fun initViews() {
        mainTextBox = findViewById(R.id.main_text_box)
        inputPassword = findViewById(R.id.input_password)
        btnCopy = findViewById(R.id.btn_copy)
        btnPaste = findViewById(R.id.btn_paste)
        btnClear = findViewById(R.id.btn_clear)
        btnShare = findViewById(R.id.btn_share)
        btnEncrypt = findViewById(R.id.btn_encrypt)
        btnDecrypt = findViewById(R.id.btn_decrypt)
        btnSave = findViewById(R.id.btn_save)
        btnImport = findViewById(R.id.btn_import)

        rgEncryptionTier = findViewById(R.id.rg_encryption_tier)
        rbMediumShort = findViewById(R.id.rb_medium_short)
        rbMaximum = findViewById(R.id.rb_maximum)
    }

    private fun initFilePicker() {
        filePickerLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                result.data?.data?.let { uri ->
                    readImportedFileContent(uri)
                }
            }
        }
    }

    private fun setupListeners() {
        rbMaximum.setOnClickListener {
            openMaximumEncryptionModule()
        }

        btnClear.setOnClickListener {
            mainTextBox.text.clear()
            importedPayload = null
            pendingEncryptedPayload = null
            Toast.makeText(this, "Memory and UI cleared", Toast.LENGTH_SHORT).show()
        }

        btnCopy.setOnClickListener {
            val textToCopy = if (!pendingEncryptedPayload.isNullOrEmpty()) pendingEncryptedPayload else mainTextBox.text.toString()
            if (!textToCopy.isNullOrEmpty()) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("EncryptedText", textToCopy)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Nothing to copy", Toast.LENGTH_SHORT).show()
            }
        }

        btnPaste.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            if (clipboard.hasPrimaryClip() && clipboard.primaryClip?.itemCount ?: 0 > 0) {
                val pastedText = clipboard.primaryClip?.getItemAt(0)?.text.toString()
                mainTextBox.setText(pastedText)
                importedPayload = null
                pendingEncryptedPayload = null
            }
        }

        btnShare.setOnClickListener {
            val textToProcess = if (!pendingEncryptedPayload.isNullOrEmpty()) pendingEncryptedPayload else mainTextBox.text.toString()
            if (!textToProcess.isNullOrEmpty()) {
                shareTextAsEncTxt(textToProcess)
            } else {
                Toast.makeText(this, "Nothing to share", Toast.LENGTH_SHORT).show()
            }
        }

        btnEncrypt.setOnClickListener {
            Log.i(TAG, "[UI_EVENT] Encrypt Button Clicked")
            processEncryptionAction(isEncrypt = true)
        }

        btnDecrypt.setOnClickListener {
            Log.i(TAG, "[UI_EVENT] Decrypt Button Clicked")
            processEncryptionAction(isEncrypt = false)
        }

        btnSave.setOnClickListener {
            val textToSave = if (!pendingEncryptedPayload.isNullOrEmpty()) pendingEncryptedPayload else mainTextBox.text.toString()
            if (!textToSave.isNullOrEmpty()) {
                saveTextToEncTxtFile(textToSave)
            } else {
                Toast.makeText(this, "Nothing to save", Toast.LENGTH_SHORT).show()
            }
        }

        btnImport.setOnClickListener {
            Log.i(TAG, "[UI_EVENT] Import Button Clicked. Launching system document provider.")
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }
            filePickerLauncher.launch(intent)
        }
    }

    private fun openMaximumEncryptionModule() {
        Log.i(TAG, "[UI_EVENT] Maximum Encrypt selected. Routing to Maximum module.")

        rbMediumShort.isChecked = true

        try {
            Class.forName("$packageName.MaximumTextEncryptionActivity")

            val intent = Intent().setClassName(
                this,
                "$packageName.MaximumTextEncryptionActivity"
            )
            startActivity(intent)
        } catch (_: ClassNotFoundException) {
            Toast.makeText(
                this,
                "Maximum Encryption module is not ready yet",
                Toast.LENGTH_SHORT
            ).show()
        } catch (e: Exception) {
            Log.e(TAG, "[NAVIGATION] Failed to open Maximum Encryption module", e)
            Toast.makeText(
                this,
                "Unable to open Maximum Encryption module",
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    private fun readImportedFileContent(uri: Uri) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "[FILE_SYSTEM] Opening InputStream to extract encrypted stream data payload.")
                contentResolver.openInputStream(uri)?.use { inputStream ->
                    val fileBytes = inputStream.readBytes()
                    val encryptedPayloadString = String(fileBytes, Charsets.UTF_8).trim()

                    importedPayload = encryptedPayloadString
                    pendingEncryptedPayload = encryptedPayloadString

                    withContext(Dispatchers.Main) {
                        if (!isFinishing && !isDestroyed) {
                            mainTextBox.setText("🔒 [Encrypted File Loaded - Enter Password and press DECRYPT]")
                            Toast.makeText(this@TextEncryptionActivity, "Encrypted payload loaded to memory", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "[FILE_SYSTEM] Critical error parsing imported stream matrix entity structure", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@TextEncryptionActivity, "Failed to load document: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun validatePassword(): CharArray? {
        val pass = inputPassword.text.toString()
        if (pass.isEmpty()) {
            Toast.makeText(this, "Password field cannot be empty", Toast.LENGTH_SHORT).show()
            return null
        }
        return pass.toCharArray()
    }

    private fun processEncryptionAction(isEncrypt: Boolean) {
        val passwordChars = validatePassword() ?: run {
            Log.w(TAG, "[VALIDATION] Password character conversion failed or empty.")
            return
        }

        Log.d(TAG, "[COROUTINE] Launching lifecycleScope block. Active Thread: ${Thread.currentThread().name}")

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "[COROUTINE_RUN] Scope started successfully.")

                if (isEncrypt) {
                    val targetText = withContext(Dispatchers.Main) { mainTextBox.text.toString() }
                    if (targetText.isEmpty() || targetText.startsWith("🔒 [Encrypted File Loaded")) {
                        withContext(Dispatchers.Main) {
                            Toast.makeText(this@TextEncryptionActivity, "Invalid target text for encryption", Toast.LENGTH_SHORT).show()
                        }
                        return@launch
                    }

                    if (rbMaximum.isChecked) {
                        Log.i(TAG, "[EXECUTION] Max Mode Selected. Preparing to encrypt payload.")
                        val plainChars = targetText.toCharArray()

                        Log.d(TAG, "[ENGINE_CALL] Invoking maxEngine.encrypt")
                        val encryptedBytes = maxEngine.encrypt(plainChars, passwordChars)
                        plainChars.fill('\u0000')

                        Log.d(TAG, "[POST_PROCESS] Converting binary structure to Base64")
                        val encryptedBase64 = Base64.encodeToString(encryptedBytes, Base64.URL_SAFE or Base64.NO_WRAP)

                        pendingEncryptedPayload = encryptedBase64

                        withContext(Dispatchers.Main) {
                            if (!isFinishing && !isDestroyed) {
                                mainTextBox.setText("🔒 [Encryption Completed in Maximum Mode - Ready to Share or Save as TXT]")
                                Toast.makeText(this@TextEncryptionActivity, "Encrypted successfully in memory", Toast.LENGTH_LONG).show()
                            }
                        }
                    } else {
                        Log.i(TAG, "[EXECUTION] MediumShort Mode Selected. Invoking encryption engine.")
                        val encryptedText = mediumShortEngine.encrypt(targetText, passwordChars)

                        pendingEncryptedPayload = encryptedText

                        withContext(Dispatchers.Main) {
                            if (!isFinishing && !isDestroyed) {
                                mainTextBox.setText(encryptedText)
                                Toast.makeText(this@TextEncryptionActivity, "Encryption Successful", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                } else {
                    Log.i(TAG, "[EXECUTION] Decryption Sequence Triggered.")
                    val cipherSource = importedPayload ?: withContext(Dispatchers.Main) { mainTextBox.text.toString() }

                    if (cipherSource.isEmpty() || cipherSource.startsWith("🔒 [Encrypted File Loaded")) {
                        withContext(Dispatchers.Main) {
                            Toast.makeText(this@TextEncryptionActivity, "No encrypted target available", Toast.LENGTH_SHORT).show()
                        }
                        return@launch
                    }

                    var decryptedText: String? = null
                    var isMaxSuccessful = false

                    try {
                        Log.d(TAG, "[DECRYPT_FLOW] Parsing Base64 payload structure.")
                        val decodedBytes = Base64.decode(cipherSource, Base64.URL_SAFE or Base64.NO_WRAP)
                        if (decodedBytes.isNotEmpty()) {
                            val version = decodedBytes[0]
                            Log.d(TAG, "[DECRYPT_FLOW] Magic / Version byte detected: $version")

                            if (version == 0x07.toByte()) {
                                Log.d(TAG, "[DECRYPT_FLOW] Routing to MediumShort engine decryptor.")
                                decryptedText = mediumShortEngine.decrypt(cipherSource, passwordChars)
                                if (decryptedText != null) {
                                    withContext(Dispatchers.Main) { rbMediumShort.isChecked = true }
                                }
                            }

                            if (decryptedText == null) {
                                if (rbMaximum.isChecked || version != 0x07.toByte()) {
                                    Log.d(TAG, "[DECRYPT_FLOW] Routing to Maximum Crypto engine decryptor block.")
                                    maxEngine.decryptAndConsume(decodedBytes, passwordChars) { decryptedChars ->
                                        decryptedText = String(decryptedChars)
                                        isMaxSuccessful = true
                                    }
                                    if (isMaxSuccessful) {
                                        withContext(Dispatchers.Main) { rbMaximum.isChecked = true }
                                    }
                                }

                                if (decryptedText == null && !rbMaximum.isChecked && version != 0x07.toByte()) {
                                    Log.d(TAG, "[DECRYPT_FLOW] Fallback matching triggered for MediumShort engine.")
                                    decryptedText = mediumShortEngine.decrypt(cipherSource, passwordChars)
                                    if (decryptedText != null) {
                                        withContext(Dispatchers.Main) { rbMediumShort.isChecked = true }
                                    }
                                }
                            }
                        }
                    } catch (innerEx: Exception) {
                        Log.e(TAG, "[DECRYPT_FLOW] Exception caught during internal processing routing structure", innerEx)
                    }

                    withContext(Dispatchers.Main) {
                        if (!isFinishing && !isDestroyed) {
                            if (decryptedText != null) {
                                Log.d(TAG, "[UI_UPDATE] Decryption sequence successful. Restoring plaintext to view.")
                                mainTextBox.setText(decryptedText)
                                importedPayload = null
                                Toast.makeText(this@TextEncryptionActivity, "Decryption Successful", Toast.LENGTH_SHORT).show()
                            } else {
                                Log.w(TAG, "[DECRYPT_FLOW] Integrity validation failed. Decrypted text references null.")
                                Toast.makeText(this@TextEncryptionActivity, "Decryption Failed: Invalid key or corrupted data", Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "[COROUTINE_CRASH] Unhandled exception in processing thread scope!", e)
                withContext(Dispatchers.Main) {
                    if (!isFinishing && !isDestroyed) {
                        Toast.makeText(this@TextEncryptionActivity, "Process Error: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            } finally {
                Log.d(TAG, "[MEMORY_CLEANUP] Finally block executed. Wiping critical memory references.")
                passwordChars.fill('\u0000')

                withContext(Dispatchers.Main) {
                    if (!isFinishing && !isDestroyed) {
                        inputPassword.text.clear()
                    }
                }
            }
        }
    }

    private fun saveTextToEncTxtFile(textPayload: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val txtFile = generateEncTxtFileStructure(textPayload, isTemporary = false)
                withContext(Dispatchers.Main) {
                    if (txtFile != null) {
                        Toast.makeText(this@TextEncryptionActivity, "Saved to: ${txtFile.absolutePath}", Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(this@TextEncryptionActivity, "Failed to write ENC TXT file structure", Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "[TXT_EXPORT] Execution error compiling stream data into file container", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@TextEncryptionActivity, "Error saving: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun shareTextAsEncTxt(textPayload: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val tempFile = generateEncTxtFileStructure(textPayload, isTemporary = true)
                if (tempFile != null) {
                    withContext(Dispatchers.Main) {
                        val contentUri = FileProvider.getUriForFile(
                            this@TextEncryptionActivity,
                            "${packageName}.fileprovider",
                            tempFile
                        )

                        val intent = Intent(Intent.ACTION_SEND).apply {
                            type = "application/octet-stream"
                            putExtra(Intent.EXTRA_STREAM, contentUri)
                            putExtra(Intent.EXTRA_TITLE, tempFile.name)
                            putExtra(Intent.EXTRA_SUBJECT, tempFile.name)
                            clipData = ClipData.newUri(
                                contentResolver,
                                tempFile.name,
                                contentUri
                            )
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }

                        startActivity(Intent.createChooser(intent, "Share Encrypted TXT Via"))
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "[SHARE_SYSTEM] Failed to invoke document container provider proxy link allocation", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@TextEncryptionActivity, "Sharing failed: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun generateEncTxtFileStructure(text: String, isTemporary: Boolean): File? {
        val targetFile: File
        if (isTemporary) {
            targetFile = File(cacheDir, generateRandomEncTxtFileName())
        } else {
            val rootDir = Environment.getExternalStorageDirectory()
            val encDir = File(rootDir, "ENC/text ENC")
            if (!encDir.exists()) {
                val isCreated = encDir.mkdirs()
                if (!isCreated) {
                    return null
                }
            }
            targetFile = File(encDir, generateRandomEncTxtFileName())
        }

        return try {
            FileOutputStream(targetFile).use { outputStream ->
                outputStream.write(text.toByteArray(Charsets.UTF_8))
            }
            targetFile
        } catch (e: Exception) {
            Log.e(TAG, "[FILE_WRITE] Error writing raw text to enc.txt structure", e)
            null
        }
    }

    private fun generateRandomEncTxtFileName(): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        val secureRandom = SecureRandom()
        val randomName = StringBuilder(20)

        repeat(20) {
            randomName.append(alphabet[secureRandom.nextInt(alphabet.length)])
        }

        return randomName.toString() + ".enc.txt"
    }
}