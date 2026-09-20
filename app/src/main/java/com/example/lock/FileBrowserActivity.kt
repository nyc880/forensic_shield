package com.example.lock

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.OpenableColumns
import android.provider.Settings
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.text.format.Formatter
import android.view.LayoutInflater
import android.view.Menu
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.PopupMenu
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.lock.safe_delete.SafeDeleteConfirmActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.LinkedHashMap
import java.util.Locale

class FileBrowserActivity : AppCompatActivity() {

    private val PERMISSION_REQUEST_CODE = 1002
    private val PREVIEW_REQUEST_CODE = 3001
    private val SYSTEM_PICKER_REQUEST_CODE = 3002

    private var currentSortMode = "DATE"
    private var searchJob: Job? = null
    private var preloadJob: Job? = null

    private lateinit var recyclerView: RecyclerView
    private lateinit var searchBar: EditText
    private lateinit var clearSearchBtn: ImageView
    private lateinit var selectedCounterTv: TextView
    private lateinit var currentPathTv: TextView
    private lateinit var emptyState: LinearLayout
    private lateinit var emptyTitle: TextView
    private lateinit var emptyMessage: TextView
    private lateinit var btnSystemPicker: MaterialButton
    private lateinit var btnSelectAll: MaterialButton
    private lateinit var btnClearSelection: MaterialButton
    private lateinit var btnSortMenu: MaterialButton
    private lateinit var bottomEncryptContainer: LinearLayout
    private lateinit var btnAction: MaterialButton
    private lateinit var screenTitle: TextView
    private lateinit var screenSubtitle: TextView

    private var allFilesList = ArrayList<StorageItem>()
    private var filteredList = ArrayList<StorageItem>()
    private var currentDir: File = Environment.getExternalStorageDirectory()
    private val selectedPaths = HashSet<String>()
    private var operationalMode = "ENCRYPT"

    private val thumbnailCache = object : LinkedHashMap<String, Bitmap>(80, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Bitmap>?): Boolean {
            return size > 120
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_file_browser)

        operationalMode = intent.getStringExtra("crypto_mode") ?: "ENCRYPT"

        screenTitle = findViewById(R.id.screen_title)
        screenSubtitle = findViewById(R.id.screen_subtitle)
        searchBar = findViewById(R.id.search_bar)
        clearSearchBtn = findViewById(R.id.btn_clear_search)
        selectedCounterTv = findViewById(R.id.selected_counter)
        currentPathTv = findViewById(R.id.current_path)
        emptyState = findViewById(R.id.empty_state)
        emptyTitle = findViewById(R.id.empty_title)
        emptyMessage = findViewById(R.id.empty_message)
        btnSystemPicker = findViewById(R.id.btn_system_picker)
        btnSelectAll = findViewById(R.id.btn_select_all)
        btnClearSelection = findViewById(R.id.btn_clear_selection)
        btnSortMenu = findViewById(R.id.btn_sort_menu)
        recyclerView = findViewById(R.id.file_list)
        bottomEncryptContainer = findViewById(R.id.bottom_encrypt_container)
        btnAction = findViewById(R.id.btn_bottom_encrypt)

        setupHeaderTexts()
        setupActionButton()

        recyclerView.layoutManager = LinearLayoutManager(this)
        updateSortButtonLabel()

        if (checkStoragePermissions()) {
            openInitialDirectory()
        } else {
            requestStoragePermissions()
        }

        searchBar.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                clearSearchBtn.visibility = if (s.isNullOrEmpty()) View.GONE else View.VISIBLE
                applySortAndFilter()
            }

            override fun afterTextChanged(s: Editable?) {}
        })

        clearSearchBtn.setOnClickListener {
            searchBar.setText("")
        }

        btnSortMenu.setOnClickListener {
            showSortMenu()
        }

        btnSystemPicker.setOnClickListener {
            openSystemFilePicker()
        }

        btnSelectAll.setOnClickListener {
            selectAllVisibleItems()
        }

        btnClearSelection.setOnClickListener {
            clearVisibleSelections()
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (searchBar.text.toString().isNotBlank()) {
                    searchBar.setText("")
                    return
                }

                val root = Environment.getExternalStorageDirectory()
                if (currentDir.absolutePath != root.absolutePath) {
                    currentDir.parentFile?.let { loadDirectory(it) } ?: finish()
                } else {
                    finish()
                }
            }
        })
    }

    private fun openSystemFilePicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }
        try {
            startActivityForResult(intent, SYSTEM_PICKER_REQUEST_CODE)
        } catch (_: Exception) {
            Toast.makeText(this, "System file picker not available", Toast.LENGTH_SHORT).show()
        }
    }

    private fun showSortMenu() {
        val popup = PopupMenu(this, btnSortMenu)
        popup.menu.add(Menu.NONE, 1, Menu.NONE, "Name")
        popup.menu.add(Menu.NONE, 2, Menu.NONE, "Date")
        popup.menu.add(Menu.NONE, 3, Menu.NONE, "Size")

        popup.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                1 -> currentSortMode = "NAME"
                2 -> currentSortMode = "DATE"
                3 -> currentSortMode = "SIZE"
            }

            updateSortButtonLabel()
            applySortAndFilter()
            true
        }

        popup.show()
    }

    private fun updateSortButtonLabel() {
        btnSortMenu.text = when (currentSortMode) {
            "NAME" -> "Sort: Name"
            "DATE" -> "Sort: Date"
            "SIZE" -> "Sort: Size"
            else -> "Sort"
        }
    }

    private fun setupHeaderTexts() {
        when (operationalMode) {
            "ENCRYPT" -> {
                screenTitle.text = "Encrypt Files"
                screenSubtitle.text = "Choose files or folders to secure"
            }

            "DECRYPT" -> {
                screenTitle.text = "Decrypt Files"
                screenSubtitle.text = "Search encrypted files instantly"
            }

            "SAFE_DELETE" -> {
                screenTitle.text = "Safe Delete"
                screenSubtitle.text = "Select files or folders for secure deletion"
            }

            "METADATA" -> {
                screenTitle.text = "Strip Metadata"
                screenSubtitle.text = "Select files to remove all digital traces"
            }
        }
    }

    private fun setupActionButton() {
        btnAction.text = when (operationalMode) {
            "ENCRYPT" -> "Continue to Encrypt"
            "DECRYPT" -> "Continue to Decrypt"
            "SAFE_DELETE" -> "Continue to Safe Delete"
            "METADATA" -> "Continue to Strip Metadata"
            else -> "Continue"
        }

        btnAction.setOnClickListener {
            if (selectedPaths.isEmpty()) {
                Toast.makeText(this, "No items selected", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            when (operationalMode) {
                "ENCRYPT" -> {
                    val intent = Intent(this, EncryptionSettingsActivity::class.java)
                    intent.putStringArrayListExtra("SELECTED_FILES", ArrayList(selectedPaths))
                    startActivity(intent)
                }

                "DECRYPT" -> {
                    val intent = Intent(this, DecryptionSettingsActivity::class.java)
                    intent.putStringArrayListExtra("SELECTED_FILES", ArrayList(selectedPaths))
                    startActivity(intent)
                }

                "SAFE_DELETE" -> {
                    val intent = Intent(this, SafeDeleteConfirmActivity::class.java)
                    intent.putStringArrayListExtra("SELECTED_FILES", ArrayList(selectedPaths))
                    startActivity(intent)
                }

                "METADATA" -> {
                    val intent = Intent(this, MetadataConfirmActivity::class.java)
                    intent.putStringArrayListExtra("SELECTED_FILES", ArrayList(selectedPaths))
                    startActivity(intent)
                }
            }
        }
    }

    private fun openInitialDirectory() {
        val root = Environment.getExternalStorageDirectory()

        if (operationalMode == "DECRYPT") {
            val encDir = File(root, "ENC")
            if (encDir.exists() && encDir.isDirectory) {
                loadDirectory(encDir)
                preloadGlobalIndex()
                return
            }
        }

        loadDirectory(root)
        preloadGlobalIndex()
    }

    private fun preloadGlobalIndex() {
        preloadJob?.cancel()
        preloadJob = lifecycleScope.launch {
            try {
                FileSearchEngine.ensureIndexed(Environment.getExternalStorageDirectory())
            } catch (_: Exception) {
            }
        }
    }

    private fun checkStoragePermissions(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.READ_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
        }
    }

    private fun requestStoragePermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
            intent.data = Uri.parse("package:$packageName")
            startActivityForResult(intent, PERMISSION_REQUEST_CODE)
        } else {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE),
                PERMISSION_REQUEST_CODE
            )
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (checkStoragePermissions()) {
                openInitialDirectory()
            } else {
                Toast.makeText(this, "Permission Denied", Toast.LENGTH_LONG).show()
            }
            return
        }

        if (requestCode == SYSTEM_PICKER_REQUEST_CODE && resultCode == RESULT_OK && data != null) {
            val uriList = ArrayList<Uri>()
            val clipData = data.clipData
            if (clipData != null) {
                for (i in 0 until clipData.itemCount) {
                    uriList.add(clipData.getItemAt(i).uri)
                }
            } else {
                data.data?.let { uriList.add(it) }
            }

            if (uriList.isNotEmpty()) {
                lifecycleScope.launch(Dispatchers.IO) {
                    val importedPaths = ArrayList<String>()
                    for (uri in uriList) {
                        try {
                            val fileName = getFileNameFromUri(uri) ?: "file_${System.currentTimeMillis()}"
                            val cacheFile = File(cacheDir, fileName)
                            contentResolver.openInputStream(uri)?.use { input ->
                                cacheFile.outputStream().use { output ->
                                    input.copyTo(output)
                                }
                            }
                            importedPaths.add(cacheFile.absolutePath)
                        } catch (_: Exception) {}
                    }

                    withContext(Dispatchers.Main) {
                        if (importedPaths.isNotEmpty()) {
                            selectedPaths.addAll(importedPaths)
                            for (item in allFilesList) {
                                item.isSelected = selectedPaths.contains(item.file.absolutePath)
                            }
                            for (item in filteredList) {
                                item.isSelected = selectedPaths.contains(item.file.absolutePath)
                            }
                            recyclerView.adapter?.notifyDataSetChanged()
                            updateSelectionUI()
                            Toast.makeText(this@FileBrowserActivity, "${importedPaths.size} file(s) imported from system picker", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }
            return
        }

        if (requestCode == PREVIEW_REQUEST_CODE && resultCode == RESULT_OK && data != null) {
            val updatedSelections = data.getStringArrayListExtra("updated_selected_files") ?: arrayListOf()

            selectedPaths.clear()
            selectedPaths.addAll(updatedSelections)

            for (item in allFilesList) {
                item.isSelected = selectedPaths.contains(item.file.absolutePath)
            }

            for (item in filteredList) {
                item.isSelected = selectedPaths.contains(item.file.absolutePath)
            }

            recyclerView.adapter?.notifyDataSetChanged()
            updateSelectionUI()
        }
    }

    private fun getFileNameFromUri(uri: Uri): String? {
        var name: String? = null
        val cursor = contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            if (it.moveToFirst()) {
                val nameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameIndex != -1) {
                    name = it.getString(nameIndex)
                }
            }
        }
        if (name == null) {
            name = uri.path?.let { path ->
                val cut = path.lastIndexOf('/')
                if (cut != -1) path.substring(cut + 1) else path
            }
        }
        return name
    }

    private fun loadDirectory(dir: File) {
        currentDir = dir
        currentPathTv.text = dir.absolutePath

        val files = dir.listFiles()
        allFilesList.clear()

        if (files != null) {
            for (f in files) {
                if (!f.name.startsWith(".")) {
                    val isSelected = selectedPaths.contains(f.absolutePath)
                    allFilesList.add(StorageItem(f, isSelected))
                }
            }
        }

        applySortAndFilter()
        updateSelectionUI()
    }

    private fun applySortAndFilter() {
        val query = searchBar.text.toString().trim()

        if (query.isEmpty()) {
            runFolderView()
        } else {
            runDeviceWideSearch(query)
        }
    }

    private fun runFolderView() {
        searchJob?.cancel()
        filteredList.clear()

        val decryptAutoFilter = operationalMode == "DECRYPT" && allFilesList.any {
            it.file.isFile && it.file.name.lowercase(Locale.getDefault()).endsWith(".enc")
        }

        for (item in allFilesList) {
            val name = item.file.name.lowercase(Locale.getDefault())

            if (decryptAutoFilter) {
                if (item.file.isDirectory || name.endsWith(".enc")) {
                    filteredList.add(item)
                }
            } else {
                filteredList.add(item)
            }
        }

        sortItems(filteredList)

        renderListState(
            title = "This folder is empty",
            message = "There are no visible files here"
        )
    }

    private fun runDeviceWideSearch(query: String) {
        searchJob?.cancel()
        searchJob = lifecycleScope.launch {
            try {
                delay(120)

                val root = Environment.getExternalStorageDirectory()
                val resultFiles = FileSearchEngine.searchFast(root, query)

                filteredList = ArrayList()

                for (matchedFile in resultFiles) {
                    if (operationalMode == "DECRYPT") {
                        if (
                            matchedFile.isDirectory ||
                            matchedFile.name.lowercase(Locale.getDefault()).endsWith(".enc")
                        ) {
                            filteredList.add(
                                StorageItem(
                                    matchedFile,
                                    selectedPaths.contains(matchedFile.absolutePath)
                                )
                            )
                        }
                    } else {
                        filteredList.add(
                            StorageItem(
                                matchedFile,
                                selectedPaths.contains(matchedFile.absolutePath)
                            )
                        )
                    }
                }

                sortItems(filteredList)

                renderListState(
                    title = "No search results",
                    message = "No file or folder matched your search in device storage"
                )
            } catch (_: Exception) {
                filteredList.clear()

                renderListState(
                    title = "Search unavailable",
                    message = "Unable to complete full device search right now"
                )
            }
        }
    }

    private fun sortItems(list: MutableList<StorageItem>) {
        when (currentSortMode) {
            "NAME" -> {
                list.sortWith(
                    compareBy<StorageItem> { !it.file.isDirectory }
                        .thenBy { it.file.name.lowercase(Locale.getDefault()) }
                )
            }

            "DATE" -> {
                list.sortWith(
                    compareBy<StorageItem> { !it.file.isDirectory }
                        .thenByDescending { it.file.lastModified() }
                )
            }

            "SIZE" -> {
                list.sortWith(
                    compareBy<StorageItem> { !it.file.isDirectory }
                        .thenByDescending { if (it.file.isDirectory) 0L else it.file.length() }
                )
            }
        }
    }

    private fun renderListState(title: String, message: String) {
        recyclerView.adapter = FileAdapter(
            items = filteredList,
            onItemClick = { selectedItem ->
                if (selectedItem.file.isDirectory) {
                    loadDirectory(selectedItem.file)
                } else {
                    openPreview(selectedItem.file)
                }
            },
            onItemSelected = { selectedItem, isChecked ->
                if (isChecked) {
                    selectedPaths.add(selectedItem.file.absolutePath)
                    selectedItem.isSelected = true
                } else {
                    selectedPaths.remove(selectedItem.file.absolutePath)
                    selectedItem.isSelected = false
                }

                updateSelectionUI()
            },
            onItemLongClick = { selectedItem, anchorView ->
                showItemActionMenu(selectedItem, anchorView)
            }
        )

        if (filteredList.isEmpty()) {
            emptyState.visibility = View.VISIBLE
            emptyTitle.text = title
            emptyMessage.text = message
        } else {
            emptyState.visibility = View.GONE
        }

        updateSelectionUI()
    }

    private fun showItemActionMenu(item: StorageItem, anchor: View) {
        val popup = PopupMenu(this, anchor)

        popup.menu.add(Menu.NONE, 1, Menu.NONE, if (item.file.isDirectory) "Select Folder" else "Select")
        popup.menu.add(Menu.NONE, 2, Menu.NONE, "Rename")
        popup.menu.add(Menu.NONE, 6, Menu.NONE, "Delete")

        if (operationalMode != "SAFE_DELETE") {
            popup.menu.add(Menu.NONE, 7, Menu.NONE, "Safe Delete")
        }

        popup.menu.add(Menu.NONE, 8, Menu.NONE, "Details")

        popup.setOnMenuItemClickListener { menuItem ->
            when (menuItem.itemId) {
                1 -> toggleSelection(item)
                2 -> showRenameDialog(item.file)
                6 -> deleteItem(item.file)
                7 -> launchSafeDeleteForSingle(item.file)
                8 -> showDetailsDialog(item.file)
            }

            true
        }

        popup.show()
    }

    private fun toggleSelection(item: StorageItem) {
        item.isSelected = !item.isSelected

        if (item.isSelected) {
            selectedPaths.add(item.file.absolutePath)
        } else {
            selectedPaths.remove(item.file.absolutePath)
        }

        recyclerView.adapter?.notifyDataSetChanged()
        updateSelectionUI()
    }

    private fun showRenameDialog(targetFile: File) {
        val input = EditText(this)
        input.setText(targetFile.name)
        input.inputType = InputType.TYPE_CLASS_TEXT

        AlertDialog.Builder(this)
            .setTitle("Rename")
            .setView(input)
            .setPositiveButton("Save") { _, _ ->
                val newName = input.text.toString().trim()

                if (newName.isBlank()) {
                    Toast.makeText(this, "Name cannot be empty", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                val destinationFile = File(targetFile.parentFile, newName)

                if (destinationFile.exists()) {
                    Toast.makeText(this, "A file or folder with this name already exists", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                val success = try {
                    targetFile.renameTo(destinationFile)
                } catch (_: Exception) {
                    false
                }

                if (success) {
                    if (selectedPaths.remove(targetFile.absolutePath)) {
                        selectedPaths.add(destinationFile.absolutePath)
                    }

                    thumbnailCache.remove(targetFile.absolutePath)
                    loadDirectory(currentDir)

                    Toast.makeText(this, "Renamed successfully", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Rename failed", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun deleteItem(targetFile: File) {
        AlertDialog.Builder(this)
            .setTitle("Delete")
            .setMessage("Delete ${targetFile.name}?")
            .setPositiveButton("Delete") { _, _ ->
                val success = deleteRecursivelySafe(targetFile)

                if (success) {
                    selectedPaths.remove(targetFile.absolutePath)
                    thumbnailCache.remove(targetFile.absolutePath)
                    loadDirectory(currentDir)
                    Toast.makeText(this, "Deleted", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Delete failed", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun launchSafeDeleteForSingle(targetFile: File) {
        val intent = Intent(this, SafeDeleteConfirmActivity::class.java)
        intent.putStringArrayListExtra("SELECTED_FILES", arrayListOf(targetFile.absolutePath))
        startActivity(intent)
    }

    private fun showDetailsDialog(targetFile: File) {
        val typeLabel = if (targetFile.isDirectory) {
            "Folder"
        } else {
            FileTypeResolver.badge(FileTypeResolver.resolve(targetFile), targetFile.extension)
        }

        val sizeValue = if (targetFile.isDirectory) {
            folderSize(targetFile)
        } else {
            targetFile.length()
        }

        val details = buildString {
            append("Name: ${targetFile.name}\n")
            append("Path: ${targetFile.absolutePath}\n")
            append("Type: $typeLabel\n")
            append("Size: ${Formatter.formatShortFileSize(this@FileBrowserActivity, sizeValue)}\n")
            append(
                "Modified: ${
                    SimpleDateFormat(
                        "yyyy-MM-dd HH:mm:ss",
                        Locale.getDefault()
                    ).format(Date(targetFile.lastModified()))
                }\n"
            )

            if (targetFile.isDirectory) {
                append("Items: ${safeChildCount(targetFile)}\n")
            }

            append("Readable: ${targetFile.canRead()}\n")
            append("Writable: ${targetFile.canWrite()}")
        }

        AlertDialog.Builder(this)
            .setTitle("Details")
            .setMessage(details)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun openPreview(file: File) {
        val intent = Intent(this, FilePreviewActivity::class.java)
        intent.putExtra("file_path", file.absolutePath)
        intent.putExtra("crypto_mode", operationalMode)
        intent.putStringArrayListExtra("preselected_files", ArrayList(selectedPaths))
        startActivityForResult(intent, PREVIEW_REQUEST_CODE)
    }

    private fun selectAllVisibleItems() {
        if (filteredList.isEmpty()) {
            Toast.makeText(this, "No items to select", Toast.LENGTH_SHORT).show()
            return
        }

        for (item in filteredList) {
            item.isSelected = true
            selectedPaths.add(item.file.absolutePath)
        }

        recyclerView.adapter?.notifyDataSetChanged()
        updateSelectionUI()
    }

    private fun clearVisibleSelections() {
        for (item in filteredList) {
            item.isSelected = false
            selectedPaths.remove(item.file.absolutePath)
        }

        recyclerView.adapter?.notifyDataSetChanged()
        updateSelectionUI()
    }

    private fun updateSelectionUI() {
        val selectedCount = selectedPaths.size

        selectedCounterTv.text = "$selectedCount Selected"
        bottomEncryptContainer.visibility = if (selectedCount > 0) View.VISIBLE else View.GONE

        val selectedVisibleCount = filteredList.count {
            selectedPaths.contains(it.file.absolutePath)
        }

        btnSelectAll.text = if (filteredList.isNotEmpty() && selectedVisibleCount == filteredList.size) {
            "All Selected"
        } else {
            "Select all"
        }

        btnClearSelection.isEnabled = selectedVisibleCount > 0
        btnClearSelection.alpha = if (selectedVisibleCount > 0) 1f else 0.55f
    }

    inner class FileAdapter(
        private val items: List<StorageItem>,
        private val onItemClick: (StorageItem) -> Unit,
        private val onItemSelected: (StorageItem, Boolean) -> Unit,
        private val onItemLongClick: (StorageItem, View) -> Unit
    ) : RecyclerView.Adapter<FileAdapter.FileViewHolder>() {

        inner class FileViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val card: MaterialCardView = view.findViewById(R.id.item_card)
            val nameTv: TextView = view.findViewById(R.id.item_name)
            val detailsTv: TextView = view.findViewById(R.id.item_details)
            val checkbox: CheckBox = view.findViewById(R.id.item_checkbox)
            val iconView: ImageView = view.findViewById(R.id.item_icon)
            val arrowView: ImageView = view.findViewById(R.id.item_arrow)
            val previewImage: ImageView = view.findViewById(R.id.item_preview)
            val fileTypeBadge: TextView = view.findViewById(R.id.item_type_badge)
            val clickZoneLeft: View = view.findViewById(R.id.click_zone_left)
            val clickZoneRight: View = view.findViewById(R.id.click_zone_right)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): FileViewHolder {
            val view = LayoutInflater.from(parent.context).inflate(R.layout.item_storage, parent, false)
            return FileViewHolder(view)
        }

        override fun onBindViewHolder(holder: FileViewHolder, position: Int) {
            val item = items[position]
            val targetFile = item.file
            val type = FileTypeResolver.resolve(targetFile)

            holder.nameTv.text = targetFile.name

            holder.previewImage.setImageDrawable(null)
            holder.previewImage.visibility = View.GONE
            holder.previewImage.tag = null

            holder.iconView.visibility = View.VISIBLE
            holder.iconView.setImageResource(FileTypeResolver.icon(type))
            holder.iconView.imageTintList = ColorStateList.valueOf(Color.parseColor(FileTypeResolver.tint(type)))

            holder.card.setCardBackgroundColor(
                Color.parseColor(if (item.isSelected) "#13261D" else "#0F1620")
            )

            holder.card.strokeColor = Color.parseColor(
                if (item.isSelected) "#2C7F58" else "#1D2B3B"
            )

            holder.fileTypeBadge.text = FileTypeResolver.badge(type, targetFile.extension)
            holder.fileTypeBadge.visibility = View.VISIBLE

            holder.checkbox.setOnCheckedChangeListener(null)
            holder.checkbox.visibility = View.VISIBLE
            holder.checkbox.isChecked = item.isSelected
            holder.checkbox.setOnCheckedChangeListener { _, isChecked ->
                val adapterPosition = holder.adapterPosition

                if (adapterPosition != RecyclerView.NO_POSITION) {
                    onItemSelected(item, isChecked)
                    notifyItemChanged(adapterPosition)
                }
            }

            if (targetFile.isDirectory) {
                val childrenCount = safeChildCount(targetFile)

                holder.detailsTv.text = "$childrenCount items"
                holder.arrowView.visibility = View.VISIBLE

                holder.iconView.setImageResource(android.R.drawable.ic_menu_agenda)
                holder.iconView.imageTintList = ColorStateList.valueOf(Color.parseColor("#86B7FF"))

                holder.fileTypeBadge.text = "FOLDER"
                holder.nameTv.setTextColor(Color.parseColor("#F4F8FC"))
            } else {
                val date = SimpleDateFormat(
                    "yyyy-MM-dd HH:mm",
                    Locale.getDefault()
                ).format(Date(targetFile.lastModified()))

                val size = Formatter.formatShortFileSize(
                    this@FileBrowserActivity,
                    targetFile.length()
                )

                holder.detailsTv.text = "$size • $date"
                holder.arrowView.visibility = View.GONE

                if (type == ResolvedFileType.IMAGE) {
                    bindImagePreview(holder, targetFile, item)
                }

                holder.nameTv.setTextColor(
                    if (type == ResolvedFileType.ENCRYPTED) {
                        Color.parseColor("#FFD76A")
                    } else {
                        Color.parseColor("#F4F8FC")
                    }
                )
            }

            holder.clickZoneLeft.setOnClickListener {
                onItemClick(item)
            }

            holder.clickZoneRight.setOnClickListener {
                val adapterPosition = holder.adapterPosition
                if (adapterPosition != RecyclerView.NO_POSITION) {
                    onItemSelected(item, !item.isSelected)
                    notifyItemChanged(adapterPosition)
                }
            }

            holder.itemView.setOnClickListener(null)
            holder.iconView.setOnClickListener(null)

            holder.itemView.setOnLongClickListener {
                onItemLongClick(item, holder.itemView)
                true
            }
        }

        private fun bindImagePreview(holder: FileViewHolder, imageFile: File, item: StorageItem) {
            val imagePath = imageFile.absolutePath
            holder.previewImage.tag = imagePath

            val cachedBitmap = thumbnailCache[imagePath]
            if (cachedBitmap != null) {
                holder.previewImage.setImageBitmap(cachedBitmap)
                holder.previewImage.visibility = View.VISIBLE
                holder.iconView.visibility = View.GONE
                return
            }

            lifecycleScope.launch {
                val bitmap = withContext(Dispatchers.IO) {
                    decodeImageThumbnail(imageFile, 220, 220)
                }

                if (bitmap != null) {
                    thumbnailCache[imagePath] = bitmap
                }

                if (holder.previewImage.tag == imagePath) {
                    if (bitmap != null) {
                        holder.previewImage.setImageBitmap(bitmap)
                        holder.previewImage.visibility = View.VISIBLE
                        holder.iconView.visibility = View.GONE
                    } else {
                        holder.previewImage.setImageDrawable(null)
                        holder.previewImage.visibility = View.GONE
                        holder.iconView.visibility = View.VISIBLE
                    }
                }
            }
        }

        override fun getItemCount(): Int = items.size
    }

    private fun safeChildCount(dir: File): Int {
        return try {
            dir.listFiles()?.count { !it.name.startsWith(".") } ?: 0
        } catch (_: Exception) {
            0
        }
    }

    private fun folderSize(dir: File): Long {
        return 0L
    }

    private fun deleteRecursivelySafe(targetFile: File): Boolean {
        return try {
            if (targetFile.isDirectory) {
                targetFile.listFiles()?.forEach { child ->
                    deleteRecursivelySafe(child)
                }
            }

            targetFile.delete()
        } catch (_: Exception) {
            false
        }
    }

    private fun decodeImageThumbnail(file: File, reqWidth: Int, reqHeight: Int): Bitmap? {
        if (!file.exists()) return null
        if (!file.isFile) return null
        if (file.length() <= 0L) return null

        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val source = ImageDecoder.createSource(file)

                ImageDecoder.decodeBitmap(source) { decoder, info, _ ->
                    decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE

                    val originalWidth = info.size.width
                    val originalHeight = info.size.height

                    if (originalWidth > 0 && originalHeight > 0) {
                        val ratio = minOf(
                            reqWidth.toFloat() / originalWidth.toFloat(),
                            reqHeight.toFloat() / originalHeight.toFloat()
                        )

                        val targetWidth = maxOf(1, (originalWidth * ratio).toInt())
                        val targetHeight = maxOf(1, (originalHeight * ratio).toInt())

                        decoder.setTargetSize(targetWidth, targetHeight)
                    }
                }
            } else {
                decodeImageThumbnailLegacy(file, reqWidth, reqHeight)
            }
        } catch (_: Exception) {
            decodeImageThumbnailLegacy(file, reqWidth, reqHeight)
        }
    }

    private fun decodeImageThumbnailLegacy(file: File, reqWidth: Int, reqHeight: Int): Bitmap? {
        return try {
            val options = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }

            BitmapFactory.decodeFile(file.absolutePath, options)

            if (options.outWidth <= 0 || options.outHeight <= 0) {
                return null
            }

            options.inSampleSize = calculateInSampleSize(options, reqWidth, reqHeight)
            options.inJustDecodeBounds = false
            options.inPreferredConfig = Bitmap.Config.RGB_565

            BitmapFactory.decodeFile(file.absolutePath, options)
        } catch (_: Exception) {
            null
        }
    }

    private fun calculateInSampleSize(
        options: BitmapFactory.Options,
        reqWidth: Int,
        reqHeight: Int
    ): Int {
        val height = options.outHeight
        val width = options.outWidth
        var inSampleSize = 1

        if (height > reqHeight || width > reqWidth) {
            val halfHeight = height / 2
            val halfWidth = width / 2

            while (
                (halfHeight / inSampleSize) >= reqHeight &&
                (halfWidth / inSampleSize) >= reqWidth
            ) {
                inSampleSize *= 2
            }
        }

        return inSampleSize.coerceAtLeast(1)
    }
}

data class StorageItem(
    val file: File,
    var isSelected: Boolean
)