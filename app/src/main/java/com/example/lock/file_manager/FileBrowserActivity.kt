package com.example.lock.file_manager

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
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
import android.view.Menu
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.view.View
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
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.recyclerview.widget.SimpleItemAnimator
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.example.lock.DecryptionSettingsActivity
import com.example.lock.EncryptionSettingsActivity
import com.example.lock.MetadataConfirmActivity
import com.example.lock.R
import com.example.lock.safe_delete.SafeDeleteConfirmActivity
import com.google.android.material.button.MaterialButton
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class FileBrowserActivity : AppCompatActivity() {

    private companion object {
        const val PERMISSION_REQUEST_CODE = 1002
        const val PREVIEW_REQUEST_CODE = 3001
        const val SYSTEM_PICKER_REQUEST_CODE = 3002
        const val SEARCH_DEBOUNCE_MS = 150L
        const val SEARCH_LIMIT = 300
        const val STATE_SELECTION = "browser_selection"
        const val VIEW_MODE_LIST = "LIST"
        const val VIEW_MODE_GRID = "GRID"
        const val DEFAULT_GRID_SPAN = 3
        const val MIN_GRID_SPAN = 2
        const val MAX_GRID_SPAN = 6
        const val PREFS_NAME = "browser_ui"
        const val PREF_VIEW_MODE = "view_mode"
        const val PREF_GRID_SPAN = "grid_span"
    }

    private data class BrowserParams(val dir: File, val sort: String, val query: String)

    private data class BrowserView(
        val dir: File?,
        val pathText: String,
        val items: List<FileListItem>,
        val emptyTitle: String,
        val emptyMessage: String,
        val scrollKey: String
    )

    private data class FolderMeta(val file: File, val isDir: Boolean, val size: Long, val modified: Long)

    private lateinit var recyclerView: RecyclerView
    private lateinit var swipeRefreshLayout: SwipeRefreshLayout
    private lateinit var searchBar: EditText
    private lateinit var clearSearchBtn: ImageView
    private lateinit var selectedCounterTv: TextView
    private lateinit var currentPathTv: TextView
    private lateinit var emptyState: LinearLayout
    private lateinit var emptyTitle: TextView
    private lateinit var emptyMessage: TextView
    private lateinit var btnSystemPicker: MaterialButton
    private lateinit var btnSelectAll: MaterialButton
    private lateinit var btnSortMenu: MaterialButton
    private lateinit var btnViewMode: MaterialButton
    private lateinit var bottomEncryptContainer: LinearLayout
    private lateinit var btnAction: MaterialButton
    private var searchProgress: View? = null
    private lateinit var scaleDetector: ScaleGestureDetector
    private var spanAccumulator = 1f

    private lateinit var adapter: FileBrowserAdapter

    private var currentDir: File = Environment.getExternalStorageDirectory()
    private val selectedPaths = HashSet<String>()
    private var operationalMode = "ENCRYPT"

    private val queryFlow = MutableStateFlow("")
    private val dirFlow = MutableStateFlow(Environment.getExternalStorageDirectory())
    private val sortFlow = MutableStateFlow("DATE")
    private val refreshNonce = MutableStateFlow(0)
    private val viewModeFlow = MutableStateFlow(VIEW_MODE_LIST)
    private val gridSpanFlow = MutableStateFlow(DEFAULT_GRID_SPAN)
    private var lastScrollKey = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_file_browser)

        operationalMode = intent.getStringExtra("crypto_mode") ?: "ENCRYPT"

        searchBar = findViewById(R.id.search_bar)
        clearSearchBtn = findViewById(R.id.btn_clear_search)
        selectedCounterTv = findViewById(R.id.selected_counter)
        currentPathTv = findViewById(R.id.current_path)
        emptyState = findViewById(R.id.empty_state)
        emptyTitle = findViewById(R.id.empty_title)
        emptyMessage = findViewById(R.id.empty_message)
        btnSystemPicker = findViewById(R.id.btn_system_picker)
        btnSelectAll = findViewById(R.id.btn_select_all)
        btnSortMenu = findViewById(R.id.btn_sort_menu)
        btnViewMode = findViewById(R.id.btn_view_mode)
        recyclerView = findViewById(R.id.file_list)
        swipeRefreshLayout = findViewById(R.id.swipe_refresh)
        bottomEncryptContainer = findViewById(R.id.bottom_encrypt_container)
        btnAction = findViewById(R.id.btn_bottom_encrypt)
        searchProgress = findViewById(R.id.search_progress)

        savedInstanceState?.getStringArrayList(STATE_SELECTION)?.let {
            selectedPaths.addAll(it)
        }

        setupActionButton()

        adapter = FileBrowserAdapter(
            scope = lifecycleScope,
            selectedPaths = selectedPaths,
            onItemClick = { item ->
                val file = File(item.path)
                if (item.isDirectory) {
                    loadDirectory(file)
                } else {
                    openPreview(file)
                }
            },
            onToggleSelect = { item ->
                toggleSelectionByPath(item.path)
            },
            onItemLongClick = { item, anchor ->
                showItemActionMenu(File(item.path), item.isDirectory, anchor)
            }
        )

        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.setHasFixedSize(true)
        (recyclerView.itemAnimator as? SimpleItemAnimator)?.supportsChangeAnimations = false
        recyclerView.adapter = adapter
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        viewModeFlow.value = if (prefs.getString(PREF_VIEW_MODE, VIEW_MODE_LIST) == VIEW_MODE_GRID) VIEW_MODE_GRID else VIEW_MODE_LIST
        gridSpanFlow.value = prefs.getInt(PREF_GRID_SPAN, DEFAULT_GRID_SPAN).coerceIn(MIN_GRID_SPAN, MAX_GRID_SPAN)
        scaleDetector = ScaleGestureDetector(this, PinchSpanListener())
        recyclerView.addOnItemTouchListener(object : RecyclerView.SimpleOnItemTouchListener() {
            override fun onInterceptTouchEvent(rv: RecyclerView, e: MotionEvent): Boolean {
                scaleDetector.onTouchEvent(e)
                return false
            }
        })
        applyLayout(resetScroll = true)
        updateSortButtonLabel()
        updateViewModeButton()

        swipeRefreshLayout.setOnRefreshListener {
            refreshNonce.value = refreshNonce.value + 1
        }

        if (checkStoragePermissions()) {
            openInitialDirectory()
        } else {
            requestStoragePermissions()
        }

        startBrowserPipeline()

        searchBar.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                val text = s?.toString() ?: ""
                clearSearchBtn.visibility = if (text.isEmpty()) View.GONE else View.VISIBLE
                if (text.isNotBlank()) searchProgress?.visibility = View.VISIBLE
                queryFlow.value = text.trim()
            }

            override fun afterTextChanged(s: Editable?) {}
        })

        clearSearchBtn.setOnClickListener {
            searchBar.setText("")
        }

        btnSortMenu.setOnClickListener {
            showSortMenu()
        }

        btnViewMode.setOnClickListener {
            val next = if (viewModeFlow.value == VIEW_MODE_GRID) VIEW_MODE_LIST else VIEW_MODE_GRID
            viewModeFlow.value = next
            getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit().putString(PREF_VIEW_MODE, next).apply()
            applyLayout(resetScroll = true)
        }

        btnSystemPicker.setOnClickListener {
            openSystemFilePicker()
        }

        btnSelectAll.setOnClickListener {
            val visible = adapter.currentList
            if (visible.isEmpty()) {
                Toast.makeText(this, "No items to select", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val selectedVisibleCount = visible.count { selectedPaths.contains(it.path) }
            if (selectedVisibleCount == visible.size) {
                for (item in visible) selectedPaths.remove(item.path)
            } else {
                for (item in visible) selectedPaths.add(item.path)
            }
            adapter.refreshAllSelections()
            updateSelectionUI()
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

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putStringArrayList(STATE_SELECTION, ArrayList(selectedPaths))
    }

    private fun startBrowserPipeline() {
        lifecycleScope.launch {
            FileSearchEngine.indexState.collect { state ->
                if (state is FileSearchEngine.IndexState.Indexing && queryFlow.value.isNotBlank()) {
                    searchProgress?.visibility = View.VISIBLE
                }
            }
        }
        lifecycleScope.launch {
            val debouncedQuery = queryFlow
                .flatMapLatest { query ->
                    flow {
                        if (query.isNotBlank()) delay(SEARCH_DEBOUNCE_MS)
                        emit(query)
                    }
                }
            combine(dirFlow, sortFlow, debouncedQuery, refreshNonce) { dir, sort, query, _ ->
                BrowserParams(dir, sort, query)
            }.flatMapLatest { params ->
                flow { emit(buildView(params)) }.flowOn(Dispatchers.IO)
            }.collect { view ->
                render(view)
            }
        }
    }

    private suspend fun buildView(params: BrowserParams): BrowserView {
        val appContext = applicationContext
        if (params.query.isBlank()) {
            val files = try {
                params.dir.listFiles()?.filter { !it.name.startsWith(".") } ?: emptyList()
            } catch (_: Exception) {
                emptyList()
            }
            val decryptFilter = operationalMode == "DECRYPT" &&
                    files.any { it.isFile && it.extension.equals("enc", ignoreCase = true) }
            val visible = if (decryptFilter) {
                files.filter { it.isDirectory || it.extension.equals("enc", ignoreCase = true) }
            } else {
                files
            }
            val metas = visible.map { file ->
                val dir = file.isDirectory
                val size = if (dir) {
                    0L
                } else {
                    try {
                        file.length()
                    } catch (_: Exception) {
                        0L
                    }
                }
                val modified = try {
                    file.lastModified()
                } catch (_: Exception) {
                    0L
                }
                FolderMeta(file, dir, size, modified)
            }
            val sorted = sortMetas(metas, params.sort)
            val items = sorted.map { meta ->
                val count = if (meta.isDir) safeChildCount(meta.file) else null
                FileListItems.fromFile(meta.file, meta.size, meta.modified, count, appContext)
            }
            return BrowserView(
                dir = params.dir,
                pathText = params.dir.absolutePath,
                items = items,
                emptyTitle = "This folder is empty",
                emptyMessage = "There are no visible files here",
                scrollKey = params.query + "\n" + params.dir.absolutePath + "\n" + params.sort + "\n" + viewModeFlow.value
            )
        }
        val root = Environment.getExternalStorageDirectory()
        val hits = FileSearchEngine.searchFast(root, params.query, SEARCH_LIMIT, params.sort)
        val filtered = if (operationalMode == "DECRYPT") {
            hits.filter { it.isDirectory || it.extension == "enc" }
        } else {
            hits
        }
        val highlightTokens = params.query.split(' ', '\t', '\n').filter { it.isNotBlank() }
        val items = filtered.map { FileListItems.fromIndexed(it, highlightTokens, appContext) }
        val pathText = if (hits.size >= SEARCH_LIMIT) {
            "${filtered.size}+ results"
        } else {
            "${filtered.size} results"
        }
        return BrowserView(
            dir = null,
            pathText = pathText,
            items = items,
            emptyTitle = "No search results",
            emptyMessage = "No file or folder matched your search in device storage",
            scrollKey = params.query + "\n" + params.dir.absolutePath + "\n" + params.sort + "\n" + viewModeFlow.value
        )
    }

    private fun render(view: BrowserView) {
        if (view.dir != null) {
            currentDir = view.dir
        }
        currentPathTv.text = view.pathText
        searchProgress?.visibility = View.GONE
        if (swipeRefreshLayout.isRefreshing) {
            swipeRefreshLayout.isRefreshing = false
        }
        val resetScroll = view.scrollKey != lastScrollKey
        lastScrollKey = view.scrollKey
        adapter.submitList(view.items) {
            if (resetScroll) {
                recyclerView.scrollToPosition(0)
            }
            updateSelectionUI()
        }
        if (view.items.isEmpty()) {
            emptyState.visibility = View.VISIBLE
            emptyTitle.text = view.emptyTitle
            emptyMessage.text = view.emptyMessage
        } else {
            emptyState.visibility = View.GONE
        }
        updateSelectionUI()
    }

    private fun sortMetas(list: List<FolderMeta>, mode: String): List<FolderMeta> {
        return when (mode) {
            "NAME" -> list.sortedWith(
                compareBy<FolderMeta> { !it.isDir }
                    .thenBy { it.file.name.lowercase(Locale.getDefault()) }
            )
            "SIZE" -> list.sortedWith(
                compareBy<FolderMeta> { !it.isDir }
                    .thenByDescending { it.size }
            )
            else -> list.sortedWith(
                compareBy<FolderMeta> { !it.isDir }
                    .thenByDescending { it.modified }
            )
        }
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

    private fun applyLayout(resetScroll: Boolean) {
        if (viewModeFlow.value == VIEW_MODE_GRID) {
            recyclerView.layoutManager = GridLayoutManager(this, gridSpanFlow.value)
        } else {
            recyclerView.layoutManager = LinearLayoutManager(this)
        }
        adapter.setGridMode(viewModeFlow.value == VIEW_MODE_GRID)
        if (resetScroll) {
            recyclerView.scrollToPosition(0)
        }
        updateViewModeButton()
    }

    private fun updateViewModeButton() {
        if (viewModeFlow.value == VIEW_MODE_GRID) {
            btnViewMode.text = "List"
            btnViewMode.setIconResource(android.R.drawable.ic_menu_sort_by_size)
        } else {
            btnViewMode.text = "Grid"
            btnViewMode.setIconResource(android.R.drawable.ic_menu_view)
        }
    }

    private inner class PinchSpanListener : ScaleGestureDetector.SimpleOnScaleGestureListener() {
        override fun onScale(detector: ScaleGestureDetector): Boolean {
            if (viewModeFlow.value != VIEW_MODE_GRID) {
                spanAccumulator = 1f
                return true
            }
            spanAccumulator *= detector.scaleFactor
            var span = gridSpanFlow.value
            while (spanAccumulator <= 0.80f && span < MAX_GRID_SPAN) {
                span += 1
                spanAccumulator = 1f
            }
            while (spanAccumulator >= 1.25f && span > MIN_GRID_SPAN) {
                span -= 1
                spanAccumulator = 1f
            }
            if (span != gridSpanFlow.value) {
                gridSpanFlow.value = span
                (recyclerView.layoutManager as? GridLayoutManager)?.spanCount = span
                getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit().putInt(PREF_GRID_SPAN, span).apply()
            }
            return true
        }
    }

    private fun showSortMenu() {
        val popup = PopupMenu(this, btnSortMenu)
        popup.menu.add(Menu.NONE, 1, Menu.NONE, "Name")
        popup.menu.add(Menu.NONE, 2, Menu.NONE, "Date")
        popup.menu.add(Menu.NONE, 3, Menu.NONE, "Size")

        popup.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                1 -> sortFlow.value = "NAME"
                2 -> sortFlow.value = "DATE"
                3 -> sortFlow.value = "SIZE"
            }

            updateSortButtonLabel()
            true
        }

        popup.show()
    }

    private fun updateSortButtonLabel() {
        btnSortMenu.text = when (sortFlow.value) {
            "NAME" -> "Sort: Name"
            "DATE" -> "Sort: Date"
            "SIZE" -> "Sort: Size"
            else -> "Sort"
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
        var startDir = root

        if (operationalMode == "DECRYPT") {
            val encDir = File(root, "ENC")
            if (encDir.exists() && encDir.isDirectory) {
                startDir = encDir
            }
        }

        dirFlow.value = startDir
        refreshNonce.value = refreshNonce.value + 1
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                FileSearchEngine.ensureIndexed(root)
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
                        } catch (_: Exception) {
                        }
                    }

                    withContext(Dispatchers.Main) {
                        if (importedPaths.isNotEmpty()) {
                            selectedPaths.addAll(importedPaths)
                            adapter.refreshAllSelections()
                            updateSelectionUI()
                            Toast.makeText(
                                this@FileBrowserActivity,
                                "${importedPaths.size} file(s) imported from system picker",
                                Toast.LENGTH_SHORT
                            ).show()
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
            adapter.refreshAllSelections()
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
        dirFlow.value = dir
    }

    private fun toggleSelectionByPath(path: String) {
        if (selectedPaths.contains(path)) {
            selectedPaths.remove(path)
        } else {
            selectedPaths.add(path)
        }
        adapter.refreshSelection(path)
        updateSelectionUI()
    }

    private fun showItemActionMenu(file: File, isDirectory: Boolean, anchor: View) {
        val popup = PopupMenu(this, anchor)

        popup.menu.add(Menu.NONE, 1, Menu.NONE, if (isDirectory) "Select Folder" else "Select")
        popup.menu.add(Menu.NONE, 2, Menu.NONE, "Rename")
        popup.menu.add(Menu.NONE, 6, Menu.NONE, "Delete")

        if (operationalMode != "SAFE_DELETE") {
            popup.menu.add(Menu.NONE, 7, Menu.NONE, "Safe Delete")
        }

        popup.menu.add(Menu.NONE, 8, Menu.NONE, "Details")

        popup.setOnMenuItemClickListener { menuItem ->
            when (menuItem.itemId) {
                1 -> toggleSelectionByPath(file.absolutePath)
                2 -> showRenameDialog(file)
                6 -> deleteItem(file)
                7 -> launchSafeDeleteForSingle(file)
                8 -> showDetailsDialog(file)
            }

            true
        }

        popup.show()
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

                lifecycleScope.launch(Dispatchers.IO) {
                    val success = try {
                        targetFile.renameTo(destinationFile)
                    } catch (_: Exception) {
                        false
                    }
                    if (success) {
                        try {
                            FileSearchEngine.onFileRenamed(targetFile, destinationFile)
                        } catch (_: Exception) {
                        }
                        ThumbnailLoader.evict(targetFile.absolutePath)
                    }
                    withContext(Dispatchers.Main) {
                        if (success) {
                            if (selectedPaths.remove(targetFile.absolutePath)) {
                                selectedPaths.add(destinationFile.absolutePath)
                            }
                            refreshNonce.value = refreshNonce.value + 1
                            Toast.makeText(this@FileBrowserActivity, "Renamed successfully", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(this@FileBrowserActivity, "Rename failed", Toast.LENGTH_SHORT).show()
                        }
                    }
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
                lifecycleScope.launch(Dispatchers.IO) {
                    val success = deleteRecursivelySafe(targetFile)
                    if (success) {
                        try {
                            FileSearchEngine.onFileDeleted(targetFile)
                        } catch (_: Exception) {
                        }
                        ThumbnailLoader.evict(targetFile.absolutePath)
                    }
                    withContext(Dispatchers.Main) {
                        if (success) {
                            selectedPaths.removeAll {
                                it == targetFile.absolutePath || it.startsWith(targetFile.absolutePath + "/")
                            }
                            refreshNonce.value = refreshNonce.value + 1
                            Toast.makeText(this@FileBrowserActivity, "Deleted", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(this@FileBrowserActivity, "Delete failed", Toast.LENGTH_SHORT).show()
                        }
                    }
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
        lifecycleScope.launch {
            val itemsCount = withContext(Dispatchers.IO) {
                if (targetFile.isDirectory) safeChildCount(targetFile) else 0
            }
            val typeLabel = if (targetFile.isDirectory) {
                "Folder"
            } else {
                FileTypeResolver.badge(FileTypeResolver.resolve(targetFile), targetFile.extension)
            }
            val sizeText = if (targetFile.isDirectory) {
                "-"
            } else {
                Formatter.formatShortFileSize(this@FileBrowserActivity, targetFile.length())
            }
            val details = buildString {
                append("Name: ${targetFile.name}\n")
                append("Path: ${targetFile.absolutePath}\n")
                append("Type: $typeLabel\n")
                append("Size: $sizeText\n")
                append(
                    "Modified: ${
                        SimpleDateFormat(
                            "yyyy-MM-dd HH:mm:ss",
                            Locale.getDefault()
                        ).format(Date(targetFile.lastModified()))
                    }\n"
                )

                if (targetFile.isDirectory) {
                    append("Items: $itemsCount\n")
                }

                append("Readable: ${targetFile.canRead()}\n")
                append("Writable: ${targetFile.canWrite()}")
            }

            AlertDialog.Builder(this@FileBrowserActivity)
                .setTitle("Details")
                .setMessage(details)
                .setPositiveButton("OK", null)
                .show()
        }
    }

    private fun openPreview(file: File) {
        val intent = Intent(this, FilePreviewActivity::class.java)
        intent.putExtra("file_path", file.absolutePath)
        intent.putExtra("crypto_mode", operationalMode)
        intent.putStringArrayListExtra("preselected_files", ArrayList(selectedPaths))
        startActivityForResult(intent, PREVIEW_REQUEST_CODE)
    }

    private fun updateSelectionUI() {
        val selectedCount = selectedPaths.size

        selectedCounterTv.text = "$selectedCount Selected"
        bottomEncryptContainer.visibility = if (selectedCount > 0) View.VISIBLE else View.GONE

        val visible = adapter.currentList
        val selectedVisibleCount = visible.count { selectedPaths.contains(it.path) }

        btnSelectAll.text = if (visible.isNotEmpty() && selectedVisibleCount == visible.size) {
            "Deselect all"
        } else {
            "Select all"
        }
    }

    private fun safeChildCount(dir: File): Int {
        return try {
            dir.listFiles()?.count { !it.name.startsWith(".") } ?: 0
        } catch (_: Exception) {
            0
        }
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
}
