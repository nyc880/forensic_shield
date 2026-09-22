package com.example.lock.file_manager

import android.content.res.ColorStateList
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewConfiguration
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.lock.R
import com.google.android.material.card.MaterialCardView
import kotlin.math.abs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class FileBrowserAdapter(
    private val scope: CoroutineScope,
    val selectedPaths: MutableSet<String>,
    private val onItemClick: (FileListItem) -> Unit,
    private val onToggleSelect: (FileListItem) -> Unit,
    private val onItemLongClick: (FileListItem, View) -> Unit
) : ListAdapter<FileListItem, RecyclerView.ViewHolder>(DIFF) {

    companion object {
        private const val PAYLOAD_SELECTION = "selection"
        private const val VIEW_TYPE_LIST = 0
        private const val VIEW_TYPE_GRID = 1
        private const val HOLD_OPEN_MS = 1500L
        private val BG_NORMAL = 0xFF0F1620.toInt()
        private val BG_SELECTED = 0xFF13261D.toInt()
        private val STROKE_NORMAL = 0xFF1D2B3B.toInt()
        private val STROKE_SELECTED = 0xFF2C7F58.toInt()
        private val HIGHLIGHT_RED = 0xFFFF5252.toInt()

        private val DIFF = object : DiffUtil.ItemCallback<FileListItem>() {
            override fun areItemsTheSame(oldItem: FileListItem, newItem: FileListItem): Boolean {
                return oldItem.path == newItem.path
            }

            override fun areContentsTheSame(oldItem: FileListItem, newItem: FileListItem): Boolean {
                return oldItem == newItem
            }
        }
    }

    private val tintStates = HashMap<Int, ColorStateList>()

    var gridMode: Boolean = false
        private set

    init {
        setHasStableIds(true)
    }

    fun setGridMode(enabled: Boolean) {
        if (gridMode == enabled) return
        gridMode = enabled
        notifyDataSetChanged()
    }

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val card: MaterialCardView = view.findViewById(R.id.item_card)
        val nameTv: TextView = view.findViewById(R.id.item_name)
        val detailsTv: TextView = view.findViewById(R.id.item_details)
        val checkbox: CheckBox = view.findViewById(R.id.item_checkbox)
        val iconView: ImageView = view.findViewById(R.id.item_icon)
        val arrowView: ImageView = view.findViewById(R.id.item_arrow)
        val previewImage: ImageView = view.findViewById(R.id.item_preview)
        val badge: TextView = view.findViewById(R.id.item_type_badge)
        val clickLeft: View = view.findViewById(R.id.click_zone_left)
        val clickRight: View = view.findViewById(R.id.click_zone_right)
        var thumbJob: Job? = null
    }

    inner class GridViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val cell: View = view.findViewById(R.id.item_cell)
        val previewImage: ImageView = view.findViewById(R.id.item_preview)
        val iconView: ImageView = view.findViewById(R.id.item_icon)
        val nameOverlay: TextView = view.findViewById(R.id.item_name)
        val overlay: View = view.findViewById(R.id.item_overlay)
        val checkbox: CheckBox = view.findViewById(R.id.item_checkbox)
        var thumbJob: Job? = null
        var holdJob: Job? = null
    }

    override fun getItemId(position: Int): Long {
        return getItem(position).path.hashCode().toLong()
    }

    override fun getItemViewType(position: Int): Int {
        return if (gridMode) VIEW_TYPE_GRID else VIEW_TYPE_LIST
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return if (viewType == VIEW_TYPE_GRID) {
            GridViewHolder(inflater.inflate(R.layout.item_storage_grid, parent, false))
        } else {
            ViewHolder(inflater.inflate(R.layout.item_storage, parent, false))
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        val item = getItem(position)
        if (holder is GridViewHolder) bindGridFull(holder, item) else bindFull(holder as ViewHolder, item)
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int, payloads: MutableList<Any>) {
        if (payloads.contains(PAYLOAD_SELECTION)) {
            val item = getItem(position)
            if (holder is GridViewHolder) bindGridSelection(holder, item) else bindSelection(holder as ViewHolder, item)
            return
        }
        super.onBindViewHolder(holder, position, payloads)
    }

    override fun onViewRecycled(holder: RecyclerView.ViewHolder) {
        if (holder is GridViewHolder) {
            holder.thumbJob?.cancel()
            holder.holdJob?.cancel()
            holder.thumbJob = null
            holder.holdJob = null
            holder.previewImage.setImageDrawable(null)
            holder.previewImage.tag = null
        } else if (holder is ViewHolder) {
            holder.thumbJob?.cancel()
            holder.thumbJob = null
            holder.previewImage.setImageDrawable(null)
            holder.previewImage.tag = null
        }
        super.onViewRecycled(holder)
    }

    fun refreshSelection(path: String) {
        val index = currentList.indexOfFirst { it.path == path }
        if (index >= 0) notifyItemChanged(index, PAYLOAD_SELECTION)
    }

    fun refreshAllSelections() {
        if (itemCount > 0) notifyItemRangeChanged(0, itemCount, PAYLOAD_SELECTION)
    }

    private fun itemAt(holder: RecyclerView.ViewHolder): FileListItem? {
        val position = holder.adapterPosition
        if (position == RecyclerView.NO_POSITION || position >= itemCount) return null
        return getItem(position)
    }

    private fun bindFull(holder: ViewHolder, item: FileListItem) {
        if (item.highlightRanges.isEmpty()) {
            holder.nameTv.text = item.name
        } else {
            holder.nameTv.text = highlightedName(item)
        }
        holder.nameTv.setTextColor(item.nameColor)
        holder.detailsTv.text = item.detailsLine
        holder.badge.text = item.badgeText
        holder.badge.visibility = View.VISIBLE
        applyIcon(holder, item)
        holder.arrowView.visibility = if (item.isDirectory) View.VISIBLE else View.GONE
        bindSelection(holder, item)

        holder.thumbJob?.cancel()
        holder.thumbJob = null
        holder.previewImage.setImageDrawable(null)
        holder.previewImage.tag = null
        holder.previewImage.visibility = View.GONE
        holder.iconView.visibility = View.VISIBLE

        if (item.showImagePreview) {
            val cached = ThumbnailLoader.get(item.path)
            if (cached != null) {
                holder.previewImage.setImageBitmap(cached)
                holder.previewImage.visibility = View.VISIBLE
                holder.iconView.visibility = View.GONE
            } else {
                holder.previewImage.tag = item.path
                holder.thumbJob = scope.launch {
                    val bitmap = ThumbnailLoader.load(item.path, item.isVideoPreview)
                    if (bitmap != null && holder.previewImage.tag == item.path) {
                        holder.previewImage.setImageBitmap(bitmap)
                        holder.previewImage.visibility = View.VISIBLE
                        holder.iconView.visibility = View.GONE
                    }
                }
            }
        }

        holder.clickLeft.setOnClickListener { itemAt(holder)?.let(onItemClick) }
        holder.clickRight.setOnClickListener { itemAt(holder)?.let(onToggleSelect) }
        holder.itemView.setOnLongClickListener {
            val current = itemAt(holder)
            if (current != null) {
                onItemLongClick(current, holder.itemView)
                true
            } else {
                false
            }
        }
    }

    private fun bindGridFull(holder: GridViewHolder, item: FileListItem) {
        holder.thumbJob?.cancel()
        holder.thumbJob = null
        holder.previewImage.setImageDrawable(null)
        holder.previewImage.tag = null
        holder.previewImage.visibility = View.GONE

        if (item.showImagePreview) {
            val cached = ThumbnailLoader.get(item.path)
            if (cached != null) {
                holder.previewImage.setImageBitmap(cached)
                holder.previewImage.visibility = View.VISIBLE
            } else {
                holder.previewImage.tag = item.path
                holder.thumbJob = scope.launch {
                    val bitmap = ThumbnailLoader.load(item.path, item.isVideoPreview)
                    if (bitmap != null && holder.previewImage.tag == item.path) {
                        holder.previewImage.setImageBitmap(bitmap)
                        holder.previewImage.visibility = View.VISIBLE
                    }
                }
            }
        }

        holder.iconView.imageTintList = null
        if (item.isDirectory) {
            holder.iconView.visibility = View.VISIBLE
            holder.iconView.setImageBitmap(FileTypeResolver.folderIconBitmap())
            holder.nameOverlay.text = item.name
            holder.nameOverlay.visibility = View.VISIBLE
        } else {
            holder.iconView.visibility = View.VISIBLE
            holder.iconView.setImageBitmap(FileTypeResolver.extensionBadgeBitmap(item.badgeText, item.tintColor))
            holder.nameOverlay.visibility = View.GONE
        }

        bindGridSelection(holder, item)

        holder.cell.setOnClickListener {
            val current = itemAt(holder) ?: return@setOnClickListener
            if (current.isDirectory) onItemClick(current) else onToggleSelect(current)
        }

        if (item.isDirectory) {
            holder.holdJob?.cancel()
            holder.cell.setOnTouchListener(null)
            holder.cell.isLongClickable = true
            holder.cell.setOnLongClickListener {
                val current = itemAt(holder)
                if (current != null) {
                    onItemLongClick(current, holder.cell)
                    true
                } else {
                    false
                }
            }
        } else {
            holder.cell.setOnLongClickListener(null)
            holder.cell.isLongClickable = false
            attachHoldToOpen(holder)
        }
    }

    private fun attachHoldToOpen(holder: GridViewHolder) {
        val slop = ViewConfiguration.get(holder.cell.context).scaledTouchSlop
        var downRawX = 0f
        var downRawY = 0f
        var downPath = ""
        holder.cell.setOnTouchListener { _, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    downRawX = event.rawX
                    downRawY = event.rawY
                    downPath = itemAt(holder)?.path ?: ""
                    holder.holdJob?.cancel()
                    holder.holdJob = scope.launch {
                        delay(HOLD_OPEN_MS)
                        val current = itemAt(holder)
                        if (current != null && !current.isDirectory && current.path == downPath) {
                            onItemClick(current)
                        }
                    }
                }
                MotionEvent.ACTION_MOVE -> {
                    if (abs(event.rawX - downRawX) > slop || abs(event.rawY - downRawY) > slop) {
                        holder.holdJob?.cancel()
                    }
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> holder.holdJob?.cancel()
            }
            false
        }
    }

    private fun bindGridSelection(holder: GridViewHolder, item: FileListItem) {
        val selected = selectedPaths.contains(item.path)
        holder.checkbox.setOnCheckedChangeListener(null)
        holder.checkbox.visibility = View.VISIBLE
        holder.checkbox.isChecked = selected
        holder.overlay.visibility = if (selected) View.VISIBLE else View.GONE
        holder.checkbox.setOnCheckedChangeListener { _, _ ->
            itemAt(holder)?.let(onToggleSelect)
        }
    }

    private fun highlightedName(item: FileListItem): CharSequence {
        val spanned = SpannableString(item.name)
        for (range in item.highlightRanges) {
            val start = range.first.coerceIn(0, item.name.length)
            val end = (range.last + 1).coerceIn(0, item.name.length)
            if (start < end) {
                spanned.setSpan(
                    ForegroundColorSpan(HIGHLIGHT_RED),
                    start,
                    end,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                )
            }
        }
        return spanned
    }

    private fun bindSelection(holder: ViewHolder, item: FileListItem) {
        val selected = selectedPaths.contains(item.path)
        holder.card.setCardBackgroundColor(if (selected) BG_SELECTED else BG_NORMAL)
        holder.card.strokeColor = if (selected) STROKE_SELECTED else STROKE_NORMAL
        holder.checkbox.setOnCheckedChangeListener(null)
        holder.checkbox.visibility = View.VISIBLE
        holder.checkbox.isChecked = selected
        holder.checkbox.setOnCheckedChangeListener { _, _ ->
            itemAt(holder)?.let(onToggleSelect)
        }
    }

    private fun applyIcon(holder: ViewHolder, item: FileListItem) {
        when (item.iconRes) {
            FileListItem.ICON_RES_FOLDER -> {
                holder.iconView.imageTintList = null
                holder.iconView.setImageBitmap(FileTypeResolver.folderIconBitmap())
            }
            FileListItem.ICON_RES_EXTENSION_BADGE -> {
                holder.iconView.imageTintList = null
                holder.iconView.setImageBitmap(FileTypeResolver.extensionBadgeBitmap(item.badgeText, item.tintColor))
            }
            else -> {
                holder.iconView.setImageResource(item.iconRes)
                holder.iconView.imageTintList = tintFor(item.tintColor)
            }
        }
    }

    private fun tintFor(color: Int): ColorStateList {
        return tintStates[color] ?: ColorStateList.valueOf(color).also { tintStates[color] = it }
    }
}
