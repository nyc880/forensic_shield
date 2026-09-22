package com.example.lock.file_manager

import android.R
import android.content.Context
import android.text.format.Formatter
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class FileListItem(
    val path: String,
    val name: String,
    val isDirectory: Boolean,
    val detailsLine: String,
    val badgeText: String,
    val iconRes: Int,
    val tintColor: Int,
    val nameColor: Int,
    val showImagePreview: Boolean,
    val isVideoPreview: Boolean,
    val sizeBytes: Long,
    val lastModified: Long,
    val highlightRanges: List<IntRange> = emptyList()
) {
    companion object {
        const val ICON_RES_FOLDER = -2
        const val ICON_RES_EXTENSION_BADGE = -3
    }
}

object FileListItems {

    private val nameDefault = 0xFFF4F8FC.toInt()
    private val nameEncrypted = 0xFFFFD76A.toInt()
    private val threadDateFormat = ThreadLocal<SimpleDateFormat>()

    fun fromFile(
        file: File,
        size: Long,
        modified: Long,
        childCount: Int?,
        context: Context
    ): FileListItem {
        val isDir = file.isDirectory
        val type = FileTypeResolver.resolveFile(file.name, isDir)
        val details = if (isDir) {
            "${childCount ?: 0} items"
        } else {
            formatFileDetails(context, size, modified)
        }
        return build(file.absolutePath, file.name, isDir, details, type, file.extension, size, modified)
    }

    fun fromIndexed(
        entry: FileSearchEngine.IndexedFile,
        highlightTokens: List<String>,
        context: Context
    ): FileListItem {
        val type = FileTypeResolver.resolveFile(entry.name, entry.isDirectory)
        val location = parentName(entry.path)
        val details = if (entry.isDirectory) {
            location
        } else {
            val base = formatFileDetails(context, entry.size, entry.lastModified)
            if (location.isEmpty()) base else "$base • $location"
        }
        val item = build(entry.path, entry.name, entry.isDirectory, details, type, entry.extension, entry.size, entry.lastModified)
        return item.copy(highlightRanges = highlightRanges(entry.name, highlightTokens))
    }

    fun highlightRanges(name: String, tokens: List<String>): List<IntRange> {
        if (tokens.isEmpty() || name.isEmpty()) return emptyList()
        val lower = name.lowercase(Locale.ROOT)
        val ranges = ArrayList<IntRange>()
        for (raw in tokens) {
            val token = raw.lowercase(Locale.ROOT)
            if (token.isEmpty()) continue
            var from = 0
            while (from <= lower.length - token.length) {
                val index = lower.indexOf(token, from)
                if (index < 0) break
                ranges.add(index until index + token.length)
                from = index + token.length
            }
        }
        if (ranges.isEmpty()) return emptyList()
        return ranges.sortedBy { it.first }
    }

    private fun build(
        path: String,
        name: String,
        isDir: Boolean,
        details: String,
        type: ResolvedFileType,
        extension: String,
        size: Long,
        modified: Long
    ): FileListItem {
        val badge = if (isDir) "FOLDER" else FileTypeResolver.badge(type, extension)
        val icon = when {
            isDir -> FileListItem.ICON_RES_FOLDER
            type == ResolvedFileType.IMAGE -> R.drawable.ic_menu_gallery
            type == ResolvedFileType.VIDEO -> R.drawable.ic_media_play
            else -> FileListItem.ICON_RES_EXTENSION_BADGE
        }
        val nameColor = if (!isDir && type == ResolvedFileType.ENCRYPTED) nameEncrypted else nameDefault
        val preview = !isDir && (type == ResolvedFileType.IMAGE || type == ResolvedFileType.VIDEO) && size > 0L
        return FileListItem(
            path = path,
            name = name,
            isDirectory = isDir,
            detailsLine = details,
            badgeText = badge,
            iconRes = icon,
            tintColor = FileTypeResolver.tintColor(type),
            nameColor = nameColor,
            showImagePreview = preview,
            isVideoPreview = preview && type == ResolvedFileType.VIDEO,
            sizeBytes = size,
            lastModified = modified
        )
    }

    private fun formatFileDetails(context: Context, size: Long, modified: Long): String {
        val sizeText = try {
            Formatter.formatShortFileSize(context, size)
        } catch (_: Exception) {
            size.toString()
        }
        val dateText = try {
            dateFormat().format(Date(modified))
        } catch (_: Exception) {
            ""
        }
        return if (dateText.isEmpty()) sizeText else "$sizeText • $dateText"
    }

    private fun parentName(path: String): String {
        return try {
            File(path).parentFile?.name ?: ""
        } catch (_: Exception) {
            ""
        }
    }

    private fun dateFormat(): SimpleDateFormat {
        var format = threadDateFormat.get()
        if (format == null) {
            format = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
            threadDateFormat.set(format)
        }
        return format
    }
}
