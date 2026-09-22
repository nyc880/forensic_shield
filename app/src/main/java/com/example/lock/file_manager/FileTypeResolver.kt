package com.example.lock.file_manager

import android.R
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.webkit.MimeTypeMap
import java.io.File
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

enum class ResolvedFileType {
    IMAGE,
    VIDEO,
    AUDIO,
    PDF,
    TEXT,
    ARCHIVE,
    APK,
    ENCRYPTED,
    FOLDER,
    UNKNOWN
}

object FileTypeResolver {

    private const val ICON_SIZE = 128

    private val imageExt = setOf("jpg", "jpeg", "png", "webp", "gif", "bmp", "heic", "heif", "tif", "tiff")
    private val videoExt = setOf("mp4", "mkv", "mov", "avi", "webm", "3gp", "m4v", "ts", "mpg", "mpeg")
    private val audioExt = setOf("mp3", "wav", "aac", "m4a", "flac", "ogg", "opus", "amr")
    private val textExt = setOf("txt", "log", "json", "xml", "csv", "md", "kt", "java", "html", "js", "css", "yaml", "yml")
    private val archiveExt = setOf("zip", "rar", "7z", "tar", "gz")

    private val extensionCache = ConcurrentHashMap<String, ResolvedFileType>()
    private val tintColorCache = ConcurrentHashMap<ResolvedFileType, Int>()
    private val badgeBitmapCache = ConcurrentHashMap<String, Bitmap>()
    private val bitmapLock = Any()
    private var cachedFolderBitmap: Bitmap? = null

    fun resolve(file: File): ResolvedFileType {
        if (file.isDirectory) return ResolvedFileType.FOLDER
        return resolveExtension(file.extension)
    }

    fun resolveFile(name: String, isDirectory: Boolean): ResolvedFileType {
        if (isDirectory) return ResolvedFileType.FOLDER
        val dot = name.lastIndexOf('.')
        val ext = if (dot < 0) "" else name.substring(dot + 1)
        return resolveExtension(ext)
    }

    private fun resolveExtension(rawExt: String): ResolvedFileType {
        val ext = rawExt.lowercase(Locale.ROOT)
        extensionCache[ext]?.let { return it }
        val mime = if (ext.isEmpty()) {
            null
        } else {
            try {
                MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext)?.lowercase(Locale.ROOT)
            } catch (_: Exception) {
                null
            }
        }
        val type = when {
            ext in imageExt || mime?.startsWith("image/") == true -> ResolvedFileType.IMAGE
            ext in videoExt || mime?.startsWith("video/") == true -> ResolvedFileType.VIDEO
            ext in audioExt || mime?.startsWith("audio/") == true -> ResolvedFileType.AUDIO
            ext == "pdf" || mime == "application/pdf" -> ResolvedFileType.PDF
            ext in textExt || mime?.startsWith("text/") == true -> ResolvedFileType.TEXT
            ext in archiveExt -> ResolvedFileType.ARCHIVE
            ext == "apk" -> ResolvedFileType.APK
            ext == "enc" -> ResolvedFileType.ENCRYPTED
            else -> ResolvedFileType.UNKNOWN
        }
        extensionCache[ext] = type
        return type
    }

    fun badge(type: ResolvedFileType, extension: String): String {
        return when (type) {
            ResolvedFileType.IMAGE -> "IMAGE"
            ResolvedFileType.VIDEO -> "VIDEO"
            ResolvedFileType.AUDIO -> "AUDIO"
            ResolvedFileType.PDF -> "PDF"
            ResolvedFileType.TEXT -> "TEXT"
            ResolvedFileType.ARCHIVE -> "ARCHIVE"
            ResolvedFileType.APK -> "APK"
            ResolvedFileType.ENCRYPTED -> "ENC"
            ResolvedFileType.FOLDER -> "FOLDER"
            ResolvedFileType.UNKNOWN -> if (extension.isBlank()) "FILE" else extension.uppercase(Locale.getDefault())
        }
    }

    fun icon(type: ResolvedFileType): Int {
        return when (type) {
            ResolvedFileType.IMAGE -> R.drawable.ic_menu_gallery
            ResolvedFileType.VIDEO -> R.drawable.ic_media_play
            ResolvedFileType.AUDIO -> R.drawable.ic_media_ff
            ResolvedFileType.PDF -> R.drawable.ic_menu_view
            ResolvedFileType.TEXT -> R.drawable.ic_menu_edit
            ResolvedFileType.ARCHIVE -> R.drawable.ic_menu_upload
            ResolvedFileType.APK -> R.drawable.sym_def_app_icon
            ResolvedFileType.ENCRYPTED -> R.drawable.ic_lock_lock
            ResolvedFileType.FOLDER -> R.drawable.ic_menu_agenda
            ResolvedFileType.UNKNOWN -> R.drawable.ic_menu_save
        }
    }

    fun tint(type: ResolvedFileType): String {
        return when (type) {
            ResolvedFileType.FOLDER -> "#86B7FF"
            ResolvedFileType.ENCRYPTED -> "#FFD76A"
            ResolvedFileType.IMAGE -> "#7CD8FF"
            ResolvedFileType.VIDEO -> "#B388FF"
            ResolvedFileType.AUDIO -> "#6EF0C2"
            ResolvedFileType.PDF -> "#FF8E8E"
            ResolvedFileType.TEXT -> "#9BE27A"
            ResolvedFileType.ARCHIVE -> "#FFB86B"
            ResolvedFileType.APK -> "#72F1B8"
            ResolvedFileType.UNKNOWN -> "#79C7FF"
        }
    }

    fun tintColor(type: ResolvedFileType): Int {
        tintColorCache[type]?.let { return it }
        val parsed = try {
            Color.parseColor(tint(type))
        } catch (_: Exception) {
            0xFFFFFFFF.toInt()
        }
        tintColorCache[type] = parsed
        return parsed
    }

    fun folderIconBitmap(): Bitmap {
        cachedFolderBitmap?.let { return it }
        synchronized(bitmapLock) {
            cachedFolderBitmap?.let { return it }
            val bitmap = Bitmap.createBitmap(ICON_SIZE, ICON_SIZE, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)
            val base = tintColor(ResolvedFileType.FOLDER)
            val back = shift(base, 0.62f)
            val backPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = back }
            val frontPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = base }
            canvas.drawRoundRect(RectF(10f, 32f, ICON_SIZE - 10f, ICON_SIZE - 22f), 14f, 14f, backPaint)
            canvas.drawRoundRect(RectF(10f, 20f, 58f, 44f), 10f, 10f, backPaint)
            canvas.drawRoundRect(RectF(10f, 38f, ICON_SIZE - 10f, ICON_SIZE - 22f), 14f, 14f, frontPaint)
            cachedFolderBitmap = bitmap
            return bitmap
        }
    }

    fun extensionBadgeBitmap(badge: String, tint: Int): Bitmap {
        val label = if (badge.isBlank()) "FILE" else badge.uppercase(Locale.getDefault()).take(4)
        badgeBitmapCache[label]?.let { return it }
        synchronized(bitmapLock) {
            badgeBitmapCache[label]?.let { return it }
            val bitmap = Bitmap.createBitmap(ICON_SIZE, ICON_SIZE, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)
            val rect = RectF(6f, 6f, ICON_SIZE - 6f, ICON_SIZE - 6f)
            val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = overlay(tint, 0x30) }
            val strokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = tint
                style = Paint.Style.STROKE
                strokeWidth = 6f
            }
            canvas.drawRoundRect(rect, 26f, 26f, fillPaint)
            canvas.drawRoundRect(rect, 26f, 26f, strokePaint)
            val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = Color.WHITE
                textAlign = Paint.Align.CENTER
                isFakeBoldText = true
                textSize = 44f
            }
            var size = 44f
            while (size > 20f && textPaint.measureText(label) > ICON_SIZE - 28f) {
                size -= 4f
                textPaint.textSize = size
            }
            val baseline = ICON_SIZE / 2f - (textPaint.descent() + textPaint.ascent()) / 2f
            canvas.drawText(label, ICON_SIZE / 2f, baseline, textPaint)
            badgeBitmapCache[label] = bitmap
            return bitmap
        }
    }

    private fun shift(color: Int, factor: Float): Int {
        val r = (Color.red(color) * factor).toInt().coerceIn(0, 255)
        val g = (Color.green(color) * factor).toInt().coerceIn(0, 255)
        val b = (Color.blue(color) * factor).toInt().coerceIn(0, 255)
        return Color.rgb(r, g, b)
    }

    private fun overlay(color: Int, alpha: Int): Int {
        return (alpha shl 24) or (color and 0x00FFFFFF)
    }
}
