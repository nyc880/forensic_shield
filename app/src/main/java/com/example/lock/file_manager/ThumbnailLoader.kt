package com.example.lock.file_manager

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.ImageDecoder
import android.graphics.Paint
import android.graphics.Path
import android.media.MediaMetadataRetriever
import android.os.Build
import android.util.LruCache
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object ThumbnailLoader {

    private const val THUMB_SIZE = 256

    private val cache = object : LruCache<String, Bitmap>(cacheSizeKb()) {
        override fun sizeOf(key: String, value: Bitmap): Int {
            return (value.byteCount / 1024).coerceAtLeast(1)
        }
    }

    private fun cacheSizeKb(): Int {
        val maxMemoryKb = (Runtime.getRuntime().maxMemory() / 1024).toInt()
        return (maxMemoryKb / 8).coerceIn(4 * 1024, 32 * 1024)
    }

    fun get(path: String): Bitmap? = cache.get(path)

    fun evict(path: String) {
        cache.remove(path)
    }

    fun clear() {
        cache.evictAll()
    }

    suspend fun load(path: String): Bitmap? = load(path, isVideo = false)

    suspend fun load(path: String, isVideo: Boolean): Bitmap? = withContext(Dispatchers.IO) {
        cache.get(path)?.let { return@withContext it }
        val file = File(path)
        if (!file.isFile || !file.exists() || file.length() <= 0L) return@withContext null
        val bitmap = try {
            if (isVideo) decodeVideo(file) else decodeModern(file)
        } catch (_: Exception) {
            try {
                if (isVideo) null else decodeLegacy(file)
            } catch (_: Exception) {
                null
            }
        }
        if (bitmap != null) cache.put(path, bitmap)
        bitmap
    }

    private fun decodeVideo(file: File): Bitmap? {
        val retriever = MediaMetadataRetriever()
        return try {
            retriever.setDataSource(file.absolutePath)
            var frame = retriever.getFrameAtTime(1_000_000L, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
            if (frame == null) frame = retriever.frameAtTime
            if (frame == null) return null
            applyPlayOverlay(downscale(frame))
        } catch (_: Exception) {
            null
        } finally {
            try {
                retriever.release()
            } catch (_: Exception) {
            }
        }
    }

    private fun downscale(source: Bitmap): Bitmap {
        val width = source.width
        val height = source.height
        if (width <= 0 || height <= 0) return source
        val ratio = minOf(
            THUMB_SIZE.toFloat() / width.toFloat(),
            THUMB_SIZE.toFloat() / height.toFloat()
        )
        if (ratio >= 1f) return source
        return Bitmap.createScaledBitmap(
            source,
            maxOf(1, (width * ratio).toInt()),
            maxOf(1, (height * ratio).toInt()),
            true
        )
    }

    private fun applyPlayOverlay(source: Bitmap): Bitmap {
        val bitmap = source.copy(Bitmap.Config.ARGB_8888, true) ?: return source
        val canvas = Canvas(bitmap)
        val cx = bitmap.width / 2f
        val cy = bitmap.height / 2f
        val radius = minOf(bitmap.width, bitmap.height) * 0.24f
        val circlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0x88000000.toInt() }
        canvas.drawCircle(cx, cy, radius, circlePaint)
        val arm = radius * 0.52f
        val triangle = Path()
        triangle.moveTo(cx - arm * 0.55f, cy - arm)
        triangle.lineTo(cx - arm * 0.55f, cy + arm)
        triangle.lineTo(cx + arm * 0.85f, cy)
        triangle.close()
        val trianglePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFFFFFFFF.toInt() }
        canvas.drawPath(triangle, trianglePaint)
        return bitmap
    }

    private fun decodeModern(file: File): Bitmap? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        val source = ImageDecoder.createSource(file)
        return ImageDecoder.decodeBitmap(source) { decoder, info, _ ->
            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            val width = info.size.width
            val height = info.size.height
            if (width > 0 && height > 0) {
                val ratio = minOf(
                    THUMB_SIZE.toFloat() / width.toFloat(),
                    THUMB_SIZE.toFloat() / height.toFloat()
                )
                if (ratio < 1f) {
                    decoder.setTargetSize(
                        maxOf(1, (width * ratio).toInt()),
                        maxOf(1, (height * ratio).toInt())
                    )
                }
            }
        }
    }

    private fun decodeLegacy(file: File): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        val options = BitmapFactory.Options().apply {
            inSampleSize = sampleSize(bounds.outWidth, bounds.outHeight)
            inPreferredConfig = Bitmap.Config.RGB_565
        }
        return BitmapFactory.decodeFile(file.absolutePath, options)
    }

    private fun sampleSize(width: Int, height: Int): Int {
        var sample = 1
        val halfWidth = width / 2
        val halfHeight = height / 2
        while (halfWidth / sample >= THUMB_SIZE && halfHeight / sample >= THUMB_SIZE) {
            sample *= 2
        }
        return sample.coerceAtLeast(1)
    }
}
