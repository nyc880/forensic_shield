package com.example.lock.crypto

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.pdf.PdfDocument
import android.graphics.pdf.PdfRenderer
import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaMuxer
import android.os.ParcelFileDescriptor
import java.io.*
import java.nio.ByteBuffer
import java.util.*

object SecureMetadataStripper {

    private const val DEFAULT_JPEG_QUALITY = 95
    private const val MAX_IMAGE_DIMENSION = 4096
    private const val VIDEO_BUFFER_SIZE = 2 * 1024 * 1024

    fun stripImage(inputStream: InputStream, outputStream: OutputStream): Boolean {
        return try {
            val bytes = inputStream.readBytes()
            val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
            options.inSampleSize = calculateInSampleSize(options, MAX_IMAGE_DIMENSION, MAX_IMAGE_DIMENSION)
            options.inJustDecodeBounds = false
            val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options) ?: return false
            val success = bitmap.compress(Bitmap.CompressFormat.JPEG, DEFAULT_JPEG_QUALITY, outputStream)
            outputStream.flush()
            bitmap.recycle()
            bytes.fill(0)
            success
        } catch (e: Exception) { false }
    }

    fun stripMedia(inputPath: String, outputPath: String): Boolean {
        var extractor: MediaExtractor? = null
        var muxer: MediaMuxer? = null
        val buffer = ByteBuffer.allocate(VIDEO_BUFFER_SIZE)
        return try {
            extractor = MediaExtractor().apply { setDataSource(inputPath) }
            muxer = MediaMuxer(outputPath, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
            val trackCount = extractor.trackCount
            val trackMap = HashMap<Int, Int>()
            for (i in 0 until trackCount) {
                val format = extractor.getTrackFormat(i)
                trackMap[i] = muxer.addTrack(format)
                extractor.selectTrack(i)
            }
            muxer.start()
            val bufferInfo = MediaCodec.BufferInfo()
            while (true) {
                bufferInfo.offset = 0
                bufferInfo.size = extractor.readSampleData(buffer, 0)
                if (bufferInfo.size < 0) break
                bufferInfo.presentationTimeUs = extractor.sampleTime
                val sampleFlags = extractor.sampleFlags
                var codecFlags = 0
                if ((sampleFlags and MediaExtractor.SAMPLE_FLAG_SYNC) != 0) codecFlags = codecFlags or MediaCodec.BUFFER_FLAG_KEY_FRAME
                bufferInfo.flags = codecFlags
                muxer.writeSampleData(trackMap[extractor.sampleTrackIndex]!!, buffer, bufferInfo)
                extractor.advance()
            }
            true
        } catch (e: Exception) { false } finally {
            try { muxer?.stop() } catch (e: Exception) {}
            muxer?.release(); extractor?.release(); buffer.array().fill(0)
        }
    }

    fun stripPdf(file: File, outputStream: OutputStream): Boolean {
        var pfd: ParcelFileDescriptor? = null
        var renderer: PdfRenderer? = null
        val newDoc = PdfDocument()
        return try {
            pfd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
            renderer = PdfRenderer(pfd)
            for (i in 0 until renderer.pageCount) {
                val page = renderer.openPage(i)
                val bitmap = Bitmap.createBitmap(page.width * 2, page.height * 2, Bitmap.Config.ARGB_8888)
                page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_PRINT)
                val newPage = newDoc.startPage(PdfDocument.PageInfo.Builder(page.width, page.height, i).create())
                newPage.canvas.drawBitmap(bitmap, android.graphics.Rect(0, 0, bitmap.width, bitmap.height), android.graphics.Rect(0, 0, page.width, page.height), null)
                newDoc.finishPage(newPage)
                bitmap.recycle(); page.close()
            }
            newDoc.writeTo(outputStream); true
        } catch (e: Exception) { false } finally { newDoc.close(); renderer?.close(); pfd?.close() }
    }

    private fun calculateInSampleSize(options: BitmapFactory.Options, reqWidth: Int, reqHeight: Int): Int {
        var inSampleSize = 1
        if (options.outHeight > reqHeight || options.outWidth > reqWidth) {
            val halfH = options.outHeight / 2; val halfW = options.outWidth / 2
            while (halfH / inSampleSize >= reqHeight && halfW / inSampleSize >= reqWidth) inSampleSize *= 2
        }
        return inSampleSize
    }
}
