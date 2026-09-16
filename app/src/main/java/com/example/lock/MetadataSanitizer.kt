package com.example.lock

import android.content.ContentUris
import android.content.Context
import android.media.MediaScannerConnection
import android.net.Uri
import android.provider.MediaStore
import java.io.File

object MetadataSanitizer {

    fun sanitizeMediaStoreAfterDelete(context: Context, file: File): Boolean {
        return try {
            val path = file.absolutePath
            val contentResolver = context.contentResolver

            val filesUri: Uri = MediaStore.Files.getContentUri("external")
            val projection = arrayOf(MediaStore.Files.FileColumns._ID)
            val selection = "${MediaStore.Files.FileColumns.DATA} = ?"
            val selectionArgs = arrayOf(path)

            var mediaId: Long? = null

            contentResolver.query(filesUri, projection, selection, selectionArgs, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idIndex = cursor.getColumnIndex(MediaStore.Files.FileColumns._ID)
                    if (idIndex != -1) {
                        mediaId = cursor.getLong(idIndex)
                    }
                }
            }

            val mediaDeleted: Boolean = if (mediaId != null) {
                val itemUri = ContentUris.withAppendedId(filesUri, mediaId!!)
                val rows = contentResolver.delete(itemUri, null, null)

                val imageThumbUri = MediaStore.Images.Thumbnails.EXTERNAL_CONTENT_URI
                contentResolver.delete(imageThumbUri, "${MediaStore.Images.Thumbnails.IMAGE_ID} = ?", arrayOf(mediaId.toString()))

                val videoThumbUri = MediaStore.Video.Thumbnails.EXTERNAL_CONTENT_URI
                contentResolver.delete(videoThumbUri, "${MediaStore.Video.Thumbnails.VIDEO_ID} = ?", arrayOf(mediaId.toString()))

                rows > 0
            } else {
                true
            }

            cleanPhysicalThumbnails(file)

            MediaScannerConnection.scanFile(
                context.applicationContext,
                arrayOf(path),
                null
            ) { _, _ -> }

            mediaDeleted
        } catch (_: Exception) {
            false
        }
    }

    private fun cleanPhysicalThumbnails(file: File) {
        try {
            val parent = file.parentFile ?: return
            val thumbDir = File(parent, ".thumbnails")
            if (thumbDir.exists() && thumbDir.isDirectory) {
                val fileNameWithoutExt = file.nameWithoutExtension
                thumbDir.listFiles()?.forEach { thumbFile ->
                    if (thumbFile.name.contains(fileNameWithoutExt) || thumbFile.name.contains(file.name)) {
                        thumbFile.delete()
                    }
                }
            }
        } catch (_: Exception) {
        }
    }
}