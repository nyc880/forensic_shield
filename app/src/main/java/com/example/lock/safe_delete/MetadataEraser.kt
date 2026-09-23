package com.example.lock.safe_delete

import android.app.PendingIntent
import android.content.ContentResolver
import android.content.ContentUris
import android.content.Context
import android.content.IntentSender
import android.database.Cursor
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.MediaStore
import java.io.File

data class MetadataReport(
    val rowsDeleted: Int,
    val thumbnailRowsDeleted: Int,
    val physicalThumbnailsPurged: Int,
    val providerItemDeleted: Boolean,
    val scannerNotified: Boolean,
    val warnings: List<String>
)

data class MediaRow(
    val id: Long,
    val mediaType: Int?,
    val displayName: String?,
    val dataPath: String?,
    val relativePath: String?,
    val isTrashed: Boolean
)

internal object MetadataEraser {

    val DOWNLOADS_URI: Uri = Uri.parse("content://media/external/downloads")

    const val VOLUME_EXTERNAL = "external"
    const val COLUMN_RELATIVE_PATH = "relative_path"
    const val COLUMN_IS_TRASHED = "is_trashed"

    private data class LegacyThumbPurge(val rows: Int, val files: Int)

    fun eraseForTarget(
        context: Context,
        targetFile: File?,
        targetName: String,
        contentUri: Uri?,
        deleteProviderItem: Boolean,
        physicalPurger: (File) -> Boolean
    ): MetadataReport {
        val warnings = mutableListOf<String>()
        val resolver = context.contentResolver
        val filesUri = MediaStore.Files.getContentUri(VOLUME_EXTERNAL)

        var rowsDeleted = 0
        var thumbnailRows = 0
        var physicalThumbs = 0

        val path = targetFile?.let { FsOps.canonicalPath(it) }
        val rowIdFromUri = rowIdFromContentUri(contentUri)
        val rows = queryRows(resolver, filesUri, path, targetName, rowIdFromUri, warnings)

        if (rows.isNotEmpty()) {
            for (row in rows) {
                val itemUri = ContentUris.withAppendedId(filesUri, row.id)

                val legacy = purgeDeprecatedThumbnailRows(
                    resolver, row.id, row.mediaType, physicalPurger, warnings
                )
                thumbnailRows += legacy.rows
                physicalThumbs += legacy.files

                if (deleteRow(resolver, itemUri, warnings)) rowsDeleted++

                deleteCollectionRow(resolver, MediaStore.Images.Media.EXTERNAL_CONTENT_URI, row.id, warnings)
                deleteCollectionRow(resolver, MediaStore.Video.Media.EXTERNAL_CONTENT_URI, row.id, warnings)
                deleteCollectionRow(resolver, MediaStore.Audio.Media.EXTERNAL_CONTENT_URI, row.id, warnings)
                deleteCollectionRow(resolver, DOWNLOADS_URI, row.id, warnings)

                notify(resolver, itemUri)
            }
        }

        if (path != null && deleteProviderItem) {
            try {
                val deletedByPath = resolver.delete(
                    filesUri,
                    "${MediaStore.MediaColumns.DATA} = ?",
                    arrayOf(path)
                )
                if (deletedByPath > 0) rowsDeleted += deletedByPath
            } catch (t: Throwable) {
                warnings.add("path-based MediaStore delete unavailable: ${t.message}")
            }
        }

        val trashed = purgeTrashedRows(resolver, filesUri, targetName, path, warnings)
        rowsDeleted += trashed

        var providerDeleted = false
        if (deleteProviderItem && contentUri != null) {
            providerDeleted = deleteThroughProvider(context, contentUri, warnings)
        }

        val scannerNotified = notifyMediaScanner(context, listOfNotNull(path))
        notify(resolver, filesUri)

        return MetadataReport(
            rowsDeleted = rowsDeleted,
            thumbnailRowsDeleted = thumbnailRows,
            physicalThumbnailsPurged = physicalThumbs,
            providerItemDeleted = providerDeleted,
            scannerNotified = scannerNotified,
            warnings = warnings
        )
    }

    fun rowIdFromContentUri(uri: Uri?): Long? {
        val candidate = uri ?: return null
        if (!MediaStore.AUTHORITY.equals(candidate.authority, ignoreCase = true)) return null
        val last = candidate.lastPathSegment ?: return null
        return last.toLongOrNull()
    }

    fun eraseForDirectory(
        context: Context,
        root: File,
        physicalPurger: (File) -> Boolean,
        warnings: MutableList<String>
    ): Int {
        if (!root.isDirectory) return 0
        val resolver = context.contentResolver
        val filesUri = MediaStore.Files.getContentUri(VOLUME_EXTERNAL)
        val prefix = FsOps.canonicalPath(root)
        val likePrefix = escapeLike(prefix) + "/%"
        var deleted = 0

        val projection = arrayOf(
            MediaStore.MediaColumns._ID,
            MediaStore.MediaColumns.DATA,
            MediaStore.MediaColumns.DISPLAY_NAME
        )

        val rows = LinkedHashMap<Long, MediaRow>()
        try {
            resolver.query(
                filesUri,
                projection,
                "${MediaStore.MediaColumns.DATA} LIKE ? ESCAPE '\\'",
                arrayOf(likePrefix),
                null
            )?.use { cursor ->
                val idIndex = cursor.getColumnIndex(MediaStore.MediaColumns._ID)
                val dataIndex = cursor.getColumnIndex(MediaStore.MediaColumns.DATA)
                val nameIndex = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
                while (cursor.moveToNext()) {
                    if (idIndex < 0) break
                    val id = cursor.getLong(idIndex)
                    val rowPath = if (dataIndex >= 0) cursor.getString(dataIndex) else null
                    if (rowPath == null) continue
                    val normalized = rowPath.trimEnd('/')
                    if (normalized != prefix && !normalized.startsWith("$prefix/")) continue
                    rows[id] = MediaRow(
                        id = id,
                        mediaType = null,
                        displayName = if (nameIndex >= 0) cursor.getString(nameIndex) else null,
                        dataPath = rowPath,
                        relativePath = null,
                        isTrashed = false
                    )
                }
            }
        } catch (t: Throwable) {
            warnings.add("directory MediaStore query failed: ${t.message}")
        }

        if (rows.isEmpty() && Build.VERSION.SDK_INT >= 29) {
            rows.putAll(queryRowsByRelativePath(context, resolver, filesUri, root, warnings))
        }

        for (row in rows.values) {
            val itemUri = ContentUris.withAppendedId(filesUri, row.id)
            if (deleteRow(resolver, itemUri, warnings)) deleted++
            if (row.mediaType == null) {
                physicalThumbnailsPurgedFor(resolver, row.id, physicalPurger, warnings)
            }
            notify(resolver, itemUri)
        }

        if (deleted > 0) notifyMediaScanner(context, listOf(prefix))
        return deleted
    }

    private fun physicalThumbnailsPurgedFor(
        resolver: ContentResolver,
        mediaId: Long,
        physicalPurger: (File) -> Boolean,
        warnings: MutableList<String>
    ) {
        if (Build.VERSION.SDK_INT >= 29) return
        purgeDeprecatedThumbnailRows(resolver, mediaId, null, physicalPurger, warnings)
    }

    fun queryRows(
        resolver: ContentResolver,
        filesUri: Uri,
        canonicalPath: String?,
        displayName: String,
        rowIdFromUri: Long?,
        warnings: MutableList<String>
    ): List<MediaRow> {
        val projection = mutableListOf(
            MediaStore.MediaColumns._ID,
            MediaStore.MediaColumns.DATA,
            MediaStore.MediaColumns.DISPLAY_NAME,
            MediaStore.Files.FileColumns.MEDIA_TYPE
        )
        if (Build.VERSION.SDK_INT >= 29) {
            projection.add(COLUMN_RELATIVE_PATH)
            projection.add(COLUMN_IS_TRASHED)
        }

        val rows = LinkedHashMap<Long, MediaRow>()

        if (canonicalPath != null) {
            rows.putAll(
                runQuery(
                    resolver,
                    filesUri,
                    projection,
                    "${MediaStore.MediaColumns.DATA} = ?",
                    arrayOf(canonicalPath),
                    warnings
                )
            )
        }

        if (Build.VERSION.SDK_INT >= 29) {
            val relativeGuess = canonicalPath?.let { buildRelativePath(it) }
            if (relativeGuess != null && relativeGuess.isNotEmpty()) {
                rows.putAll(
                    runQuery(
                        resolver,
                        filesUri,
                        projection,
                        "${MediaStore.MediaColumns.DISPLAY_NAME} = ? AND " +
                            "$COLUMN_RELATIVE_PATH LIKE ?",
                        arrayOf(displayName, "%${escapeLike(relativeGuess.trim('/'))}%"),
                        warnings
                    )
                )
            }
        }

        if (rowIdFromUri != null) {
            rows.putAll(
                runQuery(
                    resolver,
                    filesUri,
                    projection,
                    "${MediaStore.MediaColumns._ID} = ?",
                    arrayOf(rowIdFromUri.toString()),
                    warnings
                )
            )
        }

        return rows.values.toList()
    }

    fun purgeTrashedRows(
        resolver: ContentResolver,
        filesUri: Uri,
        displayName: String,
        dataPath: String?,
        warnings: MutableList<String>
    ): Int {
        if (Build.VERSION.SDK_INT < 30 || displayName.isEmpty()) return 0
        var removed = 0
        try {
            val args = Bundle()
            args.putInt(MediaStore.QUERY_ARG_MATCH_TRASHED, MediaStore.MATCH_INCLUDE)
            val selection = StringBuilder("${MediaStore.MediaColumns.DISPLAY_NAME} = ?")
            val selectionArgs = mutableListOf(displayName)
            if (dataPath != null) {
                val fileName = dataPath.substringAfterLast('/')
                selection.append(" OR ${MediaStore.MediaColumns.DATA} LIKE ? ESCAPE '\\'")
                selectionArgs.add("%" + escapeLike("/.trashed-") + "%" + escapeLike(fileName))
            }
            args.putString(ContentResolver.QUERY_ARG_SQL_SELECTION, selection.toString())
            args.putStringArray(
                ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS,
                selectionArgs.toTypedArray()
            )
            val ids = mutableListOf<Long>()
            resolver.query(
                filesUri,
                arrayOf(MediaStore.MediaColumns._ID),
                args,
                null
            )?.use { cursor ->
                val idIndex = cursor.getColumnIndex(MediaStore.MediaColumns._ID)
                if (idIndex >= 0) {
                    while (cursor.moveToNext()) ids.add(cursor.getLong(idIndex))
                }
            }
            for (id in ids) {
                val itemUri = ContentUris.withAppendedId(filesUri, id)
                if (deleteRow(resolver, itemUri, warnings)) {
                    removed++
                    notify(resolver, itemUri)
                }
            }
        } catch (t: Throwable) {
            warnings.add("trashed rows purge failed: ${t.message}")
        }
        return removed
    }

    private fun buildRelativePath(absolutePath: String): String? {
        return try {
            val root = Environment.getExternalStorageDirectory().absolutePath
            if (absolutePath.startsWith(root)) {
                val relative = absolutePath.substring(root.length).trimStart('/')
                relative.substringBeforeLast('/', "")
            } else {
                null
            }
        } catch (t: Throwable) {
            null
        }
    }

    private fun runQuery(
        resolver: ContentResolver,
        uri: Uri,
        projection: List<String>,
        selection: String?,
        selectionArgs: Array<String>?,
        warnings: MutableList<String>
    ): Map<Long, MediaRow> {
        val result = LinkedHashMap<Long, MediaRow>()
        var cursor: Cursor? = null
        try {
            cursor = resolver.query(uri, projection.toTypedArray(), selection, selectionArgs, null)
            if (cursor == null) return result
            val idIndex = cursor.getColumnIndex(MediaStore.MediaColumns._ID)
            val dataIndex = cursor.getColumnIndex(MediaStore.MediaColumns.DATA)
            val nameIndex = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
            val typeIndex = cursor.getColumnIndex(MediaStore.Files.FileColumns.MEDIA_TYPE)
            val relativeIndex = cursor.getColumnIndex(COLUMN_RELATIVE_PATH)
            val trashedIndex = cursor.getColumnIndex(COLUMN_IS_TRASHED)

            while (cursor.moveToNext()) {
                if (idIndex < 0) break
                val id = cursor.getLong(idIndex)
                val row = MediaRow(
                    id = id,
                    mediaType = if (typeIndex >= 0) cursor.getInt(typeIndex) else null,
                    displayName = if (nameIndex >= 0) cursor.getString(nameIndex) else null,
                    dataPath = if (dataIndex >= 0) cursor.getString(dataIndex) else null,
                    relativePath = if (relativeIndex >= 0) cursor.getString(relativeIndex) else null,
                    isTrashed = if (trashedIndex >= 0) cursor.getInt(trashedIndex) == 1 else false
                )
                result[id] = row
            }
        } catch (t: Throwable) {
            warnings.add("MediaStore query failed: ${t.message}")
        } finally {
            try {
                cursor?.close()
            } catch (ignored: Throwable) {
            }
        }
        return result
    }

    @Suppress("DEPRECATION")
    private fun purgeDeprecatedThumbnailRows(
        resolver: ContentResolver,
        mediaId: Long,
        mediaType: Int?,
        physicalPurger: (File) -> Boolean,
        warnings: MutableList<String>
    ): LegacyThumbPurge {
        if (Build.VERSION.SDK_INT >= 29) return LegacyThumbPurge(0, 0)
        val idText = mediaId.toString()
        var files = 0
        var rows = 0

        val targets = mutableListOf<Triple<Uri, String, String>>()
        if (mediaType == null || mediaType == MediaStore.Files.FileColumns.MEDIA_TYPE_IMAGE) {
            targets.add(
                Triple(
                    MediaStore.Images.Thumbnails.EXTERNAL_CONTENT_URI,
                    MediaStore.Images.Thumbnails.IMAGE_ID,
                    MediaStore.Images.Thumbnails.DATA
                )
            )
        }
        if (mediaType == null || mediaType == MediaStore.Files.FileColumns.MEDIA_TYPE_VIDEO) {
            targets.add(
                Triple(
                    MediaStore.Video.Thumbnails.EXTERNAL_CONTENT_URI,
                    MediaStore.Video.Thumbnails.VIDEO_ID,
                    MediaStore.Video.Thumbnails.DATA
                )
            )
        }

        for ((uri, idColumn, dataColumn) in targets) {
            var cursor: Cursor? = null
            try {
                cursor = resolver.query(uri, arrayOf(dataColumn), "$idColumn = ?", arrayOf(idText), null)
                if (cursor != null) {
                    val dataIndex = cursor.getColumnIndex(dataColumn)
                    while (cursor.moveToNext()) {
                        val path = if (dataIndex >= 0) cursor.getString(dataIndex) else null
                        if (!path.isNullOrBlank()) {
                            val file = File(path)
                            if (file.exists() && physicalPurger(file)) files++
                        }
                    }
                }
                val removed = resolver.delete(uri, "$idColumn = ?", arrayOf(idText))
                if (removed > 0) rows += removed
            } catch (t: Throwable) {
                warnings.add("legacy thumbnail row purge failed: ${t.message}")
            } finally {
                try {
                    cursor?.close()
                } catch (ignored: Throwable) {
                }
            }
        }
        return LegacyThumbPurge(rows, files)
    }

    private fun deleteRow(resolver: ContentResolver, itemUri: Uri, warnings: MutableList<String>): Boolean =
        try {
            resolver.delete(itemUri, null, null) > 0
        } catch (t: Throwable) {
            warnings.add("row delete failed for $itemUri: ${t.message}")
            false
        }

    private fun deleteCollectionRow(
        resolver: ContentResolver,
        collection: Uri,
        id: Long,
        warnings: MutableList<String>
    ) {
        try {
            resolver.delete(
                collection,
                "${MediaStore.MediaColumns._ID} = ?",
                arrayOf(id.toString())
            )
        } catch (t: Throwable) {
            SecureLog.d("collection row delete skipped for $collection: ${t.message}")
        }
    }

    fun deleteThroughProvider(
        context: Context,
        uri: Uri,
        warnings: MutableList<String> = mutableListOf()
    ): Boolean {
        val resolver = context.contentResolver
        var deleted = false

        if (Build.VERSION.SDK_INT >= 19) {
            try {
                if (DocumentsContract.isDocumentUri(context, uri)) {
                    deleted = DocumentsContract.deleteDocument(resolver, uri)
                }
            } catch (t: Throwable) {
                warnings.add("SAF delete failed: ${t.message}")
            }
        }

        if (!deleted) {
            try {
                deleted = resolver.delete(uri, null, null) > 0
            } catch (t: Throwable) {
                warnings.add("provider delete failed: ${t.message}")
            }
        }

        if (deleted) notify(resolver, uri)
        return deleted
    }

    private fun queryRowsByRelativePath(
        context: Context,
        resolver: ContentResolver,
        filesUri: Uri,
        root: File,
        warnings: MutableList<String>
    ): Map<Long, MediaRow> {
        val found = LinkedHashMap<Long, MediaRow>()
        val rootPath = FsOps.canonicalPath(root)
        val volumeRoot = VolumeRoots.all(context)
        if (volumeRoot.isEmpty()) return found

        var relative = ""
        var bestRoot = ""
        for (candidate in volumeRoot) {
            val candidatePath = FsOps.canonicalPath(candidate)
            if (candidatePath == rootPath) return found
            if (rootPath.startsWith("$candidatePath/") && candidatePath.length > bestRoot.length) {
                bestRoot = candidatePath
                relative = rootPath.substring(candidatePath.length + 1)
            }
        }
        if (relative.isEmpty()) return found

        val pattern = "%" + escapeLike(relative.trimEnd('/')) + "%"
        val projection = arrayOf(
            MediaStore.MediaColumns._ID,
            MediaStore.MediaColumns.DATA,
            MediaStore.MediaColumns.DISPLAY_NAME,
            MediaStore.MediaColumns.RELATIVE_PATH
        )

        try {
            resolver.query(
                filesUri,
                projection,
                "${MediaStore.MediaColumns.RELATIVE_PATH} LIKE ? ESCAPE '\\'",
                arrayOf(pattern),
                null
            )?.use { cursor ->
                val idIndex = cursor.getColumnIndex(MediaStore.MediaColumns._ID)
                val dataIndex = cursor.getColumnIndex(MediaStore.MediaColumns.DATA)
                val nameIndex = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
                val relativeIndex = cursor.getColumnIndex(MediaStore.MediaColumns.RELATIVE_PATH)
                val expected = relative.trim('/')
                while (cursor.moveToNext()) {
                    if (idIndex < 0) break
                    val rowRelative = if (relativeIndex >= 0) cursor.getString(relativeIndex) else null
                    val normalized = rowRelative?.trim('/') ?: continue
                    if (normalized != expected && !normalized.startsWith("$expected/")) continue
                    val id = cursor.getLong(idIndex)
                    found[id] = MediaRow(
                        id = id,
                        mediaType = null,
                        displayName = if (nameIndex >= 0) cursor.getString(nameIndex) else null,
                        dataPath = if (dataIndex >= 0) cursor.getString(dataIndex) else null,
                        relativePath = rowRelative,
                        isTrashed = false
                    )
                }
            }
        } catch (t: Throwable) {
            warnings.add("relative path MediaStore query failed: ${t.message}")
        }
        return found
    }

    internal fun escapeLike(value: String): String {
        val builder = StringBuilder(value.length + 8)
        for (character in value) {
            when (character) {
                '\\', '%', '_' -> builder.append('\\').append(character)
                else -> builder.append(character)
            }
        }
        return builder.toString()
    }

    fun notifyMediaScanner(context: Context, paths: List<String>): Boolean {
        if (paths.isEmpty()) return false
        return try {
            MediaScannerConnection.scanFile(context, paths.toTypedArray(), null, null)
            true
        } catch (t: Throwable) {
            SecureLog.w("media scanner notify failed: ${t.message}")
            false
        }
    }

    fun notify(resolver: ContentResolver, uri: Uri) {
        try {
            resolver.notifyChange(uri, null)
        } catch (t: Throwable) {
            SecureLog.d("notifyChange failed: ${Sanitizer.clean(uri.toString())}")
        }
    }
}

object MediaStoreConsent {

    fun requiresUserConsent(context: Context, uris: List<Uri>): Boolean {
        if (uris.isEmpty()) return false
        if (Build.VERSION.SDK_INT < 30) return false
        if (isAllFilesAccessGranted()) return false
        return uris.any { it.authority == MediaStore.AUTHORITY }
    }

    fun isAllFilesAccessGranted(): Boolean = try {
        if (Build.VERSION.SDK_INT >= 30) {
            Environment.isExternalStorageManager()
        } else {
            true
        }
    } catch (t: Throwable) {
        false
    }

    fun buildDeleteRequest(context: Context, uris: List<Uri>): PendingIntent? {
        if (Build.VERSION.SDK_INT < 30 || uris.isEmpty()) return null
        return try {
            MediaStore.createDeleteRequest(context.contentResolver, uris)
        } catch (t: Throwable) {
            SecureLog.w("createDeleteRequest failed: ${Sanitizer.of(t)}")
            null
        }
    }

    fun launch(context: Context, pendingIntent: PendingIntent, requestCode: Int): Boolean {
        return try {
            val sender: IntentSender = pendingIntent.intentSender
            if (context is android.app.Activity) {
                context.startIntentSenderForResult(sender, requestCode, null, 0, 0, 0)
                true
            } else {
                false
            }
        } catch (t: Throwable) {
            SecureLog.w("delete request launch failed: ${Sanitizer.of(t)}")
            false
        }
    }
}
