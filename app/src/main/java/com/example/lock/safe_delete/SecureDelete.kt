package com.example.lock.safe_delete

import android.content.ContentUris
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.MediaStore
import java.io.File

internal object TargetResolver {

    private const val AUTHORITY_EXTERNAL_STORAGE = "com.android.externalstorage.documents"
    private const val AUTHORITY_DOWNLOADS = "com.android.providers.downloads.documents"
    private const val AUTHORITY_MEDIA = "com.android.providers.media.documents"
    private const val AUTHORITY_MEDIA_STORE = "media"

    fun resolvePathForUri(context: Context, uri: Uri): String? {
        try {
            if ("file".equals(uri.scheme, ignoreCase = true)) {
                return uri.path
            }

            if (DocumentsContract.isDocumentUri(context, uri)) {
                resolveDocumentUri(context, uri)?.let { return it }
            }

            if (AUTHORITY_MEDIA_STORE.equals(uri.authority, ignoreCase = true)) {
                return queryDataColumn(context, uri, null, null)
            }
        } catch (t: Throwable) {
            SecureLog.d("uri resolution failed: ${Sanitizer.of(t, uri.toString())}")
        }
        return null
    }

    private fun resolveDocumentUri(context: Context, uri: Uri): String? {
        val documentId = try {
            DocumentsContract.getDocumentId(uri)
        } catch (t: Throwable) {
            return null
        }

        when (uri.authority) {
            AUTHORITY_EXTERNAL_STORAGE -> {
                val separator = documentId.indexOf(':')
                if (separator <= 0 || separator == documentId.lastIndex) return null
                val volume = documentId.substring(0, separator)
                val relative = documentId.substring(separator + 1)
                if ("primary".equals(volume, ignoreCase = true)) {
                    val root = Environment.getExternalStorageDirectory()?.absolutePath ?: return null
                    return "$root/$relative"
                }
                return "/storage/$volume/$relative"
            }

            AUTHORITY_DOWNLOADS -> {
                if (documentId.startsWith("raw:")) return documentId.substring(4)
                if (documentId.startsWith("msf:")) {
                    val mediaId = documentId.substring(4).toLongOrNull() ?: return null
                    return queryDataColumn(
                        context,
                        MediaStore.Files.getContentUri(MetadataEraser.VOLUME_EXTERNAL),
                        "${MediaStore.MediaColumns._ID} = ?",
                        arrayOf(mediaId.toString())
                    )
                }
                val id = documentId.toLongOrNull() ?: return null
                return queryDataColumn(
                    context,
                    ContentUris.withAppendedId(Uri.parse("content://downloads/public_downloads"), id),
                    null,
                    null
                )
            }

            AUTHORITY_MEDIA -> {
                val separator = documentId.indexOf(':')
                if (separator <= 0 || separator == documentId.lastIndex) return null
                val kind = documentId.substring(0, separator)
                val id = documentId.substring(separator + 1)
                val collection = when (kind) {
                    "image" -> MediaStore.Images.Media.EXTERNAL_CONTENT_URI
                    "video" -> MediaStore.Video.Media.EXTERNAL_CONTENT_URI
                    "audio" -> MediaStore.Audio.Media.EXTERNAL_CONTENT_URI
                    else -> MediaStore.Files.getContentUri(MetadataEraser.VOLUME_EXTERNAL)
                }
                return queryDataColumn(context, collection, "${MediaStore.MediaColumns._ID} = ?", arrayOf(id))
            }
        }
        return null
    }

    private fun queryDataColumn(
        context: Context,
        uri: Uri,
        selection: String?,
        selectionArgs: Array<String>?
    ): String? {
        return try {
            context.contentResolver.query(
                uri,
                arrayOf(MediaStore.MediaColumns.DATA),
                selection,
                selectionArgs,
                null
            )?.use { cursor ->
                val index = cursor.getColumnIndex(MediaStore.MediaColumns.DATA)
                if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
            }
        } catch (t: Throwable) {
            SecureLog.d("data column query failed: ${Sanitizer.of(t, uri.toString())}")
            null
        }
    }

    fun hasAllFilesAccess(): Boolean = MediaStoreConsent.isAllFilesAccessGranted()
}

object SecureDelete {

    private val startupCleanupDone = java.util.concurrent.atomic.AtomicBoolean(false)

    fun onAppStart(context: Context, awaitMillis: Long = 0L): Int {
        val app = context.applicationContext
        startupCleanupDone.set(true)
        val holder = intArrayOf(0)
        val worker = Thread {
            holder[0] = try {
                DeepCleaner.cleanupLeftovers(app)
            } catch (t: Throwable) {
                0
            }
        }
        worker.start()
        if (awaitMillis > 0L) {
            try {
                worker.join(awaitMillis)
            } catch (ignored: InterruptedException) {
            }
        }
        return holder[0]
    }

    private fun ensureStartupCleanup(context: Context) {
        if (startupCleanupDone.compareAndSet(false, true)) {
            val app = context.applicationContext
            Thread {
                try {
                    DeepCleaner.cleanupLeftovers(app)
                } catch (t: Throwable) {
                    SecureLog.d("startup cleanup failed")
                }
            }.start()
        }
    }

    fun purgeFiles(
        context: Context,
        files: List<File>,
        options: PurgeOptions = PurgeOptions(),
        listener: ProgressListener? = null,
        cancel: CancellationToken = NeverCancelled,
        audit: AuditSink = NullAuditSink
    ): SessionReport = purge(
        context = context,
        targets = files.map { DeleteTarget.of(it) },
        options = options,
        listener = listener,
        cancel = cancel,
        audit = audit
    )

    fun purgePaths(
        context: Context,
        paths: List<String>,
        options: PurgeOptions = PurgeOptions(),
        listener: ProgressListener? = null,
        cancel: CancellationToken = NeverCancelled,
        audit: AuditSink = NullAuditSink
    ): SessionReport = purge(
        context = context,
        targets = paths.map { DeleteTarget.ofPath(it) },
        options = options,
        listener = listener,
        cancel = cancel,
        audit = audit
    )

    fun purgeUris(
        context: Context,
        uris: List<Uri>,
        options: PurgeOptions = PurgeOptions(),
        listener: ProgressListener? = null,
        cancel: CancellationToken = NeverCancelled,
        audit: AuditSink = NullAuditSink
    ): SessionReport = purge(
        context = context,
        targets = uris.map { DeleteTarget.ofUri(context, it) },
        options = options,
        listener = listener,
        cancel = cancel,
        audit = audit
    )

    fun purge(
        context: Context,
        targets: List<DeleteTarget>,
        options: PurgeOptions = PurgeOptions(),
        listener: ProgressListener? = null,
        cancel: CancellationToken = NeverCancelled,
        audit: AuditSink = NullAuditSink
    ): SessionReport {
        ensureStartupCleanup(context)
        val sink = resolveAuditSink(context, options, audit)
        val orchestrator = PurgeOrchestrator(
            context = context.applicationContext,
            options = options,
            listener = listener,
            cancel = cancel,
            audit = sink
        )
        return try {
            orchestrator.execute(targets)
        } finally {
            (sink as? SqliteAuditLedger)?.close()
        }
    }

    fun analyze(
        context: Context,
        targets: List<DeleteTarget>,
        options: PurgeOptions = PurgeOptions()
    ): SessionReport = purge(
        context = context,
        targets = targets,
        options = options.copy(dryRun = true, writeLedger = false, deepClean = false)
    )

    fun maintenance(
        context: Context,
        bytesBudget: Long = SecureDeleteConfig.PRESSURE_CAP_BYTES,
        options: PurgeOptions = PurgeOptions()
    ): MaintenanceReport {
        ensureStartupCleanup(context)
        val orchestrator = PurgeOrchestrator(
            context = context.applicationContext,
            options = options,
            listener = null,
            cancel = NeverCancelled,
            audit = NullAuditSink
        )
        return orchestrator.maintenanceOnly(bytesBudget, options.deepCleanConfig)
    }

    fun deepClean(
        context: Context,
        config: DeepCleanConfig = DeepCleanConfig(),
        cancel: CancellationToken = NeverCancelled,
        onProgress: ((Long, Long) -> Unit)? = null
    ): DeepCleaner.Result = DeepCleaner.run(
        context.applicationContext,
        config,
        cancel,
        onProgress ?: { _, _ -> }
    )

    fun cleanupStalePressure(context: Context): Int =
        DeepCleaner.cleanupLeftovers(context.applicationContext)

    fun isDeviceCharging(context: Context): Boolean? =
        DeepCleaner.isCharging(context.applicationContext)

    fun ledgerEntries(context: Context, limit: Int = 100): List<LedgerEntry> {
        val ledger = SqliteAuditLedger.open(context) ?: return emptyList()
        return try {
            ledger.recent(limit)
        } finally {
            ledger.close()
        }
    }

    fun destroyLedger(context: Context): Boolean = LedgerMaintenance.secureDestroy(context)

    fun totalSize(files: List<File>): Long = files.sumOf { sizeOf(it) }

    fun sizeOf(target: File): Long {
        return try {
            when {
                !target.exists() -> 0L
                target.isFile -> target.length()
                else -> {
                    var total = 0L
                    target.walkBottomUp().take(MAX_SIZE_WALK_NODES).forEach { node ->
                        if (node.isFile) total += node.length()
                    }
                    total
                }
            }
        } catch (t: Throwable) {
            0L
        }
    }

    fun describeReport(report: SessionReport): String {
        val builder = StringBuilder()
        builder.append("level=").append(report.level.name)
        builder.append(" verify=").append(report.verifyMode.name)
        builder.append(" shredded=").append(report.successCount)
        builder.append(" failed=").append(report.failureCount)
        builder.append(" bytes=").append(report.totalBytesShredded)
        builder.append(" deepCleanBytes=").append(report.pressureBytes)
        builder.append(" deepClean=").append(report.deepCleanExecuted)
        builder.append(" deepCleanPending=").append(report.deepCleanPending)
        builder.append(" assurance=").append(report.assurance.name)
        builder.append(" weak=").append(report.weakDeletionCount)
        builder.append(" elapsedMs=").append(report.totalElapsedMs)
        if (report.failedTargets.isNotEmpty()) {
            builder.append(" failures=")
            builder.append(report.failedTargets.joinToString(",") { it.target.displayName })
        }
        return builder.toString()
    }

    private fun resolveAuditSink(context: Context, options: PurgeOptions, provided: AuditSink): AuditSink {
        if (provided !== NullAuditSink) return provided
        if (!options.writeLedger || options.dryRun) return NullAuditSink
        return SqliteAuditLedger.open(context) ?: NullAuditSink
    }

    private const val MAX_SIZE_WALK_NODES = 100000
}
