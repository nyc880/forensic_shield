package com.example.lock.safe_delete

import android.content.Context
import android.net.Uri
import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class SanitizationLevel {
    QUICK,
    STANDARD,
    MAXIMUM,
    PARANOID
}

enum class VerifyMode {
    NONE,
    FINAL_PASS,
    EVERY_PASS
}

enum class PassPattern {
    ZEROES,
    ONES,
    DETERMINISTIC_RANDOM,
    OS_RANDOM
}

data class PassSpec(
    val pattern: PassPattern,
    val verify: Boolean,
    val label: String
)

object SecureDeleteConfig {

    const val LOG_TAG = "SecureDelete"
    const val LOG_ENABLED = false

    const val LOW_HEAP_THRESHOLD_MB = 48
    const val OVERWRITE_BUFFER_HIGH_RAM = 40 shl 20
    const val OVERWRITE_BUFFER_LOW_RAM = 1 shl 18
    const val READ_VERIFY_BUFFER_HIGH_RAM = 40 shl 20
    const val READ_VERIFY_BUFFER_LOW_RAM = 1 shl 18
    const val PATTERN_BLOCK_BYTES = 4096

    const val ERASE_BOUNDARY_ALIGNMENT = 4L * 1024L * 1024L
    const val MAX_EXTENSION_BYTES = 64L * 1024L * 1024L
    const val EXTENSION_MIN_FILE_BYTES = 1L * 1024L * 1024L
    const val EXTENSION_FREE_SPACE_RESERVE = 96L * 1024L * 1024L

    const val RENAME_ROUNDS = 4
    const val RENAME_SUFFIX_BYTES = 12
    const val FSYNC_DIR_EVERY_RENAME = true
    const val UNLINK_RETRY_ATTEMPTS = 3

    const val TRASH_SCAN_ENABLED = true
    const val TRASH_SCAN_MAX_DEPTH = 3
    const val THUMBNAIL_PURGE_ENABLED = true
    const val THUMB_LOOSE_FILE_MAX_BYTES = 32L * 1024L * 1024L
    const val THUMB_BLOB_LIGHT_PATTERNS = 1

    const val PRESSURE_CAP_BYTES = 1024L * 1024L * 1024L
    const val PRESSURE_MIN_BYTES = 16L * 1024L * 1024L
    const val PRESSURE_RESERVE_BYTES = 64L * 1024L * 1024L
    const val PRESSURE_CHUNK_BYTES = 4 shl 20
    const val PRESSURE_FILE_COUNT_MAX = 4

    const val DEEP_CLEAN_FREE_PERCENT = 90L
    const val DEEP_CLEAN_RESERVE_BYTES = 320L * 1024L * 1024L
    const val DEEP_CLEAN_MAX_BYTES = 32L * 1024L * 1024L * 1024L
    const val DEEP_CLEAN_CHUNK_BYTES = 16L * 1024L * 1024L
    const val DEEP_CLEAN_WRITE_BUFFER_BYTES = 4 shl 20
    const val DEEP_CLEAN_FILE_PREFIX = "sd_deep_"

    const val DIRECTORY_ENTRY_SCRUB_ROUNDS = 3
    const val DIRECTORY_ENTRY_SCRUB_FILES = 8

    const val STRICT_OVERWRITE = true
    const val FADVISE_DONTNEED = 4
    const val KERNEL_MOUNT_INFO_PATH = "/proc/mounts"
    const val STORAGE_ROOT_DIR = "/storage"
    const val STORAGE_ROOT_SCAN_LIMIT = 16

    const val LEDGER_AVAILABLE = true
    const val LEDGER_DB_NAME = "sd_ledger.db"
    const val LEDGER_MAX_ROWS = 4096
    const val LEDGER_PRUNE_BATCH = 512

    val STANDARD_PASSES: List<PassSpec> = listOf(
        PassSpec(PassPattern.DETERMINISTIC_RANDOM, false, "random-pass-1"),
        PassSpec(PassPattern.ZEROES, true, "zero-final")
    )

    val MAXIMUM_PASSES: List<PassSpec> = listOf(
        PassSpec(PassPattern.DETERMINISTIC_RANDOM, false, "random-pass-1"),
        PassSpec(PassPattern.ZEROES, true, "zero-final")
    )

    val PARANOID_PASSES: List<PassSpec> = listOf(
        PassSpec(PassPattern.OS_RANDOM, false, "csprng-pass"),
        PassSpec(PassPattern.DETERMINISTIC_RANDOM, false, "random-pass-1"),
        PassSpec(PassPattern.ZEROES, true, "zero-final")
    )

    val QUICK_PASSES: List<PassSpec> = listOf(
        PassSpec(PassPattern.DETERMINISTIC_RANDOM, true, "random-final")
    )

    fun passesFor(level: SanitizationLevel, verifyMode: VerifyMode): List<PassSpec> {
        val base = when (level) {
            SanitizationLevel.QUICK -> QUICK_PASSES
            SanitizationLevel.STANDARD -> STANDARD_PASSES
            SanitizationLevel.MAXIMUM -> MAXIMUM_PASSES
            SanitizationLevel.PARANOID -> PARANOID_PASSES
        }
        return base.mapIndexed { index, pass ->
            val requested = when (verifyMode) {
                VerifyMode.NONE -> false
                VerifyMode.FINAL_PASS -> index == base.lastIndex
                VerifyMode.EVERY_PASS -> true
            }
            pass.copy(verify = requested && pass.pattern != PassPattern.OS_RANDOM)
        }
    }

    fun overwriteBufferBytes(): Int {
        val heapMb = Runtime.getRuntime().maxMemory() / (1024L * 1024L)
        return if (heapMb <= LOW_HEAP_THRESHOLD_MB) {
            OVERWRITE_BUFFER_LOW_RAM
        } else {
            OVERWRITE_BUFFER_HIGH_RAM
        }
    }

    fun verifyBufferBytes(): Int {
        val heapMb = Runtime.getRuntime().maxMemory() / (1024L * 1024L)
        return if (heapMb <= LOW_HEAP_THRESHOLD_MB) {
            READ_VERIFY_BUFFER_LOW_RAM
        } else {
            READ_VERIFY_BUFFER_HIGH_RAM
        }
    }
}

enum class TargetKind {
    FILE,
    DIRECTORY,
    CONTENT_URI,
    MISSING,
    UNSUPPORTED
}

enum class AssuranceLevel {
    BEST_EFFORT,
    WEAK;

    val label: String
        get() = when (this) {
            BEST_EFFORT -> "best-effort purge"
            WEAK -> "weak deletion"
        }
}

data class DeepCleanConfig(
    val freeSpacePercent: Long = SecureDeleteConfig.DEEP_CLEAN_FREE_PERCENT,
    val reserveBytes: Long = SecureDeleteConfig.DEEP_CLEAN_RESERVE_BYTES,
    val maxBytes: Long = SecureDeleteConfig.DEEP_CLEAN_MAX_BYTES,
    val chunkFileBytes: Long = SecureDeleteConfig.DEEP_CLEAN_CHUNK_BYTES,
    val maxRunMillis: Long = 0L,
    val requireCharging: Boolean = true,
    val systemReclaimHint: Boolean = false
)

data class DeleteTarget(
    val kind: TargetKind,
    val path: String? = null,
    val uriString: String? = null
) {
    val displayName: String
        get() = path?.let { File(it).name }
            ?: uriString?.let { Uri.parse(it).lastPathSegment ?: it }
            ?: "unknown"

    fun uriOrNull(): Uri? = uriString?.let { runCatching { Uri.parse(it) }.getOrNull() }

    companion object {
        fun of(file: File): DeleteTarget = DeleteTarget(
            kind = when {
                FsOps.isSymbolicLink(file) -> TargetKind.FILE
                !file.exists() -> TargetKind.MISSING
                file.isDirectory -> TargetKind.DIRECTORY
                else -> TargetKind.FILE
            },
            path = file.absolutePath
        )

        fun ofPath(path: String): DeleteTarget = of(File(path))

        fun ofUri(context: Context, uri: Uri): DeleteTarget {
            val resolved = TargetResolver.resolvePathForUri(context, uri)
            val kind = when {
                resolved != null && File(resolved).isDirectory -> TargetKind.DIRECTORY
                resolved != null && File(resolved).exists() -> TargetKind.FILE
                else -> TargetKind.CONTENT_URI
            }
            return DeleteTarget(kind = kind, path = resolved, uriString = uri.toString())
        }
    }
}

enum class DeletionStage {
    ANALYZE,
    RESIDUAL_SCAN,
    EXTEND,
    OVERWRITE,
    VERIFY,
    TRUNCATE,
    RENAME,
    UNLINK,
    DIRECTORY_SYNC,
    DIRECTORY_ENTRY_SCRUB,
    THUMBNAIL_PURGE,
    METADATA_ERASE,
    ALLOCATION_PRESSURE,
    LEDGER
}

data class StageOutcome(
    val stage: DeletionStage,
    val ok: Boolean,
    val detail: String = "",
    val bytes: Long = 0L,
    val elapsedMs: Long = 0L
)

data class ResidualArtifact(
    val path: String,
    val reason: String,
    val length: Long,
    val purged: Boolean
)

data class TargetReport(
    val target: DeleteTarget,
    val resolvedPath: String?,
    val length: Long,
    val passes: Int,
    val bytesOverwritten: Long,
    val verifiedBytes: Long,
    val stages: List<StageOutcome>,
    val residuals: List<ResidualArtifact>,
    val warnings: List<String>,
    val error: String?,
    val elapsedMs: Long,
    val gone: Boolean,
    val alreadyAbsent: Boolean = false,
    val assurance: AssuranceLevel = AssuranceLevel.WEAK
) {
    val success: Boolean
        get() = !alreadyAbsent && error == null && gone &&
            !(length > 0L && passes == 0) &&
            stages.none { !it.ok && it.stage.isMandatory() }

    val weakDeletion: Boolean
        get() = gone && error == null && length > 0L && passes == 0

    private fun DeletionStage.isMandatory(): Boolean = when (this) {
        DeletionStage.OVERWRITE,
        DeletionStage.VERIFY,
        DeletionStage.TRUNCATE,
        DeletionStage.UNLINK -> true

        else -> false
    }

    fun stage(stage: DeletionStage): StageOutcome? = stages.firstOrNull { it.stage == stage }
}

data class SessionReport(
    val reports: List<TargetReport>,
    val totalBytesShredded: Long,
    val totalElapsedMs: Long,
    val cancelled: Boolean,
    val level: SanitizationLevel,
    val verifyMode: VerifyMode,
    val pressureBytes: Long,
    val deepCleanExecuted: Boolean = false,
    val deepCleanPending: Boolean = false,
    val deepCleanWarnings: List<String> = emptyList(),
    val assurance: AssuranceLevel = AssuranceLevel.WEAK
) {
    val successCount: Int get() = reports.count { it.success }
    val failureCount: Int get() = reports.count { !it.success }
    val alreadyAbsentCount: Int get() = reports.count { it.alreadyAbsent }
    val weakDeletionCount: Int get() = reports.count { it.weakDeletion }
    val allGone: Boolean get() = reports.all { it.gone }
    val failedTargets: List<TargetReport> get() = reports.filter { !it.success }
    val pendingTargets: List<TargetReport>
        get() = reports.filter { !it.gone && !it.alreadyAbsent }
    val weakTargets: List<TargetReport>
        get() = reports.filter { it.weakDeletion }
    val warnings: List<String> get() = reports.flatMap { it.warnings } + deepCleanWarnings

    fun summaryLine(): String =
        "shredded=$successCount failed=$failureCount weak=$weakDeletionCount " +
            "bytes=$totalBytesShredded elapsedMs=$totalElapsedMs assurance=${assurance.name}"
}

data class PurgeOptions(
    val level: SanitizationLevel = SanitizationLevel.MAXIMUM,
    val verifyMode: VerifyMode = VerifyMode.FINAL_PASS,
    val extendToEraseBoundary: Boolean = false,
    val renameRounds: Int = SecureDeleteConfig.RENAME_ROUNDS,
    val scanTrashPaths: Boolean = SecureDeleteConfig.TRASH_SCAN_ENABLED,
    val purgeThumbnails: Boolean = SecureDeleteConfig.THUMBNAIL_PURGE_ENABLED,
    val eraseMediaStoreRows: Boolean = true,
    val scrubDirectoryEntries: Boolean = false,
    val deepClean: Boolean = false,
    val deepCleanInline: Boolean = false,
    val deepCleanConfig: DeepCleanConfig = DeepCleanConfig(),
    val writeLedger: Boolean = false,
    val dryRun: Boolean = false,
    val followSymlinks: Boolean = false
) {
    companion object {
        val QUICK_CLEAN: PurgeOptions = PurgeOptions(
            level = SanitizationLevel.QUICK,
            verifyMode = VerifyMode.FINAL_PASS,
            extendToEraseBoundary = false,
            renameRounds = 2,
            deepClean = false,
            scrubDirectoryEntries = false
        )

        val MILITARY: PurgeOptions = PurgeOptions(
            level = SanitizationLevel.MAXIMUM,
            verifyMode = VerifyMode.FINAL_PASS,
            extendToEraseBoundary = false,
            renameRounds = 6,
            scanTrashPaths = true,
            purgeThumbnails = true,
            eraseMediaStoreRows = true,
            scrubDirectoryEntries = false,
            deepClean = false,
            writeLedger = false
        )
    }
}

data class MaintenanceReport(
    val pressureBytes: Long,
    val systemReclaimedBytes: Long,
    val cacheScanMillis: Long,
    val warnings: List<String>
)

interface ProgressListener {
    fun onTargetStart(target: DeleteTarget, index: Int, total: Int)
    fun onStage(stage: DeletionStage, label: String, processedBytes: Long, totalBytes: Long)
    fun onTargetFinished(report: TargetReport)
}

interface CancellationToken {
    val isCancelled: Boolean
}

object NeverCancelled : CancellationToken {
    override val isCancelled: Boolean get() = false
}

class AtomicCancellationToken : CancellationToken {
    private val flag = AtomicBoolean(false)

    override val isCancelled: Boolean get() = flag.get()

    fun cancel() {
        flag.set(true)
    }

    fun reset() {
        flag.set(false)
    }
}

class CompositeCancellationToken(private val tokens: List<CancellationToken>) : CancellationToken {
    override val isCancelled: Boolean get() = tokens.any { it.isCancelled }
}

data class AuditEvent(
    val id: String,
    val timestampMs: Long,
    val identityHash: String,
    val length: Long,
    val level: SanitizationLevel,
    val passes: Int,
    val verifiedBytes: Long,
    val success: Boolean,
    val fsType: String,
    val residualCount: Int
)

interface AuditSink {
    fun record(event: AuditEvent)
}

object NullAuditSink : AuditSink {
    override fun record(event: AuditEvent) = Unit
}

object SecureLog {
    fun d(message: String) {
        if (SecureDeleteConfig.LOG_ENABLED) Log.d(SecureDeleteConfig.LOG_TAG, message)
    }

    fun i(message: String) {
        if (SecureDeleteConfig.LOG_ENABLED) Log.i(SecureDeleteConfig.LOG_TAG, message)
    }

    fun w(message: String) {
        if (SecureDeleteConfig.LOG_ENABLED) Log.w(SecureDeleteConfig.LOG_TAG, message)
    }

    fun e(message: String, throwable: Throwable? = null) {
        if (SecureDeleteConfig.LOG_ENABLED) Log.e(SecureDeleteConfig.LOG_TAG, message, throwable)
    }
}

object Zeroize {
    fun bytes(buffer: ByteArray?) {
        if (buffer == null || buffer.isEmpty()) return
        java.util.Arrays.fill(buffer, 0)
    }
}

object Digest {

    fun sha256Hex(vararg parts: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        for (part in parts) digest.update(part)
        return toHex(digest.digest())
    }

    fun hmacSha256Hex(key: ByteArray, data: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return toHex(mac.doFinal(data))
    }

    fun toHex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        val digits = "0123456789abcdef"
        for (i in bytes.indices) {
            val value = bytes[i].toInt() and 0xFF
            out[i * 2] = digits[value ushr 4]
            out[i * 2 + 1] = digits[value and 0x0F]
        }
        return String(out)
    }

    fun randomHex(byteCount: Int, rng: SecureRandom): String {
        val buffer = ByteArray(byteCount)
        rng.nextBytes(buffer)
        return toHex(buffer)
    }
}

object Rng {
    private val holder = object : ThreadLocal<SecureRandom>() {
        override fun initialValue(): SecureRandom = SecureRandom()
    }

    fun secure(): SecureRandom = holder.get() ?: SecureRandom()
}

object Sanitizer {

    private val PATH_LIKE = Regex("""(?:/[^\s,;:|"'()<>\[\]]+)+""")

    fun clean(message: String?, vararg secrets: String?): String {
        var out = message?.trim().orEmpty()
        if (out.isEmpty()) return "unspecified"
        for (secret in secrets) {
            if (secret.isNullOrEmpty()) continue
            out = out.replace(secret, "[redacted]")
            val name = File(secret).name
            if (name.length >= 4) out = out.replace(name, "[redacted]")
        }
        out = PATH_LIKE.replace(out, "[redacted]")
        return out
    }

    fun of(t: Throwable, vararg secrets: String?): String {
        val detail = clean(t.message, *secrets)
        return "${t.javaClass.simpleName}: $detail"
    }
}

data class ContentFingerprint(val length: Long, val digestHex: String) {

    companion object {
        private const val FULL_MAX_BYTES = 32L * 1024L * 1024L
        private const val EDGE_BYTES = 4L * 1024L * 1024L
        private const val SAMPLE_COUNT = 16L
        private const val SAMPLE_BYTES = 64 * 1024

        fun of(file: File): ContentFingerprint? {
            return try {
                if (!file.isFile || !file.canRead()) return null
                val length = file.length()
                if (length <= 0L) return ContentFingerprint(0L, "")
                val digest = MessageDigest.getInstance("SHA-256")
                val buffer = ByteArray(SAMPLE_BYTES)
                RandomAccessFile(file, "r").use { raf ->
                    if (length <= FULL_MAX_BYTES) {
                        var position = 0L
                        while (position < length) {
                            val read = raf.read(buffer, 0, minOf(buffer.size.toLong(), length - position).toInt())
                            if (read <= 0) break
                            digest.update(buffer, 0, read)
                            position += read
                        }
                        if (position != length) return null
                    } else {
                        digest.update(ByteBuffer.allocate(8).putLong(length).array())
                        readChunk(raf, digest, buffer, 0L, EDGE_BYTES)
                        val stride = (length - 2L * EDGE_BYTES) / SAMPLE_COUNT
                        for (index in 0 until SAMPLE_COUNT) {
                            readChunk(raf, digest, buffer, EDGE_BYTES + index * stride, SAMPLE_BYTES.toLong())
                        }
                        readChunk(raf, digest, buffer, length - EDGE_BYTES, EDGE_BYTES)
                    }
                }
                ContentFingerprint(length, Digest.toHex(digest.digest()))
            } catch (t: Throwable) {
                SecureLog.w("content fingerprint failed: ${Sanitizer.of(t, file.absolutePath, file.name)}")
                null
            }
        }

        fun matches(file: File, expected: ContentFingerprint): Boolean {
            if (expected.length <= 0L) return false
            if (!file.isFile || file.length() != expected.length) return false
            val candidate = of(file) ?: return false
            return candidate.digestHex == expected.digestHex
        }

        private fun readChunk(
            raf: RandomAccessFile,
            digest: MessageDigest,
            buffer: ByteArray,
            offset: Long,
            size: Long
        ) {
            raf.seek(offset)
            var remaining = size
            while (remaining > 0L) {
                val read = raf.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                if (read <= 0) break
                digest.update(buffer, 0, read)
                remaining -= read
            }
        }
    }
}
