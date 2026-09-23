package com.example.lock.safe_delete

import android.content.Context
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Locale

data class ThumbnailReport(
    val cacheFilesPurged: Int,
    val cacheBytesPurged: Long,
    val blobsRedacted: Int,
    val warnings: List<String>
)

internal class ThumbnailSanitizer(
    private val context: Context,
    private val rng: SecureRandom,
    private val cancel: CancellationToken,
    sessionNames: List<String>
) {

    private val variants: MutableList<Pair<ByteArray, String>> =
        buildVariants(sessionNames).toMutableList()

    private val dirListingCache = HashMap<String, List<File>>()
    private val reportedWarnings = LinkedHashSet<String>()

    fun addSessionNames(names: List<String>) {
        if (names.isEmpty()) return
        val known = variants.mapTo(HashSet()) { it.second }
        buildVariants(names).forEach { variant ->
            if (known.add(variant.second)) variants.add(variant)
        }
    }

    fun purgeForTarget(targetFile: File?, targetName: String): ThumbnailReport {
        val warnings = mutableListOf<String>()
        var purgedFiles = 0
        var purgedBytes = 0L
        var redactedBlobs = 0

        val nameTexts = listOf(
            targetName.lowercase(Locale.ROOT),
            targetName.substringBeforeLast('.', targetName).lowercase(Locale.ROOT)
        ).filter { it.length >= 4 }

        val candidateDirs = collectThumbnailDirs(targetFile)

        for (dir in candidateDirs) {
            if (cancel.isCancelled) break
            val entries = listingFor(dir) ?: continue

            for (entry in entries) {
                if (cancel.isCancelled) break
                if (!entry.exists() || !entry.isFile) continue
                val length = entry.length()

                if (isCacheBlob(entry.name)) {
                    if (length == 0L) {
                        if (FsOps.unlink(entry)) purgedFiles++
                        continue
                    }
                    if (wipeWholeFile(entry)) {
                        purgedFiles++
                        purgedBytes += length
                    } else if (redactBlobRegions(entry, nameTexts)) {
                        redactedBlobs++
                        warnings.add(
                            "a thumbnail cache blob could not be removed; " +
                                "name index regions were overwritten but cached image data may survive"
                        )
                    } else {
                        warnings.add("a thumbnail cache entry could not be removed")
                    }
                } else if (matchesLooseThumbnail(entry.name, nameTexts)) {
                    if (wipeWholeFile(entry)) {
                        purgedFiles++
                        purgedBytes += length
                    }
                }
            }

            VolumeRoots.removeIfEmpty(dir)
        }

        if (purgedFiles > 0 || redactedBlobs > 0) {
            SecureLog.i(
                "thumbnail purge for $targetName: files=$purgedFiles blobs=$redactedBlobs bytes=$purgedBytes"
            )
        }
        warnings.forEach { if (reportedWarnings.add(it)) SecureLog.w(it) }

        return ThumbnailReport(purgedFiles, purgedBytes, redactedBlobs, warnings)
    }

    fun purgeOwnAppCaches(): Int {
        var purged = 0
        val roots = listOfNotNull(context.cacheDir, context.externalCacheDir, context.codeCacheDir)
            .filter { it.exists() && it.isDirectory }

        for (root in roots) {
            if (cancel.isCancelled) break
            val stack = ArrayDeque<File>()
            stack.addLast(root)
            var inspected = 0
            while (stack.isNotEmpty() && inspected < MAX_CACHE_ENTRIES) {
                val current = stack.removeLast()
                val children = try {
                    current.listFiles()
                } catch (t: Throwable) {
                    null
                } ?: continue
                val cacheLikeDir = OWN_CACHE_DIR_HINTS.any { hint ->
                    current.name.lowercase(Locale.ROOT).contains(hint)
                }
                for (child in children) {
                    inspected++
                    if (FsOps.isSymbolicLink(child)) continue
                    if (child.isDirectory) {
                        stack.addLast(child)
                        continue
                    }
                    if (child.length() == 0L) {
                        if (child.delete()) purged++
                        continue
                    }
                    val nameHit = referencesAnyName(child)
                    if (nameHit || (cacheLikeDir && child.length() <= SecureDeleteConfig.THUMB_LOOSE_FILE_MAX_BYTES)) {
                        if (wipeWholeFile(child)) purged++
                    }
                }
            }
            FsOps.syncDirectory(root)
        }

        if (purged > 0) SecureLog.i("own cache purge: $purged file(s)")
        return purged
    }

    private fun listingFor(dir: File): List<File>? {
        val key = FsOps.canonicalPath(dir)
        dirListingCache[key]?.let { return it }
        val listing = try {
            if (!dir.exists() || !dir.isDirectory || !dir.canRead()) return null
            dir.listFiles()?.toList() ?: emptyList()
        } catch (t: Throwable) {
            null
        }
        if (listing != null) dirListingCache[key] = listing
        return listing
    }

    private fun collectThumbnailDirs(targetFile: File?): List<File> {
        val dirs = LinkedHashSet<String>()

        targetFile?.parentFile?.let { parent ->
            THUMB_DIR_NAMES.forEach { dirs.add(FsOps.canonicalPath(File(parent, it))) }
            parent.parentFile?.let { grand ->
                THUMB_DIR_NAMES.forEach { dirs.add(FsOps.canonicalPath(File(grand, it))) }
            }
        }

        for (root in VolumeRoots.all(context)) {
            THUMB_SCOPES.forEach { scope ->
                val base = if (scope.isEmpty()) root else File(root, scope)
                THUMB_DIR_NAMES.forEach { dirs.add(FsOps.canonicalPath(File(base, it))) }
            }
        }

        return dirs.map { File(it) }
    }

    private fun collectHits(haystack: ByteArray, length: Int, hits: MutableSet<String>) {
        for (pair in variants) {
            val needle = pair.first
            val text = pair.second
            if (needle.size > length) continue
            var i = 0
            val limit = length - needle.size
            outer@ while (i <= limit) {
                for (j in needle.indices) {
                    if (haystack[i + j] != needle[j]) {
                        i++
                        continue@outer
                    }
                }
                hits.add(text)
                i += needle.size
            }
        }
    }

    private fun referencesAnyName(file: File): Boolean {
        if (variants.isEmpty()) return false
        val length = file.length()
        if (length <= 0L) return false
        val hits = LinkedHashSet<String>()
        return try {
            RandomAccessFile(file, "r").use { raf ->
                val buffer = ByteArray(minOf(NAME_SCAN_CHUNK.toLong(), length).toInt())
                var position = 0L
                while (position < minOf(length, MAX_SCAN_BYTES)) {
                    val size = minOf(buffer.size.toLong(), length - position).toInt()
                    if (size <= 0) break
                    raf.seek(position)
                    val read = raf.read(buffer, 0, size)
                    if (read <= 0) break
                    collectHits(buffer, read, hits)
                    if (hits.isNotEmpty()) return true
                    position += (read - (MAX_VARIANT_BYTES - 1)).coerceAtLeast(1)
                }
                if (length > MAX_SCAN_BYTES) {
                    val tailStart = length - MAX_SCAN_BYTES
                    var tailPosition = tailStart
                    while (tailPosition < length) {
                        val size = minOf(buffer.size.toLong(), length - tailPosition).toInt()
                        if (size <= 0) break
                        raf.seek(tailPosition)
                        val read = raf.read(buffer, 0, size)
                        if (read <= 0) break
                        collectHits(buffer, read, hits)
                        if (hits.isNotEmpty()) return true
                        tailPosition += (read - (MAX_VARIANT_BYTES - 1)).coerceAtLeast(1)
                    }
                    if (reportedWarnings.add("large cache file partially scanned")) {
                        SecureLog.w("cache file larger than scan budget; head and tail inspected")
                    }
                }
                false
            }
        } catch (t: Throwable) {
            false
        }
    }

    internal fun findOffsets(file: File, nameTexts: List<String>): List<Long> {
        val needles = nameTexts.map { it.toByteArray(Charsets.UTF_8) }.filter { it.isNotEmpty() }
        if (needles.isEmpty()) return emptyList()

        val offsets = mutableListOf<Long>()
        val length = file.length()
        try {
            RandomAccessFile(file, "r").use { raf ->
                val buffer = ByteArray(NAME_SCAN_CHUNK)
                var position = 0L
                while (position < length) {
                    val size = minOf(buffer.size.toLong(), length - position).toInt()
                    if (size <= 0) break
                    raf.seek(position)
                    val read = raf.read(buffer, 0, size)
                    if (read <= 0) break
                    for (needle in needles) {
                        if (needle.size > read) continue
                        var i = 0
                        val limit = read - needle.size
                        outer@ while (i <= limit) {
                            for (j in needle.indices) {
                                if (buffer[i + j] != needle[j]) {
                                    i++
                                    continue@outer
                                }
                            }
                            offsets.add(position + i)
                            i += needle.size
                        }
                    }
                    position += (read - (MAX_VARIANT_BYTES - 1)).coerceAtLeast(1)
                }
            }
        } catch (t: Throwable) {
            SecureLog.w("offset scan failed: ${Sanitizer.of(t, file.absolutePath, file.name)}")
        }
        return offsets
    }

    internal fun redactBlobRegions(blob: File, nameTexts: List<String>): Boolean {
        val offsets = findOffsets(blob, nameTexts)
        if (offsets.isEmpty()) return false
        val ranges = coalesce(offsets, blob.length())

        return try {
            FsOps.openReadWrite(blob).use { channel ->
                val engine = OverwriteEngine(SanitizationLevel.QUICK, VerifyMode.NONE, rng)
                val spec = engine.passSpecs().first()
                val generator = engine.newGenerator(spec)
                val buffer = ByteArray(64 * 1024)
                val zeros = ByteArray(buffer.size)

                for ((start, end) in ranges) {
                    if (cancel.isCancelled) return false
                    var position = start
                    while (position < end) {
                        val size = minOf(buffer.size.toLong(), end - position).toInt()
                        generator.fill(buffer, position, size)
                        channel.write(ByteBuffer.wrap(buffer, 0, size), position)
                        position += size
                    }
                    var zeroPosition = start
                    while (zeroPosition < end) {
                        val size = minOf(zeros.size.toLong(), end - zeroPosition).toInt()
                        channel.write(ByteBuffer.wrap(zeros, 0, size), zeroPosition)
                        zeroPosition += size
                    }
                }
                Zeroize.bytes(buffer)
                FsOps.force(channel)
            }
            FsOps.syncDirectory(blob.parentFile)
            SecureLog.i("redacted ${ranges.size} region(s) inside a thumbnail blob")
            true
        } catch (t: Throwable) {
            SecureLog.w("blob redaction failed: ${Sanitizer.of(t, blob.absolutePath, blob.name)}")
            false
        }
    }

    internal fun coalesce(offsets: List<Long>, length: Long): List<Pair<Long, Long>> {
        val ranges = offsets.map { offset ->
            val start = alignDown((offset - REDACT_RADIUS_BYTES).coerceAtLeast(0L))
            val end = alignUp((offset + REDACT_RADIUS_BYTES).coerceAtMost(length)).coerceAtMost(length)
            start to end
        }.sortedBy { it.first }

        val merged = mutableListOf<Pair<Long, Long>>()
        for (range in ranges) {
            val last = merged.lastOrNull()
            if (last == null || range.first > last.second) {
                merged.add(range)
            } else if (range.second > last.second) {
                merged[merged.lastIndex] = last.first to range.second
            }
        }
        return merged
    }

    private fun alignDown(value: Long): Long = value - (value % REDACT_ALIGNMENT)

    private fun alignUp(value: Long): Long {
        val remainder = value % REDACT_ALIGNMENT
        return if (remainder == 0L) value else value + (REDACT_ALIGNMENT - remainder)
    }

    private fun wipeWholeFile(file: File): Boolean {
        val length = file.length()
        var overwritten = false
        try {
            if (FsOps.setWritable(file)) {
                FsOps.openReadWrite(file).use { channel ->
                    val engine = OverwriteEngine(SanitizationLevel.QUICK, VerifyMode.NONE, rng)
                    repeat(SecureDeleteConfig.THUMB_BLOB_LIGHT_PATTERNS) {
                        if (cancel.isCancelled) return@use
                        val spec = engine.passSpecs().first()
                        val generator = engine.newGenerator(spec)
                        if (engine.overwrite(channel, length, spec, generator, cancel) { }) overwritten = true
                    }
                    FsOps.truncateToZero(channel)
                }
            }
        } catch (t: Throwable) {
            SecureLog.w("cache wipe failed: ${Sanitizer.of(t, file.absolutePath, file.name)}")
        }
        val removed = FsOps.unlink(file)
        return removed && (overwritten || length == 0L)
    }

    private fun isCacheBlob(name: String): Boolean {
        val lower = name.lowercase(Locale.ROOT)
        if (lower.startsWith(".thumb") || lower.startsWith("thumb")) return true
        if (lower.startsWith("thumbs") || lower.startsWith(".thumbs")) return true
        if (lower.endsWith(".thumb") || lower.endsWith(".thum") || lower.endsWith(".thumbnail")) return true
        if (lower.endsWith(".db") && lower.contains("thumb")) return true
        val dotless = !lower.contains('.')
        if (dotless && lower.length > 6) {
            val trimmed = lower.removePrefix("-")
            if (trimmed.isNotEmpty() && trimmed.all { it.isDigit() }) return true
        }
        return false
    }

    private fun matchesLooseThumbnail(name: String, nameTexts: List<String>): Boolean {
        val lower = name.lowercase(Locale.ROOT)
        return nameTexts.any { text -> lower.contains(text) || lower.contains(text.replace('.', '_')) }
    }

    private fun buildVariants(names: List<String>): List<Pair<ByteArray, String>> {
        val texts = LinkedHashSet<String>()
        names.forEach { name ->
            val base = name.substringBeforeLast('.', name)
            texts.add(name)
            texts.add(base)
            texts.add(name.lowercase(Locale.ROOT))
            texts.add(base.lowercase(Locale.ROOT))
        }
        return texts.filter { it.length >= 4 && it.length <= MAX_VARIANT_BYTES }
            .map { it to it.toByteArray(Charsets.UTF_8) }
            .map { (text, bytes) -> bytes to text }
    }

    companion object {
        private val THUMB_DIR_NAMES = listOf(".thumbnails", ".thumbnail", "thumbnails", ".thumbs", "thumbs")

        private val THUMB_SCOPES = listOf("", "DCIM", "Pictures", "Movies", "Download", "Downloads", "Android/media")

        private val OWN_CACHE_DIR_HINTS = listOf(
            "image_cache", "imagecache", "glide", "coil", "picasso", "thumbnail", "thumbcache", "okhttp"
        )

        private const val NAME_SCAN_CHUNK = 1 shl 20
        private const val REDACT_RADIUS_BYTES = 256L * 1024L
        private const val REDACT_ALIGNMENT = 4096L
        private const val MAX_VARIANT_BYTES = 128
        private const val MAX_CACHE_ENTRIES = 20000
        private const val MAX_SCAN_BYTES = 16L * 1024L * 1024L
    }
}
