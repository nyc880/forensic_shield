package com.example.lock.metadata

import com.example.lock.metadata.IsoBmffCore.Box
import com.example.lock.metadata.IsoBmffCore.Removals
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.io.RandomAccessFile

internal object IsoBmffCore {

    const val MAX_DEPTH = 7

    val staleIndexBoxes: Set<String> = setOf("mfra", "mfro", "tfra", "sidx", "ssix")

    val containers: Set<String> = setOf(
        "moov", "trak", "mdia", "minf", "stbl", "edts", "dinf", "mvex", "moof", "traf", "mfra", "ilst",
        "iprp", "ipco", "iref", "grpl", "wave", "sinf", "schi", "strk", "stri", "cslg", "msrc", "meco", "mere"
    )

    class Box(
        val type: String,
        val start: Long,
        val size: Long,
        val headerSize: Int,
        val unparsed: Boolean = false,
        val declared: Long = 0L
    ) {
        val bodyStart: Long get() = start + headerSize
        val bodySize: Long get() = size - headerSize
        val end: Long get() = start + size
    }

    fun isUnparsedJunk(box: Box): Boolean {
        if (!box.unparsed) return false
        if (box.declared == 0L) return false
        return true
    }

    class Removals {
        private val starts = ArrayList<Long>()
        private val lengths = ArrayList<Long>()

        fun add(start: Long, length: Long) {
            if (length > 0) {
                starts.add(start)
                lengths.add(length)
            }
        }

        val isEmpty: Boolean get() = starts.isEmpty()
        fun total(): Long = lengths.sumOf { it }

        fun before(offset: Long): Long? {
            var sum = 0L
            for (i in starts.indices) {
                val start = starts[i]
                val end = start + lengths[i]
                if (offset >= end) sum += lengths[i] else if (offset >= start) return null
            }
            return sum
        }

        fun rebase(offset: Long): Long? = before(offset)?.let { offset - it }
    }

    fun readU64(b: ByteArray, i: Int): Long {
        var value = 0L
        for (k in 0 until 8) value = (value shl 8) or (b[i + k].toLong() and 0xFF)
        return value
    }

    fun readU32(b: ByteArray, i: Int): Long {
        if (i + 4 > b.size) return 0L
        return ((b[i].toLong() and 0xFF) shl 24) or ((b[i + 1].toLong() and 0xFF) shl 16) or
            ((b[i + 2].toLong() and 0xFF) shl 8) or (b[i + 3].toLong() and 0xFF)
    }

    fun readWidth(b: ByteArray, pos: Int, width: Int): Long {
        var value = 0L
        for (i in 0 until width) {
            if (pos + i >= b.size) break
            value = (value shl 8) or (b[pos + i].toLong() and 0xFF)
        }
        return value
    }

    fun readWidthIo(io: BinaryIo, width: Int): Long {
        var value = 0L
        for (i in 0 until width) value = (value shl 8) or (io.u8().toLong() and 0xFF)
        return value
    }

    fun writeWidth(out: OutputStream, width: Int, value: Long) {
        for (i in width - 1 downTo 0) out.write(((value shr (8 * i)) and 0xFF).toInt())
    }

    fun boxHeader(out: OutputStream, type: String, bodySize: Long) {
        val total = bodySize + 8
        if (total < 0xFFFFFFFFL) {
            out.write(((total shr 24) and 0xFF).toInt())
            out.write(((total shr 16) and 0xFF).toInt())
            out.write(((total shr 8) and 0xFF).toInt())
            out.write((total and 0xFF).toInt())
            out.write(type.toByteArray(Charsets.US_ASCII))
        } else {
            out.write(0)
            out.write(0)
            out.write(0)
            out.write(1)
            out.write(type.toByteArray(Charsets.US_ASCII))
            val body = bodySize + 16
            for (i in 7 downTo 0) out.write(((body shr (8 * i)) and 0xFF).toInt())
        }
    }

    fun writeBox(out: OutputStream, type: String, body: ByteArray) {
        boxHeader(out, type, body.size.toLong())
        out.write(body)
    }

    fun parseBoxes(io: BinaryIo, start: Long, end: Long, typeLimit: Int = 500_000): List<Box> {
        val boxes = ArrayList<Box>()
        var pos = start
        var guard = 0
        while (pos + 8 <= end && guard++ < typeLimit) {
            val header = io.peekAt(pos, 8) ?: break
            val size32 = Bytes.u32be(header, 0)
            val type = Bytes.asciiAt(header, 4, 4)
            if (type.any { it.code < 0x20 && it != '\u0000' }) break
            var headerSize = 8
            var size = size32
            if (size32 == 1L) {
                val large = io.peekAt(pos + 8, 8) ?: break
                size = readU64(large, 0)
                headerSize = 16
            } else if (size32 == 0L) {
                size = end - pos
            }
            if (size < headerSize || pos + size > end) {
                boxes.add(Box(type, pos, end - pos, headerSize, unparsed = true, declared = size32))
                break
            }
            boxes.add(Box(type, pos, size, headerSize))
            pos += size
        }
        return boxes
    }

    data class MetaLayout(val childrenStart: Long, val hasVersionFlags: Boolean)

    private fun firstChildValid(io: BinaryIo, start: Long, end: Long): Boolean {
        if (start + 8 > end) return false
        val header = io.peekAt(start, 8) ?: return false
        var size = Bytes.u32be(header, 0)
        if (size == 0L) size = end - start
        val type = Bytes.asciiAt(header, 4, 4)
        if (type.any { it.code < 0x20 || it.code > 0x7E }) return false
        return size >= 8 && start + size <= end
    }

    fun metaLayout(io: BinaryIo, box: Box): MetaLayout {
        val plain = box.bodyStart
        val full = box.bodyStart + 4
        val plainOk = firstChildValid(io, plain, box.end)
        val fullOk = firstChildValid(io, full, box.end)
        return when {
            fullOk -> MetaLayout(full, true)
            plainOk -> MetaLayout(plain, false)
            else -> MetaLayout(plain, false)
        }
    }

    fun childBoxes(io: BinaryIo, container: Box): List<Box> {
        val start = if (container.type == "meta") metaLayout(io, container).childrenStart else container.bodyStart
        return parseBoxes(io, start, container.end)
    }

    fun copyRange(io: BinaryIo, start: Long, size: Long, out: OutputStream) {
        copyRange(io, start, size, out, Buffers.new())
    }

    /** Same, with a caller owned buffer for loops that copy one box at a time. */
    fun copyRange(io: BinaryIo, start: Long, size: Long, out: OutputStream, buffer: ByteArray) {
        if (size <= 0) return
        io.copyRange(start, size, out, buffer)
    }

    fun copyBytes(io: BinaryIo, start: Long, size: Long, out: ByteArrayOutputStream) {
        copyRange(io, start, size, out)
    }

    /** Same, with a caller owned buffer for the per child copy loops. */
    fun copyBytes(io: BinaryIo, start: Long, size: Long, out: ByteArrayOutputStream, buffer: ByteArray) {
        copyRange(io, start, size, out, buffer)
    }

    fun zeroRanges(target: File, ranges: List<LongRange>) {
        if (ranges.isEmpty()) return
        try {
            RandomAccessFile(target, "rw").use { raf ->
                val length = raf.length()
                val buffer = ByteArray(64 * 1024)
                for (range in ranges) {
                    var pos = maxOf(0L, range.first)
                    val end = minOf(range.last, length)
                    while (pos < end) {
                        val size = minOf((end - pos), buffer.size.toLong()).toInt()
                        raf.seek(pos)
                        raf.write(buffer, 0, size)
                        pos += size
                    }
                }
                try {
                    raf.fd.sync()
                } catch (_: Exception) {
                }
            }
        } catch (_: Exception) {
        }
    }

    fun safeRanges(candidates: List<LongRange>, protectedRanges: List<LongRange>): List<LongRange> {
        if (candidates.isEmpty()) return emptyList()
        return candidates.filter { candidate ->
            protectedRanges.none { it.first < candidate.last && candidate.first < it.last }
        }
    }

    /** The C2PA extended type from C2PA spec A.5.1; every published revision shares this prefix. */
    private val c2paUuidPrefix = byteArrayOf(
        0xD8.toByte(), 0xFE.toByte(), 0xC3.toByte(), 0xD6.toByte(), 0x1B.toByte(), 0x0E.toByte(),
        0x48.toByte(), 0x3C.toByte(), 0x92.toByte(), 0x97.toByte()
    )
    private val xmpUuid = "be7acfcb97a942e89c71999491e3afac"

    /** Names what a uuid box actually carries instead of reporting every one as an anonymous blob. */
    fun uuidDetail(io: BinaryIo, box: Box): String {
        val id = io.peekAt(box.bodyStart, 16)
        if (id == null) return "'uuid' box"
        val hex = id.joinToString("") { String.format("%02x", it) }
        return when {
            c2paUuidPrefix.indices.all { id[it] == c2paUuidPrefix[it] } -> "C2PA provenance manifest (uuid box)"
            hex == xmpUuid -> "XMP packet (uuid box)"
            else -> "vendor uuid box $hex"
        }
    }

    fun uuidKind(io: BinaryIo, box: Box): MetadataKind {
        val id = io.peekAt(box.bodyStart, 16) ?: return MetadataKind.OTHER
        if (c2paUuidPrefix.indices.all { id[it] == c2paUuidPrefix[it] }) return MetadataKind.PROVENANCE
        val hex = id.joinToString("") { String.format("%02x", it) }
        return if (hex == xmpUuid) MetadataKind.XMP else MetadataKind.OTHER
    }

    fun dropReason(type: String): MetadataKind? = when (type) {
        "udta" -> MetadataKind.VIDEO_TAGS
        "meta" -> MetadataKind.VIDEO_TAGS
        "ilst" -> MetadataKind.VIDEO_TAGS
        "XMP_" -> MetadataKind.XMP
        // A uuid box is the standard carrier for a C2PA / Content Credentials manifest.
        "uuid" -> MetadataKind.PROVENANCE
        "prft" -> MetadataKind.TIMESTAMP
        "_Java" -> MetadataKind.OTHER
        "chpl" -> MetadataKind.VIDEO_TAGS
        "load" -> MetadataKind.OTHER
        "hnti", "hinf" -> MetadataKind.OTHER
        // The iTunes/QuickTime key-name table; with ilst gone it only names dropped keys,
        // and it is where the Live Photo paired-asset identifier is declared.
        "keys" -> MetadataKind.UNIQUE_ID
        // Padding is where deleted metadata survives, so it goes too.
        "free", "skip" -> MetadataKind.OTHER
        else -> null
    }

    /**
     * Apple pairs a Live Photo (MOV+HEIC) through com.apple.quicktime.content.identifier /
     * asset.identifier declared in the keys table. The value is removed with its item or
     * track, but the user must be told this file was linkable to a companion capture.
     */
    fun keysBoxDetail(io: BinaryIo, box: Box): MetadataFinding? {
        val body = io.peekAt(box.bodyStart, minOf(box.bodySize, 65536L).toInt()) ?: return null
        val text = String(body, Charsets.UTF_8)
        return if (
            text.contains("com.apple.quicktime.content.identifier") ||
            text.contains("com.apple.quicktime.asset.identifier")
        ) {
            MetadataFinding(
                MetadataKind.UNIQUE_ID,
                "paired-asset identifier (Live Photo): this file was linked to a companion " +
                    "capture — purge the pair together so neither side keeps the link"
            )
        } else null
    }
}

object IsoBmffHandler : FormatHandler {

    override val id: String = "isobmff"
    override val formats: Set<MediaFormat> = setOf(
        MediaFormat.MP4, MediaFormat.THREEGP, MediaFormat.HEIF, MediaFormat.AVIF, MediaFormat.RAW
    )

    private val imageFormats = setOf(MediaFormat.HEIF, MediaFormat.AVIF)
    private val metadataHandlerTypes = setOf("meta", "mdta", "tmcd", "sbtl", "subt", "text")
    private const val MAX_SAMPLES = 4_000_000

    internal data class Patch(val bufferOffset: Int, val entryCount: Int, val wide: Boolean, val values: LongArray)

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val top = parseTopLevel(ctx.source)
            ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a parsable ISO base media file")
        val isImage = ctx.detection.format in imageFormats ||
            (top.none { it.type == "moov" } && top.any { it.type == "meta" })
        return if (isImage) HeifScrubber.scrub(ctx, top) else scrubMovie(ctx, top)
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val top = parseTopLevel(file)
            ?: return listOf(MetadataFinding(MetadataKind.OTHER, "unparsable ISO base media structure"))
        val isImage = top.none { it.type == "moov" } && top.any { it.type == "meta" }
        return if (isImage) HeifScrubber.inspect(file, top, options) else inspectMovie(file, top, options)
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        val top = parseTopLevel(file) ?: return false
        if (top.isEmpty()) return false
        val isImage = top.none { it.type == "moov" } && top.any { it.type == "meta" }
        return if (isImage) HeifScrubber.validate(file, top) else validateMovie(file, top)
    }

    internal fun parseTopLevel(file: File): List<Box>? = try {
        BinaryIo.open(file).use { io -> IsoBmffCore.parseBoxes(io, 0L, io.length) }
    } catch (_: Exception) {
        null
    }

    /** uuid boxes are rare, so opening the file to name one is cheaper than threading an io through. */
    private fun describeUuid(file: File, box: Box): MetadataFinding = try {
        BinaryIo.open(file).use { io ->
            MetadataFinding(IsoBmffCore.uuidKind(io, box), IsoBmffCore.uuidDetail(io, box))
        }
    } catch (_: Exception) {
        MetadataFinding(MetadataKind.PROVENANCE, "'uuid' box")
    }

    private fun scrubMovie(ctx: PurgeContext, top: List<Box>): ScrubOutcome {
        val moov = top.firstOrNull { it.type == "moov" }
            ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "movie header (moov) missing")
        val removals = Removals()
        val removed = ArrayList<MetadataFinding>()

        val keepTop = ArrayList<Box>()
        for (box in top) {
            if (box.start == moov.start) {
                keepTop.add(box)
                continue
            }
            val reason = IsoBmffCore.dropReason(box.type)
            if (reason != null) {
                removals.add(box.start, box.size)
                val finding = if (box.type == "uuid") {
                    describeUuid(ctx.source, box)
                } else {
                    MetadataFinding(reason, "top level '${box.type.trim()}' box")
                }
                removed.add(finding)
                continue
            }
            if (box.type in IsoBmffCore.staleIndexBoxes) {
                removals.add(box.start, box.size)
                removed.add(MetadataFinding(MetadataKind.OTHER, "stale index box '${box.type.trim()}'"))
                continue
            }
            if (IsoBmffCore.isUnparsedJunk(box)) {
                removals.add(box.start, box.size)
                removed.add(MetadataFinding(MetadataKind.OTHER, "unparsed bytes after the last box (${box.size} bytes)"))
                continue
            }
            keepTop.add(box)
        }

        val built = buildMovieBody(ctx, moov, removed)
            ?: return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "moov rewrite failed")
        val moovBytes = built.body
        val oldMoovTotal = moov.size
        val newMoovTotal = moovBytes.size + moov.headerSize
        if (newMoovTotal > oldMoovTotal) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "rewritten moov is larger than the original")
        }
        removals.add(moov.start, (oldMoovTotal - newMoovTotal).toLong())

        val patchedMoov = applyPatches(moovBytes, built.patches, removals)
            ?: return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "chunk offset rebasing failed")

        val buffer = Buffers.new()
        try {
            BinaryIo.open(ctx.source).use { io ->
                FileOutputStream(ctx.target).use { fileOut ->
                    val out = ProgressOut(fileOut, ctx)
                    for (box in keepTop) {
                        ctx.checkCancelled()
                        if (box.start == moov.start) {
                            IsoBmffCore.writeBox(out, "moov", patchedMoov)
                        } else {
                            io.copyRange(box.start, box.size, out, buffer)
                        }
                    }
                    out.tail()
                    out.flush()
                }
            }
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "write failed")
        }

        val droppedTrackRanges = built.droppedRanges
        val keptTrackRanges = built.keptRanges
        if (droppedTrackRanges.isNotEmpty()) {
            val zeroed = ArrayList<LongRange>()
            for (range in droppedTrackRanges) {
                val start = removals.rebase(range.first) ?: continue
                zeroed.add(start until (start + (range.last - range.first)))
            }
            val protectedRanges = ArrayList<LongRange>()
            for (range in keptTrackRanges) {
                val start = removals.rebase(range.first) ?: continue
                protectedRanges.add(start until (start + (range.last - range.first)))
            }
            val safe = IsoBmffCore.safeRanges(zeroed, protectedRanges)
            IsoBmffCore.zeroRanges(ctx.target, safe)
            if (safe.isNotEmpty()) {
                removed.add(MetadataFinding(MetadataKind.TELEMETRY, "payload of removed metadata track zeroed"))
            }
        }

        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
    }

    internal class MovieRebuild(
        val body: ByteArray,
        val patches: List<Patch>,
        val droppedRanges: List<LongRange>,
        val keptRanges: List<LongRange>
    )

    internal fun buildMovieBody(
        ctx: PurgeContext,
        moov: Box,
        removed: MutableList<MetadataFinding>
    ): MovieRebuild? {
        val patches = ArrayList<Patch>()
        val droppedTrackRanges = ArrayList<LongRange>()
        val keptTrackRanges = ArrayList<LongRange>()
        val moovBody = ByteArrayOutputStream(1 shl 16)
        try {
            BinaryIo.open(ctx.source).use { io ->
                writeMovieContainer(
                    ctx, io, moov, moovBody, patches, removed, droppedTrackRanges, keptTrackRanges,
                    "moov", 0, Buffers.new()
                )
            }
        } catch (refused: PurgeRefusedException) {
            throw refused
        } catch (_: Exception) {
            return null
        }
        return MovieRebuild(moovBody.toByteArray(), patches, droppedTrackRanges, keptTrackRanges)
    }

    internal fun applyMoviePatches(
        bytes: ByteArray,
        patches: List<Patch>,
        removals: Removals
    ): ByteArray? = applyPatches(bytes, patches, removals)

    private fun writeMovieContainer(
        ctx: PurgeContext,
        io: BinaryIo,
        container: Box,
        out: ByteArrayOutputStream,
        patches: MutableList<Patch>,
        removed: MutableList<MetadataFinding>,
        droppedTrackRanges: MutableList<LongRange>,
        keptTrackRanges: MutableList<LongRange>,
        path: String,
        depth: Int,
        copyBuffer: ByteArray
    ) {
        if (depth > IsoBmffCore.MAX_DEPTH) {
            // Below this depth the container body would be copied without being parsed, so any
            // metadata hiding there would survive. Compatibility mode accepts that trade; the
            // strictest mode refuses instead of silently trusting unparsed bytes.
            if (ctx.options.maximumPrivacy) {
                throw PurgeRefusedException(
                    "box nesting exceeded the parser depth limit at $path; " +
                        "contents below this level cannot be verified in maximum privacy mode"
                )
            }
            IsoBmffCore.copyBytes(io, container.bodyStart, container.bodySize, out, copyBuffer)
            return
        }
        if (container.type == "meta" && IsoBmffCore.metaLayout(io, container).hasVersionFlags) {
            val versionFlags = io.peekAt(container.bodyStart, 4)
            if (versionFlags != null) out.write(versionFlags)
        }
        val children = IsoBmffCore.childBoxes(io, container)
        for (child in children) {
            ctx.checkCancelled()
            val childPath = "$path/${child.type.trim()}"
            val reason = IsoBmffCore.dropReason(child.type)
            if (reason != null) {
                removed.add(MetadataFinding(reason, "$childPath box"))
                continue
            }
            if (child.type in IsoBmffCore.staleIndexBoxes) {
                removed.add(MetadataFinding(MetadataKind.OTHER, "$childPath stale index"))
                continue
            }
            if (child.type == "trak" && isMetadataTrack(io, child)) {
                removed.add(MetadataFinding(MetadataKind.TELEMETRY, "$childPath metadata/telemetry track"))
                if (ctx.options.stripTelemetryTracks) {
                    val ranges = sampleRanges(io, child)
                    if (ranges == null) {
                        // The track reference is dropped either way, but without proven sample
                        // ranges the physical payload cannot be zeroed and would survive as
                        // orphan bytes. Maximum privacy refuses instead of guessing.
                        if (ctx.options.maximumPrivacy) {
                            throw PurgeRefusedException(
                                "physical sample range of metadata track at $path cannot be proven; " +
                                    "refusing to drop the track while its payload would remain"
                            )
                        }
                    } else {
                        droppedTrackRanges.addAll(ranges)
                    }
                    continue
                }
            }
            if (child.type == "trak") {
                sampleRanges(io, child)?.let { keptTrackRanges.addAll(it) }
            }
            when {
                child.type == "mvhd" || child.type == "tkhd" || child.type == "mdhd" -> {
                    val raw = io.peekAt(child.bodyStart, child.bodySize.toInt()) ?: continue
                    val patched = patchTimes(raw)
                    if (patched != null && !raw.contentEquals(patched)) {
                        removed.add(MetadataFinding(MetadataKind.TIMESTAMP, "$childPath creation/modification time"))
                    }
                    IsoBmffCore.writeBox(out, child.type, patched ?: raw)
                }
                child.type == "hdlr" -> writeHdlr(child, io, out, removed, childPath)
                child.type == "stco" || child.type == "co64" -> writeOffsetTable(child, io, out, patches)
                child.type == "saio" -> writeSaio(child, io, out, patches, removed, childPath)
                child.type == "tfhd" -> writeTfhd(child, io, out, patches)
                IsoBmffCore.containers.contains(child.type) || child.type == "meta" -> {
                    val firstInnerPatch = patches.size
                    val inner = ByteArrayOutputStream(1 shl 14)
                    writeMovieContainer(
                        ctx, io, child, inner, patches, removed, droppedTrackRanges, keptTrackRanges,
                        childPath, depth + 1, copyBuffer
                    )
                    val innerBytes = inner.toByteArray()
                    val bodyStart = out.size() + 8
                    IsoBmffCore.writeBox(out, child.type, innerBytes)
                    for (i in firstInnerPatch until patches.size) {
                        val patch = patches[i]
                        patches[i] = Patch(patch.bufferOffset + bodyStart, patch.entryCount, patch.wide, patch.values)
                    }
                }
                else -> IsoBmffCore.copyBytes(io, child.start, child.size, out, copyBuffer)
            }
        }
    }

    /**
     * The handler box carries a free text name after the handler type, and encoders put their own
     * signature there ("Lavf58.76.100", "Google", "GoPro"). The handler type has to stay or the
     * track stops decoding, the rest is blanked.
     */
    private fun writeHdlr(
        box: Box,
        io: BinaryIo,
        out: ByteArrayOutputStream,
        removed: MutableList<MetadataFinding>,
        path: String
    ) {
        val raw = io.peekAt(box.bodyStart, box.bodySize.toInt())
        if (raw == null || raw.size < 24) {
            if (raw != null) IsoBmffCore.writeBox(out, "hdlr", raw)
            return
        }
        val copy = raw.copyOf()
        var dirty = false
        for (i in 4 until 8) {
            if (copy[i].toInt() != 0) {
                copy[i] = 0
                dirty = true
            }
        }
        for (i in 24 until copy.size) {
            if (copy[i].toInt() != 0) {
                copy[i] = 0
                dirty = true
            }
        }
        if (dirty) removed.add(MetadataFinding(MetadataKind.SOFTWARE, "$path handler name"))
        IsoBmffCore.writeBox(out, "hdlr", copy)
    }

    private fun writeOffsetTable(box: Box, io: BinaryIo, out: ByteArrayOutputStream, patches: MutableList<Patch>) {
        val body = io.peekAt(box.bodyStart, box.bodySize.toInt()) ?: return
        val wide = box.type == "co64"
        val count = IsoBmffCore.readU32(body, 4).toInt()
        val entrySize = if (wide) 8 else 4
        val values = LongArray(count)
        var valid = 0
        for (i in 0 until count) {
            val at = 8 + i * entrySize
            if (at + entrySize > body.size) break
            values[i] = if (wide) IsoBmffCore.readU64(body, at) else IsoBmffCore.readU32(body, at)
            valid++
        }
        val bodyOffset = out.size()
        IsoBmffCore.writeBox(out, box.type, body)
        patches.add(Patch(bodyOffset + 8 + 8, valid, wide, values))
    }

    private fun writeSaio(
        box: Box,
        io: BinaryIo,
        out: ByteArrayOutputStream,
        patches: MutableList<Patch>,
        removed: MutableList<MetadataFinding>,
        path: String
    ) {
        val body = io.peekAt(box.bodyStart, box.bodySize.toInt()) ?: return
        if (body.size < 8) {
            IsoBmffCore.writeBox(out, "saio", body)
            return
        }
        val version = body[0].toInt() and 0xFF
        val flags = IsoBmffCore.readU32(body, 0) and 0xFFFFFF
        // Version 1 prefixes the entry table with aux_info_type and aux_info_type_parameter.
        val wide = version == 1
        var cursor = 4
        if (wide) cursor += 8
        if (cursor + 4 > body.size) {
            IsoBmffCore.writeBox(out, "saio", body)
            return
        }
        val entryStart = cursor + 4
        val count = IsoBmffCore.readU32(body, cursor).toInt()
        val entrySize = if (wide) 8 else 4
        val values = LongArray(maxOf(count, 0))
        var valid = 0
        for (i in 0 until count) {
            val at = entryStart + i * entrySize
            if (at < 0 || at + entrySize > body.size) break
            values[i] = if (wide) IsoBmffCore.readU64(body, at) else IsoBmffCore.readU32(body, at)
            valid++
        }
        val bodyOffset = out.size()
        IsoBmffCore.writeBox(out, "saio", body)
        patches.add(Patch(bodyOffset + 8 + entryStart, valid, wide, values))
        removed.add(MetadataFinding(MetadataKind.OTHER, "$path auxiliary offset table rebased"))
        if (flags and 0xFFFFFF != 0L) {
            removed.add(MetadataFinding(MetadataKind.OTHER, "$path auxiliary information"))
        }
    }

    private fun writeTfhd(box: Box, io: BinaryIo, out: ByteArrayOutputStream, patches: MutableList<Patch>) {
        val raw = io.peekAt(box.bodyStart, box.bodySize.toInt()) ?: return
        val flags = IsoBmffCore.readU32(raw, 0) and 0xFFFFFF
        val defaultBaseIsMoof = (flags and 0x020000) != 0L
        if (!defaultBaseIsMoof && (flags and 0x000001) != 0L && raw.size >= 16) {
            val value = IsoBmffCore.readU64(raw, 8)
            val copy = raw.copyOf()
            IsoBmffCore.writeBox(out, "tfhd", copy)
            patches.add(Patch(out.size() - copy.size + 8, 1, true, longArrayOf(value)))
        } else {
            IsoBmffCore.writeBox(out, "tfhd", raw)
        }
    }

    private fun applyPatches(
        bytes: ByteArray,
        patches: List<Patch>,
        removals: Removals
    ): ByteArray? {
        for (patch in patches) {
            for (i in 0 until patch.entryCount) {
                val size = if (patch.wide) 8 else 4
                val index = patch.bufferOffset + i * size
                if (index + size > bytes.size) return null
                val original = patch.values[i]
                if (original == 0L) continue
                val shift = removals.before(original) ?: return null
                val updated = original - shift
                if (updated <= 0 || (!patch.wide && updated > 0xFFFFFFFFL)) return null
                for (k in 0 until size) bytes[index + k] = ((updated shr (8 * (size - 1 - k))) and 0xFF).toByte()
            }
        }
        return bytes
    }

    internal fun patchTimes(raw: ByteArray): ByteArray? {
        if (raw.size < 12) return null
        val version = raw[0].toInt() and 0xFF
        val copy = raw.copyOf()
        if (version == 1) {
            if (copy.size < 20) return null
            for (i in 4 until 20) copy[i] = 0
        } else {
            for (i in 4 until 12) copy[i] = 0
        }
        return copy
    }

    internal fun isMetadataTrack(io: BinaryIo, trak: Box): Boolean {
        val mdia = IsoBmffCore.parseBoxes(io, trak.bodyStart, trak.end).firstOrNull { it.type == "mdia" } ?: return false
        val hdlr = IsoBmffCore.parseBoxes(io, mdia.bodyStart, mdia.end).firstOrNull { it.type == "hdlr" } ?: return false
        val body = io.peekAt(hdlr.bodyStart, hdlr.bodySize.toInt()) ?: return false
        if (body.size < 12) return false
        val handler = Bytes.asciiAt(body, 8, 4)
        if (handler in metadataHandlerTypes) return true
        val stbl = findFirst(io, trak, "stbl") ?: return false
        val stsd = IsoBmffCore.parseBoxes(io, stbl.bodyStart, stbl.end).firstOrNull { it.type == "stsd" } ?: return false
        val sample = io.peekAt(stsd.bodyStart, stsd.bodySize.toInt().coerceAtMost(64)) ?: return false
        val fourcc = if (sample.size >= 16) Bytes.asciiAt(sample, 12, 4).trim() else ""
        return fourcc == "gpmd" || fourcc == "mett" || fourcc == "metx" || fourcc == "urim" || fourcc == "camm"
    }

    private fun findFirst(io: BinaryIo, container: Box, type: String, depth: Int = 0): Box? {
        if (depth > IsoBmffCore.MAX_DEPTH) return null
        for (child in IsoBmffCore.childBoxes(io, container)) {
            if (child.type == type) return child
            if (IsoBmffCore.containers.contains(child.type)) {
                val found = findFirst(io, child, type, depth + 1)
                if (found != null) return found
            }
        }
        return null
    }

    internal fun sampleRanges(io: BinaryIo, trak: Box): List<LongRange>? {
        return try {
            val stbl = findFirst(io, trak, "stbl") ?: return null
            val children = IsoBmffCore.parseBoxes(io, stbl.bodyStart, stbl.end)
            val stco = children.firstOrNull { it.type == "stco" || it.type == "co64" } ?: return null
            val stsz = children.firstOrNull { it.type == "stsz" } ?: return null
            val stsc = children.firstOrNull { it.type == "stsc" } ?: return null
            val chunkBody = io.peekAt(stco.bodyStart, stco.bodySize.toInt()) ?: return null
            val wide = stco.type == "co64"
            val chunkCount = IsoBmffCore.readU32(chunkBody, 4).toInt()
            if (chunkCount <= 0 || chunkCount > MAX_SAMPLES) return null
            val chunkOffsets = LongArray(chunkCount)
            for (i in 0 until chunkCount) {
                val at = 8 + i * (if (wide) 8 else 4)
                if (at + (if (wide) 8 else 4) > chunkBody.size) return null
                chunkOffsets[i] = if (wide) IsoBmffCore.readU64(chunkBody, at) else IsoBmffCore.readU32(chunkBody, at)
            }
            val sizeBody = io.peekAt(stsz.bodyStart, stsz.bodySize.toInt()) ?: return null
            val constantSize = IsoBmffCore.readU32(sizeBody, 4)
            val sampleCount = IsoBmffCore.readU32(sizeBody, 8).toInt()
            if (sampleCount <= 0 || sampleCount > MAX_SAMPLES) return null
            val sizes = LongArray(sampleCount) { constantSize }
            if (constantSize == 0L) {
                for (i in 0 until sampleCount) {
                    val at = 12 + i * 4
                    if (at + 4 > sizeBody.size) return null
                    sizes[i] = IsoBmffCore.readU32(sizeBody, at)
                }
            }
            val stscBody = io.peekAt(stsc.bodyStart, stsc.bodySize.toInt()) ?: return null
            val entryCount = IsoBmffCore.readU32(stscBody, 4).toInt()
            if (entryCount <= 0 || entryCount > 1_000_000) return null
            val firstChunk = IntArray(entryCount)
            val samplesPerChunk = IntArray(entryCount)
            for (i in 0 until entryCount) {
                val at = 8 + i * 12
                if (at + 12 > stscBody.size) return null
                firstChunk[i] = IsoBmffCore.readU32(stscBody, at).toInt()
                samplesPerChunk[i] = IsoBmffCore.readU32(stscBody, at + 4).toInt()
            }
            val ranges = ArrayList<LongRange>(chunkCount)
            var sampleIndex = 0
            for (chunk in 0 until chunkCount) {
                var perChunk = samplesPerChunk[0]
                for (i in entryCount - 1 downTo 0) {
                    if (firstChunk[i] <= chunk + 1) {
                        perChunk = samplesPerChunk[i]
                        break
                    }
                }
                var chunkSize = 0L
                for (s in 0 until perChunk) {
                    if (sampleIndex >= sampleCount) break
                    chunkSize += sizes[sampleIndex]
                    sampleIndex++
                }
                if (chunkSize > 0) ranges.add(chunkOffsets[chunk] until (chunkOffsets[chunk] + chunkSize))
            }
            ranges
        } catch (_: Exception) {
            null
        }
    }

    private fun inspectMovie(file: File, top: List<Box>, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        val moov = top.firstOrNull { it.type == "moov" }
            ?: return listOf(MetadataFinding(MetadataKind.OTHER, "movie header (moov) missing"))
        try {
            BinaryIo.open(file).use { io ->
                for (box in top) {
                    if (IsoBmffCore.isUnparsedJunk(box)) {
                        findings.add(MetadataFinding(MetadataKind.OTHER, "unparsed bytes after the last box (${box.size} bytes)"))
                        continue
                    }
                    if (box.start == moov.start) continue
                    IsoBmffCore.dropReason(box.type)?.let {
                        if (box.type == "uuid") {
                            findings.add(MetadataFinding(IsoBmffCore.uuidKind(io, box), IsoBmffCore.uuidDetail(io, box)))
                        } else {
                            findings.add(MetadataFinding(it, "top level '${box.type.trim()}' box"))
                        }
                    }
                    if (box.type in IsoBmffCore.staleIndexBoxes) {
                        findings.add(MetadataFinding(MetadataKind.OTHER, "index box '${box.type.trim()}'"))
                    }
                }
                scanMovieContainer(io, moov, "moov", findings, options, 0)
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    private fun scanMovieContainer(
        io: BinaryIo,
        container: Box,
        path: String,
        findings: MutableList<MetadataFinding>,
        options: PurgeOptions,
        depth: Int
    ) {
        if (depth > IsoBmffCore.MAX_DEPTH) return
        for (child in IsoBmffCore.childBoxes(io, container)) {
            val childPath = "$path/${child.type.trim()}"
            IsoBmffCore.dropReason(child.type)?.let { findings.add(MetadataFinding(it, "$childPath box")) }
            if (child.type == "keys") {
                IsoBmffCore.keysBoxDetail(io, child)?.let { findings.add(it) }
            }
            if (child.type in IsoBmffCore.staleIndexBoxes) findings.add(MetadataFinding(MetadataKind.OTHER, "$childPath index"))
            if (child.type == "trak" && isMetadataTrack(io, child) && options.stripTelemetryTracks) {
                findings.add(MetadataFinding(MetadataKind.TELEMETRY, "$childPath metadata/telemetry track"))
            }
            if (child.type == "mvhd" || child.type == "tkhd" || child.type == "mdhd") {
                val body = io.peekAt(child.bodyStart, child.bodySize.toInt())
                if (body != null && body.isNotEmpty()) {
                    val version = body[0].toInt() and 0xFF
                    val creation = if (version == 1) IsoBmffCore.readU64(body, 4) else IsoBmffCore.readU32(body, 4)
                    val modification = if (version == 1) IsoBmffCore.readU64(body, 12) else IsoBmffCore.readU32(body, 8)
                    if (creation != 0L || modification != 0L) {
                        findings.add(MetadataFinding(MetadataKind.TIMESTAMP, "$childPath creation/modification time"))
                    }
                }
            }
            if (IsoBmffCore.containers.contains(child.type) || child.type == "meta") {
                scanMovieContainer(io, child, childPath, findings, options, depth + 1)
            }
        }
    }

    private fun validateMovie(file: File, top: List<Box>): Boolean {
        val moov = top.firstOrNull { it.type == "moov" } ?: return false
        val dataBoxes = top.filter { it.type == "mdat" || it.type == "moof" }
        return try {
            BinaryIo.open(file).use { io ->
                val traks = IsoBmffCore.parseBoxes(io, moov.bodyStart, moov.end).filter { it.type == "trak" }
                if (traks.isEmpty()) return false
                if (dataBoxes.isEmpty()) return false
                val ranges = dataBoxes.map { it.start to it.end }
                var checked = 0
                for (trak in traks) {
                    val stbl = findFirst(io, trak, "stbl") ?: continue
                    for (child in IsoBmffCore.parseBoxes(io, stbl.bodyStart, stbl.end)) {
                        if (child.type != "stco" && child.type != "co64") continue
                        val body = io.peekAt(child.bodyStart, child.bodySize.toInt()) ?: return false
                        val wide = child.type == "co64"
                        val count = IsoBmffCore.readU32(body, 4).toInt()
                        if (count > MAX_SAMPLES) return false
                        for (i in 0 until count) {
                            val at = 8 + i * (if (wide) 8 else 4)
                            if (at + (if (wide) 8 else 4) > body.size) return false
                            val offset = if (wide) IsoBmffCore.readU64(body, at) else IsoBmffCore.readU32(body, at)
                            checked++
                            if (ranges.none { offset >= it.first && offset < it.second }) return false
                        }
                    }
                }
                if (checked == 0) {

                    val types = top.map { it.type }
                    if (!types.contains("moof") || !types.contains("mdat")) return false
                }
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}


internal object HeifScrubber {

    private const val MAX_ITEMS = 100_000

    private data class ItemInfo(
        val id: Long,
        val type: String,
        val contentType: String,
        val name: String,
        val raw: ByteArray,
        val size: Long
    )

    private data class Extent(val offset: Long, val length: Long)

    private data class IlocEntry(
        val itemId: Long,
        val constructionMethod: Int,
        val baseOffset: Long,
        val baseOffsetSize: Int,
        val offsetSize: Int,
        val extents: MutableList<Extent>
    )

    private data class IlocLayout(
        val version: Int,
        val flags: Int,
        val offsetSize: Int,
        val lengthSize: Int,
        val baseOffsetSize: Int,
        val indexSize: Int,
        val entries: List<IlocEntry>
    )

    private data class OffsetField(
        val bodyOffset: Int,
        val width: Int,
        val entryIndex: Int,
        val isBase: Boolean,
        val extentIndex: Int,
        val originalBase: Long,
        val originalExtent: Long,
        val firstExtent: Long
    )

    private data class Reference(val type: String, val from: Long, val to: Long)

    fun scrub(ctx: PurgeContext, top: List<Box>): ScrubOutcome {
        val meta = top.firstOrNull { it.type == "meta" }
            ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "meta box missing")
        val removals = Removals()
        val removed = ArrayList<MetadataFinding>()

        var moovBox: Box? = null
        for (box in top) {
            if (box.start == meta.start) continue
            val reason = IsoBmffCore.dropReason(box.type)
            if (reason != null) {
                removals.add(box.start, box.size)
                removed.add(MetadataFinding(reason, "top level '${box.type.trim()}' box"))
                continue
            }
            if (box.type in IsoBmffCore.staleIndexBoxes) {
                removals.add(box.start, box.size)
                removed.add(MetadataFinding(MetadataKind.OTHER, "stale index box '${box.type.trim()}'"))
                continue
            }
            if (IsoBmffCore.isUnparsedJunk(box)) {
                removals.add(box.start, box.size)
                removed.add(MetadataFinding(MetadataKind.OTHER, "unparsed bytes after the last box (${box.size} bytes)"))
                continue
            }
            if (box.type == "moov") moovBox = box
        }

        try {
            BinaryIo.open(ctx.source).use { io ->
                val children = IsoBmffCore.childBoxes(io, meta)
                val iinf = children.firstOrNull { it.type == "iinf" }
                val iloc = children.firstOrNull { it.type == "iloc" }
                val iref = children.firstOrNull { it.type == "iref" }
                val idat = children.firstOrNull { it.type == "idat" }
                val pitm = children.firstOrNull { it.type == "pitm" }
                if (iinf == null || iloc == null) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "missing iinf/iloc")
                }
                val items = parseItems(io, iinf)
                val layout = parseIloc(io, iloc)
                val primary = pitm?.let { readPrimaryItem(io, it) } ?: -1L
                val references = iref?.let { parseReferences(io, it) } ?: emptyList()
                val thumbnailTargets = references.filter { it.type == "thmb" }.map { it.to }.toHashSet()
                val auxTargets = references.filter { it.type == "auxl" }.map { it.from }.toHashSet()
                val dropIds = HashSet<Long>()
                for (item in items) {
                    when {
                        item.name.contains("content.identifier", ignoreCase = true) ||
                            item.name.contains("asset.identifier", ignoreCase = true) -> {
                            dropIds.add(item.id)
                            removed.add(
                                MetadataFinding(MetadataKind.UNIQUE_ID, "paired-asset identifier item ${item.id}")
                            )
                        }
                        item.type.equals("Exif", ignoreCase = true) -> {
                            dropIds.add(item.id)
                            removed.add(MetadataFinding(MetadataKind.EXIF, heifItemDetail(io, layout, item.id) ?: "EXIF item ${item.id}"))
                        }
                        item.type == "mime" && isMetadataMime(item.contentType) -> {
                            dropIds.add(item.id)
                            removed.add(MetadataFinding(MetadataKind.XMP, "XML/XMP item ${item.id} (${item.contentType})"))
                        }
                        (item.type.equals("uri ", ignoreCase = true) || item.type == "uri") -> {
                            dropIds.add(item.id)
                            removed.add(MetadataFinding(MetadataKind.OTHER, "URI metadata item ${item.id}"))
                        }
                        item.type == "mime" && item.id != primary && ctx.options.stripEmbeddedThumbnails &&
                            (item.contentType.startsWith("image/") || item.id in thumbnailTargets) -> {
                            dropIds.add(item.id)
                            removed.add(MetadataFinding(MetadataKind.THUMBNAIL, "embedded preview item ${item.id}"))
                        }
                        // Portrait/depth/alpha auxiliary maps ride along via 'auxl' references;
                        // they are secondary images, never the primary, and carry scene data
                        // (face geometry) of their own. Under the thumbnail/strict policy they
                        // join the removal and verification cycle instead of being ignored.
                        item.id in auxTargets && item.id != primary && ctx.options.stripEmbeddedThumbnails -> {
                            dropIds.add(item.id)
                            removed.add(MetadataFinding(MetadataKind.THUMBNAIL, "auxiliary depth/map item ${item.id}"))
                        }
                    }
                }

                val existing = items.map { it.id }.toHashSet()
                for (reference in references) {
                    // Only a reference whose own item is gone is dropped. Throwing away the item
                    // that merely points at a missing target would delete a real image.
                    if (reference.from !in existing) dropIds.add(reference.from)
                }

                val droppedExtents = ArrayList<LongRange>()
                for (entry in layout.entries) {
                    if (entry.itemId !in dropIds) continue
                    if (entry.constructionMethod == 1) continue
                    for (extent in entry.extents) {
                        val start = entry.baseOffset + extent.offset
                        if (start > 0 && extent.length > 0) droppedExtents.add(start until (start + extent.length))
                    }
                }
                val keptExtents = ArrayList<LongRange>()
                for (entry in layout.entries) {
                    if (entry.itemId in dropIds || entry.constructionMethod == 1) continue
                    for (extent in entry.extents) {
                        val start = entry.baseOffset + extent.offset
                        if (start > 0 && extent.length > 0) keptExtents.add(start until (start + extent.length))
                    }
                }

                val keptEntries = layout.entries.filter { it.itemId !in dropIds }
                if (keptEntries.isEmpty()) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "no image items left after scrubbing")
                }
                if (primary > 0 && keptEntries.none { it.itemId == primary }) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "primary image item would be removed")
                }

                val idatEntries = layout.entries.filter { it.constructionMethod == 1 }
                val idatOffsets = HashMap<Long, Pair<Long, Long>>()
                val newIdat: ByteArray? = if (idatEntries.isEmpty() || idat == null) {
                    null
                } else {
                    val payload = io.peekAt(idat.bodyStart, idat.bodySize.toInt()) ?: ByteArray(0)
                    val out = ByteArrayOutputStream(payload.size)
                    var cursor = 0L
                    for (entry in keptEntries) {
                        if (entry.constructionMethod != 1) continue
                        // An item may store its data as several idat extents; all of them are
                        // carried over, concatenated into one extent in the rebuilt iloc.
                        var entryTotal = 0L
                        var wroteAny = false
                        for (extent in entry.extents) {
                            val start = entry.baseOffset + extent.offset
                            val length = extent.length
                            if (start < 0 || length <= 0 || start + length > payload.size) continue
                            out.write(payload, start.toInt(), length.toInt())
                            entryTotal += length
                            wroteAny = true
                        }
                        if (wroteAny) {
                            idatOffsets[entry.itemId] = Pair(cursor, entryTotal)
                            cursor += entryTotal
                        }
                    }
                    out.toByteArray()
                }

                val metaBuffer = ByteArrayOutputStream(1 shl 16)
                val copyBuffer = Buffers.new()
                val metaLayout = IsoBmffCore.metaLayout(io, meta)
                if (metaLayout.hasVersionFlags) {
                    metaBuffer.write(io.peekAt(meta.bodyStart, 4) ?: byteArrayOf(0, 0, 0, 0))
                }
                val fields = ArrayList<OffsetField>()
                var ilocBodyOffset = -1
                for (child in children) {
                    ctx.checkCancelled()
                    val dropKind = IsoBmffCore.dropReason(child.type)
                    when {
                        dropKind != null -> {
                            removed.add(MetadataFinding(dropKind, "meta/${child.type.trim()} box"))
                            removals.add(child.start, child.size)
                        }
                        child.type == "iinf" -> {
                            val body = rebuildIinfBody(io, child, items.filter { it.id !in dropIds })
                            IsoBmffCore.writeBox(metaBuffer, "iinf", body)
                        }
                        child.type == "iloc" -> {
                            val rebuilt = rebuildIloc(layout, keptEntries, idatOffsets)
                            ilocBodyOffset = metaBuffer.size() + 8
                            IsoBmffCore.writeBox(metaBuffer, "iloc", rebuilt.first)
                            fields.addAll(rebuilt.second)
                        }
                        child.type == "iref" -> {
                            val body = rebuildIrefBody(io, child, references, dropIds)
                            IsoBmffCore.writeBox(metaBuffer, "iref", body)
                        }
                        child.type == "idat" -> {
                            if (newIdat != null) IsoBmffCore.writeBox(metaBuffer, "idat", newIdat)
                            else removed.add(MetadataFinding(MetadataKind.EMBEDDED_FILE, "idat payload of removed items"))
                        }
                        else -> IsoBmffCore.copyBytes(io, child.start, child.size, metaBuffer, copyBuffer)
                    }
                }
                val metaBytes = metaBuffer.toByteArray()
                val oldMetaTotal = meta.size
                val newMetaTotal = metaBytes.size + meta.headerSize
                if (newMetaTotal > oldMetaTotal) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "rewritten meta box grew")
                }
                removals.add(meta.start, (oldMetaTotal - newMetaTotal).toLong())

                val moovBytes = moovBox?.let { box -> IsoBmffHandler.buildMovieBody(ctx, box, removed) }
                if (moovBox != null && moovBytes != null) {
                    val shrink = (moovBox.size - (moovBytes.body.size + moovBox.headerSize).toLong())
                    if (shrink < 0) {
                        return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "embedded moov grew")
                    }
                    removals.add(moovBox.start, shrink)
                }

                if (applyIlocFields(metaBytes, ilocBodyOffset, fields, removals) == null) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "item offset rebasing failed")
                }
                val patchedMoov = if (moovBox != null && moovBytes != null) {
                    IsoBmffHandler.applyMoviePatches(moovBytes.body, moovBytes.patches, removals)
                        ?: return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "embedded moov offset rebasing failed")
                } else null

                val buffer = Buffers.new()
                FileOutputStream(ctx.target).use { fileOut ->
                    val out = ProgressOut(fileOut, ctx)
                    for (box in top) {
                        when {
                            box.start == meta.start -> {
                                IsoBmffCore.boxHeader(out, "meta", metaBytes.size.toLong())
                                out.write(metaBytes)
                            }
                            box.type == "moov" && patchedMoov != null -> {
                                IsoBmffCore.boxHeader(out, "moov", patchedMoov.size.toLong())
                                out.write(patchedMoov)
                            }
                            IsoBmffCore.dropReason(box.type) != null -> Unit
                            box.type in IsoBmffCore.staleIndexBoxes -> Unit
                            IsoBmffCore.isUnparsedJunk(box) -> Unit
                            else -> io.copyRange(box.start, box.size, out, buffer)
                        }
                    }
                    out.tail()
                    out.flush()
                }

                if (droppedExtents.isNotEmpty()) {
                    val zeroed = ArrayList<LongRange>()
                    for (range in droppedExtents) {
                        val start = removals.rebase(range.first) ?: continue
                        zeroed.add(start until (start + (range.last - range.first)))
                    }
                    val protectedRanges = ArrayList<LongRange>()
                    for (range in keptExtents) {
                        val start = removals.rebase(range.first) ?: continue
                        protectedRanges.add(start until (start + (range.last - range.first)))
                    }
                    val safe = IsoBmffCore.safeRanges(zeroed, protectedRanges)
                    IsoBmffCore.zeroRanges(ctx.target, safe)
                    if (safe.isNotEmpty()) {
                        removed.add(MetadataFinding(MetadataKind.EMBEDDED_FILE, "payload of removed items zeroed"))
                    }
                }
                val distinct = removed.distinct()
                return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, distinct, emptyList(), true)
            }
        } catch (refused: PurgeRefusedException) {
            throw refused
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "HEIF rewrite failed")
        }
    }

    private fun applyIlocFields(
        metaBytes: ByteArray,
        ilocBodyOffset: Int,
        fields: List<OffsetField>,
        removals: Removals
    ): ByteArray? {
        if (fields.isEmpty()) return metaBytes
        for (field in fields) {
            val index = ilocBodyOffset + field.bodyOffset
            if (field.width <= 0 || index + field.width > metaBytes.size) return null
            val dataStart = field.originalBase + if (field.isBase) field.firstExtent else field.originalExtent
            val dataShift = removals.before(dataStart) ?: return null
            val baseShift = removals.before(field.originalBase) ?: return null
            val updated = if (field.isBase) field.originalBase - baseShift else field.originalExtent - (dataShift - baseShift)
            if (updated < 0) return null
            val maxValue = if (field.width >= 8) Long.MAX_VALUE else (1L shl (8 * field.width)) - 1
            if (updated > maxValue) return null
            for (k in 0 until field.width) {
                metaBytes[index + k] = ((updated shr (8 * (field.width - 1 - k))) and 0xFF).toByte()
            }
        }
        return metaBytes
    }

    private fun parseItems(io: BinaryIo, iinf: Box): List<ItemInfo> {
        val version = io.peekAt(iinf.bodyStart, 1)?.get(0)?.toInt()?.and(0xFF) ?: 0
        val headerSize = if (version == 0) 2 else 4
        val entries = IsoBmffCore.parseBoxes(io, iinf.bodyStart + 4 + headerSize, iinf.end)
        val items = ArrayList<ItemInfo>()
        for (infe in entries) {
            if (infe.type != "infe") continue
            val body = io.peekAt(infe.bodyStart, infe.bodySize.toInt()) ?: continue
            if (body.size < 12) continue
            val infeVersion = body[0].toInt() and 0xFF
            val id: Long
            val type: String
            var cursor: Int
            when {
                infeVersion >= 3 -> {
                    if (body.size < 14) continue
                    id = IsoBmffCore.readU32(body, 4)
                    type = Bytes.asciiAt(body, 10, 4)
                    cursor = 14
                }
                infeVersion == 2 -> {
                    if (body.size < 12) continue
                    id = ((body[4].toLong() and 0xFF) shl 8) or (body[5].toLong() and 0xFF)
                    type = Bytes.asciiAt(body, 8, 4)
                    cursor = 12
                }
                // Versions 0 and 1 have no item_type field at all.
                else -> {
                    if (body.size < 8) continue
                    id = ((body[4].toLong() and 0xFF) shl 8) or (body[5].toLong() and 0xFF)
                    type = ""
                    cursor = 8
                }
            }
            val name = readCString(body, cursor)
            cursor += name.toByteArray(Charsets.UTF_8).size + 1
            var contentType = ""
            if (type == "mime") {
                contentType = readCString(body, cursor)
            }
            items.add(ItemInfo(id, type, contentType, name, body, infe.size))
            if (items.size > MAX_ITEMS) break
        }
        return items
    }

    private fun readCString(b: ByteArray, from: Int): String {
        if (from >= b.size) return ""
        var end = from
        while (end < b.size && b[end].toInt() != 0) end++
        return String(b, from, maxOf(0, end - from), Charsets.UTF_8)
    }

    private fun parseIloc(io: BinaryIo, iloc: Box): IlocLayout {
        val body = io.peekAt(iloc.bodyStart, iloc.bodySize.toInt()) ?: return IlocLayout(0, 0, 0, 0, 0, 0, emptyList())
        var pos = 0
        val version = body[pos].toInt() and 0xFF
        val flags = ((body[pos + 1].toInt() and 0xFF) shl 16) or ((body[pos + 2].toInt() and 0xFF) shl 8) or (body[pos + 3].toInt() and 0xFF)
        pos += 4
        val sizes = body[pos].toInt() and 0xFF
        val offsetSize = (sizes shr 4) and 0x0F
        val lengthSize = sizes and 0x0F
        pos += 1
        val second = body[pos].toInt() and 0xFF
        val baseOffsetSize = (second shr 4) and 0x0F
        val indexSize = if (version in 1..2) second and 0x0F else 0
        pos += 1
        val count = if (version < 2) {
            ((body[pos].toInt() and 0xFF) shl 8) or (body[pos + 1].toInt() and 0xFF)
        } else IsoBmffCore.readU32(body, pos).toInt()
        pos += if (version < 2) 2 else 4
        val entries = ArrayList<IlocEntry>(minOf(count, MAX_ITEMS))
        for (i in 0 until minOf(count, MAX_ITEMS)) {
            if (pos >= body.size) break
            val itemId: Long
            if (version < 2) {
                itemId = ((body[pos].toLong() and 0xFF) shl 8) or (body[pos + 1].toLong() and 0xFF)
                pos += 2
            } else {
                itemId = IsoBmffCore.readU32(body, pos)
                pos += 4
            }
            var constructionMethod = 0
            if (version in 1..2) {
                if (pos + 2 > body.size) break
                constructionMethod = body[pos + 1].toInt() and 0x0F
                pos += 2
            }
            pos += 2
            var baseOffset = 0L
            if (baseOffsetSize > 0) {
                baseOffset = IsoBmffCore.readWidth(body, pos, baseOffsetSize)
                pos += baseOffsetSize
            }
            if (pos + 2 > body.size) break
            val extentCount = ((body[pos].toInt() and 0xFF) shl 8) or (body[pos + 1].toInt() and 0xFF)
            pos += 2
            val extents = ArrayList<Extent>(extentCount)
            for (e in 0 until extentCount) {
                if (indexSize > 0) pos += indexSize
                val extentOffset = if (offsetSize > 0) {
                    val value = IsoBmffCore.readWidth(body, pos, offsetSize)
                    pos += offsetSize
                    value
                } else 0L
                val extentLength = if (lengthSize > 0) {
                    val value = IsoBmffCore.readWidth(body, pos, lengthSize)
                    pos += lengthSize
                    value
                } else 0L
                extents.add(Extent(extentOffset, extentLength))
            }
            entries.add(IlocEntry(itemId, constructionMethod, baseOffset, baseOffsetSize, offsetSize, extents))
        }
        return IlocLayout(version, flags, offsetSize, lengthSize, baseOffsetSize, indexSize, entries)
    }

    private fun parseReferences(io: BinaryIo, iref: Box): List<Reference> {
        val version = io.peekAt(iref.bodyStart, 1)?.get(0)?.toInt()?.and(0xFF) ?: 0
        val width = if (version == 0) 2 else 4
        val entries = IsoBmffCore.parseBoxes(io, iref.bodyStart + 4, iref.end)
        val result = ArrayList<Reference>()
        for (entry in entries) {
            val body = io.peekAt(entry.bodyStart, entry.bodySize.toInt()) ?: continue
            if (body.size < width + width) continue
            val from = IsoBmffCore.readWidth(body, 0, width)
            val count = (body.size - width) / width
            for (i in 0 until count) {
                val to = IsoBmffCore.readWidth(body, width + i * width, width)
                result.add(Reference(entry.type, from, to))
            }
        }
        return result
    }

    private fun readPrimaryItem(io: BinaryIo, pitm: Box): Long {
        val body = io.peekAt(pitm.bodyStart, pitm.bodySize.toInt()) ?: return -1L
        if (body.size < 6) return -1L
        val version = body[0].toInt() and 0xFF
        return if (version == 0) {
            ((body[4].toLong() and 0xFF) shl 8) or (body[5].toLong() and 0xFF)
        } else IsoBmffCore.readU32(body, 4)
    }

    private fun isMetadataMime(contentType: String): Boolean {
        val value = contentType.lowercase()
        return value.contains("rdf+xml") || value == "application/xml" || value == "text/xml" ||
            value.contains("xmp") || value.contains("iptc")
    }

    private fun rebuildIinfBody(io: BinaryIo, iinf: Box, kept: List<ItemInfo>): ByteArray {
        val out = ByteArrayOutputStream(iinf.bodySize.toInt())
        val versionFlags = io.peekAt(iinf.bodyStart, 4) ?: byteArrayOf(0, 0, 0, 0)
        val version = versionFlags[0].toInt() and 0xFF
        out.write(versionFlags)
        if (version == 0) {
            out.write((kept.size shr 8) and 0xFF)
            out.write(kept.size and 0xFF)
        } else {
            for (i in 3 downTo 0) out.write((kept.size shr (8 * i)) and 0xFF)
        }
        for (item in kept) IsoBmffCore.writeBox(out, "infe", item.raw)
        return out.toByteArray()
    }

    private fun rebuildIrefBody(io: BinaryIo, iref: Box, references: List<Reference>, dropIds: Set<Long>): ByteArray {
        val versionFlags = io.peekAt(iref.bodyStart, 4) ?: byteArrayOf(0, 0, 0, 0)
        val out = ByteArrayOutputStream(iref.bodySize.toInt())
        out.write(versionFlags)
        val grouped = LinkedHashMap<Pair<String, Long>, MutableList<Long>>()
        for (reference in references) {
            if (reference.from in dropIds || reference.to in dropIds) continue
            grouped.getOrPut(Pair(reference.type, reference.from)) { ArrayList() }.add(reference.to)
        }
        val width = if ((io.peekAt(iref.bodyStart, 1)?.get(0)?.toInt()?.and(0xFF) ?: 0) == 0) 2 else 4
        for ((key, targets) in grouped) {
            val body = ByteArrayOutputStream()
            IsoBmffCore.writeWidth(body, width, key.second)
            for (target in targets) IsoBmffCore.writeWidth(body, width, target)
            IsoBmffCore.writeBox(out, key.first, body.toByteArray())
        }
        return out.toByteArray()
    }

    private fun rebuildIloc(
        layout: IlocLayout,
        kept: List<IlocEntry>,
        idatOffsets: Map<Long, Pair<Long, Long>>
    ): Pair<ByteArray, List<OffsetField>> {
        val out = ByteArrayOutputStream(1 shl 12)
        out.write(layout.version)
        out.write((layout.flags shr 16) and 0xFF)
        out.write((layout.flags shr 8) and 0xFF)
        out.write(layout.flags and 0xFF)
        out.write(((layout.offsetSize and 0x0F) shl 4) or (layout.lengthSize and 0x0F))
        out.write(((layout.baseOffsetSize and 0x0F) shl 4) or (if (layout.version in 1..2) layout.indexSize and 0x0F else 0))
        if (layout.version < 2) {
            out.write((kept.size shr 8) and 0xFF)
            out.write(kept.size and 0xFF)
        } else {
            for (i in 3 downTo 0) out.write((kept.size shr (8 * i)) and 0xFF)
        }
        val fields = ArrayList<OffsetField>()
        for ((index, entry) in kept.withIndex()) {
            if (layout.version < 2) {
                out.write(((entry.itemId shr 8) and 0xFF).toInt())
                out.write((entry.itemId and 0xFF).toInt())
            } else {
                for (i in 3 downTo 0) out.write(((entry.itemId shr (8 * i)) and 0xFF).toInt())
            }
            if (layout.version in 1..2) {
                out.write(0)
                out.write(entry.constructionMethod and 0x0F)
            }
            out.write(0)
            out.write(0)
            var baseOffset = entry.baseOffset
            val extentList: List<Extent>
            if (entry.constructionMethod == 1) {
                val mapped = idatOffsets[entry.itemId]
                if (mapped != null) {
                    baseOffset = 0L
                    extentList = listOf(Extent(mapped.first, mapped.second))
                } else extentList = entry.extents
            } else {
                extentList = entry.extents
            }
            if (layout.baseOffsetSize > 0) {
                val fieldOffset = out.size()
                IsoBmffCore.writeWidth(out, layout.baseOffsetSize, baseOffset)
                if (entry.constructionMethod != 1) {
                    fields.add(
                        OffsetField(
                            bodyOffset = fieldOffset,
                            width = layout.baseOffsetSize,
                            entryIndex = index,
                            isBase = true,
                            extentIndex = -1,
                            originalBase = entry.baseOffset,
                            originalExtent = 0L,
                            firstExtent = extentList.firstOrNull()?.offset ?: 0L
                        )
                    )
                }
            }
            val extents = extentList.ifEmpty { listOf(Extent(0L, 0L)) }
            out.write((extents.size shr 8) and 0xFF)
            out.write(extents.size and 0xFF)
            for ((extentIndex, extent) in extents.withIndex()) {
                if (layout.indexSize > 0) IsoBmffCore.writeWidth(out, layout.indexSize, 0)
                if (layout.offsetSize > 0) {
                    val fieldOffset = out.size()
                    IsoBmffCore.writeWidth(out, layout.offsetSize, extent.offset)
                    if (entry.constructionMethod != 1 && layout.baseOffsetSize == 0) {
                        fields.add(
                            OffsetField(
                                bodyOffset = fieldOffset,
                                width = layout.offsetSize,
                                entryIndex = index,
                                isBase = false,
                                extentIndex = extentIndex,
                                originalBase = entry.baseOffset,
                                originalExtent = extent.offset,
                                firstExtent = extentList.firstOrNull()?.offset ?: 0L
                            )
                        )
                    }
                }
                if (layout.lengthSize > 0) IsoBmffCore.writeWidth(out, layout.lengthSize, extent.length)
            }
        }
        return Pair(out.toByteArray(), fields)
    }

    private fun heifItemDetail(io: BinaryIo, layout: IlocLayout, itemId: Long): String? {
        return try {
            val entry = layout.entries.firstOrNull { it.itemId == itemId } ?: return null
            if (entry.extents.isEmpty()) return null
            // EXIF payloads may be split across several extents; inspection has to read the
            // whole item, not only the first fragment, or the report understates what is there.
            val budget = 1L shl 20
            val assembled = ByteArrayOutputStream(budget.toInt())
            var remaining = budget
            for (extent in entry.extents) {
                if (remaining <= 0) break
                val start = entry.baseOffset + extent.offset
                if (extent.length <= 0) continue
                val want = minOf(extent.length, remaining)
                val chunk = io.peekAt(start, want.toInt()) ?: break
                assembled.write(chunk)
                remaining -= chunk.size
            }
            val payload = assembled.toByteArray()
            if (payload.isEmpty()) return null
            val tiffStart = if (payload.size > 8 && ExifScanner.scan(payload, 0).valid) 0 else 4
            if (tiffStart >= payload.size) return null
            val scan = ExifScanner.scan(payload, tiffStart)
            val parts = scan.entries.take(6).map { it.describe() }
            if (parts.isEmpty()) "EXIF item" else "EXIF item: " + parts.joinToString(", ")
        } catch (_: Exception) {
            null
        }
    }

    fun inspect(file: File, top: List<Box>, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        val meta = top.firstOrNull { it.type == "meta" }
            ?: return listOf(MetadataFinding(MetadataKind.OTHER, "meta box missing"))
        try {
            BinaryIo.open(file).use { io ->
                val children = IsoBmffCore.childBoxes(io, meta)
                val iinf = children.firstOrNull { it.type == "iinf" }
                val iloc = children.firstOrNull { it.type == "iloc" }
                val iref = children.firstOrNull { it.type == "iref" }
                val pitm = children.firstOrNull { it.type == "pitm" }
                val primary = pitm?.let { readPrimaryItem(io, it) } ?: -1L
                for (box in top) {
                    if (box.start == meta.start) continue
                    IsoBmffCore.dropReason(box.type)?.let {
                        findings.add(MetadataFinding(it, "top level '${box.type.trim()}' box"))
                    }
                    if (box.type in IsoBmffCore.staleIndexBoxes) {
                        findings.add(MetadataFinding(MetadataKind.OTHER, "stale index box '${box.type.trim()}'"))
                    }
                    if (IsoBmffCore.isUnparsedJunk(box)) {
                        findings.add(MetadataFinding(MetadataKind.OTHER, "unparsed bytes after the last box (${box.size} bytes)"))
                    }
                }
                for (child in children) {
                    IsoBmffCore.dropReason(child.type)?.let {
                        findings.add(MetadataFinding(it, "meta/${child.type.trim()} box"))
                    }
                    if (child.type == "keys") {
                        IsoBmffCore.keysBoxDetail(io, child)?.let { findings.add(it) }
                    }
                }
                if (iinf != null) {
                    val layout = iloc?.let { parseIloc(io, it) }
                    val references = iref?.let { parseReferences(io, it) } ?: emptyList()
                    val thumbnailTargets = references.filter { it.type == "thmb" }.map { it.to }.toHashSet()
                    val auxTargets = references.filter { it.type == "auxl" }.map { it.from }.toHashSet()
                    for (item in parseItems(io, iinf)) {
                        when {
                            item.name.contains("content.identifier", ignoreCase = true) ||
                                item.name.contains("asset.identifier", ignoreCase = true) ->
                                findings.add(MetadataFinding(MetadataKind.UNIQUE_ID, "paired-asset identifier item ${item.id}"))
                            item.type.equals("Exif", ignoreCase = true) -> {
                                val detail = layout?.let { heifItemDetail(io, it, item.id) } ?: "EXIF item ${item.id}"
                                findings.add(MetadataFinding(MetadataKind.EXIF, detail))
                            }
                            item.type == "mime" && isMetadataMime(item.contentType) ->
                                findings.add(MetadataFinding(MetadataKind.XMP, "XML/XMP item (${item.contentType})"))
                            (item.type.equals("uri ", ignoreCase = true) || item.type == "uri") ->
                                findings.add(MetadataFinding(MetadataKind.OTHER, "URI metadata item"))
                            item.type == "mime" && options.stripEmbeddedThumbnails && item.id != primary &&
                                (item.contentType.startsWith("image/") || item.id in thumbnailTargets) ->
                                findings.add(MetadataFinding(MetadataKind.THUMBNAIL, "embedded preview item"))
                            item.id in auxTargets && item.id != primary && options.stripEmbeddedThumbnails ->
                                findings.add(MetadataFinding(MetadataKind.THUMBNAIL, "auxiliary depth/map item ${item.id}"))
                            else -> Unit
                        }
                    }
                }
                val moov = top.firstOrNull { it.type == "moov" }
                if (moov != null) {
                    scanMovieContainerForFindings(io, moov, "moov", findings, options, 0)
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    private fun scanMovieContainerForFindings(
        io: BinaryIo,
        container: Box,
        path: String,
        findings: MutableList<MetadataFinding>,
        options: PurgeOptions,
        depth: Int
    ) {
        if (depth > IsoBmffCore.MAX_DEPTH) return
        for (child in IsoBmffCore.childBoxes(io, container)) {
            val childPath = "$path/${child.type.trim()}"
            IsoBmffCore.dropReason(child.type)?.let { findings.add(MetadataFinding(it, "$childPath box")) }
            if (child.type == "keys") {
                IsoBmffCore.keysBoxDetail(io, child)?.let { findings.add(it) }
            }
            if (child.type == "mvhd" || child.type == "tkhd" || child.type == "mdhd") {
                val body = io.peekAt(child.bodyStart, child.bodySize.toInt())
                if (body != null && body.isNotEmpty()) {
                    val version = body[0].toInt() and 0xFF
                    val creation = if (version == 1) IsoBmffCore.readU64(body, 4) else IsoBmffCore.readU32(body, 4)
                    val modification = if (version == 1) IsoBmffCore.readU64(body, 12) else IsoBmffCore.readU32(body, 8)
                    if (creation != 0L || modification != 0L) {
                        findings.add(MetadataFinding(MetadataKind.TIMESTAMP, "$childPath creation/modification time"))
                    }
                }
            }
            if (IsoBmffCore.containers.contains(child.type) || child.type == "meta") {
                scanMovieContainerForFindings(io, child, childPath, findings, options, depth + 1)
            }
        }
    }

    fun validate(file: File, top: List<Box>): Boolean {
        val meta = top.firstOrNull { it.type == "meta" } ?: return false
        val mdatRanges = top.filter { it.type == "mdat" }.map { it.start to it.end }
        return try {
            BinaryIo.open(file).use { io ->
                val children = IsoBmffCore.childBoxes(io, meta)
                val iinf = children.firstOrNull { it.type == "iinf" } ?: return false
                val iloc = children.firstOrNull { it.type == "iloc" } ?: return false
                val items = parseItems(io, iinf)
                if (items.isEmpty()) return false
                if (items.any { it.type.equals("Exif", ignoreCase = true) }) return false
                if (items.any { it.type == "mime" && isMetadataMime(it.contentType) }) return false
                val ids = items.map { it.id }.toHashSet()
                val primary = children.firstOrNull { it.type == "pitm" }?.let { readPrimaryItem(io, it) } ?: -1L
                if (primary > 0 && primary !in ids) return false
                val idat = children.firstOrNull { it.type == "idat" }
                if (mdatRanges.isEmpty() && idat == null) return false
                val layout = parseIloc(io, iloc)
                for (entry in layout.entries) {
                    if (entry.itemId !in ids) continue
                    for (extent in entry.extents) {
                        val start = entry.baseOffset + extent.offset
                        if (extent.length <= 0) continue
                        val inside = when (entry.constructionMethod) {
                            1 -> idat != null && start >= 0 && start + extent.length <= idat.bodySize
                            else -> mdatRanges.any { start >= it.first && start + extent.length <= it.second }
                        }
                        if (!inside) return false
                    }
                }
                val iref = children.firstOrNull { it.type == "iref" }
                if (iref != null) {
                    for (reference in parseReferences(io, iref)) {
                        if (reference.from !in ids || reference.to !in ids) return false
                    }
                }
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}
