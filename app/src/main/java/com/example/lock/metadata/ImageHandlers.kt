package com.example.lock.metadata

import kotlin.math.abs
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream

object GifHandler : FormatHandler {

    override val id: String = "gif"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.GIF)

    private const val EXTENSION = 0x21
    private const val IMAGE_DESCRIPTOR = 0x2C
    private const val TRAILER = 0x3B
    private const val EXT_GRAPHICS_CONTROL = 0xF9
    private const val EXT_COMMENT = 0xFE
    private const val EXT_PLAIN_TEXT = 0x01
    private const val EXT_APPLICATION = 0xFF

    private sealed class Block {
        data class Header(val offset: Long, val length: Long) : Block()
        data class Extension(val offset: Long, val length: Long, val label: Int, val signature: String) : Block()
        data class Image(val offset: Long, val length: Long) : Block()
        data class Trailer(val offset: Long, val length: Long) : Block()
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val blocks = parse(ctx.source) ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a parsable GIF stream")
        if (blocks.none { it is Block.Image }) return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no image block found")

        val removed = ArrayList<MetadataFinding>()
        val buffer = Buffers.new()
        BinaryIo.open(ctx.source).use { io ->
            FileOutputStream(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                for (block in blocks) {
                    ctx.checkCancelled()
                    when (block) {
                        is Block.Header -> io.copyRange(block.offset, block.length, out, buffer)
                        is Block.Image -> io.copyRange(block.offset, block.length, out, buffer)
                        is Block.Trailer -> io.copyRange(block.offset, block.length, out, buffer)
                        is Block.Extension -> {
                            if (classify(block, ctx.options, removed)) {
                                io.copyRange(block.offset, block.length, out, buffer)
                            }
                        }
                    }
                }
                out.tail()
                out.flush()
            }
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
    }

    private fun classify(block: Block.Extension, options: PurgeOptions, removed: MutableList<MetadataFinding>): Boolean {
        return when (block.label) {
            EXT_GRAPHICS_CONTROL -> true
            EXT_COMMENT -> {
                removed.add(MetadataFinding(MetadataKind.COMMENT, "GIF comment extension"))
                false
            }
            EXT_PLAIN_TEXT -> {
                removed.add(MetadataFinding(MetadataKind.COMMENT, "GIF plain text extension"))
                false
            }
            EXT_APPLICATION -> {
                val signature = block.signature
                when {
                    signature.startsWith("NETSCAPE2.0") || signature.startsWith("ANIMEXTS1.0") -> true
                    signature.startsWith("ICCRGBG1") -> {
                        if (options.stripColorProfiles) {
                            removed.add(MetadataFinding(MetadataKind.ICC_PROFILE, "GIF ICC profile"))
                            false
                        } else true
                    }
                    signature.startsWith("XMP DataXMP") -> {
                        removed.add(MetadataFinding(MetadataKind.XMP, "GIF XMP packet"))
                        false
                    }
                    else -> {
                        removed.add(MetadataFinding(MetadataKind.OTHER, "GIF application extension '${signature.trim()}'"))
                        false
                    }
                }
            }
            else -> {
                removed.add(MetadataFinding(MetadataKind.OTHER, "GIF extension 0x%02X".format(block.label)))
                false
            }
        }
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val blocks = parse(file) ?: return listOf(MetadataFinding(MetadataKind.OTHER, "unparsable GIF structure"))
        val findings = ArrayList<MetadataFinding>()
        val trailer = blocks.lastOrNull { it is Block.Trailer }
        if (trailer is Block.Trailer && file.length() > trailer.offset + trailer.length) {
            findings.add(MetadataFinding(MetadataKind.OTHER, "data after the end of image trailer"))
        }
        for (block in blocks) {
            if (block is Block.Extension) classify(block, options, findings)
        }
        return findings.distinct()
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        val blocks = parse(file) ?: return false
        if (blocks.isEmpty()) return false
        val hasHeader = blocks.first() is Block.Header
        val hasImage = blocks.any { it is Block.Image }
        val hasTrailer = blocks.last() is Block.Trailer
        val trailer = blocks.lastOrNull { it is Block.Trailer }
        val cleanTail = trailer !is Block.Trailer || trailer.offset + trailer.length >= file.length()
        return hasHeader && hasImage && hasTrailer && cleanTail
    }

    private fun parse(file: File): List<Block>? {
        return try {
            BinaryIo.open(file).use { io ->
                val length = io.length
                if (length < 14) return null
                io.seek(0)
                val version = io.ascii(6)
                if (version != "GIF87a" && version != "GIF89a") return null

                val logicalScreen = io.readBytes(6)
                val packed = logicalScreen[4].toInt() and 0xFF
                var pos = 13L
                if (packed and 0x80 != 0) {
                    val gctSize = 3L * (1 shl ((packed and 0x07) + 1))
                    pos += gctSize
                }
                if (pos > length) return null
                val blocks = ArrayList<Block>()
                blocks.add(Block.Header(0L, pos))

                var guard = 0
                while (pos < length && guard++ < 5_000_000) {
                    io.seek(pos)
                    when (io.u8()) {
                        IMAGE_DESCRIPTOR -> {
                            val descriptor = io.readBytes(9)
                            var cursor = pos + 10
                            val localPacked = descriptor[8].toInt() and 0xFF
                            if (localPacked and 0x80 != 0) {
                                cursor += 3L * (1 shl ((localPacked and 0x07) + 1))
                            }
                            io.seek(cursor)
                            io.u8()
                            cursor += 1
                            val dataEnd = skipSubBlocks(io)
                            cursor = dataEnd
                            if (cursor > length) return null
                            blocks.add(Block.Image(pos, cursor - pos))
                            pos = cursor
                        }
                        EXTENSION -> {
                            val label = io.u8()
                            val start = pos
                            when (label) {
                                EXT_GRAPHICS_CONTROL, EXT_COMMENT, EXT_PLAIN_TEXT -> {
                                    val end = skipSubBlocks(io)
                                    blocks.add(Block.Extension(start, end - start, label, ""))
                                    pos = end
                                }
                                EXT_APPLICATION -> {
                                    val blockSize = io.u8()
                                    val signature = if (blockSize > 0) io.ascii(minOf(blockSize, 16)) else ""
                                    if (blockSize > 16) io.skip((blockSize - 16).toLong())
                                    val end = skipSubBlocks(io)
                                    blocks.add(Block.Extension(start, end - start, label, signature))
                                    pos = end
                                }
                                else -> {
                                    val end = skipSubBlocks(io)
                                    blocks.add(Block.Extension(start, end - start, label, ""))
                                    pos = end
                                }
                            }
                        }
                        TRAILER -> {
                            blocks.add(Block.Trailer(pos, 1))
                            return blocks
                        }
                        else -> return null
                    }
                }
                blocks
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun skipSubBlocks(io: BinaryIo): Long {
        while (true) {
            val size = io.u8()
            if (size == 0) return io.position
            io.skip(size.toLong())
            if (io.position > io.length) return io.length
        }
    }

    @Suppress("unused")
    private fun copy(out: OutputStream, value: Int) = out.write(value)
}

object BmpHandler : FormatHandler {

    override val id: String = "bmp"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.BMP)

    private data class Layout(
        val pixelOffset: Long,
        val pixelBytes: Long,
        val profileOffset: Long,
        val profileSize: Long,
        val fileLength: Long
    )

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val layout = analyse(ctx.source)
            ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a parsable BMP header")
        val removed = ArrayList<MetadataFinding>()
        val effectiveEnd = minOf(layout.fileLength, layout.pixelOffset + layout.pixelBytes)
        val stripProfile = layout.profileSize > 0 && ctx.options.stripColorProfiles
        if (stripProfile) {
            removed.add(MetadataFinding(MetadataKind.ICC_PROFILE, "embedded colour profile (${layout.profileSize} bytes)"))
        }
        if (layout.fileLength > effectiveEnd) {
            removed.add(MetadataFinding(MetadataKind.OTHER, "appended data after pixel array"))
        }
        val buffer = Buffers.new()
        BinaryIo.open(ctx.source).use { io ->
            FileOutputStream(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                val headerEnd = minOf(layout.pixelOffset, layout.fileLength)
                io.copyRange(0L, headerEnd, out, buffer)
                if (layout.profileSize > 0) {
                    ctx.stage("Removing embedded profile")
                }
                io.copyRange(layout.pixelOffset, (effectiveEnd - layout.pixelOffset).coerceAtLeast(0L), out, buffer)
                out.tail()
                out.flush()
            }
        }
        if (stripProfile) {
            patchProfileFields(ctx.target, layout)
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
    }

    private fun patchProfileFields(target: File, layout: Layout) {
        try {
            BinaryIo.openReadWrite(target).use { io ->
                val dibSize = io.peekAt(14, 4)?.let { Bytes.u32le(it, 0) } ?: return
                if (dibSize < 124L) return
                val dibStart = 14L
                val profileDataPos = dibStart + 112
                val profileSizePos = dibStart + 116
                if (profileDataPos + 8 > io.length) return
                val zero = ByteArray(8)
                io.writeAt(profileDataPos, zero)
                io.writeAt(profileSizePos, zero)
                // The profile itself usually sits between the header and the pixel array, where a
                // straight copy carries it across. Wipe it in place; if it lived past the pixel
                // array the truncation above already removed it.
                if (layout.profileOffset in 0 until layout.pixelOffset &&
                    layout.profileOffset + layout.profileSize <= io.length
                ) {
                    io.writeZeros(layout.profileOffset, layout.profileSize)
                }
                io.fsync()
            }
        } catch (_: Exception) {
        }
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val layout = analyse(file) ?: return listOf(MetadataFinding(MetadataKind.OTHER, "unparsable BMP header"))
        val findings = ArrayList<MetadataFinding>()
        if (layout.profileSize > 0 && options.stripColorProfiles) {
            findings.add(MetadataFinding(MetadataKind.ICC_PROFILE, "embedded colour profile"))
        }
        val effectiveEnd = minOf(layout.fileLength, layout.pixelOffset + layout.pixelBytes)
        if (layout.fileLength > effectiveEnd) findings.add(MetadataFinding(MetadataKind.OTHER, "appended data after pixel array"))
        return findings
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        val layout = analyse(file) ?: return false
        val expected = minOf(layout.fileLength, layout.pixelOffset + layout.pixelBytes)
        if (layout.fileLength != expected) return false
        return layout.pixelOffset >= 26 && layout.pixelBytes > 0
    }

    private fun analyse(file: File): Layout? {
        return try {
            BinaryIo.open(file).use { io ->
                val length = io.length
                if (length < 26) return null
                val header = io.peekAt(0, 26) ?: return null
                if (header[0].toInt() != 0x42 || header[1].toInt() != 0x4D) return null
                val pixelOffset = Bytes.u32le(header, 10)
                val dibSize = Bytes.u32le(header, 14)
                if (pixelOffset > length) return null
                var profileOffset = -1L
                var profileSize = 0L
                val pixelBytes: Long
                when (dibSize) {
                    12L -> {
                        val width = Bytes.u16le(header, 18)
                        val height = Bytes.u16le(header, 20)
                        val bpp = Bytes.u16le(header, 24)
                        pixelBytes = rowBytes(width.toLong(), bpp.toLong()) * height
                    }
                    40L, 52L, 56L, 108L, 124L -> {
                        val extra = io.peekAt(14, dibSize.toInt()) ?: return null
                        val width = Bytes.u32le(extra, 4).toInt()
                        val height = Bytes.u32le(extra, 8).toInt()
                        val bpp = Bytes.u16le(extra, 14).toLong()
                        val imageSize = Bytes.u32le(extra, 20)
                        val computed = if (imageSize > 0L) imageSize
                        else rowBytes(width.toLong(), bpp) * abs(height).toLong()
                        pixelBytes = computed
                        if (dibSize >= 124L) {
                            profileOffset = Bytes.u32le(extra, 112)
                            profileSize = Bytes.u32le(extra, 116)
                            if (profileSize <= 0 || profileOffset <= 0 || profileOffset + profileSize > length) {
                                profileSize = 0L
                                profileOffset = -1L
                            }
                        }
                    }
                    else -> return null
                }
                val span = if (pixelBytes <= 0) length - pixelOffset else pixelBytes
                Layout(pixelOffset, minOf(span, length - pixelOffset), profileOffset, profileSize, length)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun rowBytes(width: Long, bpp: Long): Long {
        if (width <= 0 || bpp <= 0) return 0L
        val bitsPerRow = width * bpp
        return ((bitsPerRow + 31) / 32) * 4
    }
}

object PsdHandler : FormatHandler {

    override val id: String = "psd"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.PSD)

    private const val SIGNATURE = "8BIM"
    private const val ICC_RESOURCE = 1039

    private val keepIds = setOf(
        1005, 1010, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1024, 1026, 1030, 1032, 1037,
        1038, 1041, 1042, 1046, 1047, 1048, 1049, 1052, 1062, 1063
    )

    private val namedIds = mapOf(
        1000 to "obsolete photoshop data",
        1002 to "macintosh page format",
        1008 to "caption",
        1021 to "postscript data",
        1028 to "iptc record",
        1033 to "copyright flag",
        1034 to "url",
        1035 to "thumbnail (photoshop 4)",
        1036 to "thumbnail (photoshop 5)",
        1040 to "digimarc watermark",
        1054 to "version info",
        1057 to "url list",
        1058 to "exif data 1",
        1059 to "exif data 3",
        1060 to "xmp packet",
        1061 to "caption digest",
        1064 to "pixel aspect ratio",
        1077 to "print information"
    )

    private data class Resource(val id: Int, val start: Long, val size: Long)

    private class Layout(
        val version: Int,
        val colorModeStart: Long,
        val colorModeLength: Long,
        val resourceLengthOffset: Long,
        val resourceStart: Long,
        val resourceLength: Long,
        val after: Long,
        val channels: Int,
        val height: Long,
        val width: Long,
        val depth: Int
    )

    private fun layout(io: BinaryIo): Layout? {
        val head = io.peekAt(0, 26) ?: return null
        if (Bytes.asciiAt(head, 0, 4) != "8BPS") return null
        val version = Bytes.u16be(head, 4)
        if (version != 1 && version != 2) return null
        val channels = Bytes.u16be(head, 12)
        val height = Bytes.u32be(head, 14)
        val width = Bytes.u32be(head, 18)
        val depth = Bytes.u16be(head, 22)
        if (channels <= 0 || channels > 56 || height == 0L || width == 0L) return null
        if (depth != 1 && depth != 8 && depth != 16 && depth != 32) return null
        val colorModeLengthRaw = io.peekAt(26L, 4) ?: return null
        val colorModeLength = Bytes.u32be(colorModeLengthRaw, 0)
        if (!io.inRange(30L, colorModeLength)) return null
        val resourceLengthOffset = 30L + colorModeLength
        val resourceLengthRaw = io.peekAt(resourceLengthOffset, 4) ?: return null
        val resourceLength = Bytes.u32be(resourceLengthRaw, 0)
        val resourceStart = resourceLengthOffset + 4L
        if (!io.inRange(resourceStart, resourceLength)) return null
        return Layout(
            version,
            colorModeStart = 30L,
            colorModeLength,
            resourceLengthOffset,
            resourceStart,
            resourceLength,
            after = resourceStart + resourceLength,
            channels,
            height,
            width,
            depth
        )
    }

    private fun imageDataEnd(io: BinaryIo, layout: Layout): Long? {
        val head = io.peekAt(layout.after, 8) ?: return null
        val layerLength = Bytes.u32be(head, 0)
        val sectionStart = layout.after + 4L + layerLength
        val section = io.peekAt(sectionStart, 4) ?: return null
        val compression = Bytes.u16be(section, 0)
        when (compression) {
            0 -> {
                val bytesPerSample = maxOf(1, layout.depth / 8)
                val span = layout.channels.toLong() * layout.height * layout.width * bytesPerSample
                if (span <= 0) return null
                val end = sectionStart + 2L + span
                return if (end <= io.length) end else null
            }
            1 -> {
                // RLE: a table of two byte scanline lengths precedes the packed data.
                val rows = layout.channels.toLong() * layout.height
                if (rows <= 0 || rows > 1_000_000L) return null
                val tableStart = sectionStart + 2L
                val table = io.peekAt(tableStart, (rows * 2L).toInt()) ?: return null
                var total = 0L
                for (i in 0 until rows.toInt()) total += Bytes.u16be(table, i * 2).toLong()
                val end = tableStart + rows * 2L + total
                return if (end in 1L..io.length) end else null
            }
            // ZIP and ZIP with prediction give no length without decompressing; leave the tail.
            else -> return null
        }
    }

    private fun trailingData(io: BinaryIo, layout: Layout): Boolean {
        val end = imageDataEnd(io, layout) ?: return false
        return end in 1L until io.length
    }

    private fun resources(io: BinaryIo, layout: Layout): List<Resource> {
        val out = ArrayList<Resource>()
        var cursor = layout.resourceStart
        val end = layout.resourceStart + layout.resourceLength
        while (cursor + 12L <= end) {
            val head = io.peekAt(cursor, 14) ?: break
            if (Bytes.asciiAt(head, 0, 4) != SIGNATURE) break
            val id = Bytes.u16be(head, 4)
            var nameLength = head[6].toInt() and 0xFF
            var nameSize = 1 + nameLength
            if (nameSize % 2 != 0) nameSize++
            val sizeOffset = cursor + 6 + nameSize
            val sizeRaw = io.peekAt(sizeOffset, 4) ?: break
            val size = Bytes.u32be(sizeRaw, 0)
            val dataStart = sizeOffset + 4L
            if (!io.inRange(dataStart, size)) break
            var padded = size
            if (padded % 2L != 0L) padded++
            out.add(Resource(id, cursor, 10L + nameSize + padded))
            cursor = dataStart + padded
        }
        return out
    }

    private fun kindFor(id: Int): MetadataKind = when (id) {
        1028, 1008, 1002, 1060 -> MetadataKind.IPTC
        1057, 1058 -> MetadataKind.EXIF
        1059 -> MetadataKind.XMP
        1033, 1036 -> MetadataKind.THUMBNAIL
        1034, 1035, 1050 -> MetadataKind.PATH_LEAK
        1040 -> MetadataKind.UNIQUE_ID
        1054 -> MetadataKind.SOFTWARE
        else -> MetadataKind.OTHER
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                val layout = layout(io) ?: return listOf(MetadataFinding(MetadataKind.OTHER, "unreadable PSD header"))
                if (trailingData(io, layout)) {
                    findings.add(MetadataFinding(MetadataKind.OTHER, "appended data after image data"))
                }
                for (resource in resources(io, layout)) {
                    if (resource.id == ICC_RESOURCE) {
                        if (options.stripColorProfiles) {
                            findings.add(MetadataFinding(MetadataKind.ICC_PROFILE, "icc profile resource"))
                        }
                        continue
                    }
                    if (keepIds.contains(resource.id)) continue
                    val label = namedIds[resource.id] ?: "image resource ${resource.id}"
                    findings.add(MetadataFinding(kindFor(resource.id), label))
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val removed = ArrayList<MetadataFinding>()
        val buffer = Buffers.new()
        try {
            BinaryIo.open(ctx.source).use { io ->
                val layout = layout(io)
                    ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "unreadable PSD header")
                val kept = ByteArrayOutputStream(1 shl 16)
                var dropped = 0
                for (resource in resources(io, layout)) {
                    ctx.checkCancelled()
                    if (resource.id == ICC_RESOURCE && !ctx.options.stripColorProfiles) {
                        val slice = io.peekAt(resource.start, resource.size.toInt()) ?: continue
                        kept.write(slice)
                        continue
                    }
                    if (resource.id == ICC_RESOURCE || !keepIds.contains(resource.id)) {
                        val label = if (resource.id == ICC_RESOURCE) "icc profile resource"
                        else namedIds[resource.id] ?: "image resource ${resource.id}"
                        removed.add(MetadataFinding(kindFor(resource.id), label))
                        dropped++
                        continue
                    }
                    val slice = io.peekAt(resource.start, resource.size.toInt()) ?: continue
                    kept.write(slice)
                }
                val trailing = trailingData(io, layout)
                val unresolvedTail = imageDataEnd(io, layout) == null
                if (unresolvedTail && ctx.options.maximumPrivacy) {
                    return ScrubOutcome(
                        false, PurgeStrategy.NONE, removed,
                        message = "ZIP-compressed image data length cannot be proven without decompression; " +
                            "refusing because appended bytes after the pixel stream cannot be excluded"
                    )
                }
                if (removed.isEmpty() && !trailing) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable markers")
                }
                if (trailing) {
                    removed.add(MetadataFinding(MetadataKind.OTHER, "appended data after image data"))
                }
                val resourcesBytes = kept.toByteArray()
                FileOutputStream(ctx.target).use { fileOut ->
                    val out = ProgressOut(fileOut, ctx)
                    io.copyRange(0L, layout.colorModeStart, out, buffer)
                    io.copyRange(layout.colorModeStart, layout.colorModeLength, out, buffer)
                    val resourceLength = ByteArray(4)
                    Bytes.putU32be(resourceLength, 0, resourcesBytes.size.toLong())
                    out.write(resourceLength)
                    out.write(resourcesBytes)
                    val tailEnd = imageDataEnd(io, layout) ?: io.length
                    io.copyRange(layout.after, tailEnd - layout.after, out, buffer)
                    out.tail()
                    out.flush()
                }
            }
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "psd rewrite failed")
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val layout = layout(io) ?: return false
                if (layout.after > io.length) return false
                for (resource in resources(io, layout)) {
                    if (resource.id == ICC_RESOURCE) {
                        if (options.stripColorProfiles) return false
                        continue
                    }
                    if (!keepIds.contains(resource.id)) return false
                }
                if (layout.after + 4L > io.length) return false
                // An unprovable tail is tolerated in compatibility mode but fails verification
                // under maximum privacy: absence of appended data must be demonstrated, not assumed.
                val end = imageDataEnd(io, layout) ?: return !options.maximumPrivacy
                end >= io.length
            }
        } catch (_: Exception) {
            false
        }
    }
}


object TiffHandler : FormatHandler {

    override val id: String = "tiff"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.TIFF, MediaFormat.RAW)

    private const val TAG_NEW_SUBFILE_TYPE = 0x00FE
    private const val TAG_ORIENTATION = 0x0112
    private const val TAG_SUB_IFDS = 0x014A
    private const val TAG_JPEG_IF = 0x0201
    private const val TAG_JPEG_IF_LENGTH = 0x0202
    private const val TAG_EXIF_IFD = 0x8769
    private const val TAG_GPS_IFD = 0x8825
    private const val TAG_INTEROP_IFD = 0xA005
    private const val MAX_IFD_DEPTH = 8
    private const val MAX_ENTRIES = 65535

    private data class Header(val little: Boolean, val bigTiff: Boolean, val firstIfd: Long)

    private data class Entry(
        val index: Int,
        val tag: Int,
        val type: Int,
        val count: Long,
        val valueFieldOffset: Long,
        val valueDataOffset: Long,
        val valueLength: Long,
        val inline: Boolean
    )

    private class Ifd(
        val offset: Long,
        val entries: MutableList<Entry>,
        val entryCount: Int,
        val entrySize: Int,
        val nextPointerOffset: Long,
        /** Kept in step with the file: rewriteIfd re-emits this pointer at the new tail. */
        var nextIfd: Long
    )

    private class Patches {
        val findings = ArrayList<MetadataFinding>()
        val zeroRanges = ArrayList<LongRange>()
        val keptValueRanges = ArrayList<LongRange>()
        var modified = false
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        try {
            ctx.source.copyTo(ctx.target, overwrite = true)
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = e.message ?: "copy failed")
        }
        val patches = Patches()
        try {
            BinaryIo.openReadWrite(ctx.target).use { io ->
                val header = readHeader(io)
                    ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "unparsable TIFF header")
                val chain = readIfdChain(io, header)
                if (chain.isEmpty()) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no IFD found")
                }
                ctx.stage("Cleaning TIFF directories")
                cleanChain(io, header, chain, patches, ctx)
                applyZeroRanges(io, patches)
                // Re-read: removing a sub IFD shortens the chain, and the truncation point has to
                // follow what the cleaned file still references, not what the source referenced.
                val cleanedChain = readIfdChain(io, header)
                val end = if (cleanedChain.isEmpty()) null else referencedEnd(io, header, cleanedChain)
                if (end != null && end > 0 && end < io.length) {
                    patches.findings.add(MetadataFinding(MetadataKind.OTHER, "bytes after the last TIFF data block"))
                    patches.modified = true
                    io.setLength(end)
                }
                io.fsync()
            }
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, patches.findings, message = e.message ?: "TIFF rewrite failed")
        }
        if (!patches.modified) {
            return ScrubOutcome(false, PurgeStrategy.NONE, patches.findings, message = "nothing removable")
        }
        return ScrubOutcome(true, PurgeStrategy.TAG_TABLE_REWRITE, patches.findings.distinct(), emptyList(), true)
    }

    private fun cleanChain(io: BinaryIo, header: Header, chain: List<Ifd>, patches: Patches, ctx: PurgeContext) {
        val keep = BooleanArray(chain.size) { index ->
            val ifd = chain[index]
            !(index > 0 && ctx.options.stripEmbeddedThumbnails && isThumbnail(io, header, ifd))
        }
        for (index in chain.indices) {
            if (keep[index]) continue
            val ifd = chain[index]
            patches.findings.add(MetadataFinding(MetadataKind.THUMBNAIL, "subfile IFD $index"))
            collectIfdData(io, header, ifd, patches)
            zeroIfdBlock(io, header, ifd, patches)
            patches.modified = true
        }

        val keptIndexes = chain.indices.filter { keep[it] }
        for ((position, index) in keptIndexes.withIndex()) {
            val ifd = chain[index]
            val next = if (position + 1 < keptIndexes.size) chain[keptIndexes[position + 1]].offset else 0L
            if (next != ifd.nextIfd) writeNextPointer(io, header, ifd, next)
        }
        for (index in keptIndexes) {
            ctx.checkCancelled()
            cleanIfd(io, header, chain[index], "IFD$index", patches, ctx, 0)
        }
    }

    private fun isThumbnail(io: BinaryIo, header: Header, ifd: Ifd): Boolean {
        val entry = ifd.entries.firstOrNull { it.tag == TAG_NEW_SUBFILE_TYPE } ?: return true
        val value = readEntryLong(io, header, entry)
        return value and 1L != 0L
    }

    private fun isReducedResolution(io: BinaryIo, header: Header, ifd: Ifd): Boolean {
        val entry = ifd.entries.firstOrNull { it.tag == TAG_NEW_SUBFILE_TYPE } ?: return false
        return readEntryLong(io, header, entry) and 1L != 0L
    }

    private fun cleanIfd(io: BinaryIo, header: Header, ifd: Ifd, path: String, patches: Patches, ctx: PurgeContext, depth: Int) {
        if (depth > MAX_IFD_DEPTH) return
        val kept = ArrayList<Entry>()
        for (entry in ifd.entries) {
            when {
                entry.tag == TAG_GPS_IFD -> {
                    patches.findings.add(MetadataFinding(MetadataKind.GPS, "$path GPS directory"))
                    val child = readIfd(io, header, readEntryLong(io, header, entry))
                    if (child != null) {
                        collectIfdData(io, header, child, patches)
                        zeroIfdBlock(io, header, child, patches)
                    }
                    zeroEntryValue(io, entry, patches)
                    patches.modified = true
                }
                entry.tag == TAG_EXIF_IFD || entry.tag == TAG_INTEROP_IFD -> {
                    // The whole sub directory goes, the same way the GPS directory does. Nothing in
                    // it is needed to render the image, and every handler for every other format
                    // drops its EXIF block outright.
                    patches.findings.add(MetadataFinding(MetadataKind.EXIF, "$path EXIF directory"))
                    val child = readIfd(io, header, readEntryLong(io, header, entry))
                    if (child != null) {
                        collectIfdData(io, header, child, patches)
                        zeroIfdBlock(io, header, child, patches)
                    }
                    zeroEntryValue(io, entry, patches)
                    patches.modified = true
                }
                entry.tag == TAG_SUB_IFDS -> {
                    cleanSubIfds(io, header, entry, path, patches, ctx, depth)
                    kept.add(entry)
                    trackKeptValue(io, entry, patches)
                }
                entry.tag == TAG_ORIENTATION && ctx.options.orientationPolicy == OrientationPolicy.STRIP -> {
                    patches.findings.add(MetadataFinding(MetadataKind.OTHER, "$path Orientation"))
                    zeroEntryValue(io, entry, patches)
                    patches.modified = true
                }
                else -> {
                    val banned = TagTable.bannedKind(entry.tag)
                    if (banned != null) {
                        patches.findings.add(MetadataFinding(banned, "$path ${TagTable.name(entry.tag)}"))
                        zeroEntryValue(io, entry, patches)
                        patches.modified = true
                    } else if (ctx.options.maximumPrivacy && !TagTable.isRenderEssential(entry.tag)) {
                        // Unknown or unlisted private tags are unverified, not safe: the strictest
                        // policy keeps only the rendering allowlist and drops everything else.
                        patches.findings.add(
                            MetadataFinding(MetadataKind.OTHER, "$path non-essential tag ${TagTable.name(entry.tag)}")
                        )
                        zeroEntryValue(io, entry, patches)
                        patches.modified = true
                    } else {
                        kept.add(entry)
                        trackKeptValue(io, entry, patches)
                    }
                }
            }
        }
        if (kept.size != ifd.entries.size) {
            rewriteIfd(io, header, ifd, kept)
            patches.modified = true
        }
    }

    private fun trackKeptValue(io: BinaryIo, entry: Entry, patches: Patches) {
        if (entry.inline) return
        if (entry.valueDataOffset <= 0 || entry.valueLength <= 0) return
        if (entry.valueDataOffset + entry.valueLength > io.length) return
        if (entry.valueLength > 256L * 1024 * 1024) return
        patches.keptValueRanges.add(entry.valueDataOffset until (entry.valueDataOffset + entry.valueLength))
    }

    private fun cleanSubIfds(
        io: BinaryIo,
        header: Header,
        entry: Entry,
        path: String,
        patches: Patches,
        ctx: PurgeContext,
        depth: Int
    ) {
        val declared = minOf(entry.count.toInt(), 64)
        if (declared <= 0) return
        val offsets = ArrayList<Long>(declared)
        for (i in 0 until declared) {
            val at = if (entry.inline) entry.valueFieldOffset + i * 4L else entry.valueDataOffset + i * 4L
            val value = readU32At(io, at, header.little)
            if (value <= 0) break
            offsets.add(value)
        }
        if (offsets.isEmpty()) return
        val count = offsets.size
        val keptOffsets = ArrayList<Long>()
        for (offset in offsets) {
            val child = readIfd(io, header, offset) ?: continue
            if (ctx.options.stripEmbeddedThumbnails && isReducedResolution(io, header, child)) {
                patches.findings.add(MetadataFinding(MetadataKind.THUMBNAIL, "$path subfile IFD"))
                collectIfdData(io, header, child, patches)
                zeroIfdBlock(io, header, child, patches)
                continue
            }
            cleanIfd(io, header, child, "$path/sub", patches, ctx, depth + 1)
            keptOffsets.add(offset)
        }
        if (keptOffsets.size == offsets.size) return
        for (i in 0 until count) {
            val at = if (entry.inline) entry.valueFieldOffset + i * 4L else entry.valueDataOffset + i * 4L
            val value = if (i < keptOffsets.size) keptOffsets[i] else 0L
            writeU32At(io, at, value, header.little)
        }
        val countField = entry.valueFieldOffset - (if (header.bigTiff) 8 else 4)
        if (header.bigTiff) writeU64At(io, countField, keptOffsets.size.toLong(), header.little)
        else writeU32At(io, countField, keptOffsets.size.toLong(), header.little)
        if (keptOffsets.isEmpty()) zeroEntryValue(io, entry, patches)
        patches.modified = true
    }

    private fun rewriteIfd(io: BinaryIo, header: Header, ifd: Ifd, kept: List<Entry>) {
        val entriesStart = ifd.offset + if (header.bigTiff) 8 else 2
        if (header.bigTiff) writeU64At(io, ifd.offset, kept.size.toLong(), header.little)
        else writeU16At(io, ifd.offset, kept.size, header.little)
        for ((position, entry) in kept.withIndex()) {
            val source = entriesStart + entry.index.toLong() * ifd.entrySize
            val target = entriesStart + position.toLong() * ifd.entrySize
            if (source == target) continue
            val bytes = io.peekAt(source, ifd.entrySize) ?: continue
            io.writeAt(target, bytes)
            io.writeZeros(source, ifd.entrySize.toLong())
        }
        val newTail = entriesStart + kept.size.toLong() * ifd.entrySize
        val oldTail = entriesStart + ifd.entryCount.toLong() * ifd.entrySize
        if (oldTail > newTail) io.writeZeros(newTail, oldTail - newTail)
        val nextPointer = newTail
        if (header.bigTiff) writeU64At(io, nextPointer, ifd.nextIfd, header.little)
        else writeU32At(io, nextPointer, ifd.nextIfd, header.little)
    }

    private fun writeNextPointer(io: BinaryIo, header: Header, ifd: Ifd, value: Long) {
        if (header.bigTiff) writeU64At(io, ifd.nextPointerOffset, value, header.little)
        else writeU32At(io, ifd.nextPointerOffset, value, header.little)
        ifd.nextIfd = value
    }

    private fun zeroEntryValue(io: BinaryIo, entry: Entry, patches: Patches) {
        if (entry.inline) {
            if (entry.valueLength in 1..8) io.writeZeros(entry.valueFieldOffset, entry.valueLength)
            return
        }
        if (entry.valueDataOffset <= 0 || entry.valueLength <= 0) return
        val length = minOf(entry.valueLength, io.length - entry.valueDataOffset)
        if (length > 0) patches.zeroRanges.add(entry.valueDataOffset until (entry.valueDataOffset + length))
    }

    private fun collectIfdData(io: BinaryIo, header: Header, ifd: Ifd, patches: Patches) {
        val jpegLength = ifd.entries.firstOrNull { it.tag == TAG_JPEG_IF_LENGTH }?.let { readEntryLong(io, header, it) } ?: 0L
        for (entry in ifd.entries) {
            if (entry.tag == TAG_JPEG_IF) {
                val start = readEntryLong(io, header, entry)
                if (start > 0 && jpegLength > 0 && start + jpegLength <= io.length) {
                    patches.zeroRanges.add(start until (start + jpegLength))
                }
            }
            if (entry.tag == TAG_EXIF_IFD || entry.tag == TAG_INTEROP_IFD) {
                val child = readIfd(io, header, readEntryLong(io, header, entry))
                if (child != null) {
                    collectIfdData(io, header, child, patches)
                    zeroIfdBlock(io, header, child, patches)
                }
            }
            val countsTag = when (entry.tag) {
                TagTable.TAG_STRIP_OFFSETS -> TagTable.TAG_STRIP_BYTE_COUNTS
                TagTable.TAG_TILE_OFFSETS -> TagTable.TAG_TILE_BYTE_COUNTS
                else -> -1
            }
            if (countsTag > 0) {
                val lengths = ifd.entries.firstOrNull { it.tag == countsTag }
                val offsets = entryLongs(io, header, entry)
                val sizes = if (lengths != null) entryLongs(io, header, lengths) else null
                if (offsets != null && sizes != null && offsets.size == sizes.size) {
                    for (i in offsets.indices) {
                        if (offsets[i] < 0 || sizes[i] <= 0) continue
                        val stop = minOf(offsets[i] + sizes[i], io.length)
                        if (stop > offsets[i]) patches.zeroRanges.add(offsets[i] until stop)
                    }
                }
            }
            if (entry.tag == TAG_SUB_IFDS) {
                val count = minOf(entry.count.toInt(), 64)
                for (i in 0 until count) {
                    val at = if (entry.inline) entry.valueFieldOffset + i * 4L else entry.valueDataOffset + i * 4L
                    val child = readIfd(io, header, readU32At(io, at, header.little)) ?: continue
                    collectIfdData(io, header, child, patches)
                    zeroIfdBlock(io, header, child, patches)
                }
            }
            zeroEntryValue(io, entry, patches)
        }
    }

    private fun zeroIfdBlock(io: BinaryIo, header: Header, ifd: Ifd, patches: Patches) {
        val headerSize = if (header.bigTiff) 8L else 2L
        val pointerSize = if (header.bigTiff) 8L else 4L
        val total = headerSize + ifd.entryCount.toLong() * ifd.entrySize + pointerSize
        if (total > 0 && ifd.offset >= 0 && ifd.offset + total <= io.length) {
            patches.zeroRanges.add(ifd.offset until (ifd.offset + total))
        }
    }

    private fun applyZeroRanges(io: BinaryIo, patches: Patches) {
        for (range in patches.zeroRanges) {
            // Cut the kept values out of the range rather than skipping the whole range: a removed
            // tag whose blob happens to share a block with a kept one still has to be zeroed.
            for (part in subtract(patches.keptValueRanges, range)) {
                val start = maxOf(0L, part.first)
                val end = minOf(part.last, io.length)
                if (end > start) io.writeZeros(start, end - start)
            }
        }
    }

    private fun subtract(holes: List<LongRange>, range: LongRange): List<LongRange> {
        var pieces = listOf(range)
        for (hole in holes) {
            if (hole.first >= range.last || range.first >= hole.last) continue
            val next = ArrayList<LongRange>(pieces.size + 1)
            for (piece in pieces) {
                if (hole.first >= piece.last || piece.first >= hole.last) {
                    next.add(piece)
                    continue
                }
                if (piece.first < hole.first) next.add(piece.first until hole.first)
                if (hole.last < piece.last) next.add(hole.last until piece.last)
            }
            pieces = next
        }
        return pieces
    }

    private fun readHeader(io: BinaryIo): Header? {
        val probe = io.peekAt(0, 16) ?: return null
        val little = when {
            probe[0] == 0x49.toByte() && probe[1] == 0x49.toByte() -> true
            probe[0] == 0x4D.toByte() && probe[1] == 0x4D.toByte() -> false
            else -> return null
        }
        val magic = if (little) Bytes.u16le(probe, 2) else Bytes.u16be(probe, 2)
        return when (magic) {
            42 -> {
                val first = if (little) Bytes.u32le(probe, 4) else Bytes.u32be(probe, 4)
                if (first <= 0 || first + 2 > io.length) null else Header(little, false, first)
            }
            43 -> {
                val first = if (little) Bytes.u64le(probe, 8) else IsoBmffCore.readU64(probe, 8)
                if (first <= 0 || first + 8 > io.length) null else Header(little, true, first)
            }
            else -> null
        }
    }

    private fun readU16At(io: BinaryIo, offset: Long, little: Boolean): Int {
        if (offset < 0 || offset + 2 > io.length) return -1
        val b = io.peekAt(offset, 2) ?: return -1
        return if (little) Bytes.u16le(b, 0) else Bytes.u16be(b, 0)
    }

    private fun readU32At(io: BinaryIo, offset: Long, little: Boolean): Long {
        if (offset < 0 || offset + 4 > io.length) return -1L
        val b = io.peekAt(offset, 4) ?: return -1L
        return if (little) Bytes.u32le(b, 0) else Bytes.u32be(b, 0)
    }

    private fun readU64At(io: BinaryIo, offset: Long, little: Boolean): Long {
        if (offset < 0 || offset + 8 > io.length) return -1L
        val b = io.peekAt(offset, 8) ?: return -1L
        return if (little) Bytes.u64le(b, 0) else IsoBmffCore.readU64(b, 0)
    }

    private fun writeU16At(io: BinaryIo, offset: Long, value: Int, little: Boolean) {
        val low = (value and 0xFF).toByte()
        val high = ((value ushr 8) and 0xFF).toByte()
        io.writeAt(offset, if (little) byteArrayOf(low, high) else byteArrayOf(high, low))
    }

    private fun writeU32At(io: BinaryIo, offset: Long, value: Long, little: Boolean) {
        val b = ByteArray(4)
        Bytes.putU32le(b, 0, value)
        io.writeAt(offset, if (little) b else byteArrayOf(b[3], b[2], b[1], b[0]))
    }

    private fun writeU64At(io: BinaryIo, offset: Long, value: Long, little: Boolean) {
        val b = ByteArray(8)
        Bytes.putU64le(b, 0, value)
        if (little) io.writeAt(offset, b) else {
            val reversed = ByteArray(8)
            for (i in 0 until 8) reversed[i] = b[7 - i]
            io.writeAt(offset, reversed)
        }
    }

    private fun readEntryLong(io: BinaryIo, header: Header, entry: Entry): Long {
        return when {
            entry.inline -> when (entry.type) {
                3 -> readU16At(io, entry.valueFieldOffset, header.little).toLong()
                4 -> readU32At(io, entry.valueFieldOffset, header.little)
                1, 6, 7 -> (io.peekAt(entry.valueFieldOffset, 1)?.get(0)?.toInt()?.and(0xFF) ?: 0).toLong()
                else -> 0L
            }
            entry.type == 3 -> readU16At(io, entry.valueDataOffset, header.little).toLong()
            entry.type == 4 -> readU32At(io, entry.valueDataOffset, header.little)
            else -> entry.valueDataOffset
        }
    }

    private fun typeSize(type: Int): Long = when (type) {
        1, 2, 6, 7 -> 1L
        3, 8 -> 2L
        4, 9, 11 -> 4L
        5, 10, 12, 13, 16, 17, 18 -> 8L
        // Vendor defined types do occur in camera raw files. Measuring them as zero bytes would
        // make their values invisible to the scrubber, so assume the narrowest useful width.
        else -> 1L
    }

    private fun readIfd(io: BinaryIo, header: Header, offset: Long): Ifd? {
        if (offset <= 0 || offset >= io.length) return null
        val entrySize = if (header.bigTiff) 20 else 12
        val valueFieldSize = if (header.bigTiff) 8 else 4
        val countRaw = if (header.bigTiff) readU64At(io, offset, header.little)
        else readU16At(io, offset, header.little).toLong()
        if (countRaw <= 0 || countRaw > MAX_ENTRIES) return null
        val count = countRaw.toInt()
        val entriesStart = offset + if (header.bigTiff) 8 else 2
        if (entriesStart + count.toLong() * entrySize + valueFieldSize > io.length) return null
        val entries = ArrayList<Entry>(count)
        for (i in 0 until count) {
            val pos = entriesStart + i.toLong() * entrySize
            val tag = readU16At(io, pos, header.little)
            val type = readU16At(io, pos + 2, header.little)
            val valueCount = if (header.bigTiff) readU64At(io, pos + 4, header.little)
            else readU32At(io, pos + 4, header.little)
            if (tag < 0 || type < 0 || valueCount < 0) return null
            val valueFieldOffset = pos + 4 + (if (header.bigTiff) 8 else 4)
            val length = typeSize(type) * valueCount
            val inline = length in 1..valueFieldSize.toLong()
            val dataOffset = if (inline) valueFieldOffset else {
                if (header.bigTiff) readU64At(io, valueFieldOffset, header.little)
                else readU32At(io, valueFieldOffset, header.little)
            }
            entries.add(Entry(i, tag, type, valueCount, valueFieldOffset, dataOffset, length, inline))
        }
        val nextPointerOffset = entriesStart + count.toLong() * entrySize
        val nextIfd = if (header.bigTiff) readU64At(io, nextPointerOffset, header.little)
        else readU32At(io, nextPointerOffset, header.little)
        return Ifd(offset, entries, count, entrySize, nextPointerOffset, nextIfd)
    }

    private fun readIfdChain(io: BinaryIo, header: Header): List<Ifd> {
        val chain = ArrayList<Ifd>()
        var offset = header.firstIfd
        val visited = HashSet<Long>()
        while (offset > 0 && visited.add(offset) && chain.size < 16) {
            val ifd = readIfd(io, header, offset) ?: break
            chain.add(ifd)
            offset = ifd.nextIfd
        }
        return chain
    }

    private fun entryLongs(io: BinaryIo, header: Header, entry: Entry): LongArray? {
        val count = entry.count
        if (count <= 0 || count > 1_000_000) return null
        val width = when (entry.type) {
            3 -> 2L
            4 -> 4L
            16, 18 -> 8L
            else -> return null
        }
        val base = entry.valueDataOffset
        val total = count * width
        if (base < 0 || total <= 0 || base + total > io.length) return null
        val bytes = io.peekAt(base, total.toInt()) ?: return null
        val out = LongArray(count.toInt())
        for (i in out.indices) {
            val at = (i * width).toInt()
            out[i] = when (width) {
                2L -> (if (header.little) Bytes.u16le(bytes, at) else Bytes.u16be(bytes, at)).toLong()
                4L -> if (header.little) Bytes.u32le(bytes, at) else Bytes.u32be(bytes, at)
                else -> if (header.little) Bytes.u64le(bytes, at)
                else (Bytes.u32be(bytes, at) shl 32) or Bytes.u32be(bytes, at + 4)
            }
        }
        return out
    }

    private fun childIfds(io: BinaryIo, header: Header, ifd: Ifd): List<Ifd> {
        val children = ArrayList<Ifd>()
        for (entry in ifd.entries) {
            when (entry.tag) {
                TagTable.TAG_EXIF_IFD, TagTable.TAG_GPS_IFD, TAG_INTEROP_IFD -> {
                    val child = readIfd(io, header, readEntryLong(io, header, entry))
                    if (child != null) children.add(child)
                }
                TagTable.TAG_SUB_IFDS -> {
                    val offsets = entryLongs(io, header, entry) ?: continue
                    for (offset in offsets.take(64)) {
                        val child = readIfd(io, header, offset)
                        if (child != null) children.add(child)
                    }
                }
            }
        }
        return children
    }

    private fun referencedEnd(io: BinaryIo, header: Header, chain: List<Ifd>): Long? {
        val visited = HashSet<Long>()
        return referencedEnd(io, header, chain, visited, 0)
    }

    private fun referencedEnd(
        io: BinaryIo,
        header: Header,
        chain: List<Ifd>,
        visited: MutableSet<Long>,
        depth: Int
    ): Long? {
        if (depth > MAX_IFD_DEPTH) return null
        val pointerSize = if (header.bigTiff) 8L else 4L
        var end = 0L
        for (ifd in chain) {
            if (!visited.add(ifd.offset)) continue
            end = maxOf(end, ifd.nextPointerOffset + pointerSize)
            for (entry in ifd.entries) {
                if (entry.valueLength > 0) {
                    val stop = entry.valueDataOffset + entry.valueLength
                    if (entry.valueDataOffset < 0 || stop > io.length) return null
                    end = maxOf(end, stop)
                }
                val countsTag = when (entry.tag) {
                    TagTable.TAG_STRIP_OFFSETS -> TagTable.TAG_STRIP_BYTE_COUNTS
                    TagTable.TAG_TILE_OFFSETS -> TagTable.TAG_TILE_BYTE_COUNTS
                    TagTable.TAG_JPEG_INTERCHANGE_FORMAT -> TagTable.TAG_JPEG_INTERCHANGE_FORMAT_LENGTH
                    else -> -1
                }
                if (countsTag < 0) continue
                val lengths = ifd.entries.firstOrNull { it.tag == countsTag } ?: return null
                val offsets = entryLongs(io, header, entry) ?: return null
                val sizes = entryLongs(io, header, lengths) ?: return null
                if (offsets.isEmpty() || offsets.size != sizes.size) return null
                for (i in offsets.indices) {
                    val stop = offsets[i] + sizes[i]
                    if (offsets[i] < 0 || sizes[i] < 0 || stop > io.length) return null
                    end = maxOf(end, stop)
                }
            }
            for (child in childIfds(io, header, ifd)) {
                val sub = referencedEnd(io, header, listOf(child), visited, depth + 1) ?: return null
                end = maxOf(end, sub)
            }
        }
        return end
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                val header = readHeader(io)
                    ?: return listOf(MetadataFinding(MetadataKind.OTHER, "unparsable TIFF header"))
                val chain = readIfdChain(io, header)
                if (chain.isEmpty()) return listOf(MetadataFinding(MetadataKind.OTHER, "no IFD found"))
                val end = referencedEnd(io, header, chain)
                if (end != null && end > 0 && end < io.length) {
                    findings.add(MetadataFinding(MetadataKind.OTHER, "bytes after the last TIFF data block"))
                }
                for ((index, ifd) in chain.withIndex()) {
                    // Only a reduced resolution subfile is a thumbnail. A multi page TIFF keeps
                    // full resolution pages, and those pages carry metadata of their own.
                    if (index > 0 && isThumbnail(io, header, ifd)) {
                        if (options.stripEmbeddedThumbnails) {
                            findings.add(MetadataFinding(MetadataKind.THUMBNAIL, "subfile IFD $index"))
                        }
                    }
                    inspectIfd(io, header, ifd, "IFD$index", findings, options, 0)
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    private fun inspectIfd(
        io: BinaryIo,
        header: Header,
        ifd: Ifd,
        path: String,
        findings: MutableList<MetadataFinding>,
        options: PurgeOptions,
        depth: Int
    ) {
        if (depth > MAX_IFD_DEPTH) return
        for (entry in ifd.entries) {
            when (entry.tag) {
                TAG_GPS_IFD -> findings.add(MetadataFinding(MetadataKind.GPS, "$path GPS directory"))
                TAG_EXIF_IFD, TAG_INTEROP_IFD -> {
                    findings.add(MetadataFinding(MetadataKind.EXIF, "$path EXIF directory"))
                }
                TAG_SUB_IFDS -> {
                    if (options.stripEmbeddedThumbnails) {
                        val count = minOf(entry.count.toInt(), 32)
                        for (i in 0 until count) {
                            val at = if (entry.inline) entry.valueFieldOffset + i * 4L else entry.valueDataOffset + i * 4L
                            val child = readIfd(io, header, readU32At(io, at, header.little)) ?: continue
                            if (isReducedResolution(io, header, child)) {
                                findings.add(MetadataFinding(MetadataKind.THUMBNAIL, "$path subfile IFD"))
                            }
                            inspectIfd(io, header, child, "$path/sub", findings, options, depth + 1)
                        }
                    }
                }
                else -> {
                    val banned = TagTable.bannedKind(entry.tag)
                    if (banned != null) {
                        findings.add(MetadataFinding(banned, "$path ${TagTable.name(entry.tag)}"))
                    } else if (options.maximumPrivacy && !TagTable.isRenderEssential(entry.tag)) {
                        findings.add(
                            MetadataFinding(MetadataKind.OTHER, "$path non-essential tag ${TagTable.name(entry.tag)}")
                        )
                    }
                }
            }
        }
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val header = readHeader(io) ?: return false
                val chain = readIfdChain(io, header)
                if (chain.isEmpty()) return false
                val first = chain[0]
                if (first.entries.count {
                        it.tag == TagTable.TAG_STRIP_OFFSETS || it.tag == TagTable.TAG_TILE_OFFSETS || it.tag == TAG_JPEG_IF
                    } == 0) {
                    return false
                }
                val end = referencedEnd(io, header, chain) ?: return true
                end <= 0 || end >= io.length
            }
        } catch (_: Exception) {
            false
        }
    }
}
