package com.example.lock.metadata

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream

object Mp3Handler : FormatHandler {

    override val id: String = "mp3"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.MP3)

    private const val ID3V1_SIZE = 128L
    private const val MAX_ID3V2 = 256L * 1024 * 1024
    private const val APE_FOOTER_SIZE = 32L

    private data class Plan(val audioStart: Long, val audioEnd: Long, val removed: List<MetadataFinding>)

    private val bitrateV1L1 = intArrayOf(0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0)
    private val bitrateV1L2 = intArrayOf(0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0)
    private val bitrateV1L3 = intArrayOf(0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0)
    private val bitrateV2L1 = intArrayOf(0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0)
    private val bitrateV2L23 = intArrayOf(0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0)
    private val sampleRates = intArrayOf(44100, 48000, 32000, 0)

    private fun frameLength(header: ByteArray): Int {
        if (header.size < 4) return -1
        val b0 = header[0].toInt() and 0xFF
        val b1 = header[1].toInt() and 0xFF
        val b2 = header[2].toInt() and 0xFF
        if (b0 != 0xFF || (b1 and 0xE0) != 0xE0) return -1
        val versionBits = (b1 shr 3) and 0x03
        val layerBits = (b1 shr 1) and 0x03
        if (versionBits == 1 || layerBits == 0) return -1
        val version = when (versionBits) {
            0 -> 25
            2 -> 2
            3 -> 1
            else -> return -1
        }
        val layer = 4 - layerBits
        val bitrateIndex = (b2 shr 4) and 0x0F
        val sampleIndex = (b2 shr 2) and 0x03
        if (bitrateIndex == 0 || bitrateIndex == 15 || sampleIndex == 3) return -1
        val bitrate = when {
            version == 1 && layer == 1 -> bitrateV1L1[bitrateIndex]
            version == 1 && layer == 2 -> bitrateV1L2[bitrateIndex]
            version == 1 -> bitrateV1L3[bitrateIndex]
            layer == 1 -> bitrateV2L1[bitrateIndex]
            else -> bitrateV2L23[bitrateIndex]
        }
        if (bitrate <= 0) return -1
        val baseRate = if (version == 1) sampleRates[sampleIndex] else sampleRates[sampleIndex] / 2
        if (baseRate <= 0) return -1
        val padding = (b2 shr 1) and 0x01
        val samples = when {
            layer == 1 -> 384
            layer == 2 -> 1152
            version == 1 -> 1152
            else -> 576
        }
        val length = if (layer == 1) (12 * bitrate * 1000 / baseRate + padding) * 4
        else samples / 8 * bitrate * 1000 / baseRate + padding
        return if (length < 4) -1 else length
    }

    private fun audioEndOf(io: BinaryIo, start: Long, end: Long): Long {
        var cursor = start
        var frames = 0
        while (cursor + 4 <= end && frames < 2_000_000) {
            val header = io.peekAt(cursor, 4) ?: return cursor
            val length = frameLength(header)
            if (length < 0 || cursor + length > end) return cursor
            cursor += length.toLong()
            frames++
        }
        return if (frames > 0) cursor else start
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val plan = analyse(ctx.source)
            ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no MPEG audio frames found")
        if (plan.removed.isEmpty()) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no tags found")
        }
        val buffer = Buffers.new()
        BinaryIo.open(ctx.source).use { io ->
            FileOutputStream(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                io.copyRange(plan.audioStart, plan.audioEnd - plan.audioStart, out, buffer)
                out.tail()
                out.flush()
            }
        }
        return ScrubOutcome(true, PurgeStrategy.TAG_TABLE_REWRITE, plan.removed, emptyList(), true)
    }

    private fun analyse(file: File): Plan? {
        return try {
            BinaryIo.open(file).use { io ->
                val length = io.length
                if (length < 8) return null
                val removed = ArrayList<MetadataFinding>()

                var start = 0L
                var guard = 0
                while (guard++ < 32) {
                    val tag = readId3v2(io, start) ?: break
                    removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ID3v2.${tag.second} tag, ${tag.first} bytes"))
                    start += tag.first
                }

                var end = length
                guard = 0
                while (guard++ < 16) {
                    val next = detectTrailingBlock(io, end)
                    if (next == null) break
                    removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, next.second))
                    end = next.first
                }

                if (end <= start) return null

                val frameProbe = io.peekAt(start, 4)
                val looksLikeFrame = frameProbe != null && frameProbe.size >= 2 &&
                    (frameProbe[0].toInt() and 0xFF) == 0xFF && (frameProbe[1].toInt() and 0xE0) == 0xE0
                if (!looksLikeFrame && removed.isEmpty()) return null
                if (looksLikeFrame) {
                    val framesEnd = audioEndOf(io, start, end)
                    if (framesEnd in (start + 1) until end) {
                        removed.add(
                            MetadataFinding(
                                MetadataKind.OTHER,
                                "bytes after the last audio frame (${end - framesEnd} bytes)"
                            )
                        )
                        return Plan(start, framesEnd, removed)
                    }
                }
                Plan(start, end, removed)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun readId3v2(io: BinaryIo, offset: Long): Pair<Long, Int>? {
        if (offset + 10 > io.length) return null
        val header = io.peekAt(offset, 10) ?: return null
        if (header[0] != 0x49.toByte() || header[1] != 0x44.toByte() || header[2] != 0x33.toByte()) return null
        val major = header[3].toInt() and 0xFF
        val flags = header[5].toInt() and 0xFF
        val size = ((header[6].toInt() and 0x7F) shl 21) or ((header[7].toInt() and 0x7F) shl 14) or
            ((header[8].toInt() and 0x7F) shl 7) or (header[9].toInt() and 0x7F)
        var total = 10L + size
        if (flags and 0x10 != 0) total += 10
        if (total < 10 || total > MAX_ID3V2 || offset + total > io.length) return null
        return Pair(total, major)
    }

    private fun detectTrailingBlock(io: BinaryIo, end: Long): Pair<Long, String>? {
        if (end < ID3V1_SIZE) return null

        val id3v1 = io.peekAt(end - ID3V1_SIZE, 3)
        if (id3v1 != null && id3v1[0] == 0x54.toByte() && id3v1[1] == 0x41.toByte() && id3v1[2] == 0x47.toByte()) {
            return Pair(end - ID3V1_SIZE, "ID3v1 tag")
        }

        if (end >= APE_FOOTER_SIZE) {
            val footer = io.peekAt(end - APE_FOOTER_SIZE, APE_FOOTER_SIZE.toInt())
            if (footer != null && String(footer, 0, 8, Charsets.US_ASCII) == "APETAGEX") {
                val size = com.example.lock.metadata.Bytes.u32le(footer, 12)
                val flags = com.example.lock.metadata.Bytes.u32le(footer, 20)
                var total = size
                if (flags and (1L shl 31) != 0L) total += APE_FOOTER_SIZE
                if (total > 0 && end - total >= 0) return Pair(end - total, "APEv2 tag")
            }
        }

        if (end >= 15) {
            val tail = io.peekAt(end - 15, 15)
            if (tail != null && String(tail, 6, 9, Charsets.US_ASCII) == "LYRICS200") {
                val sizeText = String(tail, 0, 6, Charsets.US_ASCII).trim()
                val size = sizeText.toLongOrNull()
                if (size != null && size > 0) {
                    val total = size + 15
                    val begin = io.peekAt(end - total, 11)
                    if (begin != null && String(begin, Charsets.US_ASCII).startsWith("LYRICSBEGIN")) {
                        return Pair(end - total, "Lyrics3 tag")
                    }
                }
            }
        }
        return null
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val plan = analyse(file) ?: return listOf(MetadataFinding(MetadataKind.OTHER, "no MPEG audio structure found"))
        val findings = ArrayList(plan.removed)
        try {
            BinaryIo.open(file).use { io ->
                val detail = readId3v2Frames(io, 0L)
                findings.addAll(detail)
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    private fun readId3v2Frames(io: BinaryIo, offset: Long): List<MetadataFinding> {
        val header = io.peekAt(offset, 10) ?: return emptyList()
        if (header[0] != 0x49.toByte() || header[1] != 0x44.toByte() || header[2] != 0x33.toByte()) return emptyList()
        val major = header[3].toInt() and 0xFF
        val size = ((header[6].toInt() and 0x7F) shl 21) or ((header[7].toInt() and 0x7F) shl 14) or
            ((header[8].toInt() and 0x7F) shl 7) or (header[9].toInt() and 0x7F)
        val body = io.peekAt(offset + 10, minOf(size, 1 shl 20)) ?: return emptyList()
        val findings = ArrayList<MetadataFinding>()
        var pos = 0
        var guard = 0
        val headerSize = if (major == 2) 6 else 10
        while (pos + headerSize <= body.size && guard++ < 256) {
            val id = String(body, pos, if (major == 2) 3 else 4, Charsets.US_ASCII)
            if (id.isEmpty() || id[0].code == 0) break
            val frameSize = if (major == 2) {
                ((body[pos + 3].toInt() and 0xFF) shl 16) or ((body[pos + 4].toInt() and 0xFF) shl 8) or (body[pos + 5].toInt() and 0xFF)
            } else if (major == 4) {
                ((body[pos + 4].toInt() and 0x7F) shl 21) or ((body[pos + 5].toInt() and 0x7F) shl 14) or
                    ((body[pos + 6].toInt() and 0x7F) shl 7) or (body[pos + 7].toInt() and 0x7F)
            } else {
                ((body[pos + 4].toInt() and 0xFF) shl 24) or ((body[pos + 5].toInt() and 0xFF) shl 16) or
                    ((body[pos + 6].toInt() and 0xFF) shl 8) or (body[pos + 7].toInt() and 0xFF)
            }
            if (frameSize <= 0) break
            val kind = when {
                id == "APIC" || id == "PIC" -> MetadataKind.THUMBNAIL
                id == "PRIV" -> MetadataKind.UNIQUE_ID
                id == "GEOB" || id == "MCDI" -> MetadataKind.EMBEDDED_FILE
                id == "COMM" || id == "USLT" || id == "ULT" -> MetadataKind.COMMENT
                id == "TXXX" || id == "TXX" -> MetadataKind.OTHER
                id.startsWith("TPE") || id.startsWith("TCOM") || id == "TOPE" -> MetadataKind.AUTHOR
                id.startsWith("TDR") || id.startsWith("TDAT") || id == "TYER" -> MetadataKind.TIMESTAMP
                id == "TENC" || id.startsWith("TS") || id == "TSS" -> MetadataKind.SOFTWARE
                id == "WXXX" || id == "WXX" -> MetadataKind.OTHER
                id.startsWith("UFID") || id == "UFI" -> MetadataKind.UNIQUE_ID
                id.startsWith("T") || id.startsWith("W") -> MetadataKind.AUDIO_TAGS
                else -> MetadataKind.AUDIO_TAGS
            }
            findings.add(MetadataFinding(kind, "ID3 frame $id"))
            pos += headerSize + frameSize
        }
        return findings
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val probe = io.peekAt(0, 2) ?: return false
                val sync = (probe[0].toInt() and 0xFF) == 0xFF && (probe[1].toInt() and 0xE0) == 0xE0
                if (!sync) return false
                val plan = analyse(file) ?: return false
                plan.audioEnd > plan.audioStart + 4
            }
        } catch (_: Exception) {
            false
        }
    }
}

object FlacHandler : FormatHandler {

    override val id: String = "flac"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.FLAC)

    private const val BLOCK_STREAMINFO = 0
    private const val BLOCK_PADDING = 1
    private const val BLOCK_APPLICATION = 2
    private const val BLOCK_SEEKTABLE = 3
    private const val BLOCK_VORBIS_COMMENT = 4
    private const val BLOCK_CUESHEET = 5
    private const val BLOCK_PICTURE = 6

    private class Block(val type: Int, val isLast: Boolean, val start: Long, val total: Long, val payload: Long)

    private fun readBlocks(io: BinaryIo): List<Block>? {
        if (io.length < 8) return null
        val magic = io.peekAt(0, 4) ?: return null
        if (!String(magic, Charsets.US_ASCII).startsWith("fLaC")) return null
        val blocks = ArrayList<Block>()
        var pos = 4L
        var guard = 0
        while (pos + 4 <= io.length && guard++ < 512) {
            val head = io.peekAt(pos, 4) ?: return null
            val isLast = (head[0].toInt() and 0x80) != 0
            val type = head[0].toInt() and 0x7F
            val size = ((head[1].toInt() and 0xFF) shl 16) or ((head[2].toInt() and 0xFF) shl 8) or (head[3].toInt() and 0xFF)
            val total = 4L + size
            if (pos + total > io.length) return null
            blocks.add(Block(type, isLast, pos, total, size.toLong()))
            pos += total
            if (isLast) break
        }
        if (blocks.isEmpty()) return null
        return blocks
    }

    private fun keep(type: Int, options: PurgeOptions): Boolean = when (type) {
        BLOCK_STREAMINFO -> true
        BLOCK_SEEKTABLE -> true
        BLOCK_PICTURE -> !options.stripEmbeddedThumbnails
        else -> false
    }

    private fun kindOf(type: Int): MetadataKind = when (type) {
        BLOCK_PADDING -> MetadataKind.OTHER
        BLOCK_APPLICATION -> MetadataKind.EMBEDDED_FILE
        BLOCK_VORBIS_COMMENT -> MetadataKind.AUDIO_TAGS
        BLOCK_CUESHEET -> MetadataKind.AUDIO_TAGS
        BLOCK_PICTURE -> MetadataKind.THUMBNAIL
        else -> MetadataKind.AUDIO_TAGS
    }

    private fun nameOf(type: Int): String = when (type) {
        BLOCK_PADDING -> "PADDING"
        BLOCK_APPLICATION -> "APPLICATION"
        BLOCK_VORBIS_COMMENT -> "VORBIS_COMMENT"
        BLOCK_CUESHEET -> "CUESHEET"
        BLOCK_PICTURE -> "PICTURE"
        else -> "block $type"
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val buffer = Buffers.new()
        val removed = ArrayList<MetadataFinding>()
        BinaryIo.open(ctx.source).use { io ->
            val blocks = readBlocks(io)
                ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a FLAC stream")
            if (blocks[0].type != BLOCK_STREAMINFO) {
                return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "FLAC without STREAMINFO")
            }
            val kept = blocks.filter { keep(it.type, ctx.options) }
            if (kept.size == blocks.size) {
                return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable blocks")
            }
            for (block in blocks) {
                if (keep(block.type, ctx.options)) continue
                removed.add(MetadataFinding(kindOf(block.type), "FLAC ${nameOf(block.type)} block"))
            }
            FileOutputStream(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                out.write("fLaC".toByteArray(Charsets.US_ASCII))
                for ((index, block) in kept.withIndex()) {
                    ctx.checkCancelled()
                    val header = ByteArray(4)
                    val last = index == kept.size - 1
                    header[0] = ((if (last) 0x80 else 0) or block.type).toByte()
                    header[1] = ((block.payload shr 16) and 0xFF).toByte()
                    header[2] = ((block.payload shr 8) and 0xFF).toByte()
                    header[3] = (block.payload and 0xFF).toByte()
                    out.write(header)
                    io.copyRange(block.start + 4, block.payload, out, buffer)
                }
                val audioStart = blocks.last().start + blocks.last().total
                io.copyRange(audioStart, io.length - audioStart, out, buffer)
                out.tail()
                out.flush()
            }
        }
        return ScrubOutcome(true, PurgeStrategy.TAG_TABLE_REWRITE, removed, emptyList(), true)
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        return try {
            BinaryIo.open(file).use { io ->
                val blocks = readBlocks(io) ?: return listOf(
                    MetadataFinding(MetadataKind.OTHER, "not a FLAC stream")
                )
                val findings = ArrayList<MetadataFinding>()
                for (block in blocks) {
                    when (block.type) {
                        BLOCK_VORBIS_COMMENT -> {
                            findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "FLAC VORBIS_COMMENT block"))
                            findings.addAll(readVorbisComment(io, block))
                        }
                        BLOCK_PICTURE -> if (options.stripEmbeddedThumbnails) {
                            findings.add(MetadataFinding(MetadataKind.THUMBNAIL, "FLAC PICTURE block"))
                        }
                        BLOCK_CUESHEET -> findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "FLAC CUESHEET block"))
                        BLOCK_APPLICATION -> findings.add(MetadataFinding(MetadataKind.EMBEDDED_FILE, "FLAC APPLICATION block"))
                        BLOCK_PADDING -> findings.add(MetadataFinding(MetadataKind.OTHER, "FLAC padding block"))
                        BLOCK_STREAMINFO, BLOCK_SEEKTABLE -> {
                        }
                        else -> findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "FLAC ${nameOf(block.type)}"))
                    }
                }
                findings
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun readVorbisComment(io: BinaryIo, block: Block): List<MetadataFinding> {
        val size = minOf(block.payload, 64L * 1024).toInt()
        val data = io.peekAt(block.start + 4, size) ?: return emptyList()
        val findings = ArrayList<MetadataFinding>()
        var pos = 0
        if (pos + 4 > data.size) return findings
        val vendorLength = Bytes.u32le(data, pos)
        pos += 4
        if (vendorLength > 0 && pos + vendorLength <= data.size) {
            val vendor = String(data, pos, vendorLength.toInt(), Charsets.UTF_8)
            findings.add(MetadataFinding(MetadataKind.SOFTWARE, "FLAC vendor string: ${vendor.take(40)}"))
            pos += vendorLength.toInt()
        }
        if (pos + 4 > data.size) return findings
        val count = Bytes.u32le(data, pos)
        pos += 4
        var guard = 0
        while (guard++ < count && pos + 4 <= data.size) {
            val length = Bytes.u32le(data, pos)
            pos += 4
            if (length <= 0 || pos + length > data.size) break
            val entry = String(data, pos, length.toInt(), Charsets.UTF_8)
            val field = entry.substringBefore('=').uppercase()
            val kind = when (field) {
                "ARTIST", "ALBUMARTIST", "COMPOSER", "PERFORMER", "LYRICIST", "CONDUCTOR" -> MetadataKind.AUTHOR
                "DATE", "YEAR" -> MetadataKind.TIMESTAMP
                "ENCODER", "ENCODED-BY" -> MetadataKind.SOFTWARE
                "COMMENT", "DESCRIPTION" -> MetadataKind.COMMENT
                "LOCATION", "GPS", "LATITUDE", "LONGITUDE" -> MetadataKind.GPS
                else -> MetadataKind.AUDIO_TAGS
            }
            findings.add(MetadataFinding(kind, "FLAC tag $field"))
            pos += length.toInt()
        }
        return findings
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val blocks = readBlocks(io) ?: return false
                if (blocks.isEmpty() || blocks[0].type != BLOCK_STREAMINFO) return false
                val kept = blocks.filter { keep(it.type, options) }
                if (kept.isEmpty()) return false
                val audioStart = blocks.last().start + blocks.last().total
                audioStart <= io.length
            }
        } catch (_: Exception) {
            false
        }
    }
}

object AacHandler : FormatHandler {

    override val id: String = "aac"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.AAC)

    private const val FLAG_MASK = 0x3C

    private data class AdtsFrame(val start: Long, val size: Int)

    private fun id3v2Size(io: BinaryIo, offset: Long): Long {
        val head = io.peekAt(offset, 10) ?: return 0L
        if (head[0] != 'I'.code.toByte() || head[1] != 'D'.code.toByte() || head[2] != '3'.code.toByte()) return 0L
        val flags = head[5].toInt() and 0xFF
        val size = ((head[6].toInt() and 0x7F) shl 21) or ((head[7].toInt() and 0x7F) shl 14) or
            ((head[8].toInt() and 0x7F) shl 7) or (head[9].toInt() and 0x7F)
        var total = 10L + size
        if (flags and 0x10 != 0) total += 10L
        return total
    }

    private fun isAdif(io: BinaryIo, offset: Long): Boolean {
        val head = io.peekAt(offset, 4) ?: return false
        return Bytes.asciiAt(head, 0, 4) == "ADIF"
    }

    private fun adtsFrames(io: BinaryIo, start: Long, end: Long): List<AdtsFrame> {
        val frames = ArrayList<AdtsFrame>()
        var cursor = start
        while (cursor + 7L <= end) {
            val head = io.peekAt(cursor, 9) ?: break
            if ((head[0].toInt() and 0xFF) != 0xFF || (head[1].toInt() and 0xF0) != 0xF0) break
            if (((head[1].toInt() shr 1) and 0x03) != 0) break
            val frameLength = ((head[3].toInt() and 0x03) shl 11) or ((head[4].toInt() and 0xFF) shl 3) or
                ((head[5].toInt() and 0xE0) shr 5)
            if (frameLength < 7 || !io.inRange(cursor, frameLength.toLong())) break
            if (cursor + frameLength > end) break
            frames.add(AdtsFrame(cursor, frameLength))
            cursor += frameLength.toLong()
        }
        return frames
    }

    private fun flagBits(io: BinaryIo, frame: AdtsFrame): Int {
        val byte = io.peekAt(frame.start + 3L, 1) ?: return 0
        return byte[0].toInt() and 0xFF
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                val length = io.length
                val prefix = id3v2Size(io, 0L)
                if (prefix > 0L) findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ID3v2 block"))
                if (isAdif(io, prefix)) {
                    val head = io.peekAt(prefix, 16) ?: return findings
                    val flags = head[4].toInt() and 0xFF
                    if (flags and 0x80 != 0) {
                        val idBits = flags and 0x7F
                        val idTail = (head[13].toInt() and 0x80) != 0
                        var idBytes = false
                        for (i in 5 until 13) if (head[i].toInt() != 0) idBytes = true
                        if (idBits != 0 || idBytes || idTail) {
                            findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ADIF copyright identifier"))
                        }
                        if ((head[13].toInt() and 0x40) != 0) {
                            findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ADIF original copy flag"))
                        }
                        if ((head[13].toInt() and 0x20) != 0) {
                            findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ADIF home flag"))
                        }
                    } else {
                        if (flags and 0x40 != 0) {
                            findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ADIF original copy flag"))
                        }
                        if (flags and 0x20 != 0) {
                            findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ADIF home flag"))
                        }
                    }
                    return findings.distinct()
                }
                val frames = adtsFrames(io, prefix, length)
                if (frames.isEmpty()) return findings
                var flagged = 0
                for (frame in frames) if (flagBits(io, frame) and FLAG_MASK != 0) flagged++
                if (flagged > 0) {
                    findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "copyright flags in $flagged frame headers"))
                }
                val last = frames.last()
                if (last.start + last.size.toLong() < length) {
                    findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "trailing tag data"))
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
                val length = io.length
                val prefix = id3v2Size(io, 0L)
                if (prefix > 0L) removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ID3v2 block"))
                if (isAdif(io, prefix)) {
                    val head = io.peekAt(prefix, 16)
                        ?: return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "unreadable ADIF header")
                    val flags = head[4].toInt() and 0xFF
                    val patched = head.copyOf(16)
                    var touched = false
                    // ISO/IEC 13818-7 ADIF layout, byte 4 onward:
                    //   bit7 = copyright_id_present; when set, a 72-bit copyright id is stored
                    //   INLINE (byte4 bits6-0 + bytes 5-12 + byte13 bit7). Bytes 5-12 are part
                    //   of that id, not bitrate. The 23-bit bitrate and the buffer fullness
                    //   fields follow at byte13 bit4 onward and are never touched here: only
                    //   the copyright id, original_copy and home flags are patched.
                    if (flags and 0x80 != 0) {
                        var idPresent = flags and 0x7F != 0 || (head[13].toInt() and 0x80) != 0
                        for (i in 5 until 13) if (head[i].toInt() != 0) idPresent = true
                        if (idPresent) {
                            // Clear the id bits that live in byte4 (0x7F) while keeping the
                            // present bit so the inline header keeps its fixed layout, then
                            // zero the remaining id bytes. Bitrate/fullness stay intact.
                            patched[4] = (patched[4].toInt() and 0x80).toByte()
                            for (i in 5 until 13) patched[i] = 0
                            patched[13] = (patched[13].toInt() and 0x7F).toByte()
                            touched = true
                            removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ADIF copyright identifier"))
                        }
                        if ((patched[13].toInt() and 0x40) != 0) {
                            patched[13] = (patched[13].toInt() and 0xBF).toByte()
                            touched = true
                            removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ADIF original copy flag"))
                        }
                        if ((patched[13].toInt() and 0x20) != 0) {
                            patched[13] = (patched[13].toInt() and 0xDF).toByte()
                            touched = true
                            removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ADIF home flag"))
                        }
                    } else {
                        // Without an inline id, original_copy (0x40) and home (0x20) sit
                        // directly in byte4 next to bitstream_type and the bitrate field:
                        // clear only those two flag bits, leave the rest of byte4 alone.
                        if (patched[4].toInt() and 0x40 != 0) {
                            patched[4] = (patched[4].toInt() and 0xBF).toByte()
                            touched = true
                            removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ADIF original copy flag"))
                        }
                        if (patched[4].toInt() and 0x20 != 0) {
                            patched[4] = (patched[4].toInt() and 0xDF).toByte()
                            touched = true
                            removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "ADIF home flag"))
                        }
                    }
                    if (!touched) {
                        if (prefix == 0L) {
                            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable markers")
                        }
                        FileOutputStream(ctx.target).use { fileOut ->
                            val out = ProgressOut(fileOut, ctx)
                            io.copyRange(prefix, length - prefix, out, buffer)
                            out.tail()
                            out.flush()
                        }
                        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
                    }
                    FileOutputStream(ctx.target).use { fileOut ->
                        val out = ProgressOut(fileOut, ctx)
                        out.write(patched)
                        io.copyRange(prefix + 16L, length - prefix - 16L, out, buffer)
                        out.tail()
                        out.flush()
                    }
                    return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
                }
                val frames = adtsFrames(io, prefix, length)
                if (frames.isEmpty()) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "not a parsable ADTS stream")
                }
                val last = frames.last()
                val bodyEnd = last.start + last.size.toLong()
                if (bodyEnd < length) removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "trailing tag data"))
                var flagged = 0
                FileOutputStream(ctx.target).use { fileOut ->
                    val out = ProgressOut(fileOut, ctx)
                    for (frame in frames) {
                        ctx.checkCancelled()
                        val bytes = ByteArray(frame.size)
                        io.seek(frame.start)
                        if (!io.readFully(bytes)) {
                            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "truncated ADTS frame")
                        }
                        val value = bytes[3].toInt() and 0xFF
                        if (value and FLAG_MASK != 0) {
                            bytes[3] = (value and FLAG_MASK.inv()).toByte()
                            flagged++
                        }
                        out.write(bytes)
                    }
                    out.tail()
                    out.flush()
                }
                if (flagged > 0) {
                    removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "copyright flags in $flagged frame headers"))
                }
            }
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "aac rewrite failed")
        }
        if (removed.isEmpty()) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable markers")
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val prefix = id3v2Size(io, 0L)
                if (isAdif(io, prefix)) return true
                val frames = adtsFrames(io, prefix, io.length)
                if (frames.isEmpty()) return false
                val last = frames.last()
                if (last.start + last.size.toLong() != io.length) return false
                for (frame in frames) {
                    if (flagBits(io, frame) and FLAG_MASK != 0) return false
                }
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}


object RiffHandler : FormatHandler {

    override val id: String = "riff"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.WAV, MediaFormat.AVI)

    private class Chunk(val id: String, val listType: String, val start: Long, val payload: Long, val total: Long)

    private val dropIds = setOf("JUNK", "PAD ", "id3 ", "ID3 ", "bext", "iXML", "axml", "XMP ", "exif", "_PMX")

    /** OpenDML super index chunks hold absolute file offsets, which a rewrite invalidates. */
    private fun isSuperIndex(id: String): Boolean =
        id.length == 4 && id[0] == 'i' && id[1] == 'x' && id[2].isDigit() && id[3].isDigit()

    private fun readChunks(io: BinaryIo): List<Chunk>? {
        if (io.length < 12) return null
        val header = io.peekAt(0, 12) ?: return null
        val riff = String(header, 0, 4, Charsets.US_ASCII)
        val form = String(header, 8, 4, Charsets.US_ASCII)
        if ((riff != "RIFF" && riff != "RF64") || (form != "WAVE" && form != "AVI " && form != "AVIX")) return null
        val chunks = ArrayList<Chunk>()
        val declared = Bytes.u32le(header, 4) + 8L
        val containerEnd = if (declared in 12L..io.length) declared else io.length
        var pos = 12L
        var guard = 0
        while (pos + 8 <= containerEnd && guard++ < 200_000) {
            val head = io.peekAt(pos, 8) ?: return null
            val id = String(head, 0, 4, Charsets.US_ASCII)
            val size = Bytes.u32le(head, 4)
            if (size < 0 || pos + 8 + size > io.length) return null
            if (pos + 8 + size > containerEnd) break
            val listType = if (id == "LIST" || id == "RIFF") {
                io.peekAt(pos + 8, 4)?.let { String(it, Charsets.US_ASCII) } ?: ""
            } else ""
            val padded = size + (size and 1L)
            chunks.add(Chunk(id, listType, pos, size, 8 + padded))
            pos += 8 + padded
        }
        if (chunks.isEmpty()) return null
        return chunks
    }

    private fun kindOf(chunk: Chunk): MetadataKind = when {
        chunk.id == "LIST" && chunk.listType == "INFO" -> MetadataKind.AUDIO_TAGS
        isSuperIndex(chunk.id) -> MetadataKind.OTHER
        chunk.id == "_PMX" -> MetadataKind.XMP
        chunk.id == "bext" -> MetadataKind.TIMESTAMP
        chunk.id == "iXML" || chunk.id == "axml" -> MetadataKind.TIMESTAMP
        chunk.id.startsWith("id3") || chunk.id.startsWith("ID3") -> MetadataKind.AUDIO_TAGS
        chunk.id == "XMP " -> MetadataKind.XMP
        chunk.id == "exif" -> MetadataKind.EXIF
        else -> MetadataKind.OTHER
    }

    private fun droppable(chunk: Chunk): Boolean = when {
        chunk.id == "LIST" && (chunk.listType == "INFO" || chunk.listType == "exif") -> true
        dropIds.contains(chunk.id) -> true
        else -> false
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val buffer = Buffers.new()
        val removed = ArrayList<MetadataFinding>()
        BinaryIo.open(ctx.source).use { io ->
            val chunks = readChunks(io)
                ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a RIFF container")
            val hasSuperIndex = chunks.any { isSuperIndex(it.id) }
            val anyDropped = chunks.any { droppable(it) }
            val kept = chunks.filter { !droppable(it) && !(hasSuperIndex && anyDropped && isSuperIndex(it.id)) }
            val containerEnd = chunks.last().start + chunks.last().total
            val trailing = containerEnd < io.length
            if (kept.size == chunks.size && !trailing) {
                return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable chunks")
            }
            val bodySize = kept.sumOf { it.total } + 4
            if (bodySize - 4 > 0xFFFFFFFFL) {
                return ScrubOutcome(
                    false, PurgeStrategy.NONE, emptyList(),
                    message = "RF64 container still exceeds 4 GiB after the rewrite; refusing to truncate its size field"
                )
            }
            for (chunk in chunks) {
                if (droppable(chunk)) {
                    removed.add(MetadataFinding(kindOf(chunk), "RIFF ${chunk.id}${if (chunk.listType.isEmpty()) "" else " ${chunk.listType}"} chunk"))
                } else if (hasSuperIndex && anyDropped && isSuperIndex(chunk.id)) {
                    removed.add(MetadataFinding(MetadataKind.OTHER, "RIFF ${chunk.id} OpenDML super index"))
                }
            }
            if (trailing) {
                removed.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the RIFF container"))
            }
            val form = io.peekAt(8, 4) ?: byteArrayOf('W'.code.toByte(), 'A'.code.toByte(), 'V'.code.toByte(), 'E'.code.toByte())
            FileOutputStream(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                val header = ByteArray(12)
                System.arraycopy("RIFF".toByteArray(Charsets.US_ASCII), 0, header, 0, 4)
                Bytes.putU32le(header, 4, bodySize)
                System.arraycopy(form, 0, header, 8, 4)
                out.write(header)
                for (chunk in kept) {
                    ctx.checkCancelled()
                    io.copyRange(chunk.start, chunk.total, out, buffer)
                }
                out.tail()
                out.flush()
            }
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed, emptyList(), true)
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        return try {
            BinaryIo.open(file).use { io ->
                val chunks = readChunks(io) ?: return listOf(MetadataFinding(MetadataKind.OTHER, "not a RIFF container"))
                val findings = ArrayList<MetadataFinding>()
                val containerEnd = chunks.last().start + chunks.last().total
                if (containerEnd < io.length) {
                    findings.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the RIFF container"))
                }
                for (chunk in chunks) {
                    if (!droppable(chunk)) continue
                    findings.add(MetadataFinding(kindOf(chunk), "RIFF ${chunk.id}${if (chunk.listType.isEmpty()) "" else " ${chunk.listType}"} chunk"))
                    if (chunk.id == "LIST" && chunk.listType == "INFO") {
                        findings.addAll(readInfoChunk(io, chunk))
                    }
                }
                findings
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun readInfoChunk(io: BinaryIo, chunk: Chunk): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        var pos = chunk.start + 12
        val end = chunk.start + 8 + chunk.payload
        var guard = 0
        while (pos + 8 <= end && guard++ < 256) {
            val head = io.peekAt(pos, 8) ?: break
            val id = String(head, 0, 4, Charsets.US_ASCII)
            val size = Bytes.u32le(head, 4)
            if (size <= 0 || pos + 8 + size > end) break
            val kind = when (id) {
                "ISFT", "IENC", "IDPI", "ISHP", "ILGT" -> MetadataKind.SOFTWARE
                "ICMT" -> MetadataKind.COMMENT
                "ICRD", "IDIT", "ISMP", "ITIM" -> MetadataKind.TIMESTAMP
                "IART", "IPRD", "IENG", "ITCH", "ICMS", "ICOP", "IPRT" -> MetadataKind.AUTHOR
                else -> MetadataKind.AUDIO_TAGS
            }
            findings.add(MetadataFinding(kind, "RIFF INFO $id"))
            pos += 8 + size + (size and 1L)
        }
        return findings
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val chunks = readChunks(io) ?: return false
                if (chunks.isEmpty()) return false
                val ids = chunks.map { it.id }
                when {
                    ids.contains("data") -> ids.contains("fmt ")
                    ids.contains("movi") || chunks.any { it.id == "LIST" && it.listType == "movi" } -> true
                    else -> ids.contains("idx1") || ids.contains("hdrl")
                }
            }
        } catch (_: Exception) {
            false
        }
    }
}

object OggHandler : FormatHandler {

    override val id: String = "ogg"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.OGG)

    private const val MAX_PAGE_DATA = 255 * 255

    private class Page(
        val start: Long,
        val total: Long,
        val serial: Long,
        val seq: Long,
        val headerType: Int,
        val granule: Long,
        val segments: List<Int>,
        val dataStart: Long,
        val ordinal: Int
    )

    /** [headerPageCount] counts pages of this logical stream that carry the header packets. */
    private class Headers(
        val packets: List<ByteArray>,
        val headerPageCount: Int,
        val codec: String
    )

    /** One logical stream prepared for rewrite, or knowingly left in place. */
    private class StreamPlan(
        val serial: Long,
        val headerPageCount: Int,
        val rebuilt: List<ByteArray>,
        val delta: Int,
        val removed: List<MetadataFinding>,
        val retained: List<MetadataFinding>
    )

    private fun parsePages(io: BinaryIo): List<Page>? {
        val pages = ArrayList<Page>()
        val ordinals = HashMap<Long, Int>()
        var pos = 0L
        var guard = 0
        while (pos + 27 <= io.length && guard++ < 5_000_000) {
            val head = io.peekAt(pos, 27) ?: return if (pages.isEmpty()) null else pages
            if (head[0] != 'O'.code.toByte() || head[1] != 'g'.code.toByte() ||
                head[2] != 'g'.code.toByte() || head[3] != 'S'.code.toByte()
            ) {
                break
            }
            val headerType = head[5].toInt() and 0xFF
            val granule = Bytes.u64le(head, 6)
            val serial = Bytes.u32le(head, 14)
            val seq = Bytes.u32le(head, 18)
            val count = head[26].toInt() and 0xFF
            val tableAt = pos + 27
            val table = io.peekAt(tableAt, count) ?: return pages
            var dataLen = 0
            val segments = ArrayList<Int>(count)
            for (i in 0 until count) {
                val size = table[i].toInt() and 0xFF
                segments.add(size)
                dataLen += size
            }
            val dataStart = tableAt + count
            if (dataStart + dataLen > io.length) break
            val ordinal = ordinals.getOrDefault(serial, 0)
            ordinals[serial] = ordinal + 1
            pages.add(Page(pos, 27L + count + dataLen, serial, seq, headerType, granule, segments, dataStart, ordinal))
            pos += 27L + count + dataLen
        }
        return if (pages.isEmpty()) null else pages
    }

    private fun serialsOf(pages: List<Page>): List<Long> {
        val seen = LinkedHashSet<Long>()
        for (page in pages) seen.add(page.serial)
        return seen.toList()
    }

    private fun collectHeaders(io: BinaryIo, pages: List<Page>, serial: Long): Headers? {
        val packets = ArrayList<ByteArray>()
        var current = java.io.ByteArrayOutputStream()
        var codec: String? = null
        var needed = 0
        var serialPages = 0
        for (page in pages) {
            if (page.serial != serial) continue
            serialPages++
            if (needed > 0 && packets.size >= needed) {
                serialPages--
                break
            }
            var offset = page.dataStart
            for (size in page.segments) {
                if (size > 0) {
                    val chunk = io.peekAt(offset, size) ?: return null
                    current.write(chunk)
                }
                offset += size
                if (size < 255) {
                    packets.add(current.toByteArray())
                    current = java.io.ByteArrayOutputStream()
                    if (codec == null) {
                        codec = codecOf(packets[0]) ?: return null
                        needed = headerPacketCount(codec)
                    }
                    if (packets.size >= needed) return Headers(packets, serialPages, codec)
                }
            }
        }
        return null
    }

    private fun codecOf(first: ByteArray): String? {
        if (first.size >= 7 && first[0] == 0x01.toByte() && String(first, 1, 6, Charsets.US_ASCII) == "vorbis") return "vorbis"
        if (first.size >= 8 && String(first, 0, 8, Charsets.US_ASCII) == "OpusHead") return "opus"
        if (first.size >= 7 && first[0] == 0x80.toByte() && String(first, 1, 6, Charsets.US_ASCII) == "theora") return "theora"
        return null
    }

    private fun headerPacketCount(codec: String): Int = when (codec) {
        "vorbis", "theora" -> 3
        else -> 2
    }

    private fun commentPrefix(codec: String): Int = if (codec == "opus") 8 else 7

    /**
     * Findings for one logical stream. Both inspect() and scrub() call this so the residual
     * contract for a stream that is knowingly retained can never drift from what verification
     * will later report.
     */
    private fun streamFindings(io: BinaryIo, serial: Long, headers: Headers?): List<MetadataFinding> {
        if (headers == null) {
            return listOf(MetadataFinding(MetadataKind.OTHER, "Ogg logical stream $serial: unparsable header packets"))
        }
        val comment = headers.packets.getOrNull(1) ?: return listOf(
            MetadataFinding(MetadataKind.OTHER, "Ogg logical stream $serial: missing comment header")
        )
        if (isCommentEmpty(headers.codec, comment)) return emptyList()
        val findings = ArrayList<MetadataFinding>()
        findings.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "${headers.codec} comment header"))
        readVendor(headers.codec, comment)?.let {
            if (it.isNotEmpty()) findings.add(MetadataFinding(MetadataKind.SOFTWARE, "${headers.codec} vendor: ${it.take(48)}"))
        }
        findings.addAll(readComments(headers.codec, comment))
        return findings
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val buffer = Buffers.new()
        BinaryIo.open(ctx.source).use { io ->
            val pages = parsePages(io)
                ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not an Ogg stream")
            val trailing = pages.isNotEmpty() && pages.last().start + pages.last().total in 1L until io.length

            val plans = ArrayList<StreamPlan>()
            val planBySerial = HashMap<Long, StreamPlan>()
            val retained = ArrayList<MetadataFinding>()
            for (serial in serialsOf(pages)) {
                ctx.checkCancelled()
                val headers = collectHeaders(io, pages, serial)
                if (headers == null) {
                    // A logical stream whose header packets cannot be parsed may carry comment
                    // tags that are invisible to this scanner. Compatibility mode leaves it
                    // alone and reports it as retained; the strictest mode refuses.
                    if (ctx.options.maximumPrivacy) {
                        throw PurgeRefusedException(
                            "Ogg logical stream $serial has no parsable header packets; " +
                                "its comment data cannot be enumerated in maximum privacy mode"
                        )
                    }
                    retained.addAll(streamFindings(io, serial, null))
                    continue
                }
                val comment = headers.packets.getOrNull(1)
                if (comment == null) {
                    if (ctx.options.maximumPrivacy) {
                        throw PurgeRefusedException("Ogg logical stream $serial has no comment header to verify")
                    }
                    retained.addAll(streamFindings(io, serial, headers))
                    continue
                }
                if (isCommentEmpty(headers.codec, comment)) continue

                val removed = ArrayList<MetadataFinding>()
                removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "${headers.codec} comment header"))
                readVendor(headers.codec, comment)?.let {
                    if (it.isNotEmpty()) removed.add(MetadataFinding(MetadataKind.SOFTWARE, "vendor: ${it.take(48)}"))
                }
                removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "comment fields of logical stream $serial"))

                val blanked = emptyComment(headers.codec)
                val firstGroup = ArrayList<ByteArray>()
                firstGroup.add(headers.packets[0])
                val restGroup = ArrayList<ByteArray>()
                restGroup.add(blanked)
                for (index in 2 until headers.packets.size) restGroup.add(headers.packets[index])
                val rebuilt = buildHeaderPages(serial, listOf(firstGroup, restGroup))
                val delta = rebuilt.size - headers.headerPageCount
                val plan = StreamPlan(serial, headers.headerPageCount, rebuilt, delta, removed, emptyList())
                plans.add(plan)
                planBySerial[serial] = plan
            }

            if (plans.isEmpty() && !trailing) {
                val message = if (retained.isNotEmpty()) {
                    "the only metadata found sits in logical streams that cannot be parsed"
                } else {
                    "comment headers already empty"
                }
                return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), residualRequired = retained, message = message)
            }

            val removed = ArrayList<MetadataFinding>()
            for (plan in plans) removed.addAll(plan.removed)
            if (trailing) removed.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the Ogg stream"))

            FileOutputStream(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                val headerPagesSeen = HashMap<Long, Int>()
                val emitted = HashSet<Long>()
                for (page in pages) {
                    ctx.checkCancelled()
                    val plan = planBySerial[page.serial]
                    if (plan == null) {
                        io.copyRange(page.start, page.total, out, buffer)
                        continue
                    }
                    val seen = headerPagesSeen.getOrDefault(plan.serial, 0)
                    if (seen < plan.headerPageCount) {
                        headerPagesSeen[plan.serial] = seen + 1
                        if (emitted.add(plan.serial)) {
                            for (rebuiltPage in plan.rebuilt) out.write(rebuiltPage)
                        }
                        continue
                    }
                    val newSeq = page.seq + plan.delta
                    if (newSeq == page.seq) {
                        io.copyRange(page.start, page.total, out, buffer)
                    } else {
                        out.write(reemitPage(io, page, newSeq))
                    }
                }
                // A stream whose header pages were never reached would otherwise vanish.
                for (plan in plans) {
                    if (!emitted.contains(plan.serial)) {
                        for (rebuiltPage in plan.rebuilt) out.write(rebuiltPage)
                    }
                }
                out.tail()
                out.flush()
            }
            return ScrubOutcome(
                true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(),
                retained.distinct(), true
            )
        }
    }

    /**
     * Lay packets out over pages. A codec setup header can be several kilobytes, which is more
     * than one page holds, so an oversized packet is split on whole 255 byte segments: a page
     * whose last segment reads 255 tells the demuxer the packet continues on the next page.
     */
    private fun buildHeaderPages(serial: Long, groups: List<List<ByteArray>>): List<ByteArray> {
        val built = ArrayList<ByteArray>()
        for (group in groups) {
            val pending = ArrayList<ByteArray>(group)
            var index = 0
            while (index < pending.size) {
                val segments = ArrayList<Int>()
                val data = java.io.ByteArrayOutputStream()
                while (index < pending.size) {
                    val packet = pending[index]
                    val wholePacketFits =
                        segments.size + lacing(packet) <= 255 && data.size() + packet.size <= MAX_PAGE_DATA
                    if (wholePacketFits) {
                        appendPacket(packet, segments, data)
                        index++
                        continue
                    }
                    if (segments.isNotEmpty()) break
                    val room = ((MAX_PAGE_DATA - data.size()) / 255).coerceAtMost(255 - segments.size)
                    if (room <= 0) break
                    val take = room * 255
                    data.write(packet, 0, take)
                    repeat(room) { segments.add(255) }
                    pending[index] = packet.copyOfRange(take, packet.size)
                    break
                }
                if (segments.isEmpty()) break
                val headerType = if (built.isEmpty()) 0x02 else 0x00
                built.add(serializePage(headerType, 0L, serial, built.size.toLong(), segments, data.toByteArray()))
            }
        }
        return built
    }

    private fun lacing(packet: ByteArray): Int = if (packet.isEmpty()) 1 else (packet.size + 254) / 255 + (if (packet.size % 255 == 0) 1 else 0)

    private fun appendPacket(packet: ByteArray, segments: MutableList<Int>, data: java.io.ByteArrayOutputStream) {
        if (packet.isEmpty()) {
            segments.add(0)
            return
        }
        var written = 0
        while (written < packet.size) {
            val chunk = minOf(255, packet.size - written)
            segments.add(chunk)
            data.write(packet, written, chunk)
            written += chunk
        }
        if (packet.size % 255 == 0) segments.add(0)
    }

    private fun emptyComment(codec: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        when (codec) {
            "opus" -> out.write("OpusTags".toByteArray(Charsets.US_ASCII))
            "vorbis" -> {
                out.write(0x03)
                out.write("vorbis".toByteArray(Charsets.US_ASCII))
            }
            "theora" -> {
                out.write(0x81)
                out.write("theora".toByteArray(Charsets.US_ASCII))
            }
        }
        val zeros = ByteArray(8)
        out.write(zeros)
        if (codec != "opus") out.write(0x01)
        return out.toByteArray()
    }

    private fun serializePage(
        headerType: Int,
        granule: Long,
        serial: Long,
        seq: Long,
        segments: List<Int>,
        data: ByteArray
    ): ByteArray {
        val header = ByteArray(27 + segments.size)
        System.arraycopy("OggS".toByteArray(Charsets.US_ASCII), 0, header, 0, 4)
        header[4] = 0
        header[5] = headerType.toByte()
        Bytes.putU64le(header, 6, granule)
        Bytes.putU32le(header, 14, serial)
        Bytes.putU32le(header, 18, seq)
        Bytes.putU32le(header, 22, 0)
        header[26] = segments.size.toByte()
        for (i in segments.indices) header[27 + i] = segments[i].toByte()
        val page = ByteArray(header.size + data.size)
        System.arraycopy(header, 0, page, 0, header.size)
        System.arraycopy(data, 0, page, header.size, data.size)
        Bytes.putU32le(page, 22, crc32(page))
        return page
    }

    private fun reemitPage(io: BinaryIo, page: Page, newSeq: Long): ByteArray {
        val dataLen = page.segments.sum()
        val data = io.peekAt(page.dataStart, dataLen) ?: ByteArray(0)
        return serializePage(page.headerType, page.granule, page.serial, newSeq, page.segments, data)
    }

    private fun crc32(data: ByteArray): Long {
        var crc = 0L
        for (byte in data) {
            crc = crc xor ((byte.toInt() and 0xFF).toLong() shl 24)
            for (i in 0 until 8) {
                crc = if (crc and 0x80000000L != 0L) ((crc shl 1) xor 0x04C11DB7L) and 0xFFFFFFFFL
                else (crc shl 1) and 0xFFFFFFFFL
            }
        }
        return crc
    }

    private fun isCommentEmpty(codec: String, packet: ByteArray): Boolean {
        val prefix = commentPrefix(codec)
        // Anything that does not parse is treated as not empty, so the rewrite replaces it with a
        // well formed empty header instead of passing a corrupt packet through.
        if (packet.size < prefix + 8) return false
        val vendorLength = Bytes.u32le(packet, prefix)
        if (vendorLength < 0 || prefix + 4 + vendorLength + 4 > packet.size) return false
        val count = Bytes.u32le(packet, prefix + 4 + vendorLength.toInt())
        if (count < 0) return false
        return vendorLength == 0L && count == 0L
    }

    private fun readVendor(codec: String, packet: ByteArray): String? {
        return try {
            val prefix = commentPrefix(codec)
            if (packet.size < prefix + 4) return null
            val length = Bytes.u32le(packet, prefix)
            if (length <= 0 || prefix + 4 + length > packet.size) return ""
            String(packet, prefix + 4, length.toInt(), Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        return try {
            BinaryIo.open(file).use { io ->
                val pages = parsePages(io) ?: return listOf(MetadataFinding(MetadataKind.OTHER, "not an Ogg stream"))
                val findings = ArrayList<MetadataFinding>()
                if (pages.isNotEmpty() && pages.last().start + pages.last().total in 1L until io.length) {
                    findings.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the Ogg stream"))
                }
                // Every logical stream is enumerated: sanitising or reporting only the first one
                // would leave sibling streams with their tags untouched and unseen.
                for (serial in serialsOf(pages)) {
                    val headers = collectHeaders(io, pages, serial)
                    findings.addAll(streamFindings(io, serial, headers))
                }
                findings.distinct()
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun readComments(codec: String, packet: ByteArray): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        var pos = commentPrefix(codec)
        if (pos + 4 > packet.size) return findings
        val vendorLength = Bytes.u32le(packet, pos)
        pos += 4 + vendorLength.toInt()
        if (pos + 4 > packet.size) return findings
        val count = Bytes.u32le(packet, pos)
        pos += 4
        var guard = 0
        while (guard++ < count && pos + 4 <= packet.size) {
            val length = Bytes.u32le(packet, pos)
            pos += 4
            if (length <= 0 || pos + length > packet.size) break
            val entry = String(packet, pos, length.toInt(), Charsets.UTF_8)
            val field = entry.substringBefore('=').uppercase()
            val kind = when (field) {
                "ARTIST", "ALBUMARTIST", "PERFORMER", "COMPOSER", "LYRICIST" -> MetadataKind.AUTHOR
                "DATE", "YEAR" -> MetadataKind.TIMESTAMP
                "ENCODER", "ENCODED-BY" -> MetadataKind.SOFTWARE
                "COMMENT", "DESCRIPTION" -> MetadataKind.COMMENT
                else -> MetadataKind.AUDIO_TAGS
            }
            findings.add(MetadataFinding(kind, "$codec tag $field"))
            pos += length.toInt()
        }
        return findings
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val pages = parsePages(io) ?: return false
                if (pages.isEmpty()) return false
                if (pages.last().start + pages.last().total < io.length) return false
                for (serial in serialsOf(pages)) {
                    val headers = collectHeaders(io, pages, serial)
                    if (headers == null) {
                        // Compatibility mode only demands a structurally sound file; a stream
                        // that cannot be parsed stays as a residual finding, not a silent pass.
                        if (options.maximumPrivacy) return false
                        continue
                    }
                    val comment = headers.packets.getOrNull(1) ?: continue
                    if (!isCommentEmpty(headers.codec, comment) && options.maximumPrivacy) return false
                }
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}
