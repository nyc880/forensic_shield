package com.example.lock.metadata

import java.io.File
import java.io.FileOutputStream
import java.util.zip.CRC32

object PngHandler : FormatHandler {

    override val id: String = "png"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.PNG)

    private val signature = byteArrayOf(
        0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    )

    private val droppedChunks = setOf(
        "tEXt", "zTXt", "iTXt", "eXIf", "tIME", "dSIG", "pCAL", "sCAL", "sTER",
        "gIFg", "gIFt", "gIFx", "oFFs", "fRAc", "caBX", "caMs", "caSt"
    )

    private val renderingChunks = setOf(
        "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "gAMA", "cHRM", "sRGB", "bKGD", "pHYs",
        "sBIT", "sPLT", "hIST", "acTL", "fcTL", "fdAT", "cICP", "mDCv", "cLLi"
    )

    private data class Chunk(val type: String, val offset: Long, val dataOffset: Long, val dataLength: Long, val totalLength: Long)

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val chunks = parseChunks(ctx.source)
        if (chunks.isEmpty()) return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a parsable PNG stream")
        if (chunks.first().type != "IHDR") return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "missing IHDR")

        val removed = ArrayList<MetadataFinding>()
        val buffer = Buffers.new()
        BinaryIo.open(ctx.source).use { io ->
            FileOutputStream(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                out.write(signature)
                io.seek(signature.size.toLong())
                for (chunk in chunks) {
                    ctx.checkCancelled()
                    if (shouldDrop(chunk, ctx.options, io, removed)) continue
                    io.copyRange(chunk.offset, chunk.totalLength, out, buffer)
                    if (chunk.type == "IEND") break
                }
                out.tail()
                out.flush()
            }
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
    }

    private fun shouldDrop(chunk: Chunk, options: PurgeOptions, io: BinaryIo, removed: MutableList<MetadataFinding>): Boolean {
        val type = chunk.type
        if (type == "IEND" || type == "IHDR") return false
        if (type in droppedChunks) {
            removed.add(MetadataFinding(kindForChunk(type, io, chunk), describeChunk(type, io, chunk)))
            return true
        }
        if (type == "iCCP") {
            if (options.stripColorProfiles) {
                removed.add(MetadataFinding(MetadataKind.ICC_PROFILE, "iCCP colour profile"))
                return true
            }
            return false
        }
        if (type in renderingChunks) return false

        val ancillary = type.isNotEmpty() && type[0].isLowerCase()
        if (ancillary) {
            removed.add(MetadataFinding(MetadataKind.OTHER, "ancillary chunk $type"))
            return true
        }
        return false
    }

    private fun kindForChunk(type: String, io: BinaryIo, chunk: Chunk): MetadataKind = when (type) {
        "caBX", "caMs", "caSt" -> MetadataKind.PROVENANCE
        "tEXt", "zTXt", "iTXt" -> {
            val probe = probeKeyword(io, chunk)
            when {
                probe == null -> MetadataKind.COMMENT
                probe.startsWith("XML:com.adobe.xmp") -> MetadataKind.XMP
                probe.contains("author", true) || probe.contains("artist", true) -> MetadataKind.AUTHOR
                probe.contains("time", true) || probe.contains("date", true) -> MetadataKind.TIMESTAMP
                probe.contains("software", true) || probe.contains("generator", true) -> MetadataKind.SOFTWARE
                probe.contains("copyright", true) -> MetadataKind.AUTHOR
                probe.contains("comment", true) || probe.contains("description", true) -> MetadataKind.COMMENT
                else -> MetadataKind.COMMENT
            }
        }
        "eXIf" -> MetadataKind.EXIF
        "tIME" -> MetadataKind.TIMESTAMP
        "pCAL", "sCAL" -> MetadataKind.DEVICE_IDENTITY
        "dSIG" -> MetadataKind.UNIQUE_ID
        "gIFg", "gIFt", "gIFx" -> MetadataKind.OTHER
        "iCCP" -> MetadataKind.ICC_PROFILE
        else -> MetadataKind.OTHER
    }

    private fun describeChunk(type: String, io: BinaryIo, chunk: Chunk): String {
        if (type == "caBX" || type == "caMs" || type == "caSt") {
            return "C2PA provenance manifest ($type chunk)"
        }
        // Only the text chunks start with a keyword; for tIME and friends the payload is binary and
        // printing it as a label produced garbage in the report.
        if (type != "tEXt" && type != "zTXt" && type != "iTXt") return "PNG $type chunk"
        val keyword = probeKeyword(io, chunk)
        return if (keyword.isNullOrEmpty()) "PNG $type chunk" else "PNG $type: $keyword"
    }

    private fun probeKeyword(io: BinaryIo, chunk: Chunk): String? {
        val size = minOf(chunk.dataLength, 96L).toInt()
        if (size <= 0) return null
        val bytes = io.peekAt(chunk.dataOffset, size) ?: return null
        val text = String(bytes, Charsets.ISO_8859_1)
        return text.substringBefore('\u0000').take(48).trim()
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val chunks = parseChunks(file)
        if (chunks.isEmpty() || chunks.first().type != "IHDR") {
            return listOf(MetadataFinding(MetadataKind.OTHER, "unparsable PNG structure"))
        }
        val findings = ArrayList<MetadataFinding>()
        BinaryIo.open(file).use { io ->
            val iend = chunks.lastOrNull { it.type == "IEND" }
            if (iend != null && iend.offset + iend.totalLength < io.length) {
                findings.add(MetadataFinding(MetadataKind.OTHER, "data after the end of image chunk"))
            }
            for (chunk in chunks) {
                val collector = ArrayList<MetadataFinding>()
                shouldDrop(chunk, options, io, collector)
                findings.addAll(collector)
                if (chunk.type == "eXIf") {
                    val size = minOf(chunk.dataLength, 1L shl 20).toInt()
                    val payload = io.peekAt(chunk.dataOffset, size)
                    if (payload != null) {
                        val scan = ExifScanner.scan(payload, 0)
                        for (entry in scan.entries) {
                            if (entry.tag == 0x0112) continue
                            val kind = if (entry.ifd.startsWith("GPS")) MetadataKind.GPS else entry.kind ?: MetadataKind.EXIF
                            findings.add(MetadataFinding(kind, entry.describe()))
                        }
                    }
                }
            }
        }
        return findings.distinct()
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        val chunks = parseChunks(file)
        if (chunks.isEmpty()) return false
        if (chunks.first().type != "IHDR") return false
        var sawIdat = false
        var sawIend = false
        BinaryIo.open(file).use { io ->
            for (chunk in chunks) {
                if (chunk.type == "IDAT") sawIdat = true
                if (chunk.type == "IEND") {
                    sawIend = true
                    if (chunk.dataLength != 0L) return false
                }
                if (!verifyCrc(io, chunk)) return false
            }
        }
        return sawIdat && sawIend && chunks.last().type == "IEND"
    }

    private fun verifyCrc(io: BinaryIo, chunk: Chunk): Boolean {
        val crcOffset = chunk.dataOffset + chunk.dataLength
        val stored = io.peekAt(crcOffset, 4) ?: return false
        val expected = com.example.lock.metadata.Bytes.u32be(stored, 0)
        val crc = CRC32()
        val typeBytes = chunk.type.toByteArray(Charsets.US_ASCII)
        crc.update(typeBytes, 0, typeBytes.size)
        val buffer = ByteArray(64 * 1024)
        var remaining = chunk.dataLength
        var offset = chunk.dataOffset
        while (remaining > 0) {
            val size = minOf(remaining, buffer.size.toLong()).toInt()
            val data = io.peekAt(offset, size) ?: return false
            crc.update(data, 0, size)
            offset += size
            remaining -= size
        }
        return crc.value == expected
    }

    private fun parseChunks(file: File): List<Chunk> {
        val chunks = ArrayList<Chunk>()
        return try {
            BinaryIo.open(file).use { io ->
                val length = io.length
                val header = io.peekAt(0, 8) ?: return emptyList()
                for (i in signature.indices) if (header[i] != signature[i]) return emptyList()
                var pos = 8L
                var guard = 0
                while (pos + 12 <= length && guard++ < 1_000_000) {
                    val headerBytes = io.peekAt(pos, 8) ?: break
                    val dataLength = com.example.lock.metadata.Bytes.u32be(headerBytes, 0)
                    val type = com.example.lock.metadata.Bytes.asciiAt(headerBytes, 4, 4)
                    if (dataLength < 0 || dataLength > length || pos + 12 + dataLength > length) {
                        chunks.add(Chunk(type, pos, pos + 8, dataLength, length - pos))
                        break
                    }
                    chunks.add(Chunk(type, pos, pos + 8, dataLength, dataLength + 12))
                    pos += dataLength + 12
                    if (type == "IEND") break
                }
                chunks
            }
        } catch (_: Exception) {
            emptyList()
        }
    }
}

object WebpHandler : FormatHandler {

    override val id: String = "webp"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.WEBP)

    private const val FLAG_ICC = 0x20
    private const val FLAG_ALPHA = 0x10
    private const val FLAG_EXIF = 0x08
    private const val FLAG_XMP = 0x04
    private const val FLAG_ANIM = 0x02

    private data class Chunk(val type: String, val offset: Long, val dataOffset: Long, val dataLength: Long, val totalLength: Long)

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val chunks = parseChunks(ctx.source)
        if (chunks.isEmpty()) return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a parsable WebP stream")
        if (chunks.none { it.type == "VP8 " || it.type == "VP8L" || it.type == "ANMF" || it.type == "ANIM" }) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no image payload found")
        }

        val removed = ArrayList<MetadataFinding>()
        val declared = declaredEnd(ctx.source)
        if (declared != null && declared in 1L until ctx.source.length()) {
            removed.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the RIFF container"))
        }
        val keep = ArrayList<Chunk>()
        for (chunk in chunks) {
            when (chunk.type) {
                "EXIF" -> removed.add(MetadataFinding(MetadataKind.EXIF, exifDetail(ctx.source, chunk)))
                "XMP " -> removed.add(MetadataFinding(MetadataKind.XMP, "XMP packet"))
                "C2PA" -> removed.add(MetadataFinding(MetadataKind.PROVENANCE, "C2PA provenance manifest (C2PA chunk)"))
                "ICCP" -> {
                    if (ctx.options.stripColorProfiles) {
                        removed.add(MetadataFinding(MetadataKind.ICC_PROFILE, "ICC colour profile"))
                    } else keep.add(chunk)
                }
                "VP8X" -> keep.add(chunk)
                "VP8 ", "VP8L", "ALPH", "ANIM", "ANMF" -> keep.add(chunk)
                else -> removed.add(MetadataFinding(MetadataKind.OTHER, "unknown RIFF chunk ${chunk.type}"))
            }
        }

        val buffer = Buffers.new()
        BinaryIo.open(ctx.source).use { io ->
            FileOutputStream(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                var payloadSize = 4L
                for (chunk in keep) payloadSize += chunk.totalLength
                val riff = ByteArray(12)
                riff[0] = 'R'.code.toByte(); riff[1] = 'I'.code.toByte(); riff[2] = 'F'.code.toByte(); riff[3] = 'F'.code.toByte()
                Bytes.putU32le(riff, 4, payloadSize)
                riff[8] = 'W'.code.toByte(); riff[9] = 'E'.code.toByte(); riff[10] = 'B'.code.toByte(); riff[11] = 'P'.code.toByte()
                out.write(riff)

                for (chunk in keep) {
                    ctx.checkCancelled()
                    if (chunk.type == "VP8X" && chunk.dataLength >= 1) {
                        val payload = io.peekAt(chunk.dataOffset, chunk.dataLength.toInt()) ?: continue
                        var flags = payload[0].toInt() and 0xFF
                        flags = flags and FLAG_EXIF.inv()
                        flags = flags and FLAG_XMP.inv()
                        if (ctx.options.stripColorProfiles) flags = flags and FLAG_ICC.inv()
                        payload[0] = flags.toByte()
                        val header = ByteArray(8)
                        header[0] = 'V'.code.toByte(); header[1] = 'P'.code.toByte()
                        header[2] = '8'.code.toByte(); header[3] = 'X'.code.toByte()
                        Bytes.putU32le(header, 4, chunk.dataLength)
                        out.write(header)
                        out.write(payload)
                        if (chunk.dataLength % 2 == 1L) out.write(0)
                    } else {
                        io.copyRange(chunk.offset, chunk.totalLength, out, buffer)
                    }
                }
                out.tail()
                out.flush()
            }
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
    }

    private fun exifDetail(file: File, chunk: Chunk): String {
        return try {
            BinaryIo.open(file).use { io ->
                val size = minOf(chunk.dataLength, 1L shl 20).toInt()
                val payload = io.peekAt(chunk.dataOffset, size) ?: return "EXIF chunk"
                val scan = ExifScanner.scan(payload, 0)
                val parts = scan.entries.take(6).map { it.describe() }
                if (parts.isEmpty()) "EXIF chunk" else "EXIF chunk: " + parts.joinToString(", ")
            }
        } catch (_: Exception) {
            "EXIF chunk"
        }
    }

    private fun declaredEnd(file: File): Long? {
        return try {
            BinaryIo.open(file).use { io ->
                val header = io.peekAt(0, 12) ?: return null
                if (Bytes.asciiAt(header, 0, 4) != "RIFF" || Bytes.asciiAt(header, 8, 4) != "WEBP") return null
                Bytes.u32le(header, 4) + 8
            }
        } catch (_: Exception) {
            null
        }
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val chunks = parseChunks(file)
        if (chunks.isEmpty()) return listOf(MetadataFinding(MetadataKind.OTHER, "unparsable WebP structure"))
        val findings = ArrayList<MetadataFinding>()
        val declared = declaredEnd(file)
        if (declared != null && declared in 1L until file.length()) {
            findings.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the RIFF container"))
        }
        for (chunk in chunks) {
            when (chunk.type) {
                "EXIF" -> findings.add(MetadataFinding(MetadataKind.EXIF, exifDetail(file, chunk)))
                "XMP " -> findings.add(MetadataFinding(MetadataKind.XMP, "XMP packet"))
                "ICCP" -> if (options.stripColorProfiles) findings.add(MetadataFinding(MetadataKind.ICC_PROFILE, "ICC colour profile"))
                "VP8X" -> {
                    val flags = readVp8xFlags(file, chunk)
                    if (flags != null) {
                        if (flags and FLAG_EXIF != 0 && chunks.none { it.type == "EXIF" }) {
                            findings.add(MetadataFinding(MetadataKind.OTHER, "VP8X EXIF flag set without payload"))
                        }
                        if (flags and FLAG_XMP != 0 && chunks.none { it.type == "XMP " }) {
                            findings.add(MetadataFinding(MetadataKind.OTHER, "VP8X XMP flag set without payload"))
                        }
                    }
                }
                "VP8 ", "VP8L", "ALPH", "ANIM", "ANMF" -> Unit
                else -> findings.add(MetadataFinding(MetadataKind.OTHER, "unknown RIFF chunk ${chunk.type}"))
            }
        }
        return findings.distinct()
    }

    private fun readVp8xFlags(file: File, chunk: Chunk): Int? {
        if (chunk.dataLength < 1) return null
        return try {
            BinaryIo.open(file).use { io -> io.peekAt(chunk.dataOffset, 1)?.get(0)?.toInt()?.and(0xFF) }
        } catch (_: Exception) {
            null
        }
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        val expected = file.length()
        val chunks = parseChunks(file)
        if (chunks.isEmpty()) return false
        val declared = try {
            BinaryIo.open(file).use { io ->
                val header = io.peekAt(0, 12) ?: return false
                if (Bytes.asciiAt(header, 0, 4) != "RIFF" || Bytes.asciiAt(header, 8, 4) != "WEBP") return false
                Bytes.u32le(header, 4) + 8
            }
        } catch (_: Exception) {
            return false
        }
        if (declared != expected) return false
        val hasPayload = chunks.any { it.type == "VP8 " || it.type == "VP8L" || it.type == "ANMF" }
        return hasPayload && chunks.none { it.type == "EXIF" || it.type == "XMP " }
    }

    private fun parseChunks(file: File): List<Chunk> {
        val chunks = ArrayList<Chunk>()
        return try {
            BinaryIo.open(file).use { io ->
                val length = io.length
                if (length < 12) return emptyList()
                val header = io.peekAt(0, 12) ?: return emptyList()
                if (Bytes.asciiAt(header, 0, 4) != "RIFF" || Bytes.asciiAt(header, 8, 4) != "WEBP") return emptyList()
                val declared = Bytes.u32le(header, 4) + 8
                var pos = 12L
                val limit = minOf(length, if (declared in 12..length) declared else length)
                var guard = 0
                while (pos + 8 <= limit && guard++ < 1_000_000) {
                    val chunkHeader = io.peekAt(pos, 8) ?: break
                    val type = Bytes.asciiAt(chunkHeader, 0, 4)
                    val size = Bytes.u32le(chunkHeader, 4)
                    if (size < 0 || pos + 8 + size > limit) {
                        chunks.add(Chunk(type, pos, pos + 8, size, limit - pos))
                        break
                    }
                    val padded = size + (size and 1L)
                    chunks.add(Chunk(type, pos, pos + 8, size, 8 + padded))
                    pos += 8 + padded
                }
                chunks
            }
        } catch (_: Exception) {
            emptyList()
        }
    }
}
