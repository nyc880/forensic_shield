package com.example.lock.metadata

import java.io.File
import java.io.FileOutputStream

object JpegHandler : FormatHandler {

    override val id: String = "jpeg"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.JPEG)

    private const val MARKER_SOI = 0xD8
    private const val MARKER_EOI = 0xD9
    private const val MARKER_SOS = 0xDA
    private const val MARKER_COM = 0xFE
    private const val MARKER_APP0 = 0xE0
    private const val MARKER_APP1 = 0xE1
    private const val MARKER_APP2 = 0xE2
    private const val MARKER_APP11 = 0xEB
    private const val MARKER_APP13 = 0xED
    private const val MARKER_APP14 = 0xEE
    private const val MAX_PAYLOAD_PROBE = 1 shl 20

    private data class Segment(
        val marker: Int,
        val headerStart: Long,
        val payloadStart: Long,
        val payloadLength: Long,
        val totalLength: Long
    ) {
        val isEntropy: Boolean get() = marker == -1
    }

    private data class Structure(
        val segments: List<Segment>,
        val valid: Boolean,
        val truncatedAt: Long,
        val tailStart: Long = -1L,
        val removed: List<MetadataFinding> = emptyList()
    )

    private enum class Decision { KEEP, DROP, EXIF_BLOCK }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val structure = analyse(ctx.source)
        if (!structure.valid || structure.segments.isEmpty()) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a parsable JPEG stream")
        }

        val removed = structure.removed.toMutableList()
        val required = ArrayList<MetadataFinding>()
        val buffer = Buffers.new()

        BinaryIo.open(ctx.source).use { io ->
            FileOutputStream(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                for (segment in structure.segments) {
                    ctx.checkCancelled()
                    if (segment.isEntropy) {
                        io.copyRange(segment.headerStart, segment.totalLength, out, buffer)
                        continue
                    }
                    when (classify(io, segment, ctx.options, removed)) {
                        Decision.KEEP -> io.copyRange(segment.headerStart, segment.totalLength, out, buffer)
                        Decision.DROP -> Unit
                        Decision.EXIF_BLOCK -> {
                            val orientation = readOrientation(io, segment)
                            val keepOrientation = ctx.options.orientationPolicy == OrientationPolicy.MINIMAL_TAG &&
                                orientation != null && orientation != 1
                            if (!keepOrientation || orientation == null) {
                                removed.add(MetadataFinding(MetadataKind.EXIF, "EXIF block (no orientation needed)"))
                            } else {
                                val minimal = ExifScanner.buildMinimalOrientationApp1(orientation)
                                writeSegment(out, MARKER_APP1, minimal)
                                required.add(MetadataFinding(MetadataKind.OTHER, "orientation value $orientation"))
                            }
                        }
                    }
                }
                out.tail()
                out.flush()
            }
        }
        return ScrubOutcome(
            success = true,
            strategy = PurgeStrategy.STRUCTURAL_REWRITE,
            removed = removed.distinct(),
            residualRequired = required,
            structureValid = true
        )
    }

    private fun writeSegment(out: java.io.OutputStream, marker: Int, payload: ByteArray) {
        out.write(0xFF)
        out.write(marker)
        val length = payload.size + 2
        out.write((length ushr 8) and 0xFF)
        out.write(length and 0xFF)
        out.write(payload)
    }

    private fun classify(
        io: BinaryIo,
        segment: Segment,
        options: PurgeOptions,
        removed: MutableList<MetadataFinding>
    ): Decision {
        val marker = segment.marker
        return when (marker) {
            MARKER_COM -> {
                if (options.keepJpegComments) Decision.KEEP
                else {
                    removed.add(MetadataFinding(MetadataKind.COMMENT, "JPEG comment segment"))
                    Decision.DROP
                }
            }
            MARKER_APP0 -> {
                val payload = readPayload(io, segment, 16)
                if (payload != null && payload.startsWithAscii(0, "JFXX\u0000")) {
                    removed.add(MetadataFinding(MetadataKind.THUMBNAIL, "JFXX extension thumbnail"))
                    Decision.DROP
                } else Decision.KEEP
            }
            MARKER_APP1 -> {
                val payload = readPayload(io, segment, MAX_PAYLOAD_PROBE)
                when {
                    payload == null -> {
                        removed.add(MetadataFinding(MetadataKind.EXIF, "unreadable APP1 block"))
                        Decision.DROP
                    }
                    payload.startsWithAscii(0, "Exif\u0000\u0000") -> Decision.EXIF_BLOCK
                    payload.startsWithAscii(0, "http://ns.adobe.com/xap/1.0/") -> {
                        removed.add(MetadataFinding(MetadataKind.XMP, "XMP packet"))
                        Decision.DROP
                    }
                    payload.startsWithAscii(0, "http://ns.adobe.com/xmp/extension/") -> {
                        removed.add(MetadataFinding(MetadataKind.XMP, "extended XMP packet"))
                        Decision.DROP
                    }
                    else -> {
                        removed.add(MetadataFinding(MetadataKind.OTHER, "APP1 vendor block"))
                        Decision.DROP
                    }
                }
            }
            MARKER_APP2 -> {
                val payload = readPayload(io, segment, 64)
                when {
                    payload != null && payload.asciiRange(0, 11) == "ICC_PROFILE" -> {
                        if (options.stripColorProfiles) {
                            removed.add(MetadataFinding(MetadataKind.ICC_PROFILE, "ICC profile"))
                            Decision.DROP
                        } else Decision.KEEP
                    }
                    payload != null && payload.startsWithAscii(0, "MPF\u0000") -> {
                        removed.add(MetadataFinding(MetadataKind.EMBEDDED_FILE, "MPF multi picture container"))
                        Decision.DROP
                    }
                    else -> {
                        removed.add(MetadataFinding(MetadataKind.OTHER, "APP2 block"))
                        Decision.DROP
                    }
                }
            }
            MARKER_APP11 -> {
                // C2PA / Content Credentials ride in APP11 as a JUMBF box. It is dropped by the
                // generic APPn rule below either way, but naming it keeps the report honest about
                // what was actually in there.
                // The JPEG XT box header in front of the JUMBF box varies by writer, so the box type
                // is located rather than assumed to sit at a fixed offset.
                val payload = readPayload(io, segment, 32)
                val jumbf = payload != null &&
                    Bytes.indexOf(payload, "jumb".toByteArray(Charsets.US_ASCII)) >= 0
                if (jumbf) {
                    removed.add(MetadataFinding(MetadataKind.PROVENANCE, "C2PA provenance manifest (APP11 JUMBF)"))
                } else {
                    removed.add(MetadataFinding(MetadataKind.OTHER, "APP11 JUMBF block"))
                }
                Decision.DROP
            }
            MARKER_APP13 -> {
                removed.add(MetadataFinding(MetadataKind.IPTC, "Photoshop/IPTC resources"))
                Decision.DROP
            }
            MARKER_APP14 -> Decision.KEEP
            in 0xE3..0xEC, 0xEF -> {
                removed.add(MetadataFinding(MetadataKind.OTHER, "APP${marker - 0xE0} block"))
                Decision.DROP
            }
            else -> Decision.KEEP
        }
    }

    private fun readPayload(io: BinaryIo, segment: Segment, maxBytes: Int): ByteArray? {
        val size = minOf(segment.payloadLength, maxBytes.toLong()).toInt()
        if (size <= 0) return ByteArray(0)
        return io.peekAt(segment.payloadStart, size)
    }

    private fun readOrientation(io: BinaryIo, segment: Segment): Int? {
        val payload = readPayload(io, segment, MAX_PAYLOAD_PROBE) ?: return null
        if (!payload.startsWithAscii(0, "Exif\u0000\u0000")) return null
        return ExifScanner.scanJpegApp1(payload).orientation
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val structure = analyse(file)
        if (!structure.valid) return listOf(MetadataFinding(MetadataKind.OTHER, "unparsable JPEG structure"))
        val findings = ArrayList<MetadataFinding>(structure.removed)
        BinaryIo.open(file).use { io ->
            for (segment in structure.segments) {
                if (segment.isEntropy) continue
                val collected = ArrayList<MetadataFinding>()
                val decision = try {
                    classify(io, segment, options, collected)
                } catch (_: Exception) {
                    Decision.KEEP
                }
                findings.addAll(collected)
                if (decision == Decision.EXIF_BLOCK) {
                    val payload = readPayload(io, segment, MAX_PAYLOAD_PROBE)
                    if (payload == null) {
                        findings.add(MetadataFinding(MetadataKind.EXIF, "EXIF block"))
                    } else {
                        val scan = ExifScanner.scanJpegApp1(payload)
                        if (scan.entries.isEmpty()) {
                            findings.add(MetadataFinding(MetadataKind.EXIF, "EXIF block"))
                        } else {
                            for (entry in scan.entries) {
                                if (entry.tag == 0x0112) continue
                                val kind = if (entry.ifd.startsWith("GPS")) MetadataKind.GPS
                                else entry.kind ?: MetadataKind.EXIF
                                findings.add(MetadataFinding(kind, entry.describe()))
                            }
                            if (scan.hasMakerNote && scan.entries.none { it.tag == 0x927C }) {
                                findings.add(MetadataFinding(MetadataKind.MAKER_NOTE, "MakerNote"))
                            }
                        }
                    }
                }
            }
        }
        return findings.distinct()
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        val structure = analyse(file)
        if (!structure.valid || structure.segments.isEmpty()) return false
        val markers = structure.segments.map { it.marker }
        val hasFrame = markers.any { it in 0xC0..0xCF && it != 0xC4 && it != 0xC8 && it != 0xCC }
        val hasScan = markers.contains(MARKER_SOS)
        val startsWithSoi = structure.segments.first().marker == MARKER_SOI
        val endsWithEoi = structure.segments.last().marker == MARKER_EOI
        val cleanTail = structure.tailStart <= 0L
        return startsWithSoi && hasFrame && hasScan && endsWithEoi && cleanTail
    }

    private fun analyse(file: File): Structure {
        val segments = ArrayList<Segment>()
        val removed = ArrayList<MetadataFinding>()
        return try {
            BinaryIo.open(file).use { io ->
                val length = io.length
                if (length < 4) return Structure(emptyList(), false, 0L)
                io.seek(0)
                if (io.u8() != 0xFF || io.u8() != MARKER_SOI) return Structure(emptyList(), false, 0L)
                segments.add(Segment(MARKER_SOI, 0L, 2L, 0L, 2L))

                while (io.position < length) {
                    val markerStart = io.position
                    var byte = io.u8OrNull() ?: break
                    if (byte != 0xFF) return Structure(segments, false, markerStart)
                    while (byte == 0xFF && io.position < length) byte = io.u8()
                    if (byte == 0xFF) break
                    val marker = byte
                    if (marker == 0x00) return Structure(segments, false, markerStart)

                    when {
                        marker == MARKER_EOI -> {
                            segments.add(Segment(MARKER_EOI, markerStart, io.position, 0L, io.position - markerStart))
                            val tail = if (io.position < length) io.position else -1L
                            if (tail > 0) {
                                removed.add(MetadataFinding(MetadataKind.OTHER, "data after the end of image marker"))
                            }
                            return Structure(segments, true, io.position, tail, removed)
                        }
                        marker in 0xD0..0xD7 || marker == 0x01 -> {
                            segments.add(Segment(marker, markerStart, io.position, 0L, io.position - markerStart))
                            continue
                        }
                        marker == MARKER_SOS -> {
                            val segmentLength = io.u16be()
                            if (segmentLength < 2 || io.position + segmentLength - 2 > length) {
                                return Structure(segments, false, markerStart)
                            }
                            val scanHeader = io.position
                            io.skip(segmentLength - 2L)
                            segments.add(
                                Segment(marker, markerStart, scanHeader, (segmentLength - 2).toLong(), io.position - markerStart)
                            )
                            val entropyStart = io.position
                            val entropyEnd = scanEntropy(io, length)
                            if (entropyEnd > entropyStart) {
                                segments.add(Segment(-1, entropyStart, entropyStart, entropyEnd - entropyStart, entropyEnd - entropyStart))
                            }
                            io.seek(entropyEnd)
                        }
                        else -> {
                            val segmentLength = io.u16be()
                            if (segmentLength < 2 || io.position + segmentLength - 2 > length) {
                                return Structure(segments, false, markerStart)
                            }
                            val payloadStart = io.position
                            io.skip(segmentLength - 2L)
                            segments.add(
                                Segment(marker, markerStart, payloadStart, (segmentLength - 2).toLong(), io.position - markerStart)
                            )
                        }
                    }
                }
                Structure(segments, false, io.position)
            }
        } catch (_: Exception) {
            Structure(segments, false, 0L)
        }
    }

    private fun scanEntropy(io: BinaryIo, length: Long): Long {
        while (io.position < length) {
            val b = io.u8()
            if (b != 0xFF) continue
            if (io.position >= length) return length
            var next = io.u8()
            while (next == 0xFF && io.position < length) next = io.u8()
            when {
                next == 0x00 -> continue
                next in 0xD0..0xD7 -> continue
                else -> return (io.position - 2).coerceAtLeast(0)
            }
        }
        return length
    }
}
