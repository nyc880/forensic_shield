package com.example.lock.metadata

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream

internal object CodecUserData {

    enum class Codec { H264, HEVC, UNKNOWN }

    private const val SEI_USER_DATA_UNREGISTERED = 5
    private const val MAX_SEI_MESSAGES = 64

    fun neutraliseAnnexB(data: ByteArray, codec: Codec, from: Int = 0, to: Int = data.size): Int {
        if (codec == Codec.UNKNOWN) return 0
        var hits = 0
        var index = from
        while (index + 4 <= to) {
            if (data[index].toInt() != 0 || data[index + 1].toInt() != 0 || data[index + 2].toInt() != 1) {
                index++
                continue
            }
            val headerIndex = index + 3
            var nalEnd = headerIndex + 1
            var nextStart = -1
            while (nalEnd + 3 <= to) {
                if (data[nalEnd].toInt() == 0 && data[nalEnd + 1].toInt() == 0 &&
                    data[nalEnd + 2].toInt() == 1
                ) {
                    nextStart = nalEnd
                    break
                }
                nalEnd++
            }
            nalEnd = if (nextStart >= 0) nextStart else to
            if (isSeiHeader(data[headerIndex].toInt() and 0xFF, codec)) {
                hits += neutraliseSei(data, headerIndex + 1, nalEnd)
            }
            index = nalEnd
        }
        return hits
    }

    fun neutraliseLengthPrefixed(data: ByteArray, codec: Codec, from: Int, to: Int): Int {
        if (codec == Codec.UNKNOWN) return 0
        var cursor = from
        var hits = 0
        var units = 0
        while (cursor + 4 <= to) {
            val size = ((data[cursor].toInt() and 0xFF) shl 24) or ((data[cursor + 1].toInt() and 0xFF) shl 16) or
                ((data[cursor + 2].toInt() and 0xFF) shl 8) or (data[cursor + 3].toInt() and 0xFF)
            if (size <= 0 || cursor + 4 + size > to) return -1
            val header = data[cursor + 4].toInt() and 0xFF
            if (isSeiHeader(header, codec)) {
                hits += neutraliseSei(data, cursor + 5, cursor + 4 + size)
            }
            cursor += 4 + size
            units++
        }
        if (units == 0 || cursor != to) return -1
        return hits
    }

    fun codecFromStreamType(streamType: Int): Codec = when (streamType) {
        0x1B, 0x02, 0x10, 0x1F, 0x20 -> Codec.H264
        0x24 -> Codec.HEVC
        else -> Codec.UNKNOWN
    }

    fun codecFromSampleEntry(fourCc: String): Codec = when (fourCc) {
        "avc1", "avc3", "avc4", "dvav", "dva1", "mjc2" -> Codec.H264
        "hvc1", "hev1", "dvhe", "dvh1", "hvc2" -> Codec.HEVC
        else -> Codec.UNKNOWN
    }

    fun countAnnexB(data: ByteArray, codec: Codec, from: Int = 0, to: Int = data.size): Int {
        if (codec == Codec.UNKNOWN) return 0
        var hits = 0
        var index = from
        while (index + 4 <= to) {
            if (data[index].toInt() != 0 || data[index + 1].toInt() != 0 || data[index + 2].toInt() != 1) {
                index++
                continue
            }
            val headerIndex = index + 3
            var nalEnd = headerIndex + 1
            var nextStart = -1
            while (nalEnd + 3 <= to) {
                if (data[nalEnd].toInt() == 0 && data[nalEnd + 1].toInt() == 0 &&
                    data[nalEnd + 2].toInt() == 1
                ) {
                    nextStart = nalEnd
                    break
                }
                nalEnd++
            }
            nalEnd = if (nextStart >= 0) nextStart else to
            if (isSeiHeader(data[headerIndex].toInt() and 0xFF, codec)) {
                hits += countSei(data, headerIndex + 1, nalEnd)
            }
            index = nalEnd
        }
        return hits
    }

    private fun countSei(data: ByteArray, start: Int, limit: Int): Int {
        var cursor = start
        var hits = 0
        var messages = 0
        while (cursor < limit && messages < MAX_SEI_MESSAGES) {
            val type = readSeiField(data, cursor, limit)
            if (type.first < 0) return hits
            cursor = type.second
            val size = readSeiField(data, cursor, limit)
            if (size.first < 0) return hits
            cursor = size.second
            val length = size.first
            if (length < 0 || cursor + length > limit) return hits
            if (type.first == SEI_USER_DATA_UNREGISTERED && length > 0) {
                for (i in cursor until cursor + length) {
                    if (data[i].toInt() and 0xFF != 0xFF) {
                        hits++
                        break
                    }
                }
            }
            cursor += length
            messages++
            if (cursor < limit && (data[cursor].toInt() and 0xFF) == 0x80) return hits
        }
        return hits
    }

    private fun isSeiHeader(header: Int, codec: Codec): Boolean {
        if (header and 0x80 != 0) return false
        return when (codec) {
            Codec.H264 -> header and 0x60 == 0 && (header and 0x1F) == 6
            Codec.HEVC -> {
                val type = (header shr 1) and 0x3F
                type == 39 || type == 40
            }
            Codec.UNKNOWN -> false
        }
    }

    private fun neutraliseSei(data: ByteArray, start: Int, limit: Int): Int {
        val targets = ArrayList<IntArray>()
        var cursor = start
        var messages = 0
        while (cursor < limit && messages < MAX_SEI_MESSAGES) {
            val type = readSeiField(data, cursor, limit)
            if (type.first < 0) return 0
            cursor = type.second
            val size = readSeiField(data, cursor, limit)
            if (size.first < 0) return 0
            cursor = size.second
            val length = size.first
            if (length < 0 || cursor + length > limit) return 0
            if (type.first == SEI_USER_DATA_UNREGISTERED && length > 0) {
                targets.add(intArrayOf(cursor, length))
            }
            cursor += length
            messages++
            if (cursor >= limit) break
            val next = data[cursor].toInt() and 0xFF
            if (next == 0x80) {
                var trailing = cursor + 1
                while (trailing < limit && data[trailing].toInt() == 0) trailing++
                if (trailing != limit) return 0
                for (target in targets) {
                    for (i in target[0] until target[0] + target[1]) data[i] = 0xFF.toByte()
                }
                return targets.size
            }
        }
        return 0
    }

    private fun readSeiField(data: ByteArray, start: Int, limit: Int): Pair<Int, Int> {
        var value = 0
        var cursor = start
        var guard = 0
        while (cursor < limit && guard < 8) {
            val byte = data[cursor].toInt() and 0xFF
            value += byte
            cursor++
            guard++
            if (byte != 0xFF) return Pair(value, cursor)
        }
        return Pair(-1, start)
    }
}

/**
 * One video stream's payload concatenated across packets plus a segment table mapping every
 * byte of that view back to the source packet that holds it. Operating on the assembled
 * elementary stream is what makes SEI units that straddle a packet boundary visible; the
 * segment table maps the length-preserving neutralisation back onto the packets. Shared by
 * the MPEG-TS and MPEG-PS handlers.
 *
 * Each segment row is [esOffset, fileOffset, length, sourcePacketStart].
 */
private class EsStream(val codec: CodecUserData.Codec) {
    val bytes = ByteArrayOutputStream()
    val segments = ArrayList<LongArray>()
    var esLength = 0L

    fun append(payload: ByteArray, fileOffset: Long, sourcePacketStart: Long) {
        bytes.write(payload, 0, payload.size)
        segments.add(longArrayOf(esLength, fileOffset, payload.size.toLong(), sourcePacketStart))
        esLength += payload.size
    }
}

/** A run of changed bytes plus the source packet that must receive them. */
private class Patch(val sourcePacketStart: Long, val fileOffset: Long, val bytes: ByteArray)

private class Neutralised(val hits: Int, val patches: List<Patch>)

/**
 * Count SEI on the assembled view, neutralise in place (length preserving) and map the
 * changed bytes back through the segment table. Shared entry point for TS and PS scrubbing.
 */
private fun neutraliseAssembled(stream: EsStream, es: ByteArray, present: Int): Neutralised {
    if (present <= 0 || es.isEmpty()) return Neutralised(0, emptyList())
    val before = es.copyOf()
    val hits = CodecUserData.neutraliseAnnexB(es, stream.codec)
    val patches = if (hits > 0) patchesFor(before, es, stream.segments) else emptyList()
    return Neutralised(hits, patches)
}

/** Translate byte-level differences in the reconstructed view back to their source packets. */
private fun patchesFor(original: ByteArray, patched: ByteArray, segments: List<LongArray>): ArrayList<Patch> {
    val patches = ArrayList<Patch>()
    var segmentCursor = 0
    var i = 0
    while (i < original.size && i < patched.size) {
        if (original[i] == patched[i]) {
            i++
            continue
        }
        var j = i + 1
        while (j < original.size && j < patched.size && original[j] != patched[j]) j++
        var runStart = i
        while (runStart < j) {
            while (segmentCursor < segments.size &&
                runStart >= segments[segmentCursor][0] + segments[segmentCursor][2]
            ) {
                segmentCursor++
            }
            if (segmentCursor >= segments.size) break
            val segment = segments[segmentCursor]
            val esStart = segment[0].toInt()
            if (runStart < esStart) break // unmapped gap; cannot place this run
            val segmentEnd = esStart + segment[2].toInt()
            val end = minOf(j, segmentEnd)
            patches.add(
                Patch(segment[3], segment[1] + (runStart - esStart), patched.copyOfRange(runStart, end))
            )
            runStart = end
        }
        i = j
    }
    return patches
}

object MpegTsHandler : FormatHandler {

    override val id: String = "mpegts"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.MPEG_TS)

    private const val PAT_PID = 0x0000
    private const val EIT_PID = 0x0012
    private const val ATSC_PSIP_PID = 0x1FFB
    private const val SCAN_LIMIT = 32L shl 20

    private data class Layout(val packetSize: Int, val syncOffset: Int, val fecSize: Int)

    private data class Elementary(
        val streamType: Int,
        val pid: Int,
        val descriptorStart: Int,
        val descriptorLength: Int,
        val metadata: Boolean
    )

    private class Analysis(
        val layout: Layout,
        val metadataPids: Set<Int>,
        val videoPids: Map<Int, CodecUserData.Codec>,
        val pmtPids: Set<Int>,
        val pmtSections: Map<Int, ByteArray>
    )

    private fun detectLayout(io: BinaryIo): Layout? {
        val probeSize = minOf(4096L, io.length).toInt()
        if (probeSize < 4) return null
        val probe = io.peekAt(0, probeSize) ?: return null
        val candidates = listOf(
            Pair(188, 0), Pair(192, 4), Pair(204, 0)
        )
        for ((size, sync) in candidates) {
            var checked = 0
            var index = sync
            while (index < probe.size && checked < 8) {
                if (probe[index].toInt() and 0xFF != 0x47) break
                checked++
                index += size
            }
            if (checked >= 4) {
                val fec = if (size == 204) 16 else 0
                return Layout(size, sync, fec)
            }
        }
        return null
    }

    private fun parsePid(packet: ByteArray, base: Int): Int =
        ((packet[base + 1].toInt() and 0x1F) shl 8) or (packet[base + 2].toInt() and 0xFF)

    private fun payloadRange(packet: ByteArray, syncOffset: Int, limit: Int): IntRange? {
        val byte3 = packet[syncOffset + 3].toInt() and 0xFF
        val afc = (byte3 shr 4) and 0x03
        var cursor = syncOffset + 4
        if (afc == 2 || afc == 3) {
            if (cursor >= limit) return null
            val adaptationLength = packet[cursor].toInt() and 0xFF
            cursor += 1 + adaptationLength
        }
        if (afc == 1 || afc == 3) {
            if (cursor >= limit) return null
            return cursor until limit
        }
        return null
    }

    private fun sectionAt(packet: ByteArray, syncOffset: Int, limit: Int): ByteArray? {
        val range = payloadRange(packet, syncOffset, limit) ?: return null
        val start = range.first
        if (packet[start].toInt() and 0xFF == 0xFF) return null
        val pointerField = packet[start].toInt() and 0xFF
        val sectionStart = start + 1 + pointerField
        if (sectionStart + 3 > limit) return null
        val sectionLength = ((packet[sectionStart + 1].toInt() and 0x0F) shl 8) or
            (packet[sectionStart + 2].toInt() and 0xFF)
        val total = 3 + sectionLength
        if (sectionStart + total > limit) return null
        return packet.copyOfRange(sectionStart, sectionStart + total)
    }

    private fun programMapPids(pat: ByteArray): List<Int> {
        val pids = ArrayList<Int>()
        if (pat.size < 12 || (pat[0].toInt() and 0xFF) != 0x00) return pids
        val sectionLength = ((pat[1].toInt() and 0x0F) shl 8) or (pat[2].toInt() and 0xFF)
        val end = 3 + sectionLength - 4
        var cursor = 8
        while (cursor + 4 <= end && cursor + 4 <= pat.size) {
            val program = ((pat[cursor].toInt() and 0xFF) shl 8) or (pat[cursor + 1].toInt() and 0xFF)
            val pid = ((pat[cursor + 2].toInt() and 0x1F) shl 8) or (pat[cursor + 3].toInt() and 0xFF)
            if (program != 0) pids.add(pid)
            cursor += 4
        }
        return pids
    }

    private fun programElements(pmt: ByteArray): List<Elementary> {
        val elements = ArrayList<Elementary>()
        if (pmt.size < 16 || (pmt[0].toInt() and 0xFF) != 0x02) return elements
        val sectionLength = ((pmt[1].toInt() and 0x0F) shl 8) or (pmt[2].toInt() and 0xFF)
        val end = 3 + sectionLength - 4
        val programInfoLength = ((pmt[10].toInt() and 0x0F) shl 8) or (pmt[11].toInt() and 0xFF)
        var cursor = 12 + programInfoLength
        while (cursor + 5 <= end && cursor + 5 <= pmt.size) {
            val streamType = pmt[cursor].toInt() and 0xFF
            val pid = ((pmt[cursor + 1].toInt() and 0x1F) shl 8) or (pmt[cursor + 2].toInt() and 0xFF)
            val infoLength = ((pmt[cursor + 3].toInt() and 0x0F) shl 8) or (pmt[cursor + 4].toInt() and 0xFF)
            val descriptorStart = cursor + 5
            var metadata = streamType in 0x15..0x19
            if (streamType == 0x06 && infoLength > 0) {
                var d = descriptorStart
                val descriptorEnd = minOf(descriptorStart + infoLength, pmt.size)
                while (d + 2 <= descriptorEnd) {
                    val tag = pmt[d].toInt() and 0xFF
                    val length = pmt[d + 1].toInt() and 0xFF
                    if (tag == 0x25 || tag == 0x26) metadata = true
                    d += 2 + length
                }
            }
            elements.add(Elementary(streamType, pid, descriptorStart, infoLength, metadata))
            cursor = descriptorStart + infoLength
        }
        return elements
    }

    private fun crc32Mpeg(data: ByteArray, from: Int, to: Int): Long {
        var crc = 0xFFFFFFFFL
        for (i in from until to) {
            crc = crc xor ((data[i].toInt() and 0xFF).toLong() shl 24)
            for (bit in 0 until 8) {
                crc = if (crc and 0x80000000L != 0L) ((crc shl 1) xor 0x04C11DB7L) and 0xFFFFFFFFL
                else (crc shl 1) and 0xFFFFFFFFL
            }
        }
        return crc and 0xFFFFFFFFL
    }

    /**
     * Assemble one PSI section for [targetPid] starting at the packet that carries a
     * payload-unit-start, then keep consuming payload of subsequent packets of the same
     * PID until the section_length declared in the header is fully collected. PSI sections
     * routinely span several transport packets; a single-packet view would truncate them.
     * The assembled section is accepted only when its MPEG-2 CRC-32 verifies, so PAT/PMT
     * decisions never run over corrupted or partially collected bytes.
     */
    private fun collectSection(
        io: BinaryIo,
        layout: Layout,
        targetPid: Int,
        startOffset: Long,
        scanEnd: Long
    ): ByteArray? {
        val packetLimit = minOf(layout.packetSize, layout.syncOffset + 188)
        var offset = startOffset
        var assembled: ByteArray? = null
        var guard = 0
        while (offset + layout.packetSize <= scanEnd && guard++ < 512) {
            val packet = io.peekAt(offset, packetLimit) ?: return null
            if (packet.size < packetLimit || (packet[0].toInt() and 0xFF) != 0x47) return null
            if (parsePid(packet, 0) != targetPid) return null
            val startsSection = (packet[1].toInt() and 0x40) != 0
            val range = payloadRange(packet, layout.syncOffset, packetLimit) ?: return null
            if (range.last < range.first) {
                if (assembled != null) return null
                offset += layout.packetSize
                continue
            }
            if (assembled == null) {
                if (!startsSection) return null
                val pointerField = packet[range.first].toInt() and 0xFF
                val sectionStart = range.first + 1 + pointerField
                if (sectionStart > range.last) {
                    offset += layout.packetSize
                    continue
                }
                assembled = packet.copyOfRange(sectionStart, range.last + 1)
            } else {
                // A new payload-unit-start before our section finished means the stream
                // skipped ahead; collecting across that gap would fabricate bytes.
                if (startsSection) return null
                val part = packet.copyOfRange(range.first, range.last + 1)
                val merged = ByteArray(assembled.size + part.size)
                System.arraycopy(assembled, 0, merged, 0, assembled.size)
                System.arraycopy(part, 0, merged, assembled.size, part.size)
                assembled = merged
            }
            if (assembled.size < 3) {
                offset += layout.packetSize
                continue
            }
            val sectionLength =
                ((assembled[1].toInt() and 0x0F) shl 8) or (assembled[2].toInt() and 0xFF)
            val total = 3 + sectionLength
            if (total > 4096 + 1024) return null
            if (assembled.size >= total) {
                val section = assembled.copyOfRange(0, total)
                // Running the CRC-32/MPEG over the whole section must resolve to zero.
                return if (crc32Mpeg(section, 0, section.size) == 0L) section else null
            }
            offset += layout.packetSize
        }
        return null
    }

    private fun analyse(io: BinaryIo): Analysis? {
        val layout = detectLayout(io) ?: return null
        val length = io.length
        var pat: ByteArray? = null
        var offset = 0L
        val scanEnd = minOf(length, SCAN_LIMIT)
        val packetLimit = minOf(layout.packetSize, layout.syncOffset + 188)
        while (offset + layout.packetSize <= scanEnd) {
            val header = io.peekAt(offset, packetLimit) ?: break
            if (header.size < packetLimit || (header[0].toInt() and 0xFF) != 0x47) {
                offset += layout.packetSize
                continue
            }
            if (parsePid(header, 0) == PAT_PID) {
                val section = collectSection(io, layout, PAT_PID, offset, scanEnd)
                if (section != null) {
                    pat = section
                    break
                }
            }
            offset += layout.packetSize
        }
        val patSection = pat ?: return null
        val pmtPids = LinkedHashSet(programMapPids(patSection))
        if (pmtPids.isEmpty()) return null
        val sections = HashMap<Int, ByteArray>()
        offset = 0L
        while (offset + layout.packetSize <= scanEnd && sections.size < pmtPids.size) {
            val header = io.peekAt(offset, packetLimit) ?: break
            if (header.size >= packetLimit && (header[0].toInt() and 0xFF) == 0x47) {
                val pid = parsePid(header, 0)
                if (pmtPids.contains(pid) && !sections.containsKey(pid)) {
                    val section = collectSection(io, layout, pid, offset, scanEnd)
                    if (section != null) sections[pid] = section
                }
            }
            offset += layout.packetSize
        }
        val metadataPids = LinkedHashSet<Int>()
        val videoPids = LinkedHashMap<Int, CodecUserData.Codec>()
        for ((_, section) in sections) {
            for (element in programElements(section)) {
                if (element.metadata) {
                    metadataPids.add(element.pid)
                } else {
                    val codec = CodecUserData.codecFromStreamType(element.streamType)
                    if (codec != CodecUserData.Codec.UNKNOWN) videoPids[element.pid] = codec
                }
            }
        }
        return Analysis(layout, metadataPids, videoPids, pmtPids, sections)
    }

    private fun rebuildPmt(pmt: ByteArray, dropPids: Set<Int>): ByteArray? {
        if (pmt.size < 16) return null
        val sectionLength = ((pmt[1].toInt() and 0x0F) shl 8) or (pmt[2].toInt() and 0xFF)
        val end = 3 + sectionLength - 4
        val programInfoLength = ((pmt[10].toInt() and 0x0F) shl 8) or (pmt[11].toInt() and 0xFF)
        val head = pmt.copyOfRange(0, 12 + programInfoLength)
        val kept = ByteArrayOutputStream()
        var cursor = 12 + programInfoLength
        var count = 0
        while (cursor + 5 <= end && cursor + 5 <= pmt.size) {
            val pid = ((pmt[cursor + 1].toInt() and 0x1F) shl 8) or (pmt[cursor + 2].toInt() and 0xFF)
            val infoLength = ((pmt[cursor + 3].toInt() and 0x0F) shl 8) or (pmt[cursor + 4].toInt() and 0xFF)
            val total = 5 + infoLength
            if (cursor + total > pmt.size) return null
            if (!dropPids.contains(pid)) {
                kept.write(pmt, cursor, total)
                count++
            }
            cursor += total
        }
        if (count == 0) return null
        val body = head + kept.toByteArray()
        val newSectionLength = body.size - 3 + 4
        if (newSectionLength > 1021) return null
        val section = ByteArray(body.size + 4)
        System.arraycopy(body, 0, section, 0, body.size)
        section[1] = (0xB0 or ((newSectionLength shr 8) and 0x0F)).toByte()
        section[2] = (newSectionLength and 0xFF).toByte()
        val crc = crc32Mpeg(section, 0, section.size - 4)
        section[section.size - 4] = ((crc shr 24) and 0xFF).toByte()
        section[section.size - 3] = ((crc shr 16) and 0xFF).toByte()
        section[section.size - 2] = ((crc shr 8) and 0xFF).toByte()
        section[section.size - 1] = (crc and 0xFF).toByte()
        return section
    }

    private fun collectEs(io: BinaryIo, analysis: Analysis): HashMap<Int, EsStream> {
        val streams = HashMap<Int, EsStream>()
        val layout = analysis.layout
        val limit = minOf(layout.packetSize, layout.syncOffset + 188)
        val scanEnd = minOf(io.length, SCAN_LIMIT)
        var cursor = 0L
        val scratch = ByteArray(layout.packetSize)
        while (cursor + layout.packetSize <= scanEnd) {
            if (!io.peekInto(cursor, scratch)) break
            if ((scratch[0].toInt() and 0xFF) != 0x47) break
            val pid = parsePid(scratch, 0)
            val codec = analysis.videoPids[pid]
            if (codec != null) {
                val range = payloadRange(scratch, layout.syncOffset, limit)
                if (range != null && range.last >= range.first) {
                    val size = range.last + 1 - range.first
                    val payload = scratch.copyOfRange(range.first, range.last + 1)
                    streams.getOrPut(pid) { EsStream(codec) }
                        .append(payload, cursor + range.first, cursor)
                }
            }
            cursor += layout.packetSize
        }
        return streams
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                // Fail closed: a file that presents as transport-stream sync bytes but whose
                // PAT/PMT cannot be CRC-verified must never be reported as having no findings.
                val analysis = analyse(io)
                    ?: return listOf(
                        MetadataFinding(
                            MetadataKind.OTHER,
                            "not a parsable transport stream; program tables could not be verified"
                        )
                    )
                val dropPids = HashSet(analysis.metadataPids)
                if (options.stripBroadcastTables) {
                    dropPids.add(EIT_PID)
                    dropPids.add(ATSC_PSIP_PID)
                }
                for (pid in analysis.metadataPids) {
                    findings.add(MetadataFinding(MetadataKind.TELEMETRY, "metadata stream pid $pid"))
                }
                if (analysis.pmtSections.values.any {
                        val rebuilt = rebuildPmt(it, dropPids)
                        rebuilt != null && rebuilt.size != it.size
                    }
                ) {
                    findings.add(MetadataFinding(MetadataKind.TELEMETRY, "metadata entries in program map"))
                }
                var cursor = 0L
                var guidePackets = 0L
                val scanEnd = minOf(io.length, SCAN_LIMIT)
                val limit = minOf(analysis.layout.packetSize, analysis.layout.syncOffset + 188)
                val scratch = ByteArray(limit)
                while (cursor + analysis.layout.packetSize <= scanEnd) {
                    if (!io.peekInto(cursor, scratch)) break
                    val packet = scratch
                    if ((packet[0].toInt() and 0xFF) != 0x47) break
                    val pid = parsePid(packet, 0)
                    if (pid == EIT_PID || pid == ATSC_PSIP_PID) guidePackets++
                    cursor += analysis.layout.packetSize
                }
                if (guidePackets > 0) {
                    findings.add(MetadataFinding(MetadataKind.VIDEO_TAGS, "broadcast guide sections"))
                }
                // Count on the reconstructed elementary stream so SEI units split across
                // packet boundaries are reported with the same view scrub() neutralises.
                var seiHits = 0
                for ((_, stream) in collectEs(io, analysis)) {
                    seiHits += CodecUserData.countAnnexB(stream.bytes.toByteArray(), stream.codec)
                }
                if (seiHits > 0) {
                    findings.add(MetadataFinding(MetadataKind.TELEMETRY, "codec user data messages"))
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val removed = ArrayList<MetadataFinding>()
        val expected = ArrayList<MetadataFinding>()
        val buffer = Buffers.new()
        var dropped = 0L
        var seiHits = 0
        var seiKept = 0
        var guideKept = 0L
        try {
            BinaryIo.open(ctx.source).use { io ->
                val analysis = analyse(io)
                    ?: if (ctx.options.maximumPrivacy) {
                        throw PurgeRefusedException(
                            "transport stream program tables could not be CRC-verified; " +
                                "maximum privacy refuses to process the stream"
                        )
                    } else {
                        return ScrubOutcome(
                            false, PurgeStrategy.NONE, emptyList(),
                            message = "not a parsable transport stream"
                        )
                    }
                val layout = analysis.layout
                val limit = minOf(layout.packetSize, layout.syncOffset + 188)
                val dropPids = HashSet(analysis.metadataPids)
                if (ctx.options.stripBroadcastTables) {
                    dropPids.add(EIT_PID)
                    dropPids.add(ATSC_PSIP_PID)
                }
                val rebuiltPmts = HashMap<Int, ByteArray>()
                for ((pid, section) in analysis.pmtSections) {
                    val rebuilt = rebuildPmt(section, dropPids)
                    if (rebuilt != null && rebuilt.size < section.size) rebuiltPmts[pid] = rebuilt
                }
                // Reconstruct every video stream first: SEI units that straddle a packet
                // boundary are only visible in the assembled elementary stream (Problem #15).
                // Neutralisation is length preserving, so results map back onto the packets.
                val packetPatches = HashMap<Long, ArrayList<Pair<Int, ByteArray>>>()
                for ((_, stream) in collectEs(io, analysis)) {
                    ctx.checkCancelled()
                    val es = stream.bytes.toByteArray()
                    val present = CodecUserData.countAnnexB(es, stream.codec)
                    if (present == 0) continue
                    if (!ctx.options.stripCodecUserData) {
                        seiKept += present
                        continue
                    }
                    if (layout.fecSize != 0) {
                        // Rewriting FEC-protected payload without regenerating the parity
                        // would corrupt the stream; maximum privacy refuses instead of
                        // leaving codec user data in place silently.
                        if (ctx.options.maximumPrivacy) {
                            throw PurgeRefusedException(
                                "transport stream carries FEC-protected codec user data; " +
                                    "maximum privacy will not copy it through unverified"
                            )
                        }
                        seiKept += present
                        continue
                    }
                    val before = es.copyOf()
                    val result = neutraliseAssembled(stream, es, present)
                    if (result.hits > 0) {
                        seiHits += result.hits
                        for (patch in result.patches) {
                            val relative = (patch.fileOffset - patch.sourcePacketStart).toInt()
                            packetPatches.getOrPut(patch.sourcePacketStart) { ArrayList() }
                                .add(Pair(relative, patch.bytes))
                        }
                    } else {
                        // Reported by inspect but not removable by the neutraliser: keep the
                        // bytes and declare them so verification records an honest residual.
                        seiKept += present
                    }
                }
                val keepGuide = !ctx.options.stripBroadcastTables
                FileOutputStream(ctx.target).use { fileOut ->
                    val out = ProgressOut(fileOut, ctx)
                    var cursor = 0L
                    val scratch = ByteArray(layout.packetSize)
                    while (cursor + layout.packetSize <= io.length) {
                        ctx.checkCancelled()
                        if (!io.peekInto(cursor, scratch)) break
                        val packet = scratch
                        if (packet[0].toInt() and 0xFF != 0x47) break
                        val pid = parsePid(packet, 0)
                        if (keepGuide && (pid == EIT_PID || pid == ATSC_PSIP_PID)) guideKept++
                        if (dropPids.contains(pid)) {
                            dropped++
                            cursor += layout.packetSize
                            continue
                        }
                        val rebuilt = rebuiltPmts[pid]
                        if (rebuilt != null && (packet[1].toInt() and 0x40) != 0) {
                            val range = payloadRange(packet, layout.syncOffset, limit)
                            if (range != null) {
                                val pointerField = packet[range.first].toInt() and 0xFF
                                val sectionStart = range.first + 1 + pointerField
                                val original = sectionAt(packet, layout.syncOffset, limit)
                                val fitsSinglePacket = sectionStart + rebuilt.size <= limit
                                if (!fitsSinglePacket || original == null) {
                                    // The rewrite does not fit this packet alone, or the
                                    // original section spanned packets. Maximum privacy will
                                    // not emit a partially verified program map.
                                    if (ctx.options.maximumPrivacy) {
                                        throw PurgeRefusedException(
                                            "program map rewrite does not fit a single transport packet " +
                                                "or the original section spanned packets; maximum privacy " +
                                                "will not leave a partially rewritten PMT"
                                        )
                                    }
                                    // Compatibility: leave the packet untouched instead of
                                    // stuffing bytes we cannot replace; validation reports
                                    // any metadata entries that survive.
                                } else {
                                    // Stuff only the span this section occupied; a second section
                                    // can share the packet and must survive.
                                    val stop = minOf(limit, sectionStart + original.size)
                                    for (i in sectionStart until stop) packet[i] = 0xFF.toByte()
                                    System.arraycopy(rebuilt, 0, packet, sectionStart, rebuilt.size)
                                }
                            }
                        }
                        // Apply the SEI neutralisation computed on the reconstructed stream;
                        // patches are keyed by source packet offset and land payload-relative.
                        val patchesHere = packetPatches[cursor]
                        if (patchesHere != null) {
                            for ((relative, bytes) in patchesHere) {
                                for (k in bytes.indices) {
                                    val at = relative + k
                                    if (at >= 0 && at < packet.size) packet[at] = bytes[k]
                                }
                            }
                        }
                        out.write(packet)
                        cursor += layout.packetSize
                    }
                    if (cursor < io.length) {
                        io.copyRange(cursor, io.length - cursor, out, buffer)
                    }
                    out.tail()
                    out.flush()
                }
                for (pid in analysis.metadataPids) {
                    removed.add(MetadataFinding(MetadataKind.TELEMETRY, "metadata stream pid $pid"))
                }
                if (ctx.options.stripBroadcastTables && dropped > 0) {
                    removed.add(MetadataFinding(MetadataKind.VIDEO_TAGS, "broadcast guide sections"))
                }
                if (rebuiltPmts.values.any { rebuilt -> analysis.pmtSections.values.any { it.size != rebuilt.size } }) {
                    removed.add(MetadataFinding(MetadataKind.TELEMETRY, "metadata entries in program map"))
                }
                if (seiHits > 0) {
                    removed.add(MetadataFinding(MetadataKind.TELEMETRY, "codec user data messages"))
                }
                if (seiKept > 0) expected.add(MetadataFinding(MetadataKind.TELEMETRY, "codec user data messages"))
                if (guideKept > 0) expected.add(MetadataFinding(MetadataKind.VIDEO_TAGS, "broadcast guide sections"))
            }
        } catch (refused: PurgeRefusedException) {
            throw refused
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "transport stream rewrite failed")
        }
        if (removed.isEmpty()) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable markers")
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), expected.distinct(), true)
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val analysis = analyse(io) ?: return false
                val layout = analysis.layout
                val limit = minOf(layout.packetSize, layout.syncOffset + 188)
                if (io.length < layout.packetSize.toLong() * 4L) return false
                var cursor = 0L
                var packets = 0L
                val scratch = ByteArray(limit)
                while (cursor + layout.packetSize <= io.length) {
                    if (!io.peekInto(cursor, scratch)) return false
                    val packet = scratch
                    if ((packet[0].toInt() and 0xFF) != 0x47) return false
                    val pid = parsePid(packet, 0)
                    if (options.stripBroadcastTables && (pid == EIT_PID || pid == ATSC_PSIP_PID)) return false
                    if (analysis.metadataPids.contains(pid)) return false
                    packets++
                    cursor += layout.packetSize
                }
                if (packets < 4) return false
                // When codec user data must be gone, verify it through the same
                // reconstructed-stream view the scrubber used.
                if (options.stripCodecUserData && analysis.layout.fecSize == 0) {
                    for ((_, stream) in collectEs(io, analysis)) {
                        if (CodecUserData.countAnnexB(stream.bytes.toByteArray(), stream.codec) > 0) {
                            return false
                        }
                    }
                }
                val dropPids = HashSet(analysis.metadataPids)
                if (options.stripBroadcastTables) {
                    dropPids.add(EIT_PID)
                    dropPids.add(ATSC_PSIP_PID)
                }
                for ((_, section) in analysis.pmtSections) {
                    if (dropPids.isEmpty()) continue
                    val rebuilt = rebuildPmt(section, dropPids)
                    if (rebuilt != null) {
                        for (element in programElements(section)) {
                            if (dropPids.contains(element.pid)) return false
                        }
                    }
                }
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}

object MpegPsHandler : FormatHandler {

    override val id: String = "mpegps"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.MPEG_PS)

    private const val PACK_START = 0xBA
    private const val SYSTEM_HEADER = 0xBB
    private const val PADDING_STREAM = 0xBE
    private const val PRIVATE_STREAM_1 = 0xBD
    private const val METADATA_STREAM = 0xFC
    private const val PROGRAM_END = 0xB9

    /** Bounds for the assembled elementary-stream view (one absurd PES cannot exhaust memory). */
    private const val MAX_PES_PAYLOAD = 4L shl 20
    private const val MAX_ES_ASSEMBLED = 64L shl 20
    private val klvPrefix = byteArrayOf(0x06, 0x0E, 0x2B, 0x34, 0x02, 0x0B, 0x01, 0x01)

    private data class Packet(val start: Long, val size: Long, val streamId: Int, val payloadStart: Long, val payloadSize: Long)

    private fun parsePackets(io: BinaryIo): List<Packet>? {
        val packets = ArrayList<Packet>()
        val length = io.length
        var cursor = 0L
        var guard = 0
        while (cursor + 4L <= length && guard < 4_000_000) {
            val head = io.peekAt(cursor, 4) ?: break
            if (head[0].toInt() != 0 || head[1].toInt() != 0 || head[2].toInt() != 1) {
                val resync = resyncToStartCode(io, cursor)
                if (resync < 0L) break
                cursor = resync
                continue
            }
            guard++
            val code = head[3].toInt() and 0xFF
            if (code == PROGRAM_END) {
                packets.add(Packet(cursor, 4L, code, cursor + 4L, 0L))
                cursor += 4L
                continue
            }
            when {
                code == PACK_START -> {
                    val probe = io.peekAt(cursor + 4L, 12) ?: break
                    val mpeg2 = (probe[0].toInt() and 0xC0) == 0x40
                    var headerSize = if (mpeg2) 14L else 12L
                    if (mpeg2) {
                        val stuffing = probe[11].toInt() and 0x07
                        headerSize += stuffing
                    }
                    if (!io.inRange(cursor, headerSize)) break
                    packets.add(Packet(cursor, headerSize, PACK_START, cursor + 4L, headerSize - 4L))
                    cursor += headerSize
                }
                code == SYSTEM_HEADER -> {
                    val probe = io.peekAt(cursor + 4L, 2) ?: break
                    val size = ((probe[0].toInt() and 0xFF) shl 8) or (probe[1].toInt() and 0xFF)
                    val total = 6L + size
                    if (!io.inRange(cursor, total)) break
                    packets.add(Packet(cursor, total, SYSTEM_HEADER, cursor + 6L, size.toLong()))
                    cursor += total
                }
                else -> {
                    val probe = io.peekAt(cursor + 4L, 2) ?: break
                    val declared = ((probe[0].toInt() and 0xFF) shl 8) or (probe[1].toInt() and 0xFF)
                    val payloadStart = cursor + 6L
                    var payloadSize = declared.toLong()
                    if (declared == 0) {
                        payloadSize = nextStartCode(io, cursor + 6L) - payloadStart
                    }
                    if (payloadSize < 0L || !io.inRange(cursor + 6L, payloadSize)) break
                    packets.add(Packet(cursor, 6L + payloadSize, code, payloadStart, payloadSize))
                    cursor = payloadStart + payloadSize
                }
            }
            if (cursor > length) break
        }
        if (packets.isEmpty()) return null
        return packets
    }

    private fun resyncToStartCode(io: BinaryIo, from: Long): Long {
        // The search window is a mebibyte, so it has to be walked in chunks: probing only the
        // first 4 KiB gave up on the first large gap and silently dropped the rest of the stream.
        val limit = minOf(io.length, from + (1L shl 20))
        val chunk = 64 * 1024
        var position = from
        while (position < limit) {
            val size = minOf(limit - position, chunk.toLong()).toInt()
            if (size < 3) break
            val probe = io.peekAt(position, size) ?: break
            var index = 0
            while (index + 3 <= probe.size) {
                if (probe[index].toInt() == 0 && probe[index + 1].toInt() == 0 && probe[index + 2].toInt() == 1) {
                    return position + index
                }
                index++
            }
            // Step back two bytes so a start code straddling the chunk edge is still found.
            position += size - 2
        }
        return -1L
    }

    /**
     * Next container-level start code: only ids >= 0xB9 count. Inside an unbounded
     * (declared-length 0) PES the elementary stream's own start codes — H.264/HEVC NAL
     * headers are always < 0x80 and MPEG video start codes top out at 0xB8 — must NOT
     * be mistaken for the boundary, or the packet ends after two bytes and the rest of
     * the stream (including any SEI user data) is misparsed away.
     */
    private fun nextStartCode(io: BinaryIo, from: Long): Long {
        val buffer = Buffers.new()
        io.seek(from)
        var position = from
        var carry1 = -1
        var carry2 = -1
        while (position < io.length) {
            val chunk = minOf(buffer.size.toLong(), io.length - position).toInt()
            if (!io.readFully(buffer, 0, chunk)) break
            for (i in 0 until chunk) {
                val value = buffer[i].toInt() and 0xFF
                if (carry1 == 0 && carry2 == 0 && value == 1) {
                    val id = io.peekAt(position + i + 1L, 1)?.get(0)?.toInt()?.and(0xFF) ?: 0xFF
                    if (id >= 0xB9) return position + i - 2
                }
                carry1 = carry2
                carry2 = value
            }
            position += chunk
        }
        return io.length
    }

    private fun isKlvPayload(io: BinaryIo, payloadStart: Long, payloadSize: Long): Boolean {
        if (payloadSize < 20L) return false
        val probe = io.peekAt(payloadStart, minOf(payloadSize, 96L).toInt()) ?: return false
        var index = 0
        while (index + klvPrefix.size <= probe.size) {
            var match = true
            for (i in klvPrefix.indices) {
                if (probe[index + i] != klvPrefix[i]) {
                    match = false
                    break
                }
            }
            if (match) return true
            index++
        }
        return false
    }

    private fun sniffCodec(io: BinaryIo, packets: List<Packet>): CodecUserData.Codec {
        var scanned = 0
        for (packet in packets) {
            if (packet.streamId !in 0xE0..0xEF) continue
            scanned++
            if (scanned > 12) break
            val size = minOf(packet.payloadSize, 4096L).toInt()
            if (size <= 8) continue
            val probe = io.peekAt(packet.payloadStart, size) ?: continue
            val copy = probe.copyOf()
            if (CodecUserData.countAnnexB(copy, CodecUserData.Codec.H264) > 0) return CodecUserData.Codec.H264
            var index = 0
            while (index + 4 < copy.size) {
                if (copy[index].toInt() == 0 && copy[index + 1].toInt() == 0 && copy[index + 2].toInt() == 1) {
                    val header = copy[index + 3].toInt() and 0xFF
                    val h264 = header and 0x1F
                    val hevc = (header shr 1) and 0x3F
                    if (h264 == 7 || h264 == 8 || h264 == 5 || h264 == 1) return CodecUserData.Codec.H264
                    if (hevc == 32 || hevc == 33 || hevc == 34 || hevc == 19 || hevc == 1) {
                        return CodecUserData.Codec.HEVC
                    }
                }
                index++
            }
        }
        return CodecUserData.Codec.UNKNOWN
    }

    /**
     * Concatenate every video PES payload into one buffer — the same assembled-stream view
     * the TS handler uses — so SEI units split across PES boundaries become visible to
     * counting, neutralisation and validation alike.
     */
    private fun buildVideoEs(io: BinaryIo, packets: List<Packet>, codec: CodecUserData.Codec): EsStream {
        val stream = EsStream(codec)
        for (packet in packets) {
            if (packet.streamId !in 0xE0..0xEF) continue
            if (packet.payloadSize <= 0L || packet.payloadSize > MAX_PES_PAYLOAD) continue
            if (stream.esLength >= MAX_ES_ASSEMBLED) break
            val payload = io.peekAt(packet.payloadStart, packet.payloadSize.toInt()) ?: continue
            stream.append(payload, packet.payloadStart, packet.start)
        }
        return stream
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                val packets = parsePackets(io) ?: return emptyList()
                if (packets.none { it.streamId == METADATA_STREAM } && packets.none { it.streamId == PRIVATE_STREAM_1 } &&
                    sniffCodec(io, packets) == CodecUserData.Codec.UNKNOWN
                ) {
                    return findings
                }
                for (packet in packets) {
                    if (packet.streamId == METADATA_STREAM) {
                        findings.add(MetadataFinding(MetadataKind.TELEMETRY, "metadata stream packet"))
                    }
                    if (packet.streamId == PRIVATE_STREAM_1 && isKlvPayload(io, packet.payloadStart, packet.payloadSize)) {
                        findings.add(MetadataFinding(MetadataKind.TELEMETRY, "smpte key length value payload"))
                    }
                }
                val codec = sniffCodec(io, packets)
                if (codec != CodecUserData.Codec.UNKNOWN) {
                    // Assembled view: an SEI split across two PES packets is still one message
                    // and must be reported even when each half alone looks like plain data.
                    val stream = buildVideoEs(io, packets, codec)
                    if (CodecUserData.countAnnexB(stream.bytes.toByteArray(), codec) > 0) {
                        findings.add(MetadataFinding(MetadataKind.TELEMETRY, "codec user data messages"))
                    }
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val removed = ArrayList<MetadataFinding>()
        val expected = ArrayList<MetadataFinding>()
        val buffer = Buffers.new()
        var seiHits = 0
        var seiKept = 0
        var dropped = 0
        try {
            BinaryIo.open(ctx.source).use { io ->
                val packets = parsePackets(io)
                    ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a parsable program stream")
                val codec = sniffCodec(io, packets)
                // Assemble the video elementary stream first (shared with the TS path) so SEI
                // units split across PES boundaries are neutralised, not merely counted.
                val packetPatches = HashMap<Long, ArrayList<Pair<Int, ByteArray>>>()
                if (codec != CodecUserData.Codec.UNKNOWN) {
                    val stream = buildVideoEs(io, packets, codec)
                    val es = stream.bytes.toByteArray()
                    val present = CodecUserData.countAnnexB(es, codec)
                    if (present > 0) {
                        if (!ctx.options.stripCodecUserData) {
                            seiKept += present
                        } else {
                            val result = neutraliseAssembled(stream, es, present)
                            if (result.hits > 0) {
                                seiHits += result.hits
                                for (patch in result.patches) {
                                    val relative = (patch.fileOffset - patch.sourcePacketStart).toInt()
                                    packetPatches.getOrPut(patch.sourcePacketStart) { ArrayList() }
                                        .add(Pair(relative, patch.bytes))
                                }
                            } else {
                                seiKept += present
                            }
                        }
                    }
                }
                FileOutputStream(ctx.target).use { fileOut ->
                    val out = ProgressOut(fileOut, ctx)
                    for (packet in packets) {
                        ctx.checkCancelled()
                        if (packet.streamId == METADATA_STREAM) {
                            removed.add(MetadataFinding(MetadataKind.TELEMETRY, "metadata stream packet"))
                            dropped++
                            continue
                        }
                        if (packet.streamId == PRIVATE_STREAM_1 &&
                            isKlvPayload(io, packet.payloadStart, packet.payloadSize)
                        ) {
                            removed.add(MetadataFinding(MetadataKind.TELEMETRY, "smpte key length value payload"))
                            dropped++
                            continue
                        }
                        // Apply the SEI neutralisation computed on the assembled stream; patches
                        // are keyed by their source packet and land at payload-relative offsets.
                        val patchesHere = packetPatches[packet.start]
                        if (patchesHere != null && packet.size in 1..(32L shl 20)) {
                            val full = io.peekAt(packet.start, packet.size.toInt())
                            if (full != null) {
                                for ((relative, bytes) in patchesHere) {
                                    for (k in bytes.indices) {
                                        val at = relative + k
                                        if (at >= 0 && at < full.size) full[at] = bytes[k]
                                    }
                                }
                                out.write(full)
                                continue
                            }
                        }
                        io.copyRange(packet.start, packet.size, out, buffer)
                    }
                    val last = packets.last()
                    val consumed = last.start + last.size
                    if (consumed < io.length) {
                        io.copyRange(consumed, io.length - consumed, out, buffer)
                    }
                    out.tail()
                    out.flush()
                }
                if (seiHits > 0) removed.add(MetadataFinding(MetadataKind.TELEMETRY, "codec user data messages"))
                if (seiKept > 0) expected.add(MetadataFinding(MetadataKind.TELEMETRY, "codec user data messages"))
            }
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "program stream rewrite failed")
        }
        if (removed.isEmpty()) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable markers")
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), expected.distinct(), true)
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val packets = parsePackets(io) ?: return false
                if (packets.size < 3) return false
                @Suppress("UNUSED_EXPRESSION")
                var sawVideo = false
                for (packet in packets) {
                    if (packet.streamId == METADATA_STREAM) return false
                    if (packet.streamId == PRIVATE_STREAM_1 && isKlvPayload(io, packet.payloadStart, packet.payloadSize)) {
                        return false
                    }
                    if (packet.streamId in 0xE0..0xEF) sawVideo = true
                }
                if (!sawVideo) return false
                val codec = sniffCodec(io, packets)
                if (options.stripCodecUserData && codec != CodecUserData.Codec.UNKNOWN) {
                    // Same assembled view the scrubber used: a split SEI must not survive.
                    val stream = buildVideoEs(io, packets, codec)
                    if (CodecUserData.countAnnexB(stream.bytes.toByteArray(), codec) > 0) return false
                }
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}
