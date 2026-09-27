package com.example.lock.metadata

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream

object AsfHandler : FormatHandler {

    override val id: String = "asf"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.ASF)

    private val headerGuid = guid("3026B2758E66CF11A6D900AA0062CE6C")
    private val dataGuid = guid("3626B2758E66CF11A6D900AA0062CE6C")
    private val filePropertiesGuid = guid("A1DCAB8C47A9CF118EE400C00C205365")
    private val headerExtensionGuid = guid("B503BF5F2EA9CF118EE300C00C205365")
    private val contentDescriptionGuid = guid("3326B2758E66CF11A6D900AA0062CE6C")
    private val extendedContentDescriptionGuid = guid("40A4D0D207E3D21197F000A0C95EA850")
    private val metadataGuid = guid("EACBF8C5AF5B77488467AA8C44FA4CCA")
    private val metadataLibraryGuid = guid("941C23449894D149A1411D134E457054")
    private val codecListGuid = guid("4052D1861DD311D0A3A400A0C90348F6")

    private class Banned(val guid: ByteArray, val kind: MetadataKind, val label: String)

    private val banned = listOf(
        Banned(contentDescriptionGuid, MetadataKind.DOCUMENT_PROPERTY, "content description"),
        Banned(extendedContentDescriptionGuid, MetadataKind.DOCUMENT_PROPERTY, "extended content description"),
        Banned(metadataGuid, MetadataKind.VIDEO_TAGS, "metadata object"),
        Banned(metadataLibraryGuid, MetadataKind.VIDEO_TAGS, "metadata library object"),
        // Purely informational: each entry carries a codec name, a description and a free text
        // information string that routinely names the muxer build. No player requires it.
        Banned(codecListGuid, MetadataKind.SOFTWARE, "codec list object")
    )

    private data class AsfObject(val guid: ByteArray, val start: Long, val size: Long) {
        val bodyStart: Long get() = start + 24L
        val bodySize: Long get() = size - 24L
    }

    private fun guid(hex: String): ByteArray {
        val out = ByteArray(16)
        for (i in 0 until 16) out[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    private fun same(a: ByteArray, b: ByteArray): Boolean {
        if (a.size < 16 || b.size < 16) return false
        for (i in 0 until 16) if (a[i] != b[i]) return false
        return true
    }

    private fun bannedFor(source: ByteArray): Banned? {
        for (entry in banned) if (same(source, entry.guid)) return entry
        return null
    }

    private fun readObject(io: BinaryIo, start: Long): AsfObject? {
        val head = io.peekAt(start, 24) ?: return null
        val size = Bytes.u64le(head, 16)
        if (size < 24L || !io.inRange(start, size)) return null
        return AsfObject(head.copyOfRange(0, 16), start, size)
    }

    private fun listObjects(io: BinaryIo, from: Long, to: Long): List<AsfObject> {
        val objects = ArrayList<AsfObject>()
        var cursor = from
        while (cursor + 24L <= to) {
            val obj = readObject(io, cursor) ?: break
            if (obj.start + obj.size > to) break
            objects.add(obj)
            cursor = obj.start + obj.size
        }
        return objects
    }

    private fun extensionChildren(io: BinaryIo, extension: AsfObject): List<AsfObject> {
        val body = extension.bodyStart
        val raw = io.peekAt(body, 22) ?: return emptyList()
        val dataSize = Bytes.u32le(raw, 18)
        val childrenStart = body + 22L
        if (!io.inRange(childrenStart, dataSize)) return emptyList()
        return listObjects(io, childrenStart, childrenStart + dataSize)
    }

    private fun copyRange(io: BinaryIo, offset: Long, size: Long, out: OutputStream, buffer: ByteArray): Long {
        io.seek(offset)
        var remaining = size
        var total = 0L
        while (remaining > 0L) {
            val chunk = minOf(remaining, buffer.size.toLong()).toInt()
            if (!io.readFully(buffer, 0, chunk)) break
            out.write(buffer, 0, chunk)
            remaining -= chunk
            total += chunk
        }
        return total
    }

    private fun inspectObjects(io: BinaryIo, objects: List<AsfObject>, findings: MutableList<MetadataFinding>) {
        for (obj in objects) {
            val entry = bannedFor(obj.guid)
            if (entry != null) {
                findings.add(MetadataFinding(entry.kind, entry.label))
                continue
            }
            if (same(obj.guid, headerExtensionGuid)) {
                inspectObjects(io, extensionChildren(io, obj), findings)
            }
        }
    }

    private fun readHeader(io: BinaryIo): Pair<Long, List<AsfObject>>? {
        if (io.length < 30L) return null
        val head = io.peekAt(0, 30) ?: return null
        if (!same(head, headerGuid)) return null
        val headerSize = Bytes.u64le(head, 16)
        if (headerSize < 30L || headerSize > io.length) return null
        val objects = listObjects(io, 30L, headerSize)
        if (objects.isEmpty()) return null
        return Pair(headerSize, objects)
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                val header = readHeader(io) ?: return emptyList()
                inspectObjects(io, header.second, findings)
                for (obj in header.second) {
                    if (same(obj.guid, filePropertiesGuid) && obj.bodySize >= 80L) {
                        val body = io.peekAt(obj.bodyStart, 80) ?: continue
                        if (body.copyOfRange(0, 16).any { it.toInt() != 0 }) {
                            findings.add(MetadataFinding(MetadataKind.UNIQUE_ID, "file id guid"))
                        }
                        if (Bytes.u64le(body, 24) != 0L) {
                            findings.add(MetadataFinding(MetadataKind.TIMESTAMP, "creation date"))
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val removed = ArrayList<MetadataFinding>()
                val buffer = Buffers.new()
        val fileId = ByteArray(16)
        var fileIdOffset = -1L
        var fileSizeOffset = -1L
        var creationDateOffset = -1L
        var dataIdOffset = -1L
        try {
            BinaryIo.open(ctx.source).use { io ->
                val header = readHeader(io)
                    ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "unreadable ASF header")
                val headerSize = header.first
                val objects = header.second
                val kept = ArrayList<AsfObject>()
                for (obj in objects) {
                    ctx.checkCancelled()
                    val entry = bannedFor(obj.guid)
                    if (entry != null) {
                        removed.add(MetadataFinding(entry.kind, entry.label))
                    } else {
                        kept.add(obj)
                    }
                }
                for (obj in objects) {
                    if (!same(obj.guid, filePropertiesGuid) || obj.bodySize < 80L) continue
                    val props = io.peekAt(obj.bodyStart, 80) ?: continue
                    if (props.copyOfRange(0, 16).any { it.toInt() != 0 }) {
                        removed.add(MetadataFinding(MetadataKind.UNIQUE_ID, "file id guid"))
                    }
                    if (Bytes.u64le(props, 24) != 0L) {
                        removed.add(MetadataFinding(MetadataKind.TIMESTAMP, "creation date"))
                    }
                }
                if (kept.isEmpty()) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "header would lose all objects")
                }
                FileOutputStream(ctx.target).use { fileOut ->
                    val out = ProgressOut(fileOut, ctx)
                    val body = ByteArrayOutputStream(1 shl 18)
                    for (obj in kept) {
                        if (same(obj.guid, headerExtensionGuid)) {
                            val raw = io.peekAt(obj.bodyStart, 22)
                            if (raw != null) {
                                val nested = ByteArrayOutputStream(1 shl 18)
                                var count = 0
                                for (child in extensionChildren(io, obj)) {
                                    val childEntry = bannedFor(child.guid)
                                    if (childEntry != null) {
                                        removed.add(MetadataFinding(childEntry.kind, childEntry.label))
                                        continue
                                    }
                                    copyRange(io, child.start, child.size, nested, buffer)
                                    count++
                                }
                                if (count > 0) {
                                    val nestedBytes = nested.toByteArray()
                                    val wrapper = ByteArrayOutputStream(22 + nestedBytes.size)
                                    wrapper.write(raw.copyOfRange(0, 18))
                                    val sizeField = ByteArray(4)
                                    Bytes.putU32le(sizeField, 0, nestedBytes.size.toLong())
                                    wrapper.write(sizeField)
                                    wrapper.write(nestedBytes)
                                    body.write(obj.guid)
                                    val size = ByteArray(8)
                                    Bytes.putU64le(size, 0, wrapper.size().toLong() + 24L)
                                    body.write(size)
                                    body.write(wrapper.toByteArray())
                                    continue
                                }
                                removed.add(MetadataFinding(MetadataKind.OTHER, "empty header extension"))
                                continue
                            }
                        }
                        val objectOffset = out.written + 30L + body.size() + 24L
                        if (same(obj.guid, filePropertiesGuid)) {
                            fileIdOffset = objectOffset
                            fileSizeOffset = objectOffset + 16L
                            creationDateOffset = objectOffset + 24L
                        }
                        copyRange(io, obj.start, obj.size, body, buffer)
                    }
                    val bodyBytes = body.toByteArray()
                    val head = ByteArrayOutputStream(30)
                    head.write(headerGuid)
                    val headSize = ByteArray(8)
                    Bytes.putU64le(headSize, 0, bodyBytes.size.toLong() + 30L)
                    head.write(headSize)
                    val count = ByteArray(4)
                    Bytes.putU32le(count, 0, countObjects(bodyBytes).toLong())
                    head.write(count)
                    head.write(byteArrayOf(0x01, 0x02))
                    out.write(head.toByteArray())
                    out.write(bodyBytes)
                    var written = out.written
                    var cursor = headerSize
                    while (cursor + 24L <= io.length) {
                        val obj = readObject(io, cursor)
                        if (obj == null) {
                            written += copyRange(io, cursor, io.length - cursor, out, buffer)
                            break
                        }
                        if (same(obj.guid, dataGuid)) {
                            dataIdOffset = written + 24L
                            val dataId = io.peekAt(obj.bodyStart, 16)
                            if (dataId != null && dataId.any { it.toInt() != 0 }) {
                                removed.add(MetadataFinding(MetadataKind.UNIQUE_ID, "data object id guid"))
                            }
                        }
                        written += copyRange(io, obj.start, obj.size, out, buffer)
                        cursor = obj.start + obj.size
                    }
                    out.tail()
                    out.flush()
                }
                if (removed.isEmpty()) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable markers")
                }
                BinaryIo.openReadWrite(ctx.target).use { out ->
                    if (fileIdOffset > 0) out.writeAt(fileIdOffset, fileId)
                    if (fileSizeOffset > 0) out.writeAt(fileSizeOffset, Bytes.u64leBytes(ctx.target.length()))
                    if (creationDateOffset > 0) out.writeZeros(creationDateOffset, 8L)
                    if (dataIdOffset > 0) out.writeAt(dataIdOffset, fileId)
                    out.fsync()
                }
            }
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "asf rewrite failed")
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
    }

    private fun countObjects(bytes: ByteArray): Int {
        var cursor = 0
        var count = 0
        while (cursor + 24 <= bytes.size) {
            val size = Bytes.u64le(bytes, cursor + 16)
            if (size < 24L || cursor + size > bytes.size) break
            count++
            cursor += size.toInt()
        }
        return count
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val header = readHeader(io) ?: return false
                val head = io.peekAt(0, 30) ?: return false
                if (Bytes.u32le(head, 24).toLong() != header.second.size.toLong()) return false
                var sawData = false
                var cursor = header.first
                while (cursor + 24L <= io.length) {
                    val obj = readObject(io, cursor) ?: return false
                    if (same(obj.guid, dataGuid)) {
                        val body = io.peekAt(obj.bodyStart, 26) ?: return false
                        if (Bytes.u64le(body, 16) == 0L && Bytes.u16le(body, 24) == 0) return false
                        sawData = true
                    }
                    if (bannedFor(obj.guid) != null) return false
                    cursor = obj.start + obj.size
                }
                for (obj in header.second) {
                    if (bannedFor(obj.guid) != null) return false
                    if (same(obj.guid, filePropertiesGuid) && obj.bodySize >= 80L) {
                        val props = io.peekAt(obj.bodyStart, 80) ?: return false
                        if (props.copyOfRange(0, 16).any { it.toInt() != 0 }) return false
                        if (Bytes.u64le(props, 24) != 0L) return false
                    }
                    if (same(obj.guid, headerExtensionGuid)) {
                        for (child in extensionChildren(io, obj)) {
                            if (bannedFor(child.guid) != null) return false
                        }
                    }
                }
                sawData
            }
        } catch (_: Exception) {
            false
        }
    }
}

object FlvHandler : FormatHandler {

    override val id: String = "flv"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.FLV)

    private const val TAG_AUDIO = 8
    private const val TAG_VIDEO = 9
    private const val TAG_SCRIPT = 18
    private const val MAX_SCRIPT_PROBE = 1 shl 20

    private data class Tag(val type: Int, val start: Long, val size: Long, val dataStart: Long, val dataSize: Long)

    private fun parseTags(io: BinaryIo): List<Tag>? {
        val length = io.length
        if (length < 13L) return null
        val head = io.peekAt(0, 9) ?: return null
        if (head[0] != 'F'.code.toByte() || head[1] != 'L'.code.toByte() || head[2] != 'V'.code.toByte()) return null
        val dataOffset = Bytes.u32be(head, 5)
        if (dataOffset < 9L || dataOffset > length) return null
        val tags = ArrayList<Tag>()
        var cursor = dataOffset
        val first = io.peekAt(cursor, 4) ?: return null
        if (Bytes.u32be(first, 0) != 0L) return null
        cursor += 4L
        while (cursor + 11L <= length) {
            val header = io.peekAt(cursor, 11) ?: break
            val type = header[0].toInt() and 0xFF
            val dataSize = ((header[1].toInt() and 0xFF) shl 16) or
                ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
            val total = 11L + dataSize + 4L
            if (!io.inRange(cursor, total)) break
            tags.add(Tag(type, cursor, total, cursor + 11L, dataSize.toLong()))
            cursor += total
        }
        if (tags.isEmpty()) return null
        return tags
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                val tags = parseTags(io) ?: return emptyList()
                for (tag in tags) {
                    if (tag.type == TAG_SCRIPT) {
                        val probe = io.peekAt(tag.dataStart, minOf(tag.dataSize, 96L).toInt())
                        val name = probe?.let { amfName(it) } ?: ""
                        val plan = if (tag.dataSize <= MAX_SCRIPT_PROBE) {
                            io.peekAt(tag.dataStart, tag.dataSize.toInt())?.let { planMetaData(it) }
                        } else {
                            null
                        }
                        if (plan != null && plan.removedNames.isEmpty()) continue
                        findings.add(
                            MetadataFinding(
                                MetadataKind.VIDEO_TAGS,
                                if (name.isEmpty()) "script data tag" else "script data tag ($name)"
                            )
                        )
                    } else if (tag.type != TAG_AUDIO && tag.type != TAG_VIDEO) {
                        findings.add(MetadataFinding(MetadataKind.OTHER, "unknown tag type ${tag.type}"))
                    }
                }
                val last = tags.last()
                val end = last.start + last.size
                if (end < io.length) {
                    findings.add(MetadataFinding(MetadataKind.OTHER, "trailing bytes after last tag"))
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    private fun amfName(data: ByteArray): String {
        if (data.size < 3) return ""
        if (data[0] != 0x02.toByte()) return ""
        val length = Bytes.u16be(data, 1)
        if (length <= 0 || 3 + length > data.size) return ""
        return Bytes.asciiAt(data, 3, length)
    }

    private class AmfProperty(val name: String, val start: Int, val end: Int)

    private val technicalKeys = setOf(
        "duration", "filesize", "width", "height", "videodatarate", "framerate", "videocodecid",
        "audiodatarate", "audiosamplerate", "audiosamplesize", "audiocodecid", "stereo",
        "hasvideo", "hasaudio", "hasmetadata", "haskeyframes", "keyframes", "lastkeyframetimestamp",
        "lasttimestamp", "videoframerate"
    )

    private fun skipAmfValue(data: ByteArray, start: Int, depth: Int): Int {
        if (depth > 8 || start >= data.size) return -1
        val type = data[start].toInt() and 0xFF
        var cursor = start + 1
        return when (type) {
            0x00 -> cursor + 8
            0x01 -> cursor + 1
            0x02 -> {
                if (cursor + 2 > data.size) -1 else cursor + 2 + Bytes.u16be(data, cursor)
            }
            0x03 -> skipAmfObject(data, cursor, depth + 1)
            0x05, 0x06 -> cursor
            0x07 -> cursor + 2
            0x08 -> {
                if (cursor + 4 > data.size) -1 else skipAmfObject(data, cursor + 4, depth + 1)
            }
            0x09 -> -1
            0x0A -> {
                if (cursor + 4 > data.size) {
                    -1
                } else {
                    var count = Bytes.u32be(data, cursor).toInt()
                    var at = cursor + 4
                    while (count > 0 && at > 0) {
                        at = skipAmfValue(data, at, depth + 1)
                        count--
                    }
                    at
                }
            }
            0x0B -> cursor + 10
            0x0C -> {
                if (cursor + 4 > data.size) -1 else cursor + 4 + Bytes.u32be(data, cursor).toInt()
            }
            else -> -1
        }
    }

    private fun skipAmfObject(data: ByteArray, start: Int, depth: Int): Int {
        var cursor = start
        var guard = 0
        while (cursor + 3 <= data.size && guard++ < 8192) {
            val nameLength = Bytes.u16be(data, cursor)
            if (nameLength == 0) {
                if (cursor + 3 <= data.size && (data[cursor + 2].toInt() and 0xFF) == 0x09) return cursor + 3
                return -1
            }
            val nameEnd = cursor + 2 + nameLength
            if (nameEnd >= data.size) return -1
            val valueEnd = skipAmfValue(data, nameEnd, depth)
            if (valueEnd < 0 || valueEnd > data.size) return -1
            cursor = valueEnd
        }
        return -1
    }

    private class MetaDataPlan(val data: ByteArray, val removedNames: List<String>, val kept: Int)

    private fun planMetaData(data: ByteArray): MetaDataPlan? {
        if (data.size < 12 || data[0] != 0x02.toByte()) return null
        val nameLength = Bytes.u16be(data, 1)
        if (nameLength <= 0 || 3 + nameLength >= data.size) return null
        val name = Bytes.asciiAt(data, 3, nameLength)
        if (!name.equals("onMetaData", ignoreCase = true)) return null
        var cursor = 3 + nameLength
        val type = data[cursor].toInt() and 0xFF
        if (type != 0x08 && type != 0x03) return null
        val countLength = if (type == 0x08) 4 else 0
        val properties = ArrayList<AmfProperty>()
        var at = cursor + 1 + countLength
        var guard = 0
        while (at + 3 <= data.size && guard++ < 4096) {
            val propertyLength = Bytes.u16be(data, at)
            if (propertyLength == 0) break
            val nameEnd = at + 2 + propertyLength
            if (nameEnd >= data.size) return null
            val valueEnd = skipAmfValue(data, nameEnd, 0)
            if (valueEnd < 0 || valueEnd > data.size) return null
            properties.add(AmfProperty(Bytes.asciiAt(data, at + 2, propertyLength), at, valueEnd))
            at = valueEnd
        }
        if (properties.isEmpty()) return null
        val kept = ArrayList<AmfProperty>()
        val dropped = ArrayList<String>()
        for (property in properties) {
            if (technicalKeys.contains(property.name.lowercase())) kept.add(property) else dropped.add(property.name)
        }
        if (dropped.isEmpty()) {
            return MetaDataPlan(data, emptyList(), kept.size)
        }
        val out = java.io.ByteArrayOutputStream(data.size)
        out.write(data, 0, cursor + 1)
        if (type == 0x08) {
            // Only an ECMA array carries an approximate element count; an AMF0 object (0x03)
            // goes straight from the type byte into its first property name.
            val countBytes = ByteArray(4)
            Bytes.putU32be(countBytes, 0, kept.size.toLong())
            out.write(countBytes)
        }
        for (property in kept) {
            out.write(data, property.start, property.end - property.start)
        }
        out.write(0x00)
        out.write(0x00)
        out.write(0x09)
        val rebuilt = out.toByteArray()
        if (rebuilt.size >= data.size) return null
        return MetaDataPlan(rebuilt, dropped, kept.size)
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val removed = ArrayList<MetadataFinding>()
        // Findings that stay in the file on purpose (an onMetaData tag we refused to
        // destroy) so verification records them as declared residuals.
        val residualRequired = ArrayList<MetadataFinding>()
        val buffer = Buffers.new()
        try {
            BinaryIo.open(ctx.source).use { io ->
                val tags = parseTags(io)
                    ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a parsable FLV stream")
                val head = io.peekAt(0, 9)
                    ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "unreadable header")
                val dataOffset = Bytes.u32be(head, 5)
                FileOutputStream(ctx.target).use { fileOut ->
                    val out = ProgressOut(fileOut, ctx)
                    io.copyRange(0L, dataOffset + 4L, out, buffer)
                    for (tag in tags) {
                        ctx.checkCancelled()
                        val payload = io.peekAt(tag.dataStart, minOf(tag.dataSize, 96L).toInt())
                        if (tag.type == TAG_SCRIPT) {
                            val name = payload?.let { amfName(it) } ?: ""
                            val raw = if (tag.dataSize <= MAX_SCRIPT_PROBE) {
                                io.peekAt(tag.dataStart, tag.dataSize.toInt())
                            } else {
                                null
                            }
                            val plan = raw?.let { planMetaData(it) }
                            if (plan != null && plan.removedNames.isEmpty()) {
                                io.copyRange(tag.start, tag.size - 4L, out, buffer)
                                val previous = ByteArray(4)
                                Bytes.putU32be(previous, 0, tag.size - 4L)
                                out.write(previous)
                                continue
                            }
                            if (plan != null) {
                                val header = io.peekAt(tag.start, 11)
                                if (header == null) {
                                    io.copyRange(tag.start, tag.size - 4L, out, buffer)
                                    val previous = ByteArray(4)
                                    Bytes.putU32be(previous, 0, tag.size - 4L)
                                    out.write(previous)
                                    continue
                                }
                                val newHeader = header.copyOf(11)
                                val size = plan.data.size
                                newHeader[1] = ((size ushr 16) and 0xFF).toByte()
                                newHeader[2] = ((size ushr 8) and 0xFF).toByte()
                                newHeader[3] = (size and 0xFF).toByte()
                                out.write(newHeader)
                                out.write(plan.data)
                                val previous = ByteArray(4)
                                Bytes.putU32be(previous, 0, 11L + size)
                                out.write(previous)
                                removed.add(
                                    MetadataFinding(
                                        MetadataKind.VIDEO_TAGS,
                                        "onMetaData fields: " + plan.removedNames.take(8).joinToString(", ")
                                    )
                                )
                                continue
                            }
                            val detail = if (name.isEmpty()) "script data tag" else "script data tag ($name)"
                            if (name.equals("onMetaData", ignoreCase = true)) {
                                // The selective AMF0 filter did not produce a plan (oversized or
                                // unparsable dictionary). Dropping the whole tag would destroy
                                // duration / keyframe structure that is not metadata, so the tag
                                // is kept and declared as a residual. Maximum privacy refuses
                                // instead of copying an unverifiable script tag through.
                                if (ctx.options.maximumPrivacy) {
                                    throw PurgeRefusedException(
                                        "onMetaData script tag could not be parsed; " +
                                            "maximum privacy refuses to copy it through unverified"
                                    )
                                }
                                io.copyRange(tag.start, tag.size - 4L, out, buffer)
                                val previous = ByteArray(4)
                                Bytes.putU32be(previous, 0, tag.size - 4L)
                                out.write(previous)
                                residualRequired.add(MetadataFinding(MetadataKind.VIDEO_TAGS, detail))
                                continue
                            }
                            removed.add(MetadataFinding(MetadataKind.VIDEO_TAGS, detail))
                            continue
                        }
                        if (tag.type != TAG_AUDIO && tag.type != TAG_VIDEO) {
                            removed.add(MetadataFinding(MetadataKind.OTHER, "unknown tag type ${tag.type}"))
                            continue
                        }
                        io.copyRange(tag.start, tag.size - 4L, out, buffer)
                        val previous = ByteArray(4)
                        Bytes.putU32be(previous, 0, tag.size - 4L)
                        out.write(previous)
                    }
                    if (tags.last().start + tags.last().size < io.length) {
                        removed.add(MetadataFinding(MetadataKind.OTHER, "trailing bytes after last tag"))
                    }
                    out.tail()
                    out.flush()
                }
            }
        } catch (refused: PurgeRefusedException) {
            throw refused
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "flv rewrite failed")
        }
        if (removed.isEmpty()) {
            return if (residualRequired.isNotEmpty()) {
                // Everything that policy could remove is already gone; the surviving
                // script tag is declared so the report shows it as an accepted residual.
                ScrubOutcome(
                    true, PurgeStrategy.STRUCTURAL_REWRITE, emptyList(),
                    residualRequired.distinct(), true
                )
            } else {
                ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable markers")
            }
        }
        return ScrubOutcome(
            true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(),
            residualRequired.distinct(), true
        )
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val tags = parseTags(io) ?: return false
                if (tags.isEmpty()) return false
                val head = io.peekAt(0, 9) ?: return false
                if (head[3].toInt() != 1) return false
                val last = tags.last()
                if (last.start + last.size != io.length) return false
                var sawMedia = false
                for (tag in tags) {
                    if (tag.type == TAG_SCRIPT) {
                        // Anything that survived the rewrite must be a metadata tag with nothing
                        // left to remove. Oversized tags were dropped rather than rebuilt.
                        if (tag.dataSize > MAX_SCRIPT_PROBE) return false
                        val raw = io.peekAt(tag.dataStart, tag.dataSize.toInt()) ?: return false
                        val plan = planMetaData(raw)
                        if (plan == null) {
                            // Compatibility: scrub kept this unparsable onMetaData tag on
                            // purpose and declared it as a residual. Maximum privacy never
                            // emits such a file (scrub refuses instead).
                            if (options.maximumPrivacy) return false
                            sawMedia = true
                            continue
                        }
                        if (plan.removedNames.isNotEmpty()) return false
                        sawMedia = true
                        continue
                    }
                    if (tag.type == TAG_AUDIO || tag.type == TAG_VIDEO) sawMedia = true
                    val tail = io.peekAt(tag.start + tag.size - 4L, 4) ?: return false
                    if (Bytes.u32be(tail, 0) != tag.size - 4L) return false
                }
                sawMedia
            }
        } catch (_: Exception) {
            false
        }
    }
}
