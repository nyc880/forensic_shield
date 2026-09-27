package com.example.lock.metadata

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream

object MatroskaHandler : FormatHandler {

    override val id: String = "matroska"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.MKV)

    private const val ID_EBML = 0x1A45DFA3L
    private const val ID_SEGMENT = 0x18538067L
    private const val ID_SEEK_HEAD = 0x114D9B74L
    private const val ID_SEEK = 0x4DBBL
    private const val ID_SEEK_ID = 0x53ABL
    private const val ID_SEEK_POSITION = 0x53ACL
    private const val ID_INFO = 0x1549A966L
    private const val ID_TAGS = 0x1254C367L
    private const val ID_ATTACHMENTS = 0x1941A469L
    private const val ID_CLUSTER = 0x1F43B675L
    private const val ID_CUES = 0x1C53BB6BL
    private const val ID_CUE_CLUSTER_POSITION = 0xF1L
    private const val ID_VOID = 0xECL
    private const val ID_CRC32 = 0xBFL
    private const val ID_INFO_UID = 0x73A4L
    private const val ID_INFO_FILENAME = 0x7384L
    private const val ID_TRACK_ENTRY = 0xAEL
    private const val ID_TRACK_UID = 0x73C5L
    private const val ID_TRACK_NAME = 0x536EL
    private const val ID_INFO_TITLE = 0x7BA9L
    private const val ID_INFO_MUXING_APP = 0x4D80L
    private const val ID_INFO_WRITING_APP = 0x5741L
    private const val ID_INFO_DATE = 0x4461L
    private const val ID_TRACKS = 0x1654AE6BL
    private const val ID_CHAPTERS = 0x1043A770L
    private const val ID_CUE_POINT = 0xBBL
    private const val ID_SEGMENT_FAMILY = 0x4444L
    private const val ID_PREV_UID = 0x3CB923L
    private const val ID_NEXT_UID = 0x3EB924L
    private const val ID_PREV_FILENAME = 0x3C83ABL
    private const val ID_NEXT_FILENAME = 0x3E83BBL
    private const val ID_CHAPTER_TRANSLATE = 0x6924L
    private const val ID_CODEC_NAME = 0x258688L

    /** What the rewrite does with one direct child of the Segment. */
    private sealed class Action {
        object Drop : Action()
        object Copy : Action()
        class Replace(val body: ByteArray, val id: Long) : Action()
        /** Padding: kept in place with its contents zeroed, so nothing shifts behind it. */
        class Voided(val size: Long) : Action()
        /** Keep the element but re-emit it, so its body can be rebuilt once the layout is known. */
        class Deferred(val id: Long) : Action()
    }

    private class Element(
        val id: Long,
        val idLength: Int,
        val sizeLength: Int,
        val size: Long,
        val unknownSize: Boolean,
        val start: Long
    ) {
        val headerLength: Int get() = idLength + sizeLength
        val dataStart: Long get() = start + headerLength
        val total: Long get() = headerLength + size
    }

    private fun readElement(io: BinaryIo, offset: Long): Element? {
        if (offset + 2 > io.length) return null
        val first = io.peekAt(offset, 1)?.get(0)?.toInt()?.and(0xFF) ?: return null
        if (first == 0) return null
        var idLength = 1
        var mask = 0x80
        while (idLength <= 4 && first and mask == 0) {
            mask = mask shr 1
            idLength++
        }
        if (idLength > 4) return null
        val idBytes = io.peekAt(offset, idLength) ?: return null
        var id = 0L
        for (i in 0 until idLength) id = (id shl 8) or (idBytes[i].toLong() and 0xFF)
        val sizeFirst = io.peekAt(offset + idLength, 1)?.get(0)?.toInt()?.and(0xFF) ?: return null
        if (sizeFirst == 0) return null
        var sizeLength = 1
        var sizeMask = 0x80
        while (sizeLength <= 8 && sizeFirst and sizeMask == 0) {
            sizeMask = sizeMask shr 1
            sizeLength++
        }
        if (sizeLength > 8) return null
        val sizeBytes = io.peekAt(offset + idLength, sizeLength) ?: return null
        var size = (sizeFirst and (sizeMask - 1)).toLong()
        var allOnes = (sizeFirst and (sizeMask - 1)) == sizeMask - 1
        for (i in 1 until sizeLength) {
            val b = sizeBytes[i].toInt() and 0xFF
            size = (size shl 8) or b.toLong()
            if (b != 0xFF) allOnes = false
        }
        if (!allOnes && offset + idLength + sizeLength + size > io.length) return null
        val effective = if (allOnes) io.length - offset - idLength - sizeLength else size
        if (effective < 0) return null
        return Element(id, idLength, sizeLength, effective, allOnes, offset)
    }

    private fun children(io: BinaryIo, parent: Element): List<Element> {
        val list = ArrayList<Element>()
        var pos = parent.dataStart
        val end = minOf(io.length, parent.dataStart + parent.size)
        var guard = 0
        while (pos + 2 <= end && guard++ < 2_000_000) {
            val element = readElement(io, pos) ?: break
            list.add(element)
            if (element.unknownSize) break
            pos += element.total
        }
        return list
    }

    private sealed class Item {
        object Skip : Item()
        class Copy(val start: Long, val length: Long) : Item()
        class Bytes(val data: ByteArray) : Item()
        class Zeroed(val header: ByteArray, val size: Long) : Item()
    }

    /** Largest payload an 8 byte EBML size vint can describe. */
    private const val MAX_VINT_VALUE = (1L shl 56) - 2L

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val buffer = Buffers.new()
        val removed = ArrayList<MetadataFinding>()
        val structural = ArrayList<MetadataFinding>()
        BinaryIo.open(ctx.source).use { io ->
            val ebml = readElement(io, 0)
            if (ebml == null || ebml.id != ID_EBML) {
                return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no EBML header")
            }
            val segment = findElement(io, ebml.dataStart + ebml.size, ID_SEGMENT)
                ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no Segment element")
            val segmentChildren = children(io, segment)
            if (segmentChildren.isEmpty()) {
                return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "empty Segment")
            }

            // Pass 1: decide what happens to each child, and rebuild the ones whose body is fixed
            // up front. SeekHead and Cues are deferred because their content depends on where
            // every other element ends up, which is not known until the layout is computed.
            val actions = ArrayList<Action>(segmentChildren.size)
            var changedAnything = false
            for (child in segmentChildren) {
                actions.add(
                    when (child.id) {
                        ID_TAGS -> {
                            removed.add(MetadataFinding(MetadataKind.VIDEO_TAGS, "Segment Tags element"))
                            changedAnything = true
                            Action.Drop
                        }
                        ID_ATTACHMENTS -> {
                            removed.add(MetadataFinding(MetadataKind.EMBEDDED_FILE, "Segment Attachments element"))
                            changedAnything = true
                            Action.Drop
                        }
                        ID_CHAPTERS -> {
                            removed.add(MetadataFinding(MetadataKind.VIDEO_TAGS, "Segment Chapters element"))
                            changedAnything = true
                            Action.Drop
                        }
                        ID_INFO -> {
                            val body = rebuildInfo(io, child, removed)
                            if (body == null) Action.Copy else {
                                changedAnything = true
                                Action.Replace(body, ID_INFO)
                            }
                        }
                        ID_TRACKS -> {
                            val body = rebuildTracks(io, child, removed, structural)
                            if (body == null) Action.Copy else {
                                changedAnything = true
                                Action.Replace(body, ID_TRACKS)
                            }
                        }
                        ID_SEEK_HEAD, ID_CUES -> Action.Deferred(child.id)
                        ID_VOID -> {
                            changedAnything = true
                            Action.Voided(child.size)
                        }
                        else -> Action.Copy
                    }
                )
            }

            val trailing = !segment.unknownSize && segment.dataStart + segment.size in 1L until io.length
            if (trailing) {
                removed.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the Segment"))
                changedAnything = true
            }
            if (!changedAnything) {
                return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "no removable elements")
            }

            // Pass 2: lay the kept elements out, treating the deferred ones as unchanged in size,
            // so SeekHead can be rebuilt against real positions. Rebuilding it may change its own
            // size, so the layout is recomputed once with the size it actually came out at.
            val originalSeekSize = segmentChildren
                .firstOrNull { it.id == ID_SEEK_HEAD }?.total ?: 0L
            var seekBody: ByteArray? = null
            var positions = layout(actions, segmentChildren, originalSeekSize)
            var seekSize = originalSeekSize
            repeat(3) {
                val head = segmentChildren.firstOrNull { it.id == ID_SEEK_HEAD }
                val rebuilt = head?.let {
                    rebuildSeekHead(io, it, actions, segmentChildren, segment.dataStart, positions)
                }
                val size = if (head == null) 0L else (rebuilt?.let { elementBytes(ID_SEEK_HEAD, it).size.toLong() } ?: head.total)
                if (rebuilt != null) seekBody = rebuilt
                if (size == seekSize) return@repeat
                seekSize = size
                positions = layout(actions, segmentChildren, seekSize)
            }

            val cuesBody = segmentChildren.firstOrNull { it.id == ID_CUES }
                ?.let { patchCues(io, it, segment.dataStart, positions) }

            val bodies = HashMap<Long, ByteArray>()
            seekBody?.let { bodies[ID_SEEK_HEAD] = it }
            cuesBody?.let { bodies[ID_CUES] = it }
            val plan = ArrayList<Item>(segmentChildren.size)
            for ((index, child) in segmentChildren.withIndex()) {
                plan.add(
                    when (val action = actions[index]) {
                        is Action.Drop -> Item.Skip
                        is Action.Copy -> Item.Copy(child.start, child.total)
                        is Action.Replace -> Item.Bytes(elementBytes(action.id, action.body))
                        is Action.Voided -> Item.Zeroed(elementHeader(ID_VOID, action.size), action.size)
                        is Action.Deferred -> {
                            val body = bodies[action.id]
                            if (body == null) Item.Copy(child.start, child.total)
                            else Item.Bytes(elementBytes(action.id, body))
                        }
                    }
                )
            }

            var newSize = 0L
            for (item in plan) {
                newSize += when (item) {
                    is Item.Skip -> 0L
                    is Item.Copy -> item.length
                    is Item.Bytes -> item.data.size.toLong()
                    is Item.Zeroed -> item.header.size + item.size
                }
            }
            if (newSize > MAX_VINT_VALUE) {
                return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "Segment too large to re-encode")
            }

            FileOutputStream(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                io.copyRange(0, segment.start, out, buffer)
                out.write(idBytes(segment.id, segment.idLength))
                writeVint(out, newSize)
                for (item in plan) {
                    ctx.checkCancelled()
                    when (item) {
                        is Item.Skip -> Unit
                        is Item.Copy -> io.copyRange(item.start, item.length, out, buffer)
                        is Item.Bytes -> out.write(item.data)
                        is Item.Zeroed -> {
                            out.write(item.header)
                            writeZeros(out, item.size)
                        }
                    }
                }
                out.tail()
                out.flush()
            }
            return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), structural.distinct(), true)
        }
    }

    /**
     * Map every kept child of the Segment to the offset it will have in the rewritten file,
     * measured from the start of the Segment payload, which is what SeekPosition and
     * CueClusterPosition are defined against.
     */
    private fun layout(
        actions: List<Action>,
        children: List<Element>,
        seekHeadSize: Long
    ): Map<Long, Long> {
        val positions = HashMap<Long, Long>()
        var cursor = 0L
        for ((index, child) in children.withIndex()) {
            when (val action = actions[index]) {
                is Action.Drop -> Unit
                is Action.Copy -> {
                    positions[child.start] = cursor
                    cursor += child.total
                }
                is Action.Replace -> {
                    positions[child.start] = cursor
                    cursor += elementBytes(action.id, action.body).size.toLong()
                }
                is Action.Voided -> {
                    positions[child.start] = cursor
                    cursor += elementHeader(ID_VOID, action.size).size + action.size
                }
                is Action.Deferred -> {
                    positions[child.start] = cursor
                    cursor += if (action.id == ID_SEEK_HEAD) seekHeadSize else child.total
                }
            }
        }
        return positions
    }

    private fun writeZeros(out: OutputStream, size: Long) {
        val block = ByteArray(minOf(size, 64L * 1024).toInt())
        var remaining = size
        while (remaining > 0) {
            val chunk = minOf(remaining, block.size.toLong()).toInt()
            out.write(block, 0, chunk)
            remaining -= chunk
        }
    }

    private fun elementBytes(id: Long, body: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(idBytes(id, idBytesLength(id)))
        writeVint(out, body.size.toLong())
        out.write(body)
        return out.toByteArray()
    }

    private fun elementHeader(id: Long, size: Long): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(idBytes(id, idBytesLength(id)))
        writeVint(out, size)
        return out.toByteArray()
    }

    private fun idBytes(id: Long, length: Int): ByteArray {
        val bytes = ByteArray(length)
        var value = id
        for (i in length - 1 downTo 0) {
            bytes[i] = (value and 0xFF).toByte()
            value = value shr 8
        }
        return bytes
    }

    private fun idBytesLength(id: Long): Int = when {
        id < 0x100 -> 1
        id < 0x10000 -> 2
        id < 0x1000000 -> 3
        id < 0x100000000L -> 4
        else -> 8
    }

    private fun writeVint(out: OutputStream, value: Long) {
        if (value < 0 || value > MAX_VINT_VALUE) {
            throw IllegalArgumentException("EBML size out of range: $value")
        }
        var length = 1
        while (length < 8 && value >= (1L shl (7 * length))) length++
        val bytes = ByteArray(length)
        var remaining = value
        for (i in length - 1 downTo 0) {
            bytes[i] = (remaining and 0xFF).toByte()
            remaining = remaining shr 8
        }
        bytes[0] = (bytes[0].toInt() or (0x80 shr (length - 1))).toByte()
        out.write(bytes)
    }

    private fun findElement(io: BinaryIo, from: Long, wanted: Long): Element? {
        var pos = from
        var guard = 0
        while (pos + 2 <= io.length && guard++ < 64) {
            val element = readElement(io, pos) ?: return null
            if (element.id == wanted) return element
            pos += element.total
        }
        return null
    }

    private fun rebuildInfo(io: BinaryIo, info: Element, removed: MutableList<MetadataFinding>): ByteArray? {
        val out = ByteArrayOutputStream()
        var changed = false
        for (child in children(io, info)) {
            when (child.id) {
                ID_INFO_TITLE -> {
                    removed.add(MetadataFinding(MetadataKind.VIDEO_TAGS, "Info Title"))
                    changed = true
                }
                ID_INFO_MUXING_APP -> {
                    removed.add(MetadataFinding(MetadataKind.SOFTWARE, "Info MuxingApp"))
                    changed = true
                }
                ID_INFO_WRITING_APP -> {
                    removed.add(MetadataFinding(MetadataKind.SOFTWARE, "Info WritingApp"))
                    changed = true
                }
                ID_INFO_DATE -> {
                    removed.add(MetadataFinding(MetadataKind.TIMESTAMP, "Info DateUTC"))
                    changed = true
                }
                ID_CRC32 -> changed = true
                ID_INFO_UID -> {
                    removed.add(MetadataFinding(MetadataKind.UNIQUE_ID, "Info SegmentUID"))
                    changed = true
                }
                ID_INFO_FILENAME -> {
                    removed.add(MetadataFinding(MetadataKind.PATH_LEAK, "Info SegmentFilename"))
                    changed = true
                }
                ID_PREV_FILENAME, ID_NEXT_FILENAME -> {
                    removed.add(MetadataFinding(MetadataKind.PATH_LEAK, "Info neighbouring segment filename"))
                    changed = true
                }
                ID_PREV_UID, ID_NEXT_UID -> {
                    removed.add(MetadataFinding(MetadataKind.UNIQUE_ID, "Info neighbouring segment UID"))
                    changed = true
                }
                ID_SEGMENT_FAMILY -> {
                    removed.add(MetadataFinding(MetadataKind.UNIQUE_ID, "Info SegmentFamily"))
                    changed = true
                }
                ID_CHAPTER_TRANSLATE -> {
                    removed.add(MetadataFinding(MetadataKind.UNIQUE_ID, "Info ChapterTranslate"))
                    changed = true
                }
                else -> {
                    val bytes = io.peekAt(child.start, child.total.toInt()) ?: return null
                    out.write(bytes)
                }
            }
        }
        return if (changed) out.toByteArray() else null
    }

    /**
     * The value a TrackUID is replaced with. It is derived from the track position so that
     * rewriting is stable: a file that has already been through this tool keeps its bytes, which
     * is what lets a second run report the file as clean instead of redoing the work.
     */
    private fun replacementTrackUid(trackIndex: Int, size: Int): ByteArray {
        val replacement = ByteArray(size)
        var value = trackIndex
        var index = size - 1
        while (index >= 0 && value > 0) {
            replacement[index] = (value and 0xFF).toByte()
            value = value shr 8
            index--
        }
        return replacement
    }

    private fun currentTrackUid(io: BinaryIo, field: Element): ByteArray? {
        val size = field.size.toInt()
        if (size !in 1..64) return null
        return io.peekAt(field.dataStart, size)
    }

    private fun rebuildTracks(
        io: BinaryIo,
        tracks: Element,
        removed: MutableList<MetadataFinding>,
        structural: MutableList<MetadataFinding>
    ): ByteArray? {
        val out = ByteArrayOutputStream()
        var changed = false
        var trackIndex = 0
        for (entry in children(io, tracks)) {
            if (entry.id != ID_TRACK_ENTRY) {
                val bytes = io.peekAt(entry.start, entry.total.toInt()) ?: return null
                out.write(bytes)
                continue
            }
            trackIndex++
            val entryBody = ByteArrayOutputStream()
            var entryChanged = false
            for (child in children(io, entry)) {
                when (child.id) {
                    ID_TRACK_UID -> {
                        // The element is mandatory, so it cannot simply go. It is replaced with a
                        // value derived from the track position rather than fresh random bytes:
                        // a random value on every run meant the file was never stable and a second
                        // pass rewrote it again. Chapters and Tags, the only elements that
                        // reference a TrackUID, are dropped whole, so nothing is left dangling.
                        val size = child.size.toInt()
                        val replacement = replacementTrackUid(trackIndex, size)
                        val current = currentTrackUid(io, child)
                        if (current != null && current.contentEquals(replacement)) {
                            val raw = io.peekAt(child.start, child.total.toInt()) ?: return null
                            entryBody.write(raw)
                        } else {
                            entryBody.write(elementHeader(ID_TRACK_UID, child.size))
                            entryBody.write(replacement)
                            removed.add(MetadataFinding(MetadataKind.UNIQUE_ID, "TrackUID replaced"))
                            structural.add(MetadataFinding(MetadataKind.UNIQUE_ID, "TrackUID"))
                            entryChanged = true
                        }
                    }
                    ID_TRACK_NAME -> {
                        removed.add(MetadataFinding(MetadataKind.VIDEO_TAGS, "Track Name"))
                        entryChanged = true
                    }
                    ID_CODEC_NAME -> {
                        removed.add(MetadataFinding(MetadataKind.SOFTWARE, "Track CodecName"))
                        entryChanged = true
                    }
                    ID_CRC32 -> entryChanged = true
                    else -> {
                        val bytes = io.peekAt(child.start, child.total.toInt()) ?: return null
                        entryBody.write(bytes)
                    }
                }
            }
            if (entryChanged) {
                val body = entryBody.toByteArray()
                out.write(elementHeader(ID_TRACK_ENTRY, body.size.toLong()))
                out.write(body)
                changed = true
            } else {
                val bytes = io.peekAt(entry.start, entry.total.toInt()) ?: return null
                out.write(bytes)
            }
        }
        return if (changed) out.toByteArray() else null
    }

    /**
     * Rebuild the SeekHead against the layout that is actually going to be written. A Seek entry
     * whose target was removed disappears with it; everything else is pointed at its new offset.
     */
    private fun rebuildSeekHead(
        io: BinaryIo,
        head: Element,
        actions: List<Action>,
        children: List<Element>,
        base: Long,
        positions: Map<Long, Long>
    ): ByteArray? {
        val droppedIds = droppedTargetIds(actions, children)
        val out = ByteArrayOutputStream()
        var changed = false
        for (seek in children(io, head)) {
            if (seek.id != ID_SEEK) {
                val bytes = io.peekAt(seek.start, seek.total.toInt()) ?: continue
                out.write(bytes)
                continue
            }
            val seekChildren = children(io, seek)
            val idElement = seekChildren.firstOrNull { it.id == ID_SEEK_ID }
            val positionElement = seekChildren.firstOrNull { it.id == ID_SEEK_POSITION }
            if (idElement == null || positionElement == null) {
                val bytes = io.peekAt(seek.start, seek.total.toInt()) ?: continue
                out.write(bytes)
                continue
            }
            val targetId = readUnsigned(io, idElement)
            if (targetId != null && droppedIds.contains(targetId)) {
                changed = true
                continue
            }
            val original = readUnsigned(io, positionElement)
            if (original == null) {
                val bytes = io.peekAt(seek.start, seek.total.toInt()) ?: continue
                out.write(bytes)
                continue
            }
            val mapped = positions[base + original]
            if (mapped == null) {
                // The entry points somewhere that is not a child of the Segment any more.
                changed = true
                continue
            }
            val body = ByteArrayOutputStream()
            for (child in seekChildren) {
                if (child.id == ID_SEEK_POSITION) {
                    writeUnsigned(body, mapped, child.size.toInt())
                } else {
                    val bytes = io.peekAt(child.start, child.total.toInt()) ?: continue
                    body.write(bytes)
                }
            }
            if (mapped != original) changed = true
            val bodyBytes = body.toByteArray()
            out.write(elementHeader(ID_SEEK, bodyBytes.size.toLong()))
            out.write(bodyBytes)
        }
        return if (changed) out.toByteArray() else null
    }

    private fun droppedTargetIds(actions: List<Action>, children: List<Element>): Set<Long> {
        val dropped = HashSet<Long>()
        for ((index, action) in actions.withIndex()) {
            if (action is Action.Drop) dropped.add(children[index].id)
        }
        return dropped
    }

    /**
     * CueClusterPosition is relative to the Segment payload, and the cluster offsets change as
     * soon as anything in front of them is removed or rebuilt. The values live inside CuePoint,
     * not directly under Cues.
     */
    private fun patchCues(
        io: BinaryIo,
        cues: Element,
        base: Long,
        positions: Map<Long, Long>
    ): ByteArray? {
        val out = ByteArrayOutputStream()
        var changed = false
        for (point in children(io, cues)) {
            if (point.id == ID_CRC32) {
                changed = true
                continue
            }
            if (point.id != ID_CUE_POINT) {
                val bytes = io.peekAt(point.start, point.total.toInt()) ?: continue
                out.write(bytes)
                continue
            }
            val body = ByteArrayOutputStream()
            for (child in children(io, point)) {
                when (child.id) {
                    ID_CUE_CLUSTER_POSITION -> {
                        val original = readUnsigned(io, child)
                        val mapped = if (original != null) positions[base + original] else null
                        if (original != null && mapped != null) {
                            writeUnsigned(body, mapped, child.size.toInt())
                            if (mapped != original) changed = true
                        } else {
                            changed = true
                        }
                    }
                    ID_CRC32 -> changed = true
                    else -> {
                        val bytes = io.peekAt(child.start, child.total.toInt()) ?: continue
                        body.write(bytes)
                    }
                }
            }
            val bodyBytes = body.toByteArray()
            out.write(elementHeader(ID_CUE_POINT, bodyBytes.size.toLong()))
            out.write(bodyBytes)
        }
        return if (changed) out.toByteArray() else null
    }

    private fun readUnsigned(io: BinaryIo, element: Element): Long? {
        if (element.size <= 0 || element.size > 8) return null
        val bytes = io.peekAt(element.dataStart, element.size.toInt()) ?: return null
        var value = 0L
        for (byte in bytes) value = (value shl 8) or (byte.toLong() and 0xFF)
        return value
    }

    private fun writeUnsigned(out: OutputStream, value: Long, size: Int) {
        if (size <= 0 || size > 8) {
            writeVint(out, value)
            return
        }
        val bytes = ByteArray(size)
        var remaining = value
        for (i in size - 1 downTo 0) {
            bytes[i] = (remaining and 0xFF).toByte()
            remaining = remaining shr 8
        }
        out.write(bytes)
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                val ebml = readElement(io, 0) ?: return listOf(MetadataFinding(MetadataKind.OTHER, "no EBML header"))
                val segment = findElement(io, ebml.dataStart + ebml.size, ID_SEGMENT)
                    ?: return listOf(MetadataFinding(MetadataKind.OTHER, "no Segment element"))
                if (!segment.unknownSize && segment.dataStart + segment.size in 1L until io.length) {
                    findings.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the Segment"))
                }
                for (child in children(io, segment)) {
                    when (child.id) {
                        ID_TAGS -> {
                            findings.add(MetadataFinding(MetadataKind.VIDEO_TAGS, "Segment Tags element"))
                            findings.addAll(readTagNames(io, child))
                        }
                        ID_ATTACHMENTS -> if (options.stripEmbeddedThumbnails) {
                            findings.add(MetadataFinding(MetadataKind.THUMBNAIL, "Segment Attachments element"))
                        }
                        ID_TRACKS -> {
                            var trackIndex = 0
                            for (entry in children(io, child)) {
                                if (entry.id != ID_TRACK_ENTRY) continue
                                trackIndex++
                                for (field in children(io, entry)) {
                                    when (field.id) {
                                        // Only a UID that still differs from the replacement is
                                        // reported, otherwise a file that has already been purged
                                        // could never be recognised as clean. The wording has to
                                        // match the structural entry the scrub records, because
                                        // residual findings are compared by detail.
                                        ID_TRACK_UID -> {
                                            val current = currentTrackUid(io, field)
                                            if (current == null ||
                                                !current.contentEquals(replacementTrackUid(trackIndex, field.size.toInt()))
                                            ) {
                                                findings.add(MetadataFinding(MetadataKind.UNIQUE_ID, "TrackUID"))
                                            }
                                        }
                                        ID_TRACK_NAME -> findings.add(MetadataFinding(MetadataKind.VIDEO_TAGS, "Track Name"))
                                    }
                                }
                            }
                        }
                        ID_INFO -> {
                            for (infoChild in children(io, child)) {
                                when (infoChild.id) {
                                    ID_INFO_TITLE -> findings.add(MetadataFinding(MetadataKind.VIDEO_TAGS, "Info Title"))
                                    ID_INFO_MUXING_APP -> findings.add(MetadataFinding(MetadataKind.SOFTWARE, "Info MuxingApp"))
                                    ID_INFO_WRITING_APP -> findings.add(MetadataFinding(MetadataKind.SOFTWARE, "Info WritingApp"))
                                    ID_INFO_DATE -> findings.add(MetadataFinding(MetadataKind.TIMESTAMP, "Info DateUTC"))
                                    ID_INFO_UID -> findings.add(MetadataFinding(MetadataKind.UNIQUE_ID, "Info SegmentUID"))
                                    ID_INFO_FILENAME -> findings.add(MetadataFinding(MetadataKind.PATH_LEAK, "Info SegmentFilename"))
                                }
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    private fun readTagNames(io: BinaryIo, tags: Element): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        for (tag in children(io, tags)) {
            val bytes = io.peekAt(tag.dataStart, minOf(tag.size, 64L * 1024).toInt()) ?: continue
            val text = String(bytes, Charsets.ISO_8859_1)
            val kind = when {
                text.contains("ARTIST") || text.contains("AUTHOR") || text.contains("DIRECTOR") -> MetadataKind.AUTHOR
                text.contains("COMMENT") || text.contains("DESCRIPTION") -> MetadataKind.COMMENT
                text.contains("DATE") -> MetadataKind.TIMESTAMP
                text.contains("ENCODER") -> MetadataKind.SOFTWARE
                else -> MetadataKind.VIDEO_TAGS
            }
            findings.add(MetadataFinding(kind, "Matroska tag"))
        }
        return findings
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val ebml = readElement(io, 0) ?: return false
                if (ebml.id != ID_EBML) return false
                val segment = findElement(io, ebml.dataStart + ebml.size, ID_SEGMENT) ?: return false
                val kids = children(io, segment)
                val end = segment.dataStart + segment.size
                kids.isNotEmpty() && kids.any { it.id == ID_TRACKS } &&
                    kids.any { it.id == ID_CLUSTER || it.id == ID_CUES } && end <= io.length &&
                    (segment.unknownSize || end >= io.length)
            }
        } catch (_: Exception) {
            false
        }
    }
}
