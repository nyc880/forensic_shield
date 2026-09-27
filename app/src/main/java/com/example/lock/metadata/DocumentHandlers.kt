package com.example.lock.metadata

import java.io.File
import java.io.FileOutputStream

object PdfHandler : FormatHandler {

    override val id: String = "pdf"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.PDF)

    private val infoKeys = listOf(
        "/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer",
        "/CreationDate", "/ModDate", "/Trapped"
    )
    private val structuralKeys = listOf(
        "/PieceInfo", "/LastModified", "/Thumb", "/Metadata", "/ID",
        "/EmbeddedFiles", "/UF", "/PTEX.Fullbanner", "/DocChecksum", "/DocMDP"
    )
    private val bannedKeys = infoKeys + structuralKeys

    /**
     * /F is the file name inside a file specification dictionary, but it is also the annotation
     * flag field everywhere else, so these only get blanked when the enclosing object really is
     * a file specification.
     */
    private val fileSpecKeys = listOf("/F", "/DOS", "/Mac", "/Unix")

    private class Span(val dictStart: Long, val dictEnd: Long, val streamStart: Long, val streamEnd: Long, val end: Long)

    private fun kindOf(key: String): MetadataKind = when (key) {
        "/Author", "/Creator" -> MetadataKind.AUTHOR
        "/Producer", "/PTEX.Fullbanner" -> MetadataKind.SOFTWARE
        "/CreationDate", "/ModDate", "/LastModified" -> MetadataKind.TIMESTAMP
        "/Metadata" -> MetadataKind.XMP
        "/ID", "/DocChecksum" -> MetadataKind.UNIQUE_ID
        "/Thumb" -> MetadataKind.THUMBNAIL
        "/EmbeddedFiles" -> MetadataKind.EMBEDDED_FILE
        "/UF", "/F", "/DOS", "/Mac", "/Unix" -> MetadataKind.PATH_LEAK
        "/DocMDP" -> MetadataKind.OTHER
        else -> MetadataKind.DOCUMENT_PROPERTY
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val removed = ArrayList<MetadataFinding>()
        try {
            val end = effectiveEnd(ctx.source)
            if (end < ctx.source.length()) {
                removed.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the PDF trailer"))
            }
            ctx.source.inputStream().use { input ->
                FileOutputStream(ctx.target).use { out ->
                    val buffer = Buffers.new()
                    var remaining = end
                    while (remaining > 0) {
                        val read = input.read(buffer, 0, minOf(remaining, buffer.size.toLong()).toInt())
                        if (read <= 0) break
                        out.write(buffer, 0, read)
                        remaining -= read
                    }
                    out.flush()
                }
            }
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = e.message ?: "copy failed")
        }
        try {
            BinaryIo.openReadWrite(ctx.target).use { io ->
                val probe = io.peekAt(0, minOf(4096L, io.length).toInt())?.let { String(it, Charsets.ISO_8859_1) } ?: ""
                if (!probe.startsWith("%PDF-")) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a PDF file")
                }
                if (findAscii(io, 0, "/Encrypt") >= 0) {
                    return ScrubOutcome(
                        false, PurgeStrategy.NONE, emptyList(),
                        message = "encrypted PDF: metadata cannot be verified, refusing"
                    )
                }
                ctx.stage("Scanning PDF objects")
                var position = 0L
                var guard = 0
                while (position < io.length && guard++ < 1_000_000) {
                    val header = findAscii(io, position, "obj")
                    if (header < 0) break
                    val start = statementStart(io, header)
                    if (start < 0) {
                        position = header + 3
                        continue
                    }
                    val span = objectSpan(io, header)
                    if (span.end <= header) break
                    if (span.streamStart > 0 && isMetadataStream(io, span)) {
                        removed.add(MetadataFinding(MetadataKind.XMP, "XMP metadata stream"))
                        blank(io, span.streamStart, span.streamEnd)
                    }
                    cleanKeys(io, span.dictStart, span.dictEnd, removed, "object", keysFor(io, span.dictStart, span.dictEnd))
                    position = span.end
                }
                removed.addAll(cleanTrailer(io))
                io.fsync()
            }
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "PDF rewrite failed")
        }
        if (removed.isEmpty()) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable metadata")
        }
        return ScrubOutcome(true, PurgeStrategy.TAG_TABLE_REWRITE, removed.distinct(), emptyList(), true)
    }

    private fun containsAscii(io: BinaryIo, from: Long, to: Long, needle: String): Boolean {
        var search = from
        var guard = 0
        while (search < to && guard++ < 64) {
            val at = findAscii(io, search, needle)
            if (at < 0 || at >= to) return false
            if (isKeyBoundary(io, at, needle.length)) return true
            search = at + needle.length
        }
        return false
    }

    /** The key set for one object dictionary, widened when the object is a file specification. */
    private fun keysFor(io: BinaryIo, from: Long, to: Long): List<String> =
        if (containsAscii(io, from, to, "/Filespec")) bannedKeys + fileSpecKeys else bannedKeys

    private fun cleanKeys(
        io: BinaryIo,
        from: Long,
        to: Long,
        removed: MutableList<MetadataFinding>,
        where: String,
        keys: List<String> = bannedKeys
    ) {
        for (key in keys) {
            var search = from
            var guard = 0
            while (search < to && guard++ < 4096) {
                val at = findAscii(io, search, key)
                if (at < 0 || at >= to) break
                if (!isKeyBoundary(io, at, key.length)) {
                    search = at + key.length
                    continue
                }
                val end = valueEnd(io, at + key.length, to)
                if (end <= at + key.length) {
                    search = at + key.length
                    continue
                }
                removed.add(MetadataFinding(kindOf(key), "PDF $key in $where"))
                blank(io, at, end)
                search = end
            }
        }
    }

    private fun cleanTrailer(io: BinaryIo): List<MetadataFinding> {
        val removed = ArrayList<MetadataFinding>()
        var position = 0L
        var guard = 0
        while (position < io.length && guard++ < 4096) {
            val at = findAscii(io, position, "trailer")
            if (at < 0) break
            val start = at + 7
            val end = findAscii(io, start, "startxref")
            val limit = if (end > start) end else io.length
            cleanKeys(io, start, limit, removed, "trailer")
            position = limit
        }
        return removed
    }

    private fun objectSpan(io: BinaryIo, objKeyword: Long): Span {
        val endobj = findAscii(io, objKeyword, "endobj")
        val stream = findAscii(io, objKeyword, "stream")
        if (stream in 0 until (if (endobj > 0) endobj else Long.MAX_VALUE)) {
            val streamStart = streamDataStart(io, stream)
            val streamEnd = findAscii(io, streamStart, "endstream")
            if (streamEnd > streamStart) {
                return Span(objKeyword + 3, stream, streamStart, streamEnd, streamEnd + 9)
            }
            return Span(objKeyword + 3, stream, 0, 0, if (endobj > 0) endobj + 6 else io.length)
        }
        val dictEnd = if (endobj > 0) endobj else io.length
        return Span(objKeyword + 3, dictEnd, 0, 0, if (endobj > 0) endobj + 6 else io.length)
    }

    private fun isMetadataStream(io: BinaryIo, span: Span): Boolean {
        val length = (span.dictEnd - span.dictStart).toInt()
        if (length in 1..8192) {
            val dict = io.peekAt(span.dictStart, length)
            if (dict != null) {
                val text = String(dict, Charsets.ISO_8859_1)
                if (text.contains("/Metadata") || text.contains("/Type /Metadata") ||
                    text.contains("/Type/Metadata")
                ) {
                    return true
                }
                if (text.contains("/Subtype /XML") || text.contains("/Subtype/XML")) return true
            }
        }
        if (span.streamStart <= 0) return false
        val probeLength = minOf(8192L, io.length - span.streamStart).toInt()
        if (probeLength <= 0) return false
        val head = io.peekAt(span.streamStart, probeLength) ?: return false
        val text = String(head, Charsets.ISO_8859_1)
        return text.contains("xpacket") || text.contains("x:xmpmeta")
    }

    private fun streamDataStart(io: BinaryIo, streamKeyword: Long): Long {
        var pos = streamKeyword + 6
        val probe = io.peekAt(pos, 2) ?: return pos
        if (probe[0] == 0x0D.toByte() && probe[1] == 0x0A.toByte()) return pos + 2
        if (probe[0] == 0x0A.toByte() || probe[0] == 0x0D.toByte()) return pos + 1
        return pos
    }

    private fun statementStart(io: BinaryIo, objKeyword: Long): Long {
        var pos = objKeyword - 1
        var digits = 0
        while (pos >= 0) {
            val b = io.peekAt(pos, 1)?.get(0)?.toInt()?.and(0xFF) ?: return -1
            val c = b.toChar()
            if (c.isWhitespace()) {
                if (digits == 0) {
                    pos--
                    continue
                }
                break
            }
            if (!c.isDigit()) return -1
            digits++
            pos--
        }
        if (digits == 0) return -1
        val before = io.peekAt(pos, 1)?.get(0)?.toInt()?.and(0xFF) ?: 32
        if (!before.toChar().isWhitespace()) return -1
        while (pos >= 0) {
            val b = io.peekAt(pos, 1)?.get(0)?.toInt()?.and(0xFF) ?: break
            if (!b.toChar().isWhitespace()) break
            pos--
        }
        return pos + 1
    }

    private fun isKeyBoundary(io: BinaryIo, at: Long, length: Int): Boolean {
        if (at > 0) {
            val before = io.peekAt(at - 1, 1)?.get(0)?.toInt()?.and(0xFF) ?: 32
            val c = before.toChar()
            if (!c.isWhitespace() && c != '<' && c != '[' && c != '/' && c != '(') return false
        }
        val after = io.peekAt(at + length, 1)?.get(0)?.toInt()?.and(0xFF) ?: 32
        val c = after.toChar()
        return c.isWhitespace() || c == '/' || c == '<' || c == '[' || c == '(' || c == '>'
    }

    private fun valueEnd(io: BinaryIo, from: Long, limit: Long): Long {
        val windowLength = (limit - from).toInt().coerceAtMost(65536)
        if (windowLength <= 0) return from
        val probe = io.peekAt(from, windowLength) ?: return from
        var index = 0
        while (index < probe.size) {
            val c = probe[index].toInt().toChar()
            if (c.isWhitespace()) {
                index++
                continue
            }
            return from + when (c) {
                '(' -> stringEnd(probe, index)
                '<' -> dictionaryOrHexEnd(probe, index)
                '[' -> arrayEnd(probe, index)
                '/' -> nameEnd(probe, index)
                else -> indirectOrNumberEnd(probe, index)
            }
        }
        return from
    }

    private fun stringEnd(probe: ByteArray, start: Int): Int {
        var depth = 0
        var index = start
        while (index < probe.size) {
            val c = probe[index].toInt().toChar()
            if (c == '\\') {
                index += 2
                continue
            }
            if (c == '(') depth++
            if (c == ')') {
                depth--
                if (depth == 0) return index + 1
            }
            index++
        }
        return probe.size
    }

    private fun dictionaryOrHexEnd(probe: ByteArray, start: Int): Int {
        if (start + 1 < probe.size && probe[start + 1].toInt().toChar() == '<') {
            var depth = 0
            var index = start
            while (index < probe.size - 1) {
                val c = probe[index].toInt().toChar()
                if (c == '<' && probe[index + 1].toInt().toChar() == '<') {
                    depth++
                    index += 2
                    continue
                }
                if (c == '>' && probe[index + 1].toInt().toChar() == '>') {
                    depth--
                    index += 2
                    if (depth == 0) return index
                    continue
                }
                index++
            }
            return probe.size
        }
        var index = start + 1
        while (index < probe.size) {
            if (probe[index].toInt().toChar() == '>') return index + 1
            index++
        }
        return probe.size
    }

    private fun arrayEnd(probe: ByteArray, start: Int): Int {
        var depth = 0
        var index = start
        while (index < probe.size) {
            val c = probe[index].toInt().toChar()
            if (c == '(') {
                index = stringEnd(probe, index)
                continue
            }
            if (c == '<') {
                index = dictionaryOrHexEnd(probe, index)
                continue
            }
            if (c == '[') depth++
            if (c == ']') {
                depth--
                if (depth == 0) return index + 1
            }
            index++
        }
        return probe.size
    }

    private fun nameEnd(probe: ByteArray, start: Int): Int {
        var index = start + 1
        while (index < probe.size) {
            val c = probe[index].toInt().toChar()
            if (c.isWhitespace() || c == '/' || c == '<' || c == '[' || c == '(' || c == '>') break
            index++
        }
        return index
    }

    private fun indirectOrNumberEnd(probe: ByteArray, start: Int): Int {
        var index = start
        var tokens = 0
        while (index < probe.size && tokens < 3) {
            val c = probe[index].toInt().toChar()
            if (c.isWhitespace()) {
                index++
                continue
            }
            var end = index
            while (end < probe.size && !probe[end].toInt().toChar().isWhitespace()) end++
            val token = String(probe, index, end - index, Charsets.ISO_8859_1)
            tokens++
            index = end
            if (token == "R") return index
            if (token.toLongOrNull() == null) return index
        }
        return index
    }

    private fun blank(io: BinaryIo, start: Long, end: Long) {
        var pos = start
        val spaces = ByteArray(8192) { 0x20 }
        while (pos < end) {
            val chunk = minOf(end - pos, spaces.size.toLong()).toInt()
            io.writeAt(pos, spaces, 0, chunk)
            pos += chunk
        }
    }

    private fun effectiveEnd(file: File): Long {
        val length = file.length()
        val tailLength = minOf(length, 8192L).toInt()
        if (tailLength <= 0) return length
        BinaryIo.open(file).use { io ->
            val tail = io.peekAt(length - tailLength, tailLength) ?: return length
            val text = String(tail, Charsets.ISO_8859_1)
            val index = text.lastIndexOf("%%EOF")
            if (index < 0) return length
            var end = length - tailLength + index + 5
            while (end < length) {
                val c = (io.peekAt(end, 1)?.get(0)?.toInt()?.and(0xFF) ?: 0).toChar()
                if (c == '\r' || c == '\n') end++ else break
            }
            return end
        }
    }

    private fun pdfTailStart(io: BinaryIo): Long {
        val window = minOf(io.length, 65536L)
        val start = io.length - window
        val bytes = io.peekAt(start, window.toInt()) ?: return -1L
        val text = String(bytes, Charsets.ISO_8859_1)
        val marker = text.lastIndexOf("%%EOF")
        if (marker < 0) return -1L
        var end = start + marker + 5
        while (end < io.length) {
            val probe = io.peekAt(end, 1) ?: break
            val value = probe[0].toInt() and 0xFF
            if (value != 0x0A && value != 0x0D && value != 0x20 && value != 0x09 && value != 0x00) break
            end++
        }
        return if (end < io.length) end else -1L
    }

    private fun findAscii(io: BinaryIo, from: Long, needle: String): Long {
        val pattern = needle.toByteArray(Charsets.ISO_8859_1)
        if (pattern.isEmpty() || from < 0) return -1L
        val chunk = 1 shl 20
        var position = from
        var carry = ByteArray(0)
        while (position < io.length) {
            val size = minOf(chunk.toLong(), io.length - position).toInt()
            if (size <= 0) break
            val bytes = io.peekAt(position, size) ?: break
            val combined = if (carry.isEmpty()) bytes else carry + bytes
            val found = Bytes.indexOf(combined, pattern)
            if (found >= 0) return position - carry.size + found
            carry = if (combined.size >= pattern.size - 1) {
                combined.copyOfRange(combined.size - (pattern.size - 1), combined.size)
            } else {
                combined
            }
            position += size
        }
        return -1L
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                val probe = io.peekAt(0, minOf(8L, io.length).toInt())?.let { String(it, Charsets.ISO_8859_1) } ?: ""
                if (!probe.startsWith("%PDF-")) {
                    return listOf(MetadataFinding(MetadataKind.OTHER, "not a PDF file"))
                }
                val tailStart = pdfTailStart(io)
                if (tailStart > 0) {
                    findings.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the PDF trailer"))
                }
                var position = 0L
                var guard = 0
                while (position < io.length && guard++ < 1_000_000) {
                    val header = findAscii(io, position, "obj")
                    if (header < 0) break
                    val start = statementStart(io, header)
                    if (start < 0) {
                        position = header + 3
                        continue
                    }
                    val span = objectSpan(io, header)
                    if (span.end <= header) break
                    for (key in keysFor(io, span.dictStart, span.dictEnd)) {
                        var search = span.dictStart
                        var keyGuard = 0
                        while (search < span.dictEnd && keyGuard++ < 4096) {
                            val at = findAscii(io, search, key)
                            if (at < 0 || at >= span.dictEnd) break
                            if (isKeyBoundary(io, at, key.length)) {
                                findings.add(MetadataFinding(kindOf(key), "PDF $key"))
                            }
                            search = at + key.length
                        }
                    }
                    if (span.streamStart > 0) {
                        val length = minOf(8192L, io.length - span.streamStart).toInt()
                        val head = io.peekAt(span.streamStart, length) ?: ByteArray(0)
                        val text = String(head, Charsets.ISO_8859_1)
                        if (text.contains("xpacket") || text.contains("x:xmpmeta")) {
                            findings.add(MetadataFinding(MetadataKind.XMP, "XMP packet"))
                        }
                    }
                    position = span.end
                }
                var trailerAt = 0L
                var trailerGuard = 0
                while (trailerAt < io.length && trailerGuard++ < 4096) {
                    val at = findAscii(io, trailerAt, "trailer")
                    if (at < 0) break
                    val end = findAscii(io, at + 7, "startxref")
                    val limit = if (end > at) end else io.length
                    for (key in bannedKeys) {
                        var search = at + 7
                        var keyGuard = 0
                        while (search < limit && keyGuard++ < 4096) {
                            val keyAt = findAscii(io, search, key)
                            if (keyAt < 0 || keyAt >= limit) break
                            if (isKeyBoundary(io, keyAt, key.length)) {
                                findings.add(MetadataFinding(kindOf(key), "PDF trailer $key"))
                            }
                            search = keyAt + key.length
                        }
                    }
                    trailerAt = limit
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val header = io.peekAt(0, minOf(8L, io.length).toInt())?.let { String(it, Charsets.ISO_8859_1) } ?: return false
                if (!header.startsWith("%PDF-")) return false
                if (pdfTailStart(io) > 0) return false
                val startxref = findAscii(io, maxOf(0L, io.length - 8192), "startxref")
                if (startxref < 0) return findAscii(io, 0, "trailer") < 0 && io.length > 0
                val digitsLength = minOf(24L, io.length - (startxref + 9)).toInt()
                if (digitsLength <= 0) return false
                val digits = io.peekAt(startxref + 9, digitsLength)?.let { String(it, Charsets.ISO_8859_1) } ?: return false
                val offset = digits.trim().split(" ", "\n", "\r").firstOrNull()?.toLongOrNull() ?: return false
                if (offset <= 0 || offset >= io.length) return false
                val at = io.peekAt(offset, 5)?.let { String(it, Charsets.ISO_8859_1) } ?: return false
                at.startsWith("xref") || at.contains("obj")
            }
        } catch (_: Exception) {
            false
        }
    }
}

object TextHandler : FormatHandler {

    override val id: String = "text"
    override val formats: Set<MediaFormat> = setOf(
        MediaFormat.TEXT, MediaFormat.SVG, MediaFormat.HTML, MediaFormat.XML, MediaFormat.RTF
    )

    // A text rewrite needs the whole document in memory. On a phone a 64 MiB buffer plus the
    // decoded String plus the output copy is an out of memory error waiting to happen, so the
    // limit is deliberately modest and larger files are reported rather than attempted.
    private const val MAX_WRITE_BYTES = 16L * 1024 * 1024
    private const val ENCODING_WINDOW = 8192
    private const val RTF_GROUP_LIMIT = 1 shl 20

    private val htmlMetaNames = listOf(
        "author", "generator", "description", "keywords", "producer", "creator", "publisher",
        "copyright", "last-modified", "date", "dcterms.created", "dcterms.modified", "og:site_name",
        "og:title", "twitter:creator"
    )
    private val namespacePrefixes = listOf("inkscape", "sodipodi", "sketch", "figma", "adobe")
    private val elementPrefixes = listOf("dc", "dcterms", "cp", "photoshop", "xmp", "pdf")
    private val encodingTokens = listOf("utf-16be", "utf-16le", "utf-32be", "utf-32le", "utf-16", "utf-32")
    private val rtfIdentityWords = listOf(
        "author", "company", "title", "subject", "manager", "operator", "keywords", "category",
        "comment", "doccomm", "hlinkbase", "creatim", "revtim", "printim", "buptim", "version",
        "vern", "edmins", "nofpages", "nofwords", "nofchars"
    )

    /**
     * Destination groups that are not part of the info block but still carry identity: the raw
     * XMP packet Word embeds, the SharePoint datastore, annotation authorship and the revision
     * save id table that fingerprints every editing session.
     */
    private val rtfDestinationWords = listOf(
        "xmlprops", "datastore", "atnid", "atnauthor", "atndate", "annotation", "rsidtbl"
    )

    private class Edit(val start: Int, val end: Int, val replacement: ByteArray?, val finding: MetadataFinding)

    private class Plan {
        val edits = ArrayList<Edit>()
        var transcoded = false
    }

    private class Tag(val start: Int, val end: Int, val nameEnd: Int, val selfClosing: Boolean)

    private class Attribute(
        val nameStart: Int,
        val nameEnd: Int,
        val valueStart: Int,
        val valueEnd: Int,
        val value: String
    )

    private fun ascii(value: String): ByteArray = value.toByteArray(Charsets.US_ASCII)

    private fun matchesAt(data: ByteArray, index: Int, token: ByteArray): Boolean {
        if (index < 0 || index + token.size > data.size) return false
        for (i in token.indices) if (data[index + i] != token[i]) return false
        return true
    }

    private fun matchesIgnoreCase(data: ByteArray, index: Int, token: ByteArray): Boolean {
        if (index < 0 || index + token.size > data.size) return false
        for (i in token.indices) {
            val left = data[index + i].toInt() and 0xFF
            val right = token[i].toInt() and 0xFF
            val normalised = if (left in 0x41..0x5A) left + 0x20 else left
            if (normalised != right) return false
        }
        return true
    }

    private fun indexOfToken(data: ByteArray, from: Int, token: ByteArray, limit: Int): Int {
        var index = from
        val last = minOf(limit, data.size) - token.size
        while (index <= last) {
            if (data[index] == token[0] && matchesAt(data, index, token)) return index
            index++
        }
        return -1
    }

    private fun isNameByte(value: Int): Boolean =
        (value in 0x61..0x7A) || (value in 0x41..0x5A) || (value in 0x30..0x39) ||
            value == '_'.code || value == '-'.code || value == '.'.code || value == ':'.code

    private fun isSpace(value: Int): Boolean = value == 0x20 || value == 0x09 || value == 0x0A || value == 0x0D

    private fun lower(data: ByteArray, from: Int, to: Int): String {
        val builder = StringBuilder(maxOf(0, to - from))
        var index = from
        while (index < to) {
            val value = data[index].toInt() and 0xFF
            val normalised = if (value in 0x41..0x5A) value + 0x20 else value
            builder.append(normalised.toChar())
            index++
        }
        return builder.toString()
    }

    private fun prefixOf(data: ByteArray, from: Int, to: Int): String {
        var colon = -1
        for (i in from until to) if (data[i].toInt() == ':'.code) colon = i
        if (colon < 0) return ""
        return lower(data, from, colon)
    }

    private fun localName(data: ByteArray, from: Int, to: Int): String {
        var start = from
        for (i in from until to) if (data[i].toInt() == ':'.code) start = i + 1
        return lower(data, start, to)
    }

    private fun readTag(data: ByteArray, start: Int, limit: Int): Tag? {
        var index = start + 1
        if (index >= limit) return null
        var closing = false
        if (data[index].toInt() == '/'.code) {
            closing = true
            index++
        }
        val nameStart = index
        while (index < limit && isNameByte(data[index].toInt() and 0xFF)) index++
        if (index == nameStart) return null
        val nameEnd = index
        var quote = 0
        var cursor = index
        while (cursor < limit) {
            val value = data[cursor].toInt() and 0xFF
            if (quote == 0) {
                if (value == '"'.code || value == '\''.code) {
                    quote = value
                } else if (value == '>'.code) {
                    var back = cursor - 1
                    while (back > nameEnd && isSpace(data[back].toInt() and 0xFF)) back--
                    val selfClosing = back > nameEnd && data[back].toInt() == '/'.code
                    return Tag(start, cursor + 1, nameEnd, selfClosing && !closing)
                }
            } else if (value == quote) {
                quote = 0
            }
            cursor++
        }
        return null
    }

    private fun indexOfByte(data: ByteArray, from: Int, value: Int, limit: Int): Int {
        var index = from
        while (index < limit) {
            if (data[index].toInt() == value) return index
            index++
        }
        return -1
    }

    private fun firstSpaceOrAngle(data: ByteArray, from: Int, limit: Int): Int {
        var index = from
        while (index < limit) {
            val value = data[index].toInt() and 0xFF
            if (isSpace(value) || value == '>'.code || value == '/'.code) return index
            index++
        }
        return limit
    }

    private fun attributes(data: ByteArray, tag: Tag): List<Attribute> {
        val list = ArrayList<Attribute>()
        var index = tag.nameEnd
        while (index < tag.end && index < data.size) {
            val value = data[index].toInt() and 0xFF
            if (value == '>'.code) break
            if (!isNameByte(value)) {
                index++
                continue
            }
            val nameStart = index
            while (index < tag.end && isNameByte(data[index].toInt() and 0xFF)) index++
            val nameEnd = index
            var probe = index
            var valueStart = index
            var valueEnd = index
            while (probe < tag.end && isSpace(data[probe].toInt() and 0xFF)) probe++
            if (probe < tag.end && data[probe].toInt() == '='.code) {
                probe++
                while (probe < tag.end && isSpace(data[probe].toInt() and 0xFF)) probe++
                if (probe < tag.end) {
                    val marker = data[probe].toInt() and 0xFF
                    if (marker == '"'.code || marker == '\''.code) {
                        val close = indexOfByte(data, probe + 1, marker, tag.end)
                        if (close > 0) {
                            valueStart = probe + 1
                            valueEnd = close + 1
                            probe = close + 1
                        } else {
                            probe = tag.end
                        }
                    } else {
                        val close = firstSpaceOrAngle(data, probe, tag.end)
                        valueStart = probe
                        valueEnd = close
                        probe = close
                    }
                }
            }
            val textEnd = if (valueEnd > valueStart && (data[valueEnd - 1].toInt() == '"'.code || data[valueEnd - 1].toInt() == '\''.code)) {
                valueEnd - 1
            } else {
                valueEnd
            }
            val text = if (textEnd > valueStart) String(data, valueStart, textEnd - valueStart, Charsets.ISO_8859_1) else ""
            list.add(Attribute(nameStart, nameEnd, valueStart, valueEnd, text))
            index = maxOf(probe, index + 1)
        }
        return list
    }

    private fun rebuildTag(data: ByteArray, tag: Tag, drops: List<Attribute>): ByteArray {
        val builder = java.io.ByteArrayOutputStream(tag.end - tag.start)
        var cursor = tag.start
        for (attribute in drops.sortedBy { it.nameStart }) {
            var from = attribute.nameStart
            while (from > cursor && isSpace(data[from - 1].toInt() and 0xFF)) from--
            if (from < cursor) continue
            builder.write(data, cursor, from - cursor)
            cursor = maxOf(attribute.valueEnd, attribute.nameEnd)
        }
        builder.write(data, cursor, tag.end - cursor)
        return builder.toByteArray()
    }

    private fun closingTag(bytes: ByteArray, tag: Tag, prefix: String, name: String, limit: Int): Int {
        val local = ascii("</" + (if (prefix.isEmpty()) "" else "$prefix:") + name)
        var index = tag.end
        while (index < limit) {
            if (matchesIgnoreCase(bytes, index, local)) {
                var cursor = index + local.size
                while (cursor < limit && isSpace(bytes[cursor].toInt() and 0xFF)) cursor++
                if (cursor < limit && bytes[cursor].toInt() == '>'.code) return cursor + 1
            }
            if (matchesAt(bytes, index, ascii("<!--"))) {
                val close = indexOfToken(bytes, index + 4, ascii("-->"), limit)
                index = if (close < 0) index + 4 else close + 3
                continue
            }
            index++
        }
        return -1
    }

    private fun normaliseEncodingTokens(bytes: ByteArray): ByteArray {
        val window = minOf(bytes.size, ENCODING_WINDOW)
        var found = false
        var index = 0
        while (index < window && !found) {
            for (token in encodingTokens) {
                val raw = ascii(token)
                if (matchesIgnoreCase(bytes, index, raw)) {
                    val after = index + raw.size
                    val boundary = after >= bytes.size || {
                        val value = bytes[after].toInt() and 0xFF
                        !(value in 0x30..0x39 || value in 0x41..0x5A || value in 0x61..0x7A || value == '-'.code)
                    }()
                    if (boundary) {
                        found = true
                        break
                    }
                }
            }
            index++
        }
        if (!found) return bytes
        val out = java.io.ByteArrayOutputStream(bytes.size)
        var cursor = 0
        index = 0
        while (index < bytes.size) {
            var matched = -1
            for (token in encodingTokens) {
                val raw = ascii(token)
                if (matchesIgnoreCase(bytes, index, raw)) {
                    val after = index + raw.size
                    val boundary = after >= bytes.size || {
                        val value = bytes[after].toInt() and 0xFF
                        !(value in 0x30..0x39 || value in 0x41..0x5A || value in 0x61..0x7A || value == '-'.code)
                    }()
                    if (boundary) {
                        matched = raw.size
                        break
                    }
                }
            }
            if (matched > 0 && index < ENCODING_WINDOW) {
                out.write(bytes, cursor, index - cursor)
                out.write(ascii("UTF-8"))
                index += matched
                cursor = index
            } else {
                index++
            }
        }
        out.write(bytes, cursor, bytes.size - cursor)
        return out.toByteArray()
    }

    private fun analyse(bytes: ByteArray, markup: Boolean, rtf: Boolean): Plan {
        val plan = Plan()
        if (rtf) {
            analyseRtf(bytes, plan)
            return plan
        }
        if (!markup) return plan
        var index = 0
        val limit = bytes.size
        var commentsUnterminated = false
        var instructionsUnterminated = false
        val absentClosings = HashSet<String>()
        while (index < limit) {
            if (bytes[index].toInt() != '<'.code) {
                index++
                continue
            }
            if (matchesAt(bytes, index, ascii("<!--"))) {
                if (commentsUnterminated) {
                    index += 4
                    continue
                }
                val close = indexOfToken(bytes, index + 4, ascii("-->"), limit)
                if (close < 0) {
                    commentsUnterminated = true
                    index += 4
                    continue
                }
                plan.edits.add(Edit(index, close + 3, null, MetadataFinding(MetadataKind.COMMENT, "markup comment")))
                index = close + 3
                continue
            }
            if (matchesAt(bytes, index, ascii("<?"))) {
                if (instructionsUnterminated) {
                    index += 2
                    continue
                }
                val close = indexOfToken(bytes, index + 2, ascii("?>"), limit)
                if (close < 0) {
                    instructionsUnterminated = true
                    index += 2
                    continue
                }
                val isXmlDeclaration = matchesIgnoreCase(bytes, index + 2, ascii("xml")) &&
                    !matchesIgnoreCase(bytes, index + 2, ascii("xml-stylesheet"))
                if (isXmlDeclaration) {
                    var standalone = false
                    var cursor = index
                    while (cursor + 10 <= close + 2) {
                        if (matchesIgnoreCase(bytes, cursor, ascii("standalone"))) {
                            standalone = true
                            break
                        }
                        cursor++
                    }
                    if (standalone) {
                        plan.edits.add(
                            Edit(
                                index, close + 2, ascii("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
                                MetadataFinding(MetadataKind.DOCUMENT_PROPERTY, "xml declaration attribute")
                            )
                        )
                    }
                } else if (!matchesIgnoreCase(bytes, index + 2, ascii("xml-stylesheet"))) {
                    plan.edits.add(
                        Edit(
                            index, close + 2, null,
                            MetadataFinding(MetadataKind.DOCUMENT_PROPERTY, "processing instruction")
                        )
                    )
                }
                index = close + 2
                continue
            }
            val tag = readTag(bytes, index, limit)
            if (tag == null) {
                index++
                continue
            }
            val closing = bytes.getOrElse(index + 1) { 0 }.toInt() == '/'.code
            val nameStart = index + 1 + (if (closing) 1 else 0)
            val name = localName(bytes, nameStart, tag.nameEnd)
            val prefix = prefixOf(bytes, nameStart, tag.nameEnd)
            if (!closing && (name == "metadata" || name == "rdf" || elementPrefixes.contains(prefix))) {
                val finding = when {
                    name == "metadata" -> MetadataFinding(MetadataKind.XMP, "metadata element")
                    name == "rdf" -> MetadataFinding(MetadataKind.XMP, "RDF metadata block")
                    else -> MetadataFinding(MetadataKind.DOCUMENT_PROPERTY, "document metadata element")
                }
                val key = prefix + "|" + name
                val closeEnd = if (absentClosings.contains(key)) -1
                else closingTag(bytes, tag, prefix, name, limit)
                if (closeEnd <= 0) absentClosings.add(key)
                if (closeEnd > 0) {
                    plan.edits.add(Edit(tag.start, closeEnd, null, finding))
                    index = closeEnd
                    continue
                }
                if (tag.selfClosing) {
                    plan.edits.add(Edit(tag.start, tag.end, null, finding))
                }
                index = tag.end
                continue
            }
            if (!closing) {
                val list = attributes(bytes, tag)
                if (name == "meta") {
                    var drop = false
                    var metaName = ""
                    for (attribute in list) {
                        val attributeName = localName(bytes, attribute.nameStart, attribute.nameEnd)
                        if (attributeName == "name" || attributeName == "property" || attributeName == "http-equiv") {
                            metaName = attribute.value.lowercase()
                            drop = htmlMetaNames.contains(metaName)
                            break
                        }
                    }
                    if (drop) {
                        plan.edits.add(
                            Edit(
                                tag.start, tag.end, null,
                                MetadataFinding(MetadataKind.DOCUMENT_PROPERTY, "meta $metaName")
                            )
                        )
                        index = tag.end
                        continue
                    }
                }
                val drops = ArrayList<Attribute>()
                var generator = false
                var namespaced = false
                for (attribute in list) {
                    val rawName = lower(bytes, attribute.nameStart, attribute.nameEnd)
                    val attributePrefix = prefixOf(bytes, attribute.nameStart, attribute.nameEnd)
                    if (rawName == "generator") {
                        generator = true
                        drops.add(attribute)
                        continue
                    }
                    if (rawName.startsWith("xmlns:") && namespacePrefixes.contains(rawName.substring(6))) {
                        drops.add(attribute)
                        continue
                    }
                    if (attributePrefix.isNotEmpty() && namespacePrefixes.contains(attributePrefix)) {
                        namespaced = true
                        drops.add(attribute)
                    }
                }
                if (generator) {
                    plan.edits.add(
                        Edit(
                            tag.start, tag.end, rebuildTag(bytes, tag, drops),
                            MetadataFinding(MetadataKind.SOFTWARE, "generator attribute")
                        )
                    )
                } else if (namespaced) {
                    plan.edits.add(
                        Edit(
                            tag.start, tag.end, rebuildTag(bytes, tag, drops),
                            MetadataFinding(MetadataKind.OTHER, "producer attribute")
                        )
                    )
                } else if (drops.isNotEmpty()) {
                    plan.edits.add(Edit(tag.start, tag.end, rebuildTag(bytes, tag, drops), MetadataFinding(MetadataKind.OTHER, "namespace declaration")))
                }
            }
            index = tag.end
        }
        return plan
    }

    private fun analyseRtf(bytes: ByteArray, plan: Plan) {
        var index = 0
        val limit = bytes.size
        while (index < limit - 2) {
            if (bytes[index].toInt() != '{'.code || bytes[index + 1].toInt() != '\\'.code) {
                index++
                continue
            }
            var cursor = index + 2
            if (cursor < limit && bytes[cursor].toInt() == '*'.code) {
                cursor++
                if (cursor < limit && bytes[cursor].toInt() == '\\'.code) cursor++
            }
            val wordStart = cursor
            while (cursor < limit && (bytes[cursor].toInt() and 0xFF) in 0x61..0x7A) cursor++
            val word = String(bytes, wordStart, cursor - wordStart, Charsets.US_ASCII).lowercase()
            val kind = when {
                word == "generator" -> MetadataKind.SOFTWARE
                rtfDestinationWords.contains(word) -> when (word) {
                    "xmlprops" -> MetadataKind.XMP
                    "atnid", "atnauthor", "atndate", "annotation" -> MetadataKind.AUTHOR
                    "rsidtbl" -> MetadataKind.REVISION_ID
                    else -> MetadataKind.DOCUMENT_PROPERTY
                }
                word == "info" || rtfIdentityWords.contains(word) -> MetadataKind.DOCUMENT_PROPERTY
                else -> null
            }
            if (kind != null) {
                val end = matchingBrace(bytes, index, minOf(limit, index + RTF_GROUP_LIMIT))
                if (end > 0) {
                    plan.edits.add(Edit(index, end, null, MetadataFinding(kind, "RTF $word group")))
                    index = end
                    continue
                }
            }
            index++
        }
    }

    private fun matchingBrace(bytes: ByteArray, from: Int, limit: Int): Int {
        var depth = 0
        var index = from
        while (index < limit) {
            val value = bytes[index].toInt()
            if (value == '\\'.code) {
                index += 2
                continue
            }
            if (value == '{'.code) {
                depth++
            } else if (value == '}'.code) {
                depth--
                if (depth == 0) return index + 1
            }
            index++
        }
        return -1
    }

    private class Decoded(val bytes: ByteArray, val bom: Boolean, val transcoded: Boolean, val legacy: Boolean)

    private fun decodeInput(raw: ByteArray): Decoded {
        if (raw.size >= 4 && (raw[0].toInt() and 0xFF) == 0xFF && (raw[1].toInt() and 0xFF) == 0xFE &&
            raw[2].toInt() == 0x00 && raw[3].toInt() == 0x00
        ) {
            return Decoded(transcode(raw, 4, Charsets.UTF_32LE), true, true, false)
        }
        if (raw.size >= 4 && raw[0].toInt() == 0x00 && raw[1].toInt() == 0x00 &&
            (raw[2].toInt() and 0xFF) == 0xFE && (raw[3].toInt() and 0xFF) == 0xFF
        ) {
            return Decoded(transcode(raw, 4, Charsets.UTF_32BE), true, true, false)
        }
        if (raw.size >= 3 && (raw[0].toInt() and 0xFF) == 0xEF && (raw[1].toInt() and 0xFF) == 0xBB && (raw[2].toInt() and 0xFF) == 0xBF) {
            return Decoded(raw.copyOfRange(3, raw.size), true, false, false)
        }
        if (raw.size >= 2 && (raw[0].toInt() and 0xFF) == 0xFF && (raw[1].toInt() and 0xFF) == 0xFE) {
            return Decoded(transcode(raw, 2, Charsets.UTF_16LE), true, true, false)
        }
        if (raw.size >= 2 && (raw[0].toInt() and 0xFF) == 0xFE && (raw[1].toInt() and 0xFF) == 0xFF) {
            return Decoded(transcode(raw, 2, Charsets.UTF_16BE), true, true, false)
        }
        if (raw.size >= 4) {
            val first = raw[0].toInt() and 0xFF
            val second = raw[1].toInt() and 0xFF
            val third = raw[2].toInt() and 0xFF
            val fourth = raw[3].toInt() and 0xFF
            val littleEndian = (first == 0x3C && second == 0x00 && third != 0x00 && fourth == 0x00) ||
                (first == 0x7B && second == 0x00)
            val bigEndian = (first == 0x00 && second == 0x3C && third == 0x00 && fourth != 0x00)
            if (littleEndian) return Decoded(transcode(raw, 0, Charsets.UTF_16LE), false, true, false)
            if (bigEndian) return Decoded(transcode(raw, 0, Charsets.UTF_16BE), false, true, false)
        }
        return Decoded(raw, false, false, !isUtf8(raw))
    }

    private fun isUtf8(raw: ByteArray): Boolean {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        return try {
            decoder.decode(java.nio.ByteBuffer.wrap(raw))
            true
        } catch (_: Exception) {
            false
        }
    }

    /** The usual suspects for text that is not Unicode: Windows code page first, Latin-1 as a floor. */
    private fun legacyCharset(): java.nio.charset.Charset = try {
        java.nio.charset.Charset.forName("windows-1252")
    } catch (_: Exception) {
        Charsets.ISO_8859_1
    }

    private fun transcode(raw: ByteArray, offset: Int, charset: java.nio.charset.Charset): ByteArray =
        String(raw, offset, raw.size - offset, charset).toByteArray(Charsets.UTF_8)

    /**
     * scrub used the detected format while inspect and validate re-sniffed the decoded bytes.
     * When those disagreed the rewrite applied the wrong rule set and verification then failed.
     * Every entry point goes through here instead.
     */
    private fun formatFor(bytes: ByteArray, detected: MediaFormat?): MediaFormat {
        val sniffed = sniff(bytes)
        return if (detected == MediaFormat.RTF || sniffed == MediaFormat.RTF) MediaFormat.RTF else sniffed
    }

    private fun sniff(bytes: ByteArray): MediaFormat {
        val window = minOf(bytes.size, 4096)
        val text = lower(bytes, 0, window)
        if (text.startsWith("{\\rtf")) return MediaFormat.RTF
        if (text.contains("<svg") || text.contains("xmlns=\"http://www.w3.org/2000/svg\"")) return MediaFormat.SVG
        if (text.contains("<!doctype html") || text.contains("<html") || text.contains("<meta ") ||
            text.contains("<head") || text.contains("<body")
        ) {
            return MediaFormat.HTML
        }
        if (text.startsWith("<?xml") || text.contains("<") && text.contains(">")) return MediaFormat.XML
        return MediaFormat.TEXT
    }

    private fun read(file: File, limit: Long): ByteArray? = try {
        if (file.length() > limit) null else BinaryIo.open(file).use { io -> io.peekAt(0, io.length.toInt()) }
    } catch (_: Exception) {
        null
    }

    private fun apply(bytes: ByteArray, plan: Plan): ByteArray? {
        if (plan.edits.isEmpty()) return bytes
        val edits = plan.edits.sortedBy { it.start }
        val out = java.io.ByteArrayOutputStream(bytes.size)
        var cursor = 0
        for (edit in edits) {
            if (edit.start < cursor || edit.start > bytes.size || edit.end > bytes.size) return null
            out.write(bytes, cursor, edit.start - cursor)
            edit.replacement?.let { out.write(it) }
            cursor = edit.end
        }
        out.write(bytes, cursor, bytes.size - cursor)
        return out.toByteArray()
    }

    private fun collected(plan: Plan): List<MetadataFinding> = plan.edits.map { it.finding }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val removed = ArrayList<MetadataFinding>()
        val raw = try {
            if (ctx.source.length() > MAX_WRITE_BYTES) {
                return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "text file too large")
            }
            BinaryIo.open(ctx.source).use { io -> io.peekAt(0, ctx.source.length().toInt()) }
                ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "empty file")
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = e.message ?: "read failed")
        }
        val decoded = decodeInput(raw)
        if (decoded.bom) removed.add(MetadataFinding(MetadataKind.ENCODING_MARKER, "byte order mark"))
        if (decoded.legacy && !ctx.options.normalizeTextToUtf8) {
            return ScrubOutcome(
                false, PurgeStrategy.NONE, emptyList(),
                message = "text is not valid UTF-8; enable normalisation instead of trusting a byte level scrub"
            )
        }
        var body = if (decoded.transcoded) normaliseEncodingTokens(decoded.bytes) else decoded.bytes
        if (decoded.legacy) {
            body = normaliseEncodingTokens(transcode(raw, 0, legacyCharset()))
            removed.add(MetadataFinding(MetadataKind.ENCODING_MARKER, "re-encoded from a legacy single byte encoding"))
        }
        val format = formatFor(body, ctx.detection.format)
        val plan = analyse(
            body,
            format == MediaFormat.SVG || format == MediaFormat.HTML || format == MediaFormat.XML,
            format == MediaFormat.RTF
        )
        removed.addAll(collected(plan))
        if (plan.edits.isEmpty() && !decoded.bom && !decoded.transcoded) {
            return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable markers")
        }
        if (decoded.transcoded && plan.edits.isEmpty()) {
            removed.add(MetadataFinding(MetadataKind.ENCODING_MARKER, "transcoded to UTF-8"))
        }
        val output = apply(body, plan)
            ?: return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "inconsistent edit plan")
        try {
            FileOutputStream(ctx.target).use { out ->
                out.write(output)
                out.flush()
            }
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "write failed")
        }
        return ScrubOutcome(true, PurgeStrategy.TEXT_SANITISE, removed.distinct(), emptyList(), true)
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            if (file.length() <= 0L) return listOf(MetadataFinding(MetadataKind.OTHER, "empty file"))
            if (file.length() > MAX_WRITE_BYTES) {
                return listOf(MetadataFinding(MetadataKind.OTHER, "text file larger than the scannable limit"))
            }
            val raw = read(file, MAX_WRITE_BYTES) ?: return listOf(MetadataFinding(MetadataKind.OTHER, "text file could not be read"))
            val decoded = decodeInput(raw)
            if (decoded.bom) findings.add(MetadataFinding(MetadataKind.ENCODING_MARKER, "byte order mark"))
            if (decoded.legacy) {
                findings.add(MetadataFinding(MetadataKind.ENCODING_MARKER, "text is not valid UTF-8"))
            }
            val format = formatFor(decoded.bytes, null)
            val plan = analyse(
                decoded.bytes,
                format == MediaFormat.SVG || format == MediaFormat.HTML || format == MediaFormat.XML,
                format == MediaFormat.RTF
            )
            findings.addAll(collected(plan))
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            val raw = read(file, MAX_WRITE_BYTES) ?: return false
            if (raw.isEmpty()) return false
            val decoded = decodeInput(raw)
            if (decoded.bom) return false
            val bytes = decoded.bytes
            var index = 0
            while (index + 2 < bytes.size) {
                if ((bytes[index].toInt() and 0xFF) == 0xEF && (bytes[index + 1].toInt() and 0xFF) == 0xBF &&
                    (bytes[index + 2].toInt() and 0xFF) == 0xBD
                ) {
                    return false
                }
                index++
            }
            val format = formatFor(bytes, null)
            val plan = analyse(
                bytes,
                format == MediaFormat.SVG || format == MediaFormat.HTML || format == MediaFormat.XML,
                format == MediaFormat.RTF
            )
            plan.edits.isEmpty()
        } catch (_: Exception) {
            false
        }
    }
}
