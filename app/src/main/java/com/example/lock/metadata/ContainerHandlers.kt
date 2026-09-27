package com.example.lock.metadata

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.Inflater

/**
 * Shared recursive pipeline for container members: stage the member, detect its format,
 * inspect it, and when findings exist run its handler to a verified rewrite. Policy decides
 * whether an unstaggable or unhandled member is copied (compatibility mode) or refused
 * (maximum privacy). Inspect-side recursion depth is tracked per thread because the
 * FormatHandler inspect contract carries no depth argument.
 */
internal object EmbeddedScrubber {

    const val MAX_DEPTH = 3

    /** Disk-staged members larger than this are not verified; strict policy then refuses them. */
    const val MAX_STAGE_BYTES = 256L * 1024 * 1024

    private val inspectDepth = ThreadLocal.withInitial { 0 }

    fun prefix(name: String, finding: MetadataFinding): MetadataFinding =
        MetadataFinding(finding.kind, "[$name] ${finding.detail}", finding.location)

    /** Members must be verifiable: refuse anything that cannot be decoded and rewritten. */
    fun strictMembers(options: PurgeOptions): Boolean =
        options.recursiveMemberScrub && (options.refuseUnsupportedMembers || options.maximumPrivacy)

    class MemberOutcome(
        /** Rewritten member content the caller must consume and then destroy; null keeps the original. */
        val outFile: File?,
        val removed: List<MetadataFinding>,
        val retained: List<MetadataFinding>
    )

    private fun handlerFor(staged: File, options: PurgeOptions): Pair<FormatDetection, FormatHandler>? {
        val detection = FormatDetector.detect(staged)
        if (detection.format == MediaFormat.UNKNOWN && !options.aggressiveUnknownScrub) return null
        val handler = FormatRegistry.handlerFor(detection.format, staged)?.takeIf { it.implemented } ?: return null
        return detection to handler
    }

    fun inspectMember(staged: File, name: String, options: PurgeOptions): List<MetadataFinding> {
        val depth = inspectDepth.get()
        val pair = handlerFor(staged, options)
        if (pair == null) {
            return if (strictMembers(options)) {
                listOf(MetadataFinding(MetadataKind.EMBEDDED_FILE, "[$name] no verifiable handler for embedded content"))
            } else {
                emptyList()
            }
        }
        if (depth >= MAX_DEPTH) {
            return if (strictMembers(options)) {
                listOf(MetadataFinding(MetadataKind.EMBEDDED_FILE, "[$name] container nesting exceeds the recursion limit"))
            } else {
                emptyList()
            }
        }
        inspectDepth.set(depth + 1)
        return try {
            pair.second.inspect(staged, options).map { prefix(name, it) }
        } catch (e: Exception) {
            if (strictMembers(options)) {
                listOf(MetadataFinding(MetadataKind.EMBEDDED_FILE, "[$name] embedded inspection failed: ${e.message}"))
            } else {
                emptyList()
            }
        } finally {
            inspectDepth.set(depth)
        }
    }

    /**
     * Inspect the staged member and, when it carries findings, scrub it through its handler
     * with the same verify-then-accept rule the outer engine uses. Returns rewritten content
     * on success; null means the original bytes stay in the archive and [MemberOutcome.retained]
     * lists the findings that verification will still see, so the batch report cannot claim
     * more than was actually achieved.
     */
    fun scrubMember(ctx: PurgeContext, staged: File, name: String): MemberOutcome {
        val options = ctx.options
        val strict = strictMembers(options)
        if (ctx.depth >= MAX_DEPTH) {
            if (strict) throw PurgeRefusedException("member $name nests deeper than the container recursion limit")
            return MemberOutcome(null, emptyList(), emptyList())
        }
        val pair = handlerFor(staged, options)
        if (pair == null) {
            if (strict) {
                throw PurgeRefusedException(
                    "member $name has no structure aware handler; maximum privacy will not copy it through unverified"
                )
            }
            return MemberOutcome(null, emptyList(), emptyList())
        }
        val (detection, handler) = pair
        val before = try {
            handler.inspect(staged, options)
        } catch (e: Exception) {
            if (strict) throw PurgeRefusedException("member $name could not be inspected: ${e.message}")
            return MemberOutcome(null, emptyList(), emptyList())
        }
        if (before.isEmpty()) return MemberOutcome(null, emptyList(), emptyList())

        var produced: File? = null
        try {
            val directory = ctx.target.parentFile
            val out = File.createTempFile(".mpurge_memb", ".tmp", directory)
            out.setReadable(true, true)
            out.setWritable(true, true)
            produced = out
            val childCtx = PurgeContext(staged, out, detection, options, ReportingSink(), ctx.depth + 1)
            val outcome = handler.scrub(childCtx)
            if (!outcome.success || !out.exists() || out.length() == 0L) {
                SecureDelete.wipeQuietly(out, 1)
                produced = null
                if (strict) {
                    throw PurgeRefusedException("member $name could not be rewritten: ${outcome.message ?: "handler declined"}")
                }
                return MemberOutcome(null, emptyList(), before)
            }
            val survived = try {
                handler.inspect(out, options)
            } catch (e: Exception) {
                SecureDelete.wipeQuietly(out, 1)
                produced = null
                if (strict) throw PurgeRefusedException("member $name verification failed: ${e.message}")
                return MemberOutcome(null, emptyList(), before)
            }
            val unexpected = survived.filter { r ->
                outcome.residualRequired.none { it.kind == r.kind && it.detail == r.detail }
            }
            val valid = try {
                handler.validate(out, options)
            } catch (_: Exception) {
                false
            }
            if (unexpected.isNotEmpty() || !valid) {
                SecureDelete.wipeQuietly(out, 1)
                produced = null
                if (strict) {
                    val reason = if (unexpected.isNotEmpty()) unexpected.joinToString("; ") { it.toString() } else "structural validation failed"
                    throw PurgeRefusedException("member $name failed embedded verification: $reason")
                }
                return MemberOutcome(null, emptyList(), before)
            }
            return MemberOutcome(out, outcome.removed.distinct(), survived.distinct())
        } catch (refused: PurgeRefusedException) {
            produced?.let { SecureDelete.wipeQuietly(it, 1) }
            throw refused
        } catch (e: Exception) {
            produced?.let { SecureDelete.wipeQuietly(it, 1) }
            if (strict) throw PurgeRefusedException("member $name processing failed: ${e.message ?: e.javaClass.simpleName}")
            return MemberOutcome(null, emptyList(), before)
        }
    }

    /** Stage member bytes onto disk next to the target so handlers can work file-to-file. */
    fun stageBytes(ctx: PurgeContext, name: String, content: ByteArray): File? {
        return try {
            val ext = memberExtension(name)
            val file = File.createTempFile(".mpurge_memb", ext, ctx.target.parentFile)
            file.setReadable(true, true)
            file.setWritable(true, true)
            file.writeBytes(content)
            file
        } catch (_: Exception) {
            null
        }
    }

    fun memberExtension(name: String): String {
        val dot = name.lastIndexOf('.')
        if (dot <= 0 || dot >= name.length - 1) return ".tmp"
        val raw = name.substring(dot + 1).lowercase()
        return if (raw.length <= 8 && raw.all { it.isLetterOrDigit() }) ".$raw" else ".tmp"
    }

    fun wipeStaged(file: File?) {
        if (file != null && file.name.startsWith(".mpurge_memb")) {
            SecureDelete.wipeQuietly(file, 1)
        }
    }
}

object ZipContainerHandler : FormatHandler {

    override val id: String = "zip"
    override val formats: Set<MediaFormat> = setOf(
        MediaFormat.ZIP, MediaFormat.DOCX, MediaFormat.XLSX, MediaFormat.PPTX, MediaFormat.ODF, MediaFormat.EPUB
    )

    private const val MAX_ENTRIES = 200_000
    private const val ZIP64_LIMIT = 0xFFFFFFFEL

    private class Entry(
        val name: String,
        val rawName: ByteArray,
        val method: Int,
        val flags: Int,
        val crc: Long,
        val compressedSize: Long,
        val uncompressedSize: Long,
        val localOffset: Long,
        val externalAttributes: Int,
        val internalAttributes: Int,
        val versionMadeBy: Int,
        val versionNeeded: Int,
        val dataStart: Long,
        val needsZip64: Boolean
    )

    private class Archive(val entries: List<Entry>, val base: Long, val end: Long)

    private fun hasCentralSignature(io: BinaryIo, offset: Long): Boolean {
        if (offset < 0 || offset + 4 > io.length) return false
        val probe = io.peekAt(offset, 4) ?: return false
        return Bytes.u32le(probe, 0) == 0x02014b50L
    }

    private fun readEntries(io: BinaryIo): List<Entry>? = readArchive(io)?.entries

    private fun readArchive(io: BinaryIo): Archive? {
        val length = io.length
        if (length < 22) return null
        val tailLength = minOf(length, 65557L).toInt()
        val tail = io.peekAt(length - tailLength, tailLength) ?: return null
        var eocd = -1
        for (i in tail.size - 22 downTo 0) {
            if (Bytes.u32le(tail, i) == 0x06054b50L) {
                eocd = i
                break
            }
        }
        if (eocd < 0) return null
        var total = Bytes.u16le(tail, eocd + 10).toLong()
        var cdOffset = Bytes.u32le(tail, eocd + 16)
        val cdSize = Bytes.u32le(tail, eocd + 12)
        val needsZip64 = total == 0xFFFFL || cdOffset == 0xFFFFFFFFL || cdSize == 0xFFFFFFFFL
        var zip64Entries = false
        if (needsZip64) {
            val locatorAt = length - tailLength + eocd - 20
            if (locatorAt >= 0) {
                val locator = io.peekAt(locatorAt, 20) ?: return null
                if (Bytes.u32le(locator, 0) == 0x07064b50L) {
                    val zip64At = Bytes.u64le(locator, 8)
                    val record = io.peekAt(zip64At, 56) ?: return null
                    if (Bytes.u32le(record, 0) != 0x06064b50L) return null
                    total = Bytes.u64le(record, 32)
                    cdOffset = Bytes.u64le(record, 48)
                    zip64Entries = true
                }
            }
        }
        var base = 0L
        if (!zip64Entries) {
            if (cdOffset <= 0 || cdSize <= 0) return null
            val eocdFileOffset = length - tailLength + eocd
            val candidate = eocdFileOffset - cdSize - cdOffset
            base = when {
                candidate in 0 until length && hasCentralSignature(io, cdOffset + candidate) -> candidate
                hasCentralSignature(io, cdOffset) -> 0L
                else -> return null
            }
        }
        if (total <= 0 || total > MAX_ENTRIES) {
            if (total == 0L) return null
        }
        var position = cdOffset + base
        val entries = ArrayList<Entry>()
        var guard = 0
        while (position + 46 <= length && guard++ < MAX_ENTRIES) {
            val header = io.peekAt(position, 46) ?: return null
            if (Bytes.u32le(header, 0) != 0x02014b50L) break
            val versionMadeBy = Bytes.u16le(header, 4)
            val versionNeeded = Bytes.u16le(header, 6)
            val flags = Bytes.u16le(header, 8)
            val method = Bytes.u16le(header, 10)
            var crc = Bytes.u32le(header, 16)
            var compressedSize = Bytes.u32le(header, 20)
            var uncompressedSize = Bytes.u32le(header, 24)
            val nameLength = Bytes.u16le(header, 28)
            val extraLength = Bytes.u16le(header, 30)
            val commentLength = Bytes.u16le(header, 32)
            val internalAttributes = Bytes.u16le(header, 36)
            val externalAttributes = Bytes.u32le(header, 38).toInt()
            var localOffset = Bytes.u32le(header, 42) + base
            val nameBytes = io.peekAt(position + 46, nameLength) ?: return null
            val name = if (flags and 0x800 != 0) {
                String(nameBytes, Charsets.UTF_8)
            } else {
                try {
                    String(nameBytes, charset("Cp437"))
                } catch (_: Exception) {
                    String(nameBytes, Charsets.ISO_8859_1)
                }
            }
            var entryZip64 = false
            if (extraLength > 0) {
                val extra = io.peekAt(position + 46 + nameLength, extraLength) ?: return null
                var cursor = 0
                while (cursor + 4 <= extra.size) {
                    val id = Bytes.u16le(extra, cursor)
                    val size = Bytes.u16le(extra, cursor + 2)
                    if (cursor + 4 + size > extra.size) break
                    if (id == 0x0001) {
                        entryZip64 = true
                        var field = cursor + 4
                        if (uncompressedSize == 0xFFFFFFFFL && field + 8 <= extra.size) {
                            uncompressedSize = Bytes.u64le(extra, field)
                            field += 8
                        }
                        if (compressedSize == 0xFFFFFFFFL && field + 8 <= extra.size) {
                            compressedSize = Bytes.u64le(extra, field)
                            field += 8
                        }
                        if (localOffset == 0xFFFFFFFFL && field + 8 <= extra.size) {
                            localOffset = Bytes.u64le(extra, field)
                            field += 8
                        }
                    }
                    cursor += 4 + size
                }
            }
            val dataStart = localDataStart(io, localOffset) ?: return null
            entries.add(
                Entry(
                    name, nameBytes, method, flags, crc, compressedSize, uncompressedSize, localOffset,
                    externalAttributes, internalAttributes, versionMadeBy, versionNeeded, dataStart, entryZip64
                )
            )
            position += 46L + nameLength + extraLength + commentLength
        }
        if (entries.isEmpty()) return null
        val eocdFileOffset = length - tailLength + eocd
        val commentLength = Bytes.u16le(tail, eocd + 20)
        val end = eocdFileOffset + 22 + commentLength
        return Archive(entries, base, end)
    }

    private fun localDataStart(io: BinaryIo, localOffset: Long): Long? {
        val header = io.peekAt(localOffset, 30) ?: return null
        if (Bytes.u32le(header, 0) != 0x04034b50L) return null
        val nameLength = Bytes.u16le(header, 26)
        val extraLength = Bytes.u16le(header, 28)
        return localOffset + 30 + nameLength + extraLength
    }

    private fun isMetadataName(name: String): Boolean {
        val lower = name.lowercase()
        return lower == "docprops/core.xml" || lower == "docprops/app.xml" || lower == "docprops/custom.xml" ||
            lower == "meta.xml" || lower.startsWith("docprops/thumbnail") || lower.endsWith(".opf") ||
            // The thumbnail relationship lives here; without rewriting this member a dropped
            // docProps/thumbnail would leave dangling Override/Relationship entries behind.
            lower == "[content_types].xml" || lower == "_rels/.rels"
    }

    private fun isThumbnailName(name: String): Boolean {
        val lower = name.lowercase()
        return lower.startsWith("docprops/thumbnail") || lower.startsWith("meta-inf/thumbnail")
    }

    /**
     * A member this handler cannot decode (encryption or an exotic method) is reported at
     * high severity so the UI shows it as an unverified survivor instead of losing it.
     */
    private fun unverifiedMemberFinding(name: String, entry: Entry): MetadataFinding =
        if (entry.flags and 0x01 != 0) {
            MetadataFinding(MetadataKind.UNVERIFIED_MEMBER, "[$name] encrypted member cannot be verified")
        } else {
            MetadataFinding(
                MetadataKind.UNVERIFIED_MEMBER,
                "[$name] unsupported compression method ${entry.method} leaves member unverified"
            )
        }

    /**
     * Declared encryption/method can look fine while the payload still fails to decode
     * (corrupt data or local/central header mismatch). Compatibility mode copies such a
     * member through; it must be declared, not silently passed off as verified.
     */
    private fun decodeFailedFinding(name: String): MetadataFinding =
        MetadataFinding(MetadataKind.UNVERIFIED_MEMBER, "[$name] member could not be decoded; copied unverified")

    private fun isUnverifiableMember(entry: Entry): Boolean =
        !entry.name.endsWith("/") &&
            (entry.compressedSize > 0 || entry.uncompressedSize > 0) &&
            (entry.flags and 0x01 != 0 || (entry.method != 0 && entry.method != 8))

    private fun sanitisedContent(name: String, content: ByteArray, removed: MutableList<MetadataFinding>): ByteArray? {
        val lower = name.lowercase()
        val text = String(content, Charsets.UTF_8)
        return when {
            lower == "docprops/core.xml" -> {
                removed.add(MetadataFinding(MetadataKind.DOCUMENT_PROPERTY, "docProps/core.xml"))
                minimalXml(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                        "<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" " +
                        "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" " +
                        "xmlns:dcmitype=\"http://purl.org/dc/dcmitype/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"></cp:coreProperties>"
                )
            }
            lower == "docprops/app.xml" -> {
                removed.add(MetadataFinding(MetadataKind.SOFTWARE, "docProps/app.xml"))
                minimalXml(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                        "<Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\"></Properties>"
                )
            }
            lower == "docprops/custom.xml" -> {
                removed.add(MetadataFinding(MetadataKind.DOCUMENT_PROPERTY, "docProps/custom.xml"))
                minimalXml(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                        "<Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/custom-properties\"></Properties>"
                )
            }
            lower.endsWith("meta.xml") -> {
                removed.add(MetadataFinding(MetadataKind.DOCUMENT_PROPERTY, name))
                minimalXml(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                        "<office:document-meta xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" " +
                        "xmlns:meta=\"urn:oasis:names:tc:opendocument:xmlns:meta:1.0\" office:version=\"1.2\">" +
                        "<office:meta></office:meta></office:document-meta>"
                )
            }
            lower == "[content_types].xml" -> {
                val cleaned = removeThumbnailReferences(text, removed)
                cleaned.toByteArray(Charsets.UTF_8)
            }
            lower == "_rels/.rels" -> {
                val cleaned = removeThumbnailReferences(text, removed)
                cleaned.toByteArray(Charsets.UTF_8)
            }
            lower.endsWith(".opf") -> {
                val cleaned = stripPackageMetadata(text, removed)
                cleaned.toByteArray(Charsets.UTF_8)
            }
            else -> null
        }
    }

    private fun minimalXml(xml: String): ByteArray = xml.toByteArray(Charsets.UTF_8)

    private fun removeThumbnailReferences(text: String, removed: MutableList<MetadataFinding>): String {
        var result = text
        val overridePattern = Regex("<Override[^>]*thumbnail[^>]*/>", RegexOption.IGNORE_CASE)
        val relationshipPattern = Regex("<Relationship[^>]*thumbnail[^>]*/>", RegexOption.IGNORE_CASE)
        if (overridePattern.containsMatchIn(result)) {
            removed.add(MetadataFinding(MetadataKind.THUMBNAIL, "thumbnail override"))
            result = overridePattern.replace(result, "")
        }
        if (relationshipPattern.containsMatchIn(result)) {
            removed.add(MetadataFinding(MetadataKind.THUMBNAIL, "thumbnail relationship"))
            result = relationshipPattern.replace(result, "")
        }
        return result
    }

    private fun stripPackageMetadata(text: String, removed: MutableList<MetadataFinding>): String {
        var result = text
        val pattern = Regex("<(dc:creator|dc:contributor|dc:date|dc:publisher|dc:rights|dc:source|dc:description)\\b[^>]*>.*?</\\1>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
        if (pattern.containsMatchIn(result)) {
            removed.add(MetadataFinding(MetadataKind.AUTHOR, "EPUB package metadata"))
            result = pattern.replace(result, "")
        }
        // dcterms:modified is mandatory in EPUB 3, so removing it would break the package.
        // Pin it to a fixed epoch value instead: the element stays valid, the date is gone.
        val metaPattern = Regex(
            "(<meta\\b[^>]*property=\"dcterms:modified\"[^>]*>)([^<]*)(</meta>)",
            RegexOption.IGNORE_CASE
        )
        if (metaPattern.containsMatchIn(result)) {
            removed.add(MetadataFinding(MetadataKind.TIMESTAMP, "EPUB modified date"))
            result = metaPattern.replace(result) { match -> match.groupValues[1] + "1970-01-01T00:00:00Z" + match.groupValues[3] }
        }
        val metaEmptyPattern = Regex("<meta\\b[^>]*property=\"dcterms:modified\"[^>]*/>", RegexOption.IGNORE_CASE)
        if (metaEmptyPattern.containsMatchIn(result)) {
            removed.add(MetadataFinding(MetadataKind.TIMESTAMP, "EPUB modified date"))
            result = metaEmptyPattern.replace(result, "")
        }
        return result
    }

    private fun inflate(data: ByteArray): ByteArray? {
        val inflater = Inflater(true)
        return try {
            inflater.setInput(data)
            val out = ByteArrayOutputStream(maxOf(64, data.size * 4))
            val buffer = ByteArray(64 * 1024)
            while (!inflater.finished()) {
                val read = inflater.inflate(buffer)
                if (read <= 0) {
                    if (inflater.needsInput() || inflater.needsDictionary()) break
                    continue
                }
                out.write(buffer, 0, read)
                if (out.size() > 64 * 1024 * 1024) break
            }
            out.toByteArray()
        } catch (_: Exception) {
            null
        } finally {
            inflater.end()
        }
    }

    private fun deflate(data: ByteArray): ByteArray {
        val deflater = Deflater(9, true)
        return try {
            deflater.setInput(data)
            deflater.finish()
            val out = ByteArrayOutputStream(maxOf(64, data.size / 2))
            val buffer = ByteArray(64 * 1024)
            while (!deflater.finished()) {
                val written = deflater.deflate(buffer)
                if (written <= 0) break
                out.write(buffer, 0, written)
            }
            out.toByteArray()
        } finally {
            deflater.end()
        }
    }

    private class Payload(val bytes: ByteArray, val method: Int, val crc: Long, val uncompressed: Long)

    private fun loadPayload(io: BinaryIo, entry: Entry, removed: MutableList<MetadataFinding>): Payload? {
        if (entry.compressedSize > MAX_MEMBER_BYTES) return null
        if (entry.flags and 0x01 != 0) return null
        if (entry.method != 0 && entry.method != 8) return null
        val raw = io.peekAt(entry.dataStart, entry.compressedSize.toInt()) ?: return null
        val content = if (entry.method == 8) inflate(raw) ?: return null else raw
        val replacement = sanitisedContent(entry.name, content, removed) ?: return null
        val crc = CRC32()
        crc.update(replacement)
        val packed = deflate(replacement)
        return if (packed.size < replacement.size) {
            Payload(packed, 8, crc.value, replacement.size.toLong())
        } else {
            val stored = CRC32()
            stored.update(replacement)
            Payload(replacement, 0, stored.value, replacement.size.toLong())
        }
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val buffer = Buffers.new()
        val removed = ArrayList<MetadataFinding>()
        // Findings that verification will legitimately still see inside retained members.
        // Declared outside the reader scope so the final outcome can carry them.
        val memberResidual = ArrayList<MetadataFinding>()
        // Members that failed to decode while staging (compatibility mode only).
        val decodeFailedNames = HashSet<String>()
        BinaryIo.open(ctx.source).use { io ->
            val archive = readArchive(io)
                ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a ZIP archive")
            val entries = archive.entries
            val kept = ArrayList<Entry>()
            val payloads = ArrayList<Payload?>()
            val childRetained = ArrayList<List<MetadataFinding>>()
            val stripMembers = ctx.options.stripArchiveMembers &&
                (ctx.detection.format == MediaFormat.ZIP || ctx.detection.format == MediaFormat.TAR)
            val strictMembers = EmbeddedScrubber.strictMembers(ctx.options)
            for (entry in entries) {
                if (isThumbnailName(entry.name) && ctx.options.stripEmbeddedThumbnails) {
                    removed.add(MetadataFinding(MetadataKind.THUMBNAIL, "archive member ${entry.name}"))
                    continue
                }
                if (isMetadataName(entry.name)) {
                    val payload = loadPayload(io, entry, removed)
                    if (payload != null) {
                        payloads.add(payload)
                        kept.add(entry)
                        childRetained.add(emptyList())
                        continue
                    }
                    val readable = readText(io, entry)
                    if (readable == null) {
                        val why = if (entry.flags and 0x01 != 0) {
                            "is encrypted and cannot be rewritten"
                        } else {
                            "uses an unsupported storage method"
                        }
                        return ScrubOutcome(
                            false, PurgeStrategy.NONE, removed,
                            message = "metadata member ${entry.name} $why"
                        )
                    }
                } else if (ctx.options.recursiveMemberScrub && !entry.name.endsWith("/")) {
                    // Every other member is dispatched through its own format handler so
                    // metadata inside embedded files is removed, not only package records.
                    val content = readMemberBytes(io, entry)
                    if (content == null) {
                        if (strictMembers) {
                            if (entry.compressedSize > 0) {
                                throw PurgeRefusedException(
                                    "member ${entry.name} cannot be decoded for verification; " +
                                        "maximum privacy refuses to copy it through unverified"
                                )
                            }
                        } else if (entry.compressedSize > 0 && !isUnverifiableMember(entry)) {
                            // Recorded so the residual loop declares the byte-for-byte copy.
                            decodeFailedNames.add(entry.name)
                        }
                    } else if (content.isEmpty()) {
                        payloads.add(null)
                        kept.add(entry)
                        childRetained.add(emptyList())
                        continue
                    } else {
                        val staged = EmbeddedScrubber.stageBytes(ctx, entry.name, content)
                        if (staged == null) {
                            if (strictMembers) {
                                throw PurgeRefusedException(
                                    "member ${entry.name} could not be staged for verification"
                                )
                            }
                        } else {
                            var memberOutcome: EmbeddedScrubber.MemberOutcome? = null
                            try {
                                memberOutcome = EmbeddedScrubber.scrubMember(ctx, staged, entry.name)
                                val rewrittenFile = memberOutcome.outFile
                                val rewritten = if (rewrittenFile != null) {
                                    try {
                                        rewrittenFile.readBytes()
                                    } catch (_: Exception) {
                                        null
                                    }
                                } else null
                                if (rewritten != null) {
                                    payloads.add(payloadFromBytes(rewritten))
                                    kept.add(entry)
                                    childRetained.add(memberOutcome.retained)
                                    for (finding in memberOutcome.removed) {
                                        removed.add(EmbeddedScrubber.prefix(entry.name, finding))
                                    }
                                    continue
                                }
                                payloads.add(null)
                                kept.add(entry)
                                childRetained.add(memberOutcome.retained)
                                continue
                            } finally {
                                EmbeddedScrubber.wipeStaged(staged)
                                memberOutcome?.outFile?.let { EmbeddedScrubber.wipeStaged(it) }
                            }
                        }
                    }
                }
                payloads.add(null)
                kept.add(entry)
                childRetained.add(emptyList())
            }
            val names = if (stripMembers) flattenedNames(kept) else null
            // Residual findings are recorded against the member's final (possibly renamed)
            // entry name, which is the name inspect() will read back from the rewritten archive.
            for (index in kept.indices) {
                val entry = kept[index]
                val finalName = names?.get(index)?.toString(Charsets.UTF_8) ?: entry.name
                for (finding in childRetained[index]) {
                    memberResidual.add(EmbeddedScrubber.prefix(finalName, finding))
                }
                // Encrypted / exotic-method members survive compatibility mode: declare them
                // at high severity so the report shows an unverified survivor, and so maximum
                // privacy (which refuses residuals before the swap) blocks the replacement.
                if (isUnverifiableMember(entry)) {
                    memberResidual.add(unverifiedMemberFinding(finalName, entry))
                }
                // Members that failed to decode during recursive staging are copied through
                // byte-for-byte in compatibility mode; never let that happen silently.
                if (decodeFailedNames.contains(entry.name)) {
                    memberResidual.add(decodeFailedFinding(finalName))
                }
            }
            if (names != null) {
                removed.add(MetadataFinding(MetadataKind.PATH_LEAK, "archive member paths"))
            }
            val trailing = archive.end in 1L until io.length
            if (removed.isEmpty() && payloads.none { it != null } && !trailing && names == null &&
                memberResidual.isEmpty() && !hasHeaderMetadataHidden(io, entries)
            ) {
                return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable metadata")
            }
            if (trailing) {
                removed.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the ZIP archive"))
            }
            FileOutputStreamCompat(ctx.target).use { fileOut ->
                val out = ProgressOut(fileOut, ctx)
                val offsets = LongArray(kept.size)
                if (archive.base > 0L) {
                    io.copyRange(0L, archive.base, out, buffer)
                }
                for (index in kept.indices) {
                    ctx.checkCancelled()
                    val entry = kept[index]
                    val payload = payloads[index]
                    offsets[index] = out.written
                    val nameBytes = names?.get(index) ?: entry.rawName
                    if (payload == null) {
                        writeLocalHeader(
                            out, nameBytes, entry.method, entry.flags and 0x08.inv(),
                            entry.crc, entry.compressedSize, entry.uncompressedSize
                        )
                        io.copyRange(entry.dataStart, entry.compressedSize, out, buffer)
                    } else {
                        val flags = entry.flags and 0x08.inv() and 0x01.inv()
                        writeLocalHeader(
                            out, nameBytes, payload.method, flags,
                            payload.crc, payload.bytes.size.toLong(), payload.uncompressed
                        )
                        out.write(payload.bytes)
                    }
                }
                val centralStart = out.written
                var centralSize = 0L
                for (index in kept.indices) {
                    val entry = kept[index]
                    val payload = payloads[index]
                    val offset = offsets[index]
                    val method = payload?.method ?: entry.method
                    val crc = payload?.crc ?: entry.crc
                    val compressed = payload?.bytes?.size?.toLong() ?: entry.compressedSize
                    val uncompressed = payload?.uncompressed ?: entry.uncompressedSize
                    val extraFlags = if (payload == null) entry.flags else entry.flags and 0x01.inv()
                    centralSize += writeCentralEntry(
                        out, names?.get(index) ?: entry.rawName, entry, method, crc,
                        compressed, uncompressed, offset, extraFlags, names != null
                    )
                }
                val count = kept.size.toLong()
                val needsZip64 = count > 0xFFFFL || centralStart > ZIP64_LIMIT || centralSize > ZIP64_LIMIT
                if (needsZip64) {
                    val zip64Offset = out.written
                    writeZip64End(out, count, centralStart, centralSize)
                    writeZip64Locator(out, zip64Offset)
                }
                writeEndOfCentralDirectory(
                    out, minOf(centralSize, ZIP64_LIMIT),
                    if (needsZip64) ZIP64_LIMIT else centralStart,
                    if (needsZip64) 0xFFFF else count.toInt()
                )
                out.tail()
                out.flush()
            }
        }
        if (removed.isEmpty()) {
            removed.add(MetadataFinding(MetadataKind.ZIP_STRUCTURE, "archive header timestamps"))
        }
        return ScrubOutcome(
            true, PurgeStrategy.ARCHIVE_REWRITE, removed.distinct(),
            memberResidual.distinct(), true
        )
    }

    /** Decompress a member into memory so it can be staged for its own handler. */
    private fun readMemberBytes(io: BinaryIo, entry: Entry): ByteArray? {
        if (entry.compressedSize <= 0 || entry.compressedSize > MAX_MEMBER_BYTES) return null
        if (entry.method != 0 && entry.method != 8) return null
        if (entry.flags and 0x01 != 0) return null
        val raw = io.peekAt(entry.dataStart, entry.compressedSize.toInt()) ?: return null
        val content = if (entry.method == 8) inflate(raw) ?: return null else raw
        if (content.size > MAX_MEMBER_BYTES) return null
        return content
    }

    private fun payloadFromBytes(replacement: ByteArray): Payload {
        val crc = CRC32()
        crc.update(replacement)
        val packed = deflate(replacement)
        return if (packed.size < replacement.size) {
            Payload(packed, 8, crc.value, replacement.size.toLong())
        } else {
            Payload(replacement, 0, crc.value, replacement.size.toLong())
        }
    }

    private fun hasHeaderMetadataHidden(io: BinaryIo, entries: List<Entry>): Boolean {
        for (entry in entries) {
            val header = io.peekAt(entry.localOffset, 30) ?: continue
            val flags = Bytes.u16le(header, 6)
            val time = Bytes.u16le(header, 10)
            val date = Bytes.u16le(header, 12)
            if (flags and 0x08 != 0) return true
            if (time != 0 || (date != 0 && date != 0x21)) return true
            if (Bytes.u16le(header, 28) > 0) return true
        }
        return false
    }

    /**
     * Directory components in member names leak the tree they were archived from, including the
     * user's home directory. Flattening them keeps the members but drops the path.
     */
    private fun flattenedNames(entries: List<Entry>): List<ByteArray> {
        val taken = HashSet<String>()
        val result = ArrayList<ByteArray>(entries.size)
        for (entry in entries) {
            val base = entry.name.substringAfterLast('/').substringAfterLast('\\')
            val name = if (base.isEmpty()) "file" else base
            var candidate = name
            var index = 1
            while (!taken.add(candidate.lowercase())) {
                val dot = name.lastIndexOf('.')
                candidate = if (dot > 0) {
                    name.substring(0, dot) + "-" + index + name.substring(dot)
                } else {
                    "$name-$index"
                }
                index++
            }
            result.add(candidate.toByteArray(Charsets.UTF_8))
        }
        return result
    }

    private fun writeLocalHeader(
        out: OutputStream,
        nameBytes: ByteArray,
        method: Int,
        flags: Int,
        crc: Long,
        compressed: Long,
        uncompressed: Long
    ) {
        val needsZip64 = compressed >= 0xFFFFFFFFL || uncompressed >= 0xFFFFFFFFL
        val header = ByteArray(30)
        Bytes.putU32le(header, 0, 0x04034b50L)
        Bytes.putU16le(header, 4, if (needsZip64) 45 else 20)
        Bytes.putU16le(header, 6, flags and 0x08.inv())
        Bytes.putU16le(header, 8, method)
        Bytes.putU16le(header, 10, 0)
        Bytes.putU16le(header, 12, 0x21)
        Bytes.putU32le(header, 14, if (needsZip64) 0xFFFFFFFFL else crc)
        Bytes.putU32le(header, 18, if (needsZip64) 0xFFFFFFFFL else compressed)
        Bytes.putU32le(header, 22, if (needsZip64) 0xFFFFFFFFL else uncompressed)
        Bytes.putU16le(header, 26, nameBytes.size)
        Bytes.putU16le(header, 28, if (needsZip64) 20 else 0)
        out.write(header)
        out.write(nameBytes)
        if (needsZip64) {
            val extra = ByteArray(20)
            Bytes.putU16le(extra, 0, 0x0001)
            Bytes.putU16le(extra, 2, 16)
            Bytes.putU64le(extra, 4, uncompressed)
            Bytes.putU64le(extra, 12, compressed)
            out.write(extra)
        }
    }

    private fun writeCentralEntry(
        out: OutputStream,
        nameBytes: ByteArray,
        entry: Entry,
        method: Int,
        crc: Long,
        compressed: Long,
        uncompressed: Long,
        localOffset: Long,
        flags: Int,
        stripAttributes: Boolean
    ): Long {
        val needsZip64 = compressed >= 0xFFFFFFFFL || uncompressed >= 0xFFFFFFFFL || localOffset >= 0xFFFFFFFFL
        val extra = if (needsZip64) {
            val extraSize = 4 + (if (uncompressed >= 0xFFFFFFFFL) 8 else 0) +
                (if (compressed >= 0xFFFFFFFFL) 8 else 0) + (if (localOffset >= 0xFFFFFFFFL) 8 else 0)
            val bytes = ByteArray(extraSize)
            Bytes.putU16le(bytes, 0, 0x0001)
            Bytes.putU16le(bytes, 2, extraSize - 4)
            var cursor = 4
            if (uncompressed >= 0xFFFFFFFFL) {
                Bytes.putU64le(bytes, cursor, uncompressed)
                cursor += 8
            }
            if (compressed >= 0xFFFFFFFFL) {
                Bytes.putU64le(bytes, cursor, compressed)
                cursor += 8
            }
            if (localOffset >= 0xFFFFFFFFL) {
                Bytes.putU64le(bytes, cursor, localOffset)
            }
            bytes
        } else ByteArray(0)
        val header = ByteArray(46)
        Bytes.putU32le(header, 0, 0x02014b50L)
        // The high byte of version made by names the host OS, and the external attributes carry
        // the Unix permission bits and file type; both are dropped on request.
        Bytes.putU16le(header, 4, if (stripAttributes) 0x14 else entry.versionMadeBy and 0x00FF)
        Bytes.putU16le(header, 6, if (needsZip64) 45 else 20)
        Bytes.putU16le(header, 8, flags and 0x08.inv())
        Bytes.putU16le(header, 10, method)
        Bytes.putU16le(header, 12, 0)
        Bytes.putU16le(header, 14, 0x21)
        Bytes.putU32le(header, 16, if (needsZip64) 0xFFFFFFFFL else crc)
        Bytes.putU32le(header, 20, if (needsZip64) 0xFFFFFFFFL else compressed)
        Bytes.putU32le(header, 24, if (needsZip64) 0xFFFFFFFFL else uncompressed)
        Bytes.putU16le(header, 28, nameBytes.size)
        Bytes.putU16le(header, 30, extra.size)
        Bytes.putU16le(header, 32, 0)
        Bytes.putU16le(header, 34, 0)
        Bytes.putU16le(header, 36, if (stripAttributes) 0 else entry.internalAttributes)
        Bytes.putU32le(header, 38, if (stripAttributes) 0L else entry.externalAttributes.toLong() and 0xFFFFFFFFL)
        Bytes.putU32le(header, 42, if (needsZip64) 0xFFFFFFFFL else localOffset)
        out.write(header)
        out.write(nameBytes)
        if (extra.isNotEmpty()) out.write(extra)
        return 46L + nameBytes.size + extra.size
    }

    private fun writeZip64End(out: OutputStream, count: Long, cdOffset: Long, cdSize: Long) {
        val record = ByteArray(56)
        Bytes.putU32le(record, 0, 0x06064b50L)
        Bytes.putU64le(record, 4, 44)
        Bytes.putU16le(record, 12, 45)
        Bytes.putU16le(record, 14, 45)
        Bytes.putU32le(record, 16, 0)
        Bytes.putU32le(record, 20, 0)
        Bytes.putU64le(record, 24, count)
        Bytes.putU64le(record, 32, count)
        Bytes.putU64le(record, 40, cdSize)
        Bytes.putU64le(record, 48, cdOffset)
        out.write(record)
    }

    private fun writeZip64Locator(out: OutputStream, zip64Offset: Long) {
        val locator = ByteArray(20)
        Bytes.putU32le(locator, 0, 0x07064b50L)
        Bytes.putU32le(locator, 4, 0)
        Bytes.putU64le(locator, 8, zip64Offset)
        Bytes.putU32le(locator, 16, 1)
        out.write(locator)
    }

    private fun writeEndOfCentralDirectory(out: OutputStream, size: Long, offset: Long, count16: Int) {
        val record = ByteArray(22)
        Bytes.putU32le(record, 0, 0x06054b50L)
        Bytes.putU16le(record, 4, 0)
        Bytes.putU16le(record, 6, 0)
        Bytes.putU16le(record, 8, count16)
        Bytes.putU16le(record, 10, count16)
        Bytes.putU32le(record, 12, if (size > ZIP64_LIMIT) 0xFFFFFFFFL else size)
        Bytes.putU32le(record, 16, if (offset > ZIP64_LIMIT) 0xFFFFFFFFL else offset)
        Bytes.putU16le(record, 20, 0)
        out.write(record)
    }

    private const val MAX_MEMBER_BYTES = 32L * 1024 * 1024

    private class FileOutputStreamCompat(file: File) : java.io.FileOutputStream(file)

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                val archive = readArchive(io) ?: return listOf(MetadataFinding(MetadataKind.OTHER, "not a ZIP archive"))
                val entries = archive.entries
                if (archive.end in 1L until io.length) {
                    findings.add(MetadataFinding(MetadataKind.OTHER, "data after the end of the ZIP archive"))
                }
                for (entry in entries) {
                    val lower = entry.name.lowercase()
                    if (isMetadataName(entry.name) && !isThumbnailName(entry.name) && readText(io, entry) == null) {
                        findings.add(MetadataFinding(MetadataKind.OTHER, "unreadable metadata member ${entry.name}"))
                    }
                    when {
                        isThumbnailName(entry.name) && options.stripEmbeddedThumbnails ->
                            findings.add(MetadataFinding(MetadataKind.THUMBNAIL, "archive member ${entry.name}"))
                        lower == "docprops/core.xml" -> {
                            val text = readText(io, entry) ?: ""
                            if (hasValues(text, listOf("<dc:title", "<dc:creator", "<dc:subject", "<cp:keywords", "<dc:description", "<cp:lastModifiedBy", "<cp:revision", "<dcterms:created", "<dcterms:modified", "<cp:category"))) {
                                findings.add(MetadataFinding(MetadataKind.DOCUMENT_PROPERTY, "docProps/core.xml"))
                            }
                        }
                        lower == "docprops/app.xml" -> {
                            val text = readText(io, entry) ?: ""
                            if (hasValues(text, listOf("<Company", "<Manager", "<Application", "<AppVersion", "<TotalTime"))) {
                                findings.add(MetadataFinding(MetadataKind.SOFTWARE, "docProps/app.xml"))
                            }
                        }
                        lower == "docprops/custom.xml" -> {
                            val text = readText(io, entry) ?: ""
                            if (text.contains("<property")) {
                                findings.add(MetadataFinding(MetadataKind.DOCUMENT_PROPERTY, "docProps/custom.xml"))
                            }
                        }
                        lower.endsWith("meta.xml") -> {
                            val text = readText(io, entry) ?: ""
                            if (hasValues(text, listOf("<meta:generator", "<dc:creator", "<meta:creation-date", "<dc:date", "<meta:user-defined", "<meta:editing-cycles", "<meta:editing-duration", "<meta:initial-creator", "<meta:keyword"))) {
                                findings.add(MetadataFinding(MetadataKind.DOCUMENT_PROPERTY, entry.name))
                            }
                        }
                        lower.endsWith(".opf") -> {
                            val text = readText(io, entry) ?: ""
                            if (hasValues(text, listOf("<dc:creator", "<dc:contributor", "<dc:date", "<dc:publisher", "<dc:rights", "dcterms:modified", "<dc:source"))) {
                                findings.add(MetadataFinding(MetadataKind.AUTHOR, "EPUB package metadata"))
                            }
                        }
                    }
                    // Members outside the package metadata set are inspected through their own
                    // format handler so a clean verdict covers embedded files as well.
                    val packageSpecial = isMetadataName(entry.name) ||
                        (isThumbnailName(entry.name) && options.stripEmbeddedThumbnails)
                    if (isUnverifiableMember(entry)) {
                        findings.add(unverifiedMemberFinding(entry.name, entry))
                    }
                    if (options.stripArchiveMembers) {
                        // Mirror of flattenedNames(): scrub rewrites names to their base
                        // component (directories become "file"), so report the pre-purge
                        // path here or the purge short-circuits to ALREADY_CLEAN and the
                        // strip never runs.
                        val base = entry.name.substringAfterLast('/').substringAfterLast('\\')
                        val target = if (base.isEmpty()) "file" else base
                        if (target != entry.name) {
                            findings.add(MetadataFinding(MetadataKind.PATH_LEAK, "member directory path"))
                        }
                    }
                    if (options.recursiveMemberScrub && !packageSpecial && !entry.name.endsWith("/")) {
                        val content = readMemberBytes(io, entry)
                        if (content != null && content.isNotEmpty()) {
                            var staged: File? = null
                            try {
                                staged = File.createTempFile(
                                    ".mpurge_memb", EmbeddedScrubber.memberExtension(entry.name), file.parentFile
                                )
                                staged.setReadable(true, true)
                                staged.setWritable(true, true)
                                staged.writeBytes(content)
                                findings.addAll(EmbeddedScrubber.inspectMember(staged, entry.name, options))
                            } catch (_: Exception) {
                            } finally {
                                EmbeddedScrubber.wipeStaged(staged)
                            }
                        } else if (content == null && entry.compressedSize > 0 &&
                            EmbeddedScrubber.strictMembers(options)
                        ) {
                            findings.add(
                                MetadataFinding(
                                    MetadataKind.EMBEDDED_FILE,
                                    "[${entry.name}] no verifiable handler for embedded content"
                                )
                            )
                        } else if (content == null && entry.compressedSize > 0 &&
                            !isUnverifiableMember(entry)
                        ) {
                            // Compatibility mode copies the undecodable member through; the
                            // same declaration is added as a residual by scrub so the report
                            // shows an unverified survivor instead of silent success.
                            findings.add(decodeFailedFinding(entry.name))
                        }
                    }
                    if (entry.localOffset > 0) {
                        val header = io.peekAt(entry.localOffset, 30)
                        if (header != null) {
                            val flags = Bytes.u16le(header, 6)
                            val time = Bytes.u16le(header, 10)
                            val date = Bytes.u16le(header, 12)
                            if (flags and 0x08 != 0) {
                                findings.add(MetadataFinding(MetadataKind.ZIP_STRUCTURE, "data descriptor"))
                            }
                            if (time != 0 || (date != 0 && date != 0x21)) {
                                findings.add(MetadataFinding(MetadataKind.TIMESTAMP, "archive member timestamp"))
                            }
                            if (Bytes.u16le(header, 28) > 0) {
                                findings.add(MetadataFinding(MetadataKind.ZIP_STRUCTURE, "archive member extra field"))
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    private fun hasValues(text: String, markers: List<String>): Boolean {
        for (marker in markers) {
            val at = text.indexOf(marker)
            if (at < 0) continue
            val close = text.indexOf('>', at)
            if (close < 0) continue
            val endTag = "</" + marker.removePrefix("<")
            val end = text.indexOf(endTag)
            if (end > close + 1 && text.substring(close + 1, end).isNotBlank()) return true
        }
        return false
    }

    private fun readText(io: BinaryIo, entry: Entry): String? {
        if (entry.compressedSize <= 0 || entry.compressedSize > MAX_MEMBER_BYTES) return null
        if (entry.flags and 0x01 != 0) return null
        if (entry.method != 0 && entry.method != 8) return null
        val raw = io.peekAt(entry.dataStart, entry.compressedSize.toInt()) ?: return null
        val content = if (entry.method == 8) inflate(raw) ?: return null else raw
        return String(content, Charsets.UTF_8)
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val archive = readArchive(io) ?: return false
                val entries = archive.entries
                if (entries.isEmpty()) return false
                for (entry in entries) {
                    if (entry.dataStart + entry.compressedSize > io.length) return false
                    if (entry.localOffset <= 0) continue
                    val header = io.peekAt(entry.localOffset, 30) ?: return false
                    if (Bytes.u16le(header, 6) and 0x08 != 0) return false
                    val time = Bytes.u16le(header, 10)
                    val date = Bytes.u16le(header, 12)
                    if (time != 0 || (date != 0 && date != 0x21)) return false
                    if (Bytes.u16le(header, 28) > 0) return false
                }
                archive.end <= 0 || archive.end >= io.length
            }
        } catch (_: Exception) {
            false
        }
    }
}

object TarHandler : FormatHandler {

    override val id: String = "tar"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.TAR)

    private const val BLOCK = 512
    private val metadataKeys = setOf(
        "uid", "gid", "uname", "gname", "atime", "ctime", "mtime", "SCHILY.dev", "SCHILY.ino",
        "SCHILY.nlink", "SCHILY.atime", "SCHILY.ctime", "SCHILY.mtime", "LIBARCHIVE.creationtime",
        "LIBARCHIVE.uid", "LIBARCHIVE.gid", "comment", "hdrcharset"
    )

    /** Path records are only dropped when member names are being normalised as well. */
    private fun isStrippedKey(key: String, options: PurgeOptions): Boolean =
        metadataKeys.contains(key) ||
            (options.stripArchiveMembers && (key == "path" || key == "linkpath"))

    /**
     * The name scrub writes for [name] under stripArchiveMembers: directory
     * components are removed and a trailing slash is preserved so directory
     * entries stay directories ("a/b/" -> "b/", "a/b.txt" -> "b.txt").
     * inspect() uses the exact same formula so it reports precisely the names
     * scrub changes — otherwise an archive whose only issue is member paths
     * would inspect as clean and the purge would short-circuit to
     * ALREADY_CLEAN without ever stripping them.
     */
    private fun flattenTarName(name: String): String {
        if (name.isEmpty()) return name
        val trailing = name.endsWith('/')
        val core = name.trimEnd('/')
        val base = core.substringAfterLast('/').substringAfterLast('\\')
        return when {
            base.isEmpty() -> name
            trailing -> "$base/"
            else -> base
        }
    }

    private data class Entry(
        val headerStart: Long,
        val type: Int,
        val name: String,
        val size: Long,
        val dataStart: Long,
        val dataBlocks: Long
    ) {
        val totalBlocks: Long get() = 1L + dataBlocks
    }

    private fun octal(text: String): Long {
        val trimmed = text.trim { it == ' ' || it == '\u0000' }
        if (trimmed.isEmpty()) return 0L
        return try {
            trimmed.toLong(8)
        } catch (_: NumberFormatException) {
            0L
        }
    }

    private fun entrySize(header: ByteArray): Long {
        val raw = header[124].toInt() and 0xFF
        if (raw and 0x80 != 0) {
            var value = (raw and 0x7F).toLong()
            for (i in 125 until 136) value = (value shl 8) or (header[i].toInt() and 0xFF).toLong()
            return value
        }
        return octal(Bytes.asciiAt(header, 124, 12))
    }

    private fun checksumValid(header: ByteArray): Boolean {
        val stored = octal(Bytes.asciiAt(header, 148, 8))
        var unsigned = 0L
        var signed = 0L
        for (i in 0 until BLOCK) {
            val value = if (i in 148..155) 0x20 else (header[i].toInt() and 0xFF)
            unsigned += value
            signed += if (i in 148..155) 0x20 else header[i].toInt()
        }
        return unsigned == stored || signed == stored
    }

    private fun parse(io: BinaryIo): List<Entry>? {
        val entries = ArrayList<Entry>()
        var cursor = 0L
        val length = io.length
        while (cursor + BLOCK <= length) {
            val header = io.peekAt(cursor, BLOCK) ?: return if (entries.isEmpty()) null else entries
            if (header.all { it.toInt() == 0 }) break
            if (!checksumValid(header)) return if (entries.isEmpty()) null else entries
            val size = entrySize(header)
            val dataBlocks = (size + BLOCK - 1) / BLOCK
            entries.add(
                Entry(
                    cursor,
                    if ((header[156].toInt() and 0xFF) == 0) '0'.code else (header[156].toInt() and 0xFF),
                    Bytes.trimAscii(header, 0, 100),
                    size,
                    cursor + BLOCK,
                    dataBlocks
                )
            )
            cursor += (1 + dataBlocks) * BLOCK
        }
        return entries
    }

    private fun paxRecords(data: ByteArray): List<Pair<String, String>> {
        val records = ArrayList<Pair<String, String>>()
        var cursor = 0
        while (cursor < data.size) {
            val space = indexOfSpace(data, cursor)
            if (space < 0) break
            val length = String(data, cursor, space - cursor, Charsets.US_ASCII).toIntOrNull() ?: break
            if (length <= 0 || cursor + length > data.size + 1) break
            val record = String(data, space + 1, maxOf(0, length - (space - cursor) - 2), Charsets.UTF_8)
            val equals = record.indexOf('=')
            if (equals > 0) records.add(Pair(record.substring(0, equals), record.substring(equals + 1)))
            cursor += length
        }
        return records
    }

    private fun indexOfSpace(data: ByteArray, from: Int): Int {
        var i = from
        while (i < data.size) {
            if (data[i].toInt().toChar() == ' ') return i
            i++
        }
        return -1
    }

    private fun writeHeader(out: java.io.OutputStream, header: ByteArray) {
        var sum = 0L
        for (i in 0 until BLOCK) {
            sum += if (i in 148..155) 0x20 else (header[i].toInt() and 0xFF)
        }
        val text = String.format("%06o", sum) + "\u0000 "
        val bytes = text.toByteArray(Charsets.US_ASCII)
        System.arraycopy(bytes, 0, header, 148, minOf(8, bytes.size))
        out.write(header)
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                val entries = parse(io) ?: return emptyList()
                var owners = 0
                var times = 0
                var pax = 0
                for (entry in entries) {
                    val header = io.peekAt(entry.headerStart, BLOCK) ?: continue
                    val uid = octal(Bytes.asciiAt(header, 108, 8))
                    val gid = octal(Bytes.asciiAt(header, 116, 8))
                    if (uid != 0L || gid != 0L) owners++
                    val uname = Bytes.trimAscii(header, 265, 297)
                    val gname = Bytes.trimAscii(header, 297, 329)
                    if (uname.isNotEmpty() || gname.isNotEmpty()) owners++
                    if (octal(Bytes.asciiAt(header, 136, 12)) != 0L) times++
                    if (entry.type == 'x'.code || entry.type == 'X'.code || entry.type == 'G'.code) {
                        val data = io.peekAt(entry.dataStart, entry.size.toInt()) ?: continue
                        val records = paxRecords(data)
                        if (records.any { isStrippedKey(it.first, options) } || entry.type == 'G'.code) pax++
                    }
                    if (entry.type == 'V'.code) findings.add(MetadataFinding(MetadataKind.OTHER, "volume label"))
                    if (options.stripArchiveMembers) {
                        // GNU long name/link records carry the original tree path and are
                        // dropped by scrub under stripArchiveMembers; report them here.
                        if (entry.type == 'L'.code || entry.type == 'K'.code) {
                            findings.add(MetadataFinding(MetadataKind.PATH_LEAK, "GNU long name/link record"))
                        }
                        val link = Bytes.trimAscii(header, 157, 257)
                        if (link.contains('/') || link.contains('\\')) {
                            findings.add(MetadataFinding(MetadataKind.PATH_LEAK, "member link target path"))
                        }
                        // Plain member names are flattened by scrub; report them here so the
                        // purge runs. (Excluded types are dropped or rewritten verbatim by
                        // scrub, so their name fields must not feed this predicate.)
                        if (entry.type != 'L'.code && entry.type != 'K'.code &&
                            entry.type != 'x'.code && entry.type != 'X'.code &&
                            entry.type != 'V'.code && entry.type != 'G'.code
                        ) {
                            val name = Bytes.trimAscii(header, 0, 100)
                            if (flattenTarName(name) != name) {
                                findings.add(MetadataFinding(MetadataKind.PATH_LEAK, "member directory path"))
                            }
                        }
                    }
                    // Regular members are staged and inspected through their own handler so
                    // embedded metadata is reported (and required to be absent) as well.
                    if (options.recursiveMemberScrub && entry.type == '0'.code && entry.size > 0L) {
                        if (entry.size > EmbeddedScrubber.MAX_STAGE_BYTES) {
                            if (EmbeddedScrubber.strictMembers(options)) {
                                findings.add(
                                    MetadataFinding(
                                        MetadataKind.EMBEDDED_FILE,
                                        "[${entry.name}] member exceeds the staging limit"
                                    )
                                )
                            }
                        } else {
                            val staged = stageEntry(io, entry.dataStart, entry.size, entry.name, file.parentFile)
                            if (staged != null) {
                                try {
                                    findings.addAll(EmbeddedScrubber.inspectMember(staged, entry.name, options))
                                } finally {
                                    EmbeddedScrubber.wipeStaged(staged)
                                }
                            } else if (EmbeddedScrubber.strictMembers(options)) {
                                findings.add(
                                    MetadataFinding(
                                        MetadataKind.EMBEDDED_FILE,
                                        "[${entry.name}] member could not be staged for verification"
                                    )
                                )
                            }
                        }
                    }
                }
                if (owners > 0) findings.add(MetadataFinding(MetadataKind.OWNER_IDENTITY, "owner and group fields"))
                if (times > 0) findings.add(MetadataFinding(MetadataKind.TIMESTAMP, "member timestamps"))
                if (pax > 0) findings.add(MetadataFinding(MetadataKind.OTHER, "extended header owner records"))
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val removed = ArrayList<MetadataFinding>()
        val buffer = Buffers.new()
        // Findings verification will still legitimately see inside retained members.
        val memberResidual = ArrayList<MetadataFinding>()
        val strictMembers = EmbeddedScrubber.strictMembers(ctx.options)
        var owners = 0
        var times = 0
        var paxDropped = 0
        try {
            BinaryIo.open(ctx.source).use { io ->
                val entries = parse(io)
                    ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a parsable TAR archive")
                FileOutputStream(ctx.target).use { fileOut ->
                    val out = ProgressOut(fileOut, ctx)
                    var index = 0
                    // Flattened path carried over from a dropped GNU 'L'/'K' record.
                    var pendingLongName: String? = null
                    var pendingLongLink: String? = null
                    while (index < entries.size) {
                        ctx.checkCancelled()
                        val entry = entries[index]
                        if (entry.type == 'V'.code) {
                            removed.add(MetadataFinding(MetadataKind.OTHER, "volume label"))
                            index++
                            continue
                        }
                        if (entry.type == 'G'.code) {
                            removed.add(MetadataFinding(MetadataKind.OTHER, "global extended header"))
                            index++
                            continue
                        }
                        if (entry.type == 'x'.code || entry.type == 'X'.code) {
                            val data = io.peekAt(entry.dataStart, entry.size.toInt()) ?: ByteArray(0)
                            val records = paxRecords(data)
                            val filtered = records.filterNot { isStrippedKey(it.first, ctx.options) }
                            val droppedKeys = records.size - filtered.size
                            if (droppedKeys > 0) {
                                paxDropped++
                                removed.add(MetadataFinding(MetadataKind.OTHER, "extended header owner records"))
                            }
                            if (filtered.isEmpty()) {
                                index++
                                continue
                            }
                            val rebuilt = ByteArrayOutputStream()
                            for ((key, value) in filtered) {
                                val payload = "$key=$value\n"
                                val body = payload.toByteArray(Charsets.UTF_8)
                                var length = body.size + 1
                                while (true) {
                                    val digits = length.toString().length
                                    val total = digits + 1 + body.size
                                    if (total == length) break
                                    length++
                                }
                                val prefix = (length.toString() + " ").toByteArray(Charsets.US_ASCII)
                                rebuilt.write(prefix)
                                rebuilt.write(body)
                            }
                            val rebuiltBytes = rebuilt.toByteArray()
                            val header = io.peekAt(entry.headerStart, BLOCK) ?: continue
                            val patched = header.copyOf(BLOCK)
                            val sizeText = String.format("%011o", rebuiltBytes.size)
                            val sizeBytes = sizeText.toByteArray(Charsets.US_ASCII)
                            for (i in 124 until 136) patched[i] = 0
                            System.arraycopy(sizeBytes, 0, patched, 124, minOf(11, sizeBytes.size))
                            patched[156] = 'x'.code.toByte()
                            writeHeader(out, patched)
                            out.write(rebuiltBytes)
                            val padding = ((BLOCK - rebuiltBytes.size % BLOCK) % BLOCK)
                            if (padding > 0) out.write(ByteArray(padding))
                            index++
                            continue
                        }
                        if (entry.type == 'L'.code || entry.type == 'K'.code) {
                            if (ctx.options.stripArchiveMembers) {
                                // GNU long name ('L') / long link ('K') records store the real
                                // path outside the ustar fields. Under stripArchiveMembers the
                                // record is dropped and its flattened base name is planted into
                                // the NEXT entry's name or link field below.
                                val tail = minOf(entry.size, 8192L)
                                val data = io.peekAt(entry.dataStart + (entry.size - tail), tail.toInt())
                                val raw = data?.let { String(it, Charsets.UTF_8) }?.substringBefore('\u0000') ?: ""
                                val flattened = raw.substringAfterLast('/').substringAfterLast('\\')
                                if (entry.type == 'L'.code) {
                                    if (flattened.isNotEmpty()) pendingLongName = flattened
                                    removed.add(MetadataFinding(MetadataKind.PATH_LEAK, "GNU long name record"))
                                } else {
                                    if (flattened.isNotEmpty()) pendingLongLink = flattened
                                    removed.add(MetadataFinding(MetadataKind.PATH_LEAK, "GNU long link record"))
                                }
                                index++
                                continue
                            }
                            // Compatibility mode: fall through and copy the record untouched.
                        }
                        val header = io.peekAt(entry.headerStart, BLOCK) ?: continue
                        val patched = header.copyOf(BLOCK)
                        var dirty = false
                        if (octal(Bytes.asciiAt(patched, 108, 8)) != 0L || octal(Bytes.asciiAt(patched, 116, 8)) != 0L) {
                            for (i in 108 until 124) patched[i] = 0
                            System.arraycopy("0000000\u0000".toByteArray(Charsets.US_ASCII), 0, patched, 108, 8)
                            System.arraycopy("0000000\u0000".toByteArray(Charsets.US_ASCII), 0, patched, 116, 8)
                            owners++
                            dirty = true
                        }
                        if (Bytes.trimAscii(patched, 265, 297).isNotEmpty() || Bytes.trimAscii(patched, 297, 329).isNotEmpty()) {
                            for (i in 265 until 297) patched[i] = 0
                            for (i in 297 until 329) patched[i] = 0
                            owners++
                            dirty = true
                        }
                        if (ctx.options.stripTimestamps && octal(Bytes.asciiAt(patched, 136, 12)) != 0L) {
                            for (i in 136 until 148) patched[i] = 0
                            System.arraycopy("00000000000\u0000".toByteArray(Charsets.US_ASCII), 0, patched, 136, 12)
                            times++
                            dirty = true
                        }
                        if (ctx.options.stripArchiveMembers) {
                            // A dropped GNU 'L'/'K' record supplied this entry's real path;
                            // plant the flattened base name before the generic name pass.
                            pendingLongName?.let { value ->
                                for (i in 0 until 100) patched[i] = 0
                                val bytes = value.toByteArray(Charsets.UTF_8)
                                System.arraycopy(bytes, 0, patched, 0, minOf(99, bytes.size))
                                pendingLongName = null
                                dirty = true
                            }
                            pendingLongLink?.let { value ->
                                for (i in 157 until 257) patched[i] = 0
                                val bytes = value.toByteArray(Charsets.UTF_8)
                                System.arraycopy(bytes, 0, patched, 157, minOf(99, bytes.size))
                                pendingLongLink = null
                                dirty = true
                            }
                            // Directory components in the member name leak the archived tree.
                            // The ustar prefix field can reconstruct the same path, so clear it
                            // too. Directory entries keep their trailing slash ("a/b/" -> "b/").
                            val current = Bytes.trimAscii(patched, 0, 100)
                            val target = flattenTarName(current)
                            if (target != current) {
                                for (i in 0 until 100) patched[i] = 0
                                val targetBytes = target.toByteArray(Charsets.UTF_8)
                                System.arraycopy(targetBytes, 0, patched, 0, minOf(99, targetBytes.size))
                                dirty = true
                                // Counted like owners/times: without this the archive would
                                // inspect clean-but-path-bearing, reach the write loop, and
                                // still fail with "no removable markers".
                                removed.add(MetadataFinding(MetadataKind.PATH_LEAK, "member directory path"))
                            }
                            if (Bytes.trimAscii(patched, 345, 500).isNotEmpty()) {
                                for (i in 345 until 500) patched[i] = 0
                                dirty = true
                            }
                            // The link target field holds a path too; flatten it to its base name.
                            val link = Bytes.trimAscii(patched, 157, 257)
                            if (link.contains('/') || link.contains('\\')) {
                                val linkBase = link.substringAfterLast('/').substringAfterLast('\\')
                                for (i in 157 until 257) patched[i] = 0
                                if (linkBase.isNotEmpty()) {
                                    val linkBytes = linkBase.toByteArray(Charsets.UTF_8)
                                    System.arraycopy(linkBytes, 0, patched, 157, minOf(99, linkBytes.size))
                                }
                                dirty = true
                                removed.add(MetadataFinding(MetadataKind.PATH_LEAK, "member link target path"))
                            }
                        }
                        // The name verification will read back from the rewritten archive.
                        val rawName = Bytes.trimAscii(header, 0, 100)
                        val finalName = if (ctx.options.stripArchiveMembers) {
                            val base = rawName.substringAfterLast('/').substringAfterLast('\\')
                            if (base.isNotEmpty()) base else rawName
                        } else rawName
                        var rewriteFile: File? = null
                        var contentSize = entry.size
                        if (ctx.options.recursiveMemberScrub && entry.type == '0'.code && entry.size > 0L) {
                            if (entry.size > EmbeddedScrubber.MAX_STAGE_BYTES) {
                                if (strictMembers) {
                                    throw PurgeRefusedException(
                                        "member $finalName exceeds the staging limit; " +
                                            "maximum privacy will not copy it through unverified"
                                    )
                                }
                            } else {
                                val staged = stageEntry(io, entry.dataStart, entry.size, finalName, ctx.target.parentFile)
                                if (staged == null) {
                                    if (strictMembers) {
                                        throw PurgeRefusedException(
                                            "member $finalName could not be staged for verification"
                                        )
                                    }
                                } else {
                                    var outcome: EmbeddedScrubber.MemberOutcome? = null
                                    try {
                                        outcome = EmbeddedScrubber.scrubMember(ctx, staged, finalName)
                                        val produced = outcome.outFile
                                        if (produced != null) {
                                            rewriteFile = produced
                                            contentSize = produced.length()
                                            dirty = true
                                        }
                                        for (finding in outcome.removed) {
                                            removed.add(EmbeddedScrubber.prefix(finalName, finding))
                                        }
                                        for (finding in outcome.retained) {
                                            memberResidual.add(EmbeddedScrubber.prefix(finalName, finding))
                                        }
                                    } finally {
                                        EmbeddedScrubber.wipeStaged(staged)
                                        if (rewriteFile == null) {
                                            outcome?.outFile?.let { EmbeddedScrubber.wipeStaged(it) }
                                        }
                                    }
                                }
                            }
                        }
                        if (contentSize != entry.size) {
                            val sizeText = String.format("%011o", contentSize)
                            val sizeBytes = sizeText.toByteArray(Charsets.US_ASCII)
                            for (i in 124 until 136) patched[i] = 0
                            System.arraycopy(sizeBytes, 0, patched, 124, minOf(11, sizeBytes.size))
                            dirty = true
                        }
                        if (dirty) writeHeader(out, patched) else out.write(header)
                        var written: Long
                        val produced = rewriteFile
                        if (produced != null) {
                            try {
                                BinaryIo.open(produced).use { rio ->
                                    rio.copyRange(0L, rio.length, out, buffer)
                                }
                            } finally {
                                EmbeddedScrubber.wipeStaged(produced)
                            }
                            written = contentSize
                        } else {
                            var remaining = entry.size
                            var cursor = entry.dataStart
                            while (remaining > 0L) {
                                val chunk = minOf(remaining, buffer.size.toLong()).toInt()
                                if (!io.inRange(cursor, chunk.toLong())) break
                                io.copyRange(cursor, chunk.toLong(), out, buffer)
                                cursor += chunk
                                remaining -= chunk
                            }
                            written = entry.size
                        }
                        val padding = (BLOCK - (written % BLOCK)) % BLOCK
                        for (i in 0 until padding) out.write(0)
                        index++
                    }
                    out.write(ByteArray(BLOCK * 2))
                    out.tail()
                    out.flush()
                }
                if (owners > 0) removed.add(MetadataFinding(MetadataKind.OWNER_IDENTITY, "owner and group fields"))
                if (times > 0) removed.add(MetadataFinding(MetadataKind.TIMESTAMP, "member timestamps"))
                if (paxDropped > 0) removed.add(MetadataFinding(MetadataKind.OTHER, "extended header owner records"))
            }
        } catch (refused: PurgeRefusedException) {
            throw refused
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "tar rewrite failed")
        }
        if (removed.isEmpty()) {
            return ScrubOutcome(
                false, PurgeStrategy.NONE, emptyList(),
                residualRequired = memberResidual,
                message = if (memberResidual.isEmpty()) {
                    "no removable markers"
                } else {
                    "embedded members carry findings that could not be rewritten: " +
                        memberResidual.joinToString("; ") { it.toString() }
                }
            )
        }
        return ScrubOutcome(
            true, PurgeStrategy.ARCHIVE_REWRITE, removed.distinct(),
            memberResidual.distinct(), true
        )
    }

    /** Copy one member's bytes to a staging file next to [directory] for its own handler. */
    private fun stageEntry(
        io: BinaryIo,
        dataStart: Long,
        size: Long,
        name: String,
        directory: File?
    ): File? {
        var file: File? = null
        return try {
            file = File.createTempFile(".mpurge_memb", EmbeddedScrubber.memberExtension(name), directory)
            file.setReadable(true, true)
            file.setWritable(true, true)
            val buf = Buffers.new()
            java.io.FileOutputStream(file).use { fos ->
                var remaining = size
                var cursor = dataStart
                while (remaining > 0L) {
                    val chunk = minOf(remaining, buf.size.toLong()).toInt()
                    if (!io.inRange(cursor, chunk.toLong())) {
                        throw IllegalStateException("member data out of range")
                    }
                    io.copyRange(cursor, chunk.toLong(), fos, buf)
                    cursor += chunk
                    remaining -= chunk
                }
                fos.flush()
            }
            file
        } catch (_: Exception) {
            EmbeddedScrubber.wipeStaged(file)
            null
        }
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val entries = parse(io) ?: return false
                if (entries.isEmpty()) return false
                for (entry in entries) {
                    val header = io.peekAt(entry.headerStart, BLOCK) ?: return false
                    if (!checksumValid(header)) return false
                    if (entry.type == 'V'.code || entry.type == 'G'.code) return false
                    if (options.stripArchiveMembers && (entry.type == 'L'.code || entry.type == 'K'.code)) return false
                    if (octal(Bytes.asciiAt(header, 108, 8)) != 0L) return false
                    if (octal(Bytes.asciiAt(header, 116, 8)) != 0L) return false
                    if (Bytes.trimAscii(header, 265, 297).isNotEmpty()) return false
                    if (Bytes.trimAscii(header, 297, 329).isNotEmpty()) return false
                    if (options.stripTimestamps && octal(Bytes.asciiAt(header, 136, 12)) != 0L) return false
                    if (entry.type == 'x'.code) {
                        val data = io.peekAt(entry.dataStart, entry.size.toInt()) ?: return false
                        if (paxRecords(data).any { isStrippedKey(it.first, options) }) return false
                    }
                }
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}

object TorrentHandler : FormatHandler {

    override val id: String = "torrent"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.TORRENT)

    private val bannedKeys = setOf(
        "announce", "announce-list", "nodes", "url-list", "httpseeds", "comment", "comment.utf8",
        "created by", "creation date", "encoding", "publisher", "publisher-url", "source",
        "signature", "creator", "author", "title"
    )

    /**
     * Clients mirror a field into a second entry with an encoding suffix, for example
     * "publisher.utf-8" next to "publisher". Only the bare name is in the banned set, so the
     * suffixed twin would survive and still name the releaser.
     */
    private fun isBanned(key: String): Boolean {
        if (bannedKeys.contains(key)) return true
        val dot = key.indexOf('.')
        if (dot <= 0) return false
        val suffix = key.substring(dot + 1).lowercase()
        if (suffix != "utf-8" && suffix != "utf8") return false
        return bannedKeys.contains(key.substring(0, dot))
    }

    private fun indexOfChar(data: ByteArray, target: Char, from: Int): Int {
        var i = from
        while (i < data.size) {
            if (data[i].toInt().toChar() == target) return i
            i++
        }
        return -1
    }

    private fun parseString(data: ByteArray, cursor: Int): Pair<String, Int>? {
        val colon = indexOfChar(data, ':', cursor)
        if (colon < 0) return null
        val length = String(data, cursor, colon - cursor, Charsets.US_ASCII).toIntOrNull() ?: return null
        if (length < 0 || colon + 1 + length > data.size) return null
        return Pair(String(data, colon + 1, length, Charsets.UTF_8), colon + 1 + length)
    }

    private fun skipValue(data: ByteArray, cursor: Int): Int? {
        if (cursor >= data.size) return null
        return when (val c = data[cursor].toInt().toChar()) {
            'i' -> {
                val end = indexOfChar(data, 'e', cursor)
                if (end < 0) null else end + 1
            }
            'l' -> {
                var pos = cursor + 1
                while (pos < data.size && data[pos].toInt().toChar() != 'e') {
                    pos = skipValue(data, pos) ?: return null
                }
                if (pos >= data.size) null else pos + 1
            }
            'd' -> {
                var pos = cursor + 1
                while (pos < data.size && data[pos].toInt().toChar() != 'e') {
                    val key = parseString(data, pos) ?: return null
                    pos = skipValue(data, key.second) ?: return null
                }
                if (pos >= data.size) null else pos + 1
            }
            else -> if (c.isDigit()) parseString(data, cursor)?.second else null
        }
    }

    private class Field(val key: String, val keyStart: Int, val valueStart: Int, val valueEnd: Int)

    private fun topLevelFields(data: ByteArray): List<Field>? {
        if (data.isEmpty() || data[0].toInt().toChar() != 'd') return null
        val fields = ArrayList<Field>()
        var cursor = 1
        while (cursor < data.size && data[cursor].toInt().toChar() != 'e') {
            val key = parseString(data, cursor) ?: return null
            val valueStart = key.second
            val valueEnd = skipValue(data, valueStart) ?: return null
            fields.add(Field(key.first, cursor, valueStart, valueEnd))
            cursor = valueEnd
        }
        if (cursor >= data.size) return null
        return fields
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                if (io.length > 64L shl 20) return emptyList()
                val data = io.peekAt(0, io.length.toInt()) ?: return emptyList()
                val fields = topLevelFields(data) ?: return listOf(MetadataFinding(MetadataKind.OTHER, "not a parsable metainfo file"))
                var info = false
                for (field in fields) {
                    if (field.key == "info") {
                        info = true
                        continue
                    }
                    if (isBanned(field.key)) {
                        val kind = when (field.key) {
                            "comment", "comment.utf8", "title", "source" -> MetadataKind.COMMENT
                            "created by", "creator" -> MetadataKind.SOFTWARE
                            "creation date" -> MetadataKind.TIMESTAMP
                            "publisher", "publisher-url", "author" -> MetadataKind.AUTHOR
                            else -> MetadataKind.OTHER
                        }
                        findings.add(MetadataFinding(kind, "field ${field.key}"))
                    }
                }
                if (!info) findings.add(MetadataFinding(MetadataKind.OTHER, "missing info dictionary"))
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        val removed = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(ctx.source).use { io ->
                if (io.length > 64L shl 20) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "metainfo file too large")
                }
                val data = io.peekAt(0, io.length.toInt())
                    ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "empty file")
                val fields = topLevelFields(data)
                    ?: return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "not a parsable bencode dictionary")
                var infoField: Field? = null
                val kept = ArrayList<Field>()
                for (field in fields) {
                    if (field.key == "info") {
                        infoField = field
                        kept.add(field)
                        continue
                    }
                    if (isBanned(field.key)) {
                        val kind = when (field.key) {
                            "comment", "comment.utf8", "title", "source" -> MetadataKind.COMMENT
                            "created by", "creator" -> MetadataKind.SOFTWARE
                            "creation date" -> MetadataKind.TIMESTAMP
                            "publisher", "publisher-url", "author" -> MetadataKind.AUTHOR
                            else -> MetadataKind.OTHER
                        }
                        removed.add(MetadataFinding(kind, "field ${field.key}"))
                    } else {
                        kept.add(field)
                    }
                }
                if (infoField == null) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = "no info dictionary")
                }
                if (removed.isEmpty()) {
                    return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable markers")
                }
                val out = ByteArrayOutputStream(data.size)
                out.write('d'.code)
                for (field in kept) {
                    out.write(data, field.keyStart, field.valueEnd - field.keyStart)
                }
                out.write('e'.code)
                FileOutputStream(ctx.target).use { fileOut ->
                    fileOut.write(out.toByteArray())
                    fileOut.flush()
                }
            }
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "metainfo rewrite failed")
        }
        return ScrubOutcome(true, PurgeStrategy.STRUCTURAL_REWRITE, removed.distinct(), emptyList(), true)
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                val data = io.peekAt(0, io.length.toInt()) ?: return false
                val fields = topLevelFields(data) ?: return false
                if (fields.none { it.key == "info" }) return false
                for (field in fields) {
                    if (bannedKeys.contains(field.key)) return false
                }
                data[data.size - 1].toInt().toChar() == 'e'
            }
        } catch (_: Exception) {
            false
        }
    }
}

object UnknownHandler : FormatHandler {

    override val id: String = "unknown"
    override val formats: Set<MediaFormat> = setOf(MediaFormat.UNKNOWN)

    private val exifSignature = "Exif\u0000\u0000".toByteArray(Charsets.US_ASCII)
    private val xmpSignature = "http://ns.adobe.com/xap/1.0/".toByteArray(Charsets.US_ASCII)
    private val xmpPacketSignature = "<?xpacket".toByteArray(Charsets.US_ASCII)
    private val xmpPacketEnd = "<?xpacket end".toByteArray(Charsets.US_ASCII)
    private val id3Signature = "ID3".toByteArray(Charsets.US_ASCII)
    private const val SCAN_WINDOW = 1 shl 20
    private const val MIN_TRAILING_ZEROS = 8192
    private const val MAX_XMP_SPAN = 262144L

    private class Hit(val offset: Long, val kind: MetadataKind, val detail: String, val length: Long)

    private fun scan(io: BinaryIo): List<Hit> {
        val hits = ArrayList<Hit>()
        val length = io.length
        val windows = ArrayList<Long>()
        windows.add(0L)
        if (length > SCAN_WINDOW) windows.add(length - SCAN_WINDOW)
        for (base in windows) {
            val size = minOf(SCAN_WINDOW.toLong(), length - base).toInt()
            if (size <= 0) continue
            val data = io.peekAt(base, size) ?: continue
            var index = 0
            while (index < data.size) {
                val exif = Bytes.indexOf(data, exifSignature, index)
                val xmp = Bytes.indexOf(data, xmpSignature, index).let { value ->
                    if (value >= 0) value else Bytes.indexOf(data, xmpPacketSignature, index)
                }
                val id3 = Bytes.indexOf(data, id3Signature, index)
                val next = listOfNotNull(
                    exif.takeIf { it >= 0 }?.let { Pair(it, "exif") },
                    xmp.takeIf { it >= 0 }?.let { Pair(it, "xmp") },
                    id3.takeIf { it >= 0 }?.let { Pair(it, "id3") }
                ).minByOrNull { it.first } ?: break
                when (next.second) {
                    "exif" -> {
                        hits.add(Hit(base + next.first, MetadataKind.EXIF, "embedded exif block", 0))
                        index = next.first + exifSignature.size + 8
                    }
                    "xmp" -> {
                        val packetStart = next.first
                        val terminator = Bytes.indexOf(data, xmpPacketEnd, packetStart + xmpPacketEnd.size)
                        val span = if (terminator > 0) {
                            (terminator - packetStart).toLong()
                        } else {
                            minOf((data.size - packetStart).toLong(), MAX_XMP_SPAN)
                        }
                        hits.add(Hit(base + packetStart, MetadataKind.XMP, "embedded xmp packet", span))
                        index = packetStart + maxOf(1, span.toInt())
                    }
                    else -> {
                        hits.add(Hit(base + next.first, MetadataKind.AUDIO_TAGS, "embedded id3 block", 0))
                        index = next.first + 3
                    }
                }
            }
        }
        if (length > MIN_TRAILING_ZEROS.toLong() * 2L) {
            var zeros = 0L
            val probe = io.peekAt(length - minOf(length, MIN_TRAILING_ZEROS.toLong() * 4L), minOf(length, MIN_TRAILING_ZEROS.toLong() * 4L).toInt())
            if (probe != null) {
                var i = probe.size - 1
                while (i >= 0 && probe[i].toInt() == 0) {
                    zeros++
                    i--
                }
                if (zeros >= MIN_TRAILING_ZEROS) {
                    hits.add(Hit(length - zeros, MetadataKind.OTHER, "trailing zero padding", zeros))
                }
            }
        }
        return hits
    }

    override fun inspect(file: File, options: PurgeOptions): List<MetadataFinding> {
        val findings = ArrayList<MetadataFinding>()
        try {
            BinaryIo.open(file).use { io ->
                for (hit in scan(io)) {
                    findings.add(MetadataFinding(hit.kind, hit.detail, hit.offset))
                }
            }
        } catch (_: Exception) {
        }
        return findings.distinct()
    }

    override fun scrub(ctx: PurgeContext): ScrubOutcome {
        if (!ctx.options.aggressiveUnknownScrub) {
            return ScrubOutcome(
                false,
                PurgeStrategy.NONE,
                emptyList(),
                message = "container layout is unknown; nothing can be verified"
            )
        }
        val removed = ArrayList<MetadataFinding>()
        val buffer = Buffers.new()
        try {
            BinaryIo.open(ctx.source).use { io ->
                FileOutputStream(ctx.target).use { fileOut ->
                    val out = ProgressOut(fileOut, ctx)
                    io.copyRange(0L, io.length, out, buffer)
                    out.tail()
                    out.flush()
                }
            }
            var newLength = ctx.target.length()
            var neutralised = 0
            BinaryIo.openReadWrite(ctx.target).use { io ->
                val hits = scan(io)
                for (hit in hits) {
                    ctx.checkCancelled()
                    when (hit.kind) {
                        MetadataKind.EXIF -> {
                            if (neutraliseExif(io, hit.offset) > 0) {
                                neutralised++
                                removed.add(MetadataFinding(MetadataKind.EXIF, "embedded exif block"))
                            }
                        }
                        MetadataKind.XMP -> {
                            if (hit.length > 0) {
                                blank(io, hit.offset, hit.length)
                                neutralised++
                                removed.add(MetadataFinding(MetadataKind.XMP, "embedded xmp packet"))
                            }
                        }
                        MetadataKind.AUDIO_TAGS -> {
                            if (neutraliseId3(io, hit.offset) > 0) {
                                neutralised++
                                removed.add(MetadataFinding(MetadataKind.AUDIO_TAGS, "embedded id3 block"))
                            }
                        }
                        else -> {
                            if (hit.length > 0) {
                                newLength = minOf(newLength, hit.offset)
                                neutralised++
                                removed.add(MetadataFinding(MetadataKind.OTHER, "trailing zero padding"))
                            }
                        }
                    }
                }
                if (newLength < io.length) io.setLength(newLength)
                io.fsync()
            }
            if (neutralised == 0) {
                return ScrubOutcome(false, PurgeStrategy.NONE, emptyList(), message = "no removable markers")
            }
            return ScrubOutcome(
                true,
                PurgeStrategy.STRUCTURAL_REWRITE,
                removed.distinct(),
                emptyList(),
                true
            )
        } catch (e: Exception) {
            return ScrubOutcome(false, PurgeStrategy.NONE, removed, message = e.message ?: "generic scrub failed")
        }
    }

    private val subIfdTags = setOf(0x014A, 0x8769, 0x8825, 0xA005)

    private fun neutraliseExif(io: BinaryIo, offset: Long): Long {
        val tiffStart = offset + exifSignature.size
        val head = io.peekAt(tiffStart, 8) ?: return 0L
        val little = head[0] == 0x49.toByte() && head[1] == 0x49.toByte()
        val big = head[0] == 0x4D.toByte() && head[1] == 0x4D.toByte()
        if (!little && !big) return 0L
        val magic = if (little) Bytes.u16le(head, 2) else Bytes.u16be(head, 2)
        if (magic != 42) return 0L
        val firstIfd = if (little) Bytes.u32le(head, 4) else Bytes.u32be(head, 4)
        if (firstIfd <= 0L || firstIfd > SCAN_WINDOW) return 0L
        val visited = HashSet<Long>()
        var end = 0L
        var next = firstIfd
        var guard = 0
        while (next in 1L until SCAN_WINDOW && visited.add(next) && guard++ < 16) {
            val outcome = neutraliseIfd(io, tiffStart, next, little, visited) ?: break
            end = maxOf(end, outcome.first)
            next = outcome.second
        }
        io.writeZeros(offset, 8L)
        return if (end > offset) end - offset else 0L
    }

    /** Zero one IFD, recurse into its sub directories, and return (highest byte touched, next IFD). */
    private fun neutraliseIfd(
        io: BinaryIo,
        tiffStart: Long,
        relativeOffset: Long,
        little: Boolean,
        visited: MutableSet<Long>
    ): Pair<Long, Long>? {
        val ifdPos = tiffStart + relativeOffset
        val countRaw = io.peekAt(ifdPos, 2) ?: return null
        val count = if (little) Bytes.u16le(countRaw, 0) else Bytes.u16be(countRaw, 0)
        if (count <= 0 || count > 4096) return null
        val entriesSize = count * 12
        val entries = io.peekAt(ifdPos + 2L, entriesSize) ?: return null
        var end = ifdPos + 2L + entriesSize + 4L
        io.writeZeros(ifdPos + 2L, entriesSize.toLong())
        for (i in 0 until count) {
            val base = i * 12
            val tag = if (little) Bytes.u16le(entries, base) else Bytes.u16be(entries, base)
            val type = if (little) Bytes.u16le(entries, base + 2) else Bytes.u16be(entries, base + 2)
            val number = if (little) Bytes.u32le(entries, base + 4) else Bytes.u32be(entries, base + 4)
            val valueOffset = if (little) Bytes.u32le(entries, base + 8) else Bytes.u32be(entries, base + 8)
            if (subIfdTags.contains(tag)) {
                // Follow the pointer before the entry that holds it is wiped.
                if (valueOffset in 1L until SCAN_WINDOW && visited.add(valueOffset)) {
                    val child = neutraliseIfd(io, tiffStart, valueOffset, little, visited)
                    if (child != null) end = maxOf(end, child.first)
                }
            }
            val total = typeSize(type) * number
            if (total > 4L && valueOffset > 0L && valueOffset < SCAN_WINDOW) {
                io.writeZeros(tiffStart + valueOffset, total)
                end = maxOf(end, tiffStart + valueOffset + total)
            }
        }
        io.writeZeros(ifdPos, 2L)
        val nextRaw = io.peekAt(ifdPos + 2L + entriesSize, 4)
        val next = if (nextRaw != null) {
            if (little) Bytes.u32le(nextRaw, 0) else Bytes.u32be(nextRaw, 0)
        } else 0L
        return Pair(end, next)
    }

    private fun typeSize(type: Int): Long = when (type) {
        1, 2, 6, 7 -> 1L
        3, 8 -> 2L
        4, 9, 11 -> 4L
        5, 10, 12, 13, 16, 17, 18 -> 8L
        else -> 1L
    }

    private fun neutraliseId3(io: BinaryIo, offset: Long): Long {
        val head = io.peekAt(offset, 10) ?: return 0L
        if (head[0] != 'I'.code.toByte() || head[1] != 'D'.code.toByte() || head[2] != '3'.code.toByte()) return 0L
        val size = ((head[6].toInt() and 0x7F) shl 21) or ((head[7].toInt() and 0x7F) shl 14) or
            ((head[8].toInt() and 0x7F) shl 7) or (head[9].toInt() and 0x7F)
        if (size <= 0) return 0L
        val bodyStart = offset + 10L
        val body = io.peekAt(bodyStart, minOf(size, SCAN_WINDOW).toInt()) ?: return 0L
        var cursor = 0
        var blanked = 0L
        while (cursor + 10 <= body.size) {
            val frameId = Bytes.asciiAt(body, cursor, 4)
            if (frameId.trim { it == '\u0000' }.isEmpty()) break
            var frameSize = ((body[cursor + 4].toInt() and 0xFF) shl 24) or
                ((body[cursor + 5].toInt() and 0xFF) shl 16) or
                ((body[cursor + 6].toInt() and 0xFF) shl 8) or (body[cursor + 7].toInt() and 0xFF)
            if ((body[cursor + 4].toInt() and 0x80) != 0) {
                frameSize = (((body[cursor + 4].toInt() and 0x7F) shl 21) or
                    ((body[cursor + 5].toInt() and 0x7F) shl 14) or
                    ((body[cursor + 6].toInt() and 0x7F) shl 7) or
                    (body[cursor + 7].toInt() and 0x7F))
            }
            if (frameSize <= 0 || cursor + 10 + frameSize > body.size) break
            io.writeZeros(bodyStart + cursor + 10L, frameSize.toLong())
            blanked += frameSize.toLong()
            cursor += 10 + frameSize
        }
        if (blanked > 0) io.writeZeros(offset, 3L)
        return blanked
    }

    private fun blank(io: BinaryIo, offset: Long, length: Long) {
        var remaining = length
        var cursor = offset
        while (remaining > 0L) {
            val chunk = minOf(remaining, 1L shl 16)
            io.writeZeros(cursor, chunk)
            cursor += chunk
            remaining -= chunk
        }
    }

    override fun validate(file: File, options: PurgeOptions): Boolean {
        return try {
            BinaryIo.open(file).use { io ->
                if (io.length <= 0L) return false
                if (options.aggressiveUnknownScrub) {
                    for (hit in scan(io)) {
                        if (hit.kind == MetadataKind.EXIF || hit.kind == MetadataKind.XMP ||
                            hit.kind == MetadataKind.AUDIO_TAGS
                        ) {
                            return false
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
