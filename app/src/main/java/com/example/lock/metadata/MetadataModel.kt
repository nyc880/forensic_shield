package com.example.lock.metadata

import java.io.File

enum class MediaFormat(val displayName: String) {
    JPEG("JPEG image"),
    PNG("PNG image"),
    WEBP("WebP image"),
    GIF("GIF image"),
    BMP("BMP image"),
    HEIF("HEIF/HEIC image"),
    AVIF("AVIF image"),
    TIFF("TIFF image"),
    RAW("Camera raw image"),
    PSD("Photoshop document"),
    MP4("MP4/MOV video"),
    THREEGP("3GP video"),
    MKV("Matroska video"),
    AVI("AVI video"),
    ASF("ASF/WMV/WMA container"),
    FLV("Flash video"),
    MPEG_TS("MPEG transport stream"),
    MPEG_PS("MPEG program stream"),
    MP3("MP3 audio"),
    FLAC("FLAC audio"),
    OGG("Ogg audio"),
    WAV("WAVE audio"),
    AAC("AAC audio"),
    PDF("PDF document"),
    DOCX("Word document"),
    XLSX("Excel workbook"),
    PPTX("PowerPoint presentation"),
    ODF("OpenDocument file"),
    EPUB("EPUB book"),
    ZIP("ZIP archive"),
    SVG("SVG vector image"),
    HTML("HTML document"),
    XML("XML document"),
    RTF("Rich text document"),
    TEXT("Text file"),
    TORRENT("BitTorrent file"),
    TAR("TAR archive"),
    UNKNOWN("Unknown binary")
}

enum class MetadataKind(val label: String, val severity: Int) {
    GPS("GPS location", 3),
    DEVICE_IDENTITY("Device identity", 3),
    OWNER_IDENTITY("Owner identity", 3),
    SERIAL_NUMBER("Serial numbers", 3),
    MAKER_NOTE("Maker note / vendor blob", 3),
    THUMBNAIL("Embedded thumbnail", 2),
    UNIQUE_ID("Unique identifiers", 3),
    TIMESTAMP("Timestamps", 2),
    SOFTWARE("Software signatures", 1),
    AUTHOR("Author/creator", 2),
    COMMENT("Comments", 1),
    XMP("XMP packet", 2),
    IPTC("IPTC/Photoshop fields", 2),
    EXIF("EXIF block", 2),
    ICC_PROFILE("Color profile", 1),
    AUDIO_TAGS("Audio tags", 1),
    VIDEO_TAGS("Video tags", 1),
    TELEMETRY("Telemetry / data track", 3),
    DOCUMENT_PROPERTY("Document properties", 2),
    REVISION_ID("Revision identifiers", 2),
    EMBEDDED_FILE("Embedded file", 2),
    PATH_LEAK("File path / name leak", 2),
    PROVENANCE("Provenance manifest (C2PA)", 3),
    ENCODING_MARKER("Encoding marker", 1),
    ZIP_STRUCTURE("Archive structure metadata", 1),
    /** An encrypted or otherwise undecodable container member that policy could not verify. */
    UNVERIFIED_MEMBER("Unverified encrypted member", 3),
    OTHER("Other metadata", 1)
}

data class MetadataFinding(
    val kind: MetadataKind,
    val detail: String,
    val location: Long = -1L
) {
    override fun toString(): String = "${kind.label} ($detail)"
}

enum class PurgeStrategy {

    STRUCTURAL_REWRITE,

    PIXEL_REBUILD,

    TAG_TABLE_REWRITE,

    ARCHIVE_REWRITE,

    TEXT_SANITISE,

    PASSTHROUGH,

    NONE
}

enum class PurgeStatus {

    SUCCESS,

    ALREADY_CLEAN,

    PARTIAL,

    UNSUPPORTED_FORMAT,

    REFUSED,

    FAILED
}

/**
 * The assurance claim a report is allowed to make. A report is VERIFIED only when the
 * rewritten output passed structural validation and a second inspection pass found no
 * residual findings outside the set the handler explicitly declared as required structure.
 * Anything short of that is never presented to the caller as a clean result.
 */
enum class AssuranceLevel {
    VERIFIED,
    UNVERIFIED,
    REFUSED,
    FAILED
}

/**
 * Phases of the replacement transaction. Every run starts at PREPARED and only advances;
 * crash recovery inspects which artefacts exist to decide whether to restore the backup or
 * wipe it, which is equivalent to knowing the last phase that committed.
 */
enum class ReplacePhase {
    PREPARED,
    OUTPUT_WRITTEN,
    OUTPUT_VERIFIED,
    BACKUP_CREATED,
    SWAP_COMMITTED,
    BACKUP_DESTROYED,
    COMPLETED
}

/**
 * What to do with the EXIF orientation tag.
 *
 * MINIMAL_TAG keeps a bare orientation value so the image still renders correctly after the
 * rest of the tag block is gone. STRIP removes it as well; only use that when the pixels are
 * already upright, otherwise viewers will render the frame rotated. Maximum privacy keeps
 * MINIMAL_TAG because rotating pixels requires a full decode that this module does not
 * perform, and a single small integer is the strictest behaviour that stays renderable.
 */
enum class OrientationPolicy {

    MINIMAL_TAG,

    STRIP
}

enum class UnknownFormatPolicy {
    REFUSE,
    COPY_UNVERIFIED
}

data class PurgeOptions(
    val orientationPolicy: OrientationPolicy = OrientationPolicy.MINIMAL_TAG,
    val stripColorProfiles: Boolean = false,
    val stripEmbeddedThumbnails: Boolean = true,
    val stripTimestamps: Boolean = true,
    val resetFileTimestamps: Boolean = true,
    val randomizeFileName: Boolean = true,
    val randomNameLength: Int = 5,
    val preserveExtension: Boolean = true,
    val secureDeleteOriginals: Boolean = true,
    val wipePasses: Int = 1,
    val stripTelemetryTracks: Boolean = true,
    /** Also normalise per member names, paths, times and OS hints inside ZIP and TAR containers. */
    val stripArchiveMembers: Boolean = false,
    val unknownFormatPolicy: UnknownFormatPolicy = UnknownFormatPolicy.COPY_UNVERIFIED,
    val keepJpegComments: Boolean = false,
    val stripBroadcastTables: Boolean = true,
    val stripCodecUserData: Boolean = true,
    val aggressiveUnknownScrub: Boolean = false,
    val hygieneOnCleanFiles: Boolean = false,
    /**
     * Rewrite non UTF-8 text as UTF-8. When this is off a text file that is not already
     * Unicode is refused instead of being "cleaned" with byte level heuristics that can leave
     * identifying strings behind inside a legacy encoding.
     */
    val normalizeTextToUtf8: Boolean = false,
    /**
     * Dispatch supported members of ZIP and TAR containers through their format handlers so
     * metadata inside embedded files is removed as well, not only the container level records.
     */
    val recursiveMemberScrub: Boolean = true,
    /**
     * Fail the whole operation when a container member has no structure aware handler instead
     * of copying it through. The maximum privacy factory always turns this on.
     */
    val refuseUnsupportedMembers: Boolean = false,
    /**
     * Fail-closed policy switch. When true the engine refuses unknown formats, refuses any
     * output whose verification pass still reports findings, and handlers refuse structures
     * whose extent cannot be proven (unresolved PSD tails, container depth limits, unprovable
     * metadata track ranges, multi packet PSI sections, unparsable Ogg logical streams).
     */
    val maximumPrivacy: Boolean = false,
    val onStage: ((String, File) -> Unit)? = null,
    val onProgress: ((bytesDone: Long, bytesTotal: Long) -> Unit)? = null,
    val isCancelled: (() -> Boolean)? = null
) {
    fun checkCancelled(file: File) {
        if (isCancelled?.invoke() == true) throw PurgeCancelledException(file)
    }

    companion object {
        /**
         * The fail-closed configuration. Unknown formats are refused rather than copied,
         * colour profiles, archive member records and telemetry tracks are removed, text is
         * normalised to UTF-8, hygiene applies to already clean files, and every handler
         * refuses structures it cannot fully account for.
         */
        @JvmStatic
        fun maximumPrivacy(
            wipePasses: Int = 3,
            onStage: ((String, File) -> Unit)? = null,
            onProgress: ((bytesDone: Long, bytesTotal: Long) -> Unit)? = null,
            isCancelled: (() -> Boolean)? = null
        ): PurgeOptions = PurgeOptions(
            orientationPolicy = OrientationPolicy.MINIMAL_TAG,
            stripColorProfiles = true,
            stripEmbeddedThumbnails = true,
            stripTimestamps = true,
            resetFileTimestamps = true,
            randomizeFileName = true,
            secureDeleteOriginals = true,
            wipePasses = wipePasses.coerceIn(1, 7),
            stripTelemetryTracks = true,
            stripArchiveMembers = true,
            unknownFormatPolicy = UnknownFormatPolicy.REFUSE,
            keepJpegComments = false,
            stripBroadcastTables = true,
            stripCodecUserData = true,
            aggressiveUnknownScrub = false,
            hygieneOnCleanFiles = true,
            normalizeTextToUtf8 = true,
            recursiveMemberScrub = true,
            refuseUnsupportedMembers = true,
            maximumPrivacy = true,
            onStage = onStage,
            onProgress = onProgress,
            isCancelled = isCancelled
        )
    }
}

class PurgeCancelledException(file: File) : Exception("Cancelled while processing ${file.name}")

class PurgeRefusedException(val reason: String) : Exception(reason)

data class InspectionResult(
    val file: File,
    val format: MediaFormat,
    val subtype: String,
    val findings: List<MetadataFinding>,
    val scannerAvailable: Boolean,
    val error: String? = null
) {
    /** The scanner ran and reported nothing. This is not proof that the file holds no metadata. */
    val noFindings: Boolean get() = findings.isEmpty() && scannerAvailable

    /** Kept for compatibility; semantically equals [noFindings], not a verified clean claim. */
    val isClean: Boolean get() = noFindings
    val riskScore: Int get() = findings.maxOfOrNull { it.kind.severity } ?: 0
}

data class PurgeReport(
    val sourceFile: File,
    val outputFile: File?,
    val format: MediaFormat,
    val subtype: String,
    val strategy: PurgeStrategy,
    val status: PurgeStatus,
    val bytesBefore: Long,
    val bytesAfter: Long,
    val removed: List<MetadataFinding> = emptyList(),
    val residual: List<MetadataFinding> = emptyList(),
    val residualRequired: List<MetadataFinding> = emptyList(),
    val structureValid: Boolean = false,
    val verifiedClean: Boolean = false,
    val originalWiped: Boolean = false,
    val message: String? = null
) {
    val succeeded: Boolean get() = status == PurgeStatus.SUCCESS || status == PurgeStatus.ALREADY_CLEAN || status == PurgeStatus.PARTIAL

    val isSecure: Boolean get() = succeeded && verifiedClean && structureValid

    /** OUTPUT_VERIFIED: the installed bytes passed validation and the residual scan was empty. */
    val outputVerified: Boolean get() = verifiedClean && structureValid

    /** SOURCE_RETIRED: a replaced output now occupies the original path. */
    val sourceRetired: Boolean get() = succeeded && outputFile != null

    /**
     * The claim this report is allowed to carry. VERIFIED is reserved for runs where the
     * output was validated and re-inspected clean; REFUSED and FAILED never suggest any
     * clean state; PARTIAL and unverified copies stay UNVERIFIED.
     */
    val assurance: AssuranceLevel
        get() = when (status) {
            PurgeStatus.REFUSED -> AssuranceLevel.REFUSED
            PurgeStatus.FAILED -> AssuranceLevel.FAILED
            PurgeStatus.UNSUPPORTED_FORMAT -> AssuranceLevel.UNVERIFIED
            PurgeStatus.PARTIAL -> AssuranceLevel.UNVERIFIED
            PurgeStatus.ALREADY_CLEAN -> if (outputVerified) AssuranceLevel.VERIFIED else AssuranceLevel.UNVERIFIED
            PurgeStatus.SUCCESS -> if (outputVerified) AssuranceLevel.VERIFIED else AssuranceLevel.UNVERIFIED
        }

    /**
     * SECURITY_COMPLETE: OUTPUT_VERIFIED and, when a rewrite took place, the backup holding
     * the pre-purge bytes was destroyed. ALREADY_CLEAN runs never created a backup, so
     * verification alone closes the contract for them.
     */
    val securityComplete: Boolean
        get() = when {
            !outputVerified -> false
            status == PurgeStatus.ALREADY_CLEAN -> true
            else -> sourceRetired && originalWiped
        }

    val bytesSaved: Long get() = (bytesBefore - bytesAfter).coerceAtLeast(0L)
}

data class PurgeBatchReport(
    val reports: List<PurgeReport>
) {
    val total: Int get() = reports.size
    val succeeded: Int get() = reports.count { it.succeeded }
    val failed: Int get() = reports.count { it.status == PurgeStatus.FAILED || it.status == PurgeStatus.REFUSED }
    val unsupported: Int get() = reports.count { it.status == PurgeStatus.UNSUPPORTED_FORMAT }
    val allSecure: Boolean get() = reports.isNotEmpty() && reports.all { it.isSecure }
    val allComplete: Boolean get() = reports.isNotEmpty() && reports.all { it.securityComplete }
    val verifiedCount: Int get() = reports.count { it.assurance == AssuranceLevel.VERIFIED }
}

interface PurgeSink {
    fun stage(text: String)
    fun found(finding: MetadataFinding)
    fun progress(bytesDone: Long)
}

class PurgeContext(
    val source: File,
    val target: File,
    val detection: FormatDetection,
    val options: PurgeOptions,
    val sink: PurgeSink,
    /** Container recursion depth; members of ZIP/TAR archives are scrubbed at depth + 1. */
    val depth: Int = 0
) {
    val sourceSize: Long = source.length()

    fun stage(text: String) {
        sink.stage(text)
        options.onStage?.invoke(text, source)
    }

    fun found(kind: MetadataKind, detail: String, location: Long = -1L) {
        sink.found(MetadataFinding(kind, detail, location))
    }

    fun progress(bytesDone: Long) {
        sink.progress(bytesDone)
        options.onProgress?.invoke(bytesDone, sourceSize)
    }

    fun checkCancelled() = options.checkCancelled(source)

    fun append(sourceIo: BinaryIo, offset: Long, size: Long, out: java.io.OutputStream, buffer: ByteArray) {
        sourceIo.copyRange(offset, size, out, buffer)
    }
}

data class ScrubOutcome(
    val success: Boolean,
    val strategy: PurgeStrategy,
    val removed: List<MetadataFinding>,
    val residualRequired: List<MetadataFinding> = emptyList(),
    val structureValid: Boolean = true,
    val message: String? = null
)

interface FormatHandler {
    val id: String
    val formats: Set<MediaFormat>

    val implemented: Boolean get() = true
    fun scrub(ctx: PurgeContext): ScrubOutcome

    fun inspect(file: File, options: PurgeOptions): List<MetadataFinding>

    fun validate(file: File, options: PurgeOptions): Boolean
}
