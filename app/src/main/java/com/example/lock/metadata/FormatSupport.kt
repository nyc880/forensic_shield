package com.example.lock.metadata


import java.io.File
import java.io.OutputStream

object FormatRegistry {

    private val handlers: List<FormatHandler> = listOf(
        JpegHandler,
        PngHandler,
        WebpHandler,
        GifHandler,
        BmpHandler,
        IsoBmffHandler,
        MatroskaHandler,
        Mp3Handler,
        FlacHandler,
        OggHandler,
        RiffHandler,
        TiffHandler,
        PdfHandler,
        ZipContainerHandler,
        PsdHandler,
        TextHandler,
        AsfHandler,
        FlvHandler,
        MpegTsHandler,
        MpegPsHandler,
        AacHandler,
        TarHandler,
        TorrentHandler,
        UnknownHandler
    )

    private val byFormat: Map<MediaFormat, FormatHandler> = buildMap {
        for (handler in handlers) {
            for (format in handler.formats) {
                if (!containsKey(format)) put(format, handler)
            }
        }
    }

    /**
     * Resolve the handler for a detected format.
     *
     * RAW is the one ambiguous entry in the table: camera raw files are either TIFF based
     * (NEF, ARW, CR2, PEF, DNG, ...) or ISO-BMFF based (CR3), and the two need completely
     * different parsers. The registry alone cannot decide, so the first bytes of the file do.
     */
    fun handlerFor(format: MediaFormat, file: File? = null): FormatHandler? {
        if (format == MediaFormat.RAW && file != null) {
            rawHandlerFor(file)?.let { return it }
        }
        return byFormat[format]
    }

    private fun rawHandlerFor(file: File): FormatHandler? {
        val head = try {
            java.io.RandomAccessFile(file, "r").use { raf ->
                val buffer = ByteArray(minOf(16L, raf.length()).toInt())
                if (buffer.isEmpty()) return null
                raf.readFully(buffer)
                buffer
            }
        } catch (_: Exception) {
            return null
        }
        if (head.size < 12) return null
        val two = head[0].toInt() and 0xFF to (head[1].toInt() and 0xFF)
        val magic = if (two.first == 0x49) Bytes.u16le(head, 2) else Bytes.u16be(head, 2)
        return when {
            two.first == 0x49 && two.second == 0x49 && magic == 42 -> TiffHandler
            two.first == 0x4D && two.second == 0x4D && magic == 42 -> TiffHandler
            // BigTIFF
            two.first == 0x49 && two.second == 0x49 && magic == 43 -> TiffHandler
            two.first == 0x4D && two.second == 0x4D && magic == 43 -> TiffHandler
            // ISO-BMFF raw (CR3 and friends): "<size>ftyp"
            head.size >= 12 && String(head, 4, 4, Charsets.US_ASCII) == "ftyp" -> IsoBmffHandler
            else -> null
        }
    }

    fun supportedFormats(): Set<MediaFormat> = byFormat.keys.toSet()

    fun describeSupport(): String = handlers.joinToString("\n") { handler ->
        "${handler.id}: " + handler.formats.joinToString(", ") { it.displayName }
    }
}

internal class ProgressOut(
    private val out: OutputStream,
    private val ctx: PurgeContext,
    private val reportEvery: Long = 1L shl 20
) : OutputStream() {
    var written: Long = 0L
        private set
    private var lastReport = 0L

    override fun write(b: Int) {
        out.write(b)
        written++
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        out.write(b, off, len)
        written += len
        if (written - lastReport >= reportEvery) {
            lastReport = written
            ctx.progress(written)
            ctx.checkCancelled()
        }
    }

    override fun flush() = out.flush()
    override fun close() = out.close()

    fun tail() {
        ctx.progress(written)
    }
}

internal class CountingOut(private val out: OutputStream) : OutputStream() {
    var written: Long = 0L
        private set

    override fun write(b: Int) {
        out.write(b)
        written++
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        out.write(b, off, len)
        written += len
    }

    override fun flush() = out.flush()
    override fun close() = out.close()
}

internal object Buffers {
    fun new(): ByteArray = ByteArray(64 * 1024)
}

internal fun ByteArray.startsWithAscii(offset: Int, text: String): Boolean {
    if (offset + text.length > size) return false
    for (i in text.indices) {
        if (this[offset + i].toInt().toChar() != text[i]) return false
    }
    return true
}

internal fun ByteArray.asciiRange(offset: Int, length: Int): String {
    if (offset < 0 || offset + length > size) return ""
    return String(this, offset, length, Charsets.US_ASCII)
}

object TagTable {

    const val TAG_IMAGE_WIDTH = 0x0100
    const val TAG_IMAGE_LENGTH = 0x0101
    const val TAG_IMAGE_DESCRIPTION = 0x010E
    const val TAG_MAKE = 0x010F
    const val TAG_MODEL = 0x0110
    const val TAG_ORIENTATION = 0x0112
    const val TAG_SOFTWARE = 0x0131
    const val TAG_DATE_TIME = 0x0132
    const val TAG_ARTIST = 0x013B
    const val TAG_HOST_COMPUTER = 0x013C
    const val TAG_SUB_IFDS = 0x014A
    const val TAG_STRIP_OFFSETS = 0x0111
    const val TAG_ROWS_PER_STRIP = 0x0116
    const val TAG_STRIP_BYTE_COUNTS = 0x0117
    const val TAG_TILE_OFFSETS = 0x0144
    const val TAG_TILE_BYTE_COUNTS = 0x0145
    const val TAG_JPEG_INTERCHANGE_FORMAT = 0x0201
    const val TAG_JPEG_INTERCHANGE_FORMAT_LENGTH = 0x0202
    const val TAG_XMP = 0x02BC
    const val TAG_IPTC = 0x83BB
    const val TAG_PHOTOSHOP_IRB = 0x8649
    const val TAG_ICC_PROFILE = 0x8773
    const val TAG_EXIF_IFD = 0x8769
    const val TAG_GPS_IFD = 0x8825
    const val TAG_COPYRIGHT = 0x8298
    const val TAG_DATE_TIME_ORIGINAL = 0x9003
    const val TAG_DATE_TIME_DIGITIZED = 0x9004
    const val TAG_OFFSET_TIME = 0x9010
    const val TAG_OFFSET_TIME_ORIGINAL = 0x9011
    const val TAG_OFFSET_TIME_DIGITIZED = 0x9012
    const val TAG_MAKER_NOTE = 0x927C
    const val TAG_USER_COMMENT = 0x9286
    const val TAG_SUBSEC_TIME = 0x9290
    const val TAG_SUBSEC_TIME_ORIGINAL = 0x9291
    const val TAG_SUBSEC_TIME_DIGITIZED = 0x9292
    const val TAG_IMAGE_SOURCE_DATA = 0x935C
    const val TAG_XP_TITLE = 0x9C9B
    const val TAG_XP_COMMENT = 0x9C9C
    const val TAG_XP_AUTHOR = 0x9C9D
    const val TAG_XP_KEYWORDS = 0x9C9E
    const val TAG_XP_SUBJECT = 0x9C9F
    const val TAG_INTEROP_IFD = 0xA005
    const val TAG_IMAGE_UNIQUE_ID = 0xA420
    const val TAG_OWNER_NAME = 0xA430
    const val TAG_BODY_SERIAL = 0xA431
    const val TAG_LENS_SPECIFICATION = 0xA432
    const val TAG_LENS_MAKE = 0xA433
    const val TAG_LENS_MODEL = 0xA434
    const val TAG_LENS_SERIAL = 0xA435
    const val TAG_PRINT_IMAGE_MATCHING = 0xC4A5
    const val TAG_WANG_ANNOTATION = 0x80A4
    const val TAG_GDAL_METADATA = 0xA480
    const val TAG_GDAL_NODATA = 0xA481
    const val TAG_IPTC_NAA = 0x83BB
    const val TAG_DNG_PRIVATE_DATA = 0xC634
    const val TAG_ORIGINAL_RAW_FILENAME = 0xC68B
    const val TAG_ORIGINAL_RAW_DATA = 0xC68C
    const val TAG_DNG_BACKWARD_VERSION = 0xC613
    const val TAG_KODAK_IFD = 0x8290

    /** C2PA manifest store carried as a TIFF IFD entry rather than in a sidecar. */
    const val TAG_C2PA_JUMBF = 0xCD41

    private val banned: Map<Int, MetadataKind> = mapOf(
        TAG_IMAGE_DESCRIPTION to MetadataKind.COMMENT,
        TAG_MAKE to MetadataKind.DEVICE_IDENTITY,
        TAG_MODEL to MetadataKind.DEVICE_IDENTITY,
        TAG_SOFTWARE to MetadataKind.SOFTWARE,
        TAG_DATE_TIME to MetadataKind.TIMESTAMP,
        TAG_ARTIST to MetadataKind.AUTHOR,
        TAG_HOST_COMPUTER to MetadataKind.DEVICE_IDENTITY,
        TAG_COPYRIGHT to MetadataKind.AUTHOR,
        TAG_DATE_TIME_ORIGINAL to MetadataKind.TIMESTAMP,
        TAG_DATE_TIME_DIGITIZED to MetadataKind.TIMESTAMP,
        TAG_OFFSET_TIME to MetadataKind.TIMESTAMP,
        TAG_OFFSET_TIME_ORIGINAL to MetadataKind.TIMESTAMP,
        TAG_OFFSET_TIME_DIGITIZED to MetadataKind.TIMESTAMP,
        TAG_MAKER_NOTE to MetadataKind.MAKER_NOTE,
        TAG_USER_COMMENT to MetadataKind.COMMENT,
        TAG_SUBSEC_TIME to MetadataKind.TIMESTAMP,
        TAG_SUBSEC_TIME_ORIGINAL to MetadataKind.TIMESTAMP,
        TAG_SUBSEC_TIME_DIGITIZED to MetadataKind.TIMESTAMP,
        TAG_IMAGE_SOURCE_DATA to MetadataKind.EMBEDDED_FILE,
        TAG_XP_TITLE to MetadataKind.AUTHOR,
        TAG_XP_COMMENT to MetadataKind.COMMENT,
        TAG_XP_AUTHOR to MetadataKind.AUTHOR,
        TAG_XP_KEYWORDS to MetadataKind.COMMENT,
        TAG_XP_SUBJECT to MetadataKind.COMMENT,
        TAG_IMAGE_UNIQUE_ID to MetadataKind.UNIQUE_ID,
        TAG_OWNER_NAME to MetadataKind.OWNER_IDENTITY,
        TAG_BODY_SERIAL to MetadataKind.SERIAL_NUMBER,
        TAG_LENS_SPECIFICATION to MetadataKind.DEVICE_IDENTITY,
        TAG_LENS_MAKE to MetadataKind.DEVICE_IDENTITY,
        TAG_LENS_MODEL to MetadataKind.DEVICE_IDENTITY,
        TAG_LENS_SERIAL to MetadataKind.SERIAL_NUMBER,
        TAG_XMP to MetadataKind.XMP,
        TAG_IPTC to MetadataKind.IPTC,
        TAG_IPTC_NAA to MetadataKind.IPTC,
        TAG_PHOTOSHOP_IRB to MetadataKind.IPTC,
        TAG_PRINT_IMAGE_MATCHING to MetadataKind.EMBEDDED_FILE,
        TAG_WANG_ANNOTATION to MetadataKind.EMBEDDED_FILE,
        TAG_GDAL_METADATA to MetadataKind.OTHER,
        TAG_GDAL_NODATA to MetadataKind.OTHER,
        TAG_DNG_PRIVATE_DATA to MetadataKind.MAKER_NOTE,
        TAG_ORIGINAL_RAW_FILENAME to MetadataKind.PATH_LEAK,
        TAG_ORIGINAL_RAW_DATA to MetadataKind.EMBEDDED_FILE,
        TAG_KODAK_IFD to MetadataKind.MAKER_NOTE,
        TAG_C2PA_JUMBF to MetadataKind.PROVENANCE
    )

    val structuralPointerTags: Set<Int> = setOf(
        TAG_STRIP_OFFSETS, TAG_TILE_OFFSETS, TAG_JPEG_INTERCHANGE_FORMAT,
        TAG_EXIF_IFD, TAG_GPS_IFD, TAG_INTEROP_IFD, TAG_SUB_IFDS,
        TAG_STRIP_BYTE_COUNTS, TAG_TILE_BYTE_COUNTS, TAG_JPEG_INTERCHANGE_FORMAT_LENGTH
    )

    /**
     * Tags that describe geometry, sampling and colour decoding: everything a decoder needs to
     * turn the stored samples into pixels. Maximum privacy keeps exactly this set (plus the
     * orientation policy value) and treats every other tag as removable, because an unlisted
     * private tag cannot be assumed harmless.
     */
    private val renderAllowlist: Set<Int> = setOf(
        TAG_IMAGE_WIDTH, TAG_IMAGE_LENGTH,
        0x0102, // BitsPerSample
        0x0103, // Compression
        0x0106, // PhotometricInterpretation
        TAG_STRIP_OFFSETS, TAG_ROWS_PER_STRIP, TAG_STRIP_BYTE_COUNTS,
        TAG_TILE_OFFSETS, TAG_TILE_BYTE_COUNTS,
        0x0115, // SamplesPerPixel
        0x011A, // XResolution
        0x011B, // YResolution
        0x011C, // PlanarConfiguration
        0x0128, // ResolutionUnit
        0x0129, // FillOrder
        0x013E, // WhitePoint
        0x013F, // PrimaryChromaticities
        0x0140, // YCbCrCoefficients
        0x0141, // YCbCrSubSampling
        0x0142, // YCbCrPositioning
        0x0143, // ReferenceBlackWhite
        0x0152, // ExtraSamples
        0x0153, // SampleFormat
        0x0154, // SMinSampleValue
        0x0155, // SMaxSampleValue
        0x828D, // CFARepeatPatternDim
        0x828E, // CFAPattern
        TAG_ORIENTATION, // handled by OrientationPolicy
        TAG_SUB_IFDS, // structural navigation
        TAG_JPEG_INTERCHANGE_FORMAT, TAG_JPEG_INTERCHANGE_FORMAT_LENGTH, // JPEG interchange payload when not a thumbnail
        // DNG / linear raw decoding set
        0xC612, // DNGVersion
        0xC613, // DNGBackwardVersion
        0xC614, // UniqueCameraModel
        0xC615, // LocalizedCameraModel
        0xC616, // CFAPlaneColor
        0xC617, // CFALayout
        0xC618, // LinearizationTable
        0xC619, // BlackLevelRepeatDim
        0xC61A, // BlackLevel
        0xC61B, // BlackLevelDeltaH
        0xC61C, // BlackLevelDeltaV
        0xC61D, // WhiteLevel
        0xC61E, // DefaultScale
        0xC61F, // DefaultCropOrigin
        0xC620, // DefaultCropSize
        0xC621, // ColorMatrix1
        0xC622, // ColorMatrix2
        0xC623, // CameraCalibration1
        0xC624, // CameraCalibration2
        0xC627, // ReductionMatrix1
        0xC628, // ReductionMatrix2
        0xC629, // AnalogBalance
        0xC62A, // AsShotNeutral
        0xC62B, // BaselineExposure
        0xC62C, // BaselineNoise
        0xC62D, // BaselineSharpness
        0xC62E, // LinearResponseLimit
        0xC630, // ShadowScale
        0xC65A, // CalibrationIlluminant1
        0xC65B, // CalibrationIlluminant2
        0xC68D, // ActiveArea
        0xC68E, // MaskedAreas
        0xC6F4, // ProfileName
        0xC6F8  // ProfileEmbedPolicy
    )

    /** True when [tag] is on the rendering allowlist used by the maximum privacy TIFF policy. */
    fun isRenderEssential(tag: Int): Boolean = tag in renderAllowlist

    fun bannedKind(tag: Int): MetadataKind? = banned[tag]

    fun isBanned(tag: Int, gpsIfd: Boolean): Boolean = gpsIfd || banned.containsKey(tag)

    fun name(tag: Int): String = when (tag) {
        TAG_IMAGE_DESCRIPTION -> "ImageDescription"
        TAG_MAKE -> "Make"
        TAG_MODEL -> "Model"
        TAG_ORIENTATION -> "Orientation"
        TAG_SOFTWARE -> "Software"
        TAG_DATE_TIME -> "DateTime"
        TAG_ARTIST -> "Artist"
        TAG_HOST_COMPUTER -> "HostComputer"
        TAG_COPYRIGHT -> "Copyright"
        TAG_DATE_TIME_ORIGINAL -> "DateTimeOriginal"
        TAG_DATE_TIME_DIGITIZED -> "DateTimeDigitized"
        TAG_MAKER_NOTE -> "MakerNote"
        TAG_USER_COMMENT -> "UserComment"
        TAG_SUBSEC_TIME -> "SubSecTime"
        TAG_IMAGE_UNIQUE_ID -> "ImageUniqueID"
        TAG_OWNER_NAME -> "CameraOwnerName"
        TAG_BODY_SERIAL -> "BodySerialNumber"
        TAG_LENS_MAKE -> "LensMake"
        TAG_LENS_MODEL -> "LensModel"
        TAG_LENS_SERIAL -> "LensSerialNumber"
        TAG_XMP -> "XMP"
        TAG_IPTC -> "IPTC"
        TAG_PHOTOSHOP_IRB -> "PhotoshopImageResources"
        TAG_PRINT_IMAGE_MATCHING -> "PrintImageMatching"
        TAG_IMAGE_SOURCE_DATA -> "ImageSourceData"
        TAG_ICC_PROFILE -> "ICCProfile"
        TAG_EXIF_IFD -> "ExifIFD"
        TAG_GPS_IFD -> "GPSIFD"
        TAG_C2PA_JUMBF -> "C2PAManifest"
        else -> String.format("0x%04X", tag)
    }
}

data class ExifEntry(
    val ifd: String,
    val tag: Int,
    val type: Int,
    val count: Long,
    val valueBytes: ByteArray? = null
) {
    val kind: MetadataKind? get() = TagTable.bannedKind(tag)
    fun describe(): String = "${TagTable.name(tag)} @$ifd"
    override fun equals(other: Any?): Boolean = other is ExifEntry && other.ifd == ifd && other.tag == tag
    override fun hashCode(): Int = ifd.hashCode() * 31 + tag
}

data class ExifScan(
    val valid: Boolean,
    val entries: List<ExifEntry>,
    val orientation: Int?,
    val littleEndian: Boolean
) {
    val bannedEntries: List<ExifEntry> get() = entries.filter { it.kind != null }
    val hasGps: Boolean get() = entries.any { it.ifd.startsWith("GPS") }
    val hasMakerNote: Boolean get() = entries.any { it.tag == TagTable.TAG_MAKER_NOTE }
}

object ExifScanner {

    private const val MAX_IFD = 24
    private const val MAX_ENTRIES_PER_IFD = 4096

    fun scan(buffer: ByteArray, base: Int, limit: Int = buffer.size - base): ExifScan {
        if (base < 0 || base + 8 > buffer.size || limit < 8) return ExifScan(false, emptyList(), null, false)
        val end = minOf(buffer.size, base + limit)
        val byteOrder = Bytes.u16be(buffer, base)
        val little = when (byteOrder) {
            0x4949 -> true
            0x4D4D -> false
            else -> return ExifScan(false, emptyList(), null, false)
        }
        val magic = if (little) Bytes.u16le(buffer, base + 2) else Bytes.u16be(buffer, base + 2)
        val bigTiff = magic == 43
        if (magic != 42 && magic != 43) return ExifScan(false, emptyList(), null, little)

        val entries = ArrayList<ExifEntry>()
        val visited = HashSet<Long>()
        var orientation: Int? = null

        val firstIfd = if (bigTiff) {
            if (base + 16 > end) return ExifScan(false, emptyList(), null, little)
            if (little) Bytes.u64le(buffer, base + 8) else readU64be(buffer, base + 8)
        } else {
            if (little) Bytes.u32le(buffer, base + 4).toLong() else Bytes.u32be(buffer, base + 4)
        }

        walkIfd(buffer, base, end, firstIfd, "IFD0", entries, visited, little, bigTiff)?.let { orientation = it }
        return ExifScan(true, entries, orientation, little)
    }

    private fun walkIfd(
        buffer: ByteArray,
        base: Int,
        end: Int,
        relativeOffset: Long,
        label: String,
        entries: MutableList<ExifEntry>,
        visited: MutableSet<Long>,
        little: Boolean,
        bigTiff: Boolean
    ): Int? {
        if (visited.size >= MAX_IFD || !visited.add(relativeOffset)) return null
        if (relativeOffset < 0 || relativeOffset > Int.MAX_VALUE) return null
        val ifdPos = base + relativeOffset.toInt()
        if (ifdPos < 0 || ifdPos + (if (bigTiff) 8 else 2) > end) return null
        var orientation: Int? = null
        try {
            val count = if (bigTiff) {
                if (little) Bytes.u64le(buffer, ifdPos) else readU64be(buffer, ifdPos)
            } else {
                if (little) Bytes.u16le(buffer, ifdPos).toLong() else Bytes.u16be(buffer, ifdPos).toLong()
            }
            val entrySize = if (bigTiff) 20 else 12
            val valueFieldSize = if (bigTiff) 8 else 4
            val entryCount = minOf(count, MAX_ENTRIES_PER_IFD.toLong()).toInt()
            val entriesStart = ifdPos + (if (bigTiff) 8 else 2)

            for (i in 0 until entryCount) {
                val entryPos = entriesStart + i * entrySize
                if (entryPos + entrySize > end) break
                val tag = if (little) Bytes.u16le(buffer, entryPos) else Bytes.u16be(buffer, entryPos)
                val type = if (little) Bytes.u16le(buffer, entryPos + 2) else Bytes.u16be(buffer, entryPos + 2)
                val cnt = if (bigTiff) {
                    if (little) Bytes.u64le(buffer, entryPos + 4) else readU64be(buffer, entryPos + 4)
                } else {
                    if (little) Bytes.u32le(buffer, entryPos + 4).toLong() else Bytes.u32be(buffer, entryPos + 4)
                }
                val valueField = entryPos + 4 + (if (bigTiff) 8 else 4)
                val byteSize = typeSize(type) * cnt
                val inline = byteSize in 1..valueFieldSize.toLong()
                val dataOffset = if (inline) {
                    valueField
                } else {
                    val relative = if (bigTiff) {
                        if (little) Bytes.u64le(buffer, valueField) else readU64be(buffer, valueField)
                    } else {
                        if (little) Bytes.u32le(buffer, valueField).toLong() else Bytes.u32be(buffer, valueField)
                    }
                    if (relative < 0 || relative > Int.MAX_VALUE) -1 else base + relative.toInt()
                }

                val valueBytes = if (inline) {
                    buffer.copyOfRange(valueField, minOf(valueField + byteSize.toInt(), end))
                } else if (dataOffset >= 0 && byteSize >= 0 && dataOffset + byteSize <= end && byteSize <= 4L * 1024 * 1024) {
                    buffer.copyOfRange(dataOffset, dataOffset + byteSize.toInt())
                } else {
                    null
                }

                entries.add(ExifEntry(label, tag, type, cnt, valueBytes))

                if (tag == TagTable.TAG_ORIENTATION && label == "IFD0" && cnt >= 1L) {
                    orientation = if (inline) {
                        if (little) Bytes.u16le(buffer, valueField) else Bytes.u16be(buffer, valueField)
                    } else if (valueBytes != null && valueBytes.size >= 2) {
                        if (little) Bytes.u16le(valueBytes, 0) else Bytes.u16be(valueBytes, 0)
                    } else null
                }
                val pointer = when (tag) {
                    TagTable.TAG_EXIF_IFD -> "ExifIFD"
                    TagTable.TAG_GPS_IFD -> "GPSIFD"
                    TagTable.TAG_INTEROP_IFD -> "InteropIFD"
                    else -> null
                }
                if (pointer != null && valueBytes != null && valueBytes.size >= 4) {
                    val pointerOffset = if (little) Bytes.u32le(valueBytes, 0).toLong() else Bytes.u32be(valueBytes, 0)
                    walkIfd(buffer, base, end, pointerOffset, pointer, entries, visited, little, bigTiff)
                }
            }

            val nextPointerPos = entriesStart + entryCount * entrySize
            if (nextPointerPos + valueFieldSize <= end) {
                val next = if (bigTiff) {
                    if (little) Bytes.u64le(buffer, nextPointerPos) else readU64be(buffer, nextPointerPos)
                } else {
                    if (little) Bytes.u32le(buffer, nextPointerPos).toLong() else Bytes.u32be(buffer, nextPointerPos)
                }
                if (next != 0L && label == "IFD0") {
                    walkIfd(buffer, base, end, next, "IFD1", entries, visited, little, bigTiff)
                }
            }
        } catch (_: Exception) {
        }
        return orientation
    }

    private fun readU64be(b: ByteArray, i: Int): Long {
        if (i + 8 > b.size) return 0L
        var value = 0L
        for (k in 0 until 8) value = (value shl 8) or (b[i + k].toLong() and 0xFF)
        return value
    }

    fun typeSize(type: Int): Long = when (type) {
        1, 2, 6, 7 -> 1L
        3, 8 -> 2L
        4, 9, 11 -> 4L
        5, 10, 12, 13, 16, 17, 18 -> 8L
        else -> 1L
    }

    fun scanJpegApp1(payload: ByteArray): ExifScan {
        if (payload.size < 8) return ExifScan(false, emptyList(), null, false)
        if (payload[0].toInt() == 0x45 && payload[1].toInt() == 0x78 && payload[2].toInt() == 0x69 &&
            payload[3].toInt() == 0x66 && payload[4].toInt() == 0 && payload[5].toInt() == 0
        ) {
            return scan(payload, 6)
        }
        return ExifScan(false, emptyList(), null, false)
    }

    fun buildMinimalOrientationApp1(orientation: Int): ByteArray {
        val buffer = ByteArray(32)
        buffer[0] = 0x45; buffer[1] = 0x78; buffer[2] = 0x69; buffer[3] = 0x66
        buffer[4] = 0x00; buffer[5] = 0x00
        var p = 6
        buffer[p++] = 0x4D; buffer[p++] = 0x4D
        buffer[p++] = 0x00; buffer[p++] = 0x2A
        Bytes.putU32be(buffer, p, 8L); p += 4
        Bytes.putU16be(buffer, p, 1); p += 2
        Bytes.putU16be(buffer, p, TagTable.TAG_ORIENTATION); p += 2
        Bytes.putU16be(buffer, p, 3); p += 2
        Bytes.putU32be(buffer, p, 1L); p += 4
        Bytes.putU16be(buffer, p, orientation); p += 2
        Bytes.putU16be(buffer, p, 0); p += 2
        Bytes.putU32be(buffer, p, 0L); p += 4
        return buffer.copyOf(p)
    }
}
