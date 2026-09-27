package com.example.lock.metadata

import java.io.File
import java.io.RandomAccessFile
import java.util.zip.ZipFile

data class FormatDetection(
    val format: MediaFormat,
    val subtype: String,
    val extension: String,
    val mimeHint: String = "",
    val notes: String? = null
)

object FormatDetector {

    private val isoBmffBrandsImage = setOf(
        "heic", "heix", "hevc", "hevx", "heim", "heis", "hevm", "hevs", "mif1", "mif2", "msf1",
        "miaf", "MiHE", "MiHA", "MiHB", "MiPR", "avci", "grid", "heif"
    )
    private val isoBmffBrandsAvif = setOf("avif", "avis", "avio")
    private val isoBmffBrandsVideo = setOf(
        "isom", "iso2", "iso4", "iso5", "iso6", "iso8", "mp41", "mp42", "mp71", "mp4v", "mmp4",
        "M4V ", "M4VH", "M4VP", "avc1", "dash", "cmfc", "msdh", "MSNV", "NDAS", "NDSC", "F4V ",
        "qt  ", "3gp4", "3gp5", "3gp6", "3gp7", "3gp8", "3gp9", "3ge6", "3gr6", "3gs6", "3g2a",
        "3g2b", "3g2c", "KDDI", "mmp4", "M4A ", "M4B ", "F4A ", "F4B ", "mp42"
    )
    private val isoBmffBrandsAudio = setOf("M4A ", "M4B ", "M4P ", "M4R ", "F4A ", "F4B ", "mp4a")
    private val isoBmffBrandsRaw = setOf("crx ", "canon", "CAEP", "CAME")

    private val textExtensions = setOf(
        "txt", "text", "md", "markdown", "csv", "tsv", "log", "json", "xml", "html", "htm", "xhtml",
        "svg", "rtf", "srt", "vtt", "lrc", "ini", "conf", "cfg", "properties", "yaml", "yml", "toml",
        "kt", "kts", "java", "js", "mjs", "ts", "py", "c", "cpp", "cc", "h", "hpp", "cs", "rb", "go",
        "rs", "swift", "sh", "bash", "zsh", "sql", "bat", "cmd", "ps1", "nfo", "me", "asc", "pem",
        "gitignore", "editorconfig", "diff", "patch", "ass"
    )

    private val rawExtensions = setOf(
        "dng", "cr2", "cr3", "crw", "nef", "nrw", "arw", "srf", "sr2", "orf", "rw2", "pef", "raf",
        "3fr", "mef", "mos", "mrw", "erf", "x3f", "rwl", "srw", "iiq", "eip", "fff", "kdc", "dcs",
        "drf", "ptx", "pxn", "r3d", "cap", "raw", "dcr", "k25", "kdc", "mdc", "bay"
    )

    /**
     * The conventional file name extension for a sniffed format. [FormatDetection.extension] is
     * taken from the file name, which is useless when the name carries no information at all: a
     * crash recovery backup is deliberately called ".b64-<token>.purgebak", and restoring it under
     * that suffix hands the user back a video file named .purgebak.
     */
    fun canonicalExtension(format: MediaFormat): String = when (format) {
        MediaFormat.JPEG -> "jpg"
        MediaFormat.PNG -> "png"
        MediaFormat.WEBP -> "webp"
        MediaFormat.GIF -> "gif"
        MediaFormat.BMP -> "bmp"
        MediaFormat.HEIF -> "heic"
        MediaFormat.AVIF -> "avif"
        MediaFormat.TIFF -> "tif"
        MediaFormat.RAW -> "dng"
        MediaFormat.PSD -> "psd"
        MediaFormat.MP4 -> "mp4"
        MediaFormat.THREEGP -> "3gp"
        MediaFormat.MKV -> "mkv"
        MediaFormat.AVI -> "avi"
        MediaFormat.ASF -> "asf"
        MediaFormat.FLV -> "flv"
        MediaFormat.MPEG_TS -> "ts"
        MediaFormat.MPEG_PS -> "mpg"
        MediaFormat.MP3 -> "mp3"
        MediaFormat.FLAC -> "flac"
        MediaFormat.OGG -> "ogg"
        MediaFormat.WAV -> "wav"
        MediaFormat.AAC -> "aac"
        MediaFormat.PDF -> "pdf"
        MediaFormat.DOCX -> "docx"
        MediaFormat.XLSX -> "xlsx"
        MediaFormat.PPTX -> "pptx"
        MediaFormat.ODF -> "odt"
        MediaFormat.EPUB -> "epub"
        MediaFormat.ZIP -> "zip"
        MediaFormat.SVG -> "svg"
        MediaFormat.HTML -> "html"
        MediaFormat.XML -> "xml"
        MediaFormat.RTF -> "rtf"
        MediaFormat.TEXT -> "txt"
        MediaFormat.TORRENT -> "torrent"
        MediaFormat.TAR -> "tar"
        MediaFormat.UNKNOWN -> "bin"
    }

    fun detect(file: File): FormatDetection {
        val ext = file.extension.lowercase()
        val header = readHeader(file, 64)
        if (header.size < 12) {
            if (isProbablyText(file)) return textDetection(file, ext)
            return FormatDetection(MediaFormat.UNKNOWN, "unknown", ext, notes = "file too small / header unreadable")
        }

        if (hasTextBom(header) || isBomlessUtf16(header)) {
            return textDetection(file, ext)
        }

        if (header.startsWith(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)) {
            return FormatDetection(MediaFormat.PNG, "png", ext, "image/png")
        }
        if (header.startsWith(0xFF, 0xD8, 0xFF)) {
            return FormatDetection(MediaFormat.JPEG, jpegSubtype(header), ext, "image/jpeg")
        }
        if (header.ascii(0, 6) == "GIF87a" || header.ascii(0, 6) == "GIF89a") {
            return FormatDetection(MediaFormat.GIF, header.ascii(0, 6), ext, "image/gif")
        }
        if (header.ascii(0, 4) == "RIFF") {
            val kind = header.ascii(8, 4)
            return when (kind) {
                "WEBP" -> FormatDetection(MediaFormat.WEBP, webpSubtype(header), ext, "image/webp")
                "WAVE" -> FormatDetection(MediaFormat.WAV, "wav", ext, "audio/wav")
                "AVI " -> FormatDetection(MediaFormat.AVI, "avi", ext, "video/x-msvideo")
                else -> FormatDetection(MediaFormat.UNKNOWN, "riff:$kind", ext, notes = "unsupported RIFF payload")
            }
        }
        if (header.ascii(0, 4) == "%PDF") {
            return FormatDetection(MediaFormat.PDF, header.ascii(5, 3), ext, "application/pdf")
        }
        if (header.ascii(0, 4) == "fLaC") {
            return FormatDetection(MediaFormat.FLAC, "flac", ext, "audio/flac")
        }
        if (header.ascii(0, 4) == "OggS") {
            return FormatDetection(MediaFormat.OGG, oggSubtype(file), ext, "audio/ogg")
        }
        if (header.ascii(0, 3) == "ID3") {
            return id3AudioDetection(file, header, ext)
        }
        if (header.u8(0) == 0xFF && (header.u8(1) and 0xE0) == 0xE0 && (header.u8(1) and 0x06) != 0) {
            return FormatDetection(MediaFormat.MP3, "mpeg-audio", ext, "audio/mpeg")
        }
        if (isAsfHeader(header)) {
            return FormatDetection(MediaFormat.ASF, asfSubtype(file), ext, "video/x-ms-asf")
        }
        if (header.ascii(0, 3) == "FLV") {
            return FormatDetection(MediaFormat.FLV, "flv", ext, "video/x-flv")
        }
        if (header.ascii(0, 4) == "ADIF") {
            return FormatDetection(MediaFormat.AAC, "adif", ext, "audio/aac")
        }
        if (isAdtsFrame(header)) {
            return FormatDetection(MediaFormat.AAC, "adts", ext, "audio/aac")
        }
        if (header.u8(0) == 0x00 && header.u8(1) == 0x00 && header.u8(2) == 0x01 && header.u8(3) == 0xBA) {
            return FormatDetection(MediaFormat.MPEG_PS, "program-stream", ext, "video/mpeg")
        }
        if (header.ascii(0, 6) == "ustar\u0000" || isTarHeader(file)) {
            return FormatDetection(MediaFormat.TAR, "tar", ext, "application/x-tar")
        }
        if (looksLikeTorrent(file)) {
            return FormatDetection(MediaFormat.TORRENT, "torrent", ext, "application/x-bittorrent")
        }
        if (isTransportStream(file)) {
            val layout = if (readHeader(file, 205).let { it.size >= 5 && it[4].toInt() and 0xFF == 0x47 }) "m2ts" else "ts"
            return FormatDetection(MediaFormat.MPEG_TS, layout, ext, "video/mp2t")
        }
        if (header.ascii(0, 4) == "8BPS") {
            return FormatDetection(MediaFormat.PSD, "psd", ext, "image/vnd.adobe.photoshop")
        }
        if (header.ascii(0, 5) == "{\\rtf") {
            return FormatDetection(MediaFormat.RTF, "rtf", ext, "application/rtf")
        }
        if (header.u8(0) == 0x1A && header.u8(1) == 0x45 && header.u8(2) == 0xDF && header.u8(3) == 0xA3) {
            return FormatDetection(MediaFormat.MKV, ebmlSubtype(file), ext, "video/x-matroska")
        }
        if (header.u8(0) == 0x42 && header.u8(1) == 0x4D) {
            return FormatDetection(MediaFormat.BMP, "bmp", ext, "image/bmp")
        }
        if (header.ascii(0, 4) == "PK\u0003\u0004" || header.ascii(0, 4) == "PK\u0005\u0006" || header.ascii(0, 4) == "PK\u0007\u0008") {
            return zipDetection(file, ext)
        }
        if (isTiffHeader(header)) {
            return tiffDetection(file, header, ext)
        }
        if (isIsoBmff(header)) {
            return isoBmffDetection(file, header, ext)
        }
        if (isTextish(header)) {
            return textDetection(file, ext)
        }
        if (textExtensions.contains(ext) && isProbablyText(file)) {
            return textDetection(file, ext)
        }
        if (stubPrefixZip(file)) {
            return FormatDetection(MediaFormat.ZIP, "zip", ext, "application/zip", notes = "container behind a leading stub")
        }
        return FormatDetection(MediaFormat.UNKNOWN, "binary", ext, notes = "no known container signature")
    }

    private fun id3v2Total(header: ByteArray): Long {
        if (header.size < 10) return 0L
        val flags = header[5].toInt() and 0xFF
        val size = ((header[6].toInt() and 0x7F) shl 21) or ((header[7].toInt() and 0x7F) shl 14) or
            ((header[8].toInt() and 0x7F) shl 7) or (header[9].toInt() and 0x7F)
        return 10L + size + (if (flags and 0x10 != 0) 10L else 0L)
    }

    private fun id3AudioDetection(file: File, header: ByteArray, ext: String): FormatDetection {
        val offset = id3v2Total(header)
        val probe = try {
            RandomAccessFile(file, "r").use { raf ->
                raf.seek(offset)
                val buffer = ByteArray(8)
                val read = raf.read(buffer)
                if (read <= 0) ByteArray(0) else buffer.copyOf(read)
            }
        } catch (_: Exception) {
            ByteArray(0)
        }
        if (isAdtsFrame(probe)) {
            return FormatDetection(MediaFormat.AAC, "adts", ext, "audio/aac")
        }
        if (probe.size >= 2 && probe[0].toInt() and 0xFF == 0xFF && (probe[1].toInt() and 0xE0) == 0xE0) {
            return FormatDetection(MediaFormat.MP3, "id3-mpeg", ext, "audio/mpeg")
        }
        if (ext == "aac" || ext == "m4a") {
            return FormatDetection(MediaFormat.AAC, "id3-adts", ext, "audio/aac")
        }
        return FormatDetection(MediaFormat.MP3, "id3v2", ext, "audio/mpeg")
    }

    private fun isAsfHeader(h: ByteArray): Boolean {
        if (h.size < 16) return false
        val prefix = byteArrayOf(
            0x30, 0x26, 0xB2.toByte(), 0x75, 0x8E.toByte(), 0x66, 0xCF.toByte(), 0x11,
            0xA6.toByte(), 0xD9.toByte(), 0x00, 0xAA.toByte(), 0x00, 0x62, 0xCE.toByte(), 0x6C
        )
        for (i in prefix.indices) if (h[i] != prefix[i]) return false
        return true
    }

    private fun asfSubtype(file: File): String {
        val probe = readHeader(file, 8192)
        val header = String(probe, Charsets.ISO_8859_1)
        return when {
            header.contains("WMA") || header.contains("WMAudio") -> "wma"
            header.contains("WMV") || header.contains("WMVideo") -> "wmv"
            else -> "asf"
        }
    }

    private fun isAdtsFrame(h: ByteArray): Boolean {
        if (h.size < 7) return false
        if (h[0].toInt() and 0xFF != 0xFF) return false
        val second = h[1].toInt() and 0xFF
        if (second and 0xF6 != 0xF0) return false
        val frameLength = ((h[3].toInt() and 0x03) shl 11) or ((h[4].toInt() and 0xFF) shl 3) or
            ((h[5].toInt() and 0xE0) shr 5)
        return frameLength in 7..8191
    }

    private fun isTarHeader(file: File): Boolean {
        val probe = readHeader(file, 512)
        if (probe.size < 512) return false
        val stored = Bytes.asciiAt(probe, 148, 8).trim { it == ' ' || it == '\u0000' }
        val expected = stored.toLongOrNull(8) ?: return false
        var sum = 0L
        for (i in 0 until 512) {
            sum += if (i in 148..155) 0x20 else (probe[i].toInt() and 0xFF)
        }
        return sum == expected
    }

    private fun looksLikeTorrent(file: File): Boolean {
        val probe = readHeader(file, 4096)
        if (probe.isEmpty() || probe[0] != 'd'.code.toByte()) return false
        val text = String(probe, Charsets.ISO_8859_1)
        return text.contains("4:info") || text.contains("8:announce")
    }

    private fun isTransportStream(file: File): Boolean {
        val probe = readHeader(file, 1024)
        for (candidate in listOf(Pair(188, 0), Pair(192, 4), Pair(204, 0))) {
            val size = candidate.first
            val sync = candidate.second
            if (probe.size < sync + 1) continue
            var checked = 0
            var index = sync
            while (index < probe.size && checked < 5) {
                if (probe[index].toInt() and 0xFF != 0x47) break
                checked++
                index += size
            }
            if (checked >= 4) return true
        }
        return false
    }

    private fun isTiffHeader(h: ByteArray): Boolean {
        if (h.size < 8) return false
        val le = h[0] == 0x49.toByte() && h[1] == 0x49.toByte()
        val be = h[0] == 0x4D.toByte() && h[1] == 0x4D.toByte()
        if (!le && !be) return false
        val magic = if (le) Bytes.u16le(h, 2) else Bytes.u16be(h, 2)
        return magic == 42 || magic == 43
    }

    private fun tiffDetection(file: File, header: ByteArray, ext: String): FormatDetection {
        val le = header[0] == 0x49.toByte()
        val mag = if (le) Bytes.u16le(header, 2) else Bytes.u16be(header, 2)
        if (mag == 43) return FormatDetection(MediaFormat.TIFF, "bigtiff", ext, "image/tiff")

        val fourCc = header.ascii(0, 4)
        if (fourCc == "IIRO" || fourCc == "IIRS" || fourCc == "MMOR" || fourCc == "IIU\u0000") {
            return FormatDetection(MediaFormat.RAW, "orf/rw2", ext, "image/x-raw")
        }
        if (fourCc == "IIII") return FormatDetection(MediaFormat.RAW, "iiq", ext, "image/x-raw")
        if (fourCc == "FOVb") return FormatDetection(MediaFormat.RAW, "x3f", ext, "image/x-raw")
        if (header.ascii(0, 15) == "FUJIFILMCCD-RAW") return FormatDetection(MediaFormat.RAW, "raf", ext, "image/x-raw")
        if (header.size >= 10 && header.ascii(8, 2) == "CR") return FormatDetection(MediaFormat.RAW, "cr2", ext, "image/x-raw")

        val make = readTiffMake(file)
        val subtype = when {
            make.contains("NIKON") -> "nef"
            make.contains("SONY") -> "arw"
            make.contains("PENTAX") || make.contains("RICOH") -> "pef"
            make.contains("SAMSUNG") -> "srw"
            make.contains("CANON") -> "cr2/crw"
            make.contains("FUJIFILM") -> "raf"
            make.contains("PANASONIC") -> "rw2"
            make.contains("OLYMPUS") -> "orf"
            make.contains("LEICA") -> "rwl"
            else -> ""
        }
        val isRawExt = ext in rawExtensions
        val resolved = if (subtype.isNotEmpty() && (isRawExt || make.isNotEmpty())) MediaFormat.RAW else MediaFormat.TIFF
        val finalSubtype = if (resolved == MediaFormat.RAW) subtype.ifEmpty { "tiff-raw" } else "tiff"
        return FormatDetection(resolved, finalSubtype, ext, if (resolved == MediaFormat.RAW) "image/x-raw" else "image/tiff")
    }

    private fun readTiffMake(file: File): String {
        return try {
            BinaryIo.open(file).use { io ->
                val le = (io.peekAt(0, 1)?.get(0)?.toInt() ?: 0) and 0xFF == 0x49
                io.seek(4)
                val ifd = if (le) io.u32le() else io.u32be()
                if (ifd <= 0 || ifd + 2 > io.length) return ""
                io.seek(ifd)
                val count = if (le) io.u16le() else io.u16be()
                var make = ""
                for (i in 0 until minOf(count, 512)) {
                    val tag = if (le) io.u16le() else io.u16be()
                    val type = if (le) io.u16le() else io.u16be()
                    val cnt = if (le) io.u32le() else io.u32be()
                    val inline = io.position
                    val size = typeSize(type) * cnt
                    if (tag == 0x010F) {
                        val valueOffset = if (size <= 4) inline else (if (le) io.u32le() else io.u32be())
                        if (size > 0) {
                            val bytes = io.peekAt(valueOffset, size.toInt().coerceAtMost(256)) ?: ByteArray(0)
                            make = String(bytes, Charsets.US_ASCII).trim().trimEnd('\u0000').uppercase()
                        }
                        break
                    }
                    io.seek(inline + 4)
                }
                make
            }
        } catch (_: Exception) {
            ""
        }
    }

    private fun typeSize(type: Int): Long = when (type) {
        1, 2, 6, 7 -> 1L
        3, 8 -> 2L
        4, 9, 11 -> 4L
        5, 10, 12, 13 -> 8L
        else -> 1L
    }

    private fun isIsoBmff(h: ByteArray): Boolean {
        if (h.size < 12) return false
        return h.ascii(4, 4) == "ftyp" || h.ascii(4, 4) == "styp" || h.ascii(4, 4) == "moov" || h.ascii(4, 4) == "meta" ||
            h.ascii(4, 4) == "free" || h.ascii(4, 4) == "skip" || h.ascii(4, 4) == "mdat" || h.ascii(4, 4) == "wide"
    }

    private fun isoBmffDetection(file: File, h: ByteArray, ext: String): FormatDetection {
        val brand = readFtypBrand(file) ?: h.ascii(8, 4)
        val minorBrand = brand.trim()
        return when {
            minorBrand in isoBmffBrandsAvif -> FormatDetection(MediaFormat.AVIF, minorBrand, ext, "image/avif")
            minorBrand in isoBmffBrandsRaw -> FormatDetection(MediaFormat.RAW, "cr3", ext, "image/x-raw")
            minorBrand in isoBmffBrandsImage -> FormatDetection(MediaFormat.HEIF, minorBrand, ext, "image/heif")
            minorBrand in isoBmffBrandsAudio -> FormatDetection(MediaFormat.MP4, "audio-mp4", ext, "audio/mp4")
            minorBrand == "qt" -> FormatDetection(MediaFormat.MP4, "mov", ext, "video/quicktime")
            minorBrand.startsWith("3g") -> FormatDetection(MediaFormat.THREEGP, minorBrand, ext, "video/3gpp")
            minorBrand in isoBmffBrandsVideo -> FormatDetection(MediaFormat.MP4, minorBrand, ext, "video/mp4")
            ext == "heic" || ext == "heif" -> FormatDetection(MediaFormat.HEIF, minorBrand, ext, "image/heif")
            ext == "avif" -> FormatDetection(MediaFormat.AVIF, minorBrand, ext, "image/avif")
            ext == "mov" -> FormatDetection(MediaFormat.MP4, "mov", ext, "video/quicktime")
            ext in setOf("3gp", "3g2") -> FormatDetection(MediaFormat.THREEGP, minorBrand, ext, "video/3gpp")
            ext in setOf("m4a", "m4b", "m4r") -> FormatDetection(MediaFormat.MP4, "audio-mp4", ext, "audio/mp4")
            else -> FormatDetection(MediaFormat.MP4, minorBrand, ext, "video/mp4")
        }
    }

    private fun readFtypBrand(file: File): String? {
        return try {
            BinaryIo.open(file).use { io ->
                val size = io.u32be()
                val type = io.ascii(4)
                if (type != "ftyp" || size < 12) return null
                io.ascii(4)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun jpegSubtype(h: ByteArray): String {
        var i = 2
        while (i + 3 < h.size) {
            if (h[i].toInt() and 0xFF != 0xFF) break
            val marker = h[i + 1].toInt() and 0xFF
            if (marker in 0xE0..0xEF) {
                return when (marker) {
                    0xE0 -> "jfif"
                    0xE1 -> if (h.ascii(i + 4, 4) == "Exif") "exif" else "app1"
                    0xE2 -> "icc"
                    0xED -> "iptc"
                    0xEE -> "adobe"
                    else -> "app${marker - 0xE0}"
                }
            }
            if (marker == 0xD8 || marker in 0xD0..0xD7 || marker == 0x01) {
                i += 2
                continue
            }
            if (i + 3 >= h.size) break
            val len = ((h[i + 2].toInt() and 0xFF) shl 8) or (h[i + 3].toInt() and 0xFF)
            if (len < 2) break
            i += 2 + len
        }
        return "jpeg"
    }

    private fun webpSubtype(h: ByteArray): String = when (h.ascii(12, 4)) {
        "VP8X" -> "extended"
        "VP8L" -> "lossless"
        "VP8 " -> "lossy"
        else -> "webp"
    }

    private fun oggSubtype(file: File): String = try {
        BinaryIo.open(file).use { io ->
            io.seek(28)
            val packet = io.readBytesOrNull(16) ?: return "ogg"
            val head = ByteArray(8)
            System.arraycopy(packet, 0, head, 0, minOf(8, packet.size))
            when {
                String(head, Charsets.US_ASCII).startsWith("OpusHead") -> "opus"
                packet[0].toInt() == 1 && String(packet, 1, 6, Charsets.US_ASCII) == "vorbis" -> "vorbis"
                String(packet, Charsets.US_ASCII).startsWith("Speex") -> "speex"
                String(packet, Charsets.US_ASCII).startsWith("fLaC") || String(packet, Charsets.US_ASCII).startsWith("\u007fFLAC") -> "flac"
                String(packet, Charsets.US_ASCII).startsWith("Theora") || String(packet, Charsets.US_ASCII) == "\u0080theora" -> "theora"
                                 else -> "ogg"
            }
        }
    } catch (_: Exception) {
        "ogg"
    }

    private fun ebmlSubtype(file: File): String = try {
        val head = readHeader(file, 4096)
        val text = String(head, Charsets.ISO_8859_1)
        when {
            text.contains("webm") -> "webm"
            text.contains("matroska") -> "mkv"
            else -> "ebml"
        }
    } catch (_: Exception) {
        "ebml"
    }

    private fun zipDetection(file: File, ext: String): FormatDetection {
        return try {
            ZipFile(file).use { zip ->
                val names = zip.entries().asSequence().take(400).map { it.name }.toHashSet()
                when {
                    names.contains("word/document.xml") -> FormatDetection(MediaFormat.DOCX, "docx", ext, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                    names.contains("xl/workbook.xml") -> FormatDetection(MediaFormat.XLSX, "xlsx", ext, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                    names.contains("ppt/presentation.xml") -> FormatDetection(MediaFormat.PPTX, "pptx", ext, "application/vnd.openxmlformats-officedocument.presentationml.presentation")
                    names.contains("mimetype") && runCatching {
                        zip.getInputStream(zip.getEntry("mimetype")).use { it.readBytes().toString(Charsets.US_ASCII) }
                    }.getOrDefault("").contains("opendocument") -> {
                        val kind = ext.ifEmpty { "odf" }
                        FormatDetection(MediaFormat.ODF, kind, ext, "application/vnd.oasis.opendocument")
                    }
                    // An EPUB is identified by its container, not by its file name: the ODF branch
                    // above already sniffs content, and a renamed or extensionless book still is one.
                    names.contains("META-INF/container.xml") &&
                        (ext == "epub" || names.any { it.lowercase().endsWith(".opf") }) ->
                        FormatDetection(MediaFormat.EPUB, "epub", ext, "application/epub+zip")
                    names.contains("AndroidManifest.xml") && ext in setOf("apk", "apks", "xapk") -> FormatDetection(MediaFormat.ZIP, "apk", ext, "application/vnd.android.package-archive")
                    else -> FormatDetection(MediaFormat.ZIP, "zip", ext, "application/zip")
                }
            }
        } catch (_: Exception) {
            FormatDetection(MediaFormat.ZIP, "zip", ext, "application/zip", notes = "central directory unreadable")
        }
    }

    private fun decodedTextProbe(probe: ByteArray): String {
        if (probe.size >= 2) {
            val first = probe[0].toInt() and 0xFF
            val second = probe[1].toInt() and 0xFF
            if (first != 0x00 && second == 0x00) {
                return String(probe, 0, minOf(probe.size, 4096), Charsets.UTF_16LE)
            }
            if (first == 0x00 && second != 0x00) {
                return String(probe, 0, minOf(probe.size, 4096), Charsets.UTF_16BE)
            }
        }
        if (probe.size >= 4 && (probe[0].toInt() and 0xFF) == 0xFF && (probe[1].toInt() and 0xFF) == 0xFE &&
            probe[2].toInt() == 0x00 && probe[3].toInt() == 0x00
        ) {
            return String(probe, 4, minOf(probe.size - 4, 4096), Charsets.UTF_32LE)
        }
        if (probe.size >= 4 && probe[0].toInt() == 0x00 && probe[1].toInt() == 0x00 &&
            (probe[2].toInt() and 0xFF) == 0xFE && (probe[3].toInt() and 0xFF) == 0xFF
        ) {
            return String(probe, 4, minOf(probe.size - 4, 4096), Charsets.UTF_32BE)
        }
        if (probe.size >= 3 && (probe[0].toInt() and 0xFF) == 0xEF && (probe[1].toInt() and 0xFF) == 0xBB && (probe[2].toInt() and 0xFF) == 0xBF) {
            return String(probe, 3, minOf(probe.size - 3, 4096), Charsets.UTF_8)
        }
        if (probe.size >= 2 && (probe[0].toInt() and 0xFF) == 0xFF && (probe[1].toInt() and 0xFF) == 0xFE) {
            return String(probe, 2, minOf(probe.size - 2, 4096), Charsets.UTF_16LE)
        }
        if (probe.size >= 2 && (probe[0].toInt() and 0xFF) == 0xFE && (probe[1].toInt() and 0xFF) == 0xFF) {
            return String(probe, 2, minOf(probe.size - 2, 4096), Charsets.UTF_16BE)
        }
        return ""
    }

    private fun stubPrefixZip(file: File): Boolean {
        val length = file.length()
        if (length < 128) return false
        val tailLength = minOf(length, 65557L).toInt()
        val tail = readAt(file, length - tailLength, tailLength) ?: return false
        var eocd = -1
        for (i in tail.size - 22 downTo 0) {
            if (Bytes.u32le(tail, i) == 0x06054b50L) {
                eocd = i
                break
            }
        }
        if (eocd < 0) return false
        val commentLength = Bytes.u16le(tail, eocd + 20)
        if (eocd + 22 + commentLength != tail.size) return false
        if (Bytes.u16le(tail, eocd + 8) == 0 && Bytes.u16le(tail, eocd + 10) == 0) return false
        val probeLength = minOf(length, 1L shl 20).toInt()
        val head = readAt(file, 0L, probeLength) ?: return false
        var index = 0
        while (index + 4 <= head.size) {
            if (head[index] == 0x50.toByte() && head[index + 1] == 0x4B.toByte() &&
                head[index + 2] == 0x03.toByte() && head[index + 3] == 0x04.toByte()
            ) {
                return true
            }
            index++
        }
        return false
    }

    private fun readAt(file: File, offset: Long, size: Int): ByteArray? = try {
        java.io.RandomAccessFile(file, "r").use { raf ->
            if (offset + size > raf.length()) {
                null
            } else {
                val buffer = ByteArray(size)
                raf.seek(offset)
                raf.readFully(buffer)
                buffer
            }
        }
    } catch (_: Exception) {
        null
    }

    private fun textDetection(file: File, ext: String): FormatDetection {
        val probe = readHeader(file, 8192)
        val transcoded = decodedTextProbe(probe)
        if (transcoded.isNotEmpty()) {
            val decoded = transcoded.trimStart('\uFEFF', ' ', '\n', '\r', '\t', '\u0000')
            val lower = decoded.lowercase()
            val view = if (lower.length > 4096) lower.substring(0, 4096) else lower
            when {
                view.contains("<svg") -> return FormatDetection(MediaFormat.SVG, "svg-bom", ext, "image/svg+xml")
                view.contains("<!doctype html") || view.contains("<html") || view.contains("<head") ->
                    return FormatDetection(MediaFormat.HTML, "html-bom", ext, "text/html")
                view.startsWith("<?xml") || (view.startsWith("<") && view.contains(">")) ->
                    return FormatDetection(MediaFormat.XML, "xml-bom", ext, "application/xml")
                view.startsWith("{\\rtf") -> return FormatDetection(MediaFormat.RTF, "rtf-bom", ext, "application/rtf")
                else -> return FormatDetection(MediaFormat.TEXT, textSubtype(ext), ext, "text/plain")
            }
        }
        val head = String(probe, Charsets.ISO_8859_1).trimStart('\uFEFF', ' ', '\n', '\r', '\t')
        return when {
            head.startsWith("<?xml") && head.contains("<svg") -> FormatDetection(MediaFormat.SVG, "svg", ext, "image/svg+xml")
            head.startsWith("<svg") -> FormatDetection(MediaFormat.SVG, "svg", ext, "image/svg+xml")
            head.startsWith("<!DOCTYPE html") || head.startsWith("<html") || head.contains("<html") -> FormatDetection(MediaFormat.HTML, "html", ext, "text/html")
            head.startsWith("<?xml") -> FormatDetection(MediaFormat.XML, "xml", ext, "application/xml")
            head.startsWith("{\\rtf") -> FormatDetection(MediaFormat.RTF, "rtf", ext, "application/rtf")
            isProbablyText(file) -> FormatDetection(MediaFormat.TEXT, textSubtype(ext), ext, "text/plain")
            stubPrefixZip(file) ->
                FormatDetection(MediaFormat.ZIP, "zip", ext, "application/zip", notes = "container behind a leading stub")
            else -> FormatDetection(MediaFormat.UNKNOWN, "binary", ext, notes = "unrecognised binary container")
        }
    }

    private fun textSubtype(ext: String): String = when (ext) {
        "txt" -> "txt"
        "csv" -> "csv"
        "json" -> "json"
        "md" -> "markdown"
        "srt" -> "subtitle-srt"
        "vtt" -> "subtitle-vtt"
        "lrc" -> "lyrics"
        "log" -> "log"
        "ini", "conf", "cfg", "properties" -> "config"
        "kt", "java", "js", "ts", "py", "c", "cpp", "h", "cs", "rb", "go", "rs", "swift", "sh" -> "source"
        else -> "text"
    }

    fun isProbablyText(file: File): Boolean {
        val probe = readHeader(file, 8192)
        if (probe.isEmpty()) return false
        var control = 0
        var zerosEven = 0
        var zerosOdd = 0
        var i = 0
        while (i < probe.size) {
            val b = probe[i].toInt() and 0xFF
            if (b == 0) {
                if (i % 2 == 0) zerosEven++ else zerosOdd++
            } else if (b < 0x09 || (b in 0x0E..0x1F) || b == 0x7F) {
                control++
            }
            i++
        }
        val zeros = zerosEven + zerosOdd
        if (zeros == 0) return control * 100 / probe.size < 2
        // Text in a 16 bit encoding puts a zero on every other byte and nowhere else. Binary data
        // scatters zeros across both parities, so the old first zero byte verdict was a coin toss.
        val zerosRatio = zeros * 100 / probe.size
        val dominant = maxOf(zerosEven, zerosOdd) * 100 / zeros
        return zerosRatio in 20..75 && dominant >= 90
    }

    private fun isBomlessUtf16(h: ByteArray): Boolean {
        if (h.size < 4) return false
        val first = h[0].toInt() and 0xFF
        val second = h[1].toInt() and 0xFF
        val third = h[2].toInt() and 0xFF
        val fourth = h[3].toInt() and 0xFF
        if (first == 0x3C && second == 0x00 && third != 0x00 && fourth == 0x00) return true
        if (first == 0x00 && second == 0x3C && third == 0x00 && fourth != 0x00) return true
        if (first == 0x7B && second == 0x00 && third == 0x5C && fourth == 0x00) return true
        return false
    }

    private fun hasTextBom(h: ByteArray): Boolean {
        if (h.size >= 3 && (h[0].toInt() and 0xFF) == 0xEF && (h[1].toInt() and 0xFF) == 0xBB &&
            (h[2].toInt() and 0xFF) == 0xBF
        ) {
            return true
        }
        if (h.size >= 4 && (h[0].toInt() and 0xFF) == 0xFF && (h[1].toInt() and 0xFF) == 0xFE &&
            (h[2].toInt() and 0xFF) == 0x00 && (h[3].toInt() and 0xFF) == 0x00
        ) {
            return true
        }
        if (h.size >= 4 && (h[0].toInt() and 0xFF) == 0x00 && (h[1].toInt() and 0xFF) == 0x00 &&
            (h[2].toInt() and 0xFF) == 0xFE && (h[3].toInt() and 0xFF) == 0xFF
        ) {
            return true
        }
        if (h.size >= 2 && (h[0].toInt() and 0xFF) == 0xFF && (h[1].toInt() and 0xFF) == 0xFE) return true
        if (h.size >= 2 && (h[0].toInt() and 0xFF) == 0xFE && (h[1].toInt() and 0xFF) == 0xFF) return true
        return false
    }

    private fun isTextish(h: ByteArray): Boolean {
        val text = String(h, Charsets.ISO_8859_1).trimStart('\uFEFF', ' ', '\n', '\r', '\t')
        return text.startsWith("<") || text.startsWith("{") || text.startsWith("<?") || text.startsWith("d8:")
    }

    private fun readHeader(file: File, size: Int): ByteArray {
        return try {
            RandomAccessFile(file, "r").use { raf ->
                val buffer = ByteArray(minOf(size.toLong(), maxOf(0L, raf.length())).toInt())
                var read = 0
                while (read < buffer.size) {
                    val n = raf.read(buffer, read, buffer.size - read)
                    if (n <= 0) break
                    read += n
                }
                if (read == buffer.size) buffer else buffer.copyOf(read)
            }
        } catch (_: Exception) {
            ByteArray(0)
        }
    }

    private fun ByteArray.startsWith(vararg values: Int): Boolean {
        if (size < values.size) return false
        for (i in values.indices) if ((this[i].toInt() and 0xFF) != values[i]) return false
        return true
    }

    private fun ByteArray.u8(i: Int): Int = Bytes.u8(this, i)

    private fun ByteArray.ascii(offset: Int, len: Int): String {
        if (offset + len > size) return ""
        return String(this, offset, len, Charsets.US_ASCII)
    }
}
