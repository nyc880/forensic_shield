package com.example.lock

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Build
import androidx.exifinterface.media.ExifInterface
import org.apache.commons.imaging.Imaging
import org.apache.commons.imaging.formats.tiff.TiffImageMetadata
import org.apache.commons.imaging.formats.tiff.constants.TiffTagConstants
import org.apache.commons.imaging.formats.tiff.write.TiffImageWriterLossless
import org.apache.commons.imaging.formats.tiff.write.TiffOutputSet
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.FileTime
import java.util.Locale
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.OutputKeys
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import org.w3c.dom.Element
import org.w3c.dom.Node

object MetadataPurgeProcessor {

    // Centralized Configuration Constants
    private const val BUFFER_SIZE = 8192
    private const val RANDOM_NAME_LENGTH = 5
    private const val CHAR_POOL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    private const val MAX_RENAME_ATTEMPTS = 50
    private const val EPOCH_ZERO_TIMESTAMP = 0L

    /**
     * Purges metadata from the given file and renames it to a 5-character random name.
     * @return The updated [File] reference pointing to the sanitized/renamed file, or null on failure.
     */
    fun purgeFile(file: File): File? {
        if (!file.exists() || !file.isFile || !file.canWrite()) return null

        val extension = file.extension.lowercase(Locale.ROOT)
        val tempFile = File.createTempFile("purge_", ".tmp", file.parentFile)

        val success = try {
            val purged = when (extension) {
                // 1. Standard Raster Images
                "jpg", "jpeg", "jpe", "jfif" -> purgeJpegImage(file, tempFile)
                "png" -> purgePngImage(file, tempFile)
                "webp" -> purgeWebpImage(file, tempFile)

                // 2. Container Images & Animations
                "heic", "heif", "avif" -> purgeIsoBmffImage(file, tempFile)
                "gif" -> purgeGifImage(file, tempFile)
                "bmp", "dib" -> purgeGenericFile(file, tempFile)

                // 3. RAW Images (TIFF/Raw Parser using Commons Imaging TiffWriter)
                "tiff", "tif", "dng", "cr2", "cr3", "crw", "nef", "nrw", "arw", "srf", "sr2",
                "orf", "rw2", "pef", "raf", "3fr", "mef", "mos", "mrw", "erf", "x3f", "rwl",
                "srw", "iiq", "eip", "fff", "kdc", "dcs", "drf", "ptx", "pxn", "r3d", "cap" -> {
                    purgeRawImage(file, tempFile)
                }

                // 4. Vector Graphics (Hardened DOM Parser with XXE protection)
                "svg" -> purgeSvgMetadata(file, tempFile)

                // 5. Audio
                "mp3" -> purgeMp3Audio(file, tempFile)

                // 6. ISO BMFF Video & Audio
                "mp4", "m4v", "m4a", "m4b", "m4r", "mov", "3gp", "3g2" -> {
                    purgeMp4Video(file, tempFile)
                }

                // 7. Documents
                "pdf" -> purgePdfMetadata(file, tempFile)

                // 8. Generic binary fallback
                else -> purgeGenericFile(file, tempFile)
            }

            if (purged && tempFile.exists() && tempFile.length() > 0) {
                overwriteOriginalFileInPlace(file, tempFile)
            } else {
                false
            }
        } catch (_: Exception) {
            false
        } finally {
            if (tempFile.exists()) tempFile.delete()
        }

        if (!success) return null

        val renamedFile = renameToRandom5CharsWithRetry(file)
        sanitizeTimestampsToEpochZero(renamedFile)

        return renamedFile
    }

    private fun renameToRandom5CharsWithRetry(file: File): File {
        val ext = file.extension
        var targetFile: File
        var attempts = 0

        do {
            val randomName = (1..RANDOM_NAME_LENGTH)
                .map { kotlin.random.Random.nextInt(0, CHAR_POOL.length) }
                .map(CHAR_POOL::get)
                .joinToString("")

            val newFileName = if (ext.isNotEmpty()) "$randomName.$ext" else randomName
            targetFile = File(file.parentFile, newFileName)
            attempts++
        } while (targetFile.exists() && attempts < MAX_RENAME_ATTEMPTS)

        if (targetFile.exists()) {
            val fallbackName = "${System.currentTimeMillis()}_${file.name}"
            targetFile = File(file.parentFile, fallbackName)
        }

        return if (file.renameTo(targetFile)) targetFile else file
    }

    private fun sanitizeTimestampsToEpochZero(file: File) {
        try {
            file.setLastModified(EPOCH_ZERO_TIMESTAMP)

            val zeroFileTime = FileTime.fromMillis(EPOCH_ZERO_TIMESTAMP)
            val attrView = Files.getFileAttributeView(file.toPath(), BasicFileAttributeView::class.java)
            attrView?.setTimes(zeroFileTime, zeroFileTime, zeroFileTime)
        } catch (_: Exception) {}
    }

    private fun overwriteOriginalFileInPlace(originalFile: File, tempFile: File): Boolean {
        return try {
            RandomAccessFile(originalFile, "rw").use { raf ->
                val oldLength = raf.length()
                raf.seek(0)
                FileInputStream(tempFile).use { fis ->
                    val buffer = ByteArray(BUFFER_SIZE)
                    var read: Int
                    while (fis.read(buffer).also { read = it } != -1) {
                        raf.write(buffer, 0, read)
                    }
                }
                val newLength = raf.filePointer
                if (oldLength > newLength) {
                    val residual = oldLength - newLength
                    val zeroBuffer = ByteArray(minOf(residual, BUFFER_SIZE.toLong()).toInt())
                    var remaining = residual
                    while (remaining > 0) {
                        val writeSize = minOf(remaining, zeroBuffer.size.toLong()).toInt()
                        raf.write(zeroBuffer, 0, writeSize)
                        remaining -= writeSize
                    }
                }
                raf.setLength(newLength)
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    // ------------------------------------------------------------------------
    // 1. RASTER IMAGES
    // ------------------------------------------------------------------------

    private fun purgeJpegImage(source: File, destination: File): Boolean {
        return try {
            val bitmap = BitmapFactory.decodeFile(source.absolutePath)
            if (bitmap != null) {
                FileOutputStream(destination).use { out ->
                    bitmap.compress(Bitmap.CompressFormat.JPEG, 100, out)
                    out.flush()
                }
                bitmap.recycle()
            } else {
                source.copyTo(destination, overwrite = true)
            }
            stripExifAttributes(destination)
            stripJpegAppSegmentsAndComments(destination)
            true
        } catch (_: Exception) {
            purgeGenericFile(source, destination)
        }
    }

    private fun purgePngImage(source: File, destination: File): Boolean {
        return try {
            val bitmap = BitmapFactory.decodeFile(source.absolutePath)
            if (bitmap != null) {
                FileOutputStream(destination).use { out ->
                    bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
                    out.flush()
                }
                bitmap.recycle()
                stripExifAttributes(destination)
                true
            } else {
                purgeGenericFile(source, destination)
            }
        } catch (_: Exception) {
            purgeGenericFile(source, destination)
        }
    }

    private fun purgeWebpImage(source: File, destination: File): Boolean {
        return try {
            val bitmap = BitmapFactory.decodeFile(source.absolutePath)
            if (bitmap != null) {
                val format = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    Bitmap.CompressFormat.WEBP_LOSSLESS
                } else {
                    Bitmap.CompressFormat.WEBP
                }
                FileOutputStream(destination).use { out ->
                    bitmap.compress(format, 100, out)
                    out.flush()
                }
                bitmap.recycle()
                stripExifAttributes(destination)
                true
            } else {
                purgeGenericFile(source, destination)
            }
        } catch (_: Exception) {
            purgeGenericFile(source, destination)
        }
    }

    // ------------------------------------------------------------------------
    // 2. ISO-BMFF CONTAINER IMAGES (HEIC / HEIF / AVIF)
    // ------------------------------------------------------------------------

    private fun purgeIsoBmffImage(source: File, destination: File): Boolean {
        return try {
            source.copyTo(destination, overwrite = true)
            stripExifAttributes(destination)
            purgeHeicItemMetadata(destination)
            true
        } catch (_: Exception) {
            purgeGenericFile(source, destination)
        }
    }

    private fun purgeHeicItemMetadata(file: File) {
        try {
            RandomAccessFile(file, "rw").use { raf ->
                val length = raf.length()
                var pos = 0L

                while (pos < length - 8) {
                    raf.seek(pos)
                    val atomSize = raf.readInt().toLong() and 0xFFFFFFFFL
                    val atomType = ByteArray(4)
                    if (raf.read(atomType) < 4) break
                    val typeStr = String(atomType, Charsets.US_ASCII)

                    val actualSize = when (atomSize) {
                        1L -> {
                            if (pos + 16 > length) break
                            raf.readLong()
                        }
                        0L -> length - pos
                        else -> atomSize
                    }

                    if (typeStr == "meta") {
                        val headerOffset = if (atomSize == 1L) 16 else 8
                        val metaContentStart = pos + headerOffset + 4
                        val metaContentEnd = pos + actualSize
                        processHeicMetaBox(raf, metaContentStart, metaContentEnd)
                        break
                    }

                    if (actualSize <= 0) break
                    pos += actualSize
                }
            }
        } catch (_: Exception) {}
    }

    private fun processHeicMetaBox(raf: RandomAccessFile, startPos: Long, endPos: Long) {
        val metadataItemIds = HashSet<Int>()
        val itemLocations = HashMap<Int, List<Pair<Long, Long>>>()

        var pos = startPos
        while (pos < endPos - 8) {
            raf.seek(pos)
            val boxSize = raf.readInt().toLong() and 0xFFFFFFFFL
            val boxTypeBytes = ByteArray(4)
            if (raf.read(boxTypeBytes) < 4) break
            val boxType = String(boxTypeBytes, Charsets.US_ASCII)

            val actualSize = when (boxSize) {
                1L -> {
                    if (pos + 16 > endPos) break
                    raf.readLong()
                }
                0L -> endPos - pos
                else -> boxSize
            }

            val headerLen = if (boxSize == 1L) 16 else 8

            when (boxType) {
                "iinf" -> {
                    parseIinfBox(raf, pos + headerLen, pos + actualSize, metadataItemIds)
                }
                "iloc" -> {
                    parseIlocBox(raf, pos + headerLen, pos + actualSize, itemLocations)
                }
            }

            if (actualSize <= 0) break
            pos += actualSize
        }

        for (itemId in metadataItemIds) {
            val extents = itemLocations[itemId] ?: continue
            for ((extentOffset, extentLength) in extents) {
                if (extentOffset > 0 && extentLength > 0 && extentOffset + extentLength <= raf.length()) {
                    raf.seek(extentOffset)
                    val zeroBuf = ByteArray(minOf(extentLength, BUFFER_SIZE.toLong()).toInt())
                    var remaining = extentLength
                    while (remaining > 0) {
                        val writeLen = minOf(remaining, zeroBuf.size.toLong()).toInt()
                        raf.write(zeroBuf, 0, writeLen)
                        remaining -= writeLen
                    }
                }
            }
        }
    }

    private fun parseIinfBox(raf: RandomAccessFile, startPos: Long, endPos: Long, metadataItemIds: MutableSet<Int>) {
        try {
            raf.seek(startPos)
            val version = raf.readUnsignedByte()
            raf.skipBytes(3)

            val entryCount = if (version == 0) raf.readUnsignedShort() else raf.readInt()
            var pos = raf.filePointer

            var entryIndex = 0
            while (entryIndex < entryCount) {
                entryIndex++
                if (pos >= endPos - 8) break
                raf.seek(pos)
                val infeSize = raf.readInt().toLong() and 0xFFFFFFFFL
                val infeTypeBytes = ByteArray(4)
                if (raf.read(infeTypeBytes) < 4) break
                val infeType = String(infeTypeBytes, Charsets.US_ASCII)

                if (infeType == "infe") {
                    val infeVersion = raf.readUnsignedByte()
                    raf.skipBytes(3)

                    val itemId: Int
                    val itemType: String

                    if (infeVersion == 2) {
                        itemId = raf.readUnsignedShort()
                        raf.skipBytes(2)
                        val itemTypeBytes = ByteArray(4)
                        raf.read(itemTypeBytes)
                        itemType = String(itemTypeBytes, Charsets.US_ASCII)
                    } else if (infeVersion == 3) {
                        itemId = raf.readInt()
                        raf.skipBytes(2)
                        val itemTypeBytes = ByteArray(4)
                        raf.read(itemTypeBytes)
                        itemType = String(itemTypeBytes, Charsets.US_ASCII)
                    } else if (infeVersion <= 1) {
                        itemId = raf.readUnsignedShort()
                        raf.skipBytes(2)
                        val itemTypeBytes = ByteArray(4)
                        raf.read(itemTypeBytes)
                        itemType = String(itemTypeBytes, Charsets.US_ASCII)
                    } else {
                        itemId = -1
                        itemType = ""
                    }

                    if (itemType.equals("Exif", ignoreCase = true) || itemType.equals("mime", ignoreCase = true)) {
                        metadataItemIds.add(itemId)
                    }
                }

                val actualInfeSize = if (infeSize == 1L) raf.readLong() else infeSize
                if (actualInfeSize <= 0) break
                pos += actualInfeSize
            }
        } catch (_: Exception) {}
    }

    private fun parseIlocBox(raf: RandomAccessFile, startPos: Long, endPos: Long, itemLocations: MutableMap<Int, List<Pair<Long, Long>>>) {
        try {
            raf.seek(startPos)
            val version = raf.readUnsignedByte()
            raf.skipBytes(3)

            val byte0 = raf.readUnsignedByte()
            val offsetSize = (byte0 shr 4) and 0x0F
            val lengthSize = byte0 and 0x0F

            val byte1 = raf.readUnsignedByte()
            val baseOffsetSize = (byte1 shr 4) and 0x0F
            val indexSize = if (version in 1..2) byte1 and 0x0F else 0

            val itemCount = if (version < 2) raf.readUnsignedShort() else raf.readInt()

            var itemIndex = 0
            while (itemIndex < itemCount) {
                itemIndex++
                if (raf.filePointer >= endPos) break
                val itemId = if (version < 2) raf.readUnsignedShort() else raf.readInt()

                if (version in 1..2) {
                    raf.skipBytes(2)
                }
                raf.skipBytes(2)

                val baseOffset = readSizedInt(raf, baseOffsetSize)
                val extentCount = raf.readUnsignedShort()
                val extents = ArrayList<Pair<Long, Long>>()

                var extentIndex = 0
                while (extentIndex < extentCount) {
                    extentIndex++
                    if (indexSize > 0) {
                        readSizedInt(raf, indexSize)
                    }
                    val extentOffset = readSizedInt(raf, offsetSize)
                    val extentLength = readSizedInt(raf, lengthSize)
                    val absoluteOffset = baseOffset + extentOffset
                    extents.add(Pair(absoluteOffset, extentLength))
                }
                itemLocations[itemId] = extents
            }
        } catch (_: Exception) {}
    }

    private fun readSizedInt(raf: RandomAccessFile, size: Int): Long {
        return when (size) {
            1 -> raf.readUnsignedByte().toLong()
            2 -> raf.readUnsignedShort().toLong()
            4 -> raf.readInt().toLong() and 0xFFFFFFFFL
            8 -> raf.readLong()
            else -> 0L
        }
    }

    // ------------------------------------------------------------------------
    // 3. RAW IMAGES (TIFF BASED)
    // ------------------------------------------------------------------------

    private fun purgeRawImage(source: File, destination: File): Boolean {
        return try {
            val bytes = source.readBytes()
            val metadata = Imaging.getMetadata(bytes) as? TiffImageMetadata

            if (metadata != null) {
                val outputSet: TiffOutputSet? = metadata.outputSet
                if (outputSet != null) {
                    outputSet.gpsDirectory?.let { outputSet.directories.remove(it) }
                    outputSet.exifDirectory?.let { outputSet.directories.remove(it) }

                    val rootDir = outputSet.rootDirectory
                    if (rootDir != null) {
                        rootDir.removeField(TiffTagConstants.TIFF_TAG_ARTIST)
                        rootDir.removeField(TiffTagConstants.TIFF_TAG_COPYRIGHT)
                        rootDir.removeField(TiffTagConstants.TIFF_TAG_IMAGE_DESCRIPTION)
                        rootDir.removeField(TiffTagConstants.TIFF_TAG_SOFTWARE)
                        rootDir.removeField(TiffTagConstants.TIFF_TAG_DATE_TIME)
                        rootDir.removeField(TiffTagConstants.TIFF_TAG_HOST_COMPUTER)
                    }

                    val writer = TiffImageWriterLossless(bytes)
                    FileOutputStream(destination).use { os ->
                        writer.write(os, outputSet)
                    }
                    stripExifAttributes(destination)
                    return true
                }
            }
            purgeRawFallback(source, destination)
        } catch (_: Exception) {
            purgeRawFallback(source, destination)
        }
    }

    private fun purgeRawFallback(source: File, destination: File): Boolean {
        return try {
            source.copyTo(destination, overwrite = true)
            stripExifAttributes(destination)
            true
        } catch (_: Exception) {
            false
        }
    }

    // ------------------------------------------------------------------------
    // 4. ANIMATED GIF IMAGES
    // ------------------------------------------------------------------------

    private fun purgeGifImage(source: File, destination: File): Boolean {
        return try {
            FileInputStream(source).use { fis ->
                FileOutputStream(destination).use { fos ->
                    val header = ByteArray(6)
                    if (fis.read(header) != 6) return false
                    fos.write(header)

                    val lsd = ByteArray(7)
                    if (fis.read(lsd) != 7) return false
                    fos.write(lsd)

                    val packed = lsd[4].toInt() and 0xFF
                    val gctFlag = (packed and 0x80) != 0
                    if (gctFlag) {
                        val gctSizeExponent = (packed and 0x07) + 1
                        val gctSizeBytes = 3 * (1 shl gctSizeExponent)
                        val gct = ByteArray(gctSizeBytes)
                        if (fis.read(gct) != gctSizeBytes) return false
                        fos.write(gct)
                    }

                    var byteRead: Int
                    while (fis.read().also { byteRead = it } != -1) {
                        if (byteRead == 0x21) {
                            val label = fis.read()
                            if (label == 0xFE || label == 0xFF) {
                                skipGifBlockSubBlocks(fis)
                            } else {
                                fos.write(0x21)
                                fos.write(label)
                            }
                        } else {
                            fos.write(byteRead)
                        }
                    }
                }
            }
            true
        } catch (_: Exception) {
            purgeGenericFile(source, destination)
        }
    }

    private fun skipGifBlockSubBlocks(fis: FileInputStream) {
        var blockSize: Int
        while (fis.read().also { blockSize = it } != -1) {
            if (blockSize == 0) break
            fis.skip(blockSize.toLong())
        }
    }

    // ------------------------------------------------------------------------
    // 5. VECTOR GRAPHICS (SVG)
    // ------------------------------------------------------------------------

    private fun purgeSvgMetadata(source: File, destination: File): Boolean {
        return try {
            val dbf = DocumentBuilderFactory.newInstance()
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            dbf.isExpandEntityReferences = false

            val builder = dbf.newDocumentBuilder()
            val doc = builder.parse(source)

            val tagsToRemove = listOf("metadata", "rdf:RDF", "title", "desc")
            for (tag in tagsToRemove) {
                val nodes = doc.getElementsByTagName(tag)
                for (i in nodes.length - 1 downTo 0) {
                    val node = nodes.item(i)
                    node.parentNode?.removeChild(node)
                }
            }

            cleanSvgNode(doc.documentElement)

            val transformer = TransformerFactory.newInstance().newTransformer()
            transformer.setOutputProperty(OutputKeys.INDENT, "yes")
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8")

            FileOutputStream(destination).use { fos ->
                transformer.transform(DOMSource(doc), StreamResult(fos))
            }
            true
        } catch (_: Exception) {
            purgeGenericFile(source, destination)
        }
    }

    private fun cleanSvgNode(node: Node) {
        if (node.nodeType == Node.ELEMENT_NODE) {
            val element = node as Element
            val attributes = element.attributes
            val attrsToRemove = mutableListOf<String>()

            for (i in 0 until attributes.length) {
                val attr = attributes.item(i)
                val attrName = attr.nodeName
                if (attrName.startsWith("inkscape:") ||
                    attrName.startsWith("sodipodi:") ||
                    attrName.startsWith("xmlns:inkscape") ||
                    attrName.startsWith("xmlns:sodipodi")
                ) {
                    attrsToRemove.add(attrName)
                }
            }

            for (attrName in attrsToRemove) {
                element.removeAttribute(attrName)
            }

            val childNodes = element.childNodes
            for (i in 0 until childNodes.length) {
                cleanSvgNode(childNodes.item(i))
            }
        }
    }

    // ------------------------------------------------------------------------
    // 6. AUDIO (MP3)
    // ------------------------------------------------------------------------

    private fun purgeMp3Audio(source: File, destination: File): Boolean {
        return try {
            val bytes = source.readBytes()
            var startOffset = 0
            var endOffset = bytes.size

            if (bytes.size >= 10 && bytes[0] == 0x49.toByte() && bytes[1] == 0x44.toByte() && bytes[2] == 0x33.toByte()) {
                val sizeByte0 = bytes[6].toInt() and 0x7F
                val sizeByte1 = bytes[7].toInt() and 0x7F
                val sizeByte2 = bytes[8].toInt() and 0x7F
                val sizeByte3 = bytes[9].toInt() and 0x7F
                val id3v2Size = (sizeByte0 shl 21) or (sizeByte1 shl 14) or (sizeByte2 shl 7) or sizeByte3
                startOffset = 10 + id3v2Size
            }

            if (endOffset - startOffset >= 128) {
                val tagIndex = endOffset - 128
                if (bytes[tagIndex] == 0x54.toByte() && bytes[tagIndex + 1] == 0x41.toByte() && bytes[tagIndex + 2] == 0x47.toByte()) {
                    endOffset -= 128
                }
            }

            if (endOffset - startOffset >= 32) {
                val apeIndex = endOffset - 32
                if (bytes[apeIndex] == 0x41.toByte() && bytes[apeIndex + 1] == 0x50.toByte() &&
                    bytes[apeIndex + 2] == 0x45.toByte() && bytes[apeIndex + 3] == 0x54.toByte()
                ) {
                    val tagSize = (bytes[apeIndex + 12].toInt() and 0xFF) or
                            ((bytes[apeIndex + 13].toInt() and 0xFF) shl 8) or
                            ((bytes[apeIndex + 14].toInt() and 0xFF) shl 16) or
                            ((bytes[apeIndex + 15].toInt() and 0xFF) shl 24)
                    if (endOffset - tagSize >= startOffset) {
                        endOffset -= tagSize
                    }
                }
            }

            if (startOffset < endOffset) {
                FileOutputStream(destination).use { fos ->
                    fos.write(bytes, startOffset, endOffset - startOffset)
                }
                true
            } else {
                purgeGenericFile(source, destination)
            }
        } catch (_: Exception) {
            purgeGenericFile(source, destination)
        }
    }

    // ------------------------------------------------------------------------
    // 7. VIDEO & AUDIO (MP4 / MOV / 3GP)
    // ------------------------------------------------------------------------

    private fun purgeMp4Video(source: File, destination: File): Boolean {
        return try {
            source.copyTo(destination, overwrite = true)
            sanitizeMp4Atoms(destination)
            true
        } catch (_: Exception) {
            purgeGenericFile(source, destination)
        }
    }

    private fun sanitizeMp4Atoms(file: File) {
        try {
            RandomAccessFile(file, "rw").use { raf ->
                val length = raf.length()
                sanitizeMp4AtomsRecursive(raf, 0L, length)
            }
        } catch (_: Exception) {}
    }

    private fun sanitizeMp4AtomsRecursive(raf: RandomAccessFile, startPos: Long, endPos: Long) {
        var pos = startPos

        val containerAtoms = setOf(
            "moov", "trak", "edts", "mdia", "minf", "stbl", "mvdra", "udta", "meta", "ilst"
        )

        val metadataAtoms = setOf(
            "XMP_", "uuid",
            "\u00a9nam", "\u00a9ART", "\u00a9alb", "\u00a9day", "\u00a9too",
            "\u00a9cmt", "\u00a9wrt", "\u00a9gen", "\u00a9grp", "\u00a9lyr",
            "\u00a9req", "\u00a9enc", "\u00a9cpy", "\u00a9des", "\u00a9spe",
            "\u00a9cpr", "covr", "gnre", "trkn", "disk", "tmpo", "rtng", "cpil",
            "aART", "soaa", "soal", "soar", "sonm", "soco", "sosn", "catg",
            "keyw", "desc", "egid", "purd", "pcst", "purl", "iTunSMPB", "iTunNORM",
            "loci", "\u00a9xyz"
        )

        while (pos < endPos - 8) {
            raf.seek(pos)

            val atomSize = raf.readInt().toLong() and 0xFFFFFFFFL
            val atomTypeBytes = ByteArray(4)
            if (raf.read(atomTypeBytes) < 4) break
            val atomType = String(atomTypeBytes, Charsets.US_ASCII)

            val actualSize = when (atomSize) {
                1L -> {
                    if (pos + 16 > endPos) break
                    raf.readLong()
                }
                0L -> endPos - pos
                else -> atomSize
            }

            if (actualSize < 8 || pos + actualSize > endPos) break

            val headerSize = if (atomSize == 1L) 16 else 8

            if (metadataAtoms.contains(atomType)) {
                val payloadSize = actualSize - headerSize
                if (payloadSize > 0) {
                    raf.seek(pos + headerSize)
                    val zeroBuffer = ByteArray(minOf(payloadSize, BUFFER_SIZE.toLong()).toInt())
                    var remaining = payloadSize
                    while (remaining > 0) {
                        val writeSize = minOf(remaining, zeroBuffer.size.toLong()).toInt()
                        raf.write(zeroBuffer, 0, writeSize)
                        remaining -= writeSize
                    }
                }
            } else if (atomType == "mvhd" || atomType == "tkhd") {
                val bodyStart = pos + headerSize
                raf.seek(bodyStart)
                val version = raf.readUnsignedByte()
                if (version == 1) {
                    raf.seek(bodyStart + 4)
                    raf.writeLong(0L)
                    raf.writeLong(0L)
                } else if (version == 0) {
                    raf.seek(bodyStart + 4)
                    raf.writeInt(0)
                    raf.writeInt(0)
                }
            } else if (containerAtoms.contains(atomType)) {
                val contentStart = pos + headerSize
                val contentEnd = pos + actualSize
                val adjustedStart = if (atomType == "meta") contentStart + 4 else contentStart
                if (adjustedStart < contentEnd) {
                    sanitizeMp4AtomsRecursive(raf, adjustedStart, contentEnd)
                }
            }

            pos += actualSize
        }
    }

    // ------------------------------------------------------------------------
    // 8. DOCUMENTS (PDF)
    // ------------------------------------------------------------------------

    private fun purgePdfMetadata(source: File, destination: File): Boolean {
        return try {
            val bytes = source.readBytes()
            var text = String(bytes, Charsets.ISO_8859_1)

            val metadataKeys = listOf(
                "/Title", "/Author", "/Subject", "/Keywords",
                "/Creator", "/Producer", "/CreationDate", "/ModDate"
            )
            for (key in metadataKeys) {
                val regex = Regex("$key\\s*\\(([^)]*)\\)")
                text = text.replace(regex) { matchResult: MatchResult ->
                    val contentLength = matchResult.groupValues[1].length
                    "$key (${" ".repeat(contentLength)})"
                }
            }

            val metadataRefRegex = Regex("/Metadata\\s+\\d+\\s+\\d+\\s+R")
            text = text.replace(metadataRefRegex) { matchResult: MatchResult ->
                " ".repeat(matchResult.value.length)
            }

            val xmpRegex = Regex("<\\?xpacket begin[\\s\\S]*?<\\?xpacket end[^>]*\\?>", RegexOption.IGNORE_CASE)
            text = text.replace(xmpRegex) { matchResult: MatchResult ->
                " ".repeat(matchResult.value.length)
            }

            FileOutputStream(destination).use { it.write(text.toByteArray(Charsets.ISO_8859_1)) }
            true
        } catch (_: Exception) {
            purgeGenericFile(source, destination)
        }
    }

    // ------------------------------------------------------------------------
    // 9. HELPER METHODS & FALLBACKS
    // ------------------------------------------------------------------------

    private fun stripExifAttributes(file: File) {
        try {
            val exif = ExifInterface(file.absolutePath)
            val attributes = listOf(
                ExifInterface.TAG_DATETIME,
                ExifInterface.TAG_DATETIME_DIGITIZED,
                ExifInterface.TAG_DATETIME_ORIGINAL,
                ExifInterface.TAG_GPS_ALTITUDE,
                ExifInterface.TAG_GPS_ALTITUDE_REF,
                ExifInterface.TAG_GPS_DATESTAMP,
                ExifInterface.TAG_GPS_LATITUDE,
                ExifInterface.TAG_GPS_LATITUDE_REF,
                ExifInterface.TAG_GPS_LONGITUDE,
                ExifInterface.TAG_GPS_LONGITUDE_REF,
                ExifInterface.TAG_GPS_PROCESSING_METHOD,
                ExifInterface.TAG_GPS_TIMESTAMP,
                ExifInterface.TAG_MAKE,
                ExifInterface.TAG_MODEL,
                ExifInterface.TAG_SUBSEC_TIME,
                ExifInterface.TAG_SUBSEC_TIME_DIGITIZED,
                ExifInterface.TAG_SUBSEC_TIME_ORIGINAL,
                ExifInterface.TAG_IMAGE_DESCRIPTION,
                ExifInterface.TAG_USER_COMMENT,
                ExifInterface.TAG_ARTIST,
                ExifInterface.TAG_COPYRIGHT,
                ExifInterface.TAG_SOFTWARE,
                ExifInterface.TAG_DEVICE_SETTING_DESCRIPTION,
                ExifInterface.TAG_MAKER_NOTE,
                ExifInterface.TAG_CAMERA_OWNER_NAME,
                ExifInterface.TAG_BODY_SERIAL_NUMBER,
                ExifInterface.TAG_LENS_MAKE,
                ExifInterface.TAG_LENS_MODEL,
                ExifInterface.TAG_LENS_SERIAL_NUMBER,
                ExifInterface.TAG_LENS_SPECIFICATION,
                ExifInterface.TAG_GPS_SPEED,
                ExifInterface.TAG_GPS_SPEED_REF,
                ExifInterface.TAG_GPS_IMG_DIRECTION,
                ExifInterface.TAG_GPS_DEST_BEARING,
                ExifInterface.TAG_THUMBNAIL_IMAGE_LENGTH,
                ExifInterface.TAG_THUMBNAIL_IMAGE_WIDTH
            )

            for (attr in attributes) {
                exif.setAttribute(attr, null)
            }
            exif.saveAttributes()
        } catch (_: Exception) {}
    }

    private fun stripJpegAppSegmentsAndComments(file: File) {
        try {
            val bytes = file.readBytes()
            if (bytes.size < 4 || bytes[0] != 0xFF.toByte() || bytes[1] != 0xD8.toByte()) return

            val baos = ByteArrayOutputStream(bytes.size)
            baos.write(0xFF)
            baos.write(0xD8)

            var i = 2
            while (i < bytes.size - 1) {
                if (bytes[i] == 0xFF.toByte()) {
                    val marker = bytes[i + 1].toInt() and 0xFF

                    if (marker == 0xDA || marker == 0xD9) {
                        baos.write(bytes, i, bytes.size - i)
                        break
                    }

                    if (marker in 0xE0..0xEF || marker == 0xFE) {
                        if (i + 3 < bytes.size) {
                            val len = ((bytes[i + 2].toInt() and 0xFF) shl 8) or (bytes[i + 3].toInt() and 0xFF)
                            i += 2 + len
                            continue
                        }
                    }
                }
                baos.write(bytes[i].toInt())
                i++
            }

            FileOutputStream(file).use { it.write(baos.toByteArray()) }
        } catch (_: Exception) {}
    }

    private fun purgeGenericFile(source: File, destination: File): Boolean {
        return try {
            source.copyTo(destination, overwrite = true)
            stripExifAttributes(destination)
            true
        } catch (_: Exception) {
            false
        }
    }
}