package com.example.lock.metadata

import java.io.Closeable
import java.io.EOFException
import java.io.File
import java.io.OutputStream
import java.io.RandomAccessFile
import java.security.SecureRandom

class BinaryIo private constructor(private val raf: RandomAccessFile) : Closeable {

    val length: Long get() = raf.length()
    var position: Long
        get() = raf.filePointer
        set(value) {
            if (value < 0 || value > raf.length()) throw EOFException("seek out of range: $value")
            raf.seek(value)
        }

    fun seek(offset: Long) {
        position = offset
    }

    fun skip(count: Long) {
        position = raf.filePointer + count
    }

    fun inRange(offset: Long, size: Long): Boolean = offset >= 0 && size >= 0 && offset + size <= raf.length()

    fun readFully(target: ByteArray, offset: Int = 0, size: Int = target.size - offset): Boolean {
        if (size <= 0) return true
        if (!inRange(raf.filePointer, size.toLong())) return false
        var read = 0
        while (read < size) {
            val n = raf.read(target, offset + read, size - read)
            if (n <= 0) return false
            read += n
        }
        return true
    }

    fun readBytes(size: Int): ByteArray {
        val out = ByteArray(size)
        if (!readFully(out)) throw EOFException("truncated file at $position, wanted $size bytes")
        return out
    }

    fun readBytesOrNull(size: Int): ByteArray? {
        if (size <= 0 || !inRange(raf.filePointer, size.toLong())) return null
        val out = ByteArray(size)
        return if (readFully(out)) out else null
    }

    fun u8(): Int {
        if (position + 1 > length) throw EOFException("u8 at end of file")
        return raf.readUnsignedByte()
    }

    fun u8OrNull(): Int? = if (position + 1 > length) null else raf.readUnsignedByte()

    fun u16be(): Int = (u8() shl 8) or u8()
    fun u16le(): Int = u8() or (u8() shl 8)

    fun u24be(): Int = (u8() shl 16) or (u8() shl 8) or u8()
    fun u24le(): Int = u8() or (u8() shl 8) or (u8() shl 16)

    fun u32be(): Long = (u16be().toLong() shl 16) or u16be().toLong()
    fun u32le(): Long = u16le().toLong() or (u16le().toLong() shl 16)

    fun i32be(): Int = (u16be() shl 16) or u16be()
    fun u64be(): Long = (u32be() shl 32) or u32be()
    fun u64le(): Long = u32le() or (u32le() shl 32)

    fun ascii(size: Int): String = String(readBytes(size), Charsets.US_ASCII)

    /**
     * Reads [size] bytes at [offset] into a caller owned buffer. Packet loops read the same number
     * of bytes millions of times, and allocating a fresh array for each one turns a large stream
     * into a garbage collection storm.
     */
    fun peekInto(offset: Long, target: ByteArray, size: Int = target.size): Boolean {
        if (!inRange(offset, size.toLong())) return false
        val saved = position
        return try {
            position = offset
            readFully(target, 0, size)
        } catch (_: Exception) {
            false
        } finally {
            if (saved <= length) raf.seek(saved)
        }
    }

    fun peekAt(offset: Long, size: Int): ByteArray? {
        if (!inRange(offset, size.toLong())) return null
        val saved = position
        return try {
            position = offset
            readBytes(size)
        } catch (_: Exception) {
            null
        } finally {
            if (saved <= length) raf.seek(saved)
        }
    }

    fun matchesAt(offset: Long, ascii: String): Boolean {
        val expected = ascii.toByteArray(Charsets.US_ASCII)
        val actual = peekAt(offset, expected.size) ?: return false
        return actual.contentEquals(expected)
    }

    fun readAsciiAt(offset: Long, size: Int): String? = peekAt(offset, size)?.let { String(it, Charsets.US_ASCII) }

    fun copyRange(offset: Long, size: Long, out: OutputStream, buffer: ByteArray): Long {
        if (size <= 0) return 0L
        if (!inRange(offset, size)) throw EOFException("range [$offset,+$size) outside file of $length bytes")
        val saved = position
        position = offset
        var remaining = size
        var copied = 0L
        while (remaining > 0) {
            val chunk = minOf(remaining, buffer.size.toLong()).toInt()
            if (!readFully(buffer, 0, chunk)) throw EOFException("truncated copy at $position")
            out.write(buffer, 0, chunk)
            remaining -= chunk
            copied += chunk
        }
        raf.seek(saved)
        return copied
    }

    fun writeAt(offset: Long, data: ByteArray, dataOffset: Int = 0, dataSize: Int = data.size) {
        raf.seek(offset)
        raf.write(data, dataOffset, dataSize)
    }

    fun writeZeros(offset: Long, count: Long, buffer: ByteArray = ByteArray(DEFAULT_BUFFER)) {
        if (count <= 0) return
        raf.seek(offset)
        var remaining = count
        while (remaining > 0) {
            val chunk = minOf(remaining, buffer.size.toLong()).toInt()
            for (i in 0 until chunk) buffer[i] = 0
            raf.write(buffer, 0, chunk)
            remaining -= chunk
        }
    }

    fun setLength(newLength: Long) {
        raf.setLength(newLength)
    }

    fun fsync() {
        try {
            raf.fd.sync()
        } catch (_: Exception) {
        }
    }

    override fun close() {
        try {
            raf.close()
        } catch (_: Exception) {
        }
    }

    companion object {
        const val DEFAULT_BUFFER = 64 * 1024

        fun open(file: File): BinaryIo = BinaryIo(RandomAccessFile(file, "r"))

        fun openReadWrite(file: File): BinaryIo = BinaryIo(RandomAccessFile(file, "rw"))
    }
}

object Bytes {
    fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xFF
    fun u16be(b: ByteArray, i: Int): Int = (u8(b, i) shl 8) or u8(b, i + 1)
    fun u16le(b: ByteArray, i: Int): Int = u8(b, i) or (u8(b, i + 1) shl 8)
    fun u32be(b: ByteArray, i: Int): Long = (u16be(b, i).toLong() shl 16) or u16be(b, i + 2).toLong()
    fun u32le(b: ByteArray, i: Int): Long = u16le(b, i).toLong() or (u16le(b, i + 2).toLong() shl 16)
    fun u64le(b: ByteArray, i: Int): Long = u32le(b, i) or (u32le(b, i + 4) shl 32)

    fun putU16be(b: ByteArray, i: Int, v: Int) {
        b[i] = ((v ushr 8) and 0xFF).toByte()
        b[i + 1] = (v and 0xFF).toByte()
    }

    fun putU16le(b: ByteArray, i: Int, v: Int) {
        b[i] = (v and 0xFF).toByte()
        b[i + 1] = ((v ushr 8) and 0xFF).toByte()
    }

    fun putU32be(b: ByteArray, i: Int, v: Long) {
        b[i] = ((v ushr 24) and 0xFF).toByte()
        b[i + 1] = ((v ushr 16) and 0xFF).toByte()
        b[i + 2] = ((v ushr 8) and 0xFF).toByte()
        b[i + 3] = (v and 0xFF).toByte()
    }

    fun putU32le(b: ByteArray, i: Int, v: Long) {
        b[i] = (v and 0xFF).toByte()
        b[i + 1] = ((v ushr 8) and 0xFF).toByte()
        b[i + 2] = ((v ushr 16) and 0xFF).toByte()
        b[i + 3] = ((v ushr 24) and 0xFF).toByte()
    }

    fun putU64le(b: ByteArray, i: Int, v: Long) {
        putU32le(b, i, v and 0xFFFFFFFFL)
        putU32le(b, i + 4, (v ushr 32) and 0xFFFFFFFFL)
    }

    fun u64leBytes(v: Long): ByteArray {
        val out = ByteArray(8)
        putU64le(out, 0, v)
        return out
    }

    fun u32beToBytes(v: Long): ByteArray {
        val out = ByteArray(4)
        putU32be(out, 0, v)
        return out
    }

    fun u32leToBytes(v: Long): ByteArray {
        val out = ByteArray(4)
        putU32le(out, 0, v)
        return out
    }

    fun asciiAt(b: ByteArray, i: Int, len: Int): String = String(b, i, len, Charsets.US_ASCII)

    fun indexOf(haystack: ByteArray, needle: ByteArray, from: Int = 0): Int {
        if (needle.isEmpty() || haystack.isEmpty()) return -1
        val first = needle[0]
        var i = maxOf(0, from)
        val limit = haystack.size - needle.size
        while (i <= limit) {
            if (haystack[i] == first) {
                var j = 1
                while (j < needle.size && haystack[i + j] == needle[j]) j++
                if (j == needle.size) return i
            }
            i++
        }
        return -1
    }

    fun trimAscii(b: ByteArray, start: Int, end: Int): String {
        val text = String(b, start, maxOf(0, end - start), Charsets.ISO_8859_1)
        return text.trim { it == '\u0000' || it <= ' ' }
    }
}

object SecureDelete {

    private const val CHUNK = 128 * 1024

    /**
     * Overwrites [file] and then deletes it. Returns true only when the contents really were
     * overwritten and flushed and the directory entry is gone. Note that on flash storage with
     * wear levelling an overwrite is not a guarantee about the physical blocks; nothing a file
     * level tool can do changes that.
     */
    /**
     * Overwrites [file] and then deletes it. Returns true only when the contents really were
     * overwritten and flushed and the directory entry is gone. Note that on flash storage with
     * wear levelling an overwrite is not a guarantee about the physical blocks; nothing a file
     * level tool can do changes that.
     */
    fun wipeFile(file: File, passes: Int = 1, onBytes: ((Long) -> Unit)? = null): Boolean {
        if (!file.exists()) return true
        if (file.isDirectory) return wipeDirectory(file, onBytes)
        val length = file.length()
        if (length == 0L) return delete(file)
        if (!file.canWrite()) return false

        val random = SecureRandom()
        var flushed: Boolean
        try {
            RandomAccessFile(file, "rw").use { raf ->
                val size = raf.length()
                val buffer = ByteArray(CHUNK)
                val effectivePasses = passes.coerceIn(1, 7)
                for (pass in 0 until effectivePasses) {
                    raf.seek(0)
                    var remaining = size
                    var written = 0L
                    while (remaining > 0) {
                        val chunk = minOf(remaining, CHUNK.toLong()).toInt()
                        if (pass == effectivePasses - 1) java.util.Arrays.fill(buffer, 0, chunk, 0.toByte())
                        else random.nextBytes(buffer)
                        raf.write(buffer, 0, chunk)
                        remaining -= chunk
                        written += chunk
                        onBytes?.invoke(written)
                    }
                }
                raf.setLength(0)
                try {
                    raf.fd.sync()
                    flushed = true
                } catch (_: Exception) {
                    // Without a flush the overwrite may never reach the medium.
                    flushed = false
                }
            }
        } catch (_: Exception) {
            return false
        }
        return flushed && delete(file)
    }

    private fun delete(file: File): Boolean = try {
        file.delete() || !file.exists()
    } catch (_: Exception) {
        false
    }

    fun wipeDirectory(directory: File, onBytes: ((Long) -> Unit)? = null): Boolean {
        if (!directory.exists()) return true
        var success = true
        directory.listFiles()?.forEach { child ->
            success = if (child.isDirectory) wipeDirectory(child, onBytes) else wipeFile(child, 1, onBytes) && success
        }
        return try {
            directory.delete() && success
        } catch (_: Exception) {
            false
        }
    }

    fun wipeQuietly(file: File?, passes: Int = 1): Boolean {
        if (file == null || !file.exists()) return true
        return try {
            wipeFile(file, passes)
        } catch (_: Exception) {
            false
        }
    }
}
