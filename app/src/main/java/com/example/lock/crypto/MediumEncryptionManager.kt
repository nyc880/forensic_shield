package com.example.lock.crypto

import android.os.Build
import androidx.annotation.RequiresApi
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Security
import java.util.Arrays
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@RequiresApi(Build.VERSION_CODES.KITKAT)
object Lock {

    private const val CHUNK_SIZE = 2 * 1024 * 1024
    private const val MAX_CHUNK_MARGIN = 256
    private const val MAX_ALLOWED_CHUNK = CHUNK_SIZE + MAX_CHUNK_MARGIN

    private const val ARGON2_MEMORY_KIB = 64 * 1024
    private const val ARGON2_TIME_COST = 2
    private const val ARGON2_PARALLELISM = 6

    private const val SALT_SIZE = 512
    private const val IV_SIZE = 512
    private const val KEY_SIZE = 32
    private const val NONCE_SIZE = 12
    private const val MAGIC_SIZE = 32
    private const val TAG_SIZE = 16
    private const val META_SIZE = 512
    private const val MAX_NAME_LEN = 253
    private const val HEADER_SIZE = SALT_SIZE + IV_SIZE + MAGIC_SIZE

    private const val PARITY_GROUP = 10
    private const val FILE_TYPE_RAW = 0
    private const val FILE_TYPE_NORMAL = 1

    private const val PARITY_FLAG = 1L shl 63
    private const val BACKUP_FLAG = 1L shl 61

    private val TYPE_M = byteArrayOf('M'.code.toByte())
    private val TYPE_D = byteArrayOf('D'.code.toByte())
    private val TYPE_P = byteArrayOf('P'.code.toByte())
    private val TYPE_B = byteArrayOf('B'.code.toByte())

    private val ALGO_HASH: ByteArray =
        MessageDigest.getInstance("SHA-256").digest(byteArrayOf(0x06) + byteArrayOf(0x06, 0x01))

    private val rng = SecureRandom()

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun encrypt(input: File, outputEnc: File, password1: ByteArray) {
        encryptLayer(input, outputEnc, password1, FILE_TYPE_NORMAL, input.name)
    }

    fun encrypt(input: File, outputEnc: File, password1: ByteArray, password2: ByteArray) {
        require(password2.isNotEmpty()) { "password2 empty - use single-arg encrypt" }
        val tmp = File(outputEnc.parentFile ?: input.parentFile, "tmp_${hex(random(8))}.tmp")
        try {
            encryptLayer(input, tmp, password2, FILE_TYPE_RAW, null)
            encryptLayer(tmp, outputEnc, password1, FILE_TYPE_NORMAL, input.name)
        } finally {
            shred(tmp)
        }
    }

    fun decrypt(inputEnc: File, outputPlain: File, password1: ByteArray) {
        decryptLayer(inputEnc, outputPlain, password1)
    }

    fun decrypt(inputEnc: File, outputPlain: File, password1: ByteArray, password2: ByteArray) {
        require(password2.isNotEmpty()) { "password2 empty - use single-arg decrypt" }
        val tmp = File(outputPlain.parentFile ?: inputEnc.parentFile, "tmp_dec_${hex(random(8))}.tmp")
        try {
            decryptLayer(inputEnc, tmp, password1)
            decryptLayer(tmp, outputPlain, password2)
        } finally {
            shred(tmp)
        }
    }

    fun peekOriginalName(inputEnc: File, password: ByteArray): String? {
        var key: ByteArray? = null
        return try {
            RandomAccessFile(inputEnc, "r").use { raf ->
                val h = readHeader(raf)
                key = deriveKey(password, h.salt)
                if (!ctEq(h.magic, keyedMagic(key!!, h.salt, h.iv))) return null
                val meta = readMeta(raf, key!!, h.baseNonce, h.hash)
                if ((meta[0].toInt() and 0xFF) != FILE_TYPE_NORMAL) return null
                val nl = meta[1].toInt() and 0xFF
                if (nl !in 1..MAX_NAME_LEN) return null
                String(meta, 2, nl, Charsets.UTF_8)
            }
        } catch (_: Exception) {
            null
        } finally {
            wipe(key)
        }
    }

    fun wipe(data: ByteArray?) {
        if (data == null) return
        for (i in data.indices) data[i] = 0
    }

    private fun encryptLayer(
        input: File,
        output: File,
        password: ByteArray,
        fileType: Int,
        originalName: String?
    ) {
        require(input.isFile) { "input missing: $input" }
        val dataLen = input.length()
        val fileSha = FileInputStream(input).use { sha256Stream(it) }

        val salt = random(SALT_SIZE)
        val iv = random(IV_SIZE)
        var key: ByteArray? = null
        try {
            key = deriveKey(password, salt)
            val magic = keyedMagic(key, salt, iv)
            val header = salt + iv + magic
            val headerHash = sha256(header)
            val baseNonce = iv.copyOfRange(0, NONCE_SIZE)

            val totalChunks = if (dataLen > 0) ((dataLen + CHUNK_SIZE - 1) / CHUNK_SIZE).toInt() else 0

            val meta = ByteArray(META_SIZE)
            when (fileType) {
                FILE_TYPE_NORMAL -> {
                    val nb = safeName(originalName!!)
                    meta[0] = FILE_TYPE_NORMAL.toByte()
                    meta[1] = nb.size.toByte()
                    System.arraycopy(nb, 0, meta, 2, nb.size)
                }
                FILE_TYPE_RAW -> meta[0] = FILE_TYPE_RAW.toByte()
                else -> error("bad fileType")
            }
            putU64(meta, 400, dataLen)
            putU32(meta, 408, totalChunks)
            System.arraycopy(fileSha, 0, meta, 412, 32)

            val group = ArrayList<ByteArray>(PARITY_GROUP)
            var ctr = 1L

            try {
                FileOutputStream(output).use { fo ->
                    fo.write(header)
                    fo.write(encChunk(key, baseNonce, 0L, TYPE_M, meta, headerHash))

                    FileInputStream(input).use { fi ->
                        val buf = ByteArray(CHUNK_SIZE)
                        while (true) {
                            val n = fi.read(buf)
                            if (n <= 0) break
                            val chunk = if (n == buf.size) buf.copyOf() else buf.copyOf(n)
                            fo.write(encChunk(key, baseNonce, ctr, TYPE_D, chunk, headerHash))
                            group.add(chunk)
                            if (group.size == PARITY_GROUP) {
                                writeParity(fo, key, baseNonce, headerHash, group, ctr - group.size + 1)
                                group.clear()
                            }
                            ctr++
                        }
                    }
                    if (group.isNotEmpty()) {
                        writeParity(fo, key, baseNonce, headerHash, group, ctr - group.size)
                        group.clear()
                    }
                }
                val backup = encChunk(key, baseNonce, BACKUP_FLAG or 0L, TYPE_B, meta, headerHash)
                FileOutputStream(output, true).use { it.write(backup) }
            } catch (e: Exception) {
                output.delete()
                throw e
            }
        } finally {
            wipe(key)
        }
    }

    private fun writeParity(
        fo: FileOutputStream,
        key: ByteArray,
        baseNonce: ByteArray,
        headerHash: ByteArray,
        group: List<ByteArray>,
        groupStart: Long
    ) {
        val parity = xorParity(group)
        fo.write(encChunk(key, baseNonce, PARITY_FLAG or groupStart, TYPE_P, parity, headerHash))
    }

    private fun decryptLayer(input: File, output: File, password: ByteArray) {
        var key: ByteArray? = null
        try {
            RandomAccessFile(input, "r").use { raf ->
                val h = readHeader(raf)
                key = deriveKey(password, h.salt)
                if (!ctEq(h.magic, keyedMagic(key!!, h.salt, h.iv))) {
                    throw IllegalArgumentException("Authentication failed: bad password or header")
                }
                val meta = readMeta(raf, key!!, h.baseNonce, h.hash)
                val dataLen = getU64(meta, 400)
                val totalChunks = getU32(meta, 408).toLong() and 0xFFFFFFFFL
                val expectedSha = meta.copyOfRange(412, 444)

                var ctr = 1L
                var written = 0L
                val md = MessageDigest.getInstance("SHA-256")

                FileOutputStream(output).use { fo ->
                    while (written < dataLen) {
                        val remChunks = (totalChunks - (ctr - 1L)).toInt()
                        val gsz = minOf(PARITY_GROUP, remChunks)
                        if (gsz <= 0) throw EOFException("truncated payload")
                        val gStart = ctr

                        val raws = ArrayList<ByteArray>(gsz)
                        repeat(gsz) {
                            raws += readChunk(raf) ?: throw EOFException("EOF data")
                        }
                        val rawParity = readChunk(raf)

                        val plains = arrayOfNulls<ByteArray>(gsz)
                        val failed = ArrayList<Int>()
                        for (i in 0 until gsz) {
                            try {
                                plains[i] = decChunk(key!!, h.baseNonce, gStart + i, TYPE_D, raws[i], h.hash)
                            } catch (e: Exception) {
                                if (e is AEADBadTagException || e is javax.crypto.BadPaddingException) {
                                    failed += i
                                    plains[i] = null
                                } else throw e
                            }
                        }

                        if (failed.size == 1 && rawParity != null) {
                            val fi = failed[0]
                            val pPlain = decChunk(key!!, h.baseNonce, PARITY_FLAG or gStart, TYPE_P, rawParity, h.hash)
                            val valid = plains.mapIndexedNotNull { i, c -> if (i != fi) c else null }
                            plains[fi] = xorParity(valid + listOf(pPlain))
                        } else if (failed.isNotEmpty()) {
                            throw IllegalArgumentException("chunk integrity failure: ${failed.size}")
                        }

                        for (pc in plains) {
                            val c = pc!!
                            val wl = minOf(c.size.toLong(), dataLen - written).toInt()
                            fo.write(c, 0, wl)
                            md.update(c, 0, wl)
                            written += wl
                        }
                        ctr += gsz
                    }
                    fo.flush()
                    fo.fd.sync()
                }

                if (!md.digest().contentEquals(expectedSha)) {
                    throw IllegalArgumentException("global hash mismatch")
                }
            }
        } catch (e: Exception) {
            if (output.exists()) shred(output)
            throw e
        } finally {
            wipe(key)
        }
    }

    private fun readMeta(
        raf: RandomAccessFile,
        key: ByteArray,
        baseNonce: ByteArray,
        headerHash: ByteArray
    ): ByteArray {
        val pos = raf.filePointer
        var rawMeta: ByteArray? = null
        try {
            rawMeta = readChunk(raf)
            if (rawMeta != null) {
                return decChunk(key, baseNonce, 0L, TYPE_M, rawMeta, headerHash)
            }
        } catch (e: Exception) {
            if (e !is AEADBadTagException && e !is javax.crypto.BadPaddingException) throw e
        }

        val backupDisk = 4 + META_SIZE + TAG_SIZE
        val fs = raf.length()
        if (fs >= HEADER_SIZE + backupDisk) {
            raf.seek(fs - backupDisk)
            val rawB = readChunk(raf)
            if (rawB != null) {
                try {
                    val meta = decChunk(key, baseNonce, BACKUP_FLAG or 0L, TYPE_B, rawB, headerHash)
                    if (rawMeta != null) raf.seek(pos + rawMeta.size + 4) else raf.seek(pos)
                    return meta
                } catch (_: Exception) {
                }
            }
        }
        throw IllegalArgumentException("Metadata unrecoverable")
    }

    private fun deriveKey(password: ByteArray, salt: ByteArray): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withMemoryAsKB(ARGON2_MEMORY_KIB)
            .withIterations(ARGON2_TIME_COST)
            .withParallelism(ARGON2_PARALLELISM)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        val out = ByteArray(KEY_SIZE)
        gen.generateBytes(password, out)
        return out
    }

    private fun keyedMagic(key: ByteArray, salt: ByteArray, iv: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        mac.update(salt)
        mac.update(iv)
        mac.update(ALGO_HASH)
        return mac.doFinal().copyOf(MAGIC_SIZE)
    }

    /** Same as Python: prefix[4] + ((u64(base[4:12]) + counter) & 0xFFFFFFFFFFFFFFFF) */
    private fun chunkNonce(base: ByteArray, counter: Long): ByteArray {
        val out = ByteArray(12)
        System.arraycopy(base, 0, out, 0, 4)
        val bc = u64be(base, 4)
        u64bePut(out, 4, bc + counter)
        return out
    }

    private fun aad(headerHash: ByteArray, counter: Long, type: ByteArray): ByteArray {
        val a = ByteArray(41)
        System.arraycopy(headerHash, 0, a, 0, 32)
        u64bePut(a, 32, counter)
        a[40] = type[0]
        return a
    }

    private fun u64be(buf: ByteArray, off: Int): Long {
        return ((buf[off].toLong() and 0xFFL) shl 56) or
                ((buf[off + 1].toLong() and 0xFFL) shl 48) or
                ((buf[off + 2].toLong() and 0xFFL) shl 40) or
                ((buf[off + 3].toLong() and 0xFFL) shl 32) or
                ((buf[off + 4].toLong() and 0xFFL) shl 24) or
                ((buf[off + 5].toLong() and 0xFFL) shl 16) or
                ((buf[off + 6].toLong() and 0xFFL) shl 8) or
                (buf[off + 7].toLong() and 0xFFL)
    }

    private fun u64bePut(buf: ByteArray, off: Int, value: Long) {
        buf[off] = (value ushr 56).toByte()
        buf[off + 1] = (value ushr 48).toByte()
        buf[off + 2] = (value ushr 40).toByte()
        buf[off + 3] = (value ushr 32).toByte()
        buf[off + 4] = (value ushr 24).toByte()
        buf[off + 5] = (value ushr 16).toByte()
        buf[off + 6] = (value ushr 8).toByte()
        buf[off + 7] = value.toByte()
    }

    private fun gcmEnc(key: ByteArray, nonce: ByteArray, pt: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
        c.updateAAD(aad)
        return c.doFinal(pt)
    }

    private fun gcmDec(key: ByteArray, nonce: ByteArray, ct: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
        c.updateAAD(aad)
        return c.doFinal(ct)
    }

    private fun encChunk(
        key: ByteArray, base: ByteArray, counter: Long, type: ByteArray,
        pt: ByteArray, headerHash: ByteArray
    ): ByteArray {
        val ct = gcmEnc(key, chunkNonce(base, counter), pt, aad(headerHash, counter, type))
        val out = ByteArray(4 + ct.size)
        ByteBuffer.wrap(out).order(ByteOrder.BIG_ENDIAN).putInt(ct.size)
        System.arraycopy(ct, 0, out, 4, ct.size)
        return out
    }

    private fun decChunk(
        key: ByteArray, base: ByteArray, counter: Long, type: ByteArray,
        raw: ByteArray, headerHash: ByteArray
    ): ByteArray {
        if (raw.size < TAG_SIZE) throw IllegalArgumentException("chunk too short")
        return gcmDec(key, chunkNonce(base, counter), raw, aad(headerHash, counter, type))
    }

    private fun xorParity(chunks: List<ByteArray>): ByteArray {
        if (chunks.isEmpty()) return ByteArray(0)
        val max = chunks.maxOf { it.size }
        val p = ByteArray(max)
        for (c in chunks) for (i in c.indices) p[i] = (p[i].toInt() xor c[i].toInt()).toByte()
        return p
    }

    private class Hdr(
        val salt: ByteArray,
        val iv: ByteArray,
        val magic: ByteArray,
        val hash: ByteArray,
        val baseNonce: ByteArray
    )

    private fun readFully(raf: RandomAccessFile, dest: ByteArray): Boolean {
        var off = 0
        while (off < dest.size) {
            val r = raf.read(dest, off, dest.size - off)
            if (r < 0) return false
            off += r
        }
        return true
    }

    private fun readHeader(raf: RandomAccessFile): Hdr {
        val salt = ByteArray(SALT_SIZE)
        val iv = ByteArray(IV_SIZE)
        val magic = ByteArray(MAGIC_SIZE)
        if (!readFully(raf, salt)) throw IllegalArgumentException("truncated salt")
        if (!readFully(raf, iv)) throw IllegalArgumentException("truncated iv")
        if (!readFully(raf, magic)) throw IllegalArgumentException("truncated magic")
        val full = salt + iv + magic
        return Hdr(salt, iv, magic, sha256(full), iv.copyOfRange(0, NONCE_SIZE))
    }

    private fun readChunk(raf: RandomAccessFile): ByteArray? {
        val lb = ByteArray(4)
        val n = raf.read(lb, 0, 1)
        if (n < 0) return null
        var off = n
        while (off < 4) {
            val r = raf.read(lb, off, 4 - off)
            if (r < 0) throw EOFException("truncated chunk length")
            off += r
        }
        val len = ByteBuffer.wrap(lb).order(ByteOrder.BIG_ENDIAN).int
        if (len < 0 || len > MAX_ALLOWED_CHUNK) throw IllegalArgumentException("bad chunk len $len")
        val p = ByteArray(len)
        if (!readFully(raf, p)) throw EOFException("EOF chunk")
        return p
    }

    private fun shred(f: File) {
        if (!f.exists()) return
        try {
            val len = f.length()
            if (len > 0) {
                RandomAccessFile(f, "rw").use { raf ->
                    repeat(3) {
                        raf.seek(0)
                        var rem = len
                        while (rem > 0) {
                            val n = minOf(1_048_576L, rem).toInt()
                            raf.write(random(n))
                            rem -= n
                        }
                        raf.fd.sync()
                    }
                }
            }
            f.delete()
        } catch (_: Exception) {
            f.delete()
        }
    }

    private fun random(n: Int) = ByteArray(n).also { rng.nextBytes(it) }

    private fun sha256(d: ByteArray) = MessageDigest.getInstance("SHA-256").digest(d)

    private fun sha256Stream(inp: java.io.InputStream): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(CHUNK_SIZE)
        while (true) {
            val n = inp.read(buf)
            if (n < 0) break
            if (n > 0) md.update(buf, 0, n)
        }
        return md.digest()
    }

    private fun ctEq(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var r = 0
        for (i in a.indices) r = r or (a[i].toInt() xor b[i].toInt())
        return r == 0
    }

    private fun safeName(name: String): ByteArray {
        var n = name
        var b = n.toByteArray(Charsets.UTF_8)
        while (b.size > MAX_NAME_LEN) {
            n = n.dropLast(1)
            b = n.toByteArray(Charsets.UTF_8)
        }
        return b
    }

    private fun putU64(buf: ByteArray, off: Int, v: Long) {
        u64bePut(buf, off, v)
    }

    private fun putU32(buf: ByteArray, off: Int, v: Int) {
        ByteBuffer.wrap(buf, off, 4).order(ByteOrder.BIG_ENDIAN).putInt(v)
    }

    private fun getU64(buf: ByteArray, off: Int) = u64be(buf, off)

    private fun getU32(buf: ByteArray, off: Int) =
        ByteBuffer.wrap(buf, off, 4).order(ByteOrder.BIG_ENDIAN).int

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
}


@RequiresApi(Build.VERSION_CODES.KITKAT)
class MediumEncryptionManager {

    data class ProgressSnapshot(val processedBytes: Long, val totalBytes: Long) {
        val percent: Int
            get() = if (totalBytes <= 0L) 0 else ((processedBytes.coerceAtMost(totalBytes) * 100L) / totalBytes).toInt()
    }

    fun encryptFile(
        inputFile: File,
        outputDirectory: File = inputFile.parentFile ?: File("."),
        password: CharArray,
        password2: CharArray? = null,
        onProgress: ((ProgressSnapshot) -> Unit)? = null
    ): File {
        if (!inputFile.exists() || !inputFile.isFile) throw SecurityException("Operation failed")
        if (!outputDirectory.exists() && !outputDirectory.mkdirs()) throw SecurityException("Operation failed")
        val outputFile = uniqueEncryptedFile(outputDirectory)
        var passBytes1: ByteArray? = null
        var passBytes2: ByteArray? = null
        try {
            onProgress?.invoke(ProgressSnapshot(0, inputFile.length()))
            passBytes1 = charArrayToByteArray(password)
            passBytes2 = password2?.let { if (it.isNotEmpty()) charArrayToByteArray(it) else null }

            if (passBytes2 != null) {
                Lock.encrypt(inputFile, outputFile, passBytes1, passBytes2)
            } else {
                Lock.encrypt(inputFile, outputFile, passBytes1)
            }

            onProgress?.invoke(ProgressSnapshot(inputFile.length(), inputFile.length()))
            return outputFile
        } catch (e: Exception) {
            outputFile.delete()
            if (e is SecurityException) throw e
            throw SecurityException("Operation failed", e)
        } finally {
            passBytes1?.let { wipe(it) }
            passBytes2?.let { wipe(it) }
            wipe(password)
            password2?.let { wipe(it) }
        }
    }

    fun decryptFile(
        inputFile: File,
        outputDirectory: File = inputFile.parentFile ?: File("."),
        password: CharArray,
        password2: CharArray? = null,
        onProgress: ((ProgressSnapshot) -> Unit)? = null
    ): File {
        if (!inputFile.exists() || !inputFile.isFile) throw SecurityException("Operation failed")
        if (!outputDirectory.exists() && !outputDirectory.mkdirs()) throw SecurityException("Operation failed")
        val tempFile = File.createTempFile(".med_dec_", ".tmp", outputDirectory)
        var result: File? = null
        var passBytes1: ByteArray? = null
        var passBytes2: ByteArray? = null
        try {
            onProgress?.invoke(ProgressSnapshot(0, inputFile.length()))
            passBytes1 = charArrayToByteArray(password)
            passBytes2 = password2?.let { if (it.isNotEmpty()) charArrayToByteArray(it) else null }

            if (passBytes2 != null) {
                Lock.decrypt(inputFile, tempFile, passBytes1, passBytes2)
            } else {
                Lock.decrypt(inputFile, tempFile, passBytes1)
            }

            val originalName = try {
                Lock.peekOriginalName(inputFile, passBytes1)
            } catch (_: Exception) {
                null
            }

            val finalName = if (!originalName.isNullOrBlank()) originalName else inputFile.nameWithoutExtension
            result = nonConflictingFile(outputDirectory, finalName)
            if (!tempFile.renameTo(result)) {
                tempFile.inputStream().use { i -> result.outputStream().use { o -> i.copyTo(o) } }
                tempFile.delete()
            }
            onProgress?.invoke(ProgressSnapshot(inputFile.length(), inputFile.length()))
            return result
        } catch (e: Exception) {
            tempFile.delete()
            result?.delete()
            if (e is SecurityException) throw e
            throw SecurityException("Operation failed", e)
        } finally {
            passBytes1?.let { wipe(it) }
            passBytes2?.let { wipe(it) }
            wipe(password)
            password2?.let { wipe(it) }
        }
    }

    private fun uniqueEncryptedFile(dir: File): File {
        val alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        val rnd = SecureRandom()
        val sb = StringBuilder(23)
        repeat(23) { sb.append(alphabet[rnd.nextInt(alphabet.length)]) }
        val name = sb.toString() + ".enc"
        val file = File(dir, name)
        return if (!file.exists()) file else uniqueEncryptedFile(dir)
    }

    private fun nonConflictingFile(dir: File, name: String): File {
        val safe = name.replace('\u0000', '_').replace('/', '_').replace('\\', '_').trim()
        if (safe.isEmpty() || safe == "." || safe == "..") throw SecurityException("Operation failed")
        var candidate = File(dir, safe)
        if (!candidate.exists()) return candidate
        val dot = safe.lastIndexOf('.')
        val base = if (dot > 0) safe.substring(0, dot) else safe
        val ext = if (dot > 0) safe.substring(dot) else ""
        for (i in 1..9999) {
            candidate = File(dir, "$base ($i)$ext")
            if (!candidate.exists()) return candidate
        }
        throw SecurityException("Operation failed")
    }

    private fun charArrayToByteArray(chars: CharArray): ByteArray {
        val charBuffer = CharBuffer.wrap(chars)
        val byteBuffer = StandardCharsets.UTF_8.encode(charBuffer)
        val bytes = ByteArray(byteBuffer.remaining())
        byteBuffer.get(bytes)
        if (byteBuffer.hasArray()) {
            Arrays.fill(byteBuffer.array(), 0.toByte())
        }
        return bytes
    }

    private fun wipe(arr: ByteArray) = Arrays.fill(arr, 0.toByte())
    private fun wipe(arr: CharArray) = Arrays.fill(arr, '\u0000')
}
