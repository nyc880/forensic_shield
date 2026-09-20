package com.example.lock.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.KeyParameter
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.concurrent.CancellationException

class LightEncryptionManager {

    data class ProgressSnapshot(
        val percent: Int,
        val currentBytes: Long,
        val totalBytes: Long
    )

    companion object {
        private val FILE_MAGIC: ByteArray = byteArrayOf(0x45, 0x5A, 0x59, 0x53, 0x5F, 0x45, 0x5A, 0x59) // "EZYS_EZY"
        private const val FORMAT_VERSION: Byte = 0x01
        private const val MAGIC_SIZE: Int = 8
        private const val VERSION_SIZE: Int = 1
        private const val SALT_SIZE: Int = 16
        private const val BASE_NONCE_SIZE: Int = 24
        private const val KEY_SIZE_BYTES: Int = 32
        private const val TAG_SIZE_BYTES: Int = 16
        private const val METADATA_BLOCK_SIZE: Int = 512
        private const val METADATA_MAX_NAME_SIZE: Int = METADATA_BLOCK_SIZE - 8 - 2 // 502 بایت برای نام فایل
        private const val HEADER_HASH_SIZE: Int = 32

        private const val ARGON2_TYPE: Int = Argon2Parameters.ARGON2_id
        private const val ARGON2_VERSION: Int = Argon2Parameters.ARGON2_VERSION_13
        private const val ARGON2_MEMORY_KB: Int = 32 * 1024
        private const val ARGON2_ITERATIONS: Int = 2
        private const val ARGON2_PARALLELISM: Int = 1

        private const val CHUNK_DATA_SIZE: Int = 1 * 1024 * 1024
        private const val CHUNK_TOTAL_SIZE: Int = CHUNK_DATA_SIZE + TAG_SIZE_BYTES
        private const val BUFFER_SIZE: Int = 256 * 1024

        private const val ERROR_INVALID_HEADER: String = "Invalid or corrupted file header."
        private const val ERROR_DECRYPTION_FAILED: String = "Decryption failed. Incorrect password or tampered data."
        private const val ERROR_FILE_INCOMPLETE: String = "Decryption failed. Encrypted file is truncated or incomplete."
    }

    fun encryptFile(
        inputFile: File,
        outputDirectory: File,
        password: CharArray,
        isCancelled: () -> Boolean = { false },
        onProgress: ((ProgressSnapshot) -> Unit)? = null
    ): File {
        if (!inputFile.exists() || !inputFile.isFile) {
            throw IllegalArgumentException("Input file does not exist.")
        }
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs()
        }

        val outputFile = File(outputDirectory, EngineType.generateFileName(EngineType.EASY))
        val originalFileSize = inputFile.length()
        val nameBytes = inputFile.name.toByteArray(StandardCharsets.UTF_8)

        if (nameBytes.size > METADATA_MAX_NAME_SIZE) {
            throw IllegalArgumentException("File name exceeds maximum supported size of $METADATA_MAX_NAME_SIZE bytes.")
        }

        var salt: ByteArray? = null
        var baseNonce: ByteArray? = null
        var derivedKey: ByteArray? = null
        var headerHash: ByteArray? = null
        var paddedMetadata: ByteArray? = null
        var encryptedMetadata: ByteArray? = null
        var buffer: ByteArray? = null

        try {
            BufferedInputStream(FileInputStream(inputFile), BUFFER_SIZE).use { inputStream ->
                BufferedOutputStream(FileOutputStream(outputFile), BUFFER_SIZE).use { outputStream ->
                    if (isCancelled()) throw CancellationException("Operation cancelled by user.")

                    val random = SecureRandom()
                    salt = ByteArray(SALT_SIZE).also { random.nextBytes(it) }
                    baseNonce = ByteArray(BASE_NONCE_SIZE).also { random.nextBytes(it) }

                    derivedKey = deriveKey(password, salt!!)
                    headerHash = computeHeaderHash(FORMAT_VERSION, salt!!, baseNonce!!)

                    if (isCancelled()) throw CancellationException("Operation cancelled by user.")

                    outputStream.write(FILE_MAGIC)
                    outputStream.write(byteArrayOf(FORMAT_VERSION))
                    outputStream.write(salt)
                    outputStream.write(baseNonce)
                    outputStream.write(headerHash)

                    paddedMetadata = ByteArray(METADATA_BLOCK_SIZE)
                    val metaBuffer = ByteBuffer.wrap(paddedMetadata!!)
                    metaBuffer.putLong(originalFileSize)
                    metaBuffer.putShort(nameBytes.size.toShort())
                    metaBuffer.put(nameBytes)

                    encryptedMetadata = encryptChunk(derivedKey!!, baseNonce!!, 0L, 'M'.code.toByte(), paddedMetadata!!, METADATA_BLOCK_SIZE, headerHash!!)
                    outputStream.write(encryptedMetadata)

                    buffer = ByteArray(CHUNK_DATA_SIZE)
                    var chunkIndex = 1L
                    var bytesRead: Int
                    var processedBytes: Long = 0

                    while (inputStream.read(buffer!!).also { bytesRead = it } != -1) {
                        if (isCancelled()) throw CancellationException("Operation cancelled by user.")

                        val encryptedChunk = encryptChunk(derivedKey!!, baseNonce!!, chunkIndex, 'D'.code.toByte(), buffer!!, bytesRead, headerHash!!)
                        outputStream.write(encryptedChunk)
                        processedBytes += bytesRead
                        val percent = if (originalFileSize > 0) ((processedBytes * 100) / originalFileSize).toInt().coerceIn(0, 100) else 100
                        onProgress?.invoke(ProgressSnapshot(percent, processedBytes, originalFileSize))
                        chunkIndex++
                    }
                }
            }
        } catch (e: Exception) {
            if (outputFile.exists()) {
                outputFile.delete()
            }
            throw e
        } finally {
            wipe(salt)
            wipe(baseNonce)
            wipe(derivedKey)
            wipe(headerHash)
            wipe(paddedMetadata)
            wipe(encryptedMetadata)
            wipe(buffer)
            wipe(password)
        }
        return outputFile
    }

    fun decryptFile(
        inputFile: File,
        outputDirectory: File,
        password: CharArray,
        isCancelled: () -> Boolean = { false },
        onProgress: ((ProgressSnapshot) -> Unit)? = null
    ): File {
        if (!inputFile.exists() || !inputFile.isFile) {
            throw IllegalArgumentException("Input file does not exist.")
        }
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs()
        }

        var outputFile: File? = null
        var magicBuffer: ByteArray? = null
        var versionBuffer: ByteArray? = null
        var salt: ByteArray? = null
        var baseNonce: ByteArray? = null
        var headerHash: ByteArray? = null
        var derivedKey: ByteArray? = null
        var encryptedMetaChunk: ByteArray? = null
        var metadata: ByteArray? = null
        var chunkBuffer: ByteArray? = null

        try {
            BufferedInputStream(FileInputStream(inputFile), BUFFER_SIZE).use { inputStream ->
                if (isCancelled()) throw CancellationException("Operation cancelled by user.")

                magicBuffer = ByteArray(MAGIC_SIZE)
                val magicBytesRead = readFully(inputStream, magicBuffer!!, MAGIC_SIZE)

                if (magicBytesRead != MAGIC_SIZE || !magicBuffer!!.contentEquals(FILE_MAGIC)) {
                    throw IllegalArgumentException(ERROR_INVALID_HEADER)
                }

                versionBuffer = ByteArray(VERSION_SIZE)
                readFully(inputStream, versionBuffer!!, VERSION_SIZE)
                if (versionBuffer!![0] != FORMAT_VERSION) {
                    throw IllegalArgumentException(ERROR_INVALID_HEADER)
                }

                salt = ByteArray(SALT_SIZE)
                readFully(inputStream, salt!!, SALT_SIZE)

                baseNonce = ByteArray(BASE_NONCE_SIZE)
                readFully(inputStream, baseNonce!!, BASE_NONCE_SIZE)

                headerHash = ByteArray(HEADER_HASH_SIZE)
                readFully(inputStream, headerHash!!, HEADER_HASH_SIZE)

                val expectedHeaderHash = computeHeaderHash(FORMAT_VERSION, salt!!, baseNonce!!)
                if (!MessageDigest.isEqual(headerHash!!, expectedHeaderHash)) {
                    throw IllegalArgumentException(ERROR_INVALID_HEADER)
                }

                derivedKey = deriveKey(password, salt!!)

                val encryptedMetaSizeBytes = METADATA_BLOCK_SIZE + TAG_SIZE_BYTES
                encryptedMetaChunk = ByteArray(encryptedMetaSizeBytes)
                val metaBytesRead = readFully(inputStream, encryptedMetaChunk!!, encryptedMetaSizeBytes)

                if (metaBytesRead != encryptedMetaSizeBytes) {
                    throw IllegalArgumentException(ERROR_INVALID_HEADER)
                }

                metadata = decryptChunk(derivedKey!!, baseNonce!!, 0L, 'M'.code.toByte(), encryptedMetaChunk!!, headerHash!!)

                val metaBuffer = ByteBuffer.wrap(metadata!!)
                val expectedFileSize = metaBuffer.getLong()
                val nameLength = metaBuffer.getShort().toInt() and 0xFFFF

                if (expectedFileSize < 0 || nameLength < 0 || nameLength > METADATA_MAX_NAME_SIZE) {
                    throw IllegalArgumentException(ERROR_INVALID_HEADER)
                }

                val nameBytes = ByteArray(nameLength)
                metaBuffer.get(nameBytes)
                val rawFileName = String(nameBytes, StandardCharsets.UTF_8)

                val sanitizedName = sanitizeFileName(rawFileName)
                outputFile = getUniqueFile(outputDirectory, sanitizedName)

                BufferedOutputStream(FileOutputStream(outputFile!!), BUFFER_SIZE).use { outputStream ->
                    val totalEncryptedBytes = inputFile.length()
                    chunkBuffer = ByteArray(CHUNK_TOTAL_SIZE)
                    var chunkIndex = 1L
                    var bytesRead: Int
                    var totalDecryptedBytes: Long = 0

                    while (readFully(inputStream, chunkBuffer!!, CHUNK_TOTAL_SIZE).also { bytesRead = it } > 0) {
                        if (isCancelled()) throw CancellationException("Operation cancelled by user.")

                        val rawEncrypted = if (bytesRead == CHUNK_TOTAL_SIZE) chunkBuffer!! else chunkBuffer!!.copyOf(bytesRead)

                        val decryptedChunk = decryptChunk(derivedKey!!, baseNonce!!, chunkIndex, 'D'.code.toByte(), rawEncrypted, headerHash!!)

                        outputStream.write(decryptedChunk)
                        totalDecryptedBytes += decryptedChunk.size

                        val percent = if (totalEncryptedBytes > 0) ((inputStream.available() * 100) / totalEncryptedBytes).toInt().coerceIn(0, 100) else 100
                        onProgress?.invoke(ProgressSnapshot(100 - percent, totalDecryptedBytes, expectedFileSize))

                        chunkIndex++
                    }

                    if (totalDecryptedBytes != expectedFileSize) {
                        throw SecurityException(ERROR_FILE_INCOMPLETE)
                    }
                }
                return outputFile!!
            }
        } catch (e: Exception) {
            if (outputFile != null && outputFile!!.exists()) {
                outputFile!!.delete()
            }
            throw e
        } finally {
            wipe(magicBuffer)
            wipe(versionBuffer)
            wipe(salt)
            wipe(baseNonce)
            wipe(headerHash)
            wipe(derivedKey)
            wipe(encryptedMetaChunk)
            wipe(metadata)
            wipe(chunkBuffer)
            wipe(password)
        }
    }

    private fun sanitizeFileName(name: String): String {
        val clean = File(name).name
            .replace(Regex("[\\\\/:*?\"<>|\\x00-\\x1F]"), "_")
            .replace(Regex("\\.+$"), "")
            .trim()
        return if (clean.isEmpty()) "decrypted_file" else clean
    }

    private fun getUniqueFile(targetDir: File, fileName: String): File {
        var file = File(targetDir, fileName)
        if (!file.exists()) return file

        val nameWithoutExt = file.nameWithoutExtension
        val ext = file.extension
        val dotExt = if (ext.isNotEmpty()) ".$ext" else ""

        var count = 1
        while (file.exists()) {
            file = File(targetDir, "$nameWithoutExt ($count)$dotExt")
            count++
        }
        return file
    }

    private fun encryptChunk(
        derivedKey: ByteArray,
        baseNonce: ByteArray,
        chunkIndex: Long,
        chunkType: Byte,
        data: ByteArray,
        length: Int,
        aad: ByteArray
    ): ByteArray {
        var chunkNonce: ByteArray? = null
        var subKey: ByteArray? = null
        try {
            chunkNonce = deriveChunkNonce(baseNonce, chunkIndex, chunkType)

            val nonce16 = chunkNonce.copyOfRange(0, 16)
            subKey = hChaCha20(derivedKey, nonce16)
            wipe(nonce16)

            val subNonce = ByteArray(12)
            System.arraycopy(chunkNonce, 16, subNonce, 4, 8)

            val cipher = ChaCha20Poly1305()
            val params = AEADParameters(KeyParameter(subKey), TAG_SIZE_BYTES * 8, subNonce, aad)
            cipher.init(true, params)

            val out = ByteArray(cipher.getOutputSize(length))
            val len = cipher.processBytes(data, 0, length, out, 0)
            cipher.doFinal(out, len)
            return out
        } finally {
            wipe(chunkNonce)
            wipe(subKey)
        }
    }

    private fun decryptChunk(
        derivedKey: ByteArray,
        baseNonce: ByteArray,
        chunkIndex: Long,
        chunkType: Byte,
        encryptedData: ByteArray,
        aad: ByteArray
    ): ByteArray {
        var chunkNonce: ByteArray? = null
        var subKey: ByteArray? = null
        var out: ByteArray? = null
        try {
            chunkNonce = deriveChunkNonce(baseNonce, chunkIndex, chunkType)

            val nonce16 = chunkNonce.copyOfRange(0, 16)
            subKey = hChaCha20(derivedKey, nonce16)
            wipe(nonce16)

            val subNonce = ByteArray(12)
            System.arraycopy(chunkNonce, 16, subNonce, 4, 8)

            val cipher = ChaCha20Poly1305()
            val params = AEADParameters(KeyParameter(subKey), TAG_SIZE_BYTES * 8, subNonce, aad)
            cipher.init(false, params)

            out = ByteArray(cipher.getOutputSize(encryptedData.size))
            val len = cipher.processBytes(encryptedData, 0, encryptedData.size, out, 0)
            val finalLen = cipher.doFinal(out, len)
            val totalLen = len + finalLen

            if (totalLen < out.size) {
                val trimmed = out.copyOf(totalLen)
                wipe(out)
                return trimmed
            }
            return out
        } catch (e: Exception) {
            wipe(out)
            throw SecurityException(ERROR_DECRYPTION_FAILED, e)
        } finally {
            wipe(chunkNonce)
            wipe(subKey)
        }
    }

    private fun deriveChunkNonce(baseNonce: ByteArray, chunkIndex: Long, chunkType: Byte): ByteArray {
        val nonce = baseNonce.clone()
        val indexBytes = ByteBuffer.allocate(8).putLong(chunkIndex).array()
        for (i in 0 until 8) {
            nonce[i] = (nonce[i].toInt() xor indexBytes[i].toInt()).toByte()
        }
        nonce[8] = (nonce[8].toInt() xor chunkType.toInt()).toByte()
        return nonce
    }

    private fun deriveKey(password: CharArray, salt: ByteArray): ByteArray {
        var passwordBytes: ByteArray? = null
        try {
            passwordBytes = charArrayToByteArray(password)
            val builder = Argon2Parameters.Builder(ARGON2_TYPE)
                .withVersion(ARGON2_VERSION)
                .withMemoryAsKB(ARGON2_MEMORY_KB)
                .withIterations(ARGON2_ITERATIONS)
                .withParallelism(ARGON2_PARALLELISM)
                .withSalt(salt)
                .build()
            val generator = Argon2BytesGenerator()
            generator.init(builder)
            val result = ByteArray(KEY_SIZE_BYTES)
            generator.generateBytes(passwordBytes, result, 0, result.size)
            return result
        } finally {
            wipe(passwordBytes)
        }
    }

    private fun hChaCha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574

        for (i in 0 until 8) {
            state[4 + i] = packLittleEndian32(key, i * 4)
        }
        for (i in 0 until 4) {
            state[12 + i] = packLittleEndian32(nonce16, i * 4)
        }

        for (i in 0 until 10) {
            quarterRound(state, 0, 4, 8, 12)
            quarterRound(state, 1, 5, 9, 13)
            quarterRound(state, 2, 6, 10, 14)
            quarterRound(state, 3, 7, 11, 15)

            quarterRound(state, 0, 5, 10, 15)
            quarterRound(state, 1, 6, 11, 12)
            quarterRound(state, 2, 7, 8, 13)
            quarterRound(state, 3, 4, 9, 14)
        }

        val out = ByteArray(32)
        unpackLittleEndian32(state[0], out, 0)
        unpackLittleEndian32(state[1], out, 4)
        unpackLittleEndian32(state[2], out, 8)
        unpackLittleEndian32(state[3], out, 12)
        unpackLittleEndian32(state[12], out, 16)
        unpackLittleEndian32(state[13], out, 20)
        unpackLittleEndian32(state[14], out, 24)
        unpackLittleEndian32(state[15], out, 28)

        Arrays.fill(state, 0)
        return out
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 16)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 12)
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 8)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 7)
    }

    private fun rotl(v: Int, c: Int): Int = (v shl c) or (v ushr (32 - c))

    private fun packLittleEndian32(src: ByteArray, offset: Int): Int {
        return (src[offset].toInt() and 0xFF) or
                ((src[offset + 1].toInt() and 0xFF) shl 8) or
                ((src[offset + 2].toInt() and 0xFF) shl 16) or
                ((src[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun unpackLittleEndian32(value: Int, dst: ByteArray, offset: Int) {
        dst[offset] = value.toByte()
        dst[offset + 1] = (value ushr 8).toByte()
        dst[offset + 2] = (value ushr 16).toByte()
        dst[offset + 3] = (value ushr 24).toByte()
    }

    private fun charArrayToByteArray(chars: CharArray): ByteArray {
        val charBuffer = CharBuffer.wrap(chars)
        val byteBuffer = StandardCharsets.UTF_8.encode(charBuffer)
        val bytes = ByteArray(byteBuffer.remaining())
        byteBuffer.get(bytes)
        Arrays.fill(byteBuffer.array(), 0.toByte())
        return bytes
    }

    private fun computeHeaderHash(version: Byte, salt: ByteArray, baseNonce: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(version)
        digest.update(salt)
        digest.update(baseNonce)
        return digest.digest()
    }

    private fun readFully(inputStream: InputStream, buffer: ByteArray, length: Int): Int {
        var totalBytesRead = 0
        while (totalBytesRead < length) {
            val bytesRead = inputStream.read(buffer, totalBytesRead, length - totalBytesRead)
            if (bytesRead == -1) break
            totalBytesRead += bytesRead
        }
        return totalBytesRead
    }

    private fun wipe(b: ByteArray?) {
        if (b != null) {
            Arrays.fill(b, 0.toByte())
        }
    }

    private fun wipe(c: CharArray?) {
        if (c != null) {
            Arrays.fill(c, '\u0000')
        }
    }
}