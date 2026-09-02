package com.example.lock.crypto

import android.util.Log
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.security.SecureRandom
import java.util.concurrent.CancellationException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class LightEncryptionManager {

    data class ProgressSnapshot(
        val percent: Int,
        val currentBytes: Long,
        val totalBytes: Long
    )

    companion object {
        private const val TAG: String = "LightEncryptionManager"

        private val FILE_MAGIC: ByteArray = byteArrayOf(0x45, 0x5A, 0x59, 0x53, 0x5F, 0x45, 0x5A, 0x59)
        private const val MAGIC_SIZE: Int = 8
        private const val SALT_SIZE: Int = 16
        private const val BASE_NONCE_SIZE: Int = 12
        private const val HEADER_HASH_SIZE: Int = 32
        private const val METADATA_BLOCK_SIZE: Int = 512
        private const val KEY_SIZE_BITS: Int = 256
        private const val PBKDF2_ITERATIONS: Int = 10000
        private const val GCM_TAG_LENGTH_BITS: Int = 128
        private const val GCM_TAG_LENGTH_BYTES: Int = 16

        private const val CHUNK_DATA_SIZE: Int = 1024 * 1024
        private const val CHUNK_TOTAL_SIZE: Int = CHUNK_DATA_SIZE + GCM_TAG_LENGTH_BYTES
        private const val BUFFER_SIZE: Int = 256 * 1024

        private const val ERROR_INVALID_HEADER: String = "Invalid or corrupted file header."
        private const val ERROR_DECRYPTION_FAILED: String = "Decryption failed. Incorrect password or tampered data."
        private const val ALGORITHM_PBKDF2: String = "PBKDF2WithHmacSHA256"
        private const val ALGORITHM_AES: String = "AES"
        private const val TRANSFORMATION_AES_GCM: String = "AES/GCM/NoPadding"
    }

    fun encryptFile(
        inputFile: File,
        outputDirectory: File,
        password: CharArray,
        isCancelled: () -> Boolean = { false },
        onProgress: ((ProgressSnapshot) -> Unit)? = null
    ): File {
        Log.d(TAG, "Starting encryption for file: ${inputFile.absolutePath}")

        if (!inputFile.exists() || !inputFile.isFile) {
            Log.e(TAG, "Encryption failed: Input file does not exist.")
            throw IllegalArgumentException("Input file does not exist.")
        }
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs()
        }

        val outputFile = File(outputDirectory, EngineType.generateFileName(EngineType.EASY))
        val metadata = inputFile.name.toByteArray(Charsets.UTF_8)

        try {
            BufferedInputStream(FileInputStream(inputFile), BUFFER_SIZE).use { inputStream ->
                BufferedOutputStream(FileOutputStream(outputFile), BUFFER_SIZE).use { outputStream ->
                    if (isCancelled()) throw CancellationException("Operation cancelled by user.")

                    val random = SecureRandom()
                    val salt = ByteArray(SALT_SIZE).also { random.nextBytes(it) }
                    val baseNonce = ByteArray(BASE_NONCE_SIZE).also { random.nextBytes(it) }

                    Log.d(TAG, "Generating derived key using PBKDF2...")
                    val derivedKey = deriveKey(password, salt)
                    val headerHash = computeHeaderHash(salt, baseNonce)

                    if (isCancelled()) throw CancellationException("Operation cancelled by user.")

                    outputStream.write(FILE_MAGIC)
                    outputStream.write(salt)
                    outputStream.write(baseNonce)
                    outputStream.write(headerHash)
                    Log.d(TAG, "Header written successfully.")

                    val paddedMetadata = ByteArray(METADATA_BLOCK_SIZE)
                    val copyLength = metadata.size.coerceAtMost(METADATA_BLOCK_SIZE)
                    System.arraycopy(metadata, 0, paddedMetadata, 0, copyLength)

                    val cipher = Cipher.getInstance(TRANSFORMATION_AES_GCM)
                    val keySpec = SecretKeySpec(derivedKey, ALGORITHM_AES)

                    val encryptedMetadata = encryptChunk(cipher, keySpec, baseNonce, 0L, 'M'.code.toByte(), paddedMetadata, METADATA_BLOCK_SIZE, headerHash)
                    outputStream.write(encryptedMetadata)
                    Log.d(TAG, "Metadata chunk encrypted and written.")

                    val totalBytes = inputFile.length()
                    val buffer = ByteArray(CHUNK_DATA_SIZE)
                    var chunkIndex = 1L
                    var bytesRead: Int
                    var processedBytes: Long = 0

                    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                        if (isCancelled()) {
                            throw CancellationException("Operation cancelled by user.")
                        }

                        val encryptedChunk = encryptChunk(cipher, keySpec, baseNonce, chunkIndex, 'D'.code.toByte(), buffer, bytesRead, headerHash)
                        outputStream.write(encryptedChunk)
                        processedBytes += bytesRead
                        val percent = if (totalBytes > 0) ((processedBytes * 100) / totalBytes).toInt().coerceIn(0, 100) else 100
                        onProgress?.invoke(ProgressSnapshot(percent, processedBytes, totalBytes))
                        chunkIndex++
                    }
                    Log.d(TAG, "Encryption completed successfully. Output file: ${outputFile.absolutePath}, Total chunks: ${chunkIndex - 1}")
                }
            }
        } catch (e: Exception) {
            if (outputFile.exists()) {
                outputFile.delete()
                Log.w(TAG, "Encryption cancelled or failed. Partial output file deleted.")
            }
            throw e
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
        Log.d(TAG, "Starting decryption for file: ${inputFile.absolutePath}")

        if (!inputFile.exists() || !inputFile.isFile) {
            Log.e(TAG, "Decryption error: Input file does not exist.")
            throw IllegalArgumentException("Input file does not exist.")
        }
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs()
        }

        var outputFile: File? = null

        try {
            BufferedInputStream(FileInputStream(inputFile), BUFFER_SIZE).use { inputStream ->
                if (isCancelled()) throw CancellationException("Operation cancelled by user.")

                val magicBuffer = ByteArray(MAGIC_SIZE)
                val magicBytesRead = readFully(inputStream, magicBuffer, MAGIC_SIZE)

                if (magicBytesRead != MAGIC_SIZE || !magicBuffer.contentEquals(FILE_MAGIC)) {
                    Log.e(TAG, "Decryption error: Invalid magic header.")
                    throw IllegalArgumentException(ERROR_INVALID_HEADER)
                }
                Log.d(TAG, "Magic header verified successfully.")

                val salt = ByteArray(SALT_SIZE)
                readFully(inputStream, salt, SALT_SIZE)

                val baseNonce = ByteArray(BASE_NONCE_SIZE)
                readFully(inputStream, baseNonce, BASE_NONCE_SIZE)

                val headerHash = ByteArray(HEADER_HASH_SIZE)
                readFully(inputStream, headerHash, HEADER_HASH_SIZE)

                Log.d(TAG, "Header components extracted. Deriving key...")
                val derivedKey = deriveKey(password, salt)

                val encryptedMetaSizeBytes = METADATA_BLOCK_SIZE + GCM_TAG_LENGTH_BYTES
                val encryptedMetaChunk = ByteArray(encryptedMetaSizeBytes)
                val metaBytesRead = readFully(inputStream, encryptedMetaChunk, encryptedMetaSizeBytes)

                if (metaBytesRead != encryptedMetaSizeBytes) {
                    Log.e(TAG, "Decryption error: Metadata chunk size mismatch.")
                    throw IllegalArgumentException(ERROR_INVALID_HEADER)
                }

                val cipher = Cipher.getInstance(TRANSFORMATION_AES_GCM)
                val keySpec = SecretKeySpec(derivedKey, ALGORITHM_AES)

                Log.d(TAG, "Decrypting metadata chunk...")
                val metadata = decryptChunk(cipher, keySpec, baseNonce, 0L, 'M'.code.toByte(), encryptedMetaChunk, headerHash)
                val originalName = extractOriginalFileName(metadata) ?: inputFile.nameWithoutExtension
                Log.d(TAG, "Metadata decrypted. Extracted original filename: $originalName")

                outputFile = File(outputDirectory, originalName)

                BufferedOutputStream(FileOutputStream(outputFile!!), BUFFER_SIZE).use { outputStream ->
                    val totalBytes = inputFile.length()
                    val chunkBuffer = ByteArray(CHUNK_TOTAL_SIZE)
                    var chunkIndex = 1L
                    var bytesRead: Int

                    while (readFully(inputStream, chunkBuffer, CHUNK_TOTAL_SIZE).also { bytesRead = it } > 0) {
                        if (isCancelled()) {
                            throw CancellationException("Operation cancelled by user.")
                        }

                        val rawEncrypted = if (bytesRead == CHUNK_TOTAL_SIZE) chunkBuffer else chunkBuffer.copyOf(bytesRead)

                        Log.v(TAG, "Decrypting data chunk #$chunkIndex with size ${rawEncrypted.size} bytes...")
                        val decryptedChunk = decryptChunk(cipher, keySpec, baseNonce, chunkIndex, 'D'.code.toByte(), rawEncrypted, headerHash)

                        outputStream.write(decryptedChunk)

                        val currentStreamPos = processedBytesTracker(chunkIndex, CHUNK_TOTAL_SIZE, totalBytes)
                        val percent = if (totalBytes > 0) ((chunkIndex * CHUNK_TOTAL_SIZE * 100) / totalBytes).toInt().coerceIn(0, 100) else 100
                        onProgress?.invoke(ProgressSnapshot(percent.coerceAtMost(100), currentStreamPos, totalBytes))

                        chunkIndex++
                    }
                }
                Log.d(TAG, "Decryption completed successfully. Output path: ${outputFile!!.absolutePath}")
                return outputFile!!
            }
        } catch (e: Exception) {
            if (outputFile != null && outputFile!!.exists()) {
                outputFile!!.delete()
                Log.w(TAG, "Decryption cancelled or failed. Partial output file deleted.")
            }
            throw e
        }
    }

    private fun processedBytesTracker(chunkIndex: Long, chunkSize: Int, totalBytes: Long): Long {
        val calculated = chunkIndex * chunkSize
        return if (calculated > totalBytes) totalBytes else calculated
    }

    private fun extractOriginalFileName(metadata: ByteArray): String? {
        return try {
            val nullIndex = metadata.indexOf(0.toByte())
            val length = if (nullIndex >= 0) nullIndex else metadata.size
            if (length > 0) String(metadata, 0, length, Charsets.UTF_8).trim() else null
        } catch (e: Exception) {
            Log.w(TAG, "Failed to extract original file name from metadata: ${e.message}")
            null
        }
    }

    private fun encryptChunk(
        cipher: Cipher,
        keySpec: SecretKeySpec,
        baseNonce: ByteArray,
        chunkIndex: Long,
        chunkType: Byte,
        data: ByteArray,
        length: Int,
        aad: ByteArray
    ): ByteArray {
        val nonce = deriveChunkNonce(baseNonce, chunkIndex, chunkType)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce)

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(aad)
        return cipher.doFinal(data, 0, length)
    }

    private fun decryptChunk(
        cipher: Cipher,
        keySpec: SecretKeySpec,
        baseNonce: ByteArray,
        chunkIndex: Long,
        chunkType: Byte,
        encryptedData: ByteArray,
        aad: ByteArray
    ): ByteArray {
        try {
            val nonce = deriveChunkNonce(baseNonce, chunkIndex, chunkType)
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce)

            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(aad)
            return cipher.doFinal(encryptedData)
        } catch (e: Exception) {
            Log.e(TAG, "Crypto Exception on Chunk #$chunkIndex. Error: ${e.javaClass.simpleName} - ${e.message}", e)
            throw SecurityException(ERROR_DECRYPTION_FAILED, e)
        }
    }

    private fun deriveChunkNonce(baseNonce: ByteArray, chunkIndex: Long, chunkType: Byte): ByteArray {
        val nonce = baseNonce.clone()
        val indexBytes = java.nio.ByteBuffer.allocate(8).putLong(chunkIndex).array()
        for (i in 0 until 8) {
            nonce[i] = (nonce[i].toInt() xor indexBytes[i].toInt()).toByte()
        }
        nonce[8] = (nonce[8].toInt() xor chunkType.toInt()).toByte()
        return nonce
    }

    private fun deriveKey(password: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_SIZE_BITS)
        val factory = SecretKeyFactory.getInstance(ALGORITHM_PBKDF2)
        return factory.generateSecret(spec).encoded
    }

    private fun computeHeaderHash(salt: ByteArray, baseNonce: ByteArray): ByteArray {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
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
}