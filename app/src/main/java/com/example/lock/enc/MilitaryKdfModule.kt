package com.example.lock.enc

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object KdfConfig {

    const val MEMORY_MB = 64

    const val ITERATIONS = 3

    const val PARALLELISM = 4

    const val MAX_MEMORY_KB = 1024 * 1024

    const val MAX_ITERATIONS = 20

    const val MAX_PARALLELISM = 16

    const val HEAP_SAFETY_DIVISOR = 2
}

data class KdfParams(
    val kdfId: Byte = KDF_ARGON2ID_V13,
    val memoryCostKb: Int,
    val iterations: Int,
    val parallelism: Int
) {

    companion object {

        const val KDF_ARGON2ID_V13: Byte = 0x01

        const val ENCODED_SIZE_BYTES = 13

        val DEFAULT = KdfParams(
            kdfId = KDF_ARGON2ID_V13,
            memoryCostKb = KdfConfig.MEMORY_MB * 1024,
            iterations = KdfConfig.ITERATIONS,
            parallelism = KdfConfig.PARALLELISM
        )

        const val MIN_ITERATIONS = 1
        const val MAX_ITERATIONS = KdfConfig.MAX_ITERATIONS

        const val MIN_PARALLELISM = 1
        const val MAX_PARALLELISM = KdfConfig.MAX_PARALLELISM

        const val MAX_MEMORY_KB = KdfConfig.MAX_MEMORY_KB

        fun fromByteArray(bytes: ByteArray, offset: Int = 0): KdfParams {
            if (bytes.size < offset + ENCODED_SIZE_BYTES) {
                throw SecurityException("KDF parameter block is truncated.")
            }
            val buffer = ByteBuffer.wrap(bytes, offset, ENCODED_SIZE_BYTES)
            val params = KdfParams(
                kdfId = buffer.get(),
                memoryCostKb = buffer.int,
                iterations = buffer.int,
                parallelism = buffer.int
            )
            params.validate()
            return params
        }
    }

    fun toByteArray(): ByteArray {
        validate()
        return ByteBuffer.allocate(ENCODED_SIZE_BYTES)
            .put(kdfId)
            .putInt(memoryCostKb)
            .putInt(iterations)
            .putInt(parallelism)
            .array()
    }

    fun validate() {
        if (kdfId != KDF_ARGON2ID_V13) {
            throw SecurityException("Unsupported KDF algorithm id.")
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw SecurityException("KDF iteration count out of bounds.")
        }
        if (parallelism < MIN_PARALLELISM || parallelism > MAX_PARALLELISM) {
            throw SecurityException("KDF parallelism out of bounds.")
        }
        if (memoryCostKb < 8 * parallelism || memoryCostKb > MAX_MEMORY_KB) {
            throw SecurityException("KDF memory cost out of bounds.")
        }
    }
}

class CascadedKeyContainer(
    val xChaCha20Key: LockedSecret,
    val aes256Key: LockedSecret,
    val chainMacKey: LockedSecret,
    val salt: ByteArray,
    val params: KdfParams
) : AutoCloseable {

    @Volatile
    var isWiped: Boolean = false
        private set

    @Synchronized
    fun wipe(): Boolean {
        if (isWiped) return true
        var allFreed = xChaCha20Key.wipe()
        allFreed = aes256Key.wipe() && allFreed
        allFreed = chainMacKey.wipe() && allFreed
        Arrays.fill(salt, 0.toByte())
        isWiped = true
        return allFreed
    }

    @Throws(SecurityException::class)
    override fun close() {
        if (!wipe()) {
            throw SecurityException(
                "Secure key memory could not be destroyed; material may persist."
            )
        }
    }
}

class MilitaryKdfModule private constructor(
    val defaultParams: KdfParams
) {

    companion object {

        const val SALT_SIZE_BYTES = 32

        private const val MASTER_SECRET_SIZE = 64
        private const val XCHACHA_KEY_SIZE = 32
        private const val AES_KEY_SIZE = 32
        private const val CHAIN_KEY_SIZE = 48

        private val INFO_XCHACHA =
            "CVLT|v1|xchacha20-poly1305-key".toByteArray(StandardCharsets.US_ASCII)
        private val INFO_AES =
            "CVLT|v1|aes-256-gcm-key".toByteArray(StandardCharsets.US_ASCII)
        private val INFO_CHAIN =
            "CVLT|v1|chain-hmac-sha384-key".toByteArray(StandardCharsets.US_ASCII)

        fun create(params: KdfParams = KdfParams.DEFAULT): MilitaryKdfModule {
            params.validate()
            return MilitaryKdfModule(params)
        }

        fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
            return MessageDigest.isEqual(a, b)
        }

        fun wipeCharArray(chars: CharArray) {
            Arrays.fill(chars, '\u0000')
        }

        fun wipeByteArray(bytes: ByteArray) {
            Arrays.fill(bytes, 0.toByte())
        }
    }

    private val secureRandom = SecureRandom()

    private val argon2Lock = Any()

    fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_SIZE_BYTES)
        secureRandom.nextBytes(salt)
        return salt
    }

    fun deriveKeys(password: CharArray): CascadedKeyContainer {
        return deriveKeysWithSalt(password, generateSalt(), defaultParams)
    }

    @Throws(IllegalArgumentException::class, SecurityException::class)
    fun deriveKeysWithSalt(
        password: CharArray,
        salt: ByteArray,
        params: KdfParams = defaultParams
    ): CascadedKeyContainer {
        require(salt.size == SALT_SIZE_BYTES) { "Salt must be exactly 32 bytes." }

        params.validate()
        ensureMemoryFeasible(params)

        if (!NativeMemoryManager.isNativeAvailable()) {
            throw SecurityException(
                "Secure native key storage unavailable; key derivation aborted. Fail-closed."
            )
        }

        val masterSecret = ByteArray(MASTER_SECRET_SIZE)
        var passwordBytes: ByteArray? = null
        var xHeap: ByteArray? = null
        var aesHeap: ByteArray? = null
        var chainHeap: ByteArray? = null
        var xLocked: LockedSecret? = null
        var aesLocked: LockedSecret? = null
        var chainLocked: LockedSecret? = null

        try {
            passwordBytes = normalizedPasswordToBytes(password)

            val argon2Params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(params.memoryCostKb)
                .withIterations(params.iterations)
                .withParallelism(params.parallelism)
                .build()

            synchronized(argon2Lock) {
                val generator = Argon2BytesGenerator()
                generator.init(argon2Params)
                generator.generateBytes(passwordBytes, masterSecret)
            }

            xHeap = hkdfExpand(masterSecret, INFO_XCHACHA, XCHACHA_KEY_SIZE)
            xLocked = LockedSecret.fromByteArray(xHeap)
            xHeap = null

            aesHeap = hkdfExpand(masterSecret, INFO_AES, AES_KEY_SIZE)
            aesLocked = LockedSecret.fromByteArray(aesHeap)
            aesHeap = null

            chainHeap = hkdfExpand(masterSecret, INFO_CHAIN, CHAIN_KEY_SIZE)
            chainLocked = LockedSecret.fromByteArray(chainHeap)
            chainHeap = null

            return CascadedKeyContainer(
                xChaCha20Key = xLocked,
                aes256Key = aesLocked,
                chainMacKey = chainLocked,
                salt = salt.copyOf(SALT_SIZE_BYTES),
                params = params
            )

        } catch (e: Throwable) {
            xHeap?.let { wipeByteArray(it) }
            aesHeap?.let { wipeByteArray(it) }
            chainHeap?.let { wipeByteArray(it) }
            xLocked?.let { it.wipe() }
            aesLocked?.let { it.wipe() }
            chainLocked?.let { it.wipe() }
            throw SecurityException("Key derivation failed securely; operation aborted.")
        } finally {
            passwordBytes?.let { wipeByteArray(it) }
            wipeByteArray(masterSecret)
        }
    }

    private fun ensureMemoryFeasible(params: KdfParams) {
        val maxHeapKb = Runtime.getRuntime().maxMemory() / 1024L
        val limitKb = maxHeapKb / KdfConfig.HEAP_SAFETY_DIVISOR.toLong()
        if (params.memoryCostKb.toLong() > limitKb) {
            throw SecurityException("Device memory is insufficient for this KDF profile.")
        }
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))

        val output = ByteArray(outputLength)
        var previousBlock = ByteArray(0)
        var offset = 0
        var counter: Byte = 1

        try {
            while (offset < outputLength) {
                mac.update(previousBlock)
                mac.update(info)
                mac.update(counter)
                val block = mac.doFinal()

                val copyLen = minOf(block.size, outputLength - offset)
                System.arraycopy(block, 0, output, offset, copyLen)
                offset += copyLen

                if (previousBlock.isNotEmpty()) wipeByteArray(previousBlock)
                previousBlock = block
                counter++
            }
        } finally {
            if (previousBlock.isNotEmpty()) wipeByteArray(previousBlock)
        }
        return output
    }

    private fun normalizedPasswordToBytes(chars: CharArray): ByteArray {
        val normalized = java.text.Normalizer.normalize(
            String(chars),
            java.text.Normalizer.Form.NFKC
        )
        return normalized.toByteArray(StandardCharsets.UTF_8)
    }
}
