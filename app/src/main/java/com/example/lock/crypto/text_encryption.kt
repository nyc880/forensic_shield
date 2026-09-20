package com.example.lock.crypto

import android.os.Looper
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


// -----------------------------------------------------------------------------
//  Configuration — every tunable parameter lives here.
// -----------------------------------------------------------------------------
object MseV8Config {

    const val VERSION_V9: Byte = 0x09
    const val VERSION_V8: Byte = 0x08
    const val VERSION_V7_LEGACY: Byte = 0x07

    /** v9 compact salt (Argon2id minimum is 8 bytes). */
    const val SALT_BYTES = 8
    /** XChaCha20 nonce. */
    const val NONCE_BYTES = 24
    const val KEY_BYTES = 32
    const val TAG_BITS = 128
    const val AEAD_TAG_BYTES = TAG_BITS / 8
    const val GCM_TAG_BYTES = AEAD_TAG_BYTES

    /** Frozen v8 sizes — needed to decrypt old AES-256-GCM packets. */
    const val V8_SALT_BYTES = 16
    const val V8_NONCE_BYTES = 12
    const val V8_HEADER_BYTES = 1 + 1 + V8_SALT_BYTES + V8_NONCE_BYTES

    /** [version][profile][salt][nonce]  — v9 = 34 bytes */
    const val HEADER_BYTES = 1 + 1 + SALT_BYTES + NONCE_BYTES
    /** v7: [version][salt 16][nonce 12] */
    const val LEGACY_HEADER_BYTES = 1 + V8_SALT_BYTES + V8_NONCE_BYTES

    const val DEFAULT_MAX_PLAINTEXT_BYTES = 2 * 1024 * 1024
    const val MAX_PASSWORD_CHARS = 1024

    /** Tighter buckets so short strings waste fewer bytes. */
    val PADDING_BUCKETS = intArrayOf(
        16, 24, 32, 40, 48, 56, 64, 80, 96, 112,
        128, 160, 192, 224, 256, 320, 384, 512
    )
    const val PADDING_LENGTH_TRAILER_BYTES = 2
    const val LARGE_PADDING_STRIDE_BYTES = 128
    /** Below this, only 8-byte alignment is applied (no large length-hiding). */
    const val LIGHT_PADDING_MAX_BYTES = 64
    /** GZIP header overhead makes tiny payloads larger, not smaller. */
    const val GZIP_MIN_PLAINTEXT_BYTES = 150

    const val FLAG_UNCOMPRESSED: Byte = 0x00
    const val FLAG_COMPRESSED: Byte = 0x01

    val DOMAIN_INFO = "com.example.lock.MSE.v9.xchacha20".toByteArray(Charsets.US_ASCII)
    val DOMAIN_AAD = "com.example.lock.MSE.v9.aad".toByteArray(Charsets.US_ASCII)

    val DOMAIN_INFO_V8 = "com.example.lock.MSE.v8.aes-gcm".toByteArray(Charsets.US_ASCII)
    val DOMAIN_AAD_V8 = "com.example.lock.MSE.v8.aad".toByteArray(Charsets.US_ASCII)

    val DOMAIN_INFO_V7 = "com.example.lock.MSE.v7.aes-gcm".toByteArray(Charsets.US_ASCII)
    val DOMAIN_AAD_V7 = "com.example.lock.MSE.v7.aad".toByteArray(Charsets.US_ASCII)
    const val PBKDF2_LEGACY_ALGO = "PBKDF2WithHmacSHA512"
    const val PBKDF2_LEGACY_ROUNDS = 600_000

    const val LOG_TAG = "MseV9"
}


// -----------------------------------------------------------------------------
//  Argon2id cost profiles — the id is stored in the packet header, so decryption
//  always repeats the exact derivation (parameters are enum bound: a hostile
//  packet cannot force an expensive derivation).
// -----------------------------------------------------------------------------
enum class Argon2Profile(
    val id: Byte,
    val memoryKib: Int,
    val iterations: Int,
    val lanes: Int
) {
    /** 16 MiB, t=2 — memory constrained devices. */
    LOW_MEMORY(0x01, 16 * 1024, 2, 1),

    /** 32 MiB, t=3 — default (roadmap target). */
    BALANCED(0x02, 32 * 1024, 3, 1),

    /** 32 MiB, t=3, p=2 — faster on multi core devices. */
    HIGH(0x03, 32 * 1024, 3, 2),

    /** 64 MiB, t=4, p=4 — flagship devices only. */
    EXTREME(0x04, 64 * 1024, 4, 4);

    val memoryBytes: Long get() = memoryKib.toLong() * 1024L

    companion object {
        private val ALL = values()

        fun fromId(id: Byte): Argon2Profile? = ALL.firstOrNull { it.id == id }
    }
}


// -----------------------------------------------------------------------------
//  Engine
// -----------------------------------------------------------------------------
class MediumShortEncryptionEngine(
    private val profile: Argon2Profile = Argon2Profile.BALANCED,
    private val autoDegradeOnMemoryPressure: Boolean = true,
    private val legacyV7DecryptionEnabled: Boolean = true,
    private val compressionEnabled: Boolean = true,
    private val wipeCallerPassword: Boolean = false,
    private val maxPlaintextBytes: Int = MseV8Config.DEFAULT_MAX_PLAINTEXT_BYTES
) {

    companion object {
        const val DEFAULT_MAX_PLAINTEXT_BYTES = MseV8Config.DEFAULT_MAX_PLAINTEXT_BYTES

        private const val TAG = MseV8Config.LOG_TAG
        private const val AES_GCM = "AES/GCM/NoPadding"
        private const val CHACHA_POLY = "ChaCha20-Poly1305"
        private const val MAC_ALGO = "HmacSHA512"
        private const val BASE64_ENCODE_FLAGS = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        private const val BASE64_DECODE_FLAGS = Base64.URL_SAFE or Base64.NO_WRAP
        private const val SALT_OFFSET = 2
        private const val NONCE_OFFSET = SALT_OFFSET + MseV8Config.SALT_BYTES
        private const val V8_SALT_OFFSET = 2
        private const val V8_NONCE_OFFSET = V8_SALT_OFFSET + MseV8Config.V8_SALT_BYTES

        private val DEGRADATION_CHAIN = arrayOf(
            Argon2Profile.EXTREME, Argon2Profile.HIGH, Argon2Profile.BALANCED, Argon2Profile.LOW_MEMORY
        )

        fun peekVersion(encryptedBase64: String): Byte? = try {
            val cleaned = stripWhitespace(encryptedBase64)
            if (cleaned.isEmpty()) null else Base64.decode(cleaned, BASE64_DECODE_FLAGS).firstOrNull()
        } catch (_: Throwable) {
            null
        }

        fun isOwnPacket(encryptedBase64: String): Boolean {
            val version = peekVersion(encryptedBase64) ?: return false
            return version == MseV8Config.VERSION_V9 ||
                    version == MseV8Config.VERSION_V8 ||
                    version == MseV8Config.VERSION_V7_LEGACY
        }

        private fun stripWhitespace(value: String): String {
            var hasWhitespace = false
            for (c in value) {
                if (c.isWhitespace()) {
                    hasWhitespace = true
                    break
                }
            }
            if (!hasWhitespace) return value

            val builder = StringBuilder(value.length)
            for (c in value) if (!c.isWhitespace()) builder.append(c)
            return builder.toString()
        }

        internal fun degradationChainFor(profile: Argon2Profile): Array<Argon2Profile> {
            val start = DEGRADATION_CHAIN.indexOf(profile).coerceAtLeast(0)
            return DEGRADATION_CHAIN.copyOfRange(start, DEGRADATION_CHAIN.size)
        }
    }

    private val random = SecureRandom()
    private val paddingBuckets: IntArray = MseV8Config.PADDING_BUCKETS.copyOf().apply { sort() }

    init {
        require(paddingBuckets.isNotEmpty()) { "PADDING_BUCKETS must not be empty" }
        require(paddingBuckets.first() > MseV8Config.PADDING_LENGTH_TRAILER_BYTES) {
            "The smallest padding bucket must leave room for the length trailer"
        }
        require(maxPlaintextBytes > 0) { "maxPlaintextBytes must be positive" }
    }


    // ------------------------------------------------------------------ public API

    fun encrypt(plainText: String, password: CharArray): String {
        warnIfOnMainThread("encrypt")
        validatePassword(password)

        val scope = WipeScope()
        val passwordCopy = scope.trackChars(password.copyOf())
        try {
            val raw = scope.track(encodeUtf8Strict(plainText))
            require(raw.size <= maxPlaintextBytes) {
                "Plaintext exceeds the configured limit of $maxPlaintextBytes bytes"
            }

            var compressionFlag = MseV8Config.FLAG_UNCOMPRESSED
            var body: ByteArray = raw
            if (compressionEnabled && raw.size >= MseV8Config.GZIP_MIN_PLAINTEXT_BYTES) {
                val candidate = gzipCompress(raw)
                if (candidate != null && candidate.size + 1 < raw.size) {
                    compressionFlag = MseV8Config.FLAG_COMPRESSED
                    body = scope.track(candidate)
                }
            }

            val payload = scope.track(ByteArray(1 + body.size))
            payload[0] = compressionFlag
            System.arraycopy(body, 0, payload, 1, body.size)

            val padded = scope.track(pad(payload))

            val salt = scope.track(ByteArray(MseV8Config.SALT_BYTES))
            val nonce = scope.track(ByteArray(MseV8Config.NONCE_BYTES))
            random.nextBytes(salt)
            random.nextBytes(nonce)

            val derivation = deriveMasterKey(passwordCopy, salt, scope)
            val encKey = scope.track(hkdfExpand(derivation.key, MseV8Config.DOMAIN_INFO, MseV8Config.KEY_BYTES))

            val header = scope.track(ByteArray(MseV8Config.HEADER_BYTES))
            header[0] = MseV8Config.VERSION_V9
            header[1] = derivation.profile.id
            System.arraycopy(salt, 0, header, SALT_OFFSET, MseV8Config.SALT_BYTES)
            System.arraycopy(nonce, 0, header, NONCE_OFFSET, MseV8Config.NONCE_BYTES)

            val aad = scope.track(buildAad(MseV8Config.DOMAIN_AAD, header))
            val ciphertext = scope.track(xchachaEncrypt(padded, encKey, nonce, aad))

            val packet = scope.track(ByteArray(header.size + ciphertext.size))
            System.arraycopy(header, 0, packet, 0, header.size)
            System.arraycopy(ciphertext, 0, packet, header.size, ciphertext.size)

            Log.d(TAG, "encrypted ${raw.size} B -> ${packet.size} B (${derivation.profile.name})")
            return Base64.encodeToString(packet, BASE64_ENCODE_FLAGS)
        } finally {
            scope.wipeAll()
            if (wipeCallerPassword) password.fill('\u0000')
        }
    }

    fun decrypt(encryptedBase64: String, password: CharArray): String? {
        warnIfOnMainThread("decrypt")
        if (password.isEmpty() || password.size > MseV8Config.MAX_PASSWORD_CHARS) {
            Log.w(TAG, "decrypt() received an empty/oversized password array — nothing attempted")
            return null
        }
        warnIfPasswordLooksWiped(password)

        val scope = WipeScope()
        val passwordCopy = scope.trackChars(password.copyOf())
        return try {
            val cleaned = stripWhitespace(encryptedBase64)
            if (cleaned.isEmpty()) return null

            val packet = try {
                Base64.decode(cleaned, BASE64_DECODE_FLAGS)
            } catch (_: Exception) {
                null
            }
            if (packet == null || packet.isEmpty()) return null
            scope.track(packet)

            val plainBytes = when (packet[0]) {
                MseV8Config.VERSION_V9 -> decryptV9Packet(packet, passwordCopy)
                MseV8Config.VERSION_V8 -> decryptV8Packet(packet, passwordCopy)
                MseV8Config.VERSION_V7_LEGACY ->
                    if (legacyV7DecryptionEnabled) decryptV7Packet(packet, passwordCopy) else null
                else -> null
            }
            if (plainBytes == null) return null
            scope.track(plainBytes)

            decodeUtf8Strict(plainBytes)
        } catch (_: Throwable) {
            null
        } finally {
            scope.wipeAll()
            if (wipeCallerPassword) password.fill('\u0000')
        }
    }

    fun decryptAndConsume(
        encryptedBase64: String,
        password: CharArray,
        consumer: (CharArray) -> Unit
    ): Boolean {
        val passwordCopy = password.copyOf()
        var plainChars: CharArray? = null
        return try {
            val text = decrypt(encryptedBase64, passwordCopy) ?: return false
            plainChars = text.toCharArray()
            consumer(plainChars)
            true
        } catch (_: Throwable) {
            false
        } finally {
            plainChars?.fill('\u0000')
            passwordCopy.fill('\u0000')
        }
    }

    suspend fun encryptAsync(plainText: String, password: CharArray): String =
        withContext(Dispatchers.Default) { encrypt(plainText, password) }

    suspend fun decryptAsync(encryptedBase64: String, password: CharArray): String? =
        withContext(Dispatchers.Default) { decrypt(encryptedBase64, password) }


    // ------------------------------------------------------------------ KDF

    private class Derivation(val key: ByteArray, val profile: Argon2Profile)

    private fun deriveMasterKey(password: CharArray, salt: ByteArray, scope: WipeScope): Derivation {
        val chain = if (autoDegradeOnMemoryPressure) degradationChainFor(profile) else arrayOf(profile)
        val passwordBytes = scope.track(encodeUtf8(password))
        var lastFailure: Throwable? = null

        for (candidate in chain) {
            val startedAt = System.currentTimeMillis()
            val key = try {
                Argon2idPure.hash(
                    password = passwordBytes,
                    salt = salt,
                    memoryKib = candidate.memoryKib,
                    iterations = candidate.iterations,
                    lanes = candidate.lanes,
                    tagLength = MseV8Config.KEY_BYTES
                )
            } catch (t: Throwable) {
                lastFailure = t
                null
            }
            if (key != null) {
                if (candidate != profile) {
                    Log.w(TAG, "Argon2id degraded to ${candidate.name} (${candidate.memoryKib} KiB)")
                }
                Log.d(
                    TAG,
                    "Argon2id m=${candidate.memoryKib} KiB t=${candidate.iterations} " +
                            "p=${candidate.lanes} in ${System.currentTimeMillis() - startedAt} ms"
                )
                return Derivation(scope.track(key), candidate)
            }
        }
        throw GeneralSecurityException(
            "Argon2id key derivation failed (out of memory or invalid parameters)", lastFailure
        )
    }

    private fun derivePbkdf2Legacy(password: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(
            password, salt, MseV8Config.PBKDF2_LEGACY_ROUNDS, MseV8Config.KEY_BYTES * 8
        )
        val scope = WipeScope()
        return try {
            scope.track(
                SecretKeyFactory.getInstance(MseV8Config.PBKDF2_LEGACY_ALGO)
                    .generateSecret(spec).encoded
            ).copyOf()
        } finally {
            spec.clearPassword()
            scope.wipeAll()
        }
    }


    // ------------------------------------------------------------------ decryption

    private fun decryptV9Packet(packet: ByteArray, password: CharArray): ByteArray? {
        if (packet.size < MseV8Config.HEADER_BYTES + MseV8Config.AEAD_TAG_BYTES + 1) return null

        val profile = Argon2Profile.fromId(packet[1]) ?: run {
            Log.w(TAG, "unknown KDF profile in header: ${packet[1]}")
            return null
        }

        val scope = WipeScope()
        return try {
            val header = scope.track(packet.copyOfRange(0, MseV8Config.HEADER_BYTES))
            val salt = scope.track(header.copyOfRange(SALT_OFFSET, SALT_OFFSET + MseV8Config.SALT_BYTES))
            val nonce = scope.track(header.copyOfRange(NONCE_OFFSET, NONCE_OFFSET + MseV8Config.NONCE_BYTES))
            val aad = scope.track(buildAad(MseV8Config.DOMAIN_AAD, header))

            val passwordBytes = scope.track(encodeUtf8(password))
            val masterKey = scope.track(
                Argon2idPure.hash(
                    password = passwordBytes,
                    salt = salt,
                    memoryKib = profile.memoryKib,
                    iterations = profile.iterations,
                    lanes = profile.lanes,
                    tagLength = MseV8Config.KEY_BYTES
                )
            )
            val encKey = scope.track(hkdfExpand(masterKey, MseV8Config.DOMAIN_INFO, MseV8Config.KEY_BYTES))

            val ciphertext = scope.track(packet.copyOfRange(MseV8Config.HEADER_BYTES, packet.size))
            val padded = scope.track(xchachaDecrypt(ciphertext, encKey, nonce, aad))

            finishDecryptPayload(padded, scope)
        } catch (t: Throwable) {
            Log.d(TAG, "v9 decryption failed: ${t.javaClass.simpleName}")
            null
        } finally {
            scope.wipeAll()
        }
    }

    private fun decryptV8Packet(packet: ByteArray, password: CharArray): ByteArray? {
        if (packet.size < MseV8Config.V8_HEADER_BYTES + MseV8Config.GCM_TAG_BYTES + 1) return null

        val profile = Argon2Profile.fromId(packet[1]) ?: run {
            Log.w(TAG, "unknown KDF profile in header: ${packet[1]}")
            return null
        }

        val scope = WipeScope()
        return try {
            val header = scope.track(packet.copyOfRange(0, MseV8Config.V8_HEADER_BYTES))
            val salt = scope.track(header.copyOfRange(V8_SALT_OFFSET, V8_SALT_OFFSET + MseV8Config.V8_SALT_BYTES))
            val nonce = scope.track(header.copyOfRange(V8_NONCE_OFFSET, V8_NONCE_OFFSET + MseV8Config.V8_NONCE_BYTES))
            val aad = scope.track(buildAad(MseV8Config.DOMAIN_AAD_V8, header))

            val passwordBytes = scope.track(encodeUtf8(password))
            val masterKey = scope.track(
                Argon2idPure.hash(
                    password = passwordBytes,
                    salt = salt,
                    memoryKib = profile.memoryKib,
                    iterations = profile.iterations,
                    lanes = profile.lanes,
                    tagLength = MseV8Config.KEY_BYTES
                )
            )
            val encKey = scope.track(hkdfExpand(masterKey, MseV8Config.DOMAIN_INFO_V8, MseV8Config.KEY_BYTES))

            val ciphertext = scope.track(packet.copyOfRange(MseV8Config.V8_HEADER_BYTES, packet.size))
            val padded = scope.track(gcmDecrypt(ciphertext, encKey, nonce, aad))

            finishDecryptPayload(padded, scope)
        } catch (t: Throwable) {
            Log.d(TAG, "v8 decryption failed: ${t.javaClass.simpleName}")
            null
        } finally {
            scope.wipeAll()
        }
    }

    private fun decryptV7Packet(packet: ByteArray, password: CharArray): ByteArray? {
        if (packet.size < MseV8Config.LEGACY_HEADER_BYTES + MseV8Config.GCM_TAG_BYTES + 1) return null

        val scope = WipeScope()
        return try {
            val header = scope.track(packet.copyOfRange(0, MseV8Config.LEGACY_HEADER_BYTES))
            val salt = scope.track(header.copyOfRange(1, 1 + MseV8Config.V8_SALT_BYTES))
            val nonce = scope.track(
                header.copyOfRange(1 + MseV8Config.V8_SALT_BYTES, MseV8Config.LEGACY_HEADER_BYTES)
            )
            val aad = scope.track(buildAad(MseV8Config.DOMAIN_AAD_V7, header))

            val masterKey = scope.track(derivePbkdf2Legacy(password, salt))
            val encKey = scope.track(hkdfExpand(masterKey, MseV8Config.DOMAIN_INFO_V7, MseV8Config.KEY_BYTES))

            val ciphertext = scope.track(packet.copyOfRange(MseV8Config.LEGACY_HEADER_BYTES, packet.size))
            val decrypted = scope.track(gcmDecrypt(ciphertext, encKey, nonce, aad))

            val payload = unpadLegacyV7(decrypted) ?: return null
            scope.track(payload)
            decodeCompressedBody(payload, scope)
        } catch (t: Throwable) {
            Log.d(TAG, "v7 legacy decryption failed: ${t.javaClass.simpleName}")
            null
        } finally {
            scope.wipeAll()
        }
    }

    private fun finishDecryptPayload(padded: ByteArray, scope: WipeScope): ByteArray? {
        val payload = unpad(padded) ?: run {
            Log.w(TAG, "malformed padding / length trailer")
            return null
        }
        scope.track(payload)
        return decodeCompressedBody(payload, scope)
    }

    private fun decodeCompressedBody(payload: ByteArray, scope: WipeScope): ByteArray? {
        if (payload.isEmpty()) return null
        val compressionFlag = payload[0]
        val body = scope.track(payload.copyOfRange(1, payload.size))
        if (body.size > maxPlaintextBytes) return null
        return when (compressionFlag) {
            MseV8Config.FLAG_UNCOMPRESSED -> body.copyOf()
            MseV8Config.FLAG_COMPRESSED -> try {
                gzipDecompressBounded(body, maxPlaintextBytes)
            } catch (_: Exception) {
                null
            }
            else -> null
        }
    }


    // ------------------------------------------------------------------ padding

    /** `[flag][data][zero padding][padLength 2B big-endian]`, total = next bucket. */
    internal fun pad(data: ByteArray): ByteArray {
        val target = bucketFor(data.size + MseV8Config.PADDING_LENGTH_TRAILER_BYTES)
        val padLength = target - data.size

        val out = ByteArray(target)
        System.arraycopy(data, 0, out, 0, data.size)
        out[out.size - 2] = ((padLength ushr 8) and 0xFF).toByte()
        out[out.size - 1] = (padLength and 0xFF).toByte()
        return out
    }

    internal fun unpad(padded: ByteArray): ByteArray? {
        val size = padded.size
        if (size < MseV8Config.PADDING_LENGTH_TRAILER_BYTES + 1) return null

        val padLength = ((padded[size - 2].toInt() and 0xFF) shl 8) or (padded[size - 1].toInt() and 0xFF)
        if (padLength < MseV8Config.PADDING_LENGTH_TRAILER_BYTES) return null

        val dataEnd = size - padLength
        if (dataEnd < 1) return null

        var accumulator = 0
        for (i in dataEnd until size - MseV8Config.PADDING_LENGTH_TRAILER_BYTES) {
            accumulator = accumulator or (padded[i].toInt() and 0xFF)
        }
        if (accumulator != 0) return null

        return padded.copyOfRange(0, dataEnd)
    }

    private fun unpadLegacyV7(data: ByteArray): ByteArray? {
        if (data.isEmpty()) return null
        val rawPadByte = data[data.size - 1].toInt() and 0xFF
        val padLength = if (rawPadByte == 0) 256 else rawPadByte
        if (padLength > data.size) return null

        val dataEnd = data.size - padLength
        if (dataEnd < 1) return null

        var accumulator = 0
        for (i in dataEnd until data.size - 1) {
            accumulator = accumulator or (data[i].toInt() and 0xFF)
        }
        if (accumulator != 0) return null

        return data.copyOfRange(0, dataEnd)
    }

    private fun bucketFor(size: Int): Int {
        if (size <= MseV8Config.LIGHT_PADDING_MAX_BYTES) {
            val aligned = ((size + 7) / 8) * 8
            return aligned.coerceAtLeast(size)
        }
        for (bucket in paddingBuckets) {
            if (size <= bucket) return bucket
        }
        val stride = MseV8Config.LARGE_PADDING_STRIDE_BYTES
        return ((size + stride - 1) / stride) * stride
    }


    // ------------------------------------------------------------------ primitives

    private fun xchachaEncrypt(plain: ByteArray, key: ByteArray, nonce24: ByteArray, aad: ByteArray): ByteArray {
        require(nonce24.size == 24) { "XChaCha20 nonce must be 24 bytes" }
        val nonce16 = nonce24.copyOfRange(0, 16)
        val subKey = hChaCha20(key, nonce16)
        wipeBytesSecure(nonce16)
        val nonce12 = ByteArray(12)
        try {
            System.arraycopy(nonce24, 16, nonce12, 4, 8)
            val cipher = Cipher.getInstance(CHACHA_POLY)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(subKey, "ChaCha20"), IvParameterSpec(nonce12))
            cipher.updateAAD(aad)
            return cipher.doFinal(plain)
        } finally {
            wipeBytesSecure(subKey)
            wipeBytesSecure(nonce12)
        }
    }

    private fun xchachaDecrypt(ciphertext: ByteArray, key: ByteArray, nonce24: ByteArray, aad: ByteArray): ByteArray {
        require(nonce24.size == 24) { "XChaCha20 nonce must be 24 bytes" }
        val nonce16 = nonce24.copyOfRange(0, 16)
        val subKey = hChaCha20(key, nonce16)
        wipeBytesSecure(nonce16)
        val nonce12 = ByteArray(12)
        try {
            System.arraycopy(nonce24, 16, nonce12, 4, 8)
            val cipher = Cipher.getInstance(CHACHA_POLY)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(subKey, "ChaCha20"), IvParameterSpec(nonce12))
            cipher.updateAAD(aad)
            return cipher.doFinal(ciphertext)
        } finally {
            wipeBytesSecure(subKey)
            wipeBytesSecure(nonce12)
        }
    }

    /** RFC 8439 / XChaCha HChaCha20 with the standard ChaCha constants. */
    private fun hChaCha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        for (i in 0 until 8) state[4 + i] = packLittleEndian32(key, i * 4)
        for (i in 0 until 4) state[12 + i] = packLittleEndian32(nonce16, i * 4)

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
        state.fill(0)
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

    private fun gcmDecrypt(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(MseV8Config.TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, outLength: Int): ByteArray {
        val mac = Mac.getInstance(MAC_ALGO)
        val out = ByteArray(outLength)
        var previous = ByteArray(0)
        var position = 0
        var counter = 1

        try {
            while (position < outLength) {
                mac.init(SecretKeySpec(prk, MAC_ALGO))
                mac.update(previous)
                mac.update(info)
                mac.update(counter.toByte())
                val block = mac.doFinal()
                val amount = minOf(block.size, outLength - position)
                System.arraycopy(block, 0, out, position, amount)
                wipeBytesSecure(previous)
                previous = block
                position += amount
                counter++
            }
            return out
        } catch (t: Throwable) {
            wipeBytesSecure(out)
            throw t
        } finally {
            wipeBytesSecure(previous)
        }
    }

    private fun buildAad(domain: ByteArray, header: ByteArray): ByteArray {
        val aad = ByteArray(domain.size + header.size)
        System.arraycopy(domain, 0, aad, 0, domain.size)
        System.arraycopy(header, 0, aad, domain.size, header.size)
        return aad
    }

    private fun gzipCompress(data: ByteArray): ByteArray? {
        val output = WipeableByteArrayOutputStream(data.size + 64)
        return try {
            GZIPOutputStream(output).use { it.write(data) }
            val compressed = output.toByteArray()
            if (compressed.size >= data.size) null else compressed
        } catch (_: Exception) {
            null
        } finally {
            output.wipe()
        }
    }

    private fun gzipDecompressBounded(data: ByteArray, max: Int): ByteArray {
        val output = WipeableByteArrayOutputStream(minOf(8192, max))
        val chunk = ByteArray(8192)
        var total = 0
        try {
            GZIPInputStream(ByteArrayInputStream(data)).use { gzip ->
                while (true) {
                    val read = gzip.read(chunk)
                    if (read < 0) break
                    if (read == 0) continue
                    total = Math.addExact(total, read)
                    if (total > max) throw IllegalArgumentException("Decompression limit exceeded")
                    output.write(chunk, 0, read)
                }
            }
            return output.toByteArray()
        } finally {
            wipeBytesSecure(chunk)
            output.wipe()
        }
    }


    // ------------------------------------------------------------------ encoding

    private fun encodeUtf8Strict(text: String): ByteArray {
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val encodingBuffer = encoder.encode(CharBuffer.wrap(text))
        val out = ByteArray(encodingBuffer.remaining())
        encodingBuffer.get(out)
        if (encodingBuffer.hasArray()) encodingBuffer.array().fill(0)
        return out
    }

    private fun decodeUtf8Strict(bytes: ByteArray): String {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val charBuffer = decoder.decode(ByteBuffer.wrap(bytes))
        val text = charBuffer.toString()
        if (charBuffer.hasArray()) charBuffer.array().fill('\u0000')
        return text
    }

    private fun encodeUtf8(chars: CharArray): ByteArray {
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val charBuffer = encoder.encode(CharBuffer.wrap(chars))
        val out = ByteArray(charBuffer.remaining())
        charBuffer.get(out)
        if (charBuffer.hasArray()) charBuffer.array().fill(0)
        return out
    }

    private fun validatePassword(password: CharArray) {
        require(password.isNotEmpty()) { "Password must not be empty" }
        require(password.size <= MseV8Config.MAX_PASSWORD_CHARS) { "Password is too long" }
    }

    private fun warnIfPasswordLooksWiped(password: CharArray) {
        var allNul = true
        for (c in password) {
            if (c != '\u0000') {
                allNul = false
                break
            }
        }
        if (allNul) {
            Log.w(
                TAG,
                "password array is all NUL characters — it was likely wiped by another " +
                        "component. Pass a fresh copy to every attempt: " +
                        "mediumShortEngine.decrypt(cipher, passwordChars.copyOf())"
            )
        }
    }

    private fun warnIfOnMainThread(operation: String) {
        try {
            if (Looper.getMainLooper()?.thread === Thread.currentThread()) {
                Log.w(TAG, "$operation() on the main thread: use ${operation}Async() instead")
            }
        } catch (_: Throwable) {
            // no Looper (unit tests)
        }
    }
}


// =============================================================================
//  Argon2id (RFC 9106) + BLAKE2b — pure Kotlin, no dependency.
//  Verified against the RFC 9106 §5.3 vector and a differential test suite.
// =============================================================================
internal object Argon2idPure {

    private const val BLOCK_LONGS = 128          // 1024-byte block = 128 x u64
    private const val SYNC_POINTS = 4
    private const val TYPE_ID = 2                // Argon2id
    private const val VERSION = 0x13             // v1.3
    private const val ADDRESSES_PER_BLOCK = 128

    private val zeroBlock = LongArray(BLOCK_LONGS)   // read only, shared safely

    /** memoryKib = memory cost, iterations = t, lanes = p, tagLength = output bytes. */
    internal fun hash(
        password: ByteArray,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        lanes: Int,
        tagLength: Int,
        secret: ByteArray = EMPTY,
        associatedData: ByteArray = EMPTY
    ): ByteArray {
        require(lanes >= 1) { "lanes must be >= 1" }
        require(iterations >= 1) { "iterations must be >= 1" }
        require(tagLength >= 4) { "tag length must be >= 4" }
        require(salt.size >= 8) { "salt must be >= 8 bytes" }

        // m' = 4 * p * floor(m / 4p)
        val laneLength = (memoryKib / (SYNC_POINTS * lanes)) * SYNC_POINTS
        require(laneLength >= 8) { "memory cost too small for $lanes lanes" }
        val memoryBlocks = laneLength * lanes
        val segmentLength = laneLength / SYNC_POINTS

        val memory = LongArray(memoryBlocks * BLOCK_LONGS)
        val runner = LaneRunner(lanes)

        try {
            val h0 = blake2b(
                64,
                concat(
                    int32(lanes), int32(tagLength), int32(memoryKib), int32(iterations),
                    int32(VERSION), int32(TYPE_ID),
                    int32(password.size), password,
                    int32(salt.size), salt,
                    int32(secret.size), secret,
                    int32(associatedData.size), associatedData
                )
            )

            for (lane in 0 until lanes) {
                for (index in 0..1) {
                    val blockBytes = hPrime(1024, concat(h0, int32(index), int32(lane)))
                    bytesToLongs(blockBytes, memory, (lane * laneLength + index) * BLOCK_LONGS)
                }
            }

            for (pass in 0 until iterations) {
                for (slice in 0 until SYNC_POINTS) {
                    runner.runSlice { lane ->
                        // per-lane scratch: lanes of the same slice run in parallel
                        val r = LongArray(BLOCK_LONGS)
                        val q = LongArray(BLOCK_LONGS)
                        val addressBlock = LongArray(BLOCK_LONGS)
                        val inputBlock = LongArray(BLOCK_LONGS)
                        try {
                            fillSegment(
                                memory, r, q, addressBlock, inputBlock,
                                pass, slice, lane, lanes, laneLength, segmentLength, memoryBlocks, iterations
                            )
                        } finally {
                            r.fill(0L); q.fill(0L); addressBlock.fill(0L); inputBlock.fill(0L)
                        }
                    }
                }
            }

            val finalBlock = LongArray(BLOCK_LONGS)
            for (lane in 0 until lanes) {
                val offset = (lane * laneLength + laneLength - 1) * BLOCK_LONGS
                for (i in 0 until BLOCK_LONGS) finalBlock[i] = finalBlock[i] xor memory[offset + i]
            }
            return hPrime(tagLength, longsToBytes(finalBlock))
        } finally {
            runner.close()
            memory.fill(0L)
        }
    }

    /** H0 digest — same value as the RFC 9106 "pre-hashing digest". */
    internal fun initialHash(
        password: ByteArray,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        lanes: Int,
        tagLength: Int,
        secret: ByteArray = EMPTY,
        associatedData: ByteArray = EMPTY
    ): ByteArray = blake2b(
        64,
        concat(
            int32(lanes), int32(tagLength), int32(memoryKib), int32(iterations),
            int32(VERSION), int32(TYPE_ID),
            int32(password.size), password,
            int32(salt.size), salt,
            int32(secret.size), secret,
            int32(associatedData.size), associatedData
        )
    )

    private fun fillSegment(
        memory: LongArray,
        r: LongArray,
        q: LongArray,
        addressBlock: LongArray,
        inputBlock: LongArray,
        pass: Int,
        slice: Int,
        lane: Int,
        lanes: Int,
        laneLength: Int,
        segmentLength: Int,
        memoryBlocks: Int,
        iterations: Int
    ) {
        // Argon2id: the first half of the first pass uses data independent addressing
        val dataIndependent = pass == 0 && slice < 2
        var startingIndex = 0

        if (dataIndependent) {
            inputBlock.fill(0L)
            inputBlock[0] = pass.toLong()
            inputBlock[1] = lane.toLong()
            inputBlock[2] = slice.toLong()
            inputBlock[3] = memoryBlocks.toLong()
            inputBlock[4] = iterations.toLong()
            inputBlock[5] = TYPE_ID.toLong()
        }
        if (pass == 0 && slice == 0) {
            startingIndex = 2 // the first two blocks of each lane already exist
            if (dataIndependent) nextAddresses(r, q, addressBlock, inputBlock)
        }

        var currentOffset = lane * laneLength + slice * segmentLength + startingIndex
        val laneStart = lane * laneLength
        val laneEnd = laneStart + laneLength

        for (index in startingIndex until segmentLength) {
            val previousOffset = if (currentOffset == laneStart) laneEnd - 1 else currentOffset - 1
            val pseudoRandom: Long
            if (dataIndependent) {
                if (index % ADDRESSES_PER_BLOCK == 0) nextAddresses(r, q, addressBlock, inputBlock)
                pseudoRandom = addressBlock[index % ADDRESSES_PER_BLOCK]
            } else {
                pseudoRandom = memory[previousOffset * BLOCK_LONGS]
            }

            var referenceLane = ((pseudoRandom ushr 32) % lanes).toInt()
            if (pass == 0 && slice == 0) referenceLane = lane

            val referenceIndex = indexAlpha(
                pass, slice, index, laneLength, segmentLength,
                pseudoRandom and 0xFFFFFFFFL, referenceLane == lane
            )

            fillBlock(
                memory, r, q,
                previousOffset * BLOCK_LONGS,
                (referenceLane * laneLength + referenceIndex) * BLOCK_LONGS,
                currentOffset * BLOCK_LONGS,
                withXor = pass > 0
            )
            currentOffset++
        }
    }

    private fun nextAddresses(r: LongArray, q: LongArray, addressBlock: LongArray, inputBlock: LongArray) {
        inputBlock[6]++
        writeBlock(r, q, zeroBlock, inputBlock, addressBlock)
        writeBlock(r, q, zeroBlock, addressBlock, addressBlock)
    }

    private fun writeBlock(r: LongArray, q: LongArray, prev: LongArray, ref: LongArray, out: LongArray) {
        for (i in 0 until BLOCK_LONGS) r[i] = prev[i] xor ref[i]
        System.arraycopy(r, 0, q, 0, BLOCK_LONGS)
        permute(q)
        for (i in 0 until BLOCK_LONGS) out[i] = r[i] xor q[i]
    }

    private fun fillBlock(
        memory: LongArray,
        r: LongArray,
        q: LongArray,
        previousOffset: Int,
        referenceOffset: Int,
        outputOffset: Int,
        withXor: Boolean
    ) {
        for (i in 0 until BLOCK_LONGS) r[i] = memory[previousOffset + i] xor memory[referenceOffset + i]
        System.arraycopy(r, 0, q, 0, BLOCK_LONGS)
        permute(q)
        if (withXor) {
            for (i in 0 until BLOCK_LONGS) memory[outputOffset + i] = memory[outputOffset + i] xor r[i] xor q[i]
        } else {
            for (i in 0 until BLOCK_LONGS) memory[outputOffset + i] = r[i] xor q[i]
        }
    }

    /** P: 8 rounds over consecutive 128-byte groups, then 8 rounds over strided pairs. */
    private fun permute(v: LongArray) {
        var base = 0
        while (base < BLOCK_LONGS) {
            blakeRound(
                v,
                base, base + 1, base + 2, base + 3, base + 4, base + 5, base + 6, base + 7,
                base + 8, base + 9, base + 10, base + 11, base + 12, base + 13, base + 14, base + 15
            )
            base += 16
        }
        var s = 0
        while (s < 16) {
            blakeRound(
                v,
                s, s + 1, s + 16, s + 17, s + 32, s + 33, s + 48, s + 49,
                s + 64, s + 65, s + 80, s + 81, s + 96, s + 97, s + 112, s + 113
            )
            s += 2
        }
    }

    private fun blakeRound(
        v: LongArray,
        i0: Int, i1: Int, i2: Int, i3: Int, i4: Int, i5: Int, i6: Int, i7: Int,
        i8: Int, i9: Int, i10: Int, i11: Int, i12: Int, i13: Int, i14: Int, i15: Int
    ) {
        g(v, i0, i4, i8, i12); g(v, i1, i5, i9, i13); g(v, i2, i6, i10, i14); g(v, i3, i7, i11, i15)
        g(v, i0, i5, i10, i15); g(v, i1, i6, i11, i12); g(v, i2, i7, i8, i13); g(v, i3, i4, i9, i14)
    }

    private fun g(v: LongArray, a: Int, b: Int, c: Int, d: Int) {
        var va = v[a]
        var vb = v[b]
        var vc = v[c]
        var vd = v[d]
        va = blaMka(va, vb); vd = java.lang.Long.rotateRight(vd xor va, 32)
        vc = blaMka(vc, vd); vb = java.lang.Long.rotateRight(vb xor vc, 24)
        va = blaMka(va, vb); vd = java.lang.Long.rotateRight(vd xor va, 8)
        vc = blaMka(vc, vd); vb = java.lang.Long.rotateRight(vb xor vc, 63)
        v[a] = va; v[b] = vb; v[c] = vc; v[d] = vd
    }

    private fun blaMka(x: Long, y: Long): Long {
        val low = 0xFFFFFFFFL
        return x + y + 2L * ((x and low) * (y and low))
    }

    private fun indexAlpha(
        pass: Int,
        slice: Int,
        index: Int,
        laneLength: Int,
        segmentLength: Int,
        pseudoRandom: Long,
        sameLane: Boolean
    ): Int {
        val referenceAreaSize: Int = if (pass == 0) {
            when {
                slice == 0 -> index - 1
                sameLane -> slice * segmentLength + index - 1
                else -> slice * segmentLength + (if (index == 0) -1 else 0)
            }
        } else {
            if (sameLane) laneLength - segmentLength + index - 1
            else laneLength - segmentLength + (if (index == 0) -1 else 0)
        }

        val j1 = pseudoRandom and 0xFFFFFFFFL
        val x = (j1 * j1) ushr 32
        val y = (referenceAreaSize.toLong() * x) ushr 32
        val relativePosition = referenceAreaSize - 1 - y

        val startPosition = if (pass != 0) {
            if (slice == SYNC_POINTS - 1) 0 else (slice + 1) * segmentLength
        } else 0

        return ((startPosition + relativePosition) % laneLength).toInt()
    }

    // ---------------------------------------------------------------- H' / BLAKE2b

    /** H'(T, X) — variable length hash built on BLAKE2b (RFC 9106 §3.3). */
    internal fun hPrime(outputLength: Int, input: ByteArray): ByteArray {
        if (outputLength <= 64) return blake2b(outputLength, concat(int32(outputLength), input))

        val out = ByteArray(outputLength)
        var position = 0
        var buffer = blake2b(64, concat(int32(outputLength), input))
        System.arraycopy(buffer, 0, out, position, 32)
        position += 32
        var toProduce = outputLength - 32

        while (toProduce > 64) {
            buffer = blake2b(64, buffer)
            System.arraycopy(buffer, 0, out, position, 32)
            position += 32
            toProduce -= 32
        }
        val last = blake2b(toProduce, buffer)
        System.arraycopy(last, 0, out, position, toProduce)
        return out
    }

    private val IV = longArrayOf(
        0x6a09e667f3bcc908UL.toLong(), 0xbb67ae8584caa73bUL.toLong(),
        0x3c6ef372fe94f82bUL.toLong(), 0xa54ff53a5f1d36f1UL.toLong(),
        0x510e527fade682d1UL.toLong(), 0x9b05688c2b3e6c1fUL.toLong(),
        0x1f83d9abfb41bd6bUL.toLong(), 0x5be0cd19137e2179UL.toLong()
    )

    private val SIGMA = intArrayOf(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0
    )

    /** BLAKE2b with an arbitrary digest length (1..64), unkeyed. */
    internal fun blake2b(outputLength: Int, input: ByteArray): ByteArray {
        require(outputLength in 1..64) { "BLAKE2b output length must be 1..64" }

        val h = LongArray(8)
        System.arraycopy(IV, 0, h, 0, 8)
        h[0] = h[0] xor (0x01010000L xor outputLength.toLong())

        val block = LongArray(16)
        var offset = 0
        val total = input.size

        while (offset < total) {
            java.util.Arrays.fill(block, 0L)
            val take = minOf(128, total - offset)
            for (i in 0 until take) {
                block[i shr 3] = block[i shr 3] or ((input[offset + i].toLong() and 0xFF) shl ((i and 7) * 8))
            }
            offset += take
            compress(h, block, offset.toLong(), offset == total)
        }
        if (total == 0) {
            java.util.Arrays.fill(block, 0L)
            compress(h, block, 0L, true)
        }

        val out = ByteArray(outputLength)
        for (i in 0 until outputLength) {
            out[i] = ((h[i shr 3] ushr ((i and 7) * 8)) and 0xFF).toByte()
        }
        h.fill(0L)
        return out
    }

    private fun compress(h: LongArray, block: LongArray, counter: Long, last: Boolean) {
        val v = LongArray(16)
        System.arraycopy(h, 0, v, 0, 8)
        System.arraycopy(IV, 0, v, 8, 8)
        v[12] = v[12] xor counter
        if (last) v[14] = v[14] xor -1L

        for (round in 0 until 12) {
            val s = (round % 10) * 16
            gb(v, 0, 4, 8, 12, block[SIGMA[s]], block[SIGMA[s + 1]])
            gb(v, 1, 5, 9, 13, block[SIGMA[s + 2]], block[SIGMA[s + 3]])
            gb(v, 2, 6, 10, 14, block[SIGMA[s + 4]], block[SIGMA[s + 5]])
            gb(v, 3, 7, 11, 15, block[SIGMA[s + 6]], block[SIGMA[s + 7]])
            gb(v, 0, 5, 10, 15, block[SIGMA[s + 8]], block[SIGMA[s + 9]])
            gb(v, 1, 6, 11, 12, block[SIGMA[s + 10]], block[SIGMA[s + 11]])
            gb(v, 2, 7, 8, 13, block[SIGMA[s + 12]], block[SIGMA[s + 13]])
            gb(v, 3, 4, 9, 14, block[SIGMA[s + 14]], block[SIGMA[s + 15]])
        }
        for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
        v.fill(0L)
    }

    private fun gb(v: LongArray, a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        var va = v[a]
        var vb = v[b]
        var vc = v[c]
        var vd = v[d]
        va = va + vb + x
        vd = java.lang.Long.rotateRight(vd xor va, 32)
        vc = vc + vd
        vb = java.lang.Long.rotateRight(vb xor vc, 24)
        va = va + vb + y
        vd = java.lang.Long.rotateRight(vd xor va, 16)
        vc = vc + vd
        vb = java.lang.Long.rotateRight(vb xor vc, 63)
        v[a] = va; v[b] = vb; v[c] = vc; v[d] = vd
    }

    // ---------------------------------------------------------------- helpers

    private fun bytesToLongs(bytes: ByteArray, target: LongArray, offset: Int) {
        for (i in 0 until BLOCK_LONGS) {
            val b = i * 8
            target[offset + i] = (bytes[b].toLong() and 0xFF) or
                    ((bytes[b + 1].toLong() and 0xFF) shl 8) or
                    ((bytes[b + 2].toLong() and 0xFF) shl 16) or
                    ((bytes[b + 3].toLong() and 0xFF) shl 24) or
                    ((bytes[b + 4].toLong() and 0xFF) shl 32) or
                    ((bytes[b + 5].toLong() and 0xFF) shl 40) or
                    ((bytes[b + 6].toLong() and 0xFF) shl 48) or
                    ((bytes[b + 7].toLong() and 0xFF) shl 56)
        }
    }

    private fun longsToBytes(source: LongArray): ByteArray {
        val out = ByteArray(source.size * 8)
        for (i in source.indices) {
            val value = source[i]
            val base = i * 8
            for (b in 0 until 8) out[base + b] = ((value ushr (b * 8)) and 0xFF).toByte()
        }
        return out
    }

    private fun int32(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 24) and 0xFF).toByte()
    )

    private fun concat(vararg parts: Any): ByteArray {
        var size = 0
        for (part in parts) size += if (part is ByteArray) part.size else 4
        val out = ByteArray(size)
        var position = 0
        for (part in parts) {
            if (part is ByteArray) {
                System.arraycopy(part, 0, out, position, part.size)
                position += part.size
            } else {
                val value = part as Int
                out[position] = (value and 0xFF).toByte()
                out[position + 1] = ((value ushr 8) and 0xFF).toByte()
                out[position + 2] = ((value ushr 16) and 0xFF).toByte()
                out[position + 3] = ((value ushr 24) and 0xFF).toByte()
                position += 4
            }
        }
        return out
    }

    /** One thread per lane (capped by the core count); lanes of a slice are independent. */
    private class LaneRunner(private val laneCount: Int) {
        private val pool: ExecutorService? = if (laneCount > 1) {
            Executors.newFixedThreadPool(minOf(laneCount, Runtime.getRuntime().availableProcessors().coerceAtLeast(1)))
        } else null

        fun runSlice(action: (Int) -> Unit) {
            val executor = pool
            if (executor == null) {
                action(0)
                return
            }
            val futures = ArrayList<java.util.concurrent.Future<*>>(laneCount)
            for (lane in 0 until laneCount) futures.add(executor.submit { action(lane) })
            for (future in futures) future.get()
        }

        fun close() {
            pool?.shutdownNow()
        }
    }
}

private val EMPTY = ByteArray(0)


// -----------------------------------------------------------------------------
//  Memory hygiene helpers
// -----------------------------------------------------------------------------

/** ByteArrayOutputStream whose growth buffer can be zeroed (reset() alone does not). */
private class WipeableByteArrayOutputStream(initialSize: Int) :
    ByteArrayOutputStream(initialSize.coerceAtLeast(32)) {

    fun wipe() {
        try {
            buf.fill(0)
        } catch (_: Throwable) {
            // best effort
        }
        reset()
    }
}

private fun wipeBytes(bytes: ByteArray?) {
    bytes?.fill(0)
}

/** Key material wipe: 00 -> FF -> 00. */
private fun wipeBytesSecure(bytes: ByteArray?) {
    if (bytes == null) return
    bytes.fill(0x00)
    bytes.fill(0xFF.toByte())
    bytes.fill(0x00)
}

private fun wipeDirectBufferBytes(buffer: ByteBuffer?) {
    if (buffer == null || !buffer.isDirect) return
    try {
        val capacity = buffer.capacity()
        buffer.clear()
        buffer.put(ByteArray(capacity))
        buffer.clear()
    } catch (_: Throwable) {
        // never let memory hygiene break the crypto path
    }
}

/** Registers every temporary buffer of one operation; a single finally wipes them all. */
private class WipeScope {
    private val byteArrays = ArrayList<ByteArray>(24)
    private val directBuffers = ArrayList<ByteBuffer>(2)
    private val charArrays = ArrayList<CharArray>(2)

    fun track(buffer: ByteArray): ByteArray {
        byteArrays.add(buffer)
        return buffer
    }

    fun trackDirect(buffer: ByteBuffer): ByteBuffer {
        directBuffers.add(buffer)
        return buffer
    }

    fun trackChars(chars: CharArray): CharArray {
        charArrays.add(chars)
        return chars
    }

    fun wipeAll() {
        for (index in byteArrays.indices) wipeBytesSecure(byteArrays[index])
        byteArrays.clear()

        for (index in directBuffers.indices) wipeDirectBufferBytes(directBuffers[index])
        directBuffers.clear()

        for (index in charArrays.indices) charArrays[index].fill('\u0000')
        charArrays.clear()
    }
}