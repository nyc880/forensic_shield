package com.example.lock.crypto

import android.os.Build
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.PBEKeySpec

// =====================================================================================
// GLOBAL CONFIGURATION & VARIABLES SPECIFICATION TABLE (FOR EASY MODIFICATION)
// =====================================================================================
/*
+-----------------------------------+-----------------------------------+---------------------------------------+
| VARIABLE NAME                     | VALUE / TYPE                      | ROLE / CRYPTOGRAPHIC DOMAIN           |
+-----------------------------------+-----------------------------------+---------------------------------------+
| SALT_BYTES                        | 32 (Int)                          | Entropy injection size for PBKDF2     |
| NONCE_BYTES                       | 12 (Int)                          | AES-GCM initialization vector space  |
| KEY_BYTES                         | 32 (Int)                          | AES-256 raw symmetric key length      |
| TAG_BYTES                         | 16 (Int)                          | GCM Authentication tag size           |
| TAG_BITS                          | 128 (Int)                         | GCM Authentication tag bit length     |
| HMAC_BYTES                        | 64 (Int)                          | Outer layer signature verification   |
| HEADER_NONCE_BYTES                | 12 (Int)                          | Master envelope inner IV size         |
| HEADER_PLAINTEXT_BYTES            | 50 (Int)                          | Architectural metadata byte bounds    |
| HEADER_CIPHERTEXT_BYTES           | 66 (Int)                          | Enveloped structural layout scale     |
| PBKDF2_ALGORITHM                  | "PBKDF2WithHmacSHA512"            | Cryptographic key derivation standard |
| MIN_CONTAINER_SIZE_BYTES          | 4096 (Int)                        | Absolute minimal padding perimeter   |
| MAX_CONTAINER_SIZE_BYTES          | 16777216 (Int)                    | Maximum allowable allocation floor    |
| DEFAULT_CONTAINER_SIZE_BYTES      | 524288 (Int)                      | Nominal memory mapping standard       |
| DEFAULT_MAX_PLAINTEXT_BYTES       | 262144 (Int)                      | Plaintext capacity limit              |
| GZIP_OVERHEAD_BYTES               | 1024 (Int)                        | Compression boundaries mitigation    |
| MIN_PASSWORD_CHARS                | 1 (Int)                           | Lower validation barrier              |
| MAX_PASSWORD_CHARS                | 1024 (Int)                        | Upper parsing limit                   |
| MAX_PROFILE_ITERATIONS            | 8 (Int)                           | Security profiles computation maximum|
| MAX_PROFILE_MEMORY_KIB            | 32768 (Int)                       | Security profiles memory ceiling     |
| MAX_PROFILE_PARALLELISM           | 8 (Int)                           | Multi-threading thread limit          |
| DIAGNOSTIC_TAG                    | "MaxCryptoDiagnostics"            | Target tracking filtering system tag  |
+-----------------------------------+-----------------------------------+---------------------------------------+
*/

class MaxTextEncryptionEngine(
    private val profile: SecurityProfile = SecurityProfile.EXTREME_MOBILE,
    private val compressionEnabled: Boolean = false,
    private val containerSizeBytes: Int = DEFAULT_CONTAINER_SIZE_BYTES,
    private val maxPlaintextBytes: Int = DEFAULT_MAX_PLAINTEXT_BYTES
) {

    companion object {
        private const val SALT_BYTES                = 32
        private const val NONCE_BYTES               = 12
        private const val KEY_BYTES                 = 32
        private const val TAG_BYTES                 = 16
        private const val TAG_BITS                  = 128
        private const val HMAC_BYTES                = 64

        private const val HEADER_NONCE_BYTES        = 12
        private const val HEADER_PLAINTEXT_BYTES    = 50
        private const val HEADER_CIPHERTEXT_BYTES   = HEADER_PLAINTEXT_BYTES + TAG_BYTES

        private const val HEADER_BYTES              = SALT_BYTES + 1 + HEADER_NONCE_BYTES + HEADER_CIPHERTEXT_BYTES
        private const val WRAPPED_DEK_BYTES         = KEY_BYTES + TAG_BYTES
        private const val METADATA_PLAINTEXT_BYTES  = 64
        private const val METADATA_CIPHERTEXT_BYTES = METADATA_PLAINTEXT_BYTES + TAG_BYTES

        private const val PBKDF2_ALGORITHM          = "PBKDF2WithHmacSHA512"

        private const val MIN_CONTAINER_SIZE_BYTES  = 4096
        private const val MAX_CONTAINER_SIZE_BYTES  = 16 * 1024 * 1024
        const val DEFAULT_CONTAINER_SIZE_BYTES      = 512 * 1024
        const val DEFAULT_MAX_PLAINTEXT_BYTES       = 256 * 1024
        private const val GZIP_OVERHEAD_BYTES       = 1024

        private const val MIN_PASSWORD_CHARS        = 1
        private const val MAX_PASSWORD_CHARS        = 1024
        private const val MAX_PROFILE_ITERATIONS    = 8
        private const val MAX_PROFILE_MEMORY_KIB    = 32 * 1024
        private const val MAX_PROFILE_PARALLELISM   = 8

        private const val COMPRESSION_NONE: Byte    = 0x00
        private const val COMPRESSION_GZIP: Byte    = 0x01

        private const val DIAGNOSTIC_TAG            = "MaxCryptoDiagnostics"

        private val HKDF_STATIC_CONTEXT = "com.example.lock.MaxTextEncryptionEngine.v12.hkdf_context_salt".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_HEADER   = "com.example.lock.MaxTextEncryptionEngine.v12.header".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_KEK      = "com.example.lock.MaxTextEncryptionEngine.v12.kek".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_AUTH     = "com.example.lock.MaxTextEncryptionEngine.v12.auth".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_WRAP     = "com.example.lock.MaxTextEncryptionEngine.v12.wrap".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_METADATA = "com.example.lock.MaxTextEncryptionEngine.v12.metadata".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_DATA     = "com.example.lock.MaxTextEncryptionEngine.v12.data".toByteArray(Charsets.US_ASCII)
    }

    init {
        Log.d(DIAGNOSTIC_TAG, "[INIT] Instantiating Portable Engine. Thread: ${Thread.currentThread().name}")
        Log.d(DIAGNOSTIC_TAG, "[INIT] Params -> Profile: ${profile.name}, Compression: $compressionEnabled, Target Size: $containerSizeBytes bytes")
        require(containerSizeBytes in MIN_CONTAINER_SIZE_BYTES..MAX_CONTAINER_SIZE_BYTES)
        require(maxPlaintextBytes > 0 && maxPlaintextBytes < containerSizeBytes)
    }

    enum class SecurityProfile(
        val id: Byte,
        val iterations: Int,
        val memoryKib: Int,
        val parallelism: Int
    ) {
        STANDARD(0x01, 3, 64 * 1024, 4),
        HIGH(0x02, 4, 128 * 1024, 4),
        EXTREME_MOBILE(0x03, 6, 32 * 1024, 4),
        ULTRA_LOW(0x04, 8, 16 * 1024, 2),
        LOW(0x05, 6, 32 * 1024, 2);

        val pbkdf2Iterations: Int
            get() = when (this) {
                ULTRA_LOW -> 200_000
                LOW -> 400_000
                STANDARD -> 600_000
                HIGH -> 1_000_000
                EXTREME_MOBILE -> 2_000_000
            }

        companion object {
            fun from(id: Byte, iterations: Int, memoryKib: Int, parallelism: Int): SecurityProfile? {
                return values().firstOrNull {
                    it.id == id && it.iterations == iterations &&
                            it.memoryKib == memoryKib && it.parallelism == parallelism
                }
            }
        }
    }

    enum class HardwareSecurityLevel(val id: Byte) {
        SOFTWARE(0x00),
        KEYSTORE(0x01),
        STRONGBOX(0x02)
    }

    private data class ParsedHeader(
        val salt: ByteArray,
        val hardwareLevel: HardwareSecurityLevel,
        val containerSize: Int,
        val wrapNonce: ByteArray,
        val metadataNonce: ByteArray,
        val dataNonce: ByteArray
    )

    private val secureRandom = SecureRandom.getInstanceStrong()

    suspend fun encrypt(plainText: CharArray, password: CharArray): ByteArray = withContext(Dispatchers.Default) {
        val startTime = System.currentTimeMillis()
        Log.i(DIAGNOSTIC_TAG, "[ENCRYPT START] Invoked portable encryption sequence. Thread: ${Thread.currentThread().name}")

        var rawBytes: ByteArray? = null
        var storedBytes: ByteArray? = null
        var masterKey: ByteArray? = null
        var dynamicHkdfSalt: ByteArray? = null
        var ikm: ByteArray? = null
        var prk: ByteArray? = null
        var kek: ByteArray? = null
        var authKey: ByteArray? = null
        var dek: ByteArray? = null
        var salt: ByteArray? = null
        var wrapNonce: ByteArray? = null
        var metadataNonce: ByteArray? = null
        var dataNonce: ByteArray? = null
        var metadataKey: ByteArray? = null
        var hmacTag: ByteArray? = null
        var packet: ByteArray? = null
        var passwordBuffer: ByteBuffer? = null
        var plainHeader: ByteArray? = null
        var headerNonce: ByteArray? = null
        var headerKey: ByteArray? = null
        var metadata: ByteArray? = null
        val randomChunk = ByteArray(4096)

        try {
            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 1: Validating Password constraints")
            validatePasswordMilitary(password)

            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 2: Extracting plaintext UTF-8 bytes from CharArray")
            passwordBuffer = charArrayToDirectUtf8(plainText)
            rawBytes = directToByteArray(passwordBuffer)
            wipeDirectBuffer(passwordBuffer)

            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Plaintext extracted size: ${rawBytes.size} bytes")
            require(rawBytes!!.size <= maxPlaintextBytes) { "Plaintext exceeds max boundary" }

            val compressionId: Byte
            if (compressionEnabled) {
                Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 3: Compression enabled. Executing GZIP allocation")
                val compStart = System.currentTimeMillis()
                val candidate = gzipCompressFixed(rawBytes)
                Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Compression sub-task finished in ${System.currentTimeMillis() - compStart} ms")
                if (candidate != null && candidate.size < rawBytes.size) {
                    storedBytes = candidate
                    compressionId = COMPRESSION_GZIP
                    Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Compressed capacity savings payload: ${candidate.size} bytes")
                } else {
                    candidate?.let { wipeMilitary(it) }
                    storedBytes = rawBytes.copyOf()
                    compressionId = COMPRESSION_NONE
                    Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Compression sub-task bypassed (No space optimization)")
                }
            } else {
                storedBytes = rawBytes.copyOf()
                compressionId = COMPRESSION_NONE
            }

            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 4: Allocating primary containment structure of size: $containerSizeBytes bytes")
            packet = ByteArray(containerSizeBytes)

            salt = ByteArray(SALT_BYTES)
            headerNonce = ByteArray(HEADER_NONCE_BYTES)
            wrapNonce = ByteArray(NONCE_BYTES)
            metadataNonce = ByteArray(NONCE_BYTES)
            dataNonce = ByteArray(NONCE_BYTES)

            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 5: Sampling entropy from SecureRandom engine")
            secureRandom.nextBytes(salt)
            secureRandom.nextBytes(headerNonce)
            secureRandom.nextBytes(wrapNonce)
            secureRandom.nextBytes(metadataNonce)
            secureRandom.nextBytes(dataNonce)

            val hardwareLevel = HardwareSecurityLevel.SOFTWARE
            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 6: Operating in Hardware-Independent Software Level for Cross-Device Portability")

            plainHeader = ByteArray(HEADER_PLAINTEXT_BYTES).also {
                ByteBuffer.wrap(it).order(ByteOrder.BIG_ENDIAN)
                    .put(hardwareLevel.id)
                    .putInt(profile.iterations)
                    .putInt(profile.memoryKib)
                    .put(profile.parallelism.toByte())
                    .putInt(containerSizeBytes)
                    .put(wrapNonce)
                    .put(metadataNonce)
                    .put(dataNonce)
            }

            Log.i(DIAGNOSTIC_TAG, "[ENCRYPT] Step 7: Initiating KDF Master Key derivation block (${profile.pbkdf2Iterations} iterations)")
            val kdfStartTime = System.currentTimeMillis()
            masterKey = derivePbkdf2(password, salt, profile.pbkdf2Iterations)
            Log.i(DIAGNOSTIC_TAG, "[ENCRYPT] Master Key KDF segment completed in ${System.currentTimeMillis() - kdfStartTime} ms")

            headerKey = hkdfExpand(masterKey, DOMAIN_HEADER, KEY_BYTES)
            val headerAad = buildAad(DOMAIN_HEADER, salt, profile.id)

            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 8: Sealing structural header data envelope via AES-GCM")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(headerKey, "AES"), GCMParameterSpec(TAG_BITS, headerNonce))
            cipher.updateAAD(headerAad)

            val encryptedHeaderOffset = SALT_BYTES + 1 + HEADER_NONCE_BYTES
            cipher.doFinal(plainHeader, 0, plainHeader.size, packet, encryptedHeaderOffset)

            System.arraycopy(salt, 0, packet, 0, SALT_BYTES)
            packet[SALT_BYTES] = profile.id
            System.arraycopy(headerNonce, 0, packet, SALT_BYTES + 1, HEADER_NONCE_BYTES)

            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 9: Extracting subkeys via multi-domain HKDF engine")
            dynamicHkdfSalt = hmacSha512(HKDF_STATIC_CONTEXT, salt)
            ikm = combine(masterKey, null)
            prk = hkdfExtract(dynamicHkdfSalt, ikm)

            kek = hkdfExpand(prk, DOMAIN_KEK, KEY_BYTES)
            authKey = hkdfExpand(prk, DOMAIN_AUTH, KEY_BYTES)

            dek = ByteArray(KEY_BYTES)
            secureRandom.nextBytes(dek)

            val runningHeaderRef = ByteArray(HEADER_BYTES)
            System.arraycopy(packet, 0, runningHeaderRef, 0, HEADER_BYTES)

            var runningOffset = HEADER_BYTES

            val wrapAad = buildAad(DOMAIN_WRAP, runningHeaderRef, null)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(kek, "AES"), GCMParameterSpec(TAG_BITS, wrapNonce))
            cipher.updateAAD(wrapAad)
            cipher.doFinal(dek, 0, dek.size, packet, runningOffset)
            runningOffset += WRAPPED_DEK_BYTES

            metadata = ByteArray(METADATA_PLAINTEXT_BYTES)
            ByteBuffer.wrap(metadata).order(ByteOrder.BIG_ENDIAN)
                .putInt(storedBytes.size)
                .put(compressionId)

            val metadataAad = buildAad(DOMAIN_METADATA, runningHeaderRef, null)
            metadataKey = hkdfExpand(prk, DOMAIN_METADATA, KEY_BYTES)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(metadataKey, "AES"), GCMParameterSpec(TAG_BITS, metadataNonce))
            cipher.updateAAD(metadataAad)
            cipher.doFinal(metadata, 0, metadata.size, packet, runningOffset)
            runningOffset += METADATA_CIPHERTEXT_BYTES

            val dataRegionBytes = dataRegionSize(false)
            require(storedBytes.size <= dataRegionBytes) { "Data exceeds container capacity" }

            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 10: Filling raw data segment residual space with highly unpredictable noise")
            var bytesToFill = dataRegionBytes
            var fillingOffset = runningOffset
            while (bytesToFill > 0) {
                secureRandom.nextBytes(randomChunk)
                val chunkLen = minOf(bytesToFill, randomChunk.size)
                System.arraycopy(randomChunk, 0, packet, fillingOffset, chunkLen)
                fillingOffset += chunkLen
                bytesToFill -= chunkLen
            }

            System.arraycopy(storedBytes, 0, packet, runningOffset, storedBytes.size)

            val dataAad = buildAad(DOMAIN_DATA, runningHeaderRef, null,
                packet.copyOfRange(runningOffset - METADATA_CIPHERTEXT_BYTES - WRAPPED_DEK_BYTES, runningOffset - METADATA_CIPHERTEXT_BYTES),
                packet.copyOfRange(runningOffset - METADATA_CIPHERTEXT_BYTES, runningOffset)
            )

            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 11: Encrypting payload space with Data Encryption Key (DEK)")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(TAG_BITS, dataNonce))
            cipher.updateAAD(dataAad)
            cipher.doFinal(packet, runningOffset, dataRegionBytes, packet, runningOffset)

            // AES-GCM writes ciphertext PLUS a 16-byte authentication tag.
            // The dataRegionBytes variable is only the plaintext/data-region size;
            // after doFinal(), the written output length is dataRegionBytes + TAG_BYTES.
            // If we advance only by dataRegionBytes, the final HMAC is written 16 bytes too early
            // and overwrites the GCM tag. That produces a portable file with a valid header
            // but a failing outer HMAC on the receiving phone.
            runningOffset += dataRegionBytes + TAG_BYTES

            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Step 12: Generating final authenticating outer-shell signature (HMAC)")
            Log.d("DEBUG_HMAC", "[ENCRYPT_DEBUG] Key Length: ${authKey?.size}, Data Length: $runningOffset")
            hmacTag = hmacSha512ZeroCopy(authKey, packet, runningOffset)
            System.arraycopy(hmacTag, 0, packet, runningOffset, HMAC_BYTES)

            Log.i(DIAGNOSTIC_TAG, "[ENCRYPT COMPLETE] Total portable transformation sequence successful. Time elapsed: ${System.currentTimeMillis() - startTime} ms")
            packet
        } catch (e: Throwable) {
            Log.e(DIAGNOSTIC_TAG, "!!! CRITICAL CRASH DETECTED IN ENCRYPT ENGINE CORE !!!", e)
            throw java.security.GeneralSecurityException("Encryption engine failure: ${e.message}", e)
        } finally {
            Log.d(DIAGNOSTIC_TAG, "[ENCRYPT] Cleaning and zeroing temporary high-entropy raw arrays from volatile memory")
            wipeMilitary(rawBytes)
            wipeMilitary(storedBytes)
            wipeMilitary(masterKey)
            wipeMilitary(dynamicHkdfSalt)
            wipeMilitary(ikm)
            wipeMilitary(prk)
            wipeMilitary(kek)
            wipeMilitary(authKey)
            wipeMilitary(dek)
            wipeMilitary(metadataKey)
            wipeMilitary(hmacTag)
            wipeMilitary(plainHeader)
            wipeMilitary(headerNonce)
            wipeMilitary(headerKey)
            wipeMilitary(metadata)
            wipeMilitary(randomChunk)
            password.fill('\u0000')
        }
    }

    suspend fun decryptAndConsume(packet: ByteArray, password: CharArray, consumer: (CharArray) -> Unit): Unit = withContext(Dispatchers.Default) {
        val startTime = System.currentTimeMillis()
        Log.i(DIAGNOSTIC_TAG, "[DECRYPT START] Invoked verification/decryption sequence. Thread: ${Thread.currentThread().name}")

        var masterKey: ByteArray? = null
        var dynamicHkdfSalt: ByteArray? = null
        var ikm: ByteArray? = null
        var prk: ByteArray? = null
        var kek: ByteArray? = null
        var authKey: ByteArray? = null
        var dek: ByteArray? = null
        var outputBytes: ByteArray? = null
        var stored: ByteArray? = null
        var charResult: CharArray? = null
        var salt: ByteArray? = null
        var headerNonce: ByteArray? = null
        var encryptedHeader: ByteArray? = null
        var plainHeader: ByteArray? = null
        var headerKey: ByteArray? = null
        var metadata: ByteArray? = null
        var decryptedPayloadSpace: ByteArray? = null

        try {
            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Step 1: Performing validation checks")
            validatePasswordMilitary(password)

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Structural package boundary assessment: ${packet.size} bytes")
            if (packet.size < MIN_CONTAINER_SIZE_BYTES || packet.size > MAX_CONTAINER_SIZE_BYTES) {
                Log.e(DIAGNOSTIC_TAG, "[DECRYPT ERROR] Package dimension violations triggered. Size parameters out of bounds.")
                return@withContext
            }

            salt = packet.copyOfRange(0, SALT_BYTES)
            val profileId = packet[SALT_BYTES]
            headerNonce = packet.copyOfRange(SALT_BYTES + 1, SALT_BYTES + 1 + HEADER_NONCE_BYTES)
            encryptedHeader = packet.copyOfRange(SALT_BYTES + 1 + HEADER_NONCE_BYTES, HEADER_BYTES)

            val parsedProfile = SecurityProfile.values().firstOrNull { it.id == profileId }
            if (parsedProfile == null) {
                Log.e(DIAGNOSTIC_TAG, "[DECRYPT ERROR] Structural verification failed. Unknown Security Profile Byte: $profileId")
                return@withContext
            }
            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Target metadata Profile detected: ${parsedProfile.name}")

            Log.i(DIAGNOSTIC_TAG, "[DECRYPT] Step 2: Running baseline KDF sequence for Header Isolation Envelope (${parsedProfile.pbkdf2Iterations} iterations)")
            val kdfStart = System.currentTimeMillis()
            masterKey = derivePbkdf2(password, salt, parsedProfile.pbkdf2Iterations)
            Log.i(DIAGNOSTIC_TAG, "[DECRYPT] Header KDF derivation processing complete in ${System.currentTimeMillis() - kdfStart} ms")

            headerKey = hkdfExpand(masterKey, DOMAIN_HEADER, KEY_BYTES)
            val headerAad = buildAad(DOMAIN_HEADER, salt, profileId)

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Step 3: Decrypting primary configuration packet header layout")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(headerKey, "AES"), GCMParameterSpec(TAG_BITS, headerNonce))
            cipher.updateAAD(headerAad)
            plainHeader = cipher.doFinal(encryptedHeader)
            wipeMilitary(headerKey)

            if (plainHeader == null) {
                Log.e(DIAGNOSTIC_TAG, "[DECRYPT ERROR] Cipher evaluation layer returned a null structural descriptor block")
                return@withContext
            }

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Step 4: Extracting binary manifest map rules from decrypted block")
            val parsed = parsePlainHeader(plainHeader, salt, parsedProfile)
            if (parsed == null) {
                Log.e(DIAGNOSTIC_TAG, "[DECRYPT ERROR] Logical interpretation failed. Parsed values failed structural sanity tests.")
                return@withContext
            }
            wipeMilitary(plainHeader)

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Container specifications mapping -> Expected: ${parsed.containerSize} bytes, Received: ${packet.size} bytes")
            if (parsed.containerSize != packet.size) {
                Log.e(DIAGNOSTIC_TAG, "[DECRYPT ERROR] Target structural sizing variance anomaly discovered. Termination forced.")
                return@withContext
            }

            if (parsed.hardwareLevel != HardwareSecurityLevel.SOFTWARE) {
                Log.e(DIAGNOSTIC_TAG, "[DECRYPT ERROR] Secure Hardware layer found in header manifest. This engine variation handles portable software structures exclusively.")
                return@withContext
            }

            val offset = HEADER_BYTES

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Step 6: Regenerating subkeys for operational domains")
            dynamicHkdfSalt = hmacSha512(HKDF_STATIC_CONTEXT, parsed.salt)
            ikm = combine(masterKey, null)
            prk = hkdfExtract(dynamicHkdfSalt, ikm)
            kek = hkdfExpand(prk, DOMAIN_KEK, KEY_BYTES)
            authKey = hkdfExpand(prk, DOMAIN_AUTH, KEY_BYTES)

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Step 7: Performing full authentication scan via structural HMAC validation")
            val bodyLength = packet.size - HMAC_BYTES
            Log.d("DEBUG_HMAC", "[DECRYPT_DEBUG] Key Length: ${authKey?.size}, Data Length: $bodyLength")
            val receivedHmac = packet.copyOfRange(bodyLength, packet.size)
            val calculatedHmac = hmacSha512ZeroCopy(authKey, packet, bodyLength)

            if (!MessageDigest.isEqual(receivedHmac, calculatedHmac)) {
                Log.e(DIAGNOSTIC_TAG, "!!! SECURITY WARNING: CRYPTOGRAPHIC MAC VERIFICATION REJECTED. CONTAINER TAMPERING DETECTED !!!")
                wipeMilitary(receivedHmac)
                wipeMilitary(calculatedHmac)
                return@withContext
            }
            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Outer HMAC envelope verified. Packet integrity: 100% Intact")

            val wrappedDekOffset = offset
            val metadataCiphertextOffset = offset + WRAPPED_DEK_BYTES

            val runningHeaderRef = packet.copyOfRange(0, HEADER_BYTES)
            val wrapAad = buildAad(DOMAIN_WRAP, runningHeaderRef, null)

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Step 8: Decrypting Data Encryption Key wrapper")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(kek, "AES"), GCMParameterSpec(TAG_BITS, parsed.wrapNonce))
            cipher.updateAAD(wrapAad)
            dek = cipher.doFinal(packet, wrappedDekOffset, WRAPPED_DEK_BYTES)

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Step 9: Decrypting metadata records segment")
            val metadataKey = hkdfExpand(prk, DOMAIN_METADATA, KEY_BYTES)
            val metadataAad = buildAad(DOMAIN_METADATA, runningHeaderRef, null)

            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(metadataKey, "AES"), GCMParameterSpec(TAG_BITS, parsed.metadataNonce))
            cipher.updateAAD(metadataAad)
            metadata = cipher.doFinal(packet, metadataCiphertextOffset, METADATA_CIPHERTEXT_BYTES)
            wipeMilitary(metadataKey)

            if (metadata == null) {
                Log.e(DIAGNOSTIC_TAG, "[DECRYPT ERROR] Metadata payload decryption validation failed")
                return@withContext
            }

            val metaBuffer = ByteBuffer.wrap(metadata).order(ByteOrder.BIG_ENDIAN)
            val storedLength = metaBuffer.int
            val compressionId = metaBuffer.get()
            wipeMilitary(metadata)

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Manifest details discovered -> Payload: $storedLength bytes, Compression Code: $compressionId")

            val payloadDataOffset = metadataCiphertextOffset + METADATA_CIPHERTEXT_BYTES
            val dataCiphertextSize = bodyLength - payloadDataOffset
            if (storedLength < 0 || storedLength > dataCiphertextSize - TAG_BYTES || storedLength > maxPlaintextBytes) {
                Log.e(DIAGNOSTIC_TAG, "[DECRYPT ERROR] Extracted spatial sizing constraints do not match baseline profile map rules")
                return@withContext
            }

            val dataAad = buildAad(DOMAIN_DATA, runningHeaderRef, null,
                packet.copyOfRange(wrappedDekOffset, wrappedDekOffset + WRAPPED_DEK_BYTES),
                packet.copyOfRange(metadataCiphertextOffset, metadataCiphertextOffset + METADATA_CIPHERTEXT_BYTES)
            )

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Step 10: Executing full text payload zone decryption using DEK matrix")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(TAG_BITS, parsed.dataNonce))
            cipher.updateAAD(dataAad)

            decryptedPayloadSpace = cipher.doFinal(packet, payloadDataOffset, dataCiphertextSize)
            stored = ByteArray(storedLength)
            System.arraycopy(decryptedPayloadSpace, 0, stored, 0, storedLength)

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Step 11: Assessing decompression transformation filters")
            outputBytes = when (compressionId) {
                COMPRESSION_NONE -> stored.copyOf()
                COMPRESSION_GZIP -> {
                    val decompStart = System.currentTimeMillis()
                    val result = gzipDecompressFixed(stored, maxPlaintextBytes)
                    Log.d(DIAGNOSTIC_TAG, "[DECRYPT] GZIP expansion processing finished in ${System.currentTimeMillis() - decompStart} ms")
                    result ?: return@withContext
                }
                else -> {
                    Log.e(DIAGNOSTIC_TAG, "[DECRYPT ERROR] Unrecognized compression signature header code discovered.")
                    return@withContext
                }
            }

            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Step 12: Converting unencrypted payload block back into CharBuffer safely")
            charResult = decodeUtf8ToCharArray(outputBytes)

            Log.i(DIAGNOSTIC_TAG, "[DECRYPT COMPLETE] Entire portable sequence completed successfully. Invoking final consumption lambda. Time elapsed: ${System.currentTimeMillis() - startTime} ms")
            consumer(charResult)

        } catch (e: Exception) {
            Log.e(DIAGNOSTIC_TAG, "!!! INTERNAL DECRYPTION PIPELINE TERMINATED BY EXCEPTION UNCAUGHT !!!", e)
        } finally {
            Log.d(DIAGNOSTIC_TAG, "[DECRYPT] Executing scrub cleaning sweeps across system memory tracks")
            wipeMilitary(masterKey)
            wipeMilitary(dynamicHkdfSalt)
            wipeMilitary(ikm)
            wipeMilitary(prk)
            wipeMilitary(kek)
            wipeMilitary(authKey)
            wipeMilitary(dek)
            wipeMilitary(stored)
            wipeMilitary(outputBytes)
            wipeMilitary(salt)
            wipeMilitary(headerNonce)
            wipeMilitary(encryptedHeader)
            wipeMilitary(plainHeader)
            wipeMilitary(headerKey)
            wipeMilitary(metadata)
            wipeMilitary(decryptedPayloadSpace)
            charResult?.fill('\u0000')
            password.fill('\u0000')
        }
    }

    private fun parsePlainHeader(plainHeader: ByteArray, salt: ByteArray, parsedProfile: SecurityProfile): ParsedHeader? {
        if (plainHeader.size != HEADER_PLAINTEXT_BYTES) return null
        val buffer = ByteBuffer.wrap(plainHeader).order(ByteOrder.BIG_ENDIAN)

        val hardwareId = buffer.get().toInt() and 0xff
        val iterations = buffer.int
        val memoryKib = buffer.int
        val parallelism = buffer.get().toInt() and 0xff
        val containerSize = buffer.int

        var valid = 1
        valid = valid and if (hardwareId <= HardwareSecurityLevel.STRONGBOX.id.toInt()) 1 else 0
        valid = valid and if (containerSize in MIN_CONTAINER_SIZE_BYTES..MAX_CONTAINER_SIZE_BYTES) 1 else 0
        valid = valid and if (iterations in 1..MAX_PROFILE_ITERATIONS) 1 else 0
        valid = valid and if (memoryKib in (16 * 1024)..MAX_PROFILE_MEMORY_KIB) 1 else 0
        valid = valid and if (parallelism in 1..MAX_PROFILE_PARALLELISM) 1 else 0

        val policy = SecurityProfile.from(parsedProfile.id, iterations, memoryKib, parallelism)
        valid = valid and if (policy != null) 1 else 0

        val wrapNonce = ByteArray(NONCE_BYTES)
        val metadataNonce = ByteArray(NONCE_BYTES)
        val dataNonce = ByteArray(NONCE_BYTES)
        buffer.get(wrapNonce)
        buffer.get(metadataNonce)
        buffer.get(dataNonce)

        if (valid == 0) {
            Log.w(DIAGNOSTIC_TAG, "[HEADER VALIDATION FAILED] Structural data corruption rules violated inside plaintext header container properties.")
            return null
        }

        return ParsedHeader(
            salt, HardwareSecurityLevel.values()[hardwareId],
            containerSize, wrapNonce, metadataNonce, dataNonce
        )
    }

    private fun buildAad(
        domain: ByteArray, header: ByteArray, hardwareEnvelope: ByteArray? = null,
        wrappedDek: ByteArray? = null, metadataCiphertext: ByteArray? = null
    ): ByteArray {
        val aad = ByteArray(domain.size + header.size + (hardwareEnvelope?.size ?: 0) + (wrappedDek?.size ?: 0) + (metadataCiphertext?.size ?: 0))
        var offset = 0
        System.arraycopy(domain, 0, aad, offset, domain.size); offset += domain.size
        System.arraycopy(header, 0, aad, offset, header.size); offset += header.size
        hardwareEnvelope?.let { System.arraycopy(it, 0, aad, offset, it.size); offset += it.size }
        wrappedDek?.let { System.arraycopy(it, 0, aad, offset, it.size); offset += it.size }
        metadataCiphertext?.let { System.arraycopy(it, 0, aad, offset, it.size) }
        return aad
    }

    private fun buildAad(domain: ByteArray, salt: ByteArray, profileId: Byte): ByteArray {
        val aad = ByteArray(domain.size + salt.size + 1)
        System.arraycopy(domain, 0, aad, 0, domain.size)
        System.arraycopy(salt, 0, aad, domain.size, salt.size)
        aad[domain.size + salt.size] = profileId
        return aad
    }

    private fun derivePbkdf2(password: CharArray, salt: ByteArray, iterations: Int): ByteArray {
        val spec = PBEKeySpec(password, salt, iterations, KEY_BYTES * 8)
        var raw: ByteArray? = null
        try {
            val generated = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM).generateSecret(spec)
            raw = generated?.encoded
        } catch (e: Exception) {
            Log.w(DIAGNOSTIC_TAG, "[KDF ROUTER] Native SecretKeyFactory instantiation threw exception: ${e.message}. Routing processing tasks into local fallback loop.")
        }

        if (raw == null || raw.isEmpty()) {
            var passwordBytes: ByteArray? = null
            var uCurrent: ByteArray? = null
            var uNext: ByteArray? = null
            var t: ByteArray? = null
            val sAndI = ByteArray(salt.size + 4)
            try {
                val charBuffer = CharBuffer.wrap(password)
                val byteBuffer = Charsets.UTF_8.encode(charBuffer)
                passwordBytes = ByteArray(byteBuffer.remaining())
                byteBuffer.get(passwordBytes)
                if (byteBuffer.hasArray()) {
                    byteBuffer.array().fill(0)
                }

                val mac = Mac.getInstance("HmacSHA512")
                mac.init(SecretKeySpec(passwordBytes, "HmacSHA512"))

                System.arraycopy(salt, 0, sAndI, 0, salt.size)
                sAndI[sAndI.size - 4] = 0
                sAndI[sAndI.size - 3] = 0
                sAndI[sAndI.size - 2] = 0
                sAndI[sAndI.size - 1] = 1

                val initialCurrent = mac.doFinal(sAndI)
                uCurrent = initialCurrent
                t = initialCurrent.copyOf()

                val localNext = ByteArray(mac.macLength)
                uNext = localNext

                var currentRef = initialCurrent
                var nextRef = localNext

                for (j in 2..iterations) {
                    mac.update(currentRef)
                    mac.doFinal(nextRef, 0)
                    for (k in t.indices) {
                        t[k] = (t[k].toInt() xor nextRef[k].toInt()).toByte()
                    }
                    val temp = currentRef
                    currentRef = nextRef
                    nextRef = temp
                }

                uCurrent = currentRef
                uNext = nextRef
                raw = t.copyOfRange(0, KEY_BYTES)
            } finally {
                wipeMilitary(passwordBytes)
                wipeMilitary(uCurrent)
                wipeMilitary(uNext)
                wipeMilitary(t)
                wipeMilitary(sAndI)
            }
        }

        return try {
            raw!!.copyOf()
        } finally {
            spec.clearPassword()
            raw?.fill(0)
        }
    }

    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val hmac = Mac.getInstance("HmacSHA512")
        hmac.init(SecretKeySpec(salt, "HmacSHA512"))
        return hmac.doFinal(ikm)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        val hmac = Mac.getInstance("HmacSHA512")
        val output = ByteArray(outputLength)
        var previous = ByteArray(0)
        var position = 0
        var counter = 1

        return try {
            while (position < outputLength) {
                hmac.init(SecretKeySpec(prk, "HmacSHA512"))
                hmac.update(previous)
                hmac.update(info)
                hmac.update(counter.toByte())
                val block = hmac.doFinal()
                val amount = minOf(block.size, outputLength - position)
                System.arraycopy(block, 0, output, position, amount)
                wipeMilitary(previous)
                previous = block
                position += amount
                counter++
            }
            output
        } finally {
            wipeMilitary(previous)
        }
    }

    private fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray {
        val hmac = Mac.getInstance("HmacSHA512")
        hmac.init(SecretKeySpec(key, "HmacSHA512"))
        return hmac.doFinal(data)
    }

    private fun hmacSha512ZeroCopy(key: ByteArray, packet: ByteArray, length: Int): ByteArray {
        val hmac = Mac.getInstance("HmacSHA512")
        hmac.init(SecretKeySpec(key, "HmacSHA512"))
        hmac.update(packet, 0, length)
        return hmac.doFinal()
    }

    private fun combine(first: ByteArray, second: ByteArray?): ByteArray {
        if (second == null) return first.copyOf()
        return ByteArray(first.size + second.size).apply {
            System.arraycopy(first, 0, this, 0, first.size)
            System.arraycopy(second, 0, this, first.size, second.size)
        }
    }

    private class FixedByteArrayOutputStream(private val buffer: ByteArray) : OutputStream() {
        var count = 0
            private set
        override fun write(b: Int) {
            if (count >= buffer.size) throw java.lang.IllegalStateException("Buffer Overflow")
            buffer[count++] = b.toByte()
        }
        override fun write(b: ByteArray, off: Int, len: Int) {
            if (count + len > buffer.size) throw java.lang.IllegalStateException("Buffer Overflow")
            System.arraycopy(b, off, buffer, count, len)
            count += len
        }
    }

    private fun gzipCompressFixed(bytes: ByteArray): ByteArray? {
        val maxAlloc = bytes.size + GZIP_OVERHEAD_BYTES
        val fixedBuffer = ByteArray(maxAlloc)
        return try {
            val fbaos = FixedByteArrayOutputStream(fixedBuffer)
            GZIPOutputStream(fbaos).use { it.write(bytes) }
            fixedBuffer.copyOfRange(0, fbaos.count)
        } catch (_: Exception) {
            null
        } finally {
            wipeMilitary(fixedBuffer)
        }
    }

    private fun gzipDecompressFixed(bytes: ByteArray, maxOutput: Int): ByteArray? {
        val fixedBuffer = ByteArray(maxOutput)
        return try {
            var total = 0
            GZIPInputStream(ByteArrayInputStream(bytes)).use { gzip ->
                val chunk = ByteArray(8192)
                while (true) {
                    val count = gzip.read(chunk)
                    if (count < 0) break
                    if (total + count > maxOutput) throw IllegalArgumentException("Decompression limit exceeded")
                    System.arraycopy(chunk, 0, fixedBuffer, total, count)
                    total += count
                }
                wipeMilitary(chunk)
            }
            fixedBuffer.copyOfRange(0, total)
        } catch (_: Exception) {
            null
        } finally {
            wipeMilitary(fixedBuffer)
        }
    }

    private fun charArrayToDirectUtf8(chars: CharArray): ByteBuffer {
        val output = ByteBuffer.allocateDirect((chars.size * 4) + 4)
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val resEncode = encoder.encode(CharBuffer.wrap(chars), output, true)
        if (resEncode.isError) resEncode.throwException()
        val resFlush = encoder.flush(output)
        if (resFlush.isError) resFlush.throwException()
        output.flip()
        return output
    }

    private fun directToByteArray(buffer: ByteBuffer): ByteArray {
        val duplicate = buffer.duplicate()
        return ByteArray(duplicate.remaining()).also { duplicate.get(it) }
    }

    private fun decodeUtf8ToCharArray(bytes: ByteArray): CharArray {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val buffer = CharBuffer.allocate(bytes.size)
        val resDecode = decoder.decode(ByteBuffer.wrap(bytes), buffer, true)
        if (resDecode.isError) resDecode.throwException()
        val resFlush = decoder.flush(buffer)
        if (resFlush.isError) resFlush.throwException()
        buffer.flip()
        return CharArray(buffer.remaining()).also {
            buffer.get(it)
            buffer.array().fill('\u0000')
        }
    }

    private fun validatePasswordMilitary(password: CharArray) {
        require(password.size in MIN_PASSWORD_CHARS..MAX_PASSWORD_CHARS) { "Invalid length" }
    }

    private fun dataRegionSize(hardwareEnabled: Boolean): Int {
        return containerSizeBytes - HEADER_BYTES -
                (if (hardwareEnabled) 56 else 0) - // 56 represents previous hardcoded HARDWARE_ENVELOPE_BYTES reference
                WRAPPED_DEK_BYTES - METADATA_CIPHERTEXT_BYTES - TAG_BYTES - HMAC_BYTES
    }

    private fun wipeDirectBuffer(buffer: ByteBuffer?) {
        if (buffer == null || !buffer.isDirect) return
        buffer.rewind()
        while (buffer.hasRemaining()) buffer.put(0)
        buffer.rewind()
    }

    private fun wipeMilitary(bytes: ByteArray?) {
        if (bytes == null) return
        bytes.fill(0x00.toByte())
        bytes.fill(0xFF.toByte())
        bytes.fill(0x00.toByte())
    }
}