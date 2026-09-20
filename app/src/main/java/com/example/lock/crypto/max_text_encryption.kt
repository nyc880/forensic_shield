package com.example.lock.crypto

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// =====================================================================================
//  MAX TEXT ENCRYPTION ENGINE  (container format "MX2")
//
//  Pure software construction. No Android Keystore, no StrongBox, no native library,
//  no third party dependency: Argon2id (RFC 9106), BLAKE2b, XChaCha20-Poly1305
//  (draft-irtf-cfrg-xchacha-03), HKDF-SHA-512 (RFC 5869) and HMAC-SHA-512 are either
//  implemented inside this file or provided by the JDK. AES-256-GCM is provided by the
//  platform provider (javax.crypto) and is used only as the outer cascade layer and as
//  the data key wrapper.
//
//  ---------------------------------------------------------------------------------
//  KEY SCHEDULE
//  ---------------------------------------------------------------------------------
//  KDF-1  Argon2id(password, saltPrimary, profile.primary*, secret = pepper,
//                    associatedData = DOMAIN_KDF_PRIMARY)  -> masterKey (32 B)
//  KDF-2  Argon2id(password, saltSecondary, profile.secondary*, secret = pepper,
//                    associatedData = DOMAIN_KDF_SECONDARY) -> wrapKey   (32 B)
//
//  masterKey  -> HKDF-SHA-512 -> headerKey (32 B)   seals the header
//                             -> authKey   (64 B)   outer HMAC-SHA-512 key
//  dek        -> 32 random bytes per message, stored wrapped:
//                    wrappedDek = AES-256-GCM(wrapKey, wrapNonce, dek)
//  innerKey   -> HKDF-SHA-512(ikm = masterKey || dek, salt = entropyBlob,
//                             info = DOMAIN_INNER)      (32 B)
//  outerKey   -> dek itself (AES-256-GCM)
//
//  The payload therefore needs BOTH derivations: KDF-1 supplies masterKey (header and
//  authentication) and takes part in innerKey, while KDF-2 protects the only copy of the
//  random dek that the inner key and the outer AES layer depend on. Breaking one
//  primitive or one key derivation is not sufficient to recover the plaintext.
//
//  ---------------------------------------------------------------------------------
//  CONTAINER LAYOUT  (all integers big endian)
//  ---------------------------------------------------------------------------------
//  CLEARTEXT PREFIX - 128 bytes
//     offset size field
//          0    1  magic0                0x4D ('M')
//          1    1  magic1                0x58 ('X')
//          2    1  formatId              0x02
//          3    1  profileId             MaxCryptoProfile id (KDF parameters, enum bound)
//          4    1  flags                 0x00 (reserved, always zero)
//          5    1  reserved              0x00
//          6   24  headerNonce           XChaCha20-Poly1305 nonce of the header layer
//         30   32  saltPrimary           Argon2id salt for KDF-1
//         62   32  saltSecondary         Argon2id salt for KDF-2
//         94   32  entropyBlob           per message entropy, mixed into every subkey
//        126    2  reserved              0x0000
//
//  ENCRYPTED HEADER - 160 bytes plaintext / 176 bytes ciphertext
//          0    4  containerSize         total container size in bytes
//          4    4  payloadLength         real payload length before padding
//          8    1  compressionFlag       0x00 none, 0x01 gzip
//          9    1  paddingPolicy         MaxPaddingPolicy id used by the sender
//         10    2  reserved              0x0000
//         12   24  dataNonce             XChaCha20-Poly1305 nonce of the inner layer
//         36   12  wrapNonce             AES-256-GCM nonce of the dek wrapper
//         48   12  outerNonce            AES-256-GCM nonce of the outer cascade layer
//         60    8  creationTimeMillis    sender wall clock, informational only
//         68   92  reserved              zeros
//
//  BODY
//     wrappedDek  48 bytes   AES-256-GCM ciphertext of the 32 byte dek, tag included
//     payload     n bytes    AES-256-GCM( XChaCha20-Poly1305( paddedPayload ) )
//     hmac        64 bytes   HMAC-SHA-512 over every preceding byte of the container
//
//  Total overhead = 128 + 176 + 48 + 16 + 16 + 64 = 448 bytes.
//  The payload region absorbs the padding: encryptedPayloadLength = containerSize - 448.
//  Padding bytes are produced by SecureRandom, so the padding region is never a run of
//  zeros and carries no length trailer that could be read before authentication.
//
//  ---------------------------------------------------------------------------------
//  AUTHENTICATION / ASSOCIATED DATA
//  ---------------------------------------------------------------------------------
//  headerAad = DOMAIN_HEADER  || prefix
//  wrapAad   = DOMAIN_WRAP    || prefix || encryptedHeader
//  innerAad  = DOMAIN_INNER   || prefix || encryptedHeader || wrappedDek
//  outerAad  = DOMAIN_OUTER   || prefix || encryptedHeader || wrappedDek || innerTag
//  hmac input = the whole container minus the trailing 64 byte tag
//  Verification order on decryption: HMAC first (cheapest rejection), then the header,
//  then the dek unwrap, then the outer and the inner layer.
// =====================================================================================

/** Cost profiles. The identifier travels in the clear inside the prefix, but every
 *  parameter is bound to the enum: a hostile container can never request a weaker or
 *  more expensive derivation than the ones declared here. */
enum class MaxCryptoProfile(
    val id: Byte,
    /** Argon2id memory cost of KDF-1 in KiB. */
    val primaryMemoryKib: Int,
    /** Argon2id time cost of KDF-1. */
    val primaryIterations: Int,
    /** Argon2id parallelism (lanes) of KDF-1. */
    val primaryLanes: Int,
    /** Argon2id memory cost of KDF-2 in KiB. */
    val secondaryMemoryKib: Int,
    /** Argon2id time cost of KDF-2. */
    val secondaryIterations: Int,
    /** Argon2id parallelism (lanes) of KDF-2. */
    val secondaryLanes: Int
) {
    /** 64 MiB / 32 MiB - entry level devices with a small heap. */
    MOBILE_HARDENED(0x01, 64 * 1024, 6, 4, 32 * 1024, 6, 4),

    /** 128 MiB / 64 MiB, t = 10, p = 4 - the reference "MAX" profile. */
    MOBILE_MAXIMUM(0x02, 128 * 1024, 10, 4, 64 * 1024, 10, 4),

    /** 256 MiB / 128 MiB, t = 12, p = 4 - large heap devices and desktops. */
    STATIONARY_PARANOID(0x03, 256 * 1024, 12, 4, 128 * 1024, 12, 4);

    /** Peak heap needed while one derivation runs, in bytes. */
    val peakDerivationBytes: Long
        get() = maxOf(primaryMemoryKib, secondaryMemoryKib).toLong() * 1024L

    /** Bytes that must be resident if the two derivations are not separated by a GC. */
    val cumulativeDerivationBytes: Long
        get() = (primaryMemoryKib.toLong() + secondaryMemoryKib.toLong()) * 1024L

    companion object {
        private val ALL = values()

        fun fromId(id: Byte): MaxCryptoProfile? = ALL.firstOrNull { it.id == id }
    }
}

/** How the payload is padded before encryption. */
enum class MaxPaddingPolicy(val id: Byte) {
    /** Pad up to the next size bucket: every container inside a bucket has the same
     *  size, which hides the plaintext length but also reveals the bucket itself. */
    BUCKET_EXACT(0x01),

    /** Pad to a uniformly random size between the required size and the next bucket.
     *  No two containers share a size class, at the cost of leaking a lower bound. */
    BUCKET_RANDOMIZED(0x02);

    companion object {
        private val ALL = values()

        fun fromId(id: Byte): MaxPaddingPolicy? = ALL.firstOrNull { it.id == id }
    }
}

/** Supplies the application level pepper (Argon2id "secret" input).
 *
 *  The engine zeroes the array it receives, therefore the implementation MUST return a
 *  fresh copy on every call.
 *
 *  Threat model note: a pepper compiled into the APK is recoverable by anyone who
 *  reverse engineers the application, so it only raises the cost for an attacker who
 *  holds the container without the APK. A pepper stored in application private storage
 *  is device bound and permanently prevents containers from being opened on another
 *  device or after a reinstall. Both cases are documented trade offs; the default is
 *  no pepper at all. */
fun interface MaxPepperSource {

    /** Returns a fresh copy of the pepper; an empty array means "no pepper". */
    fun pepper(): ByteArray

    companion object {
        val NONE: MaxPepperSource = MaxPepperSource { ByteArray(0) }

        /** Fixed pepper (for example a build time constant). Used only if unavoidable. */
        fun constant(pepper: ByteArray): MaxPepperSource =
            MaxPepperSource { pepper.copyOf() }
    }
}

enum class MaxLogLevel { DEBUG, INFO, WARN, ERROR }

/** Logging hook. The engine never touches android.util.Log directly so that it stays a
 *  plain JVM file: the application decides where the messages go. */
fun interface MaxEngineLogger {

    fun log(level: MaxLogLevel, message: String)

    companion object {
        val SILENT: MaxEngineLogger = MaxEngineLogger { _, _ -> }
    }
}

/** Coarse progress stages. Both derivations dominate the total runtime, so the listener
 *  is also called with the fraction of the running derivation when it advances. */
enum class MaxEngineStage {
    PRIMARY_DERIVATION,
    SECONDARY_DERIVATION,
    HEADER_PROCESSING,
    PAYLOAD_ENCRYPTION,
    INTEGRITY_CHECK,
    PAYLOAD_DECRYPTION,
    FINALIZING
}

fun interface MaxProgressListener {
    fun onProgress(stage: MaxEngineStage, fraction: Float)
}

/** Why a decryption attempt did not produce plaintext. */
enum class MaxFailureReason {
    MALFORMED_CONTAINER,
    UNSUPPORTED_VERSION,
    UNSUPPORTED_PROFILE,
    AUTHENTICATION_FAILED,
    RESOURCE_EXHAUSTED,
    INTERNAL_ERROR
}

/** Result of [MaxTextEncryptionEngine.decrypt]. The plaintext is handed over as a
 *  CharArray: the caller owns it and must wipe it when it is no longer needed. */
sealed class MaxDecryptionResult {

    class Success(val plaintext: CharArray) : MaxDecryptionResult()

    class Failure(val reason: MaxFailureReason, val detail: String? = null) : MaxDecryptionResult()

    val isSuccess: Boolean get() = this is Success
}

/** Raised for configuration errors, insufficient heap and internal crypto failures. */
class MaxCryptoException(message: String, cause: Throwable? = null) :
    GeneralSecurityException(message, cause)

/**
 * Password based text encryption engine with a dual Argon2id key schedule and a
 * XChaCha20-Poly1305 / AES-256-GCM cascade.
 *
 * Every operation is blocking, it must run off the main thread ([encryptAsync] and
 * [decryptAndConsumeAsync] do that). The reference profile allocates 128 MiB and
 * 64 MiB of mutable heap and takes seconds to minutes on a phone, which is the
 * intended trade off: the caller shows progress through [MaxProgressListener].
 */
class MaxTextEncryptionEngine(
    /** Cost profile used for encryption. Decryption follows the id stored in the prefix. */
    private val profile: MaxCryptoProfile = MaxCryptoProfile.MOBILE_MAXIMUM,
    /** Padding policy used for encryption. Decryption follows the id stored in the header. */
    private val paddingPolicy: MaxPaddingPolicy = MaxPaddingPolicy.BUCKET_RANDOMIZED,
    /** Apply gzip when it really shrinks the payload.
     *
     *  Disabled by default: zlib keeps the uncompressed bytes in native buffers that
     *  the engine cannot wipe, and the padding engine already hides the payload length.
     *  Enable it when container size matters more than that residue. */
    private val compressionEnabled: Boolean = false,
    /** Optional Argon2id secret. See [MaxPepperSource] before enabling it. */
    private val pepperSource: MaxPepperSource = MaxPepperSource.NONE,
    /** Diagnostics sink, [MaxEngineLogger.SILENT] by default. */
    private val logger: MaxEngineLogger = MaxEngineLogger.SILENT,
    /** Run a GC between the two derivations so the 128 MiB block is released before the
     *  64 MiB block is requested. Disable it only if the device heap is known to hold
     *  both allocations at the same time. */
    private val reclaimHeapBetweenDerivations: Boolean = true,
    /** Zero the password array supplied by the caller. */
    private val wipeCallerPassword: Boolean = true,
    /** Profiles accepted while decrypting. A container names its profile in its
     *  cleartext prefix, so this is the only knob a hostile file could use to pick the
     *  cost of the derivation: narrow it when containers only ever come from this build. */
    private val acceptedProfiles: Set<MaxCryptoProfile> = MaxCryptoProfile.values().toSet(),
    private val maxPlaintextBytes: Int = DEFAULT_MAX_PLAINTEXT_BYTES,
    private val maxContainerBytes: Int = DEFAULT_MAX_CONTAINER_BYTES
) {

    companion object {
        const val FORMAT_ID: Byte = 0x02

        const val SUPPORTED_PREFIX_BYTES = 128
        const val HEADER_PLAINTEXT_BYTES = 160
        const val HEADER_CIPHERTEXT_BYTES = HEADER_PLAINTEXT_BYTES + 16
        const val WRAPPED_DEK_BYTES = 32 + 16
        const val KEY_BYTES = 32
        const val XCHACHA_NONCE_BYTES = 24
        const val AES_NONCE_BYTES = 12
        const val AEAD_TAG_BYTES = 16
        const val HMAC_BYTES = 64

        /** prefix + header + wrapped dek + inner tag + outer tag + hmac */
        const val CONTAINER_OVERHEAD_BYTES = SUPPORTED_PREFIX_BYTES + HEADER_CIPHERTEXT_BYTES +
                WRAPPED_DEK_BYTES + AEAD_TAG_BYTES + AEAD_TAG_BYTES + HMAC_BYTES

        const val MIN_CONTAINER_BYTES = 4 * 1024
        const val DEFAULT_MAX_CONTAINER_BYTES = 32 * 1024 * 1024
        const val HARD_MAX_CONTAINER_BYTES = 128 * 1024 * 1024
        const val DEFAULT_MAX_PLAINTEXT_BYTES = 1024 * 1024
        const val MAX_PASSWORD_CHARS = 1024
        const val GZIP_SLACK_BYTES = 1024

        /** Size ladder of the padding engine, in bytes. */
        private val PADDING_BUCKETS = intArrayOf(
            4 * 1024, 8 * 1024, 16 * 1024, 32 * 1024,
            64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024,
            1 * 1024 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
            16 * 1024 * 1024, 32 * 1024 * 1024, 64 * 1024 * 1024
        )

        private const val FLAG_UNCOMPRESSED: Byte = 0x00
        private const val FLAG_COMPRESSED: Byte = 0x01

        private const val MAGIC_0: Byte = 0x4D
        private const val MAGIC_1: Byte = 0x58

        private val MAGIC = byteArrayOf(MAGIC_0, MAGIC_1)

        private const val OFF_MAGIC = 0
        private const val OFF_FORMAT = 2
        private const val OFF_PROFILE = 3
        private const val OFF_FLAGS = 4
        private const val OFF_HEADER_NONCE = 6
        private const val OFF_SALT_PRIMARY = 30
        private const val OFF_SALT_SECONDARY = 62
        private const val OFF_ENTROPY = 94

        private val SALT_PRIMARY_OFFSET = OFF_SALT_PRIMARY
        private val SALT_SECONDARY_OFFSET = OFF_SALT_SECONDARY

        private const val OFF_HDR_CONTAINER_SIZE = 0
        private const val OFF_HDR_PAYLOAD_LENGTH = 4
        private const val OFF_HDR_COMPRESSION = 8
        private const val OFF_HDR_PADDING_POLICY = 9
        private const val OFF_HDR_DATA_NONCE = 12
        private const val OFF_HDR_WRAP_NONCE = 36
        private const val OFF_HDR_OUTER_NONCE = 48
        private const val OFF_HDR_TIMESTAMP = 60

        private val DOMAIN_KDF_PRIMARY =
            "com.example.lock.MX2.kdf.primary".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_KDF_SECONDARY =
            "com.example.lock.MX2.kdf.secondary".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_HEADER = "com.example.lock.MX2.header".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_AUTH = "com.example.lock.MX2.auth".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_WRAP = "com.example.lock.MX2.wrap".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_INNER = "com.example.lock.MX2.inner".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_OUTER = "com.example.lock.MX2.outer".toByteArray(Charsets.US_ASCII)

        private const val GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val HMAC_ALGORITHM = "HmacSHA512"

        private const val MAX_RANDOM_CHUNK_BYTES = 64 * 1024

        /** Heap kept free on top of the derivation itself (containers, arrays, codecs). */
        private const val HEAP_SAFETY_MARGIN_BYTES = 24L * 1024L * 1024L

        /**
         * True when the container was produced by this engine. Containers of the older
         * "no magic byte" format are rejected on purpose: they started with a random
         * salt byte and could be mistaken for another engine's packet.
         */
        fun isOwnPacket(packet: ByteArray): Boolean =
            packet.size >= SUPPORTED_PREFIX_BYTES &&
                    packet[0] == MAGIC_0 && packet[1] == MAGIC_1 &&
                    packet[OFF_FORMAT] == FORMAT_ID

        fun peekFormatId(packet: ByteArray): Byte? =
            if (packet.size > OFF_FORMAT) packet[OFF_FORMAT] else null

        fun peekProfileId(packet: ByteArray): Byte? =
            if (isOwnPacket(packet)) packet[OFF_PROFILE] else null

        /** Worst case heap a profile needs, in bytes, when both derivations stay alive. */
        fun requiredHeapBytes(profile: MaxCryptoProfile): Long =
            profile.cumulativeDerivationBytes + HEAP_SAFETY_MARGIN_BYTES

        /**
         * Runs the internal test vectors (RFC 9106, RFC 8439, RFC 5869 and
         * draft-irtf-cfrg-xchacha-03). Returns an empty list when everything passes,
         * otherwise one entry per failing vector. Call it once per release build:
         *
         *     val failures = MaxTextEncryptionEngine.verifyImplementations()
         *     if (failures.isNotEmpty()) throw IllegalStateException(failures.toString())
         */
        fun verifyImplementations(): List<String> = MaxCryptoVectors.run()
    }

    private val random = SecureRandom()

    init {
        require(maxPlaintextBytes > 0) { "maxPlaintextBytes must be positive" }
        require(maxContainerBytes in (CONTAINER_OVERHEAD_BYTES + 1)..HARD_MAX_CONTAINER_BYTES) {
            "maxContainerBytes must be between ${CONTAINER_OVERHEAD_BYTES + 1} and $HARD_MAX_CONTAINER_BYTES"
        }
        require(maxPlaintextBytes + CONTAINER_OVERHEAD_BYTES <= maxContainerBytes) {
            "maxPlaintextBytes does not fit into maxContainerBytes"
        }
    }

    // ---------------------------------------------------------------------------- API

    /**
     * Encrypts [plainText] and returns the raw container. The caller is responsible for
     * the textual encoding (for example Base64 URL safe, no wrap) and for wiping the
     * returned array once it has been written or shared.
     *
     * Blocking, with a multi second runtime. [password] is wiped unless
     * [wipeCallerPassword] is disabled.
     */
    fun encrypt(
        plainText: CharArray,
        password: CharArray,
        progress: MaxProgressListener? = null
    ): ByteArray {
        val startedAt = System.currentTimeMillis()
        validatePassword(password)

        val scope = MaxMemoryScope()
        val passwordBytes = scope.track(encodeUtf8Replacing(password))

        try {
            val rawPlaintext = scope.track(encodeUtf8Strict(plainText))
            require(rawPlaintext.size <= maxPlaintextBytes) {
                "Plaintext of ${rawPlaintext.size} bytes exceeds the configured limit of " +
                        "$maxPlaintextBytes bytes"
            }
            logger.log(MaxLogLevel.DEBUG, "plaintext=$rawPlaintext.size bytes")

            val compressionFlag: Byte
            val payload: ByteArray
            if (compressionEnabled) {
                val candidate = scope.trackOrNull(gzipCompress(rawPlaintext))
                if (candidate != null && candidate.size + 1 < rawPlaintext.size) {
                    compressionFlag = FLAG_COMPRESSED
                    payload = candidate
                } else {
                    compressionFlag = FLAG_UNCOMPRESSED
                    payload = scope.track(rawPlaintext.copyOf())
                }
            } else {
                compressionFlag = FLAG_UNCOMPRESSED
                payload = scope.track(rawPlaintext.copyOf())
            }

            val containerSize = selectContainerSize(payload.size)
            val paddedLength = containerSize - CONTAINER_OVERHEAD_BYTES
            logger.log(
                MaxLogLevel.DEBUG,
                "container=$containerSize bytes, payload region=$paddedLength bytes"
            )

            val prefix = scope.track(ByteArray(SUPPORTED_PREFIX_BYTES))
            val headerPlain = scope.track(ByteArray(HEADER_PLAINTEXT_BYTES))
            val saltPrimary = scope.track(ByteArray(KEY_BYTES))
            val saltSecondary = scope.track(ByteArray(KEY_BYTES))
            val entropyBlob = scope.track(ByteArray(KEY_BYTES))
            val headerNonce = scope.track(ByteArray(XCHACHA_NONCE_BYTES))
            val dataNonce = scope.track(ByteArray(XCHACHA_NONCE_BYTES))
            val wrapNonce = scope.track(ByteArray(AES_NONCE_BYTES))
            val outerNonce = scope.track(ByteArray(AES_NONCE_BYTES))

            random.nextBytes(saltPrimary)
            random.nextBytes(saltSecondary)
            random.nextBytes(entropyBlob)
            random.nextBytes(headerNonce)
            random.nextBytes(dataNonce)
            random.nextBytes(wrapNonce)
            random.nextBytes(outerNonce)

            val pepper = scope.track(pepperSource.pepper())

            // ---- KDF-1: master key (header + authentication + inner layer binding)
            val masterKey = scope.track(
                deriveArgon2id(
                    passwordBytes = passwordBytes,
                    salt = saltPrimary,
                    memoryKib = profile.primaryMemoryKib,
                    iterations = profile.primaryIterations,
                    lanes = profile.primaryLanes,
                    secret = pepper,
                    associatedData = DOMAIN_KDF_PRIMARY,
                    tagLength = KEY_BYTES,
                    stage = MaxEngineStage.PRIMARY_DERIVATION,
                    progress = progress
                )
            )

            // ---- KDF-2: key wrapper for the random data key
            if (reclaimHeapBetweenDerivations) reclaimHeap()
            val wrapKey = scope.track(
                deriveArgon2id(
                    passwordBytes = passwordBytes,
                    salt = saltSecondary,
                    memoryKib = profile.secondaryMemoryKib,
                    iterations = profile.secondaryIterations,
                    lanes = profile.secondaryLanes,
                    secret = pepper,
                    associatedData = DOMAIN_KDF_SECONDARY,
                    tagLength = KEY_BYTES,
                    stage = MaxEngineStage.SECONDARY_DERIVATION,
                    progress = progress
                )
            )

            val headerKey = scope.track(
                hkdfSha512(masterKey, entropyBlob, DOMAIN_HEADER, KEY_BYTES)
            )
            val authKey = scope.track(
                hkdfSha512(masterKey, entropyBlob, DOMAIN_AUTH, HMAC_BYTES)
            )

            val dek = scope.track(ByteArray(KEY_BYTES))
            random.nextBytes(dek)

            val innerKey = scope.track(
                hkdfSha512(concat(masterKey, dek), entropyBlob, DOMAIN_INNER, KEY_BYTES)
            )

            progress?.onProgress(MaxEngineStage.HEADER_PROCESSING, 0f)

            // ---- cleartext prefix
            prefix[OFF_MAGIC] = MAGIC_0
            prefix[OFF_MAGIC + 1] = MAGIC_1
            prefix[OFF_FORMAT] = FORMAT_ID
            prefix[OFF_PROFILE] = profile.id
            prefix[OFF_FLAGS] = 0x00
            System.arraycopy(headerNonce, 0, prefix, OFF_HEADER_NONCE, XCHACHA_NONCE_BYTES)
            System.arraycopy(saltPrimary, 0, prefix, SALT_PRIMARY_OFFSET, KEY_BYTES)
            System.arraycopy(saltSecondary, 0, prefix, SALT_SECONDARY_OFFSET, KEY_BYTES)
            System.arraycopy(entropyBlob, 0, prefix, OFF_ENTROPY, KEY_BYTES)

            // ---- encrypted header
            val headerBuffer = ByteBuffer.wrap(headerPlain).order(ByteOrder.BIG_ENDIAN)
            headerBuffer.putInt(OFF_HDR_CONTAINER_SIZE, containerSize)
            headerBuffer.putInt(OFF_HDR_PAYLOAD_LENGTH, payload.size)
            headerBuffer.put(OFF_HDR_COMPRESSION, compressionFlag)
            headerBuffer.put(OFF_HDR_PADDING_POLICY, paddingPolicy.id)
            System.arraycopy(dataNonce, 0, headerPlain, OFF_HDR_DATA_NONCE, XCHACHA_NONCE_BYTES)
            System.arraycopy(wrapNonce, 0, headerPlain, OFF_HDR_WRAP_NONCE, AES_NONCE_BYTES)
            System.arraycopy(outerNonce, 0, headerPlain, OFF_HDR_OUTER_NONCE, AES_NONCE_BYTES)
            headerBuffer.putLong(OFF_HDR_TIMESTAMP, System.currentTimeMillis())

            val headerAad = scope.track(concat(DOMAIN_HEADER, prefix))
            val encryptedHeader = scope.track(
                MaxXChaCha20Poly1305.seal(headerKey, headerNonce, headerAad, headerPlain)
            )

            // ---- data key wrapper
            val wrapAad = scope.track(concat(DOMAIN_WRAP, prefix, encryptedHeader))
            val wrappedDek = scope.track(
                aesGcmEncrypt(wrapKey, wrapNonce, wrapAad, dek)
            )

            progress?.onProgress(MaxEngineStage.PAYLOAD_ENCRYPTION, 0f)

            // ---- padded payload: random fill, then the real bytes on top
            val paddedPayload = scope.track(ByteArray(paddedLength))
            val randomScratch = scope.track(ByteArray(minOf(MAX_RANDOM_CHUNK_BYTES, paddedLength)))
            var filled = 0
            while (filled < paddedLength) {
                random.nextBytes(randomScratch)
                val chunk = minOf(randomScratch.size, paddedLength - filled)
                System.arraycopy(randomScratch, 0, paddedPayload, filled, chunk)
                filled += chunk
            }
            System.arraycopy(payload, 0, paddedPayload, 0, payload.size)

            // ---- inner layer: XChaCha20-Poly1305 under a key that needs both masterKey and dek
            val innerAad = scope.track(concat(DOMAIN_INNER, prefix, encryptedHeader, wrappedDek))
            val innerCiphertext = scope.track(
                MaxXChaCha20Poly1305.seal(innerKey, dataNonce, innerAad, paddedPayload)
            )
            // ---- outer layer: AES-256-GCM under the random data key. Its associated
            // data binds the length of the inner layer rather than the inner tag, because
            // that tag does not exist before this call: the outer tag already covers the
            // whole inner ciphertext byte for byte.
            val outerAad = scope.track(
                concat(
                    DOMAIN_OUTER, prefix, encryptedHeader, wrappedDek,
                    int32BigEndian(innerCiphertext.size)
                )
            )
            val outerCiphertext = scope.track(
                aesGcmEncrypt(dek, outerNonce, outerAad, innerCiphertext)
            )

            val bodyLength = prefix.size + encryptedHeader.size + wrappedDek.size + outerCiphertext.size
            val packet = ByteArray(bodyLength + HMAC_BYTES)
            System.arraycopy(prefix, 0, packet, 0, prefix.size)
            System.arraycopy(encryptedHeader, 0, packet, prefix.size, encryptedHeader.size)
            System.arraycopy(
                wrappedDek, 0, packet, prefix.size + encryptedHeader.size, wrappedDek.size
            )
            System.arraycopy(
                outerCiphertext, 0, packet,
                prefix.size + encryptedHeader.size + wrappedDek.size, outerCiphertext.size
            )

            val mac = scope.track(hmacSha512(authKey, packet, 0, bodyLength))
            System.arraycopy(mac, 0, packet, bodyLength, HMAC_BYTES)

            progress?.onProgress(MaxEngineStage.FINALIZING, 1f)
            logger.log(
                MaxLogLevel.INFO,
                "encrypted ${rawPlaintext.size} bytes into $containerSize bytes in " +
                        "${System.currentTimeMillis() - startedAt} ms (${profile.name})"
            )
            return packet
        } catch (e: MaxCryptoException) {
            throw e
        } catch (e: Throwable) {
            logger.log(MaxLogLevel.ERROR, "encryption failed: ${e.javaClass.simpleName}: ${e.message}")
            throw MaxCryptoException("Encryption failed", e)
        } finally {
            scope.wipeAll()
            if (wipeCallerPassword) password.fill('\u0000')
        }
    }

    /**
     * Decrypts a raw container and hands the plaintext over as a CharArray. The array is
     * wiped as soon as [consumer] returns, so the consumer must copy what it needs.
     *
     * Returns true only when the container was authentic and [consumer] ran.
     */
    fun decryptAndConsume(
        packet: ByteArray,
        password: CharArray,
        progress: MaxProgressListener? = null,
        consumer: (CharArray) -> Unit
    ): Boolean {
        var plaintext: CharArray? = null
        return try {
            when (val result = decrypt(packet, password, progress)) {
                is MaxDecryptionResult.Success -> {
                    plaintext = result.plaintext
                    consumer(result.plaintext)
                    true
                }
                is MaxDecryptionResult.Failure -> {
                    logger.log(
                        MaxLogLevel.WARN,
                        "decryption rejected: ${result.reason}${result.detail?.let { " ($it)" } ?: ""}"
                    )
                    false
                }
            }
        } finally {
            plaintext?.fill('\u0000')
        }
    }

    /** Decrypts a raw container. [password] is wiped unless [wipeCallerPassword] is off. */
    fun decrypt(
        packet: ByteArray,
        password: CharArray,
        progress: MaxProgressListener? = null
    ): MaxDecryptionResult {
        val startedAt = System.currentTimeMillis()
        if (password.isEmpty() || password.size > MAX_PASSWORD_CHARS) {
            return MaxDecryptionResult.Failure(
                MaxFailureReason.MALFORMED_CONTAINER, "invalid password length"
            )
        }

        val scope = MaxMemoryScope()
        val passwordBytes = scope.track(encodeUtf8Replacing(password))

        try {
            if (!isOwnPacket(packet)) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.UNSUPPORTED_VERSION, "missing MX2 header"
                )
            }
            if (packet.size < MIN_CONTAINER_BYTES || packet.size > maxContainerBytes) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.MALFORMED_CONTAINER, "container size ${packet.size}"
                )
            }
            val profile = MaxCryptoProfile.fromId(packet[OFF_PROFILE])
                ?: return MaxDecryptionResult.Failure(
                    MaxFailureReason.UNSUPPORTED_PROFILE, "profile id ${packet[OFF_PROFILE]}"
                )
            if (profile !in acceptedProfiles) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.UNSUPPORTED_PROFILE,
                    "profile ${profile.name} is not accepted by this engine instance"
                )
            }
            if (packet[OFF_FLAGS] != 0.toByte()) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.UNSUPPORTED_VERSION, "unknown flags"
                )
            }

            val bodyLength = packet.size - HMAC_BYTES
            val prefix = scope.track(packet.copyOfRange(0, SUPPORTED_PREFIX_BYTES))
            val saltPrimary = scope.track(
                packet.copyOfRange(SALT_PRIMARY_OFFSET, SALT_PRIMARY_OFFSET + KEY_BYTES)
            )
            val saltSecondary = scope.track(
                packet.copyOfRange(SALT_SECONDARY_OFFSET, SALT_SECONDARY_OFFSET + KEY_BYTES)
            )
            val entropyBlob = scope.track(
                packet.copyOfRange(OFF_ENTROPY, OFF_ENTROPY + KEY_BYTES)
            )
            val headerNonce = scope.track(
                packet.copyOfRange(OFF_HEADER_NONCE, OFF_HEADER_NONCE + XCHACHA_NONCE_BYTES)
            )
            val encryptedHeader = scope.track(
                packet.copyOfRange(SUPPORTED_PREFIX_BYTES, SUPPORTED_PREFIX_BYTES + HEADER_CIPHERTEXT_BYTES)
            )

            val pepper = scope.track(pepperSource.pepper())
            ensureHeapFor(profile)

            val masterKey = scope.track(
                deriveArgon2id(
                    passwordBytes = passwordBytes,
                    salt = saltPrimary,
                    memoryKib = profile.primaryMemoryKib,
                    iterations = profile.primaryIterations,
                    lanes = profile.primaryLanes,
                    secret = pepper,
                    associatedData = DOMAIN_KDF_PRIMARY,
                    tagLength = KEY_BYTES,
                    stage = MaxEngineStage.PRIMARY_DERIVATION,
                    progress = progress
                )
            )

            // ---- cheapest rejection first: the outer tag authenticates everything
            progress?.onProgress(MaxEngineStage.INTEGRITY_CHECK, 0f)
            val authKey = scope.track(hkdfSha512(masterKey, entropyBlob, DOMAIN_AUTH, HMAC_BYTES))
            val receivedMac = scope.track(
                packet.copyOfRange(bodyLength, packet.size)
            )
            val computedMac = scope.track(hmacSha512(authKey, packet, 0, bodyLength))
            if (!MessageDigest.isEqual(receivedMac, computedMac)) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.AUTHENTICATION_FAILED, "container authentication tag mismatch"
                )
            }
            progress?.onProgress(MaxEngineStage.INTEGRITY_CHECK, 1f)

            // ---- header
            val headerKey = scope.track(hkdfSha512(masterKey, entropyBlob, DOMAIN_HEADER, KEY_BYTES))
            val headerAad = scope.track(concat(DOMAIN_HEADER, prefix))
            val headerPlain = scope.track(
                MaxXChaCha20Poly1305.open(headerKey, headerNonce, headerAad, encryptedHeader)
                    ?: return MaxDecryptionResult.Failure(
                        MaxFailureReason.AUTHENTICATION_FAILED, "header not authentic"
                    )
            )
            if (headerPlain.size != HEADER_PLAINTEXT_BYTES) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.MALFORMED_CONTAINER, "header length"
                )
            }

            val headerBuffer = ByteBuffer.wrap(headerPlain).order(ByteOrder.BIG_ENDIAN)
            val containerSize = headerBuffer.getInt(OFF_HDR_CONTAINER_SIZE)
            val payloadLength = headerBuffer.getInt(OFF_HDR_PAYLOAD_LENGTH)
            val compressionFlag = headerPlain[OFF_HDR_COMPRESSION]
            val paddingId = headerPlain[OFF_HDR_PADDING_POLICY]
            if (MaxPaddingPolicy.fromId(paddingId) == null) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.UNSUPPORTED_VERSION, "padding policy $paddingId"
                )
            }
            if (containerSize != packet.size) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.MALFORMED_CONTAINER,
                    "declared $containerSize, received ${packet.size}"
                )
            }
            val paddedLength = containerSize - CONTAINER_OVERHEAD_BYTES
            if (payloadLength < 0 || payloadLength > paddedLength) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.MALFORMED_CONTAINER, "payload length $payloadLength"
                )
            }

            val dataNonce = scope.track(
                headerPlain.copyOfRange(OFF_HDR_DATA_NONCE, OFF_HDR_DATA_NONCE + XCHACHA_NONCE_BYTES)
            )
            val wrapNonce = scope.track(
                headerPlain.copyOfRange(OFF_HDR_WRAP_NONCE, OFF_HDR_WRAP_NONCE + AES_NONCE_BYTES)
            )
            val outerNonce = scope.track(
                headerPlain.copyOfRange(OFF_HDR_OUTER_NONCE, OFF_HDR_OUTER_NONCE + AES_NONCE_BYTES)
            )

            // ---- KDF-2 only after the container proved authentic
            val wrappedDekOffset = SUPPORTED_PREFIX_BYTES + HEADER_CIPHERTEXT_BYTES
            val wrappedDek = scope.track(
                packet.copyOfRange(wrappedDekOffset, wrappedDekOffset + WRAPPED_DEK_BYTES)
            )
            if (reclaimHeapBetweenDerivations) reclaimHeap()
            val wrapKey = scope.track(
                deriveArgon2id(
                    passwordBytes = passwordBytes,
                    salt = saltSecondary,
                    memoryKib = profile.secondaryMemoryKib,
                    iterations = profile.secondaryIterations,
                    lanes = profile.secondaryLanes,
                    secret = pepper,
                    associatedData = DOMAIN_KDF_SECONDARY,
                    tagLength = KEY_BYTES,
                    stage = MaxEngineStage.SECONDARY_DERIVATION,
                    progress = progress
                )
            )

            val wrapAad = scope.track(concat(DOMAIN_WRAP, prefix, encryptedHeader))
            val dek = scope.track(
                aesGcmDecrypt(wrapKey, wrapNonce, wrapAad, wrappedDek)
                    ?: return MaxDecryptionResult.Failure(
                        MaxFailureReason.AUTHENTICATION_FAILED, "data key not authentic"
                    )
            )
            if (dek.size != KEY_BYTES) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.MALFORMED_CONTAINER, "unexpected data key length"
                )
            }

            val outerOffset = wrappedDekOffset + WRAPPED_DEK_BYTES
            val outerCiphertextLength = bodyLength - outerOffset
            if (outerCiphertextLength < AEAD_TAG_BYTES + AEAD_TAG_BYTES) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.MALFORMED_CONTAINER, "truncated payload region"
                )
            }

            val outerCiphertext = scope.track(
                packet.copyOfRange(outerOffset, outerOffset + outerCiphertextLength)
            )
            val outerAad = scope.track(
                concat(
                    DOMAIN_OUTER, prefix, encryptedHeader, wrappedDek,
                    int32BigEndian(outerCiphertextLength - AEAD_TAG_BYTES)
                )
            )

            progress?.onProgress(MaxEngineStage.PAYLOAD_DECRYPTION, 0f)
            val innerFromOuter = scope.track(
                aesGcmDecrypt(dek, outerNonce, outerAad, outerCiphertext)
                    ?: return MaxDecryptionResult.Failure(
                        MaxFailureReason.AUTHENTICATION_FAILED, "outer layer not authentic"
                    )
            )
            if (innerFromOuter.size != paddedLength + AEAD_TAG_BYTES) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.MALFORMED_CONTAINER, "outer layer length"
                )
            }

            val innerKey = scope.track(
                hkdfSha512(concat(masterKey, dek), entropyBlob, DOMAIN_INNER, KEY_BYTES)
            )
            val innerAad = scope.track(concat(DOMAIN_INNER, prefix, encryptedHeader, wrappedDek))
            val paddedPayload = scope.track(
                MaxXChaCha20Poly1305.open(innerKey, dataNonce, innerAad, innerFromOuter)
                    ?: return MaxDecryptionResult.Failure(
                        MaxFailureReason.AUTHENTICATION_FAILED, "inner layer not authentic"
                    )
            )
            if (paddedPayload.size != paddedLength) {
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.MALFORMED_CONTAINER, "padded length mismatch"
                )
            }

            val payload = scope.track(paddedPayload.copyOfRange(0, payloadLength))
            val plaintextBytes = when (compressionFlag) {
                FLAG_UNCOMPRESSED -> {
                    if (payload.size > maxPlaintextBytes) {
                        return MaxDecryptionResult.Failure(
                            MaxFailureReason.MALFORMED_CONTAINER, "plaintext limit"
                        )
                    }
                    scope.track(payload.copyOf())
                }
                FLAG_COMPRESSED -> scope.track(
                    gzipDecompress(payload, maxPlaintextBytes)
                        ?: return MaxDecryptionResult.Failure(
                            MaxFailureReason.MALFORMED_CONTAINER, "gzip payload invalid"
                        )
                )
                else -> return MaxDecryptionResult.Failure(
                    MaxFailureReason.UNSUPPORTED_VERSION, "compression flag $compressionFlag"
                )
            }

            val plaintext = decodeUtf8(plaintextBytes)
            if (plaintext.size > maxPlaintextBytes) {
                plaintext.fill('\u0000')
                return MaxDecryptionResult.Failure(
                    MaxFailureReason.MALFORMED_CONTAINER, "plaintext limit"
                )
            }

            progress?.onProgress(MaxEngineStage.FINALIZING, 1f)
            logger.log(
                MaxLogLevel.INFO,
                "decrypted ${packet.size} bytes into ${plaintext.size} chars in " +
                        "${System.currentTimeMillis() - startedAt} ms (${profile.name})"
            )
            return MaxDecryptionResult.Success(plaintext)
        } catch (e: OutOfMemoryError) {
            logger.log(MaxLogLevel.ERROR, "out of memory during decryption")
            return MaxDecryptionResult.Failure(
                MaxFailureReason.RESOURCE_EXHAUSTED, "out of memory"
            )
        } catch (e: MaxCryptoException) {
            return MaxDecryptionResult.Failure(MaxFailureReason.RESOURCE_EXHAUSTED, e.message)
        } catch (e: Throwable) {
            logger.log(MaxLogLevel.ERROR, "decryption aborted: ${e.javaClass.simpleName}: ${e.message}")
            return MaxDecryptionResult.Failure(MaxFailureReason.INTERNAL_ERROR, e.javaClass.simpleName)
        } finally {
            scope.wipeAll()
            if (wipeCallerPassword) password.fill('\u0000')
        }
    }

    suspend fun encryptAsync(
        plainText: CharArray,
        password: CharArray,
        progress: MaxProgressListener? = null
    ): ByteArray = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
        encrypt(plainText, password, progress)
    }

    suspend fun decryptAndConsumeAsync(
        packet: ByteArray,
        password: CharArray,
        progress: MaxProgressListener? = null,
        consumer: (CharArray) -> Unit
    ): Boolean = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
        decryptAndConsume(packet, password, progress, consumer)
    }

    // ------------------------------------------------------------------ internals

    private fun validatePassword(password: CharArray) {
        require(password.size in 1..MAX_PASSWORD_CHARS) {
            "Password length must be between 1 and $MAX_PASSWORD_CHARS characters"
        }
        var empty = true
        for (c in password) {
            if (c != '\u0000') {
                empty = false
                break
            }
        }
        require(!empty) { "Password is empty" }
    }

    private fun deriveArgon2id(
        passwordBytes: ByteArray,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        lanes: Int,
        secret: ByteArray,
        associatedData: ByteArray,
        tagLength: Int,
        stage: MaxEngineStage,
        progress: MaxProgressListener?
    ): ByteArray {
        ensureHeapFor(profile)
        val startedAt = System.currentTimeMillis()
        val listener = if (progress == null) null else { fraction: Float ->
            progress.onProgress(stage, fraction)
        }
        val key = MaxArgon2idCore.hash(
            password = passwordBytes,
            salt = salt,
            memoryKib = memoryKib,
            iterations = iterations,
            lanes = lanes,
            tagLength = tagLength,
            secret = secret,
            associatedData = associatedData,
            onProgress = listener
        )
        logger.log(
            MaxLogLevel.INFO,
            "argon2id m=$memoryKib KiB t=$iterations p=$lanes in " +
                    "${System.currentTimeMillis() - startedAt} ms"
        )
        return key
    }

    /** Heap this instance needs for [profile], honouring [reclaimHeapBetweenDerivations]. */
    fun requiredHeapBytesFor(profile: MaxCryptoProfile): Long {
        val derivation = if (reclaimHeapBetweenDerivations) {
            profile.peakDerivationBytes
        } else {
            profile.cumulativeDerivationBytes
        }
        return derivation + HEAP_SAFETY_MARGIN_BYTES
    }

    /**
     * Refuses to start a derivation that cannot fit into the process heap. The check runs
     * twice: a first refusal triggers a collection, because memory held by garbage that
     * has not been collected yet must not be reported as unavailable.
     */
    private fun ensureHeapFor(profile: MaxCryptoProfile) {
        val required = requiredHeapBytesFor(profile)
        if (usableHeapBytes() >= required) return
        reclaimHeap()
        val afterCollection = usableHeapBytes()
        if (afterCollection < required) {
            throw MaxCryptoException(
                "Not enough heap for ${profile.name}: ${afterCollection / (1024 * 1024)} MiB usable, " +
                        "${required / (1024 * 1024)} MiB required. Add android:largeHeap=\"true\" " +
                        "to the manifest or select a smaller MaxCryptoProfile."
            )
        }
    }

    private fun usableHeapBytes(): Long {
        val runtime = Runtime.getRuntime()
        return runtime.maxMemory() - (runtime.totalMemory() - runtime.freeMemory())
    }

    private fun reclaimHeap() {
        System.gc()
        try {
            Thread.sleep(40L)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        System.gc()
    }

    /** Picks the container size for [payloadBytes] according to [paddingPolicy]. */
    private fun selectContainerSize(payloadBytes: Int): Int {
        val required = payloadBytes + CONTAINER_OVERHEAD_BYTES
        require(required <= maxContainerBytes) {
            "Payload does not fit into the configured container limit of $maxContainerBytes bytes"
        }

        // Never go below MIN_CONTAINER_BYTES: the decoder rejects anything smaller, so a
        // randomised size must not be allowed to fall under that floor.
        val lower = maxOf(required, MIN_CONTAINER_BYTES)
        var bucket = -1
        for (candidate in PADDING_BUCKETS) {
            if (candidate >= lower && candidate <= maxContainerBytes) {
                bucket = candidate
                break
            }
        }
        if (bucket < 0) bucket = maxContainerBytes

        val upper = nextBucketAfter(bucket)
        return when (paddingPolicy) {
            MaxPaddingPolicy.BUCKET_EXACT -> bucket
            MaxPaddingPolicy.BUCKET_RANDOMIZED -> {
                val span = upper - lower
                if (span <= 0) bucket else lower + random.nextInt(span)
            }
        }
    }

    private fun nextBucketAfter(bucket: Int): Int {
        for (candidate in PADDING_BUCKETS) {
            if (candidate > bucket) return minOf(candidate, maxContainerBytes)
        }
        return maxContainerBytes
    }

    // ------------------------------------------------------------------ JCE helpers

    private fun aesGcmEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(GCM_TRANSFORMATION)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, nonce)
        )
        cipher.updateAAD(aad)
        return cipher.doFinal(plain)
    }

    private fun aesGcmDecrypt(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray
    ): ByteArray? = try {
        val cipher = Cipher.getInstance(GCM_TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, nonce)
        )
        cipher.updateAAD(aad)
        cipher.doFinal(ciphertext)
    } catch (_: GeneralSecurityException) {
        null
    }

    private fun hmacSha512(key: ByteArray, data: ByteArray, offset: Int, length: Int): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
        mac.update(data, offset, length)
        return mac.doFinal()
    }

    /**
     * GZIP helper. The output goes into a caller owned fixed buffer that is wiped
     * afterwards, so no growing stream buffer keeps a copy of the plaintext around.
     * Returns null when compression does not pay off.
     */
    private fun gzipCompress(input: ByteArray): ByteArray? {
        val buffer = ByteArray(input.size + GZIP_SLACK_BYTES)
        return try {
            val sink = MaxFixedByteArrayOutputStream(buffer)
            GZIPOutputStream(sink).use { it.write(input) }
            if (sink.count + GZIP_SLACK_BYTES >= input.size) null else buffer.copyOf(sink.count)
        } catch (_: Exception) {
            null
        } finally {
            buffer.fill(0)
        }
    }

    private fun gzipDecompress(input: ByteArray, limit: Int): ByteArray? {
        val buffer = ByteArray(limit.coerceAtLeast(1))
        return try {
            var total = 0
            GZIPInputStream(ByteArrayInputStream(input)).use { gzip ->
                val chunk = ByteArray(8192)
                try {
                    while (true) {
                        val read = gzip.read(chunk)
                        if (read < 0) break
                        if (total + read > limit) throw IllegalStateException("decompression limit")
                        System.arraycopy(chunk, 0, buffer, total, read)
                        total += read
                    }
                } finally {
                    chunk.fill(0)
                }
            }
            buffer.copyOf(total)
        } catch (_: Exception) {
            null
        } finally {
            buffer.fill(0)
        }
    }

    /** Strict UTF-8: the plaintext must survive the round trip unchanged, so anything
     *  that cannot be represented is reported instead of silently replaced. */
    private fun encodeUtf8Strict(text: CharArray): ByteArray = encodeUtf8(text, strict = true)

    /** Lenient UTF-8 for the password: an unpaired surrogate must not make a password
     *  unusable, and the mapping stays deterministic. */
    private fun encodeUtf8Replacing(text: CharArray): ByteArray = encodeUtf8(text, strict = false)

    private fun encodeUtf8(text: CharArray, strict: Boolean): ByteArray {
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(if (strict) CodingErrorAction.REPORT else CodingErrorAction.REPLACE)
            .onUnmappableCharacter(if (strict) CodingErrorAction.REPORT else CodingErrorAction.REPLACE)
        val buffer = CharBuffer.wrap(text)
        val encoded = encoder.encode(buffer)
        val out = ByteArray(encoded.remaining())
        encoded.get(out)
        if (encoded.hasArray()) encoded.array().fill(0)
        return out
    }

    private fun decodeUtf8(bytes: ByteArray): CharArray {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val decoded = decoder.decode(ByteBuffer.wrap(bytes))
        val out = CharArray(decoded.remaining())
        decoded.get(out)
        if (decoded.hasArray()) decoded.array().fill('\u0000')
        return out
    }
}

// =====================================================================================
//  MEMORY HYGIENE
//  A single registry collects every temporary buffer of one operation; one finally
//  block wipes all of them. Java arrays cannot be locked or reliably scrubbed once the
//  JIT considers them dead, so the goal here is a short lifetime plus an explicit
//  overwrite, not a hardware guarantee.
// =====================================================================================

private class MaxMemoryScope {

    private val byteArrays = ArrayList<ByteArray>(32)
    private val charArrays = ArrayList<CharArray>(4)

    fun track(bytes: ByteArray): ByteArray {
        byteArrays.add(bytes)
        return bytes
    }

    /** Same as [track] for a nullable result: registers it only when it exists. */
    fun trackOrNull(bytes: ByteArray?): ByteArray? {
        if (bytes != null) byteArrays.add(bytes)
        return bytes
    }

    fun track(chars: CharArray): CharArray {
        charArrays.add(chars)
        return chars
    }

    fun wipeAll() {
        for (index in byteArrays.indices) wipeBytesSecure(byteArrays[index])
        byteArrays.clear()
        for (index in charArrays.indices) charArrays[index].fill('\u0000')
        charArrays.clear()
    }
}

/** 0x00 -> 0xFF -> 0x00 overwrite for key material. */
private fun wipeBytesSecure(bytes: ByteArray?) {
    if (bytes == null) return
    bytes.fill(0x00)
    bytes.fill(0xFF.toByte())
    bytes.fill(0x00)
}

private fun wipeLongs(values: LongArray?) {
    values?.fill(0L)
}

private fun wipeInts(values: IntArray?) {
    values?.fill(0)
}

private fun int32BigEndian(value: Int): ByteArray = byteArrayOf(
    ((value ushr 24) and 0xFF).toByte(),
    ((value ushr 16) and 0xFF).toByte(),
    ((value ushr 8) and 0xFF).toByte(),
    (value and 0xFF).toByte()
)

/** Output stream over a caller owned buffer: it fails instead of growing, and the buffer
 *  can be wiped by the caller once the compressed bytes have been copied out. */
private class MaxFixedByteArrayOutputStream(private val buffer: ByteArray) : java.io.OutputStream() {

    var count = 0
        private set

    override fun write(b: Int) {
        if (count >= buffer.size) throw java.io.IOException("fixed buffer overflow")
        buffer[count++] = b.toByte()
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (count + len > buffer.size) throw java.io.IOException("fixed buffer overflow")
        System.arraycopy(b, off, buffer, count, len)
        count += len
    }
}

private fun concat(vararg parts: ByteArray): ByteArray {
    var size = 0
    for (part in parts) size += part.size
    val out = ByteArray(size)
    var offset = 0
    for (part in parts) {
        System.arraycopy(part, 0, out, offset, part.size)
        offset += part.size
    }
    return out
}

// =====================================================================================
//  HKDF-SHA-512 (RFC 5869)
// =====================================================================================

private const val HMAC_SHA512_BYTES = 64

private fun hmacSha512Raw(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA512")
    mac.init(SecretKeySpec(key, "HmacSHA512"))
    return mac.doFinal(data)
}

private fun hmacSha512Raw(key: ByteArray, data: ByteArray, offset: Int, length: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA512")
    mac.init(SecretKeySpec(key, "HmacSHA512"))
    mac.update(data, offset, length)
    return mac.doFinal()
}

private fun hkdfSha512(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    require(length in 1..(255 * HMAC_SHA512_BYTES)) { "invalid HKDF output length" }
    val effectiveSalt = if (salt.isEmpty()) ByteArray(HMAC_SHA512_BYTES) else salt
    val prk = hmacSha512Raw(effectiveSalt, ikm)
    val out = ByteArray(length)
    var previous = ByteArray(0)
    var offset = 0
    var counter = 1
    try {
        val mac = Mac.getInstance("HmacSHA512")
        while (offset < length) {
            mac.init(SecretKeySpec(prk, "HmacSHA512"))
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            val block = mac.doFinal()
            wipeBytesSecure(previous)
            previous = block
            val amount = minOf(block.size, length - offset)
            System.arraycopy(block, 0, out, offset, amount)
            offset += amount
            counter++
        }
        return out
    } finally {
        wipeBytesSecure(previous)
        wipeBytesSecure(prk)
        if (effectiveSalt !== salt) wipeBytesSecure(effectiveSalt)
    }
}

// =====================================================================================
//  XCHACHA20-POLY1305  (draft-irtf-cfrg-xchacha-03, section 2.3)
//  Pure Kotlin so that the engine stays independent from the platform provider and from
//  the API level of the device.
// =====================================================================================

internal object MaxXChaCha20Poly1305 {

    const val KEY_BYTES = 32
    const val NONCE_BYTES = 24
    const val TAG_BYTES = 16

    private const val BLOCK_BYTES = 64

    /** AEAD_XChaCha20_Poly1305 encryption. Returns ciphertext followed by the 16 byte tag. */
    fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "XChaCha20 key must be 32 bytes" }
        require(nonce.size == NONCE_BYTES) { "XChaCha20 nonce must be 24 bytes" }

        val subKey = hChaCha20(key, nonce)
        val ietfNonce = ByteArray(12)
        System.arraycopy(nonce, 16, ietfNonce, 4, 8)
        try {
            return sealIetf(subKey, ietfNonce, aad, plaintext)
        } finally {
            wipeBytesSecure(subKey)
            wipeBytesSecure(ietfNonce)
        }
    }

    /** AEAD_XChaCha20_Poly1305 decryption of ciphertext||tag. Null when not authentic. */
    fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, sealed: ByteArray): ByteArray? {
        if (key.size != KEY_BYTES || nonce.size != NONCE_BYTES) return null

        val subKey = hChaCha20(key, nonce)
        val ietfNonce = ByteArray(12)
        System.arraycopy(nonce, 16, ietfNonce, 4, 8)
        try {
            return openIetf(subKey, ietfNonce, aad, sealed)
        } finally {
            wipeBytesSecure(subKey)
            wipeBytesSecure(ietfNonce)
        }
    }

    /** AEAD_CHACHA20_POLY1305 (RFC 8439) with a 96 bit nonce: the inner construction of
     *  XChaCha20-Poly1305, exposed separately so that the RFC vectors can be replayed. */
    fun sealIetf(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray
    ): ByteArray {
        require(key.size == KEY_BYTES) { "ChaCha20 key must be 32 bytes" }
        require(nonce.size == 12) { "ChaCha20-Poly1305 nonce must be 12 bytes" }

        var oneTimeKey: ByteArray? = null
        var ciphertext: ByteArray? = null
        var tag: ByteArray? = null
        try {
            oneTimeKey = chacha20Block(key, 0, nonce)
            ciphertext = chacha20Xor(key, nonce, 1, plaintext)
            tag = poly1305(oneTimeKey, macData(aad, ciphertext))

            val out = ByteArray(ciphertext.size + TAG_BYTES)
            System.arraycopy(ciphertext, 0, out, 0, ciphertext.size)
            System.arraycopy(tag, 0, out, ciphertext.size, TAG_BYTES)
            return out
        } finally {
            wipeBytesSecure(oneTimeKey)
            wipeBytesSecure(ciphertext)
            wipeBytesSecure(tag)
        }
    }

    /** AEAD_CHACHA20_POLY1305 (RFC 8439) decryption. Null when the tag does not verify. */
    fun openIetf(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        sealed: ByteArray
    ): ByteArray? {
        if (key.size != KEY_BYTES || nonce.size != 12) return null
        if (sealed.size < TAG_BYTES) return null

        var oneTimeKey: ByteArray? = null
        var ciphertext: ByteArray? = null
        var receivedTag: ByteArray? = null
        var expectedTag: ByteArray? = null
        try {
            oneTimeKey = chacha20Block(key, 0, nonce)
            val ciphertextLength = sealed.size - TAG_BYTES
            ciphertext = sealed.copyOf(ciphertextLength)
            receivedTag = sealed.copyOfRange(ciphertextLength, sealed.size)
            expectedTag = poly1305(oneTimeKey, macData(aad, ciphertext))
            if (!MessageDigest.isEqual(receivedTag, expectedTag)) return null
            return chacha20Xor(key, nonce, 1, ciphertext)
        } finally {
            wipeBytesSecure(oneTimeKey)
            wipeBytesSecure(ciphertext)
            wipeBytesSecure(receivedTag)
            wipeBytesSecure(expectedTag)
        }
    }

    // ---------------------------------------------------------------- core primitives

    /** HChaCha20: returns the 32 byte subkey that turns the 24 byte nonce into a 12 byte one. */
    fun hChaCha20(key: ByteArray, nonce: ByteArray): ByteArray {
        require(key.size == KEY_BYTES)
        require(nonce.size >= 16)
        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646E
        state[2] = 0x79622D32
        state[3] = 0x6B206574
        for (i in 0 until 8) state[4 + i] = loadLe32(key, i * 4)
        for (i in 0 until 4) state[12 + i] = loadLe32(nonce, i * 4)
        try {
            repeat(10) { doubleRound(state) }
            val out = ByteArray(32)
            for (i in 0 until 4) storeLe32(out, i * 4, state[i])
            for (i in 0 until 4) storeLe32(out, 16 + i * 4, state[12 + i])
            return out
        } finally {
            wipeInts(state)
        }
    }

    /** One ChaCha20 block: 64 keystream bytes with the IETF layout (32 bit counter). */
    fun chacha20Block(key: ByteArray, counter: Int, nonce: ByteArray): ByteArray {
        require(key.size == KEY_BYTES)
        require(nonce.size == 12)
        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646E
        state[2] = 0x79622D32
        state[3] = 0x6B206574
        for (i in 0 until 8) state[4 + i] = loadLe32(key, i * 4)
        state[12] = counter
        for (i in 0 until 3) state[13 + i] = loadLe32(nonce, i * 4)

        val working = state.copyOf()
        try {
            repeat(10) { doubleRound(working) }
            val out = ByteArray(BLOCK_BYTES)
            for (i in 0 until 16) storeLe32(out, i * 4, working[i] + state[i])
            return out
        } finally {
            wipeInts(state)
            wipeInts(working)
        }
    }

    /** XORs [data] with the ChaCha20 keystream starting at [initialCounter]. */
    fun chacha20Xor(
        key: ByteArray,
        nonce: ByteArray,
        initialCounter: Int,
        data: ByteArray
    ): ByteArray {
        val out = ByteArray(data.size)
        var counter = initialCounter
        var offset = 0
        var keystream: ByteArray? = null
        try {
            while (offset < data.size) {
                wipeBytesSecure(keystream)
                keystream = chacha20Block(key, counter, nonce)
                val take = minOf(BLOCK_BYTES, data.size - offset)
                for (i in 0 until take) {
                    out[offset + i] = (data[offset + i].toInt() xor keystream[i].toInt()).toByte()
                }
                offset += take
                counter++
            }
            return out
        } finally {
            wipeBytesSecure(keystream)
        }
    }

    private fun doubleRound(v: IntArray) {
        quarterRound(v, 0, 4, 8, 12)
        quarterRound(v, 1, 5, 9, 13)
        quarterRound(v, 2, 6, 10, 14)
        quarterRound(v, 3, 7, 11, 15)
        quarterRound(v, 0, 5, 10, 15)
        quarterRound(v, 1, 6, 11, 12)
        quarterRound(v, 2, 7, 8, 13)
        quarterRound(v, 3, 4, 9, 14)
    }

    private fun quarterRound(v: IntArray, a: Int, b: Int, c: Int, d: Int) {
        v[a] += v[b]
        v[d] = Integer.rotateLeft(v[d] xor v[a], 16)
        v[c] += v[d]
        v[b] = Integer.rotateLeft(v[b] xor v[c], 12)
        v[a] += v[b]
        v[d] = Integer.rotateLeft(v[d] xor v[a], 8)
        v[c] += v[d]
        v[b] = Integer.rotateLeft(v[b] xor v[c], 7)
    }

    /** Poly1305 one time authenticator (RFC 8439, section 2.5). Only the first 32 bytes
     *  of [key] are used, so the caller may pass the 64 byte ChaCha20 block directly. */
    fun poly1305(key: ByteArray, message: ByteArray): ByteArray {
        require(key.size >= 32) { "Poly1305 key must be at least 32 bytes" }

        val r0 = loadLe32(key, 0) and 0x3FFFFFF
        val r1 = (loadLe32(key, 3) ushr 2) and 0x3FFFF03
        val r2 = (loadLe32(key, 6) ushr 4) and 0x3FFC0FF
        val r3 = (loadLe32(key, 9) ushr 6) and 0x3F03FFF
        val r4 = (loadLe32(key, 12) ushr 8) and 0x00FFFFF

        val s1 = r1 * 5
        val s2 = r2 * 5
        val s3 = r3 * 5
        val s4 = r4 * 5

        var h0 = 0
        var h1 = 0
        var h2 = 0
        var h3 = 0
        var h4 = 0

        val block = ByteArray(16)
        var offset = 0
        while (offset < message.size) {
            val take = minOf(16, message.size - offset)
            java.util.Arrays.fill(block, 0)
            System.arraycopy(message, offset, block, 0, take)
            val highBit: Int
            if (take == 16) {
                highBit = 1 shl 24
            } else {
                block[take] = 0x01
                highBit = 0
            }

            h0 += loadLe32(block, 0) and 0x3FFFFFF
            h1 += (loadLe32(block, 3) ushr 2) and 0x3FFFFFF
            h2 += (loadLe32(block, 6) ushr 4) and 0x3FFFFFF
            h3 += (loadLe32(block, 9) ushr 6) and 0x3FFFFFF
            h4 += (loadLe32(block, 12) ushr 8) or highBit

            var d0 = h0.toLong() * r0 + h1.toLong() * s4 + h2.toLong() * s3 +
                    h3.toLong() * s2 + h4.toLong() * s1
            var d1 = h0.toLong() * r1 + h1.toLong() * r0 + h2.toLong() * s4 +
                    h3.toLong() * s3 + h4.toLong() * s2
            var d2 = h0.toLong() * r2 + h1.toLong() * r1 + h2.toLong() * r0 +
                    h3.toLong() * s4 + h4.toLong() * s3
            var d3 = h0.toLong() * r3 + h1.toLong() * r2 + h2.toLong() * r1 +
                    h3.toLong() * r0 + h4.toLong() * s4
            var d4 = h0.toLong() * r4 + h1.toLong() * r3 + h2.toLong() * r2 +
                    h3.toLong() * r1 + h4.toLong() * r0

            var carry = (d0 ushr 26).toInt()
            h0 = (d0 and 0x3FFFFFF).toInt()
            d1 += carry.toLong()
            carry = (d1 ushr 26).toInt()
            h1 = (d1 and 0x3FFFFFF).toInt()
            d2 += carry.toLong()
            carry = (d2 ushr 26).toInt()
            h2 = (d2 and 0x3FFFFFF).toInt()
            d3 += carry.toLong()
            carry = (d3 ushr 26).toInt()
            h3 = (d3 and 0x3FFFFFF).toInt()
            d4 += carry.toLong()
            carry = (d4 ushr 26).toInt()
            h4 = (d4 and 0x3FFFFFF).toInt()

            h0 += carry * 5
            carry = h0 ushr 26
            h0 = h0 and 0x3FFFFFF
            h1 += carry

            offset += take
        }
        wipeBytesSecure(block)

        // full carry
        var carry = h1 ushr 26
        h1 = h1 and 0x3FFFFFF
        h2 += carry
        carry = h2 ushr 26
        h2 = h2 and 0x3FFFFFF
        h3 += carry
        carry = h3 ushr 26
        h3 = h3 and 0x3FFFFFF
        h4 += carry
        carry = h4 ushr 26
        h4 = h4 and 0x3FFFFFF
        h0 += carry * 5
        carry = h0 ushr 26
        h0 = h0 and 0x3FFFFFF
        h1 += carry

        // h + -p, then select
        var g0 = h0 + 5
        carry = g0 ushr 26
        g0 = g0 and 0x3FFFFFF
        var g1 = h1 + carry
        carry = g1 ushr 26
        g1 = g1 and 0x3FFFFFF
        var g2 = h2 + carry
        carry = g2 ushr 26
        g2 = g2 and 0x3FFFFFF
        var g3 = h3 + carry
        carry = g3 ushr 26
        g3 = g3 and 0x3FFFFFF
        var g4 = h4 + carry - (1 shl 26)

        // Logical shift on purpose: the selection mask must be 0 when h + 5 overflowed
        // into bit 31 of g4 and 0xFFFFFFFF otherwise. An arithmetic shift would leave
        // 0xFFFFFFFE behind and keep bits of g that have to be discarded.
        var mask = (g4 ushr 31) - 1
        g0 = g0 and mask
        g1 = g1 and mask
        g2 = g2 and mask
        g3 = g3 and mask
        g4 = g4 and mask
        mask = mask.inv()
        h0 = (h0 and mask) or g0
        h1 = (h1 and mask) or g1
        h2 = (h2 and mask) or g2
        h3 = (h3 and mask) or g3
        h4 = (h4 and mask) or g4

        // serialise, add s, truncate to 128 bits
        var word0 = (h0 or (h1 shl 26))
        var word1 = ((h1 ushr 6) or (h2 shl 20))
        var word2 = ((h2 ushr 12) or (h3 shl 14))
        var word3 = ((h3 ushr 18) or (h4 shl 8))

        var sum = (word0.toLong() and 0xFFFFFFFFL) + (loadLe32(key, 16).toLong() and 0xFFFFFFFFL)
        word0 = sum.toInt()
        sum = (word1.toLong() and 0xFFFFFFFFL) + (loadLe32(key, 20).toLong() and 0xFFFFFFFFL) +
                (sum ushr 32)
        word1 = sum.toInt()
        sum = (word2.toLong() and 0xFFFFFFFFL) + (loadLe32(key, 24).toLong() and 0xFFFFFFFFL) +
                (sum ushr 32)
        word2 = sum.toInt()
        sum = (word3.toLong() and 0xFFFFFFFFL) + (loadLe32(key, 28).toLong() and 0xFFFFFFFFL) +
                (sum ushr 32)
        word3 = sum.toInt()

        val tag = ByteArray(16)
        storeLe32(tag, 0, word0)
        storeLe32(tag, 4, word1)
        storeLe32(tag, 8, word2)
        storeLe32(tag, 12, word3)
        return tag
    }

    private fun macData(aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val aadPadding = paddingLength(aad.size)
        val textPadding = paddingLength(ciphertext.size)
        val out = ByteArray(aad.size + aadPadding + ciphertext.size + textPadding + 16)
        var offset = 0
        System.arraycopy(aad, 0, out, offset, aad.size)
        offset += aad.size + aadPadding
        System.arraycopy(ciphertext, 0, out, offset, ciphertext.size)
        offset += ciphertext.size + textPadding
        storeLe64(out, offset, aad.size.toLong())
        storeLe64(out, offset + 8, ciphertext.size.toLong())
        return out
    }

    private fun paddingLength(length: Int): Int = (16 - (length % 16)) % 16

    private fun loadLe32(source: ByteArray, offset: Int): Int =
        (source[offset].toInt() and 0xFF) or
                ((source[offset + 1].toInt() and 0xFF) shl 8) or
                ((source[offset + 2].toInt() and 0xFF) shl 16) or
                ((source[offset + 3].toInt() and 0xFF) shl 24)

    private fun storeLe32(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value and 0xFF).toByte()
        target[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        target[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        target[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }

    private fun storeLe64(target: ByteArray, offset: Int, value: Long) {
        for (i in 0 until 8) {
            target[offset + i] = ((value ushr (i * 8)) and 0xFF).toByte()
        }
    }
}

// =====================================================================================
//  ARGON2ID (RFC 9106) + BLAKE2b
//  Pure Kotlin, single flat LongArray for the 1024 byte blocks. The progress callback is
//  reported once per slice so that a calling screen can display a real progress bar
//  instead of an indeterminate spinner.
// =====================================================================================

internal object MaxArgon2idCore {

    private const val BLOCK_LONGS = 128          // 1024 byte block = 128 x u64
    private const val SYNC_POINTS = 4
    private const val TYPE_ID = 2                // Argon2id
    private const val VERSION = 0x13             // v1.3
    private const val ADDRESSES_PER_BLOCK = 128
    private const val MIN_PROGRESS_STEP = 0.01f

    private val zeroBlock = LongArray(BLOCK_LONGS)   // read only, shared

    /** memoryKib = memory cost, iterations = time cost t, lanes = parallelism p. */
    fun hash(
        password: ByteArray,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        lanes: Int,
        tagLength: Int,
        secret: ByteArray = ByteArray(0),
        associatedData: ByteArray = ByteArray(0),
        onProgress: ((Float) -> Unit)? = null
    ): ByteArray {
        require(lanes in 1..0xFFFFFF) { "lanes out of range" }
        require(iterations >= 1) { "iterations must be at least 1" }
        require(tagLength >= 4) { "tag length must be at least 4 bytes" }
        require(salt.size >= 8) { "salt must be at least 8 bytes" }

        val laneLength = (memoryKib / (SYNC_POINTS * lanes)) * SYNC_POINTS
        require(laneLength >= 8) { "memory cost too small for $lanes lanes" }
        val memoryBlocks = laneLength * lanes
        val segmentLength = laneLength / SYNC_POINTS

        val memory = LongArray(memoryBlocks * BLOCK_LONGS)
        val runner = LaneRunner(lanes)
        var lastReported = -1f

        try {
            val h0 = blake2b(
                64,
                concat(
                    int32Le(lanes), int32Le(tagLength), int32Le(memoryKib), int32Le(iterations),
                    int32Le(VERSION), int32Le(TYPE_ID),
                    int32Le(password.size), password,
                    int32Le(salt.size), salt,
                    int32Le(secret.size), secret,
                    int32Le(associatedData.size), associatedData
                )
            )

            for (lane in 0 until lanes) {
                for (index in 0..1) {
                    val blockBytes = hPrime(1024, concat(h0, int32Le(index), int32Le(lane)))
                    bytesToLongs(blockBytes, memory, (lane * laneLength + index) * BLOCK_LONGS)
                    blockBytes.fill(0)
                }
            }
            h0.fill(0)

            for (pass in 0 until iterations) {
                for (slice in 0 until SYNC_POINTS) {
                    runner.runSlice { lane ->
                        val r = LongArray(BLOCK_LONGS)
                        val q = LongArray(BLOCK_LONGS)
                        val addressBlock = LongArray(BLOCK_LONGS)
                        val inputBlock = LongArray(BLOCK_LONGS)
                        try {
                            fillSegment(
                                memory, r, q, addressBlock, inputBlock,
                                pass, slice, lane, lanes, laneLength, segmentLength,
                                memoryBlocks, iterations
                            )
                        } finally {
                            wipeLongs(r)
                            wipeLongs(q)
                            wipeLongs(addressBlock)
                            wipeLongs(inputBlock)
                        }
                    }
                    val progress = (pass * SYNC_POINTS + slice + 1).toFloat() /
                            (iterations * SYNC_POINTS).toFloat()
                    if (onProgress != null && progress - lastReported >= MIN_PROGRESS_STEP) {
                        lastReported = progress
                        onProgress(progress)
                    }
                }
            }

            val finalBlock = LongArray(BLOCK_LONGS)
            try {
                for (lane in 0 until lanes) {
                    val offset = (lane * laneLength + laneLength - 1) * BLOCK_LONGS
                    for (i in 0 until BLOCK_LONGS) finalBlock[i] = finalBlock[i] xor memory[offset + i]
                }
                return hPrime(tagLength, longsToBytes(finalBlock))
            } finally {
                wipeLongs(finalBlock)
            }
        } finally {
            runner.close()
            wipeLongs(memory)
        }
    }

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
            startingIndex = 2
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

    private fun nextAddresses(
        r: LongArray,
        q: LongArray,
        addressBlock: LongArray,
        inputBlock: LongArray
    ) {
        inputBlock[6]++
        writeBlock(r, q, zeroBlock, inputBlock, addressBlock)
        writeBlock(r, q, zeroBlock, addressBlock, addressBlock)
    }

    private fun writeBlock(
        r: LongArray,
        q: LongArray,
        previous: LongArray,
        reference: LongArray,
        out: LongArray
    ) {
        for (i in 0 until BLOCK_LONGS) r[i] = previous[i] xor reference[i]
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
            for (i in 0 until BLOCK_LONGS) {
                memory[outputOffset + i] = memory[outputOffset + i] xor r[i] xor q[i]
            }
        } else {
            for (i in 0 until BLOCK_LONGS) memory[outputOffset + i] = r[i] xor q[i]
        }
    }

    /** P permutation: 8 rounds on consecutive 128 byte groups, then 8 rounds on strided pairs. */
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
        g(v, i0, i4, i8, i12)
        g(v, i1, i5, i9, i13)
        g(v, i2, i6, i10, i14)
        g(v, i3, i7, i11, i15)
        g(v, i0, i5, i10, i15)
        g(v, i1, i6, i11, i12)
        g(v, i2, i7, i8, i13)
        g(v, i3, i4, i9, i14)
    }

    private fun g(v: LongArray, a: Int, b: Int, c: Int, d: Int) {
        var va = v[a]
        var vb = v[b]
        var vc = v[c]
        var vd = v[d]
        va = blaMka(va, vb); vd = java.lang.Long.rotateRight(vd xor va, 32)
        vc = blaMka(vc, vd); vb = java.lang.Long.rotateRight(vb xor vc, 24)
        va = blaMka(va, vb); vd = java.lang.Long.rotateRight(vd xor va, 16)
        vc = blaMka(vc, vd); vb = java.lang.Long.rotateRight(vb xor vc, 63)
        v[a] = va
        v[b] = vb
        v[c] = vc
        v[d] = vd
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

        var relativePosition = pseudoRandom
        relativePosition = (relativePosition * relativePosition) ushr 32
        relativePosition = referenceAreaSize - 1 - ((referenceAreaSize * relativePosition) ushr 32)

        val startPosition = if (pass != 0) {
            if (slice == SYNC_POINTS - 1) 0 else (slice + 1) * segmentLength
        } else 0

        return ((startPosition + relativePosition) % laneLength).toInt()
    }

    // ---------------------------------------------------------------- H' / BLAKE2b

    /** H'(T, X) from RFC 9106, section 3.3. */
    fun hPrime(outputLength: Int, input: ByteArray): ByteArray {
        if (outputLength <= 64) return blake2b(outputLength, concat(int32Le(outputLength), input))

        val out = ByteArray(outputLength)
        var position = 0
        var buffer = blake2b(64, concat(int32Le(outputLength), input))
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

    /** BLAKE2b with an arbitrary digest length (1..64 bytes), unkeyed. */
    fun blake2b(outputLength: Int, input: ByteArray): ByteArray {
        require(outputLength in 1..64) { "BLAKE2b output length must be 1..64" }

        val h = LongArray(8)
        System.arraycopy(IV, 0, h, 0, 8)
        h[0] = h[0] xor (0x01010000L xor outputLength.toLong())

        val block = LongArray(16)
        var offset = 0
        val total = input.size

        try {
            while (offset < total) {
                java.util.Arrays.fill(block, 0L)
                val take = minOf(128, total - offset)
                for (i in 0 until take) {
                    block[i shr 3] = block[i shr 3] or
                            ((input[offset + i].toLong() and 0xFF) shl ((i and 7) * 8))
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
            return out
        } finally {
            wipeLongs(h)
            wipeLongs(block)
        }
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
        wipeLongs(v)
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
        v[a] = va
        v[b] = vb
        v[c] = vc
        v[d] = vd
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

    private fun int32Le(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 24) and 0xFF).toByte()
    )

    /** One thread per lane, capped by the number of available processors. */
    private class LaneRunner(private val laneCount: Int) {

        private val pool: ExecutorService? = if (laneCount > 1) {
            Executors.newFixedThreadPool(
                minOf(laneCount, Runtime.getRuntime().availableProcessors().coerceAtLeast(1))
            )
        } else {
            null
        }

        fun runSlice(action: (Int) -> Unit) {
            val executor = pool
            if (executor == null) {
                action(0)
                return
            }
            val futures = ArrayList<Future<*>>(laneCount)
            for (lane in 0 until laneCount) {
                futures.add(executor.submit { action(lane) })
            }
            for (future in futures) future.get()
        }

        fun close() {
            pool?.shutdownNow()
        }
    }
}

// =====================================================================================
//  INTERNAL TEST VECTORS
//  RFC 9106 section 5.3 (Argon2id), RFC 8439 sections 2.3.2 / 2.5.2 / 2.8.2
//  (ChaCha20, Poly1305, AEAD_CHACHA20_POLY1305) and draft-irtf-cfrg-xchacha-03
//  sections 2.2.1 / A.1 (HChaCha20, AEAD_XCHACHA20_POLY1305).
// =====================================================================================

private object MaxCryptoVectors {

    fun run(): List<String> {
        val failures = ArrayList<String>()
        var checks = 0

        fun check(name: String, expectedHex: String, actual: ByteArray) {
            checks++
            val actualHex = toHex(actual)
            if (!actualHex.equals(expectedHex, ignoreCase = true)) {
                failures.add("$name\n  expected: $expectedHex\n  actual:   $actualHex")
            }
        }

        val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

        // RFC 8439 section 2.3.2
        check(
            "ChaCha20 block function",
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
                    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
            MaxXChaCha20Poly1305.chacha20Block(
                key, 1, hex("000000090000004a00000000")
            )
        )

        // draft-irtf-cfrg-xchacha-03 section 2.2.1
        check(
            "HChaCha20 subkey",
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
            MaxXChaCha20Poly1305.hChaCha20(
                key, hex("000000090000004a0000000031415927")
            )
        )

        // RFC 8439 section 2.5.2
        check(
            "Poly1305 tag",
            "a8061dc1305136c6c22b8baf0c0127a9",
            MaxXChaCha20Poly1305.poly1305(
                hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
                "Cryptographic Forum Research Group".toByteArray(Charsets.US_ASCII)
            )
        )

        // RFC 8439 section 2.8.2
        run {
            val plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you " +
                    "only one tip for the future, sunscreen would be it.")
                .toByteArray(Charsets.US_ASCII)
            val keyBytes = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            val nonce = hex("070000004041424344454647")
            val aad = hex("50515253c0c1c2c3c4c5c6c7")
            val expected = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
                    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
                    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
                    "3ff4def08e4b7a9de576d26586cec64b6116" + "1ae10b594f09e26a7e902ecbd0600691"
            check(
                "AEAD_CHACHA20_POLY1305",
                expected,
                MaxXChaCha20Poly1305.sealIetf(keyBytes, nonce, aad, plaintext)
            )

            // draft-irtf-cfrg-xchacha-03 A.1
            val xNonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
            val xExpected = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
                    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
                    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
                    "21f9664c97637da9768812f615c68b13b52e" + "c0875924c1c7987947deafd8780acf49"
            val sealed = MaxXChaCha20Poly1305.seal(keyBytes, xNonce, aad, plaintext)
            check("AEAD_XCHACHA20_POLY1305", xExpected, sealed)

            // the same inputs must come back out of the opener; a flipped tag must not
            val opened = MaxXChaCha20Poly1305.open(keyBytes, xNonce, aad, sealed)
            check("XChaCha20-Poly1305 round trip", toHex(plaintext), opened ?: ByteArray(0))
            val tampered = sealed.copyOf()
            tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x01).toByte()
            if (MaxXChaCha20Poly1305.open(keyBytes, xNonce, aad, tampered) != null) {
                failures.add("XChaCha20-Poly1305 accepted a modified tag")
            }
        }

        // RFC 9106 section 5.3
        run {
            val password = ByteArray(32) { 0x01 }
            val salt = ByteArray(16) { 0x02 }
            val secret = ByteArray(8) { 0x03 }
            val associatedData = ByteArray(12) { 0x04 }
            check(
                "Argon2id RFC 9106 5.3",
                "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
                MaxArgon2idCore.hash(
                    password = password,
                    salt = salt,
                    memoryKib = 32,
                    iterations = 3,
                    lanes = 4,
                    tagLength = 32,
                    secret = secret,
                    associatedData = associatedData
                )
            )
        }

        // HKDF-SHA-512 differential check against a second, independent implementation
        run {
            val ikm = ByteArray(48) { (it * 7 + 5).toByte() }
            val salt = ByteArray(24) { (it * 3 + 1).toByte() }
            val info = "com.example.lock.MX2.vectors".toByteArray(Charsets.US_ASCII)
            for (length in intArrayOf(1, 32, 64, 65, 200, 255 * 64)) {
                check(
                    "HKDF-SHA-512 length $length",
                    toHex(referenceHkdfSha512(ikm, salt, info, length)),
                    hkdfSha512(ikm, salt, info, length)
                )
            }
        }

        // Poly1305 edge cases (empty message, partial trailing block, exact multiples of
        // 16 bytes) cross checked against a BigInteger form of the same definition.
        run {
            val polyKey = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            val random = java.security.SecureRandom()
            for (length in intArrayOf(0, 1, 2, 15, 16, 17, 31, 32, 33, 48, 64, 1000)) {
                val message = ByteArray(length)
                random.nextBytes(message)
                check(
                    "Poly1305 / BigInteger comparison, message of $length bytes",
                    toHex(referencePoly1305(polyKey, message)),
                    MaxXChaCha20Poly1305.poly1305(polyKey, message)
                )
            }
            for (iteration in 0 until 16) {
                val key = ByteArray(32)
                val message = ByteArray(1 + random.nextInt(200))
                random.nextBytes(key)
                random.nextBytes(message)
                check(
                    "Poly1305 / BigInteger comparison, random case $iteration",
                    toHex(referencePoly1305(key, message)),
                    MaxXChaCha20Poly1305.poly1305(key, message)
                )
            }
        }

        return failures
    }

    // ---------------------------------------------------------------- reference code

    /** Straightforward, independent HKDF-SHA-512 used to cross check [hkdfSha512]. */
    private fun referenceHkdfSha512(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int
    ): ByteArray {
        val effectiveSalt = if (salt.isEmpty()) ByteArray(64) else salt
        val prk = hmacSha512Raw(effectiveSalt, ikm)
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var filled = 0
        var counter = 1
        while (filled < length) {
            val mac = Mac.getInstance("HmacSHA512")
            mac.init(SecretKeySpec(prk, "HmacSHA512"))
            mac.update(previous)
            mac.update(info)
            mac.update(byteArrayOf(counter.toByte()))
            val block = mac.doFinal()
            val take = minOf(block.size, length - filled)
            System.arraycopy(block, 0, out, filled, take)
            filled += take
            previous = block
            counter++
        }
        return out
    }

    /**
     * Poly1305 evaluated with arbitrary precision integers straight from the definition in
     * RFC 8439 section 2.5 (accumulator * r mod 2^130 - 5, then + s mod 2^128). Fully
     * independent from the limb based production code, which is what makes it a useful
     * reference for the partial trailing block handling.
     */
    private fun referencePoly1305(key: ByteArray, message: ByteArray): ByteArray {
        val prime = java.math.BigInteger.ONE.shiftLeft(130)
            .subtract(java.math.BigInteger.valueOf(5))

        val clampedR = key.copyOfRange(0, 16)
        clampedR[3] = (clampedR[3].toInt() and 0x0F).toByte()
        clampedR[7] = (clampedR[7].toInt() and 0x0F).toByte()
        clampedR[11] = (clampedR[11].toInt() and 0x0F).toByte()
        clampedR[15] = (clampedR[15].toInt() and 0x0F).toByte()
        clampedR[4] = (clampedR[4].toInt() and 0xFC).toByte()
        clampedR[8] = (clampedR[8].toInt() and 0xFC).toByte()
        clampedR[12] = (clampedR[12].toInt() and 0xFC).toByte()

        val r = java.math.BigInteger(1, clampedR.reversedArray())
        val s = java.math.BigInteger(1, key.copyOfRange(16, 32).reversedArray())

        var accumulator = java.math.BigInteger.ZERO
        var offset = 0
        while (offset < message.size) {
            val take = minOf(16, message.size - offset)
            val block = ByteArray(take + 1)
            System.arraycopy(message, offset, block, 0, take)
            block[take] = 0x01
            accumulator = accumulator.add(java.math.BigInteger(1, block.reversedArray()))
            accumulator = accumulator.multiply(r).mod(prime)
            offset += take
        }

        accumulator = accumulator.add(s).mod(java.math.BigInteger.ONE.shiftLeft(128))
        val bigEndian = accumulator.toByteArray()
        val littleEndian = ByteArray(16)
        var cursor = bigEndian.size - 1
        var index = 0
        while (cursor >= 0 && index < 16) {
            littleEndian[index] = bigEndian[cursor]
            cursor--
            index++
        }
        return littleEndian
    }

    private fun toHex(bytes: ByteArray): String {
        val builder = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val value = b.toInt() and 0xFF
            builder.append(HEX[value ushr 4])
            builder.append(HEX[value and 0x0F])
        }
        return builder.toString()
    }

    private fun hex(value: String): ByteArray {
        val out = ByteArray(value.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(value[i * 2], 16) shl 4) or
                    Character.digit(value[i * 2 + 1], 16)).toByte()
        }
        return out
    }

    private const val HEX = "0123456789abcdef"
}
