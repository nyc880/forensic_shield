// ============================================================================
// ContainerHeader.kt — CVLT encrypted container header (format version 0x03)
// Package: com.example.lock.enc
//
// Canonical layout — 86 bytes, fixed order, big-endian:
//   [0..3]    magic      "CVLT" (0x43 0x56 0x4C 0x54)
//   [4]       version    0x03
//   [5..17]   KdfParams  (13 bytes: kdfId | memoryCostKb | iterations | parallelism)
//   [18..49]  salt       (32 bytes, Argon2id)
//   [50..73]  XChaCha20-Poly1305 master nonce (24 bytes)
//   [74..85]  AES-256-GCM master nonce (12 bytes)
//
// Version history:
//   0x01 — original format (truncation-vulnerable; never parsed here).
//   0x02 — FINAL record + chained AAD + embedded KdfParams. ENCRYPTED WITH A
//          NON-STANDARD XChaCha20 (wrong second ChaCha constant 0x33322064).
//   0x03 — IDENTICAL on-disk structure to 0x02, but the XChaCha20 layer uses
//          the STANDARD constants (draft-irtf-cfrg-xchacha-03 compliant).
//          The bump exists purely so legacy 0x02 containers fail with a
//          clear "Unsupported container version" instead of a confusing
//          "authentication failed". No real user data exists in 0x02.
//
// Why the header is authenticated:
//   1. KdfParams are embedded. Argon2id output is a function of (m, t, p):
//      the exact parameters used at encryption time MUST travel with the
//      container, otherwise decryption on another device (or after an app
//      update) silently derives a different key and fails.
//   2. The serialized header bytes are bound into the record chain:
//      chainState[0] = HMAC-SHA384(chainMacKey, headerBytes), and chainState
//      is part of every record's AAD. Any header tampering therefore breaks
//      authentication of the first record.
//   3. Parsing uses readFully semantics: a partial read can never masquerade
//      as EOF, and hostile KDF parameter values are rejected by bounds
//      validation inside KdfParams.fromByteArray (anti-DoS).
// ============================================================================

package com.example.lock.enc

import java.io.DataInputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * Metadata and KDF parameters of an encrypted CVLT container.
 */
data class ContainerHeader(
    val version: Byte = CURRENT_VERSION,
    val params: KdfParams,
    val salt: ByteArray,
    val xChaChaNonce: ByteArray,
    val aesNonce: ByteArray
) {

    init {
        require(salt.size == SALT_SIZE) {
            "Salt must be exactly $SALT_SIZE bytes."
        }
        require(xChaChaNonce.size == XCHACHA_NONCE_SIZE) {
            "XChaCha20 master nonce must be exactly $XCHACHA_NONCE_SIZE bytes."
        }
        require(aesNonce.size == AES_NONCE_SIZE) {
            "AES-GCM master nonce must be exactly $AES_NONCE_SIZE bytes."
        }
        params.validate()
    }

    companion object {
        val MAGIC_BYTES: ByteArray = byteArrayOf(0x43, 0x56, 0x4C, 0x54) // "CVLT"
        const val CURRENT_VERSION: Byte = 0x03

        const val SALT_SIZE = 32
        const val XCHACHA_NONCE_SIZE = 24
        const val AES_NONCE_SIZE = 12

        // 4 magic + 1 version + 13 KdfParams + 32 salt + 24 nonce + 12 nonce = 86
        const val HEADER_SIZE: Int =
            4 + 1 + KdfParams.ENCODED_SIZE_BYTES + SALT_SIZE + XCHACHA_NONCE_SIZE + AES_NONCE_SIZE

        private const val PARAMS_OFFSET = 5

        /**
         * Strict parser for exactly HEADER_SIZE bytes.
         * Rejects unknown magic, unsupported versions, and hostile KDF
         * parameters (bounds are enforced inside KdfParams.fromByteArray).
         */
        fun parse(raw: ByteArray): ContainerHeader {
            if (raw.size != HEADER_SIZE) {
                throw SecurityException("Invalid container header length.")
            }

            val buffer = ByteBuffer.wrap(raw)

            val magic = ByteArray(MAGIC_BYTES.size)
            buffer.get(magic)
            if (!MessageDigest.isEqual(magic, MAGIC_BYTES)) {
                throw SecurityException("Not a CVLT container: magic bytes mismatch.")
            }

            val version = buffer.get()
            if (version != CURRENT_VERSION) {
                throw SecurityException("Unsupported container version: $version")
            }

            // Validates kdfId and enforces bounds on m/t/p (anti-DoS).
            val params = KdfParams.fromByteArray(raw, PARAMS_OFFSET)

            // Advance past the 13-byte params field so the buffer position
            // matches the canonical layout before reading the salt.
            buffer.position(PARAMS_OFFSET + KdfParams.ENCODED_SIZE_BYTES)

            val salt = ByteArray(SALT_SIZE)
            val xChaChaNonce = ByteArray(XCHACHA_NONCE_SIZE)
            val aesNonce = ByteArray(AES_NONCE_SIZE)
            buffer.get(salt)
            buffer.get(xChaChaNonce)
            buffer.get(aesNonce)

            return ContainerHeader(
                version = version,
                params = params,
                salt = salt,
                xChaChaNonce = xChaChaNonce,
                aesNonce = aesNonce
            )
        }

        /**
         * Reads exactly HEADER_SIZE bytes with readFully semantics.
         * Returns the parsed header AND the exact raw bytes as read from the
         * stream. The raw copy is what must be bound into the chain state —
         * never re-serialize for that purpose.
         * A truncated header surfaces as EOFException.
         */
        fun readFrom(input: DataInputStream): Pair<ContainerHeader, ByteArray> {
            val raw = ByteArray(HEADER_SIZE)
            input.readFully(raw)
            return Pair(parse(raw), raw)
        }
    }

    /** Canonical, deterministic serialization (the exact bytes written to disk). */
    fun serialize(): ByteArray {
        val buffer = ByteBuffer.allocate(HEADER_SIZE)
        buffer.put(MAGIC_BYTES)
        buffer.put(version)
        buffer.put(params.toByteArray())
        buffer.put(salt)
        buffer.put(xChaChaNonce)
        buffer.put(aesNonce)
        return buffer.array()
    }

    fun writeToStream(output: OutputStream) {
        output.write(serialize())
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ContainerHeader

        if (version != other.version) return false
        if (params != other.params) return false
        if (!salt.contentEquals(other.salt)) return false
        if (!xChaChaNonce.contentEquals(other.xChaChaNonce)) return false
        if (!aesNonce.contentEquals(other.aesNonce)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version.toInt()
        result = 31 * result + params.hashCode()
        result = 31 * result + salt.contentHashCode()
        result = 31 * result + xChaChaNonce.contentHashCode()
        result = 31 * result + aesNonce.contentHashCode()
        return result
    }
}
