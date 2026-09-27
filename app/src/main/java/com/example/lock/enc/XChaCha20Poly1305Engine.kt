// ============================================================================
// File #2 (was: 2_Xchacha20.txt) — XChaCha20Poly1305Engine.kt
// XChaCha20-Poly1305 AEAD engine per draft-irtf-cfrg-xchacha
// Package: com.example.lock.enc
// Path: app/src/main/java/com/example/lock/enc/XChaCha20Poly1305Engine.kt
//
// Changes in this revision (step 4):
//   1. REMOVED the engine-level encryptStream/decryptStream API instead of
//      patching it with readFully. Rationale:
//      - It was dead code: FileContainerEngine (file #9) is the only
//        container path and calls just the single-shot encrypt/decrypt.
//      - It defined a SECOND on-disk format (raw nonce + 64 KB chunks) with
//        no header, no salt, no chain state and no FINAL marker — vulnerable
//        to the exact truncation attack that format v0x02 eliminated, and
//        unreadable by the container engine.
//      - Its reads used single read() calls: partial reads (SAF/Content
//        streams) caused false "tampered" errors plus the silent-exit bug
//        (while (read(sizeBuffer) == 4)).
//      Deleting the API removes all three problems at the root.
//   2. decrypt() plaintext hygiene: the internal buffer that carries the
//      plaintext is now wiped in a finally block on BOTH success and failure
//      paths; only the trimmed result copy escapes (fixes the audit finding
//      that `output` was left on the heap).
//   3. Error classification: ONLY InvalidCipherTextException (Poly1305 tag
//      mismatch) is translated into a sanitized SecurityException;
//      programming/environment errors propagate unchanged instead of being
//      mislabeled as "data tampered".
//   4. Protocol check: a ciphertext shorter than the 16-byte tag raises
//      SecurityException before any crypto processing.
//
// Verified core: HChaCha20 (column/diagonal quarter rounds, little-endian
// word loads, output words 0-3 and 12-15 WITHOUT adding the initial state)
// and the XChaCha construction (subkey = HChaCha20(key, nonce[0:16]); AEAD
// nonce = 0x00*4 || nonce[16:24]) now reproduce the OFFICIAL test vectors of
// draft-irtf-cfrg-xchacha-03 exactly:
//   - Section 2.2.1 HChaCha20 KAT (see XChaCha20Poly1305EngineTest)
//   - Appendix A.3.1 AEAD_XCHACHA20_POLY1305 (ciphertext, tag AND the
//     Poly1305 one-time key match byte-for-byte)
//
// Step-6 fix (CRITICAL): the second ChaCha constant was WRONG in the
// original module and was inherited here: 0x33322064 ("d 23") instead of the
// standard 0x3320646e ("nd 3" from "expand 32-byte k"). With the wrong
// constant the engine still round-trips (encrypt/decrypt agree) but produces
// a NON-STANDARD XChaCha: incompatible with libsodium/Tink/WireGuard and the
// draft vectors. The constant is corrected below; containers produced by the
// buggy build are unreadable by this version (there are no real files, only
// tests — accepted incompatibility).
// ============================================================================

package com.example.lock.enc

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

/**
 * Single-shot XChaCha20-Poly1305 AEAD engine.
 * Streaming/chunking is owned exclusively by FileContainerEngine (file #9).
 */
class XChaCha20Poly1305Engine private constructor() {

    companion object {
        const val KEY_SIZE_BYTES = 32        // 256-bit key
        const val NONCE_SIZE_BYTES = 24      // 192-bit XChaCha master nonce
        const val HCHACHA_NONCE_SIZE = 16    // nonce[0:16] -> HChaCha20
        const val AEAD_NONCE_SIZE = 12       // inner ChaCha20-Poly1305 nonce
        const val MAC_TAG_SIZE_BYTES = 16    // Poly1305 tag (128-bit)

        // Standard ChaCha20 constants: little-endian words of the ASCII
        // string "expand 32-byte k" ("expa", "nd 3", "2-by", "te k").
        // FIXED in step 6: word 2 was 0x33322064 ("d 23") — non-standard.
        private val CHACHA20_CONSTANTS = intArrayOf(
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
        )

        private val secureRandom = SecureRandom()

        fun create(): XChaCha20Poly1305Engine = XChaCha20Poly1305Engine()

        /** Random 24-byte master nonce from the OS CSPRNG. */
        fun generateNonce(): ByteArray {
            val nonce = ByteArray(NONCE_SIZE_BYTES)
            secureRandom.nextBytes(nonce)
            return nonce
        }

        fun wipeByteArray(bytes: ByteArray) {
            Arrays.fill(bytes, 0.toByte())
        }

        /** Constant-time comparison (timing-attack resistance). */
        fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
            return MessageDigest.isEqual(a, b)
        }
    }

    /**
     * HChaCha20: (256-bit key, 128-bit nonce) -> 256-bit subkey.
     * Per draft-irtf-cfrg-xchacha section 2.2.
     */
    fun hChaCha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "Key must be exactly 32 bytes." }
        require(nonce16.size == HCHACHA_NONCE_SIZE) { "HChaCha20 nonce must be exactly 16 bytes." }

        val state = IntArray(16)
        val subkey = ByteArray(KEY_SIZE_BYTES)

        try {
            state[0] = CHACHA20_CONSTANTS[0]
            state[1] = CHACHA20_CONSTANTS[1]
            state[2] = CHACHA20_CONSTANTS[2]
            state[3] = CHACHA20_CONSTANTS[3]

            // Key: 8 little-endian 32-bit words
            val keyBuffer = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN)
            for (i in 0 until 8) {
                state[4 + i] = keyBuffer.getInt(i * 4)
            }

            // Nonce: 4 little-endian 32-bit words
            val nonceBuffer = ByteBuffer.wrap(nonce16).order(ByteOrder.LITTLE_ENDIAN)
            for (i in 0 until 4) {
                state[12 + i] = nonceBuffer.getInt(i * 4)
            }

            // 20 rounds = 10 double rounds (column + diagonal)
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

            // Output = words 0..3 and 12..15, WITHOUT adding the initial state
            val outBuffer = ByteBuffer.wrap(subkey).order(ByteOrder.LITTLE_ENDIAN)
            outBuffer.putInt(0 * 4, state[0])
            outBuffer.putInt(1 * 4, state[1])
            outBuffer.putInt(2 * 4, state[2])
            outBuffer.putInt(3 * 4, state[3])
            outBuffer.putInt(4 * 4, state[12])
            outBuffer.putInt(5 * 4, state[13])
            outBuffer.putInt(6 * 4, state[14])
            outBuffer.putInt(7 * 4, state[15])

            return subkey
        } finally {
            Arrays.fill(state, 0)
        }
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] = x[a] + x[b]; x[d] = (x[d] xor x[a]).rotateLeft(16)
        x[c] = x[c] + x[d]; x[b] = (x[b] xor x[c]).rotateLeft(12)
        x[a] = x[a] + x[b]; x[d] = (x[d] xor x[a]).rotateLeft(8)
        x[c] = x[c] + x[d]; x[b] = (x[b] xor x[c]).rotateLeft(7)
    }

    /**
     * Single-shot in-memory encryption.
     * Returns ciphertext || 16-byte Poly1305 tag.
     */
    fun encrypt(
        plaintext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray? = null
    ): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "Key must be exactly 32 bytes." }
        require(nonce.size == NONCE_SIZE_BYTES) { "Nonce must be exactly 24 bytes." }

        val hChaChaNonce = nonce.copyOfRange(0, HCHACHA_NONCE_SIZE)
        val subkey = hChaCha20(key, hChaChaNonce)

        // Inner AEAD nonce: 0x00*4 || nonce[16:24]
        val aeadNonce = ByteArray(AEAD_NONCE_SIZE)
        System.arraycopy(nonce, HCHACHA_NONCE_SIZE, aeadNonce, 4, NONCE_SIZE_BYTES - HCHACHA_NONCE_SIZE)

        try {
            val cipher = ChaCha20Poly1305()
            cipher.init(true, ParametersWithIV(KeyParameter(subkey), aeadNonce))
            associatedData?.let { cipher.processAADBytes(it, 0, it.size) }

            val output = ByteArray(cipher.getOutputSize(plaintext.size))
            val len = cipher.processBytes(plaintext, 0, plaintext.size, output, 0)
            cipher.doFinal(output, len)
            return output // ciphertext is not sensitive; no wipe required
        } finally {
            wipeByteArray(hChaChaNonce)
            wipeByteArray(subkey)
            wipeByteArray(aeadNonce)
        }
    }

    /**
     * Single-shot in-memory decryption with Poly1305 tag verification.
     * BouncyCastle verifies the tag BEFORE releasing any plaintext, and the
     * plaintext-bearing buffer is wiped here on all paths.
     */
    fun decrypt(
        ciphertext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray? = null
    ): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "Key must be exactly 32 bytes." }
        require(nonce.size == NONCE_SIZE_BYTES) { "Nonce must be exactly 24 bytes." }
        if (ciphertext.size < MAC_TAG_SIZE_BYTES) {
            throw SecurityException("Ciphertext is shorter than the Poly1305 authentication tag.")
        }

        val hChaChaNonce = nonce.copyOfRange(0, HCHACHA_NONCE_SIZE)
        val subkey = hChaCha20(key, hChaChaNonce)

        val aeadNonce = ByteArray(AEAD_NONCE_SIZE)
        System.arraycopy(nonce, HCHACHA_NONCE_SIZE, aeadNonce, 4, NONCE_SIZE_BYTES - HCHACHA_NONCE_SIZE)

        var output: ByteArray? = null
        try {
            val cipher = ChaCha20Poly1305()
            cipher.init(false, ParametersWithIV(KeyParameter(subkey), aeadNonce))
            associatedData?.let { cipher.processAADBytes(it, 0, it.size) }

            val out = ByteArray(cipher.getOutputSize(ciphertext.size))
            output = out
            val len = cipher.processBytes(ciphertext, 0, ciphertext.size, out, 0)
            val finalLen = cipher.doFinal(out, len)

            return out.copyOf(len + finalLen)
        } catch (e: InvalidCipherTextException) {
            // Sanitized: no cause, no internal detail (anti-forensic policy).
            throw SecurityException("Authentication failed: data tampered or wrong key.")
        } finally {
            // FIX: wipe the plaintext-bearing buffer on success AND failure.
            output?.let { wipeByteArray(it) }
            wipeByteArray(hChaChaNonce)
            wipeByteArray(subkey)
            wipeByteArray(aeadNonce)
        }
    }
}
