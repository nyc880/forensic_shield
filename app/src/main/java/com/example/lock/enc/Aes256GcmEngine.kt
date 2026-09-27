// ============================================================================
// File #3 (was: 3_AES-256.txt) — Aes256GcmEngine.kt
// AES-256-GCM AEAD engine (hardware-accelerated through Conscrypt / ARMv8)
// Package: com.example.lock.enc
// Path: app/src/main/java/com/example/lock/enc/Aes256GcmEngine.kt
//
// Changes in this revision (step 4):
//   1. REMOVED the engine-level encryptStream/decryptStream API instead of
//      patching it with readFully. It was dead code (FileContainerEngine —
//      file #9 — is the only streaming path), it defined a SECOND weaker
//      on-disk format (no header/salt/chain/FINAL marker — vulnerable to the
//      truncation attack v0x02 eliminated), and its reads used single read()
//      calls (partial-read false "tampered" errors + the silent
//      while(read==4) exit bug). Deletion removes all of it at the root.
//   2. Error classification: ONLY GCM tag failures (AEADBadTagException /
//      BadPaddingException) are translated into a sanitized SecurityException.
//      Init/programming/environment errors propagate unchanged instead of
//      every failure claiming "data tampered".
//   3. Protocol check: a ciphertext shorter than the 16-byte GCM tag raises
//      SecurityException before touching JCE.
//   4. Removed the no-op `finally { secretKey = null }` (dropping a reference
//      wipes nothing). DOCUMENTED inherent limitation: SecretKeySpec and the
//      JCE provider clone key bytes internally; those clones cannot be wiped
//      from Kotlin. The definitive fix is a native crypto core (planned).
// ============================================================================

package com.example.lock.enc

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Single-shot AES-256-GCM AEAD engine.
 * Streaming/chunking is owned exclusively by FileContainerEngine (file #9).
 */
class Aes256GcmEngine private constructor() {

    companion object {
        const val KEY_SIZE_BYTES = 32    // 256-bit key
        const val NONCE_SIZE_BYTES = 12  // 96-bit GCM IV (standard)
        const val TAG_SIZE_BITS = 128    // 128-bit authentication tag
        const val TAG_SIZE_BYTES = 16

        private const val CIPHER_ALGORITHM = "AES/GCM/NoPadding"
        private const val KEY_ALGORITHM = "AES"

        private val secureRandom = SecureRandom()

        fun create(): Aes256GcmEngine = Aes256GcmEngine()

        /** Random 12-byte master nonce/IV from the OS CSPRNG. */
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
     * Single-shot in-memory encryption. Returns ciphertext || 16-byte tag.
     *
     * Note: SecretKeySpec clones the key bytes internally and the provider
     * keeps its own expanded key schedule; neither clone is reachable for
     * wiping from Kotlin (inherent JCE limitation — see header comment).
     */
    fun encrypt(
        plaintext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray? = null
    ): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "AES key must be exactly 32 bytes." }
        require(nonce.size == NONCE_SIZE_BYTES) { "GCM nonce must be exactly 12 bytes." }

        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, KEY_ALGORITHM),
            GCMParameterSpec(TAG_SIZE_BITS, nonce)
        )
        associatedData?.let { cipher.updateAAD(it) }
        return cipher.doFinal(plaintext)
    }

    /**
     * Single-shot in-memory decryption with GCM tag verification.
     * The provider releases plaintext only after the tag verifies.
     */
    fun decrypt(
        ciphertext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray? = null
    ): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "AES key must be exactly 32 bytes." }
        require(nonce.size == NONCE_SIZE_BYTES) { "GCM nonce must be exactly 12 bytes." }
        if (ciphertext.size < TAG_SIZE_BYTES) {
            throw SecurityException("Ciphertext is shorter than the GCM authentication tag.")
        }

        try {
            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, KEY_ALGORITHM),
                GCMParameterSpec(TAG_SIZE_BITS, nonce)
            )
            associatedData?.let { cipher.updateAAD(it) }
            return cipher.doFinal(ciphertext)
        } catch (e: AEADBadTagException) {
            // Sanitized: no cause, no internal detail (anti-forensic policy).
            throw SecurityException("Authentication failed: data tampered or wrong key.")
        } catch (e: BadPaddingException) {
            // Some providers report GCM tag failures as plain BadPaddingException.
            throw SecurityException("Authentication failed: data tampered or wrong key.")
        }
    }
}
