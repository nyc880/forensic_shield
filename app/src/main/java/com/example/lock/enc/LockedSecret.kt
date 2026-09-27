// ============================================================================
// File #7 (was: 7_RAM2(kotlin).txt) — LockedSecret.kt
// Isolated container for long-lived secrets in page-locked native memory
// Package: com.example.lock.enc
// Path: app/src/main/java/com/example/lock/enc/LockedSecret.kt
//
// Role in the hybrid architecture (chosen 2026-09-21):
//   Persistent home of every derived key is mlock'd native memory managed by
//   NativeMemoryManager. The JVM heap holds a key only as a short-lived
//   "borrowed" copy during a crypto call (useKey), wiped in a finally block.
//   The old design flaw this fixes: keys previously lived their whole
//   lifetime as JVM heap arrays (CascadedKeyContainer) and LockedSecret was
//   dead code never referenced by any module.
//
// Changes vs the original file 7:
//   - finalize() REMOVED: finalizers are unreliable on ART and deprecated;
//     destruction is explicit (close()/wipe()), guaranteed by the container
//     engine's finally blocks.
//   - fromByteArray() wipes the JVM source array on ALL paths (including
//     native write failure, where the partially-filled secret is destroyed).
//   - Fail-closed: allocation throws when the native layer is unavailable —
//     no silent fallback to heap-resident secrets.
//   - English-only comments; package unified to com.example.lock.enc.
//
// Step-8 change (exception-safety contract):
//   - wipe() is now NON-throwing and returns Boolean: `true` = buffer is
//     definitively destroyed (or was already destroyed); `false` = the free
//     attempt failed and locked memory may still contain the secret. A
//     throwing wipe() inside a finally block could mask the original
//     exception (report item 5), so all cleanup paths must use wipe().
//   - close() keeps the strict AutoCloseable contract: it calls wipe() and
//     throws SecurityException when destruction failed. Use close() where a
//     failure must be reported; use wipe() in finally blocks.
// ============================================================================

package com.example.lock.enc

/**
 * AutoCloseable holder for one secret (a cryptographic key) whose persistent
 * copy lives in mlock'd native memory. Thread-safe: every operation is
 * synchronized on this instance; use-after-wipe is rejected.
 */
class LockedSecret private constructor(
    /** Capacity of the locked buffer, in bytes. */
    val size: Int
) : AutoCloseable {

    private var address: Long = 0L

    @Volatile
    var isWiped: Boolean = false
        private set

    init {
        require(size > 0) { "Secret buffer size must be positive." }
        // Fail-closed: throws SecurityException when mlock/allocation fails
        // or the native library is not loaded. Never falls back to the heap.
        address = NativeMemoryManager.allocateLocked(size.toLong())
    }

    companion object {
        /**
         * Absorbs [source] into a fresh locked buffer. The JVM source array
         * is wiped on every path — success or failure — because it already
         * contains the secret.
         */
        fun fromByteArray(source: ByteArray): LockedSecret {
            require(source.isNotEmpty()) { "Cannot store an empty secret." }
            val secret = LockedSecret(source.size)
            try {
                secret.write(source)
            } catch (t: Throwable) {
                // The locked buffer may hold a partial secret — destroy it.
                secret.wipe()
                throw t
            } finally {
                NativeMemoryManager.wipeByteArray(source)
            }
            return secret
        }

        /** Allocates an empty locked buffer (caller fills it via write()). */
        fun allocate(size: Int): LockedSecret = LockedSecret(size)
    }

    /**
     * Copies [data] into the locked buffer. The caller remains responsible
     * for wiping [data] afterwards (fromByteArray does it automatically).
     */
    @Synchronized
    fun write(data: ByteArray) {
        check(!isWiped) { "Secret was already destroyed." }
        require(data.size <= size) { "Data exceeds the locked buffer capacity." }
        NativeMemoryManager.copyFromByteArray(data, address, data.size)
    }

    /** Copies the secret into a caller-provided JVM array (borrower wipes it). */
    @Synchronized
    fun readToByteArray(destination: ByteArray) {
        check(!isWiped) { "Secret was already destroyed." }
        require(destination.size >= size) { "Destination array is too small." }
        NativeMemoryManager.copyToByteArray(address, destination, size)
    }

    /**
     * Borrow pattern: materializes the secret into a transient JVM array for
     * the duration of [block] (needed while crypto engines run on the JVM),
     * and wipes that array in a finally block regardless of the outcome.
     * The persistent copy never leaves locked native memory.
     */
    @Synchronized
    fun <R> useKey(block: (ByteArray) -> R): R {
        check(!isWiped) { "Secret was already destroyed." }
        val tempKey = ByteArray(size)
        try {
            readToByteArray(tempKey)
            return block(tempKey)
        } finally {
            NativeMemoryManager.wipeByteArray(tempKey)
        }
    }

    /**
     * Zeroizes (natively), unlocks and frees the buffer. Idempotent and
     * NON-throwing: safe to call from finally blocks without masking the
     * in-flight exception.
     *
     * @return `true` when the buffer is definitively destroyed (or was
     *         already destroyed); `false` when the native free attempt
     *         failed and locked memory may still contain key material.
     *         Callers should treat `false` as a security incident worth
     *         logging/reporting through the anti-tamper channel.
     */
    @Synchronized
    fun wipe(): Boolean {
        if (isWiped || address == 0L) return true
        return try {
            NativeMemoryManager.freeLocked(address, size.toLong())
            address = 0L
            isWiped = true
            true
        } catch (t: Throwable) {
            // Never propagate from a cleanup path. Keep the address marked
            // live: a retry of wipe() may still succeed later.
            false
        }
    }

    /**
     * Strict destruction for AutoCloseable contexts: throws
     * [SecurityException] when the locked buffer could not be destroyed.
     * In finally-block cleanup paths prefer the non-throwing [wipe].
     */
    @Throws(SecurityException::class)
    override fun close() {
        if (!wipe()) {
            throw SecurityException(
                "Secure key memory could not be destroyed; material may persist."
            )
        }
    }

    // Deliberately NO finalize(): on ART it may never run (or run far too
    // late) and it cannot be trusted for security-critical cleanup. Owners
    // must call close()/wipe() explicitly — the container engine does so in
    // its finally blocks.
}
