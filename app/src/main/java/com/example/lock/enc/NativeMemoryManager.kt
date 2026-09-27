// ============================================================================
// NativeMemoryManager.kt — JNI bridge to the native locked-memory allocator
// Package: com.example.lock.enc (must match JNI symbols in native-lib.cpp)
// Location: app/src/main/java/com/example/lock/enc/NativeMemoryManager.kt
//
// Failure policy:
//   - Data-path operations (allocate / copy) FAIL CLOSED: they throw when the
//     native layer rejects the request.
//   - Cleanup operations FAIL SOFT: wipeByteArray falls back to Arrays.fill
//     when the native layer is unavailable, so finally-blocks never throw.
//   - Startup self-test: the library is marked unavailable if any native
//     symbol fails to link (UnsatisfiedLinkError) or the round-trip self-test
//     fails, so a broken build surfaces at initialization instead of
//     mid-encryption.
//
// ProGuard/R8: keep the class and its native methods, e.g.
//   -keepclasseswithmembernames class com.example.lock.enc.NativeMemoryManager {
//       native <methods>;
//   }
//   otherwise obfuscated renaming breaks JNI symbol resolution again.
// ============================================================================

package com.example.lock.enc

import java.util.Arrays

object NativeMemoryManager {

    @Volatile
    private var isNativeLoaded = false

    init {
        isNativeLoaded = try {
            System.loadLibrary("cvltsec_native")
            // Round-trip + negative-path self-test. Also catches mismatched
            // JNI symbol names immediately (throws UnsatisfiedLinkError).
            nativeSelfTest()
        } catch (t: Throwable) {
            false
        }
    }

    fun isNativeAvailable(): Boolean = isNativeLoaded

    /**
     * Allocates [size] bytes outside the Java heap, page-locked with mlock.
     * Fail-closed: throws when the native layer is unavailable, or when the
     * allocation/mlock request is rejected (no silent fallback to swappable memory).
     */
    fun allocateLocked(size: Long): Long {
        check(isNativeLoaded) { "Native memory library is not loaded." }
        require(size > 0) { "Allocation size must be positive." }
        val address = nativeAllocateLocked(size)
        if (address == 0L) {
            throw SecurityException(
                "Secure allocation failed: mlock unavailable or request rejected. Fail-closed."
            )
        }
        return address
    }

    /**
     * Zeroizes, unlocks and frees a locked allocation.
     * Returns false when the address is unknown/stale (double free), the size
     * does not match the allocation record, or the native layer is unavailable.
     * Does not throw: cleanup paths must remain usable inside finally-blocks.
     */
    fun freeLocked(address: Long, size: Long): Boolean {
        if (!isNativeLoaded || address == 0L) return false
        return nativeFreeLocked(address, size)
    }

    /**
     * Copies [length] bytes from a JVM array into locked native memory.
     * Fail-closed: throws on any bounds/address rejection.
     */
    fun copyFromByteArray(src: ByteArray, destAddress: Long, length: Int) {
        check(isNativeLoaded) { "Native memory library is not loaded." }
        require(length >= 0 && length <= src.size) {
            "Copy length exceeds source array bounds."
        }
        if (!nativeCopyFromByteArray(src, destAddress, length)) {
            throw SecurityException(
                "Native copy-in rejected: invalid address or bounds violation. Fail-closed."
            )
        }
    }

    /**
     * Copies [length] bytes from locked native memory into a JVM array.
     * Fail-closed: throws on any bounds/address rejection.
     */
    fun copyToByteArray(srcAddress: Long, dest: ByteArray, length: Int) {
        check(isNativeLoaded) { "Native memory library is not loaded." }
        require(length >= 0 && length <= dest.size) {
            "Copy length exceeds destination array bounds."
        }
        if (!nativeCopyToByteArray(srcAddress, dest, length)) {
            throw SecurityException(
                "Native copy-out rejected: invalid address or bounds violation. Fail-closed."
            )
        }
    }

    /**
     * Zeroizes a JVM byte array. Uses the native wipe (GetPrimitiveArrayCritical,
     * no transient heap copy) when available; otherwise falls back to Arrays.fill.
     * Never throws — safe to call from finally-blocks.
     */
    fun wipeByteArray(array: ByteArray) {
        if (isNativeLoaded) {
            try {
                nativeWipeByteArray(array)
                return
            } catch (t: Throwable) {
                // Fall through to the managed fallback below.
            }
        }
        Arrays.fill(array, 0.toByte())
    }

    // ---- native methods (symbols defined in native-lib.cpp) ----
    private external fun nativeAllocateLocked(size: Long): Long
    private external fun nativeFreeLocked(address: Long, size: Long): Boolean
    private external fun nativeCopyFromByteArray(src: ByteArray, destAddress: Long, length: Int): Boolean
    private external fun nativeCopyToByteArray(srcAddress: Long, dest: ByteArray, length: Int): Boolean
    private external fun nativeWipeByteArray(array: ByteArray)
    private external fun nativeSelfTest(): Boolean
}
