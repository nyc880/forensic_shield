// ============================================================================
// File #12 (was: forensic_manager.txt) — ForensicManager.kt
// Central orchestrator of the anti-forensic engine — FINAL INTEGRATION
// Package: com.example.lock.enc
// Path: app/src/main/java/com/example/lock/enc/ForensicManager.kt
//
// What this file connects (every module in the project):
//
//   FileContainerEngine (#9)  <- the ONLY crypto entry point; receives the
//                                KDF module and a SecurityEventSink so that
//                                key-destruction failures are observable.
//   MilitaryKdfModule (#1)    -> owns Argon2id + HKDF key separation; its
//                                LockedSecret-based storage is what makes
//                                the fail-closed native check below real.
//   LockedSecret (#7)         \
//   NativeMemoryManager (#6)   } mlock'd native key memory; the manager
//   native-lib.cpp (#4)       /  refuses to serve ANY operation when this
//                              layer is unavailable (fail-closed, no heap
//                              fallback).
//   AntiTamperEngine (#10)    -> environment gate executed before every
//                                cryptographic operation.
//   SecurityThreat (#11)      -> the severity model + the SecurityEvent
//                                channel used for ALL reporting.
//   ContainerHeader (#8), XChaCha20Poly1305Engine (#2), Aes256GcmEngine (#3)
//                             -> used indirectly through FileContainerEngine;
//                                never touched directly from this layer.
//
// Step-12 integration items (report round 4):
//   - item 19: threat reporting is WIRED, not commented out. The app
//     injects a SecurityEventSink (UI toast / encrypted local log /
//     telemetry); every finding of every assessment and every
//     security-relevant failure flows through it as a sanitized event.
//   - item 21: key-material destruction failures inside the container
//     engine reach the same channel via the sink passed to
//     FileContainerEngine.create().
//   - item 22: this manager NEVER wipes the caller's password CharArray.
//     The original file did exactly that in a finally block — a contract
//     violation, because the caller owns the array (it may legitimately
//     reuse it, e.g. to show the vault again). Ownership rule: only the
//     creator of a secret wipes it. All INTERNAL copies are wiped by the
//     KDF/engine layers themselves.
//   - item 24: the environment gate blocks ONLY on HIGH/CRITICAL findings;
//     LOW/MEDIUM findings are reported and the operation continues.
//   - NOTE: the online rate limiter (item 27) was REMOVED by decision of
//     the app owner. It throttled guessing through the app UI only and had
//     no effect on offline brute-force over a stolen container file; the
//     offline defenses are the Argon2id work factor and the cascaded AEAD.
//
// Step-13 hardening (report round 5):
//   - ONE-OPERATION-AT-A-TIME: protectFile/accessFile are fully serialized
//     by a ReentrantLock. Rationale: each operation runs Argon2id with the
//     default 64 MB memory cost; two concurrent derivations would demand
//     ~128 MB at once and OOM weak devices, and the engine's temp-file
//     bookkeeping must not interleave either. The lock is held for the
//     whole operation — KDF and engine — so every shared resource is
//     covered.
//   - SIGNATURE-PIN CONSISTENCY: getInstance() refuses a late or changed
//     signature pin with an exception instead of silently letting the
//     signature check run as CHECK_UNAVAILABLE for the whole process
//     lifetime (see requirePinConsistency).
//
// SCOPE NOTE (report round 5, item 4): no counter inside this class can
//   defend against OFFLINE brute-force over a stolen container file — the
//   attacker bypasses the app entirely. The only defenses there are the
//   Argon2id work factor and the cascaded AEAD. Documentation must state
//   this distinction explicitly.
//
// Error contract for protectFile/accessFile (disjoint and exhaustive):
//   - SecurityThreatException (SecurityException) — the environment is
//     COMPROMISED; carries the full assessment for reporting.
//   - SecurityException — the DATA is untrusted (wrong password, tampered
//     or truncated container).
//   - java.io.IOException — storage failure; retryable.

//   - IllegalArgumentException — caller/programming error.
// ============================================================================

package com.example.lock.enc

import android.content.Context
import java.io.File
import java.io.IOException
import java.util.concurrent.locks.ReentrantLock

/**
 * Central facade of the CVLT anti-forensic engine.
 *
 * Typical application wiring (Application.onCreate — the ONLY place that
 * should pass the signature pin):
 * ```
 * val manager = ForensicManager.getInstance(this, SIGNATURE_PIN_SHA256)
 * manager.setReporter { event -> /* toast / encrypted log */ }
 * manager.startupMaintenance(listOf(vaultDir))   // orphan temp sweep
 * ```
 *
 * Concurrency contract (report round 5, item 1): at most ONE
 * protectFile/accessFile runs at any moment, enforced by [operationLock].
 * Callers may still invoke both from any thread; the second caller simply
 * blocks until the first finishes. Never call from the UI thread — the
 * wait plus the operation itself are blocking by nature.
 *
 * The injected reporter is called from whichever thread triggered the
 * event and must be fast and thread-safe.
 */
class ForensicManager private constructor(
    context: Context,
    private val signaturePin: String?
) {

    // ------------------------------------------------------------------
    // Module wiring (see header diagram)
    // ------------------------------------------------------------------

    /** Environmental watchdog; receives the APK signature pin (may be
     *  null, in which case the signature check reports CHECK_UNAVAILABLE
     *  instead of silently passing). */
    private val antiTamperEngine = AntiTamperEngine.create(context, signaturePin)

    /** Argon2id + HKDF key derivation with locked-native key storage. */
    private val kdfModule = MilitaryKdfModule.create()

    /** Container engine — the ONLY path to crypto. Gets a sink so that
     *  key-destruction failures become reportable events (item 21). */
    private val fileContainerEngine = FileContainerEngine.create(
        kdfModule = kdfModule,
        securityEventSink = SecurityEventSink { event -> dispatch(event) }
    )

    /** Application-provided reporter (UI/log/telemetry). Null = silent. */
    @Volatile
    private var appReporter: SecurityEventSink? = null

    /**
     * Serializes protectFile/accessFile end to end (report round 5,
     * item 1). ReentrantLock (not synchronized) so the same thread can
     * safely re-enter if a future helper nests operations, and so lock
     * ownership is visible in diagnostics.
     */
    private val operationLock = ReentrantLock()

    companion object {
        @Volatile
        private var instance: ForensicManager? = null

        /**
         * Process-wide singleton.
         *
         * [signaturePin] is the SHA-256 hex digest of the release signing
         * certificate (see AntiTamperEngine) and is read ONLY on the first
         * creation. PIN CONSISTENCY (report round 5, item 2): once the
         * instance exists, any non-null [signaturePin] that differs from
         * the one it was created with throws IllegalStateException. This
         * turns the dangerous silent case — "created pinless first, real
         * pin arrives too late, signature check stays CHECK_UNAVAILABLE
         * forever" — into a loud, immediate failure. Repeat calls with the
         * default null pin are accepted and keep the existing instance.
         */
        fun getInstance(
            context: Context,
            signaturePin: String? = null
        ): ForensicManager {
            val existing = instance
            if (existing != null) {
                requirePinConsistency(existing, signaturePin)
                return existing
            }
            return synchronized(this) {
                val current = instance
                if (current != null) {
                    requirePinConsistency(current, signaturePin)
                    current
                } else {
                    // Fail-closed before publishing the instance: without
                    // locked native memory there is no secure key storage,
                    // and NO operation may silently fall back to the heap.
                    check(NativeMemoryManager.isNativeAvailable()) {
                        "Native locked-memory library is unavailable; " +
                                "the secure engine refuses to start (fail-closed)."
                    }
                    ForensicManager(
                        context.applicationContext,
                        signaturePin
                    ).also { created -> instance = created }
                }
            }
        }

        /**
         * Enforces the pin-consistency rule of [getInstance]. A non-null
         * requested pin must be byte-identical to the pin the existing
         * instance was created with; in particular, requesting a real pin
         * from an instance that was created WITHOUT one is a fatal wiring
         * mistake (the signature check is already degraded for the whole
         * process lifetime) and must never pass silently.
         */
        private fun requirePinConsistency(
            existing: ForensicManager,
            requested: String?
        ) {
            if (requested != null && existing.signaturePin != requested) {
                throw IllegalStateException(
                    "ForensicManager already exists with a different (or " +
                            "missing) signature pin. Call getInstance() exactly " +
                            "once — in Application.onCreate — with the real " +
                            "release pin; a late or changed pin is rejected."
                )
            }
        }
    }

    // ==================================================================
    // Reporting channel (item 19)
    // ==================================================================

    /**
     * Installs the application's reporter. May be called once at startup;
     * calling again replaces the previous sink. Pass null to mute.
     */
    fun setReporter(reporter: SecurityEventSink?) {
        appReporter = reporter
    }

    /**
     * Delivers one sanitized event to the app reporter. Swallows reporter
     * failures on purpose: an observer must never break the engine or leak
     * an exception into crypto paths.
     */
    private fun dispatch(event: SecurityEvent) {
        val reporter = appReporter ?: return
        try {
            reporter.onSecurityEvent(event)
        } catch (_: Throwable) {
            // Reporters are untrusted observers.
        }
    }

    private fun dispatch(kind: SecurityEvent.Kind, detail: String) {
        dispatch(SecurityEvent(kind, detail))
    }

    // ==================================================================
    // Environment gate (items 19 + 24)
    // ==================================================================

    /**
     * Runs a FULL environment assessment and reports every finding through
     * the channel. Returns the assessment for UI display; does NOT throw —
     * use [protectFile]/[accessFile] for enforcement.
     */
    fun assessEnvironment(): EnvironmentAssessment {
        val assessment = antiTamperEngine.assess()
        if (assessment.threats.isNotEmpty()) {
            dispatch(
                SecurityEvent(
                    SecurityEvent.Kind.THREAT_ASSESSMENT,
                    "Environment assessment reported " +
                            "${assessment.threats.size} finding(s); verdict: " +
                            "${assessment.verdict}.",
                    threats = assessment.threats
                )
            )
        }
        return assessment
    }

    /**
     * Fail-closed gate: throws [SecurityThreatException] when the
     * environment carries HIGH or CRITICAL findings. LOW/MEDIUM findings
     * are reported but do not block (item 24). The exception carries the
     * complete finding list so the reporter loses nothing.
     */
    private fun enforceEnvironment() {
        val assessment = assessEnvironment()
        if (assessment.hasSeverityAtLeast(ThreatSeverity.HIGH)) {
            throw SecurityThreatException(assessment)
        }
    }

    // ==================================================================
    // Public operations
    // ==================================================================

    /**
     * Encrypts [inputFile] into [outputFile] (in-place when they are the
     * same file). Runs the environment gate first.
     *
     * SERIALIZATION: executes under [operationLock] — at most one crypto
     * operation (and one Argon2id memory allocation) runs at a time.
     *
     * PASSWORD OWNERSHIP (item 22): [password] belongs to the caller.
     * This method never wipes it; every internal copy is destroyed by the
     * KDF/container layers themselves.
     *
     * @throws SecurityThreatException environment is COMPROMISED
     * @throws SecurityException untrusted-data failure inside the engine
     * @throws IOException storage failure (retryable)
     * @throws IllegalArgumentException caller error (missing file, short
     *                                  password, bad parameters)
     */
    @Throws(
        SecurityException::class,
        IOException::class,
        IllegalArgumentException::class
    )
    fun protectFile(
        inputFile: File,
        outputFile: File,
        password: CharArray,
        metadata: ByteArray = ByteArray(0),
        onProgress: ((Long) -> Unit)? = null,
        isCancelled: (() -> Boolean)? = null
    ) {
        operationLock.lock()
        try {
            enforceEnvironment()
            try {
                fileContainerEngine.encryptFile(
                    inputFile,
                    outputFile,
                    password,
                    metadata,
                    onProgress,
                    isCancelled
                )
            } catch (e: SecurityException) {
                dispatch(
                    SecurityEvent.Kind.OPERATION_FAILURE,
                    "Encryption aborted by an integrity failure."
                )
                throw e
            }
            // IOException propagates unchanged: it is a storage problem,
            // not a security verdict, and must not be laundered into one.
        } finally {
            operationLock.unlock()
        }
    }

    /**
     * Decrypts the container [inputFile] into [outputFile], guarded by the
     * environment gate AND the exponential rate limiter (item 27).
     *
     * SERIALIZATION: executes under [operationLock], which also makes the
     * failure-counter updates atomic with respect to other operations.
     *
     * PASSWORD OWNERSHIP (item 22): identical to [protectFile] — the
     * caller's [password] is never wiped here.
     *
     * @throws SecurityThreatException environment is COMPROMISED
     * @throws SecurityException wrong password / tampered container
     * @throws IOException storage failure
     */
    @Throws(
        SecurityException::class,
        IOException::class
    )
    fun accessFile(inputFile: File, outputFile: File, password: CharArray) {
        operationLock.lock()
        try {
            enforceEnvironment()
            try {
                fileContainerEngine.decryptFile(inputFile, outputFile, password)
            } catch (e: SecurityException) {
                // Wrong password and tampering are indistinguishable by
                // design (the engine sanitizes both).
                dispatch(
                    SecurityEvent.Kind.OPERATION_FAILURE,
                    "Decryption rejected the supplied credential or data."
                )
                throw e
            }
        } finally {
            operationLock.unlock()
        }
    }

    /**
     * Decrypts [inputFile] into [outputDirectory] and returns the restored
     * file, using the container's embedded metadata for the output name when
     * it carries one. Same gate, same serialization and same error families
     * as [accessFile].
     *
     * @throws SecurityThreatException environment is COMPROMISED
     * @throws SecurityException wrong password / tampered container
     * @throws IOException storage failure
     */
    @Throws(
        SecurityException::class,
        IOException::class
    )
    fun accessToDirectory(
        inputFile: File,
        outputDirectory: File,
        password: CharArray,
        fallbackName: String? = null,
        onProgress: ((Long) -> Unit)? = null,
        isCancelled: (() -> Boolean)? = null
    ): File {
        operationLock.lock()
        try {
            enforceEnvironment()
            try {
                return fileContainerEngine.decryptToDirectory(
                    inputFile,
                    outputDirectory,
                    password,
                    fallbackName,
                    onProgress,
                    isCancelled
                )
            } catch (e: SecurityException) {
                dispatch(
                    SecurityEvent.Kind.OPERATION_FAILURE,
                    "Decryption rejected the supplied credential or data."
                )
                throw e
            }
        } finally {
            operationLock.unlock()
        }
    }

    // ==================================================================
    // Startup maintenance (README contract)
    // ==================================================================

    /**
     * MUST be called once at app startup (Application.onCreate), BEFORE
     * any crypto operation, for every directory used as crypto output.
     * Securely removes orphaned temp files left by killed/crashed runs
     * and reports how many were swept.
     *
     * Returns the total number of files removed.
     */
    fun startupMaintenance(outputDirs: List<File>): Int {
        var removed = 0
        for (dir in outputDirs) {
            try {
                removed += FileContainerEngine.cleanupOrphanedTempFiles(dir)
            } catch (_: Throwable) {
                // Never let maintenance break startup; the sweep will run
                // again on the next launch.
            }
        }
        if (removed > 0) {
            dispatch(
                SecurityEvent.Kind.STARTUP_SWEEP,
                "Startup sweep securely removed $removed orphaned " +
                        "intermediate file(s) from a previously interrupted run."
            )
        }
        return removed
    }
}
