// ============================================================================
// File #10 (was: 10_ANTI-hack.txt) — AntiTamperEngine.kt
// Environmental watchdog: anti-debug, anti-hook, root/emulator/signature
// Package: com.example.lock.enc
// Path: app/src/main/java/com/example/lock/enc/AntiTamperEngine.kt
//
// Step-9 redesign (report round 4, items 23–26):
//   1. ASSESS-THEN-ENFORCE replaces verifyEnvironmentOrThrow(). assess()
//      runs EVERY check, collects ALL findings and never throws, so the
//      reporting layer always sees the complete picture (item 24).
//      enforceCleanEnvironment() is the only throwing entry point and it
//      fails closed ONLY on HIGH/CRITICAL findings — LOW/MEDIUM findings
//      are reported, not crashed on (item 24).
//   2. SIGNATURE CHECK (item 23): pins the SHA-256 of the APK signing
//      certificate and compares it in constant time. On API 28+ it uses
//      GET_SIGNING_CERTIFICATES (the API fed by the v2/v3 scheme data),
//      flags unexpected multiple signers, and falls back to the deprecated
//      GET_SIGNATURES path below 28. v1/v2/v3 scheme validity itself is
//      enforced by the installer; the runtime pin proves we are still the
//      binary that was signed. A missing/malformed pin or a failed lookup
//      yields CHECK_UNAVAILABLE — it never silently passes.
//   3. FRIDA PORT SCAN WITHOUT INTERNET PERMISSION: the app must not hold
//      the INTERNET permission (anti-forensic policy), which would make a
//      TCP connect to 127.0.0.1 fail anyway. Instead we parse
//      /proc/net/tcp{,6} for listeners on Frida's default ports — no
//      socket, no permission needed.
//   4. CHECK RESILIENCE (items 24/25): every check is wrapped; an internal
//      error becomes a CHECK_UNAVAILABLE finding instead of an exception,
//      and no single boolean can flip a multi-signal COMPROMISED verdict
//      to CLEAN because the verdict is derived from the full finding list.
//   5. SANITIZED MESSAGES (item 26): fixed English templates only; no
//      paths containing user data, no raw exception text, no secrets.
//   6. English-only comments; package unified to com.example.lock.enc.
//
// Honest scope (see README "inherent limitations"): ALL runtime checks live
// inside the very process an attacker may control. They raise the cost of an
// attack dramatically but are not mathematically unbypassable on a rooted
// device; the composite verdict + full reporting is the design answer.
// ============================================================================

package com.example.lock.enc

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.Debug
import java.io.File
import java.security.MessageDigest
import java.util.Arrays

/**
 * Environmental protection engine.
 *
 * Thread-safety: instances are stateless after construction; [assess] may be
 * called from any background thread (it performs file I/O — never call it
 * on the UI thread).
 */
class AntiTamperEngine private constructor(
    private val context: Context,
    /**
     * SHA-256 hex digest (64 chars, colons/spaces allowed) of the expected
     * APK signing certificate. When null, the signature check reports
     * CHECK_UNAVAILABLE instead of passing silently.
     */
    private val expectedSignatureSha256: String?
) {

    companion object {
        /** Frida's default listening ports (server + portal). */
        private val FRIDA_PORTS_HEX = arrayOf("69B2", "69B3") // 27042, 27043

        /** Loopback addresses as encoded in /proc/net/tcp{,6} hex fields. */
        private val LOOPBACK_LOCALS = arrayOf(
            "0100007F",                                   // 127.0.0.1 (v4)
            "00000000000000000000000001000000",          // ::1 (v6)
            "0000000000000000FFFF00000100007F"           // ::ffff:127.0.0.1
        )

        /** Common locations of the `su` binary on rooted devices. */
        private val ROOT_PATHS = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/magisk/.core/bin/su"
        )

        /** Known injection/hooking libraries inside /proc/self/maps. */
        private val KNOWN_HOOKING_LIBRARIES = arrayOf(
            "frida",
            "xposed",
            "substrate",
            "com.saurik.substrate",
            "libfrida-gadget.so",
            "riru",
            "zygisk"
        )

        fun create(
            context: Context,
            expectedSignatureSha256: String? = null
        ): AntiTamperEngine {
            return AntiTamperEngine(
                context.applicationContext,
                expectedSignatureSha256
            )
        }

        // ------------------------------------------------------------------
        // Small sanitized helpers
        // ------------------------------------------------------------------

        private fun threat(
            type: ThreatType,
            severity: ThreatSeverity,
            message: String
        ) = SecurityThreat(type, severity, message)

        private fun checkUnavailable(detail: String) = threat(
            ThreatType.CHECK_UNAVAILABLE,
            ThreatSeverity.LOW,
            "A security check could not be evaluated: $detail"
        )

        private fun hexToBytesOrNull(hex: String): ByteArray? {
            val clean = hex.replace(":", "").replace(" ", "").lowercase()
            if (clean.length != 64) return null
            return try {
                ByteArray(32) { i ->
                    clean.substring(2 * i, 2 * i + 2).toInt(16).toByte()
                }
            } catch (e: NumberFormatException) {
                null
            }
        }
    }

    // ======================================================================
    // Public API
    // ======================================================================

    /**
     * Runs every environmental check and returns the COMPLETE assessment.
     * Never throws: internal failures are reported as CHECK_UNAVAILABLE
     * findings so the caller always gets an answer (report item 24).
     */
    fun assess(): EnvironmentAssessment {
        val findings = mutableListOf<SecurityThreat>()

        findings += checkDebugger()
        findings += checkHookingFrameworks()
        findings += checkRootIndicators()
        findings += checkEmulator()
        findings += checkSignatureIntegrity()

        return EnvironmentAssessment.of(findings)
    }

    /**
     * Fail-closed gate for cryptographic operations: throws
     * [SecurityThreatException] when the assessment contains HIGH or
     * CRITICAL findings. LOW/MEDIUM findings do NOT throw — they must be
     * reported by the caller, not turned into a crash (report item 24).
     * The exception carries the full finding list for reporting.
     */
    @Throws(SecurityThreatException::class)
    fun enforceCleanEnvironment() {
        val assessment = assess()
        if (assessment.hasSeverityAtLeast(ThreatSeverity.HIGH)) {
            throw SecurityThreatException(assessment)
        }
    }

    // ======================================================================
    // Individual checks — each returns a (possibly empty) finding list and
    // never lets an internal error escape.
    // ======================================================================

    /** 1. Java (JDWP) and native (ptrace) debugger detection. */
    private fun checkDebugger(): List<SecurityThreat> {
        val findings = mutableListOf<SecurityThreat>()
        try {
            if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
                findings += threat(
                    ThreatType.DEBUGGER_ATTACHED,
                    ThreatSeverity.CRITICAL,
                    "A Java debugger is attached to the process."
                )
            }
        } catch (t: Throwable) {
            findings += checkUnavailable("debugger state query")
        }

        try {
            val statusFile = File("/proc/self/status")
            if (statusFile.exists()) {
                statusFile.forEachLine { line ->
                    if (line.startsWith("TracerPid:")) {
                        // Format is "TracerPid:\t0" on most kernels, but be
                        // tolerant of whitespace variations.
                        val value = line.substringAfter(':').trim()
                        val tracerPid = value.toIntOrNull() ?: 0
                        if (tracerPid != 0) {
                            findings += threat(
                                ThreatType.DEBUGGER_ATTACHED,
                                ThreatSeverity.CRITICAL,
                                "A native ptrace tracer is attached to the process."
                            )
                        }
                    }
                }
            }
        } catch (t: Throwable) {
            findings += checkUnavailable("ptrace state query")
        }
        return findings
    }

    /** 2. Frida / Xposed / Substrate detection (classes, maps, ports). */
    private fun checkHookingFrameworks(): List<SecurityThreat> {
        val findings = mutableListOf<SecurityThreat>()

        // a) Xposed runtime classes.
        try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            findings += threat(
                ThreatType.HOOKING_FRAMEWORK,
                ThreatSeverity.CRITICAL,
                "A hooking framework was detected in the process."
            )
        } catch (_: ClassNotFoundException) {
            // Absence of the class is the normal, healthy state.
        } catch (t: Throwable) {
            findings += checkUnavailable("hooking class query")
        }

        // b) Injected libraries visible in /proc/self/maps.
        try {
            val mapsFile = File("/proc/self/maps")
            if (mapsFile.exists()) {
                var injected: String? = null
                mapsFile.forEachLine { line ->
                    if (injected == null) {
                        val lower = line.lowercase()
                        for (lib in KNOWN_HOOKING_LIBRARIES) {
                            if (lower.contains(lib)) {
                                injected = lib
                                return@forEachLine
                            }
                        }
                    }
                }
                if (injected != null) {
                    findings += threat(
                        ThreatType.HOOKING_FRAMEWORK,
                        ThreatSeverity.CRITICAL,
                        "A code-injection library was detected in process memory."
                    )
                }
            }
        } catch (t: Throwable) {
            findings += checkUnavailable("process memory map query")
        }

        // c) Frida default listening ports — parsed from /proc/net/tcp so
        //    the engine needs NO INTERNET permission (anti-forensic policy).
        try {
            if (fridaListenerPresent()) {
                findings += threat(
                    ThreatType.HOOKING_FRAMEWORK,
                    ThreatSeverity.HIGH,
                    "A dynamic instrumentation server was detected on a default local port."
                )
            }
        } catch (t: Throwable) {
            findings += checkUnavailable("local listener query")
        }

        return findings
    }

    /** 3. Root indicators. Severity HIGH (blocking) but not CRITICAL:
     *     a rooted device is hostile, yet the container format itself
     *     remains cryptographically sound — the verdict drives policy. */
    private fun checkRootIndicators(): List<SecurityThreat> {
        val findings = mutableListOf<SecurityThreat>()
        try {
            for (path in ROOT_PATHS) {
                if (File(path).exists()) {
                    findings += threat(
                        ThreatType.ROOT_INDICATOR,
                        ThreatSeverity.HIGH,
                        "Root management binaries were detected on this device."
                    )
                    break // one finding per category keeps reports clean
                }
            }
            val tags = Build.TAGS
            if (tags != null && tags.contains("test-keys")) {
                findings += threat(
                    ThreatType.ROOT_INDICATOR,
                    ThreatSeverity.HIGH,
                    "The OS build is signed with insecure test keys."
                )
            }
        } catch (t: Throwable) {
            findings += checkUnavailable("root indicator query")
        }
        return findings
    }

    /** 4. Emulator detection (MEDIUM: report and warn, do not block). */
    private fun checkEmulator(): List<SecurityThreat> {
        val findings = mutableListOf<SecurityThreat>()
        try {
            val isEmulator =
                Build.FINGERPRINT.startsWith("generic") ||
                    Build.FINGERPRINT.startsWith("unknown") ||
                    Build.MODEL.contains("google_sdk") ||
                    Build.MODEL.contains("Emulator") ||
                    Build.MODEL.contains("Android SDK built for x86") ||
                    Build.MANUFACTURER.contains("Genymotion") ||
                    (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) ||
                    Build.PRODUCT.contains("sdk_gphone") ||
                    Build.HARDWARE.contains("goldfish") ||
                    Build.HARDWARE.contains("ranchu")

            if (isEmulator) {
                findings += threat(
                    ThreatType.EMULATOR_ENVIRONMENT,
                    ThreatSeverity.MEDIUM,
                    "The application is running inside an emulator environment."
                )
            }
        } catch (t: Throwable) {
            findings += checkUnavailable("emulator detection query")
        }
        return findings
    }

    /**
     * 5. APK signing-certificate pin (report item 23).
     *
     * The v1/v2/v3 scheme validity of the installed package is enforced by
     * the system installer before this code can run; here we prove the
     * running binary is still the one that was signed, by comparing the
     * SHA-256 digest of the current signing certificate against the pin in
     * constant time. Any inability to verify is reported as
     * CHECK_UNAVAILABLE — verification can never "pass by error".
     */
    private fun checkSignatureIntegrity(): List<SecurityThreat> {
        val pinHex = expectedSignatureSha256
        if (pinHex.isNullOrBlank()) {
            return listOf(checkUnavailable("signature pin is not configured"))
        }
        val pinBytes = hexToBytesOrNull(pinHex)
            ?: return listOf(checkUnavailable("signature pin is malformed"))

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signingInfo = packageInfo.signingInfo
                    ?: return listOf(checkUnavailable("signing info unavailable"))

                val findings = mutableListOf<SecurityThreat>()

                // Multiple concurrent signers are never expected for this
                // app (key rotation is handled by the OS history, not by
                // adding signers), so flag it as a distinct finding.
                if (signingInfo.hasMultipleSigners()) {
                    findings += threat(
                        ThreatType.SIGNATURE_MISMATCH,
                        ThreatSeverity.HIGH,
                        "The package reports multiple concurrent signers."
                    )
                }

                val signers = signingInfo.apkContentsSigners
                if (signers.isNullOrEmpty()) {
                    findings += checkUnavailable("no signing certificates exposed")
                    return findings
                }
                findings += compareSignatureHash(signers[0], pinBytes)
                return findings
            } else {
                @Suppress("DEPRECATION")
                val packageInfo = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
                @Suppress("DEPRECATION")
                val signatures = packageInfo.signatures
                if (signatures.isNullOrEmpty()) {
                    return listOf(checkUnavailable("no signing certificates exposed"))
                }
                // NOTE: below API 28 the deprecated GET_SIGNATURES value can
                // be spoofed on a rooted device — an inherent platform
                // limitation (see README "inherent limitations").
                return compareSignatureHash(signatures[0], pinBytes)
            }
        } catch (e: PackageManager.NameNotFoundException) {
            return listOf(checkUnavailable("package metadata unavailable"))
        } catch (t: Throwable) {
            return listOf(checkUnavailable("signature verification failed"))
        }
    }

    /**
     * Hashes one [Signature] and compares it to [pinBytes] in constant
     * time. Returns a CRITICAL finding on mismatch, otherwise nothing.
     */
    private fun compareSignatureHash(
        signature: Signature,
        pinBytes: ByteArray
    ): List<SecurityThreat> {
        val digest = MessageDigest.getInstance("SHA-256")
        val computed = digest.digest(signature.toByteArray())
        try {
            val match = MessageDigest.isEqual(computed, pinBytes)
            if (!match) {
                return listOf(
                    threat(
                        ThreatType.SIGNATURE_MISMATCH,
                        ThreatSeverity.CRITICAL,
                        "The application signature does not match the expected " +
                            "certificate; the package may have been repackaged."
                    )
                )
            }
            return emptyList()
        } finally {
            Arrays.fill(computed, 0.toByte())
        }
    }

    /**
     * Scans /proc/net/tcp and /proc/net/tcp6 for LISTEN sockets on Frida's
     * default ports bound to loopback. Reading these proc files requires no
     * permission, unlike opening a TCP socket (which needs INTERNET — a
     * permission this app refuses to hold).
     */
    private fun fridaListenerPresent(): Boolean {
        val procFiles = arrayOf(File("/proc/net/tcp"), File("/proc/net/tcp6"))
        for (procFile in procFiles) {
            if (!procFile.exists()) continue
            try {
                var found = false
                procFile.forEachLine { line ->
                    // Columns: sl local_address rem_address st ...
                    val columns = line.trim().split("\\s+".toRegex())
                    if (columns.size >= 4) {
                        val local = columns[1]
                        val state = columns[3]
                        if (state.equals("0A", ignoreCase = true)) { // LISTEN
                            val colon = local.lastIndexOf(':')
                            if (colon > 0) {
                                val address = local.substring(0, colon)
                                val port = local.substring(colon + 1)
                                if (LOOPBACK_LOCALS.any {
                                        it.equals(address, ignoreCase = true)
                                    } &&
                                    FRIDA_PORTS_HEX.any {
                                        it.equals(port, ignoreCase = true)
                                    }
                                ) {
                                    found = true
                                    return@forEachLine
                                }
                            }
                        }
                    }
                }
                if (found) return true
            } catch (_: Throwable) {
                // This proc flavor may not exist; fall through to the next.
            }
        }
        return false
    }
}

