// ============================================================================
// File #11 (was: 11_REPORT_anti_hack.txt) — SecurityThreat.kt
// Threat model for the environmental protection layer
// Package: com.example.lock.enc
// Path: app/src/main/java/com/example/lock/enc/SecurityThreat.kt
//
// Step-9 redesign (report round 4, items 24 and 26):
//   1. SEVERITY MODEL replaces the old binary isCritical flag. Threats are
//      graded LOW / MEDIUM / HIGH / CRITICAL so the response policy can
//      distinguish "report and continue" from "fail closed". The old design
//      threw an exception for EVERY finding — including non-critical ones —
//      which meant "crash instead of report" and lost all findings after
//      the first one (item 24).
//   2. ASSESSMENT AGGREGATE: an environment scan returns the FULL list of
//      findings plus one composite verdict, never just the first hit. An
//      attacker patching a single check cannot turn a multi-signal
//      COMPROMISED verdict into CLEAN (item 25 defense-in-depth).
//   3. SANITIZED MESSAGES ONLY (item 26): a SecurityThreat must never carry
//      passwords, key material, container paths or raw exception text that
//      could contain user data. Messages are fixed English templates; the
//      forensic reporting layer (ForensicManager) may therefore forward
//      them without leaking secrets.
//   4. English-only comments; package unified to com.example.lock.enc.
// ============================================================================

package com.example.lock.enc

/** Categories of environmental threats the anti-tamper layer can detect. */
enum class ThreatType {
    /** Java (JDWP) or native (ptrace) debugger attached to the process. */
    DEBUGGER_ATTACHED,

    /** Dynamic instrumentation / code injection (Frida, Xposed, Substrate). */
    HOOKING_FRAMEWORK,

    /** Root indicators (su binaries, test-keys builds). */
    ROOT_INDICATOR,

    /** Execution inside an emulator / simulator environment. */
    EMULATOR_ENVIRONMENT,

    /** APK signing certificate does not match the pinned hash. */
    SIGNATURE_MISMATCH,

    /**
     * A check could not be executed or evaluated (I/O error, missing pin,
     * malformed input...). The environment is UNKNOWN, not proven clean.
     */
    CHECK_UNAVAILABLE
}

/**
 * Graded severity (report item 24). Response policy:
 *  - CRITICAL: block cryptographic operations, report immediately.
 *  - HIGH:     block cryptographic operations by default, report.
 *  - MEDIUM:   allow operation, report (user-visible warning possible).
 *  - LOW:      record silently (telemetry/forensic log only).
 */
enum class ThreatSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /** True when this severity is at least as severe as [other]. */
    fun isAtLeast(other: ThreatSeverity): Boolean = compareTo(other) >= 0
}

/**
 * One sanitized, reportable finding. Fields are immutable and contain no
 * secret material by construction (report item 26) — see header comment.
 */
data class SecurityThreat(
    val type: ThreatType,
    val severity: ThreatSeverity,
    /** Fixed English template; safe to log, display or send to reporting. */
    val message: String,
    /** Wall-clock time of detection (epoch millis). */
    val timestampMillis: Long = System.currentTimeMillis()
)

/** Composite verdict over the whole environment scan. */
enum class EnvironmentVerdict {
    /** No findings at all. */
    CLEAN,

    /**
     * Non-blocking findings present (LOW/MEDIUM): report them, but do not
     * stop the user. Typical: emulator, or a check that could not run.
     */
    DEGRADED,

    /**
     * Blocking findings present (HIGH/CRITICAL): cryptographic operations
     * must refuse to run until the environment is clean.
     */
    COMPROMISED
}

/**
 * Result of one full environment assessment. Always contains the COMPLETE
 * list of findings — callers (ForensicManager) report every entry, never
 * only the first (report item 24).
 */
data class EnvironmentAssessment(
    val verdict: EnvironmentVerdict,
    val threats: List<SecurityThreat>
) {
    /** Highest severity present, or null when the assessment is clean. */
    val worstSeverity: ThreatSeverity?
        get() = threats.map { it.severity }.maxOrNull()

    fun hasSeverityAtLeast(level: ThreatSeverity): Boolean =
        threats.any { it.severity.isAtLeast(level) }

    companion object {
        private val CLEAN_INSTANCE =
            EnvironmentAssessment(EnvironmentVerdict.CLEAN, emptyList())

        fun clean(): EnvironmentAssessment = CLEAN_INSTANCE

        /**
         * Builds the assessment and derives the verdict from the worst
         * finding: HIGH/CRITICAL -> COMPROMISED, LOW/MEDIUM -> DEGRADED,
         * nothing -> CLEAN.
         */
        fun of(threats: List<SecurityThreat>): EnvironmentAssessment {
            if (threats.isEmpty()) return CLEAN_INSTANCE
            val verdict = if (threats.any {
                    it.severity.isAtLeast(ThreatSeverity.HIGH)
                }
            ) {
                EnvironmentVerdict.COMPROMISED
            } else {
                EnvironmentVerdict.DEGRADED
            }
            return EnvironmentAssessment(verdict, threats.toList())
        }
    }
}

/**
 * Thrown ONLY by the fail-closed enforcement path when the assessment
 * contains HIGH or CRITICAL findings. Carries the full sanitized list so
 * the caller can still report every finding after handling the exception
 * (never just the first one).
 */
class SecurityThreatException(
    val assessment: EnvironmentAssessment
) : SecurityException(
    assessment.threats.firstOrNull()?.message
        ?: "Environment assessment failed."
)

// ==========================================================================
// Security event channel (step 12 wiring, report items 19 and 21)
// ==========================================================================

/**
 * One sanitized, reportable security event flowing through the central
 * channel. Produced by the engine layer (cleanup failures), by the
 * ForensicManager (rate limiting, assessments, operation failures) and
 * consumed by the application's reporting implementation.
 *
 * Like [SecurityThreat], an event NEVER carries passwords, keys, container
 * contents or raw exception text (report item 26): `detail` is always a
 * fixed English template with at most an operation/stage name in it.
 */
data class SecurityEvent(
    val kind: Kind,
    val detail: String,
    val timestampMillis: Long = System.currentTimeMillis(),
    /**
     * Individual findings — populated for THREAT_ASSESSMENT events so the
     * reporter receives the complete sanitized list (never only the first
     * finding). Empty for all other kinds.
     */
    val threats: List<SecurityThreat> = emptyList()
) {
    enum class Kind {
        /** Secure destruction of key/plaintext material failed (item 21). */
        CLEANUP_FAILURE,

        /** Password-attempt lockout engaged or attempt rejected (item 27). */
        RATE_LIMIT_ENFORCED,

        /** Environment assessment produced one or more findings. */
        THREAT_ASSESSMENT,

        /** A crypto operation failed on untrusted data (wrong password,
         *  tampering, truncation). The category is sanitized. */
        OPERATION_FAILURE,

        /** Startup maintenance removed orphaned secure temp files. */
        STARTUP_SWEEP
    }
}

/**
 * Sink for [SecurityEvent]s. Implemented by the application (UI toast,
 * local encrypted log, telemetry...) and injected into ForensicManager.
 *
 * Contract: implementations MUST be non-blocking and thread-safe — events
 * may arrive from any thread, including inside crypto-engine finally
 * blocks, where throwing is forbidden.
 */
fun interface SecurityEventSink {
    fun onSecurityEvent(event: SecurityEvent)
}
