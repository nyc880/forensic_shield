package com.example.lock.crypto

import java.io.File
import java.security.SecureRandom

enum class EngineType(val suffix: String, val zipSuffix: String) {
    MAX(".max.enc", ".max.zip.enc"),
    MEDIUM(".enc", ".zip.enc"),
    EASY(".easy.enc", ".easy.zip.enc");

    companion object {

        // --------------------------------------------------------------
        // Container identification
        // --------------------------------------------------------------

        /** Version byte of the NEW modular engine (com.example.lock.enc). */
        const val NEW_CONTAINER_VERSION: Byte = 0x03

        /** Version byte of the LEGACY EncryptionManager format (v11). */
        const val LEGACY_MAX_VERSION: Byte = 11

        /** "CVLT" — shared by the legacy (v11) and the new (v0x03) format. */
        private val MAGIC_CVLT = byteArrayOf(0x43, 0x56, 0x4C, 0x54)

        /** "EZYS_EZY" — the real magic written by lightEncryptionManager. */
        private const val MAGIC_EASY = "EZYS_EZY"

        private const val ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
        private const val RANDOM_LENGTH = 23
        private val RANDOM = SecureRandom()

        fun randomName(length: Int = RANDOM_LENGTH): String {
            val sb = StringBuilder(length)
            repeat(length) { sb.append(ALPHABET[RANDOM.nextInt(ALPHABET.length)]) }
            return sb.toString()
        }

        fun generateFileName(engine: EngineType): String {
            return randomName() + engine.suffix
        }

        fun generateZipFileName(engine: EngineType): String {
            return randomName() + engine.zipSuffix
        }

        fun fromString(name: String): EngineType {
            return try { valueOf(name.uppercase()) } catch (_: Exception) { MAX }
        }

        fun fromFileName(fileName: String): EngineType? {
            val lower = fileName.lowercase()
            return when {
                lower.endsWith(".max.zip.enc") -> MAX
                lower.endsWith(".easy.zip.enc") -> EASY
                lower.endsWith(".medium.zip.enc") -> MEDIUM
                lower.endsWith(".zip.enc") -> MEDIUM

                lower.endsWith(".max.enc") -> MAX
                lower.endsWith(".easy.enc") -> EASY
                lower.endsWith(".medium.enc") -> MEDIUM
                lower.endsWith(".enc") -> MEDIUM

                lower.endsWith(".cvm") -> MEDIUM
                lower.endsWith(".cvl") -> EASY
                else -> null
            }
        }

        /**
         * Reads the version byte of a CVLT container.
         * Returns null when the file is not a CVLT container (or is too small).
         */
        private fun readCvltVersion(file: File): Byte? {
            if (!file.exists() || !file.isFile || file.length() < 5) return null
            return try {
                file.inputStream().use { input ->
                    val header = ByteArray(5)
                    var off = 0
                    while (off < header.size) {
                        val n = input.read(header, off, header.size - off)
                        if (n < 0) return null
                        off += n
                    }
                    for (i in MAGIC_CVLT.indices) {
                        if (header[i] != MAGIC_CVLT[i]) return null
                    }
                    header[4]
                }
            } catch (_: Exception) { null }
        }

        /**
         * TRUE when [file] is a container produced by the LEGACY
         * EncryptionManager (magic "CVLT" + version byte 11).
         *
         * The new modular engine CANNOT read those files (different format,
         * no migration path), so every MAX decrypt call site must route them
         * back to the legacy reader until the user re-encrypts them.
         */
        fun isLegacyMaxContainer(file: File): Boolean {
            return readCvltVersion(file) == LEGACY_MAX_VERSION
        }

        /**
         * TRUE when [file] is a container produced by the NEW modular engine
         * (magic "CVLT" + version byte 0x03).
         */
        fun isNewMaxContainer(file: File): Boolean {
            return readCvltVersion(file) == NEW_CONTAINER_VERSION
        }

        fun detectFromFile(file: File): EngineType? {
            fromFileName(file.name)?.let { return it }

            if (!file.exists() || file.length() < 9) return null
            return try {
                file.inputStream().use { input ->
                    val headerBytes = ByteArray(9)
                    var off = 0
                    while (off < headerBytes.size) {
                        val n = input.read(headerBytes, off, headerBytes.size - off)
                        if (n < 0) return null
                        off += n
                    }

                    // EASY: the real magic written by lightEncryptionManager
                    // is "EZYS_EZY" (the old "CVLT_EZY" check never matched).
                    if (String(headerBytes, 0, 8, Charsets.US_ASCII) == MAGIC_EASY) {
                        return EASY
                    }

                    for (i in MAGIC_CVLT.indices) {
                        if (headerBytes[i] != MAGIC_CVLT[i]) return null
                    }
                    // "CVLT" is shared by the legacy (11) and the new (0x03)
                    // MAX format; both are handled by the MAX branch and are
                    // told apart by isLegacyMaxContainer().
                    when (headerBytes[4]) {
                        NEW_CONTAINER_VERSION, LEGACY_MAX_VERSION -> return MAX
                    }
                    null
                }
            } catch (_: Exception) { null }
        }

        fun detectCandidates(file: File): List<EngineType> {
            val detected = detectFromFile(file)
            return if (detected != null) {
                listOf(detected) + values().filter { it != detected }
            } else {
                values().toList()
            }
        }

        fun isEncryptedFile(file: File): Boolean {
            val name = file.name.lowercase()
            if (name.endsWith(".enc") || name.endsWith(".cvm") || name.endsWith(".cvl")) return true
            return detectFromFile(file) != null
        }

        fun isZipFile(file: File): Boolean {
            val lower = file.name.lowercase()
            if (lower.endsWith(".zip") && !lower.endsWith(".zip.enc")) return true
            return try {
                file.inputStream().use { input ->
                    val sig = ByteArray(4)
                    val read = input.read(sig)
                    read == 4 && sig[0] == 0x50.toByte() && sig[1] == 0x4B.toByte()
                }
            } catch (_: Exception) { false }
        }

        fun isZipEncFile(file: File): Boolean {
            val lower = file.name.lowercase()
            return lower.endsWith(".zip.enc")
        }
    }
}
