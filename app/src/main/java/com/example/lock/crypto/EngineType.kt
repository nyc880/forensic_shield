package com.example.lock.crypto

import java.io.File
import java.security.SecureRandom

enum class EngineType(val suffix: String, val zipSuffix: String) {
    MAX(".max.enc", ".max.zip.enc"),
    MEDIUM(".enc", ".zip.enc"),
    EASY(".easy.enc", ".easy.zip.enc");

    companion object {
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

                    val magic8 = String(headerBytes, 0, 8, Charsets.US_ASCII)
                    if (magic8 == "CVLT_EZY") {
                        return EASY
                    }

                    if (headerBytes[0] == 0x43.toByte() &&
                        headerBytes[1] == 0x56.toByte() &&
                        headerBytes[2] == 0x4C.toByte() &&
                        headerBytes[3] == 0x54.toByte() &&
                        headerBytes[4] == 11.toByte()
                    ) {
                        return MAX
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