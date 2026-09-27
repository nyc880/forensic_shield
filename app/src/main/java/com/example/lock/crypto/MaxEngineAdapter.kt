package com.example.lock.crypto

import android.content.Context
import com.example.lock.enc.FileContainerEngine
import com.example.lock.enc.ForensicManager
import com.example.lock.enc.SecurityEventSink
import java.io.File
import java.security.SecureRandom

class MaxEngineAdapter private constructor(
    private val forensic: ForensicManager
) {

    companion object {

        /** Output suffix of the new MAX engine. */
        const val SUFFIX = ".max.enc"

        private const val NAME_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
        private const val NAME_LENGTH = 23
        private val RANDOM = SecureRandom()

        @Volatile
        private var instance: MaxEngineAdapter? = null

        /**
         * Call with the real signature pin ONLY when you are sure about it:
         * a wrong pin produces a CRITICAL finding and blocks every crypto
         * operation. Passing null keeps the signature check as
         * CHECK_UNAVAILABLE (LOW, non-blocking).
         */
        fun getInstance(
            context: Context,
            signaturePinSha256Hex: String? = null
        ): MaxEngineAdapter =
            instance ?: synchronized(this) {
                instance ?: MaxEngineAdapter(
                    ForensicManager.getInstance(
                        context.applicationContext,
                        signaturePinSha256Hex
                    )
                ).also { created -> instance = created }
            }

        fun randomName(length: Int = NAME_LENGTH): String =
            buildString(length) {
                repeat(length) { append(NAME_ALPHABET[RANDOM.nextInt(NAME_ALPHABET.length)]) }
            }
    }

    // ------------------------------------------------------------------
    // Wiring helpers
    // ------------------------------------------------------------------

    fun setReporter(sink: SecurityEventSink?) = forensic.setReporter(sink)

    fun assessEnvironment() = forensic.assessEnvironment()

    /** Call once in Application.onCreate, before any crypto operation. */
    fun startupMaintenance(outputDirs: List<File>): Int =
        forensic.startupMaintenance(outputDirs)

    // ------------------------------------------------------------------
    // Encrypt / decrypt
    // ------------------------------------------------------------------

    /**
     * Encrypts [inputFile] into a NEW random-named container inside
     * [outputDirectory] and returns the created file. The original filename
     * (with its extension) travels inside the container as metadata, so the
     * decrypt path restores it exactly.
     *
     * No minimum password length is enforced: the policy is the app's choice.
     *
     * @throws IllegalArgumentException missing input
     * @throws com.example.lock.enc.SecurityThreatException unsafe environment
     * @throws SecurityException untrusted data / secure memory unavailable
     * @throws java.io.IOException storage failure
     * @throws com.example.lock.enc.OperationCancelledException aborted through [isCancelled]
     */
    fun encryptFile(
        inputFile: File,
        outputDirectory: File,
        password: CharArray,
        onProgress: ((processedPlaintextBytes: Long) -> Unit)? = null,
        isCancelled: (() -> Boolean)? = null
    ): File {
        require(inputFile.exists() && inputFile.isFile) { "Input file does not exist." }
        if (!outputDirectory.exists() && !outputDirectory.mkdirs()) {
            throw java.io.IOException("Output directory is not available.")
        }

        val metadata = metadataFor(inputFile.name)
        val outputFile = uniqueFile(outputDirectory, randomName(), SUFFIX)
        forensic.protectFile(
            inputFile,
            outputFile,
            password,
            metadata,
            onProgress,
            isCancelled
        )
        return outputFile
    }

    /**
     * Decrypts a NEW container (v0x03) into [outputDirectory] and returns the
     * restored file. The output name comes from the container metadata when
     * present (original filename + extension), otherwise from [inputFile]'s
     * name with the suffix stripped.
     *
     * @throws com.example.lock.enc.SecurityThreatException unsafe environment
     * @throws SecurityException wrong password or tampered container
     * @throws java.io.IOException storage failure
     * @throws com.example.lock.enc.OperationCancelledException aborted through [isCancelled]
     */
    fun decryptFile(
        inputFile: File,
        outputDirectory: File,
        password: CharArray,
        onProgress: ((processedPlaintextBytes: Long) -> Unit)? = null,
        isCancelled: (() -> Boolean)? = null
    ): File {
        require(inputFile.exists() && inputFile.isFile) { "Container file does not exist." }
        if (!outputDirectory.exists() && !outputDirectory.mkdirs()) {
            throw java.io.IOException("Output directory is not available.")
        }

        return forensic.accessToDirectory(
            inputFile = inputFile,
            outputDirectory = outputDirectory,
            password = password,
            fallbackName = inputFile.name.removeSuffix(SUFFIX)
                .ifBlank { inputFile.nameWithoutExtension },
            onProgress = onProgress,
            isCancelled = isCancelled
        )
    }

    /**
     * Legacy containers (v11) are no longer supported after removal of
     * EncryptionManager. Attempting to decrypt them will throw
     * SecurityException with a clear message. Users must re-encrypt
     * those files with the new engine.
     */
    fun decryptLegacy(
        inputFile: File,
        outputDirectory: File,
        password: CharArray
    ): File {
        throw SecurityException("Legacy container (v11) is not supported. File was created with the old engine and must be re-encrypted.")
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    /**
     * UTF-8 bytes of the original name, truncated when it would exceed the
     * engine's metadata cap (extension is preserved, base name is cut).
     */
    private fun metadataFor(originalName: String): ByteArray {
        val raw = originalName.toByteArray(Charsets.UTF_8)
        if (raw.size <= FileContainerEngine.MAX_METADATA_BYTES) return raw

        val dot = originalName.lastIndexOf('.')
        val base = if (dot > 0) originalName.substring(0, dot) else originalName
        val extension = if (dot > 0) originalName.substring(dot) else ""
        val extensionBytes = extension.toByteArray(Charsets.UTF_8)
        val keep = (FileContainerEngine.MAX_METADATA_BYTES - extensionBytes.size).coerceAtLeast(0)
        return base.toByteArray(Charsets.UTF_8).copyOf(keep) + extensionBytes
    }

    private fun uniqueFile(dir: File, baseName: String, suffix: String): File {
        val cleanBase = baseName.substringBeforeLast('.').ifBlank { randomName() }
        val extension = if (suffix.isNotEmpty()) {
            suffix
        } else {
            baseName.substringAfterLast('.', "").let { if (it.isEmpty()) "" else ".$it" }
        }

        var candidate = File(dir, "$cleanBase$extension")
        var n = 1
        while (candidate.exists() && n < 1000) {
            candidate = File(dir, "${cleanBase}_$n$extension")
            n++
        }
        return candidate
    }
}
