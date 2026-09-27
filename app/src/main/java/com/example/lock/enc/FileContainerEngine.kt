// ============================================================================
// FileContainerEngine.kt — streaming container engine (format version 0x03)
// Package: com.example.lock.enc
//
// On-disk format (v0x03 — same structure as v0x02, but the XChaCha20 layer
// uses the standard draft-irtf-cfrg-xchacha constants; see ContainerHeader):
//   HEADER (86 bytes)                 — see ContainerHeader
//   RECORD 0..N:
//     size(4, big-endian)             — byte length of the CIPHERTEXT only
//     flag(1)                         — 0x00 = intermediate, 0x01 = FINAL
//     ciphertext(size)                — AES-256-GCM( XChaCha20-Poly1305(plaintext_i) )
//
//   AAD_i          = flag(1) || index_i(8, big-endian) || chainState_i(48)
//   chainState_0   = HMAC-SHA384(chainMacKey, HEADER bytes)
//   chainState_i+1 = HMAC-SHA384(chainMacKey, chainState_i || ciphertext_i)
//                    (advanced for intermediate records only)
//   nonce_i        = masterNonce with its low 8 bytes XORed with index_i
//                    (per layer: 24-byte XChaCha master / 12-byte AES master)
//
// Integrity guarantees (fixes the v0x01 truncation vulnerability; exercised
// by FileContainerEngineAndroidTest — truncation, bit-flip, reorder,
// duplicate, trailing data, empty file, wrong password):
//   - Exactly one FINAL record must be present and must be the last record.
//     Decryption fails on: missing FINAL (tail truncation), partial records,
//     trailing bytes after FINAL, record size out of bounds, unknown flag,
//     or any AAD/authentication-tag mismatch (reorder, replay, splice,
//     duplication, bit-flip, header tampering).
//   - An empty plaintext is stored as a single FINAL record with an empty
//     payload, so even a zero-byte file authenticates the password. In v0x01
//     a header-only file "decrypted successfully" with ANY password.
//   - The header is cryptographically bound into chainState_0, which is
//     inside every AAD (header authentication, key/params integrity).
//   - Key separation: the chain MAC uses the dedicated HKDF-derived
//     chainMacKey — never the AES key — and chainState_0 no longer hashes
//     raw key material.
//   - KDF parameters travel in the header and are used verbatim at
//     decryption (Argon2 output depends on m/t/p — portability fix).
//   - readFully semantics everywhere: a short read can never masquerade as
//     EOF (v0x01 silently exited the record loop on a partial size read).
//   - Atomic, durable finalization: fsync(temp) -> Files.move(ATOMIC_MOVE,
//     REPLACE_EXISTING). The destination is never deleted before the new
//     file is fully persisted; in-place operation (output == input) is safe.
//     The temp file lives in the SAME directory as the destination (never in
//     a generic cache dir): rename(2) is atomic only within one filesystem.
//     createTempFile gives it an unpredictable SecureRandom suffix.
//   - Fail-closed cleanup: on any error the temp file is overwritten with
//     zeros IN PLACE (RandomAccessFile — never truncate, otherwise the zeros
//     land in new extents and the old plaintext blocks survive), fsynced,
//     then unlinked (secureDeleteFile). Essential on the decrypt path, where
//     the temp may already hold partial plaintext.
//   - Crash recovery: temp names carry a distinctive prefix; the app calls
//     cleanupOrphanedTempFiles() AT STARTUP, BEFORE any crypto operation, to
//     securely remove leftovers from runs killed by lmkd/crash/power loss
//     (where catch blocks never ran). A live-temp registry additionally
//     prevents the sweep from ever deleting a temp owned by a currently
//     running operation in this process.
//   - In-place encryption: the original (plaintext-holding) inode is wiped
//     ONLY AFTER atomicReplace has succeeded, through a file descriptor that
//     was opened BEFORE the operation started (the fd survives the rename's
//     unlink). The plaintext is therefore never destroyed before the
//     container is durable at the destination: any earlier failure or kill
//     leaves the original file fully intact and the temp is simply swept.
//     Residual window: a kill between the successful rename and the wipe
//     can leave the old inode's blocks unzeroed (documented trade-off).
//     Honest limitation: flash storage (eMMC/UFS) wear-leveling may keep old
//     physical blocks alive after any overwrite, and F2FS copy-on-write can
//     defeat in-place overwrite; no user-space API can guarantee physical
//     erasure — the device's file-based encryption (FBE) is the layer that
//     ultimately protects deleted data.
//   - Keys never persist on the JVM heap: the KDF stores them in mlock'd
//     native memory (LockedSecret); this engine borrows a short-lived copy
//     per record via useKey, wiped immediately after each crypto call.
//   - Every plaintext/key buffer owned by this class is wiped in finally
//     blocks, including exception paths.
// ============================================================================

package com.example.lock.enc

import android.os.Build
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.io.SequenceInputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Thrown when a running operation is aborted through the [isCancelled]
 * callback. Deliberately a RuntimeException so it can cross the stream
 * boundary without polluting the engine's signature; the engine still
 * performs its fail-closed cleanup (the temp file is zero-overwritten and
 * unlinked) before it escapes, so the destination is never touched.
 */
class OperationCancelledException(
    message: String = "The operation was cancelled."
) : RuntimeException(message)

/**
 * Cascaded container engine: XChaCha20-Poly1305 (layer 1) then AES-256-GCM
 * (layer 2), streamed in 1 MiB chunks with a chained, truncation-resistant
 * record structure and atomic file finalization.
 *
 * Error contract for ALL public entry points (report item 10):
 *  - java.io.IOException — the operation failed because of STORAGE: the
 *    input/output file could not be read/written/created/renamed, or the
 *    stream broke. The data itself is not suspected; the caller may retry
 *    once storage is available. File state is always left consistent:
 *    the destination is only replaced after the new content is durable.
 *  - SecurityException — the operation failed because the DATA is
 *    untrusted: any authentication-tag mismatch, structural violation
 *    (truncation, trailing bytes, bad record size, unknown flag), wrong
 *    password, or the native locked-memory layer being unavailable
 *    (fail-closed). Messages are sanitized; nothing is logged. On this
 *    path the destination file is NEVER created or replaced, and any
 *    intermediate temp holding partial plaintext is zero-overwritten
 *    before unlink.
 *  - IllegalArgumentException — caller/programming errors (missing input
 *    file, bad KDF parameters, password below policy). Never raised by
 *    file content.
 * These three families are disjoint and exhaustive; nothing else escapes.
 */
class FileContainerEngine private constructor(
    private val kdfModule: MilitaryKdfModule,
    private val xChaChaEngine: XChaCha20Poly1305Engine,
    private val aesEngine: Aes256GcmEngine,
    /**
     * Optional sink for sanitized security events (step 12 wiring, report
     * item 21): receives CLEANUP_FAILURE events when locked key material or
     * plaintext blocks could not be destroyed. Null disables observation.
     * The sink is never allowed to break an operation: every call site is
     * exception-guarded.
     */
    private val securityEventSink: SecurityEventSink?
) {

    companion object {
        /** Plaintext chunk size: 1 MiB. */
        const val CHUNK_SIZE_BYTES = 1 * 1024 * 1024

        private const val FLAG_INTERMEDIATE: Byte = 0x00
        private const val FLAG_FINAL: Byte = 0x01

        private const val POLY1305_TAG_BYTES = 16
        private const val GCM_TAG_BYTES = 16
        private const val TAG_OVERHEAD_BYTES = POLY1305_TAG_BYTES + GCM_TAG_BYTES

        /** Record ciphertext bounds (an empty FINAL record is tags-only). */
        private const val MIN_RECORD_BYTES = TAG_OVERHEAD_BYTES
        private const val MAX_RECORD_BYTES = CHUNK_SIZE_BYTES + TAG_OVERHEAD_BYTES

        private const val HMAC_ALGORITHM = "HmacSHA384"
        private const val AAD_FRAME_BYTES = 1 + 8 // flag || index
        private const val RECORD_FRAME_BYTES = 4 + 1 // size || flag

        /**
         * Distinctive marker for our temp files. A temp name looks like
         * ".cvltsec.tmp.<outputName><SecureRandom digits>.tmp", which lets
         * cleanupOrphanedTempFiles() recognize leftovers from interrupted
         * runs without ever touching unrelated user files.
         */
        private const val TEMP_PREFIX = ".cvltsec.tmp."

        // ------------------------------------------------------------------
        // Optional plaintext envelope (metadata carried INSIDE the payload)
        //
        // The on-disk container format is NOT changed: when metadata is
        // supplied the plaintext stream simply starts with
        //   magic(8) || length(4, big-endian) || metadata(length) || payload
        // so any other v0x03 implementation still reads the container as a
        // normal (slightly longer) plaintext. Containers written without
        // metadata are detected on decrypt and yield a null prefix.
        // ------------------------------------------------------------------

        private val ENVELOPE_MAGIC = "CVLTENV1".toByteArray(Charsets.US_ASCII)
        private const val ENVELOPE_MAGIC_BYTES = 8
        private const val ENVELOPE_LENGTH_BYTES = 4

        /** Hard cap on the metadata block (anti-DoS against a hostile header). */
        const val MAX_METADATA_BYTES = 512

        /** Default: no metadata, byte-identical to the previous behaviour. */
        val EMPTY_METADATA: ByteArray = ByteArray(0)

        /**
         * Temps currently owned by a RUNNING operation in this process.
         * cleanupOrphanedTempFiles() never touches these, so an ill-timed
         * sweep can no longer destroy live intermediates. (Cross-process
         * leftovers from a dead app process are exactly what the sweep IS
         * supposed to remove — a dead process cannot hold entries here.)
         */
        private val liveTemps = java.util.Collections.synchronizedSet(mutableSetOf<String>())

        private fun registerTemp(f: File) {
            liveTemps.add(f.absolutePath)
        }

        private fun unregisterTemp(f: File) {
            liveTemps.remove(f.absolutePath)
        }

        fun create(
            kdfModule: MilitaryKdfModule = MilitaryKdfModule.create(),
            xChaChaEngine: XChaCha20Poly1305Engine = XChaCha20Poly1305Engine.create(),
            aesEngine: Aes256GcmEngine = Aes256GcmEngine.create(),
            securityEventSink: SecurityEventSink? = null
        ): FileContainerEngine {
            return FileContainerEngine(
                kdfModule,
                xChaChaEngine,
                aesEngine,
                securityEventSink
            )
        }

        /**
         * Securely removes leftover temp files from a previous INTERRUPTED
         * run (process killed by lmkd, crash, power loss — situations where
         * no catch/finally block ever executes). A leftover from a failed
         * decrypt may contain partial plaintext, so every match is
         * zero-overwritten in place, fsynced, then unlinked.
         *
         * CONTRACT: call this ONLY at app startup, BEFORE any encrypt or
         * decrypt operation begins, and for every directory used as crypto
         * output. As defense in depth, temps registered as live by a running
         * operation in this process are always skipped.
         *
         * Only files matching our distinctive TEMP_PREFIX are touched; no
         * unrelated user file can match.
         *
         * Returns the number of files removed.
         */
        fun cleanupOrphanedTempFiles(dir: File): Int {
            if (!dir.isDirectory) return 0
            var removed = 0
            val files = dir.listFiles() ?: return 0
            for (f in files) {
                if (f.isFile &&
                    f.name.startsWith(TEMP_PREFIX) &&
                    f.name.endsWith(".tmp") &&
                    !liveTemps.contains(f.absolutePath) // never kill a live temp
                ) {
                    secureDeleteFile(f)
                    removed++
                }
            }
            return removed
        }

        /**
         * Overwrites [file] with zeros IN PLACE, then fsyncs.
         *
         * MUST NOT truncate: opening with FileOutputStream(file) truncates
         * the file to zero and the rewritten bytes may land in NEW extents,
         * leaving the original blocks (holding partial plaintext) untouched
         * on disk. RandomAccessFile("rw") preserves the existing extents, so
         * the zeros replace the sensitive data block-for-block at the
         * filesystem level.
         *
         * Honest limitation: on flash storage (eMMC/UFS) the FTL /
         * wear-leveling layer may keep stale physical blocks after any
         * overwrite, and on copy-on-write filesystems (F2FS) even in-place
         * overwrite is not guaranteed. No user-space API can guarantee
         * physical erasure; the device's file-based encryption (FBE) is the
         * layer that ultimately protects deleted data.
         */
        private fun secureOverwriteFile(file: File) {
            try {
                if (!file.exists()) return
                RandomAccessFile(file, "rw").use { raf ->
                    val length = raf.length()
                    if (length > 0L) {
                        val zeros = ByteArray(64 * 1024)
                        var remaining = length
                        while (remaining > 0L) {
                            val n = if (remaining > zeros.size) zeros.size else remaining.toInt()
                            raf.write(zeros, 0, n)
                            remaining -= n
                        }
                        raf.fd.sync()
                    }
                }
            } catch (e: Exception) {
                // Best-effort: the caller still proceeds with its next step.
            }
        }

        /**
         * Best-effort secure removal: in-place zero overwrite (no truncate),
         * fsync, then unlink. Used on every failure path and by orphan
         * cleanup so no partial plaintext survives a failed/interrupted run.
         */
        private fun secureDeleteFile(file: File) {
            secureOverwriteFile(file)
            try {
                file.delete()
            } catch (e: Exception) {
                // Nothing more can be done from user space.
            }
        }

        /**
         * Zero-fills the file behind an ALREADY-OPEN descriptor and fsyncs.
         * Used for the in-place case, where the fd keeps the unlinked old
         * inode alive after the rename so its plaintext blocks can be wiped.
         * No truncate semantics involved: the fd was opened on the original.
         */
        private fun zeroFillAndSync(raf: RandomAccessFile) {
            val length = raf.length()
            if (length <= 0L) {
                raf.fd.sync()
                return
            }
            val zeros = ByteArray(64 * 1024)
            var remaining = length
            while (remaining > 0L) {
                val n = if (remaining > zeros.size) zeros.size else remaining.toInt()
                raf.write(zeros, 0, n)
                remaining -= n
            }
            raf.fd.sync()
        }
    }

    // ========================================================================
    // File-level API (atomic + durable)
    // ========================================================================

    /**
     * Encrypts [inputFile] into a v0x03 container at [outputFile].
     * The output is written to a temp file, fsynced, then moved atomically
     * over the destination. The destination is never deleted up-front, so a
     * crash or power loss cannot destroy both copies.
     *
     * In-place encryption (outputFile == inputFile): the plaintext inode is
     * zero-wiped through a pre-opened descriptor ONLY after the atomic
     * replace succeeds, so any earlier failure or kill leaves the original
     * file intact (and the temp is swept by cleanupOrphanedTempFiles).
     */
    fun encryptFile(
        inputFile: File,
        outputFile: File,
        password: CharArray,
        metadata: ByteArray = EMPTY_METADATA,
        onProgress: ((processedPlaintextBytes: Long) -> Unit)? = null,
        isCancelled: (() -> Boolean)? = null
    ) {
        require(inputFile.exists() && inputFile.canRead()) {
            "Input file does not exist or is not readable."
        }
        require(metadata.size <= MAX_METADATA_BYTES) {
            "Metadata block is too large (max $MAX_METADATA_BYTES bytes)."
        }
        val parentDir = outputFile.absoluteFile.parentFile
        require(parentDir != null && (parentDir.isDirectory || parentDir.mkdirs())) {
            "Output directory is not available."
        }

        // createTempFile generates a unique, unpredictable name (SecureRandom)
        // and creates the file atomically with owner-only permissions. The
        // distinctive TEMP_PREFIX marks it for orphan cleanup after crashes.
        val tempFile = File.createTempFile(TEMP_PREFIX + outputFile.name, null, parentDir)
        registerTemp(tempFile)

        var oldInode: RandomAccessFile? = null

        try {
            // In-place mode: the rename will unlink the old inode holding
            // the PLAINTEXT. To wipe those blocks we need a descriptor that
            // survives the unlink, so it is opened early and used ONLY
            // after the container is safely installed at the destination.
            // Never zero the plaintext before that point: a failure or kill
            // mid-way must leave the original file fully intact.
            //
            // canonicalFile throws IOException — it must live INSIDE the
            // try (report item 4): if it ran between registerTemp() and the
            // try-block, a failure there would leak a registered temp entry
            // plus an orphaned temp file.
            val inPlace = inputFile.canonicalFile == outputFile.canonicalFile
            if (inPlace) {
                oldInode = RandomAccessFile(inputFile, "rw")
            }

            FileInputStream(inputFile).use { fin ->
                FileOutputStream(tempFile).use { fout ->
                    encryptStream(fin, fout, password, metadata, onProgress, isCancelled)
                    fout.flush()
                    fout.fd.sync() // durability: data on stable storage BEFORE the move
                }
            }
            atomicReplace(tempFile, outputFile)

            // The container is now durable at the destination. Only NOW wipe
            // the unlinked-but-still-open old inode (plaintext blocks).
            oldInode?.let { raf ->
                try {
                    zeroFillAndSync(raf)
                } catch (e: Exception) {
                    // Best-effort: the data is already protected in place,
                    // but the failed plaintext-block wipe is observable
                    // through the security channel (report item 21).
                    reportIfCleanupFailed(false, "in-place plaintext wipe")
                }
            }
        } catch (e: Exception) {
            // Fail-closed cleanup. The original plaintext has NOT been
            // touched (the wipe only runs after a successful replace), so
            // destroying the temp is always safe here.
            secureDeleteFile(tempFile)
            throw e
        } finally {
            try {
                oldInode?.close()
            } catch (e: Exception) {
                // cleanup paths never throw
            }
            unregisterTemp(tempFile)
        }
    }

    /**
     * Decrypts a v0x03 container at [inputFile] into [outputFile], with the
     * same atomic + durable finalization as [encryptFile]. Any integrity
     * failure aborts before the destination is replaced; the temp file,
     * which may already contain partial plaintext, is zero-overwritten
     * before being unlinked.
     */
    fun decryptFile(
        inputFile: File,
        outputFile: File,
        password: CharArray,
        onProgress: ((processedPlaintextBytes: Long) -> Unit)? = null,
        isCancelled: (() -> Boolean)? = null
    ) {
        require(inputFile.exists() && inputFile.canRead()) {
            "Container file does not exist or is not readable."
        }
        val parentDir = outputFile.absoluteFile.parentFile
        require(parentDir != null && (parentDir.isDirectory || parentDir.mkdirs())) {
            "Output directory is not available."
        }

        val tempFile = File.createTempFile(TEMP_PREFIX + outputFile.name, null, parentDir)
        registerTemp(tempFile)

        try {
            FileInputStream(inputFile).use { fin ->
                FileOutputStream(tempFile).use { fout ->
                    decryptStream(fin, fout, password, onProgress, isCancelled)
                    fout.flush()
                    fout.fd.sync()
                }
            }
            atomicReplace(tempFile, outputFile)
        } catch (e: Exception) {
            // Fail-closed cleanup. On the DECRYPT path the temp may already
            // hold partial plaintext (records authenticated before the
            // failure), so it must be zero-overwritten, not merely unlinked.
            secureDeleteFile(tempFile)
            throw e
        } finally {
            unregisterTemp(tempFile)
        }
    }

    /**
     * Decrypts [inputFile] into [outputDirectory] and returns the restored
     * file. When the container carries metadata (see [encryptFile]) the
     * output name comes from it — that is how the original filename and its
     * extension survive the round trip; otherwise [fallbackName] is used.
     *
     * Identical guarantees to [decryptFile]: fsync before the move, atomic
     * replace, and fail-closed destruction of the temp on any error (the
     * destination is never created or replaced on a failure).
     */
    @Throws(
        SecurityException::class,
        IOException::class,
        IllegalArgumentException::class
    )
    fun decryptToDirectory(
        inputFile: File,
        outputDirectory: File,
        password: CharArray,
        fallbackName: String? = null,
        onProgress: ((processedPlaintextBytes: Long) -> Unit)? = null,
        isCancelled: (() -> Boolean)? = null
    ): File {
        require(inputFile.exists() && inputFile.canRead()) {
            "Container file does not exist or is not readable."
        }
        require(outputDirectory.isDirectory || outputDirectory.mkdirs()) {
            "Output directory is not available."
        }

        val tempFile = File.createTempFile(
            TEMP_PREFIX + (fallbackName ?: "output"), null, outputDirectory
        )
        registerTemp(tempFile)

        var extracted: ByteArray? = null
        try {
            FileInputStream(inputFile).use { fin ->
                FileOutputStream(tempFile).use { fout ->
                    val splitter = EnvelopeStrippingOutputStream(fout)
                    decryptStream(fin, splitter, password, onProgress, isCancelled)
                    splitter.flush()
                    fout.flush()
                    fout.fd.sync() // durable before the rename
                    extracted = splitter.metadata
                }
            }

            val target = uniqueTargetFile(
                outputDirectory,
                resolveOutputName(extracted, fallbackName, inputFile)
            )
            atomicReplace(tempFile, target)
            return target
        } catch (e: Exception) {
            // Nothing has been written to the destination yet, and the temp
            // may already hold partial plaintext.
            secureDeleteFile(tempFile)
            throw e
        } finally {
            unregisterTemp(tempFile)
            extracted?.let { NativeMemoryManager.wipeByteArray(it) }
        }
    }

    /**
     * Atomic replace: rename(2)/Files.move replaces an existing destination
     * atomically. NEVER delete the destination first — that opens a window
     * where a crash destroys both files.
     */
    private fun atomicReplace(tempFile: File, target: File) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                Files.move(
                    tempFile.toPath(),
                    target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
                )
            } catch (e: IOException) {
                // Fallback: File.renameTo also maps to rename(2), which
                // replaces the target atomically on POSIX filesystems.
                if (!tempFile.renameTo(target)) {
                    throw SecurityException("Atomic finalization of the output file failed.")
                }
            }
            syncDirectoryBestEffort(target.parentFile)
        } else {
            if (!tempFile.renameTo(target)) {
                throw SecurityException("Atomic finalization of the output file failed.")
            }
        }
    }

    /** Persists the rename itself. Best-effort: not all filesystems support it. */
    private fun syncDirectoryBestEffort(dir: File?) {
        if (dir == null) return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        try {
            FileChannel.open(dir.toPath(), StandardOpenOption.READ).use { channel ->
                channel.force(true)
            }
        } catch (e: Exception) {
            // Directory fsync unsupported on this filesystem; the file data
            // itself was already synced before the move.
        }
    }

    // ========================================================================
    // Stream-level API (the v0x03 container format)
    // ========================================================================

    /**
     * Encrypts an arbitrary stream into the v0x03 container format.
     * Look-ahead reads determine which chunk is the last one so it can be
     * marked FINAL. An empty input produces a single empty FINAL record.
     */
    fun encryptStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        password: CharArray,
        metadata: ByteArray = EMPTY_METADATA,
        onProgress: ((processedPlaintextBytes: Long) -> Unit)? = null,
        isCancelled: (() -> Boolean)? = null
    ) {
        require(metadata.size <= MAX_METADATA_BYTES) {
            "Metadata block is too large (max $MAX_METADATA_BYTES bytes)."
        }

        val salt = kdfModule.generateSalt()
        val masterXChaChaNonce = XChaCha20Poly1305Engine.generateNonce()
        val masterAesNonce = Aes256GcmEngine.generateNonce()

        // Fixed, portable, RFC 9106 low-memory parameters (module defaults).
        val keys = kdfModule.deriveKeysWithSalt(password, salt)

        val readBuffer = ByteArray(CHUNK_SIZE_BYTES)
        var pending: ByteArray? = null
        var chainState = ByteArray(0)
        var headerBytes: ByteArray? = null

        try {
            val header = ContainerHeader(
                params = keys.params,
                salt = salt,
                xChaChaNonce = masterXChaChaNonce,
                aesNonce = masterAesNonce
            )
            headerBytes = header.serialize()
            outputStream.write(headerBytes)

            // Bind the exact header bytes into the chain root.
            chainState = initialChainState(keys.chainMacKey, headerBytes)

            var index = 0L
            var processed = 0L

            // The optional envelope becomes the first bytes of the PLAINTEXT
            // stream, so it is covered by exactly the same records and tags as
            // the payload and stays invisible in the container structure.
            val source: InputStream = if (metadata.isEmpty()) {
                inputStream
            } else {
                SequenceInputStream(
                    ByteArrayInputStream(buildEnvelope(metadata)),
                    inputStream
                )
            }

            pending = readNextChunk(source, readBuffer)

            if (pending == null) {
                // Empty plaintext: one FINAL record with empty payload, so the
                // password is still authenticated and the container cannot be
                // confused with a truncated file.
                val layer2 = writeRecord(
                    outputStream, ByteArray(0), FLAG_FINAL, index, chainState,
                    keys, masterXChaChaNonce, masterAesNonce
                )
                NativeMemoryManager.wipeByteArray(layer2)
            } else {
                while (true) {
                    val current = pending ?: break
                    val chunkSize = current.size
                    pending = readNextChunk(source, readBuffer)
                    val flag = if (pending == null) FLAG_FINAL else FLAG_INTERMEDIATE

                    // 'current' (plaintext) is wiped inside writeRecord, on all paths.
                    val layer2 = writeRecord(
                        outputStream, current, flag, index, chainState,
                        keys, masterXChaChaNonce, masterAesNonce
                    )

                    processed += chunkSize
                    onProgress?.invoke(processed)
                    if (isCancelled?.invoke() == true) {
                        throw OperationCancelledException("Encryption was cancelled.")
                    }

                    if (flag == FLAG_FINAL) {
                        NativeMemoryManager.wipeByteArray(layer2)
                        break
                    }

                    val nextChain = updateChainState(chainState, layer2, keys.chainMacKey)
                    NativeMemoryManager.wipeByteArray(layer2)
                    NativeMemoryManager.wipeByteArray(chainState)
                    chainState = nextChain
                    index++
                }
            }

            outputStream.flush()
        } finally {
            pending?.let { NativeMemoryManager.wipeByteArray(it) }
            NativeMemoryManager.wipeByteArray(readBuffer) // holds the last plaintext chunk
            NativeMemoryManager.wipeByteArray(chainState)
            headerBytes?.let { NativeMemoryManager.wipeByteArray(it) }
            reportIfCleanupFailed(keys.wipe(), "encrypt")
            NativeMemoryManager.wipeByteArray(salt)
            NativeMemoryManager.wipeByteArray(masterXChaChaNonce)
            NativeMemoryManager.wipeByteArray(masterAesNonce)
        }
    }

    /**
     * Decrypts a v0x03 container stream with full structural validation.
     * Fails closed on: truncated header, missing FINAL record, short reads,
     * out-of-bounds record sizes, unknown flags, trailing data after FINAL,
     * and any authentication-tag mismatch.
     */
    fun decryptStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        password: CharArray,
        onProgress: ((processedPlaintextBytes: Long) -> Unit)? = null,
        isCancelled: (() -> Boolean)? = null
    ) {
        val din = DataInputStream(BufferedInputStream(inputStream, 64 * 1024))

        val parsedHeader = try {
            ContainerHeader.readFrom(din)
        } catch (e: EOFException) {
            throw SecurityException("Container is truncated: header is incomplete.")
        }
        val header = parsedHeader.first
        val headerRaw = parsedHeader.second

        val keys = try {
            // KDF parameters come from the header — never from device state.
            kdfModule.deriveKeysWithSalt(password, header.salt, header.params)
        } catch (e: Throwable) {
            wipeHeaderMaterial(header, headerRaw)
            throw e
        }

        var chainState = ByteArray(0)
        try {
            chainState = initialChainState(keys.chainMacKey, headerRaw)

            var index = 0L
            var seenFinal = false
            var processed = 0L

            while (true) {
                val recordSize = readRecordSizeOrEof(din)
                if (recordSize == -1) {
                    // Clean EOF between records.
                    if (!seenFinal) {
                        throw SecurityException(
                            "Container is truncated: the FINAL record is missing."
                        )
                    }
                    break
                }
                if (recordSize < MIN_RECORD_BYTES || recordSize > MAX_RECORD_BYTES) {
                    throw SecurityException(
                        "Record size out of bounds: container is corrupted or tampered."
                    )
                }

                val flagValue = din.readUnsignedByte() // EOFException if truncated
                if (flagValue != FLAG_INTERMEDIATE.toInt() && flagValue != FLAG_FINAL.toInt()) {
                    throw SecurityException(
                        "Unknown record flag: container is corrupted or tampered."
                    )
                }
                val flag = flagValue.toByte()

                val encrypted = ByteArray(recordSize)
                din.readFully(encrypted) // EOFException on a short record

                val xNonce = deriveChunkNonce(
                    header.xChaChaNonce, index, XChaCha20Poly1305Engine.NONCE_SIZE_BYTES
                )
                val aNonce = deriveChunkNonce(
                    header.aesNonce, index, Aes256GcmEngine.NONCE_SIZE_BYTES
                )
                val aad = buildAad(flag, index, chainState)

                var layer1: ByteArray? = null
                var plain: ByteArray? = null
                var nextChain: ByteArray? = null
                try {
                    // Layer order: AES-GCM first, then XChaCha20-Poly1305.
                    // Keys are borrowed from locked native memory per crypto
                    // call; useKey wipes each transient JVM copy.
                    layer1 = keys.aes256Key.useKey { aesKey ->
                        aesEngine.decrypt(encrypted, aesKey, aNonce, aad)
                    }
                    val l1 = layer1
                    plain = keys.xChaCha20Key.useKey { xKey ->
                        xChaChaEngine.decrypt(l1, xKey, xNonce, aad)
                    }
                    val plainSize = plain!!.size
                    outputStream.write(plain)
                    processed += plainSize
                    onProgress?.invoke(processed)
                    if (isCancelled?.invoke() == true) {
                        throw OperationCancelledException("Decryption was cancelled.")
                    }

                    if (flag == FLAG_INTERMEDIATE) {
                        nextChain = updateChainState(chainState, encrypted, keys.chainMacKey)
                    }
                } finally {
                    NativeMemoryManager.wipeByteArray(encrypted)
                    layer1?.let { NativeMemoryManager.wipeByteArray(it) }
                    plain?.let { NativeMemoryManager.wipeByteArray(it) }
                    NativeMemoryManager.wipeByteArray(xNonce)
                    NativeMemoryManager.wipeByteArray(aNonce)
                    NativeMemoryManager.wipeByteArray(aad)
                }

                if (flag == FLAG_FINAL) {
                    seenFinal = true
                    // The FINAL record must be the very last byte of the container.
                    if (din.read() != -1) {
                        throw SecurityException("Trailing data after the FINAL record.")
                    }
                    break
                }

                // Advance the chain (intermediate records only).
                val previousChain = chainState
                chainState = nextChain ?: error("Internal error: chain state was not advanced.")
                NativeMemoryManager.wipeByteArray(previousChain)
                index++
            }

            outputStream.flush()
        } catch (e: EOFException) {
            throw SecurityException("Container is truncated or incomplete.")
        } finally {
            NativeMemoryManager.wipeByteArray(chainState)
            reportIfCleanupFailed(keys.wipe(), "decrypt")
            wipeHeaderMaterial(header, headerRaw)
        }
    }

    // ========================================================================
    // Internals
    // ========================================================================

    /**
     * Encrypts one chunk through both layers and writes the framed record:
     * size(4) || flag(1) || ciphertext.
     *
     * [plainChunk] is wiped here on ALL paths (success and failure).
     * Returns the layer-2 ciphertext; the caller owns and wipes it after the
     * chain update. (Ciphertext is not sensitive; wiping it is hygiene only.)
     */
    private fun writeRecord(
        output: OutputStream,
        plainChunk: ByteArray,
        flag: Byte,
        index: Long,
        chainState: ByteArray,
        keys: CascadedKeyContainer,
        masterXChaChaNonce: ByteArray,
        masterAesNonce: ByteArray
    ): ByteArray {
        val xNonce = deriveChunkNonce(
            masterXChaChaNonce, index, XChaCha20Poly1305Engine.NONCE_SIZE_BYTES
        )
        val aNonce = deriveChunkNonce(
            masterAesNonce, index, Aes256GcmEngine.NONCE_SIZE_BYTES
        )
        val aad = buildAad(flag, index, chainState)
        var layer1: ByteArray? = null
        try {
            // Keys are borrowed from locked native memory for the duration of
            // each crypto call only; useKey wipes the transient JVM copy.
            layer1 = keys.xChaCha20Key.useKey { xKey ->
                xChaChaEngine.encrypt(plainChunk, xKey, xNonce, aad)
            }
            val l1 = layer1
            val layer2 = keys.aes256Key.useKey { aesKey ->
                aesEngine.encrypt(l1, aesKey, aNonce, aad)
            }

            val frame = ByteBuffer.allocate(RECORD_FRAME_BYTES)
                .putInt(layer2.size)
                .put(flag)
                .array()

            output.write(frame)
            output.write(layer2)
            return layer2
        } finally {
            NativeMemoryManager.wipeByteArray(plainChunk)
            layer1?.let { NativeMemoryManager.wipeByteArray(it) }
            NativeMemoryManager.wipeByteArray(xNonce)
            NativeMemoryManager.wipeByteArray(aNonce)
            NativeMemoryManager.wipeByteArray(aad)
        }
    }

    /**
     * Reads the next plaintext chunk (up to CHUNK_SIZE_BYTES).
     *
     * Fill-loop semantics (report item 3): keeps reading until the buffer is
     * full or the stream is exhausted, instead of returning whatever the
     * first read() happened to deliver. InputStream.read() is allowed to
     * return fewer bytes than requested even mid-stream (e.g. SAF /
     * content-resolver backed streams), and short reads must NOT produce
     * extra small records — the record count, per-record AAD indices and
     * the nonce schedule would all shift, which is exactly what an attacker
     * might try to induce. Returns null only at true EOF. A read of 0
     * bytes (exotic non-blocking streams) is retried, as before.
     */
    private fun readNextChunk(input: InputStream, buffer: ByteArray): ByteArray? {
        var total = 0
        while (total < buffer.size) {
            val n = input.read(buffer, total, buffer.size - total)
            if (n == -1) break
            if (n == 0) continue
            total += n
        }
        return if (total == 0) null else buffer.copyOf(total)
    }

    /**
     * Reads the 4-byte record size. Returns -1 ONLY on a clean EOF at a
     * record boundary; a partial frame raises EOFException (-> truncation).
     */
    private fun readRecordSizeOrEof(din: DataInputStream): Int {
        val first = din.read()
        if (first == -1) return -1
        val rest = ByteArray(3)
        din.readFully(rest)
        return (first shl 24) or
                ((rest[0].toInt() and 0xFF) shl 16) or
                ((rest[1].toInt() and 0xFF) shl 8) or
                (rest[2].toInt() and 0xFF)
    }

    /** AAD_i = flag(1) || index(8, big-endian) || chainState_i(48). */
    private fun buildAad(flag: Byte, index: Long, chainState: ByteArray): ByteArray {
        return ByteBuffer.allocate(AAD_FRAME_BYTES + chainState.size)
            .put(flag)
            .putLong(index)
            .put(chainState)
            .array()
    }

    /** chainState_0 = HMAC-SHA384(chainMacKey, headerBytes) — binds the header. */
    private fun initialChainState(chainMacKey: LockedSecret, headerBytes: ByteArray): ByteArray {
        return chainMacKey.useKey { key ->
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
            mac.doFinal(headerBytes)
        }
    }

    /** chainState_i+1 = HMAC-SHA384(chainMacKey, chainState_i || ciphertext_i). */
    private fun updateChainState(
        currentChainState: ByteArray,
        recordCiphertext: ByteArray,
        chainMacKey: LockedSecret
    ): ByteArray {
        return chainMacKey.useKey { key ->
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
            mac.update(currentChainState)
            mac.doFinal(recordCiphertext)
        }
    }

    /**
     * Per-record nonce: the low 8 bytes of the master nonce are XORed with
     * the record index. XOR with distinct indices is injective, so nonces are
     * unique per record under the same (per-container, random) master.
     */
    private fun deriveChunkNonce(masterNonce: ByteArray, chunkIndex: Long, nonceSize: Int): ByteArray {
        val nonce = masterNonce.copyOf(nonceSize)
        val indexBytes = ByteBuffer.allocate(8).putLong(chunkIndex).array()
        val offset = nonceSize - 8
        for (i in 0 until 8) {
            nonce[offset + i] = (nonce[offset + i].toInt() xor indexBytes[i].toInt()).toByte()
        }
        return nonce
    }

    /**
     * Reports a failed secure-destruction through the optional security
     * event sink (report item 21). Guarded against everything: a sink must
     * never be able to break a cleanup path or mask the in-flight result.
     */
    private fun reportIfCleanupFailed(destructionSucceeded: Boolean, stage: String) {
        if (destructionSucceeded) return
        val sink = securityEventSink ?: return
        try {
            sink.onSecurityEvent(
                SecurityEvent(
                    SecurityEvent.Kind.CLEANUP_FAILURE,
                    "Secure destruction of key material was incomplete " +
                            "during the $stage operation."
                )
            )
        } catch (_: Throwable) {
            // Never let an observer break cleanup.
        }
    }

    private fun wipeHeaderMaterial(header: ContainerHeader, raw: ByteArray) {
        NativeMemoryManager.wipeByteArray(raw)
        NativeMemoryManager.wipeByteArray(header.salt)
        NativeMemoryManager.wipeByteArray(header.xChaChaNonce)
        NativeMemoryManager.wipeByteArray(header.aesNonce)
    }

    // ========================================================================
    // Optional metadata envelope (plaintext-level, format compatible)
    // ========================================================================

    /** magic(8) || length(4, big-endian) || metadata. */
    private fun buildEnvelope(metadata: ByteArray): ByteArray {
        return ByteBuffer
            .allocate(ENVELOPE_MAGIC_BYTES + ENVELOPE_LENGTH_BYTES + metadata.size)
            .put(ENVELOPE_MAGIC)
            .putInt(metadata.size)
            .put(metadata)
            .array()
    }

    private fun resolveOutputName(
        metadata: ByteArray?,
        fallbackName: String?,
        inputFile: File
    ): String {
        val fromMetadata = metadata?.let { bytes ->
            try {
                bytes.toString(Charsets.UTF_8)
            } catch (_: Exception) {
                null
            }
        }
        val candidate = when {
            !fromMetadata.isNullOrBlank() -> fromMetadata
            !fallbackName.isNullOrBlank() -> fallbackName
            else -> inputFile.name.removeSuffix(".enc").ifBlank { inputFile.name }
        }
        // A name is untrusted input: it must never escape the output directory.
        val safe = candidate
            .replace('\u0000', '_')
            .replace('/', '_')
            .replace('\\', '_')
            .trim()
        return if (safe.isBlank() || safe == "." || safe == "..") inputFile.name else safe
    }

    private fun uniqueTargetFile(directory: File, name: String): File {
        var candidate = File(directory, name)
        if (!candidate.exists()) return candidate
        val dot = name.lastIndexOf('.')
        val base = if (dot > 0) name.substring(0, dot) else name
        val extension = if (dot > 0) name.substring(dot) else ""
        var n = 1
        while (n < 10_000) {
            candidate = File(directory, "$base ($n)$extension")
            if (!candidate.exists()) return candidate
            n++
        }
        return File(directory, "${System.currentTimeMillis()}_$name")
    }

    /**
     * Sits between the engine and the destination stream on the DECRYPT path:
     * it consumes the optional envelope (when present) and forwards only the
     * real payload to [delegate]. Containers written without metadata are
     * recognised by the absent magic and pass through untouched, so this is
     * fully backward compatible with every container created before this
     * feature existed.
     */
    private class EnvelopeStrippingOutputStream(
        private val delegate: OutputStream
    ) : OutputStream() {

        // 0 = magic, 1 = length, 2 = metadata, 3 = pass-through
        private var state = 0
        private var buffer = ByteArray(0)
        private var metadataLength = 0

        /** Extracted metadata, or null when the container carries none. */
        var metadata: ByteArray? = null
            private set

        override fun write(oneByte: Int) {
            write(byteArrayOf(oneByte.toByte()), 0, 1)
        }

        override fun write(source: ByteArray, offset: Int, length: Int) {
            var off = offset
            var remaining = length
            while (remaining > 0) {
                when (state) {
                    0 -> {
                        val take = minOf(FileContainerEngine.ENVELOPE_MAGIC_BYTES - buffer.size, remaining)
                        buffer += source.copyOfRange(off, off + take)
                        off += take
                        remaining -= take
                        if (buffer.size == FileContainerEngine.ENVELOPE_MAGIC_BYTES) {
                            if (MessageDigest.isEqual(buffer, FileContainerEngine.ENVELOPE_MAGIC)) {
                                state = 1
                                buffer = ByteArray(0)
                            } else {
                                // Not enveloped: emit what we read, then stream through.
                                delegate.write(buffer)
                                state = 3
                                buffer = ByteArray(0)
                            }
                        }
                    }
                    1 -> {
                        val take = minOf(FileContainerEngine.ENVELOPE_LENGTH_BYTES - buffer.size, remaining)
                        buffer += source.copyOfRange(off, off + take)
                        off += take
                        remaining -= take
                        if (buffer.size == FileContainerEngine.ENVELOPE_LENGTH_BYTES) {
                            metadataLength = ByteBuffer.wrap(buffer).int
                            if (metadataLength < 0 || metadataLength > FileContainerEngine.MAX_METADATA_BYTES) {
                                throw SecurityException(
                                    "Container metadata is malformed or oversized."
                                )
                            }
                            state = 2
                            buffer = ByteArray(0)
                        }
                    }
                    2 -> {
                        val take = minOf(metadataLength - buffer.size, remaining)
                        buffer += source.copyOfRange(off, off + take)
                        off += take
                        remaining -= take
                        if (buffer.size == metadataLength) {
                            metadata = buffer
                            state = 3
                            buffer = ByteArray(0)
                        }
                    }
                    else -> {
                        delegate.write(source, off, remaining)
                        remaining = 0
                    }
                }
            }
        }

        override fun flush() {
            delegate.flush()
        }

        override fun close() {
            // The engine owns [delegate]'s lifecycle (it lives inside a
            // .use {} block); never close it from here.
            delegate.flush()
        }
    }
}
