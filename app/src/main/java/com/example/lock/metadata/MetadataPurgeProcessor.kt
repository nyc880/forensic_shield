package com.example.lock.metadata

import java.io.File
import java.io.IOException
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

object MetadataPurgeProcessor {

    @JvmStatic
    fun purgeFile(file: File): File? {
        val report = purge(file)
        return if (report.succeeded) report.outputFile else null
    }

    @JvmStatic
    fun purge(file: File, options: PurgeOptions = PurgeOptions.maximumPrivacy()): PurgeReport =
        MetadataPurgeEngine.purge(file, options)

    @JvmStatic
    fun purgeAll(files: Collection<File>, options: PurgeOptions = PurgeOptions.maximumPrivacy()): PurgeBatchReport =
        MetadataPurgeEngine.purgeAll(files.toList(), options)

    @JvmStatic
    fun purgePaths(paths: Collection<String>, options: PurgeOptions = PurgeOptions.maximumPrivacy()): PurgeBatchReport =
        MetadataPurgeEngine.purgeAll(paths.map { File(it) }, options)

    @JvmStatic
    fun inspect(file: File, options: PurgeOptions = PurgeOptions.maximumPrivacy()): InspectionResult =
        MetadataPurgeEngine.inspect(file, options)

    @JvmStatic
    fun validate(file: File, options: PurgeOptions = PurgeOptions.maximumPrivacy()): Boolean =
        MetadataPurgeEngine.validate(file, options)

    fun supportedFormats(): Set<MediaFormat> = com.example.lock.metadata.FormatRegistry.supportedFormats()

    @JvmStatic
    fun recoverInterrupted(directory: File): List<File> = MetadataPurgeEngine.recoverInterruptedArtifacts(directory)

    @JvmStatic
    val version: String get() = MetadataPurgeEngine.VERSION

    fun isSuccess(report: PurgeReport): Boolean = report.status == PurgeStatus.SUCCESS || report.status == PurgeStatus.ALREADY_CLEAN
}

class ReportingSink : PurgeSink {
    val findings = CopyOnWriteArrayList<MetadataFinding>()
    @Volatile var stageText: String = ""
        private set

    override fun stage(text: String) {
        stageText = text
    }

    override fun found(finding: MetadataFinding) {
        findings.add(finding)
    }

    override fun progress(bytesDone: Long) {
    }
}

object MetadataPurgeEngine {

    const val VERSION = "2.0.0"

    private const val TEMP_PREFIX = ".mpurge_"
    private const val TEMP_SUFFIX = ".tmp"
    private const val BACKUP_SUFFIX = ".purgebak"
    private const val BACKUP_PREFIX = "b64-"
    private const val SPACE_HEADROOM = 64L * 1024L
    private const val STALE_ARTIFACT_AGE = 10L * 60L * 1000L

    private val namePool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    private val secureRandom = java.security.SecureRandom()

    fun inspect(rawFile: File, options: PurgeOptions = PurgeOptions.maximumPrivacy()): InspectionResult {
        val file = rawFile.absoluteFile
        val detection = FormatDetector.detect(file)
        val handler = FormatRegistry.handlerFor(detection.format, file)?.takeIf { it.implemented }
        if (!file.exists() || !file.isFile) {
            return InspectionResult(file, detection.format, detection.subtype, emptyList(), false, "file not readable")
        }
        if (handler == null) {
            return InspectionResult(
                file, detection.format, detection.subtype, emptyList(), false,
                "no structure aware handler for ${detection.format.displayName}"
            )
        }
        return try {
            val findings = handler.inspect(file, options)
            InspectionResult(file, detection.format, detection.subtype, findings, true)
        } catch (e: Exception) {
            InspectionResult(file, detection.format, detection.subtype, emptyList(), false, e.message)
        }
    }

    fun validate(rawFile: File, options: PurgeOptions = PurgeOptions.maximumPrivacy()): Boolean {
        val file = rawFile.absoluteFile
        val detection = FormatDetector.detect(file)
        val handler = FormatRegistry.handlerFor(detection.format, file) ?: return false
        if (!handler.implemented) return false
        return try {
            handler.validate(file, options)
        } catch (_: Exception) {
            false
        }
    }

    fun purge(rawFile: File, options: PurgeOptions = PurgeOptions.maximumPrivacy()): PurgeReport {
        val file = rawFile.absoluteFile
        val detection = FormatDetector.detect(file)
        val bytesBefore = if (file.exists()) file.length() else 0L

        if (!file.exists() || !file.isFile) {
            return failed(file, detection, bytesBefore, PurgeStatus.FAILED, "source is not a readable file")
        }
        if (file.length() == 0L) {
            return failed(file, detection, 0L, PurgeStatus.FAILED, "empty file")
        }
        if (!file.canRead()) {
            return failed(file, detection, bytesBefore, PurgeStatus.FAILED, "permission denied while reading")
        }
        val parent = file.absoluteFile.parentFile
        if (!file.canWrite() || parent == null || !parent.canWrite()) {
            return failed(file, detection, bytesBefore, PurgeStatus.FAILED, "permission denied while writing")
        }

        var handler = FormatRegistry.handlerFor(detection.format, file)?.takeIf { it.implemented }
        if (detection.format == MediaFormat.UNKNOWN && !options.aggressiveUnknownScrub) handler = null
        if (handler == null) {
            // Maximum privacy never falls back to a copy: an unhandled format is a boundary of
            // the security claim, not a file that can be relabelled as processed.
            val refuse = options.unknownFormatPolicy == UnknownFormatPolicy.REFUSE || options.maximumPrivacy
            return if (refuse) {
                failed(
                    file, detection, bytesBefore, PurgeStatus.REFUSED,
                    "no structure aware handler for ${detection.format.displayName}; refusing to report a false clean result"
                )
            } else {
                copyUnverified(file, detection, options)
            }
        }

        val preFindings = try {
            handler.inspect(file, options)
        } catch (e: Exception) {
            return failed(file, detection, bytesBefore, PurgeStatus.FAILED, "inspection failed: ${e.message}")
        }
        if (preFindings.isEmpty()) {
            // Nothing to remove, but that is not the same as claiming the container is sound: a
            // damaged file with no metadata is still damaged, and the report has to say so.
            val intact = try {
                handler.validate(file, options)
            } catch (_: Exception) {
                false
            }
            var clean = file
            if (options.hygieneOnCleanFiles) {
                if (options.randomizeFileName) clean = renameToRandom(file, options) ?: file
                if (options.resetFileTimestamps) {
                    try {
                        clean.setLastModified(0L)
                    } catch (_: Exception) {
                    }
                }
            }
            return PurgeReport(
                sourceFile = file,
                outputFile = clean,
                format = detection.format,
                subtype = detection.subtype,
                strategy = PurgeStrategy.PASSTHROUGH,
                status = PurgeStatus.ALREADY_CLEAN,
                bytesBefore = bytesBefore,
                bytesAfter = bytesBefore,
                removed = emptyList(),
                residual = emptyList(),
                structureValid = intact,
                verifiedClean = intact,
                message = if (intact) {
                    "no metadata found"
                } else {
                    "no metadata found, but the file fails structural validation and was left untouched"
                }
            )
        }

        val requiredSpace = bytesBefore + SPACE_HEADROOM
        val usable = try {
            file.parentFile?.usableSpace ?: Long.MAX_VALUE
        } catch (_: Exception) {
            Long.MAX_VALUE
        }
        if (usable < requiredSpace) {
            return failed(file, detection, bytesBefore, PurgeStatus.REFUSED, "not enough free space for a safe rewrite")
        }

        val sink = ReportingSink()
        val run = randomToken(12)
        var temp: File? = null
        var phase = ReplacePhase.PREPARED
        try {
            temp = createSiblingTemp(file, run)
            val ctx = PurgeContext(file, temp, detection, options, sink)
            ctx.stage("Rewriting ${detection.format.displayName}")
            val outcome = handler.scrub(ctx)
            options.checkCancelled(file)

            if (!outcome.success) {
                return failed(
                    file, detection, bytesBefore, PurgeStatus.FAILED,
                    outcome.message ?: "rewrite failed", removed = outcome.removed
                )
            }
            if (!temp.exists() || temp.length() == 0L) {
                return failed(file, detection, bytesBefore, PurgeStatus.FAILED, "rewrite produced no output", outcome.removed)
            }

            try {
                java.io.FileOutputStream(temp, true).use { handle ->
                    handle.flush()
                    handle.fd.sync()
                }
            } catch (_: Exception) {
            }
            phase = ReplacePhase.OUTPUT_WRITTEN

            ctx.stage("Verifying")
            val residual = try {
                handler.inspect(temp, options)
            } catch (e: Exception) {
                return failed(file, detection, bytesBefore, PurgeStatus.FAILED, "verification failed: ${e.message}", outcome.removed)
            }
            val structureValid = try {
                handler.validate(temp, options)
            } catch (_: Exception) {
                false
            }

            val unexpected = residual.filter { r -> outcome.residualRequired.none { it.kind == r.kind && it.detail == r.detail } }
            if (unexpected.isNotEmpty()) {
                // Fail closed before the original is touched: in maximum privacy a file whose
                // verification pass still reports findings is never installed over the source.
                if (options.maximumPrivacy) {
                    return failed(
                        file, detection, bytesBefore, PurgeStatus.REFUSED,
                        "maximum privacy: residual metadata survived verification: " + unexpected.joinToString("; ") { it.toString() },
                        outcome.removed
                    )
                }
                return failed(
                    file, detection, bytesBefore, PurgeStatus.FAILED,
                    "verification found residual metadata: " + unexpected.joinToString("; ") { it.toString() },
                    outcome.removed
                )
            }
            if (!structureValid) {
                return failed(file, detection, bytesBefore, PurgeStatus.FAILED, "rewritten file failed structural validation", outcome.removed)
            }
            phase = ReplacePhase.OUTPUT_VERIFIED

            ctx.stage("Replacing original")
            val swapped = swapIn(file, temp, run, options, onPhase = { phase = it }) ?: return failed(
                file, detection, bytesBefore, PurgeStatus.FAILED,
                "replacement transaction failed in phase $phase; original kept", outcome.removed
            )
            val installed = swapped.installed
            temp = null

            val bytesAfter = installed.length()
            return PurgeReport(
                sourceFile = file,
                outputFile = installed,
                format = detection.format,
                subtype = detection.subtype,
                strategy = outcome.strategy,
                status = if (residual.isEmpty()) PurgeStatus.SUCCESS else PurgeStatus.PARTIAL,
                bytesBefore = bytesBefore,
                bytesAfter = bytesAfter,
                removed = outcome.removed,
                residual = residual,
                residualRequired = outcome.residualRequired,
                structureValid = true,
                verifiedClean = residual.isEmpty(),
                originalWiped = options.secureDeleteOriginals && swapped.wiped,
                message = if (residual.isEmpty()) {
                    outcome.message
                } else {
                    "purged; " + residual.joinToString("; ") { it.toString() } + " could not be removed"
                }
            )
        } catch (cancelled: PurgeCancelledException) {
            throw cancelled
        } catch (refused: PurgeRefusedException) {
            // Handlers signal unprovable structures through this exception; the original file
            // is left exactly as it was and the report carries a REFUSED assurance level.
            return failed(file, detection, bytesBefore, PurgeStatus.REFUSED, refused.reason)
        } catch (e: Exception) {
            return failed(file, detection, bytesBefore, PurgeStatus.FAILED, e.message ?: e.javaClass.simpleName)
        } finally {
            temp?.let { SecureDelete.wipeQuietly(it, 1) }
        }
    }

    private fun copyUnverified(file: File, detection: FormatDetection, options: PurgeOptions): PurgeReport {
        var temp: File? = null
        val run = randomToken(12)
        return try {
            temp = createSiblingTemp(file, run)
            file.copyTo(temp, overwrite = true)
            val swapped = swapIn(file, temp, run, options, rename = options.randomizeFileName)
            val installed = swapped?.installed
            temp = null
            PurgeReport(
                sourceFile = file,
                outputFile = installed,
                format = detection.format,
                subtype = detection.subtype,
                strategy = PurgeStrategy.NONE,
                status = PurgeStatus.UNSUPPORTED_FORMAT,
                bytesBefore = file.length(),
                bytesAfter = installed?.length() ?: 0L,
                verifiedClean = false,
                structureValid = false,
                // The copy is not clean, but the original really was overwritten, and the report
                // used to stay silent about that because the wipe result was thrown away here.
                originalWiped = options.secureDeleteOriginals && swapped?.wiped == true,
                message = "copied without verification; no handler for ${detection.format.displayName}"
            )
        } catch (e: Exception) {
            failed(file, detection, file.length(), PurgeStatus.FAILED, e.message ?: "copy failed")
        } finally {
            temp?.let { SecureDelete.wipeQuietly(it, 1) }
        }
    }

    private fun failed(
        file: File,
        detection: FormatDetection,
        bytesBefore: Long,
        status: PurgeStatus,
        message: String,
        removed: List<MetadataFinding> = emptyList()
    ): PurgeReport = PurgeReport(
        sourceFile = file,
        outputFile = null,
        format = detection.format,
        subtype = detection.subtype,
        strategy = PurgeStrategy.NONE,
        status = status,
        bytesBefore = bytesBefore,
        bytesAfter = 0L,
        removed = removed,
        structureValid = false,
        verifiedClean = false,
        message = message
    )

    private fun createSiblingTemp(file: File, runToken: String): File {
        val directory = file.parentFile ?: throw IOException("file has no parent directory")
        var temp = File(directory, TEMP_PREFIX + runToken + TEMP_SUFFIX)
        var guard = 0
        while (temp.exists() && guard++ < 64) {
            temp = File(directory, TEMP_PREFIX + randomToken(12) + TEMP_SUFFIX)
        }
        if (!temp.createNewFile()) throw IOException("could not create a staging file")
        // Owner only. Never widen these: a world readable staging copy of the user's media is
        // exactly the leak this library exists to prevent.
        temp.setReadable(true, true)
        temp.setWritable(true, true)
        return temp
    }

    /** The replaced file plus whether the copy of the original was really overwritten. */
    private data class SwapResult(val installed: File, val wiped: Boolean)

    /**
     * Runs the replacement transaction, advancing [onPhase] through ReplacePhase at every
     * committed step. Crash recovery keys off the two artefacts these phases create: while
     * OUTPUT_WRITTEN..OUTPUT_VERIFIED hold, the staging file exists and the backup may hold
     * the only copy of the source; once SWAP_COMMITTED and BACKUP_DESTROYED hold, only the
     * installed rewrite remains.
     */
    private fun swapIn(
        original: File,
        rewritten: File,
        runToken: String,
        options: PurgeOptions,
        rename: Boolean = true,
        onPhase: (ReplacePhase) -> Unit = { }
    ): SwapResult? {
        val directory = original.parentFile ?: return null
        onPhase(ReplacePhase.PREPARED)
        val backup = File(directory, backupName(runToken))
        if (backup.exists()) SecureDelete.wipeQuietly(backup, 1)

        if (!original.renameTo(backup)) {
            val fallbackOk = try {
                original.copyTo(backup, overwrite = true)
                original.delete()
            } catch (_: Exception) {
                false
            }
            if (!fallbackOk) return null
        }
        onPhase(ReplacePhase.BACKUP_CREATED)

        if (!rewritten.renameTo(original)) {
            val reinstall = try {
                rewritten.copyTo(original, overwrite = true)
                rewritten.delete()
            } catch (_: Exception) {
                false
            }
            if (!reinstall) {
                backup.renameTo(original)
                return null
            }
        }
        onPhase(ReplacePhase.SWAP_COMMITTED)

        var installed = original
        if (rename && options.randomizeFileName) {
            installed = renameToRandom(original, options) ?: original
        }

        val wiped = if (options.secureDeleteOriginals) {
            SecureDelete.wipeQuietly(backup, options.wipePasses)
        } else {
            backup.delete() || !backup.exists()
        }
        if (wiped) onPhase(ReplacePhase.BACKUP_DESTROYED)

        if (options.resetFileTimestamps) {
            try {
                installed.setLastModified(0L)
            } catch (_: Exception) {
            }
        }
        onPhase(ReplacePhase.COMPLETED)
        return SwapResult(installed, wiped)
    }

    private fun renameToRandom(file: File, options: PurgeOptions): File? {
        val directory = file.parentFile ?: return null
        val extension = if (options.preserveExtension) file.extension else ""
        val length = options.randomNameLength.coerceIn(3, 24)
        repeat(64) {
            val candidate = File(directory, randomToken(length) + if (extension.isEmpty()) "" else ".$extension")
            if (candidate.exists()) return@repeat
            if (file.renameTo(candidate)) return candidate
        }
        return null
    }

    /**
     * The backup keeps the original bytes while the rewritten file is installed, but its name
     * must not reveal what it holds. It is therefore derived only from the random run token,
     * which is shared with the staging file of the same run so recovery can tell the two
     * interrupted states apart.
     */
    private fun backupName(runToken: String): String = ".$BACKUP_PREFIX$runToken$BACKUP_SUFFIX"

    private fun runTokenOfTemp(entry: File): String? {
        val name = entry.name
        if (!name.startsWith(TEMP_PREFIX) || !name.endsWith(TEMP_SUFFIX)) return null
        return name.substring(TEMP_PREFIX.length, name.length - TEMP_SUFFIX.length)
    }

    private fun runTokenOfBackup(entry: File): String? {
        val name = entry.name
        if (!name.startsWith(".$BACKUP_PREFIX") || !name.endsWith(BACKUP_SUFFIX)) return null
        return name.substring(1 + BACKUP_PREFIX.length, name.length - BACKUP_SUFFIX.length)
    }

    private fun sameContent(left: File, right: File): Boolean {
        if (left.length() != right.length()) return false
        return try {
            BinaryIo.open(left).use { first ->
                BinaryIo.open(right).use { second ->
                    val leftBuffer = ByteArray(64 * 1024)
                    val rightBuffer = ByteArray(64 * 1024)
                    while (true) {
                        val readLeft = first.readFully(leftBuffer)
                        val readRight = second.readFully(rightBuffer)
                        if (readLeft != readRight) return false
                        if (!readLeft) return true
                        if (!leftBuffer.contentEquals(rightBuffer)) return false
                    }
                    @Suppress("UNREACHABLE_CODE")
                    true
                }
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun randomToken(length: Int): String {
        val builder = StringBuilder(length)
        repeat(length) { builder.append(namePool[secureRandom.nextInt(namePool.length)]) }
        return builder.toString()
    }

    /**
     * Clean up after a crash.
     *
     * A run leaves at most two artefacts that share a token: the staging file (rewritten bytes,
     * never installed) and the backup (original bytes). If the staging file is still there the
     * swap never happened, so the backup is the only copy of the user's file and it is restored.
     * If only the backup is left, the swap finished and the backup is the pre purge original, so
     * it is wiped instead of being resurrected.
     */
    fun recoverInterruptedArtifacts(directory: File): List<File> {
        val restored = ArrayList<File>()
        val staleBefore = System.currentTimeMillis() - STALE_ARTIFACT_AGE
        val entries = directory.listFiles() ?: return restored
        val stagedRuns = HashSet<String>()
        for (entry in entries) {
            if (!entry.isFile || entry.lastModified() >= staleBefore) continue
            val run = runTokenOfTemp(entry) ?: continue
            stagedRuns.add(run)
            val backup = File(directory, backupName(run))
            if (backup.exists() && backup.isFile) {
                val target = recoveredName(directory, run, backup)
                if (target != null && backup.renameTo(target)) {
                    restored.add(target)
                    SecureDelete.wipeQuietly(entry, 1)
                    continue
                }
            }
            SecureDelete.wipeQuietly(entry, 1)
        }
        for (entry in directory.listFiles() ?: return restored) {
            if (!entry.isFile) continue
            val run = runTokenOfBackup(entry) ?: continue
            if (stagedRuns.contains(run)) continue
            SecureDelete.wipeQuietly(entry, 1)
        }
        return restored
    }

    private fun recoveredName(directory: File, run: String, content: File): File? {
        // The backup file name is deliberately meaningless, so the suffix has to come from the
        // content. Restoring a video as "recovered-<token>.purgebak" would hide what it is.
        val extension = try {
            FormatDetector.canonicalExtension(FormatDetector.detect(content).format)
        } catch (_: Exception) {
            ""
        }
        val suffix = if (extension.isEmpty()) "" else ".$extension"
        repeat(64) {
            val candidate = File(directory, "recovered-$run$suffix")
            if (!candidate.exists()) return candidate
        }
        return null
    }

    fun purgeAll(
        files: List<File>,
        options: PurgeOptions = PurgeOptions.maximumPrivacy(),
        onFileDone: ((PurgeReport) -> Unit)? = null
    ): PurgeBatchReport {
        val reports = ArrayList<PurgeReport>(files.size)
        for (file in files) {
            options.checkCancelled(file)
            val report = purge(file, options)
            reports.add(report)
            onFileDone?.invoke(report)
        }
        return PurgeBatchReport(reports)
    }

    fun formatHint(extension: String): String = extension.lowercase(Locale.ROOT)
}
