package com.example.lock.safe_delete

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.storage.StorageManager
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.util.UUID

internal class FilePurgeOutcome(
    var length: Long = 0L,
    var passes: Int = 0,
    var bytesOverwritten: Long = 0L,
    var verifiedBytes: Long = 0L,
    var gone: Boolean = false,
    var error: String? = null,
    val stages: MutableList<StageOutcome> = mutableListOf(),
    val warnings: MutableList<String> = mutableListOf(),
    val residuals: MutableList<ResidualArtifact> = mutableListOf()
)

internal class PurgeOrchestrator(
    private val context: Context,
    private val options: PurgeOptions,
    private val listener: ProgressListener?,
    private val cancel: CancellationToken,
    private val audit: AuditSink
) {

    private val rng = Rng.secure()
    private val engine = OverwriteEngine(options.level, options.verifyMode, rng)
    private var thumbs: ThumbnailSanitizer? = null

    fun execute(targets: List<DeleteTarget>): SessionReport {
        val started = System.currentTimeMillis()
        val reports = ArrayList<TargetReport>(targets.size)

        thumbs = if (options.purgeThumbnails) {
            ThumbnailSanitizer(context, rng, cancel, targets.map { it.displayName })
        } else {
            null
        }

        targets.forEachIndexed { index, target ->
            if (cancel.isCancelled) {
                reports.add(cancelledReport(target, index, targets.size, started))
                return@forEachIndexed
            }
            listener?.onTargetStart(target, index, targets.size)
            val report = purgeTarget(target, index, targets.size)
            reports.add(report)
            listener?.onTargetFinished(report)
        }

        if (!options.dryRun && !cancel.isCancelled) {
            thumbs?.purgeOwnAppCaches()
        }

        var pressureBytes = 0L
        var deepCleanExecuted = false
        var deepCleanPending = false
        val deepCleanWarnings = mutableListOf<String>()
        if (options.deepClean && !options.dryRun && !cancel.isCancelled && reports.any { !it.alreadyAbsent }) {
            if (options.deepCleanInline) {
                val result = DeepCleaner.run(context, options.deepCleanConfig, cancel) { written, budget ->
                    listener?.onStage(
                        DeletionStage.ALLOCATION_PRESSURE,
                        "deep clean: churning free space to force flash garbage collection",
                        written,
                        budget
                    )
                }
                pressureBytes = result.bytesWritten
                deepCleanExecuted = result.executed && result.bytesWritten > 0L
                result.skippedReason?.let { deepCleanWarnings.add("deep clean skipped: $it") }
                deepCleanWarnings.addAll(result.warnings)
            } else {
                deepCleanPending = true
                deepCleanWarnings.add(
                    "deep clean deferred to the background scheduler; it runs while the device is charging"
                )
            }
        }

        val assurance = when {
            reports.isEmpty() -> AssuranceLevel.WEAK
            reports.any { it.assurance == AssuranceLevel.WEAK } -> AssuranceLevel.WEAK
            else -> AssuranceLevel.BEST_EFFORT
        }

        val report = SessionReport(
            reports = reports,
            totalBytesShredded = reports.sumOf { it.bytesOverwritten },
            totalElapsedMs = System.currentTimeMillis() - started,
            cancelled = cancel.isCancelled,
            level = options.level,
            verifyMode = options.verifyMode,
            pressureBytes = pressureBytes,
            deepCleanExecuted = deepCleanExecuted,
            deepCleanPending = deepCleanPending,
            deepCleanWarnings = deepCleanWarnings,
            assurance = assurance
        )
        SecureLog.i("session complete: ${report.summaryLine()} pressureBytes=$pressureBytes")
        return report
    }

    private fun cancelledReport(
        target: DeleteTarget,
        index: Int,
        total: Int,
        began: Long
    ): TargetReport {
        val path = target.path
        val present = path?.let { File(it).exists() } ?: true
        val warning = "cancelled before processing target ${index + 1}/$total; nothing was destroyed"
        SecureLog.w(warning)
        return TargetReport(
            target = target,
            resolvedPath = path,
            length = 0L,
            passes = 0,
            bytesOverwritten = 0L,
            verifiedBytes = 0L,
            stages = listOf(
                StageOutcome(DeletionStage.ANALYZE, false, "cancelled before processing")
            ),
            residuals = emptyList(),
            warnings = listOf(warning),
            error = "cancelled before processing",
            elapsedMs = System.currentTimeMillis() - began,
            gone = !present,
            alreadyAbsent = false,
            assurance = AssuranceLevel.WEAK
        )
    }

    private fun purgeTarget(target: DeleteTarget, index: Int, total: Int): TargetReport {
        val began = System.currentTimeMillis()
        val stages = mutableListOf<StageOutcome>()
        val warnings = mutableListOf<String>()
        val residuals = mutableListOf<ResidualArtifact>()
        var error: String? = null
        var length = 0L
        var passes = 0
        var bytesOverwritten = 0L
        var verifiedBytes = 0L
        var resolvedPath = target.path
        var gone = false
        var alreadyAbsent = false
        var fsInfo: FsInfo? = null

        val file = target.path?.let { File(it) }

        try {
            if (file != null && FsOps.isSymbolicLink(file) && options.followSymlinks && file.exists()) {
                warnings.add("symlink followed by request; the linked file is the target")
            }

            when {
                file == null -> {
                    if (target.uriString != null) {
                        val outcome = purgeUriTarget(target)
                        stages.addAll(outcome.stages)
                        warnings.addAll(outcome.warnings)
                        residuals.addAll(outcome.residuals)
                        length = outcome.length
                        passes = outcome.passes
                        bytesOverwritten = outcome.bytesOverwritten
                        verifiedBytes = outcome.verifiedBytes
                        gone = outcome.gone
                        error = outcome.error
                    } else {
                        stages.add(StageOutcome(DeletionStage.ANALYZE, false, "no file path"))
                        error = "target cannot be resolved to a file"
                    }
                }

                FsOps.isSymbolicLink(file) && !options.followSymlinks -> {
                    val removed = FsOps.unlink(file)
                    FsOps.syncDirectory(file.parentFile)
                    stages.add(
                        StageOutcome(
                            DeletionStage.UNLINK,
                            removed,
                            "symlink unlinked without following its target",
                            0L,
                            0L
                        )
                    )
                    if (!removed) {
                        error = "symlink could not be removed"
                    } else {
                        warnings.add("symlink removed; the linked file was left untouched")
                        gone = !FsOps.isSymbolicLink(file)
                    }
                }

                !file.exists() -> {
                    stages.add(StageOutcome(DeletionStage.ANALYZE, true, "already absent"))
                    warnings.add("target was already absent; nothing destroyed")
                    gone = true
                    alreadyAbsent = true
                    if (!options.dryRun) {
                        cleanResidualsOfAbsentTarget(
                            file = file,
                            targetName = target.displayName,
                            stages = stages,
                            warnings = warnings,
                            residuals = residuals
                        )
                    }
                }

                target.kind == TargetKind.CONTENT_URI && !FsOps.canOpenReadWrite(file) -> {
                    val outcome = purgeUriTarget(target)
                    stages.addAll(outcome.stages)
                    warnings.addAll(outcome.warnings)
                    residuals.addAll(outcome.residuals)
                    length = outcome.length
                    passes = outcome.passes
                    bytesOverwritten = outcome.bytesOverwritten
                    verifiedBytes = outcome.verifiedBytes
                    gone = outcome.gone
                    error = outcome.error
                }

                file.isDirectory -> {
                    val outcome = purgeDirectory(file)
                    stages.addAll(outcome.stages)
                    warnings.addAll(outcome.warnings)
                    residuals.addAll(outcome.residuals)
                    length = outcome.length
                    passes = outcome.passes
                    bytesOverwritten = outcome.bytesOverwritten
                    verifiedBytes = outcome.verifiedBytes
                    gone = outcome.gone
                    error = outcome.error
                    resolvedPath = file.absolutePath
                }

                else -> {
                    val links = FsOps.linkCount(file)
                    if (links > 1) {
                        warnings.add(
                            "file has $links hard links; remaining links still expose the same data"
                        )
                    }
                    listener?.onStage(DeletionStage.ANALYZE, "analyze", 0L, 0L)
                    val analyzeStart = System.currentTimeMillis()
                    val info = FsOps.fsInfoFor(file)
                    fsInfo = info
                    val analyzeOk = if (options.dryRun) {
                        try {
                            FsOps.openReadOnly(file).use { }
                            true
                        } catch (t: Throwable) {
                            false
                        }
                    } else {
                        FsOps.setWritable(file) && FsOps.canOpenReadWrite(file)
                    }
                    stages.add(
                        StageOutcome(
                            DeletionStage.ANALYZE,
                            analyzeOk,
                            "fs=${info.effectiveFsType} discard=${if (info.discardKnown) info.hasDiscardOption.toString() else "unknown"} " +
                                "ro=${info.readOnly} links=$links",
                            file.length(),
                            System.currentTimeMillis() - analyzeStart
                        )
                    )
                    if (!info.readOnly && info.discardKnown && !info.hasDiscardOption) {
                        warnings.add(
                            "volume is mounted without discard; freed blocks depend on scheduled fstrim and controller garbage collection"
                        )
                    }
                    if (info.readOnly) {
                        warnings.add("volume reports read-only mount; overwrite may fail")
                    }
                    if (!analyzeOk) {
                        if (target.uriString != null) {
                            val outcome = purgeUriTarget(target)
                            stages.addAll(outcome.stages)
                            warnings.addAll(outcome.warnings)
                            residuals.addAll(outcome.residuals)
                            length = outcome.length
                            passes = outcome.passes
                            bytesOverwritten = outcome.bytesOverwritten
                            verifiedBytes = outcome.verifiedBytes
                            gone = outcome.gone
                            error = outcome.error
                            if (outcome.error == null) {
                                SecureLog.i("used provider path for ${target.displayName}")
                            }
                        } else {
                            error = "file cannot be opened for writing"
                        }
                    } else {
                        var outcome = purgeSingleFile(file, eraseMetadata = target.uriString == null)
                        if (outcome.error != null && !outcome.gone && target.uriString != null) {
                            val fallback = purgeUriTarget(target)
                            outcome.stages.addAll(fallback.stages)
                            outcome.warnings.addAll(fallback.warnings)
                            outcome.residuals.addAll(fallback.residuals)
                            outcome.length = maxOf(outcome.length, fallback.length)
                            outcome.passes = maxOf(outcome.passes, fallback.passes)
                            outcome.bytesOverwritten += fallback.bytesOverwritten
                            outcome.verifiedBytes += fallback.verifiedBytes
                            if (fallback.gone) {
                                outcome.gone = true
                                outcome.error = fallback.error
                            }
                        }
                        stages.addAll(outcome.stages)
                        warnings.addAll(outcome.warnings)
                        residuals.addAll(outcome.residuals)
                        length = outcome.length
                        passes = outcome.passes
                        bytesOverwritten = outcome.bytesOverwritten
                        verifiedBytes = outcome.verifiedBytes
                        gone = outcome.gone
                        error = outcome.error
                        resolvedPath = file.absolutePath
                    }
                }
            }

            if (target.kind == TargetKind.CONTENT_URI || target.uriString != null) {
                val uri = target.uriOrNull()
                if (uri != null && !options.dryRun && (options.eraseMediaStoreRows || !gone)) {
                    val metaStart = System.currentTimeMillis()
                    val metaOutcome = MetadataEraser.eraseForTarget(
                        context = context,
                        targetFile = file,
                        targetName = target.displayName,
                        contentUri = uri,
                        deleteProviderItem = !gone,
                        physicalPurger = ::purgeAuxiliaryFile
                    )
                    stages.add(
                        StageOutcome(
                            DeletionStage.METADATA_ERASE,
                            metaOutcome.warnings.isEmpty(),
                            "rows=${metaOutcome.rowsDeleted} thumbs=${metaOutcome.thumbnailRowsDeleted} " +
                                "providerDeleted=${metaOutcome.providerItemDeleted}",
                            0L,
                            System.currentTimeMillis() - metaStart
                        )
                    )
                    warnings.addAll(metaOutcome.warnings)
                    gone = gone || metaOutcome.providerItemDeleted
                }
            }
        } catch (t: Throwable) {
            SecureLog.e("purge failed for a target: ${Sanitizer.of(t, target.path, target.uriString)}")
            error = Sanitizer.of(t, target.path, target.uriString)
        }

        if (error != null && gone) {
            gone = !(file?.exists() ?: false)
        }
        if (file != null && file.exists()) gone = false

        val assurance = computeAssurance(
            gone = gone,
            alreadyAbsent = alreadyAbsent,
            error = error,
            length = length,
            passes = passes,
            verifiedBytes = verifiedBytes,
            stages = stages,
            residuals = residuals,
            info = fsInfo
        )

        val report = TargetReport(
            target = target,
            resolvedPath = resolvedPath,
            length = length,
            passes = passes,
            bytesOverwritten = bytesOverwritten,
            verifiedBytes = verifiedBytes,
            stages = stages,
            residuals = residuals,
            warnings = warnings,
            error = error,
            elapsedMs = System.currentTimeMillis() - began,
            gone = gone,
            alreadyAbsent = alreadyAbsent,
            assurance = assurance
        )

        writeLedgerEntry(report, file)
        SecureLog.i(
            "target[${index + 1}/$total] success=${report.success} weak=${report.weakDeletion} " +
                "gone=${report.gone} bytes=$bytesOverwritten passes=$passes assurance=${assurance.name}"
        )
        return report
    }

    private fun computeAssurance(
        gone: Boolean,
        alreadyAbsent: Boolean,
        error: String?,
        length: Long,
        passes: Int,
        verifiedBytes: Long,
        stages: List<StageOutcome>,
        residuals: List<ResidualArtifact>,
        info: FsInfo?
    ): AssuranceLevel {
        if (!gone || error != null) return AssuranceLevel.WEAK
        if (length > 0L && passes == 0) return AssuranceLevel.WEAK
        if (stages.any { !it.ok && it.stage.isAssuranceCritical() }) return AssuranceLevel.WEAK
        if (alreadyAbsent) return AssuranceLevel.BEST_EFFORT
        val verifyRequested = engine.passSpecs().any { it.verify }
        if (verifyRequested && length > 0L && verifiedBytes <= 0L) return AssuranceLevel.BEST_EFFORT
        return AssuranceLevel.BEST_EFFORT
    }

    private fun DeletionStage.isAssuranceCritical(): Boolean = when (this) {
        DeletionStage.OVERWRITE,
        DeletionStage.VERIFY,
        DeletionStage.TRUNCATE,
        DeletionStage.UNLINK -> true

        else -> false
    }

    private fun cleanResidualsOfAbsentTarget(
        file: File,
        targetName: String,
        stages: MutableList<StageOutcome>,
        warnings: MutableList<String>,
        residuals: MutableList<ResidualArtifact>
    ) {
        if (options.scanTrashPaths) {
            val scanStart = System.currentTimeMillis()
            val scan = TrashPathAudit.scan(context, file)
            warnings.addAll(scan.warnings)
            val sweep = TrashPathAudit.sweepResiduals(scan.candidates, file.name, null, rng, cancel)
            residuals.addAll(sweep.artifacts)
            if (sweep.reportedOnly > 0) {
                warnings.add(
                    "${sweep.reportedOnly} name-similar residual candidate(s) were found for an absent target; " +
                        "their content could not be verified so they were reported without deletion"
                )
            }
            stages.add(
                StageOutcome(
                    DeletionStage.RESIDUAL_SCAN,
                    true,
                    "inspected=${scan.inspected} candidates=${scan.candidates.size} " +
                        "contentVerified=${sweep.contentVerifiedPurged} reportedOnly=${sweep.reportedOnly}",
                    0L,
                    System.currentTimeMillis() - scanStart
                )
            )
        }

        if (options.purgeThumbnails) {
            val thumbStart = System.currentTimeMillis()
            val report = thumbs?.purgeForTarget(file, targetName)
            report?.warnings?.let { warnings.addAll(it) }
            stages.add(
                StageOutcome(
                    DeletionStage.THUMBNAIL_PURGE,
                    true,
                    "cache files=${report?.cacheFilesPurged ?: 0} blobs=${report?.blobsRedacted ?: 0}",
                    0L,
                    System.currentTimeMillis() - thumbStart
                )
            )
        }
    }

    private fun purgeSingleFile(
        file: File,
        scanTrash: Boolean = options.scanTrashPaths,
        eraseMetadata: Boolean = options.eraseMediaStoreRows,
        purgeThumbnail: Boolean = options.purgeThumbnails
    ): FilePurgeOutcome {
        val outcome = FilePurgeOutcome()
        outcome.length = file.length()

        if (options.dryRun) {
            outcome.stages.add(StageOutcome(DeletionStage.ANALYZE, true, "dry-run"))
            outcome.error = "dry-run: no data destroyed"
            return outcome
        }

        if (scanTrash) {
            val scanStart = System.currentTimeMillis()
            val expected = ContentFingerprint.of(file)
            if (expected == null) {
                outcome.warnings.add(
                    "content fingerprint unavailable before overwrite; residual candidates will be reported without deletion"
                )
            }
            val scan = TrashPathAudit.scan(context, file)
            outcome.warnings.addAll(scan.warnings)
            val sweep = TrashPathAudit.sweepResiduals(scan.candidates, file.name, expected, rng, cancel)
            outcome.residuals.addAll(sweep.artifacts)
            if (sweep.reportedOnly > 0) {
                outcome.warnings.add(
                    "${sweep.reportedOnly} name-similar residual candidate(s) did not match the original content; " +
                        "they were reported without deletion"
                )
            }
            outcome.stages.add(
                StageOutcome(
                    DeletionStage.RESIDUAL_SCAN,
                    true,
                    "inspected=${scan.inspected} candidates=${scan.candidates.size} " +
                        "contentVerified=${sweep.contentVerifiedPurged} reportedOnly=${sweep.reportedOnly}",
                    0L,
                    System.currentTimeMillis() - scanStart
                )
            )
        }

        if (!FsOps.setWritable(file)) {
            outcome.warnings.add("file reported read-only; attempting overwrite anyway")
        }

        val channel: FileChannel = try {
            FsOps.openReadWrite(file)
        } catch (t: Throwable) {
            outcome.error = "cannot open for writing: ${Sanitizer.of(t, file.absolutePath, file.name)}"
            outcome.stages.add(StageOutcome(DeletionStage.OVERWRITE, false, outcome.error!!))
            return outcome
        }

        try {
            if (options.extendToEraseBoundary) {
                val extendStart = System.currentTimeMillis()
                val newLength = extendFile(channel, file, outcome)
                if (newLength > outcome.length) {
                    outcome.stages.add(
                        StageOutcome(
                            DeletionStage.EXTEND,
                            true,
                            "extended ${outcome.length} -> $newLength",
                            newLength - outcome.length,
                            System.currentTimeMillis() - extendStart
                        )
                    )
                    outcome.length = newLength
                }
            }

            val specs = engine.passSpecs()
            var overwriteOk = true
            var verifyOk = true
            var verifiedBytes = 0L

            for ((passIndex, spec) in specs.withIndex()) {
                if (cancel.isCancelled) {
                    outcome.warnings.add("cancelled after $passIndex pass(es)")
                    overwriteOk = false
                    break
                }
                val passStart = System.currentTimeMillis()
                val generator = engine.newGenerator(spec)
                listener?.onStage(
                    DeletionStage.OVERWRITE,
                    "pass ${passIndex + 1}/${specs.size} (${spec.label})",
                    outcome.length * passIndex,
                    outcome.length * specs.size
                )
                val passOk = engine.overwrite(channel, outcome.length, spec, generator, cancel) { processed ->
                    listener?.onStage(
                        DeletionStage.OVERWRITE,
                        "pass ${passIndex + 1}/${specs.size} (${spec.label})",
                        outcome.length * passIndex + processed,
                        outcome.length * specs.size
                    )
                }
                if (passOk) {
                    outcome.passes++
                    outcome.bytesOverwritten += outcome.length
                } else {
                    overwriteOk = false
                }
                outcome.stages.add(
                    StageOutcome(
                        DeletionStage.OVERWRITE,
                        passOk,
                        "${spec.label} bytes=${outcome.length}",
                        outcome.length,
                        System.currentTimeMillis() - passStart
                    )
                )
                if (!passOk) break

                if (spec.verify && !generator.verifiable) {
                    outcome.warnings.add("${spec.label} cannot be verified (non-reproducible CSPRNG pattern)")
                    outcome.stages.add(
                        StageOutcome(
                            DeletionStage.VERIFY,
                            true,
                            "${spec.label} not reproducible by design",
                            0L,
                            0L
                        )
                    )
                } else if (spec.verify) {
                    FsOps.adviseDontNeed(file)
                    val verifyStart = System.currentTimeMillis()
                    listener?.onStage(DeletionStage.VERIFY, "verifying ${spec.label}", 0L, outcome.length)
                    val verification = engine.verify(channel, outcome.length, generator, cancel) { processed ->
                        listener?.onStage(DeletionStage.VERIFY, "verifying ${spec.label}", processed, outcome.length)
                    }
                    if (verification.ok) {
                        verifiedBytes += verification.bytesVerified
                    } else {
                        verifyOk = false
                        outcome.warnings.add(
                            "verification failed for ${spec.label}: " +
                                "${verification.reason ?: "mismatch"} at ${verification.firstMismatchOffset}"
                        )
                    }
                    outcome.stages.add(
                        StageOutcome(
                            DeletionStage.VERIFY,
                            verification.ok,
                            "${spec.label} verified=${verification.bytesVerified} " +
                                "reason=${verification.reason ?: "ok"}",
                            verification.bytesVerified,
                            System.currentTimeMillis() - verifyStart
                        )
                    )
                }
            }

            outcome.verifiedBytes = verifiedBytes

            if (overwriteOk) {
                val truncateStart = System.currentTimeMillis()
                val truncated = FsOps.truncateToZero(channel)
                outcome.stages.add(
                    StageOutcome(
                        DeletionStage.TRUNCATE,
                        truncated,
                        "length reset",
                        outcome.length,
                        System.currentTimeMillis() - truncateStart
                    )
                )
                if (!truncated) outcome.warnings.add("truncate to zero failed")
            }

            if (!overwriteOk && SecureDeleteConfig.STRICT_OVERWRITE) {
                outcome.error = "overwrite pass failed; content may survive"
            }
            if (!verifyOk) {
                outcome.warnings.add("one or more verification passes did not match")
            }
        } catch (t: Throwable) {
            SecureLog.e("internal purge error: ${Sanitizer.of(t, file.absolutePath, file.name)}")
            outcome.error = Sanitizer.of(t, file.absolutePath, file.name)
        } finally {
            try {
                channel.close()
            } catch (ignored: Throwable) {
            }
        }

        if (outcome.error != null && SecureDeleteConfig.STRICT_OVERWRITE) {
            outcome.gone = !file.exists()
            return outcome
        }

        val parent = file.parentFile
        val renameStart = System.currentTimeMillis()
        val renamed = FsOps.renameChain(file, options.renameRounds, SecureDeleteConfig.FSYNC_DIR_EVERY_RENAME, rng)
        val renameOk = options.renameRounds <= 0 || !renamed.exists() || renamed.name != file.name
        outcome.stages.add(
            StageOutcome(
                DeletionStage.RENAME,
                renameOk,
                "rounds=${options.renameRounds}",
                0L,
                System.currentTimeMillis() - renameStart
            )
        )

        val unlinkStart = System.currentTimeMillis()
        val unlinked = FsOps.unlink(renamed)
        outcome.stages.add(
            StageOutcome(
                DeletionStage.UNLINK,
                unlinked,
                "final=${renamed.name}",
                0L,
                System.currentTimeMillis() - unlinkStart
            )
        )

        val syncStart = System.currentTimeMillis()
        val synced = FsOps.syncDirectory(parent)
        outcome.stages.add(
            StageOutcome(
                DeletionStage.DIRECTORY_SYNC,
                synced,
                "parent directory synced",
                0L,
                System.currentTimeMillis() - syncStart
            )
        )

        if (options.scrubDirectoryEntries && parent != null && parent.canWrite()) {
            val scrubStart = System.currentTimeMillis()
            val scrub = FsOps.scrubDirectoryEntries(
                parent,
                SecureDeleteConfig.DIRECTORY_ENTRY_SCRUB_ROUNDS,
                SecureDeleteConfig.DIRECTORY_ENTRY_SCRUB_FILES,
                rng
            )
            outcome.stages.add(
                StageOutcome(
                    DeletionStage.DIRECTORY_ENTRY_SCRUB,
                    scrub.ok,
                    "created=${scrub.filesCreated} removed=${scrub.filesRemoved}",
                    0L,
                    System.currentTimeMillis() - scrubStart
                )
            )
        }

        thumbnailsAndMetadata(file, outcome, eraseMetadata, purgeThumbnail)

        outcome.gone = !file.exists() && !renamed.exists()
        if (!outcome.gone) {
            outcome.warnings.add("file still present after unlink")
        }
        return outcome
    }

    private fun thumbnailsAndMetadata(
        file: File,
        outcome: FilePurgeOutcome,
        eraseMetadata: Boolean,
        purgeThumbnail: Boolean
    ) {
        if (cancel.isCancelled) return

        if (purgeThumbnail) {
            val start = System.currentTimeMillis()
            val thumbReport = thumbs?.purgeForTarget(file, file.name)
            outcome.stages.add(
                StageOutcome(
                    DeletionStage.THUMBNAIL_PURGE,
                    thumbReport?.warnings?.isEmpty() ?: true,
                    "files=${thumbReport?.cacheFilesPurged ?: 0} " +
                        "blobs=${thumbReport?.blobsRedacted ?: 0} " +
                        "bytes=${thumbReport?.cacheBytesPurged ?: 0}",
                    thumbReport?.cacheBytesPurged ?: 0L,
                    System.currentTimeMillis() - start
                )
            )
            thumbReport?.warnings?.let { outcome.warnings.addAll(it) }
        }

        if (eraseMetadata) {
            val start = System.currentTimeMillis()
            val meta = MetadataEraser.eraseForTarget(
                context = context,
                targetFile = file,
                targetName = file.name,
                contentUri = null,
                deleteProviderItem = false,
                physicalPurger = ::purgeAuxiliaryFile
            )
            outcome.stages.add(
                StageOutcome(
                    DeletionStage.METADATA_ERASE,
                    meta.warnings.isEmpty(),
                    "rows=${meta.rowsDeleted} thumbs=${meta.thumbnailRowsDeleted} " +
                        "physical=${meta.physicalThumbnailsPurged}",
                    0L,
                    System.currentTimeMillis() - start
                )
            )
            outcome.warnings.addAll(meta.warnings)
        }
    }

    private fun purgeDirectory(root: File): FilePurgeOutcome {
        val outcome = FilePurgeOutcome()
        val children = ArrayList<File>()
        collectTree(root, children, outcome)

        thumbs?.addSessionNames(children.map { it.name })

        for (child in children) {
            if (cancel.isCancelled) {
                outcome.warnings.add("cancelled while shredding a directory tree")
                break
            }
            if (FsOps.isSymbolicLink(child)) {
                FsOps.unlink(child)
                continue
            }
            if (child.isDirectory) continue
            val childOutcome = purgeSingleFile(
                file = child,
                scanTrash = false,
                eraseMetadata = false,
                purgeThumbnail = false
            )
            outcome.length += childOutcome.length
            outcome.passes = maxOf(outcome.passes, childOutcome.passes)
            outcome.bytesOverwritten += childOutcome.bytesOverwritten
            outcome.verifiedBytes += childOutcome.verifiedBytes
            outcome.warnings.addAll(childOutcome.warnings)
            outcome.residuals.addAll(childOutcome.residuals)
            outcome.stages.addAll(childOutcome.stages)
            if (childOutcome.error != null) {
                if (outcome.error == null) {
                    outcome.error = childOutcome.error
                } else {
                    outcome.warnings.add("additional child failure: ${childOutcome.error}")
                }
            }
        }

        if (options.purgeThumbnails) {
            val start = System.currentTimeMillis()
            var thumbnailFiles = 0
            var thumbnailBlobs = 0
            for (child in children) {
                if (cancel.isCancelled) break
                val report = thumbs?.purgeForTarget(child, child.name)
                thumbnailFiles += report?.cacheFilesPurged ?: 0
                thumbnailBlobs += report?.blobsRedacted ?: 0
                report?.warnings?.let { outcome.warnings.addAll(it) }
            }
            outcome.stages.add(
                StageOutcome(
                    DeletionStage.THUMBNAIL_PURGE,
                    true,
                    "tree files=$thumbnailFiles blobs=$thumbnailBlobs",
                    0L,
                    System.currentTimeMillis() - start
                )
            )
        }

        if (options.eraseMediaStoreRows) {
            val start = System.currentTimeMillis()
            val deleted = MetadataEraser.eraseForDirectory(
                context = context,
                root = root,
                physicalPurger = ::purgeAuxiliaryFile,
                warnings = outcome.warnings
            )
            outcome.stages.add(
                StageOutcome(
                    DeletionStage.METADATA_ERASE,
                    true,
                    "tree rows deleted=$deleted",
                    0L,
                    System.currentTimeMillis() - start
                )
            )
        }

        compactStages(outcome.stages)

        val ordered = children.sortedByDescending { it.absolutePath.length } + root
        for (node in ordered) {
            if (node.exists() && node.isDirectory) {
                node.delete()
            }
        }

        FsOps.syncDirectory(root.parentFile)
        outcome.stages.add(
            StageOutcome(
                DeletionStage.UNLINK,
                !root.exists(),
                "tree root=${root.name}",
                0L,
                0L
            )
        )
        outcome.gone = !root.exists()
        if (!outcome.gone) outcome.warnings.add("directory not fully removed")
        return outcome
    }

    private fun collectTree(root: File, out: MutableList<File>, outcome: FilePurgeOutcome) {
        val stack = ArrayDeque<File>()
        stack.addLast(root)
        var visited = 0
        while (stack.isNotEmpty()) {
            val current = stack.removeLast()
            val entries = try {
                current.listFiles()
            } catch (t: Throwable) {
                outcome.warnings.add("cannot list a directory inside the tree")
                null
            } ?: continue
            for (entry in entries) {
                visited++
                if (visited > MAX_TREE_ENTRIES) {
                    outcome.warnings.add("tree walk truncated at $MAX_TREE_ENTRIES entries")
                    return
                }
                out.add(entry)
                if (entry.isDirectory && !FsOps.isSymbolicLink(entry)) stack.addLast(entry)
            }
        }
    }

    private fun purgeUriTarget(target: DeleteTarget): FilePurgeOutcome {
        val outcome = FilePurgeOutcome()
        val uri = target.uriOrNull()
        if (uri == null) {
            outcome.error = "invalid uri"
            return outcome
        }
        if (options.dryRun) {
            outcome.error = "dry-run: no data destroyed"
            return outcome
        }

        val resolver = context.contentResolver

        try {
            resolver.openFileDescriptor(uri, "r")?.use { probe ->
                if (probe.statSize > 0L) outcome.length = probe.statSize
            }
        } catch (t: Throwable) {
            SecureLog.d("provider stat probe failed: ${Sanitizer.of(t, target.path, target.uriString)}")
        }

        var destroyed = false
        try {
            resolver.openFileDescriptor(uri, "rw")?.use { pfd ->
                destroyed = destroyThroughDescriptor(pfd, "rw", outcome)
            }
        } catch (t: Throwable) {
            outcome.warnings.add("provider rw descriptor failed: ${Sanitizer.of(t, target.path, target.uriString)}")
        }

        if (!destroyed && !cancel.isCancelled) {
            try {
                resolver.openFileDescriptor(uri, "rwt")?.use { pfd ->
                    destroyed = destroyThroughDescriptor(pfd, "rwt", outcome)
                    if (destroyed) {
                        outcome.warnings.add(
                            "rw descriptor unavailable; content destroyed through truncating descriptor without full overwrite passes"
                        )
                    }
                }
            } catch (t: Throwable) {
                outcome.warnings.add("provider rwt descriptor failed: ${Sanitizer.of(t, target.path, target.uriString)}")
            }
        }

        if (!destroyed && outcome.error == null && !cancel.isCancelled) {
            outcome.error = "provider content could not be destroyed"
        }

        val deleted = MetadataEraser.deleteThroughProvider(context, uri, outcome.warnings)
        outcome.stages.add(
            StageOutcome(
                DeletionStage.UNLINK,
                deleted,
                "provider entry removed=$deleted",
                0L,
                0L
            )
        )
        val pathKnown = target.path != null
        val pathStillPresent = target.path?.let { File(it).exists() } ?: true
        outcome.gone = deleted || (pathKnown && !pathStillPresent)
        if (!deleted) outcome.warnings.add("provider refused deletion; item may still exist")
        return outcome
    }

    private fun destroyThroughDescriptor(
        pfd: ParcelFileDescriptor,
        mode: String,
        outcome: FilePurgeOutcome
    ): Boolean {
        return try {
            val writeChannel = FileOutputStream(pfd.fileDescriptor).channel
            val readChannel = FileInputStream(pfd.fileDescriptor).channel
            val size = if (pfd.statSize > 0L) pfd.statSize else runCatching { writeChannel.size() }.getOrDefault(0L)
            if (size > outcome.length) outcome.length = size

            if (size <= 0L) {
                outcome.stages.add(
                    StageOutcome(DeletionStage.TRUNCATE, true, "provider descriptor mode=$mode already empty", 0L, 0L)
                )
                return true
            }

            val specs = engine.passSpecs()
            var passesDone = 0
            var failed = false
            for ((passIndex, spec) in specs.withIndex()) {
                if (cancel.isCancelled) break
                val generator = engine.newGenerator(spec)
                listener?.onStage(
                    DeletionStage.OVERWRITE,
                    "provider pass ${passIndex + 1}/${specs.size} (${spec.label})",
                    size * passIndex,
                    size * specs.size
                )
                val passOk = engine.overwrite(writeChannel, size, spec, generator, cancel) { processed ->
                    listener?.onStage(
                        DeletionStage.OVERWRITE,
                        "provider pass ${passIndex + 1}/${specs.size} (${spec.label})",
                        size * passIndex + processed,
                        size * specs.size
                    )
                }
                outcome.stages.add(
                    StageOutcome(DeletionStage.OVERWRITE, passOk, "provider ${spec.label} mode=$mode", size, 0L)
                )
                if (!passOk) {
                    failed = true
                    if (outcome.error == null) outcome.error = "provider overwrite failed"
                    break
                }
                passesDone++
                outcome.passes++
                outcome.bytesOverwritten += size
                if (spec.verify && generator.verifiable) {
                    val verification = engine.verify(readChannel, size, generator, cancel) { }
                    outcome.stages.add(
                        StageOutcome(
                            DeletionStage.VERIFY,
                            verification.ok,
                            "provider verify ${spec.label} ${verification.reason ?: "ok"}",
                            verification.bytesVerified,
                            0L
                        )
                    )
                    outcome.verifiedBytes += verification.bytesVerified
                    if (!verification.ok) {
                        outcome.warnings.add(
                            "provider verification failed for ${spec.label}: ${verification.reason ?: "mismatch"}"
                        )
                    }
                }
            }

            if (failed || cancel.isCancelled) return false

            val truncated = FsOps.truncateToZero(writeChannel)
            outcome.stages.add(
                StageOutcome(DeletionStage.TRUNCATE, truncated, "provider truncate mode=$mode", size, 0L)
            )
            passesDone > 0 && truncated
        } catch (t: Throwable) {
            outcome.warnings.add("provider descriptor mode=$mode failed: ${Sanitizer.of(t)}")
            false
        }
    }

    private fun extendFile(channel: FileChannel, file: File, outcome: FilePurgeOutcome): Long {
        val original = runCatching { channel.size() }.getOrDefault(file.length())
        if (original <= 0L) return original
        if (original < SecureDeleteConfig.EXTENSION_MIN_FILE_BYTES) {
            outcome.warnings.add(
                "extension skipped: file smaller than " +
                    "${SecureDeleteConfig.EXTENSION_MIN_FILE_BYTES} bytes"
            )
            return original
        }

        val alignment = SecureDeleteConfig.ERASE_BOUNDARY_ALIGNMENT
        val remainder = original % alignment
        var target = if (remainder == 0L) original + alignment else original + (alignment - remainder) + alignment

        if (target - original > SecureDeleteConfig.MAX_EXTENSION_BYTES) {
            target = original + SecureDeleteConfig.MAX_EXTENSION_BYTES
        }
        val growth = target - original
        if (growth <= 0L) return original

        val required = growth + SecureDeleteConfig.EXTENSION_FREE_SPACE_RESERVE
        val headroom = FsOps.spaceHeadroom(file.parentFile ?: file)
        if (headroom < required) {
            outcome.warnings.add(
                "extension skipped: $headroom bytes headroom, $required required for growth and reserve"
            )
            return original
        }

        return try {
            val probe = ByteArray(1)
            rng.nextBytes(probe)
            channel.position(target - 1L)
            val written = channel.write(ByteBuffer.wrap(probe))
            val actual = channel.size()
            if (written == 1 && actual >= target) {
                channel.position(0L)
                FsOps.force(channel)
                actual
            } else {
                channel.position(0L)
                outcome.warnings.add("extension incomplete: requested $target, actual $actual")
                if (actual > original) actual else original
            }
        } catch (t: Throwable) {
            runCatching { channel.position(0L) }
            outcome.warnings.add("extension failed: ${Sanitizer.of(t, file.absolutePath, file.name)}")
            original
        }
    }

    private fun purgeAuxiliaryFile(file: File): Boolean {
        if (!file.exists() || !file.isFile) return !file.exists()
        val length = file.length()
        var ok = false
        try {
            if (FsOps.setWritable(file)) {
                FsOps.openReadWrite(file).use { channel ->
                    val spec = PassSpec(PassPattern.DETERMINISTIC_RANDOM, false, "aux")
                    val generator = engine.newGenerator(spec)
                    ok = engine.overwrite(channel, length, spec, generator, cancel) { }
                    FsOps.truncateToZero(channel)
                }
            }
        } catch (t: Throwable) {
            SecureLog.w("auxiliary purge failed: ${Sanitizer.of(t, file.absolutePath, file.name)}")
        }
        val renamed = FsOps.renameChain(file, 2, false, rng)
        val removed = FsOps.unlink(renamed)
        FsOps.syncDirectory(renamed.parentFile)
        return removed && (ok || length == 0L)
    }

    private fun compactStages(stages: MutableList<StageOutcome>) {
        if (stages.size <= MAX_STAGE_ENTRIES) return
        val grouped = LinkedHashMap<DeletionStage, StageOutcome>()
        for (stage in stages) {
            val existing = grouped[stage.stage]
            grouped[stage.stage] = if (existing == null) {
                stage
            } else {
                StageOutcome(
                    stage = stage.stage,
                    ok = existing.ok && stage.ok,
                    detail = "aggregated",
                    bytes = existing.bytes + stage.bytes,
                    elapsedMs = existing.elapsedMs + stage.elapsedMs
                )
            }
        }
        stages.clear()
        stages.addAll(grouped.values)
    }

    private fun writeLedgerEntry(report: TargetReport, file: File?) {
        if (!options.writeLedger || options.dryRun) return
        try {
            val identitySource = report.resolvedPath ?: report.target.displayName
            val identityHash = SqliteAuditLedger.identityHash(context, identitySource)
            val fsType = file?.let { FsOps.fsInfoFor(it).fsType } ?: "provider"
            val event = AuditEvent(
                id = UUID.randomUUID().toString(),
                timestampMs = System.currentTimeMillis(),
                identityHash = identityHash,
                length = report.length,
                level = options.level,
                passes = report.passes,
                verifiedBytes = report.verifiedBytes,
                success = report.success,
                fsType = fsType,
                residualCount = report.residuals.size
            )
            audit.record(event)
        } catch (t: Throwable) {
            SecureLog.w("ledger write failed: ${Sanitizer.of(t)}")
        }
    }

    fun maintenanceOnly(bytesBudget: Long, config: DeepCleanConfig): MaintenanceReport {
        val started = System.currentTimeMillis()
        val effective = config.copy(
            maxBytes = minOf(config.maxBytes, bytesBudget.coerceAtLeast(0L)),
            requireCharging = false
        )
        val result = DeepCleaner.run(context, effective, cancel) { _, _ -> }
        val warnings = result.warnings.toMutableList()
        result.skippedReason?.let { warnings.add("deep clean skipped: $it") }
        return MaintenanceReport(
            pressureBytes = result.bytesWritten,
            systemReclaimedBytes = result.systemReclaimedBytes,
            cacheScanMillis = System.currentTimeMillis() - started,
            warnings = warnings
        )
    }

    private companion object {
        const val MAX_TREE_ENTRIES = 200000
        const val MAX_STAGE_ENTRIES = 400
    }
}

object DeepCleaner {

    data class Result(
        val bytesWritten: Long,
        val systemReclaimedBytes: Long,
        val filesWritten: Int,
        val fsyncedFiles: Int,
        val leftoversRemoved: Int,
        val skippedReason: String?,
        val stoppedByTimeBudget: Boolean = false,
        val stoppedByReserve: Boolean = false,
        val warnings: List<String>
    ) {
        val executed: Boolean get() = skippedReason == null
        val stoppedEarly: Boolean get() = stoppedByTimeBudget || stoppedByReserve
    }

    private val running = java.util.concurrent.atomic.AtomicBoolean(false)

    fun isRunning(): Boolean = running.get()

    fun candidateDirs(context: Context, create: Boolean): List<File> {
        val dirs = LinkedHashSet<File>()
        runCatching {
            context.noBackupFilesDir?.let { dirs.add(File(it, "deepclean")) }
        }
        runCatching {
            context.getExternalFilesDirs(null)?.forEach { dir ->
                if (dir != null) dirs.add(File(dir, "deepclean"))
            }
        }
        val out = mutableListOf<File>()
        for (dir in dirs) {
            if (dir.isDirectory) {
                out.add(dir)
            } else if (create && dir.mkdirs()) {
                out.add(dir)
            }
        }
        return out
    }

    fun cleanupLeftovers(context: Context): Int {
        if (!running.compareAndSet(false, true)) return 0
        return try {
            cleanupLeftoversInternal(context)
        } finally {
            running.set(false)
        }
    }

    private fun cleanupLeftoversInternal(context: Context): Int {
        var removed = 0
        for (dir in candidateDirs(context, false)) {
            val children = dir.listFiles() ?: continue
            for (child in children) {
                if (!child.name.startsWith(SecureDeleteConfig.DEEP_CLEAN_FILE_PREFIX)) continue
                if (FsOps.unlink(child)) removed++
            }
            VolumeRoots.removeIfEmpty(dir)
        }
        return removed
    }

    fun isCharging(context: Context): Boolean? {
        return try {
            val battery = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
                ?: return null
            val plugged = battery.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1)
            val status = battery.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
            when {
                plugged == BatteryManager.BATTERY_PLUGGED_AC ||
                    plugged == BatteryManager.BATTERY_PLUGGED_USB ||
                    plugged == BatteryManager.BATTERY_PLUGGED_WIRELESS -> true

                status == BatteryManager.BATTERY_STATUS_CHARGING ||
                    status == BatteryManager.BATTERY_STATUS_FULL -> true

                else -> false
            }
        } catch (t: Throwable) {
            null
        }
    }

    fun run(
        context: Context,
        config: DeepCleanConfig,
        cancel: CancellationToken,
        onProgress: (Long, Long) -> Unit
    ): Result {
        if (!running.compareAndSet(false, true)) {
            return Result(
                0L, 0L, 0, 0, 0,
                "another deep clean is already running",
                false,
                false,
                emptyList()
            )
        }
        try {
            return runLocked(context, config, cancel, onProgress)
        } finally {
            running.set(false)
        }
    }

    private fun runLocked(
        context: Context,
        config: DeepCleanConfig,
        cancel: CancellationToken,
        onProgress: (Long, Long) -> Unit
    ): Result {
        val startedAt = System.currentTimeMillis()
        val warnings = mutableListOf<String>()
        val leftovers = cleanupLeftoversInternal(context)

        if (config.requireCharging) {
            when (isCharging(context)) {
                false -> return Result(
                    0L, 0L, 0, 0, leftovers,
                    "device is not charging; deep clean deferred to avoid battery drain and flash wear",
                    false,
                    false,
                    warnings
                )

                null -> warnings.add("charging state unknown; proceeding with deep clean")
                true -> Unit
            }
        }

        var systemReclaimed = 0L
        if (config.systemReclaimHint && Build.VERSION.SDK_INT >= 26) {
            try {
                val storageManager = context.getSystemService(Context.STORAGE_SERVICE) as? StorageManager
                if (storageManager != null) {
                    val allocatable = runCatching {
                        storageManager.getAllocatableBytes(StorageManager.UUID_DEFAULT)
                    }.getOrDefault(0L)
                    val request = minOf(allocatable / 2, config.maxBytes).coerceAtLeast(0L)
                    if (request > 0L) {
                        runCatching { storageManager.allocateBytes(StorageManager.UUID_DEFAULT, request) }
                            .onSuccess { systemReclaimed = request }
                            .onFailure { warnings.add("system reclaim hint rejected: ${Sanitizer.of(it)}") }
                    }
                }
            } catch (t: Throwable) {
                warnings.add("storage manager unavailable: ${Sanitizer.of(t)}")
            }
        }

        val dirs = dedupeByVolume(candidateDirs(context, true))
        if (dirs.isEmpty()) {
            return Result(
                0L, systemReclaimed, 0, 0, leftovers,
                "no private directory available for deep clean",
                false,
                false,
                warnings
            )
        }

        val rng = Rng.secure()
        val buffer = ByteArray(
            minOf(SecureDeleteConfig.DEEP_CLEAN_WRITE_BUFFER_BYTES.toLong(), config.chunkFileBytes).toInt()
        )
        var totalWritten = 0L
        var filesWritten = 0
        var fsynced = 0
        var stoppedByTime = false
        var stoppedByReserve = false

        for (dir in dirs) {
            if (cancel.isCancelled || stoppedByTime) break
            val free = FsOps.availableBytes(dir)
            val room = (free - config.reserveBytes).coerceAtLeast(0L)
            val budget = minOf(config.maxBytes, room * config.freeSpacePercent / 100L)
            if (budget < config.chunkFileBytes) {
                warnings.add("free space on one volume is below the deep clean threshold; volume skipped")
                continue
            }
            val kept = mutableListOf<File>()
            var dirWritten = 0L
            try {
                while (dirWritten < budget && !cancel.isCancelled) {
                    if (config.maxRunMillis > 0L &&
                        System.currentTimeMillis() - startedAt > config.maxRunMillis
                    ) {
                        stoppedByTime = true
                        warnings.add("deep clean reached its time budget; the remainder is rescheduled")
                        break
                    }
                    if (FsOps.availableBytes(dir) < config.reserveBytes) {
                        stoppedByReserve = true
                        warnings.add("deep clean stopped on one volume to keep the reserved free space")
                        break
                    }
                    val file = File(dir, SecureDeleteConfig.DEEP_CLEAN_FILE_PREFIX + Digest.randomHex(8, rng) + ".bin")
                    try {
                        FileOutputStream(file).use { out ->
                            var remaining = minOf(config.chunkFileBytes, budget - dirWritten)
                            while (remaining > 0L && !cancel.isCancelled) {
                                rng.nextBytes(buffer)
                                val size = minOf(buffer.size.toLong(), remaining).toInt()
                                out.write(buffer, 0, size)
                                remaining -= size
                                dirWritten += size
                                totalWritten += size
                                onProgress(totalWritten, budget)
                            }
                            out.flush()
                            out.fd.sync()
                            fsynced++
                        }
                        filesWritten++
                        kept.add(file)
                    } catch (t: Throwable) {
                        warnings.add("deep clean write stopped on one volume: ${Sanitizer.of(t, dir.absolutePath)}")
                        if (file.exists()) kept.add(file)
                        break
                    }
                }
            } finally {
                for (file in kept) {
                    if (file.exists() && !FsOps.unlink(file)) {
                        warnings.add("a deep clean file could not be removed")
                    }
                }
                FsOps.syncDirectory(dir)
            }
        }

        Zeroize.bytes(buffer)
        SecureLog.i(
            "deep clean: written=$totalWritten files=$filesWritten fsynced=$fsynced " +
                "reclaimed=$systemReclaimed leftovers=$leftovers"
        )
        return Result(
            totalWritten, systemReclaimed, filesWritten, fsynced, leftovers, null,
            stoppedByTime, stoppedByReserve, warnings
        )
    }

    private fun dedupeByVolume(dirs: List<File>): List<File> {
        val seen = LinkedHashSet<String>()
        val out = mutableListOf<File>()
        for (dir in dirs) {
            val info = FsOps.fsInfoFor(dir)
            val key = info.effectiveMountPoint + "|" + info.effectiveFsType
            if (seen.add(key)) out.add(dir)
        }
        return out
    }
}
