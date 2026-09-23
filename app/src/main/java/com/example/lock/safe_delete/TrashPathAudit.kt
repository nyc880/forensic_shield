package com.example.lock.safe_delete

import android.content.Context
import android.os.Environment
import java.io.File
import java.util.Locale

internal object VolumeRoots {

    fun all(context: Context): List<File> {
        val roots = LinkedHashSet<String>()

        try {
            Environment.getExternalStorageDirectory()?.let { roots.add(FsOps.canonicalPath(it)) }
        } catch (t: Throwable) {
            SecureLog.d("primary external storage unavailable")
        }

        try {
            val storageRoot = File(SecureDeleteConfig.STORAGE_ROOT_DIR)
            storageRoot.listFiles()?.take(SecureDeleteConfig.STORAGE_ROOT_SCAN_LIMIT)?.forEach { entry ->
                if (!entry.isDirectory) return@forEach
                if (entry.name.equals("emulated", ignoreCase = true)) {
                    entry.listFiles()?.take(SecureDeleteConfig.STORAGE_ROOT_SCAN_LIMIT)?.forEach { user ->
                        if (user.isDirectory) roots.add(FsOps.canonicalPath(user))
                    }
                } else {
                    roots.add(FsOps.canonicalPath(entry))
                }
            }
        } catch (t: Throwable) {
            SecureLog.d("storage volume enumeration failed: ${t.message}")
        }

        try {
            context.getExternalFilesDirs(null)?.forEach { dir ->
                dir ?: return@forEach
                val root = stripAppSpecificSuffix(FsOps.canonicalPath(dir))
                if (root != null) roots.add(root)
            }
        } catch (t: Throwable) {
            SecureLog.d("external files dirs unavailable: ${t.message}")
        }

        return roots.map { File(it) }.filter { it.exists() && it.isDirectory }
    }

    private fun stripAppSpecificSuffix(path: String): String? {
        val marker = "/Android/data/"
        val index = path.indexOf(marker)
        if (index <= 0) return if (path.contains("/Android/")) null else path
        return path.substring(0, index)
    }

    fun removeIfEmpty(file: File?): Boolean {
        val target = file ?: return false
        return try {
            if (target.isDirectory && (target.listFiles()?.isEmpty() != false)) {
                val removed = target.delete()
                if (removed) FsOps.syncDirectory(target.parentFile)
                removed
            } else {
                false
            }
        } catch (t: Throwable) {
            false
        }
    }
}

internal object TrashPathAudit {

    private val KNOWN_TRASH_DIR_NAMES = listOf(
        ".trash",
        ".trashed",
        "trash",
        "Trashed",
        ".Trash-1000",
        ".Trash-0",
        "Recycle",
        "recycle",
        "RECYCLED",
        "recycler",
        ".recycler",
        "recyclebin",
        ".recyclebin",
        ".recycle",
        "\$RECYCLE.BIN",
        "LOST.DIR",
        "found.000",
        "Recently Deleted",
        "RecentlyDeleted",
        ".trashbin",
        ".globaltrash",
        "dustbin",
        ".dustbin"
    )

    private val COMMON_MEDIA_DIRS = listOf(
        "DCIM", "Pictures", "Movies", "Download", "Downloads", "Documents", "Android"
    )

    private val NESTED_TRASH_PARENTS = listOf(
        "Pictures/.Gallery2",
        "DCIM/Camera",
        "Pictures/Screenshots"
    )

    private val RESIDUAL_SUFFIXES = listOf(
        ".bak", ".tmp", ".temp", ".orig", ".old", ".save", ".swp", ".part", ".partial", ".crdownload"
    )

    private val TRASH_PREFIX_REGEX = Regex("""^\.(trashed|pending)-\d+-(.+)$""")

    data class ScanResult(
        val candidates: List<File>,
        val inspected: Int,
        val truncated: Boolean,
        val warnings: List<String>
    )

    fun scan(context: Context, target: File, maxDepth: Int = SecureDeleteConfig.TRASH_SCAN_MAX_DEPTH): ScanResult {
        val candidates = LinkedHashSet<String>()
        val warnings = mutableListOf<String>()
        val targetName = target.name
        val targetPath = FsOps.canonicalPath(target)
        var inspected = 0
        var truncated = false

        val searchDirs = LinkedHashSet<File>()
        target.parentFile?.let { searchDirs.add(it) }
        target.parentFile?.parentFile?.let { searchDirs.add(it) }

        for (root in VolumeRoots.all(context)) {
            searchDirs.add(root)
            KNOWN_TRASH_DIR_NAMES.forEach { name ->
                searchDirs.add(File(root, name))
            }
            COMMON_MEDIA_DIRS.forEach { common ->
                val dir = File(root, common)
                if (dir.isDirectory) {
                    KNOWN_TRASH_DIR_NAMES.forEach { name -> searchDirs.add(File(dir, name)) }
                }
            }
            NESTED_TRASH_PARENTS.forEach { nested ->
                val dir = File(root, nested)
                if (dir.isDirectory) {
                    searchDirs.add(dir)
                    KNOWN_TRASH_DIR_NAMES.forEach { name -> searchDirs.add(File(dir, name)) }
                }
            }
        }

        for (dir in searchDirs) {
            if (!dir.exists() || !dir.isDirectory) continue
            inspected += inspectDirectory(dir, targetName, targetPath, candidates, warnings)
            if (inspected > MAX_INSPECTED) {
                truncated = true
                warnings.add("residual scan truncated after $MAX_INSPECTED entries")
                break
            }
            if (maxDepth <= 0) continue
            if (isKnownTrashDir(dir)) {
                inspected += inspectNested(dir, targetName, targetPath, candidates, warnings, maxDepth)
            }
        }

        return ScanResult(candidates.map { File(it) }, inspected, truncated, warnings)
    }

    private fun inspectDirectory(
        dir: File,
        targetName: String,
        targetPath: String,
        out: MutableSet<String>,
        warnings: MutableList<String>
    ): Int {
        val children = try {
            dir.listFiles()
        } catch (t: Throwable) {
            warnings.add("cannot list a scanned directory")
            return 0
        } ?: return 0

        var inspected = 0
        val inTrashDir = isKnownTrashDir(dir)
        for (child in children) {
            inspected++
            if (FsOps.isSymbolicLink(child)) continue
            if (child.isDirectory) continue
            val path = FsOps.canonicalPath(child)
            if (path == targetPath) continue
            if (matches(targetName, child.name, inTrashDir)) {
                out.add(path)
            }
        }
        return inspected
    }

    private fun inspectNested(
        dir: File,
        targetName: String,
        targetPath: String,
        out: MutableSet<String>,
        warnings: MutableList<String>,
        depth: Int
    ): Int {
        var inspected = 0
        val queue = ArrayDeque<Pair<File, Int>>()
        queue.addLast(dir to 0)
        while (queue.isNotEmpty()) {
            val (current, level) = queue.removeFirst()
            if (level >= depth) continue
            val children = try {
                current.listFiles()
            } catch (t: Throwable) {
                continue
            } ?: continue
            for (child in children) {
                inspected++
                if (inspected > MAX_INSPECTED) return inspected
                if (FsOps.isSymbolicLink(child)) continue
                if (child.isDirectory) {
                    queue.addLast(child to level + 1)
                    continue
                }
                val path = FsOps.canonicalPath(child)
                if (path == targetPath) continue
                if (matches(targetName, child.name, true)) out.add(path)
            }
        }
        return inspected
    }

    fun matches(targetName: String, candidateName: String, insideTrashDir: Boolean): Boolean {
        if (targetName.isEmpty()) return false
        if (candidateName == targetName) return insideTrashDir

        TRASH_PREFIX_REGEX.matchEntire(candidateName)?.let { match ->
            if (match.groupValues[2] == targetName) return true
        }

        val lowerCandidate = candidateName.lowercase(Locale.ROOT)
        val lowerTarget = targetName.lowercase(Locale.ROOT)

        if (lowerCandidate == ".$lowerTarget") return true

        if (RESIDUAL_SUFFIXES.any { lowerCandidate == lowerTarget + it || lowerCandidate == lowerTarget + it + "~" }) {
            return true
        }

        if (insideTrashDir) {
            val baseName = targetName.substringBeforeLast('.', targetName).lowercase(Locale.ROOT)
            if (baseName.length >= 4 && lowerCandidate == baseName) return true
            if (lowerCandidate.length > lowerTarget.length && lowerCandidate.startsWith(lowerTarget)) {
                val next = lowerCandidate[lowerTarget.length]
                if (next == '.' || next == '-' || next == '_' || next == ' ' ||
                    next == '~' || next == '(' || next == '+'
                ) {
                    return true
                }
            }
        }

        return false
    }

    private fun isKnownTrashDir(dir: File): Boolean =
        KNOWN_TRASH_DIR_NAMES.any { it.equals(dir.name, ignoreCase = true) }

    fun reasonFor(file: File, targetName: String): String {
        val name = file.name
        val parentName = file.parentFile?.name ?: ""
        return when {
            TRASH_PREFIX_REGEX.matches(name) -> "platform trash entry"
            isKnownTrashDir(file.parentFile ?: File("/")) -> "indexed in ($parentName)"
            name.startsWith(".") -> "hidden duplicate"
            else -> "residual copy of $targetName"
        }
    }

    data class SweepResult(
        val artifacts: List<ResidualArtifact>,
        val contentVerifiedPurged: Int,
        val reportedOnly: Int
    )

    fun sweepResiduals(
        files: List<File>,
        targetName: String,
        expected: ContentFingerprint?,
        rng: java.security.SecureRandom,
        cancel: CancellationToken
    ): SweepResult {
        if (files.isEmpty()) return SweepResult(emptyList(), 0, 0)
        val engine = OverwriteEngine(
            level = SanitizationLevel.QUICK,
            verifyMode = VerifyMode.FINAL_PASS,
            rng = rng
        )
        val artifacts = mutableListOf<ResidualArtifact>()
        var verifiedPurged = 0
        var reportedOnly = 0
        for (file in files) {
            if (cancel.isCancelled) break
            val length = if (file.isFile) file.length() else 0L
            val contentConfirmed = expected != null && expected.length > 0L &&
                ContentFingerprint.matches(file, expected)
            if (!contentConfirmed) {
                reportedOnly++
                artifacts.add(
                    ResidualArtifact(
                        path = file.absolutePath,
                        reason = reasonFor(file, targetName) +
                            "; name-similar only, content not confirmed, reported without deletion",
                        length = length,
                        purged = false
                    )
                )
                continue
            }
            var purged = false
            try {
                if (file.isFile) {
                    if (FsOps.setWritable(file)) {
                        FsOps.openReadWrite(file).use { channel ->
                            val spec = engine.passSpecs().first()
                            val generator = engine.newGenerator(spec)
                            val ok = engine.overwrite(channel, length, spec, generator, cancel) { }
                            val truncated = FsOps.truncateToZero(channel)
                            purged = ok || truncated
                        }
                    }
                }
                val renamed = FsOps.renameChain(file, 2, false, rng)
                purged = FsOps.unlink(renamed) || purged
                FsOps.syncDirectory(renamed.parentFile)
            } catch (t: Throwable) {
                SecureLog.w("residual purge failed: ${Sanitizer.of(t, file.absolutePath, file.name)}")
            }
            val gone = purged && !file.exists()
            if (gone) verifiedPurged++
            artifacts.add(
                ResidualArtifact(
                    path = file.absolutePath,
                    reason = reasonFor(file, targetName) + "; content-verified residual copy",
                    length = length,
                    purged = gone
                )
            )
        }
        SecureLog.i("residual sweep: verifiedPurged=$verifiedPurged reportedOnly=$reportedOnly")
        return SweepResult(artifacts, verifiedPurged, reportedOnly)
    }

    private const val MAX_INSPECTED = 20000
}
