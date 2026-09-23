package com.example.lock.safe_delete

import android.os.StatFs
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.security.SecureRandom

data class FsInfo(
    val fsType: String,
    val mountPoint: String,
    val hasDiscardOption: Boolean,
    val readOnly: Boolean,
    val backingFsType: String? = null,
    val backingMountPoint: String? = null,
    val discardKnown: Boolean = false
) {
    val effectiveFsType: String get() = backingFsType ?: fsType
    val effectiveMountPoint: String get() = backingMountPoint ?: mountPoint
}

data class DirectoryScrubResult(
    val filesCreated: Int,
    val filesRemoved: Int,
    val ok: Boolean
)

internal object FsOps {

    const val MODE_OWNER_READ_WRITE: Int = 0b110000000

    fun openReadWrite(file: File): FileChannel = FileChannel.open(
        file.toPath(),
        StandardOpenOption.READ,
        StandardOpenOption.WRITE
    )

    fun openReadOnly(file: File): FileChannel = FileChannel.open(
        file.toPath(),
        StandardOpenOption.READ
    )

    fun canOpenReadWrite(file: File): Boolean = try {
        openReadWrite(file).use { }
        true
    } catch (t: Throwable) {
        false
    }

    fun force(channel: FileChannel): Boolean = try {
        channel.force(true)
        true
    } catch (t: Throwable) {
        SecureLog.w("fsync failed: ${t.message}")
        false
    }

    fun adviseDontNeed(file: File) {
        if (!file.exists()) return
        try {
            val osClass = Class.forName("android.system.Os")
            val method = osClass.getMethod(
                "posix_fadvise",
                java.io.FileDescriptor::class.java,
                java.lang.Long.TYPE,
                java.lang.Long.TYPE,
                java.lang.Integer.TYPE
            )
            RandomAccessFile(file, "rw").use { raf ->
                method.invoke(null, raf.fd, 0L, 0L, SecureDeleteConfig.FADVISE_DONTNEED)
            }
        } catch (t: Throwable) {
            SecureLog.d("fadvise skipped: ${t.message}")
        }
    }

    fun syncDirectory(directory: File?): Boolean {
        val dir = directory ?: return false
        if (!dir.exists() || !dir.isDirectory) return false

        try {
            val fd = Os.open(dir.absolutePath, OsConstants.O_RDONLY, 0)
            try {
                Os.fsync(fd)
                return true
            } finally {
                try {
                    Os.close(fd)
                } catch (ignored: Throwable) {
                }
            }
        } catch (t: Throwable) {
            SecureLog.d("directory sync via Os failed: ${t.message}")
        }

        return try {
            FileChannel.open(dir.toPath(), StandardOpenOption.READ).use { it.force(true) }
            true
        } catch (t: Throwable) {
            SecureLog.w("directory sync failed: ${Sanitizer.of(t)}")
            false
        }
    }

    fun setWritable(file: File): Boolean {
        if (file.canWrite()) return true
        try {
            Os.chmod(file.absolutePath, MODE_OWNER_READ_WRITE)
        } catch (t: Throwable) {
            SecureLog.d("chmod failed: ${Sanitizer.of(t)}")
        }
        try {
            file.setWritable(true, false)
        } catch (ignored: Throwable) {
        }
        return file.canWrite()
    }

    fun isSymbolicLink(file: File): Boolean = try {
        Files.isSymbolicLink(file.toPath())
    } catch (t: Throwable) {
        false
    }

    fun linkCount(file: File): Int = try {
        val count = Files.getAttribute(file.toPath(), "unix:nlink")
        (count as? Number)?.toInt() ?: 1
    } catch (t: Throwable) {
        1
    }

    fun isRegularFile(file: File): Boolean = try {
        Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)
    } catch (t: Throwable) {
        file.isFile
    }

    fun unlink(file: File): Boolean {
        val path = file.toPath()
        if (isSymbolicLink(file)) {
            return try {
                Files.deleteIfExists(path)
                !Files.exists(path, LinkOption.NOFOLLOW_LINKS)
            } catch (t: Throwable) {
                SecureLog.w("symlink removal failed: ${Sanitizer.of(t)}")
                false
            }
        }
        repeat(SecureDeleteConfig.UNLINK_RETRY_ATTEMPTS) { attempt ->
            if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return true
            if (file.delete()) return true
            setWritable(file)
            if (attempt > 0) {
                try {
                    RandomAccessFile(file, "rw").use { it.setLength(0L) }
                } catch (ignored: Throwable) {
                }
            }
        }
        return !Files.exists(path, LinkOption.NOFOLLOW_LINKS)
    }

    fun canonicalPath(file: File): String = try {
        file.canonicalPath
    } catch (t: Throwable) {
        file.absolutePath
    }

    fun fsInfoFor(path: File): FsInfo {
        val target = canonicalPath(path)
        val surface = parseMountFor(target) ?: return FsInfo("unknown", "/", false, false, null, null, false)

        if (surface.fsType.lowercase(java.util.Locale.ROOT) in FUSE_LIKE_FS_TYPES) {
            if (!isSharedStoragePath(target)) {
                return surface.copy(discardKnown = false)
            }
            val dataDir = try {
                android.os.Environment.getDataDirectory()
            } catch (t: Throwable) {
                null
            }
            if (dataDir != null) {
                val backing = parseMountFor(canonicalPath(dataDir))
                if (backing != null && backing.fsType.lowercase(java.util.Locale.ROOT) !in FUSE_LIKE_FS_TYPES) {
                    return surface.copy(
                        hasDiscardOption = backing.hasDiscardOption,
                        readOnly = surface.readOnly || backing.readOnly,
                        backingFsType = backing.fsType,
                        backingMountPoint = backing.mountPoint,
                        discardKnown = true
                    )
                }
            }
            return surface.copy(discardKnown = false)
        }

        return surface.copy(discardKnown = true)
    }

    private fun isSharedStoragePath(canonicalTarget: String): Boolean =
        canonicalTarget.startsWith("/storage/emulated/") ||
            canonicalTarget == "/storage/emulated" ||
            canonicalTarget.startsWith("/sdcard/") ||
            canonicalTarget == "/sdcard"

    private val FUSE_LIKE_FS_TYPES = setOf("fuse", "fuseblk", "sdcardfs", "esdfs")

    private fun parseMountFor(target: String): FsInfo? {
        var best: FsInfo? = null
        var bestLength = -1

        try {
            File(SecureDeleteConfig.KERNEL_MOUNT_INFO_PATH).forEachLine { line ->
                val parts = line.split(' ')
                if (parts.size < 4) return@forEachLine
                val mountPoint = unescapeMountPath(parts[1])
                val fsType = parts[2]
                val options = parts[3]
                val isWithin = target == mountPoint || target.startsWith(
                    if (mountPoint.endsWith("/")) mountPoint else "$mountPoint/"
                )
                if (isWithin && mountPoint.length > bestLength) {
                    bestLength = mountPoint.length
                    best = FsInfo(
                        fsType = fsType,
                        mountPoint = mountPoint,
                        hasDiscardOption = options.split(',').contains("discard"),
                        readOnly = options.split(',').contains("ro")
                    )
                }
            }
        } catch (t: Throwable) {
            SecureLog.w("mount table read failed: ${Sanitizer.of(t)}")
        }

        return best
    }

    private fun unescapeMountPath(raw: String): String =
        raw.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n")

    fun availableBytes(directory: File): Long = try {
        StatFs(directory.absolutePath).availableBytes
    } catch (t: Throwable) {
        directory.usableSpace
    }

    fun totalBytes(directory: File): Long = try {
        StatFs(directory.absolutePath).totalBytes
    } catch (t: Throwable) {
        directory.totalSpace
    }

    fun spaceHeadroom(directory: File): Long {
        val available = availableBytes(directory)
        return (available - SecureDeleteConfig.PRESSURE_RESERVE_BYTES).coerceAtLeast(0L)
    }

    fun renameChain(
        start: File,
        rounds: Int,
        syncEachRename: Boolean,
        rng: SecureRandom
    ): File {
        var current = start
        if (rounds <= 0) return current
        val parent = current.parentFile ?: return current

        repeat(rounds) {
            val name = Digest.randomHex(SecureDeleteConfig.RENAME_SUFFIX_BYTES, rng) + ".dat"
            val candidate = File(parent, name)
            val renamed = try {
                current.renameTo(candidate)
            } catch (t: Throwable) {
                false
            }
            if (renamed) {
                current = candidate
                if (syncEachRename) syncDirectory(parent)
            }
        }
        return current
    }

    fun truncateToZero(channel: FileChannel): Boolean = try {
        channel.truncate(0L)
        channel.force(true)
        true
    } catch (t: Throwable) {
        SecureLog.w("truncate failed: ${t.message}")
        false
    }

    fun scrubDirectoryEntries(
        directory: File,
        rounds: Int,
        filesPerRound: Int,
        rng: SecureRandom
    ): DirectoryScrubResult {
        if (rounds <= 0 || filesPerRound <= 0) return DirectoryScrubResult(0, 0, false)
        var created = 0
        var removed = 0
        var ok = true
        if (!directory.exists() || !directory.isDirectory || !directory.canWrite()) {
            return DirectoryScrubResult(0, 0, false)
        }

        val buffer = ByteArray(SecureDeleteConfig.PATTERN_BLOCK_BYTES)
        repeat(rounds) {
            val batch = ArrayList<File>(filesPerRound)
            repeat(filesPerRound) {
                val name = "." + Digest.randomHex(8, rng)
                val file = File(directory, name)
                try {
                    FileOutputStream(file).use { stream ->
                        rng.nextBytes(buffer)
                        stream.write(buffer)
                        stream.flush()
                        stream.fd.sync()
                    }
                    created++
                    batch.add(file)
                } catch (t: Throwable) {
                    ok = false
                }
            }
            batch.forEach { file ->
                if (file.delete()) removed++
            }
        }
        Zeroize.bytes(buffer)
        syncDirectory(directory)
        return DirectoryScrubResult(created, removed, ok && created == removed)
    }

    fun writeRandomMass(
        directory: File,
        bytes: Long,
        chunkBytes: Int,
        fileCountMax: Int,
        rng: SecureRandom,
        cancel: CancellationToken,
        onProgress: (Long) -> Unit = {}
    ): Long {
        if (bytes <= 0L) return 0L
        val files = fileCountMax.coerceAtLeast(1)
        val perFile = bytes / files
        var remainder = bytes % files
        var written = 0L

        val buffer = ByteArray(chunkBytes.coerceAtLeast(SecureDeleteConfig.PATTERN_BLOCK_BYTES))

        for (index in 0 until files) {
            if (cancel.isCancelled) break
            var remaining = perFile + if (remainder > 0) {
                remainder--
                1L
            } else {
                0L
            }
            if (remaining <= 0L) continue

            val file = File(directory, "." + Digest.randomHex(10, rng))
            try {
                FileOutputStream(file).use { stream ->
                    while (remaining > 0L && !cancel.isCancelled) {
                        rng.nextBytes(buffer)
                        val size = minOf(buffer.size.toLong(), remaining).toInt()
                        stream.write(buffer, 0, size)
                        remaining -= size
                        written += size
                        onProgress(written)
                    }
                    stream.flush()
                    stream.fd.sync()
                }
            } catch (t: Throwable) {
                SecureLog.w("pressure write failed: ${t.message}")
            } finally {
                adviseDontNeed(file)
                if (!unlink(file)) {
                    SecureLog.w("pressure file could not be removed")
                }
            }
        }

        Zeroize.bytes(buffer)
        syncDirectory(directory)
        return written
    }
}
