package com.example.lock

import android.app.Activity
import android.content.Context
import android.os.Build
import java.io.File
import java.io.RandomAccessFile
import java.security.SecureRandom
import java.util.Arrays
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean

object SafeExit {

    private const val PURGE_BUFFER_SIZE = 64 * 1024          // 64 KiB write buffer
    private const val PURGE_TIME_BUDGET_MS = 6_000L          // hard deadline for file purge
    private const val EXIT_GRACE_MS = 250L                   // let window-close animation finish
    private const val RENAME_ROUNDS = 3                      // filename obfuscation rounds
    private const val RANDOM_NAME_LENGTH = 12

    private val FILE_NAME_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray()

    /** Prevents double execution when the button is tapped twice. */
    private val isExiting = AtomicBoolean(false)

    /** Files that must be purged on exit (registered by feature modules). */
    private val sensitiveFiles = Collections.synchronizedSet(HashSet<File>())

    /** Cleanup callbacks contributed by feature modules (DB, Keystore, engines...). */
    private val exitHooks = Collections.synchronizedList(ArrayList<() -> Unit>())

    /**
     * Anti-dead-code-elimination sink. Reading the wiped buffer back and storing
     * the result in a @Volatile field makes it far harder for the ART/JIT
     * compiler to elide the fill operation.
     */
    @Volatile
    private var sink: Int = 0

    /** Register a file (or any path) that must be securely purged on Safe Exit. */
    @JvmStatic
    fun registerSensitiveFile(file: File) {
        sensitiveFiles.add(file.absoluteFile)
    }

    @JvmStatic
    fun registerSensitiveFile(path: String) {
        sensitiveFiles.add(File(path).absoluteFile)
    }

    /**
     * Register a cleanup callback executed during Safe Exit, BEFORE file purge.
     * Use for: cancelling coroutine scopes, checkpointing/closing databases,
     * destroying Keystore keys (crypto-erase), wiping static holders, etc.
     */
    @JvmStatic
    fun addExitHook(hook: () -> Unit) {
        exitHooks.add(hook)
    }

    @JvmStatic
    fun wipe(bytes: ByteArray?) = wipeBytes(bytes)

    @JvmStatic
    fun wipe(chars: CharArray?) = wipeChars(chars)

    @JvmStatic
    fun wipeBytes(vararg arrays: ByteArray?) {
        for (a in arrays) {
            if (a == null || a.isEmpty()) continue
            Arrays.fill(a, 0.toByte())
            var v = 0
            for (b in a) v = v or b.toInt()   // touch every byte, defeat fill-elision
            sink = v
        }
    }

    @JvmStatic
    fun wipeChars(vararg arrays: CharArray?) {
        for (a in arrays) {
            if (a == null || a.isEmpty()) continue
            Arrays.fill(a, '\u0000')
            var v = 0
            for (c in a) v = v or c.code
            sink = v
        }
    }

    @JvmStatic
    fun performSafeExit(
        activity: Activity,
        sensitiveByteArrays: Array<ByteArray?> = emptyArray(),
        sensitiveCharArrays: Array<CharArray?> = emptyArray()
    ) {
        if (!isExiting.compareAndSet(false, true)) return

        val appContext = activity.applicationContext

        wipeChars(*sensitiveCharArrays)
        wipeBytes(*sensitiveByteArrays)

        activity.runOnUiThread {
            try {
                activity.finishAffinity()
            } catch (_: Exception) {
            }
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    activity.finishAndRemoveTask()
                }
            } catch (_: Exception) {
            }
        }

        Thread {
            try {
                // 3a) Feature-module cleanups: DB checkpoint+close, Keystore key
                //     destruction (crypto-erase), coroutine cancel, static holders.
                runExitHooks()

                // 3b) Flash purge: registered files + cache directories.
                purgeVolatileFiles(appContext)

                // 3c) Best-effort hint: drop unreferenced objects before dying.
                System.gc()
                System.runFinalization()

                // 3d) Small grace so the window-close animation completes cleanly.
                Thread.sleep(EXIT_GRACE_MS)
            } catch (_: Throwable) {
                // Never let cleanup errors block process termination.
            } finally {
                // ---- Phase 4: the definitive RAM wipe. ----------------------------
                // killProcess returns every page of this app to the kernel.
                killProcess()
            }
        }.start()
    }

    @JvmStatic
    fun securePurgeFile(file: File): Boolean {
        return try {
            if (!file.exists()) return true
            if (file.isDirectory) return purgeDirectory(file, Long.MAX_VALUE) <= 0
            if (!file.canWrite()) return file.delete()

            val length = file.length()
            if (length > 0L) {
                RandomAccessFile(file, "rws").use { raf ->
                    val zeros = ByteArray(PURGE_BUFFER_SIZE)
                    var pos = 0L
                    while (pos < length) {
                        val chunk = minOf(zeros.size.toLong(), length - pos).toInt()
                        raf.write(zeros, 0, chunk)
                        pos += chunk
                    }
                    raf.fd.sync()
                    raf.setLength(0L)
                    raf.fd.sync()
                }
            }
            obfuscateNameAndDelete(file)
        } catch (_: Exception) {
            file.delete()
        }
    }

    private fun runExitHooks() {
        val hooks = synchronized(exitHooks) { exitHooks.toList() }
        for (hook in hooks) {
            try {
                hook()
            } catch (_: Throwable) {
            }
        }
    }

    private fun purgeVolatileFiles(context: Context) {
        val targets = LinkedHashSet<File>()
        synchronized(sensitiveFiles) { targets.addAll(sensitiveFiles) }

        context.cacheDir?.let { targets.add(it) }
        context.externalCacheDir?.let { targets.add(it) }

        val deadline = System.currentTimeMillis() + PURGE_TIME_BUDGET_MS
        for (target in targets) {
            purgeRecursively(target, deadline)
        }
        sensitiveFiles.clear()
    }

    private fun purgeRecursively(target: File, deadline: Long): Int {
        var failures = 0
        try {
            if (!target.exists()) return 0

            if (target.isDirectory) {
                target.listFiles()?.forEach { child ->
                    failures += purgeRecursively(child, deadline)
                }
                if (!target.delete()) failures++
                return failures
            }

            if (System.currentTimeMillis() < deadline) {
                if (!securePurgeFile(target)) failures++
            } else {
                if (!target.delete()) failures++
            }
        } catch (_: Exception) {
            try {
                target.delete()
            } catch (_: Exception) {
            }
            failures++
        }
        return failures
    }

    private fun purgeDirectory(dir: File, deadline: Long): Int = purgeRecursively(dir, deadline)

    private fun obfuscateNameAndDelete(file: File): Boolean {
        val rng = SecureRandom()
        var current = file
        val parent = current.parentFile

        if (parent != null && parent.canWrite()) {
            repeat(RENAME_ROUNDS) {
                val candidate = File(parent, randomName(rng))
                if (current.renameTo(candidate)) current = candidate
            }
        }
        return current.delete()
    }

    private fun randomName(rng: SecureRandom): String {
        val sb = StringBuilder(RANDOM_NAME_LENGTH)
        repeat(RANDOM_NAME_LENGTH) { sb.append(FILE_NAME_ALPHABET[rng.nextInt(FILE_NAME_ALPHABET.size)]) }
        return sb.toString()
    }

    private fun killProcess() {
        try {
            android.os.Process.killProcess(android.os.Process.myPid())
        } catch (_: Throwable) {
        }
        try {
            System.exit(0)
        } catch (_: Throwable) {
        }
    }
}