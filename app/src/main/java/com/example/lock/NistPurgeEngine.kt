package com.example.lock

import android.content.Context
import android.net.Uri
import java.io.File
import java.io.RandomAccessFile
import java.security.SecureRandom
import java.util.Arrays

object NistPurgeEngine {

    fun sanitizeOriginalFile(context: Context, uri: Uri): Boolean {
        val path = uri.path ?: return false
        val targetFile = File(path)

        if (!targetFile.exists() || !targetFile.canWrite()) {
            return false
        }

        if (targetFile.isDirectory) {
            return targetFile.delete()
        }

        return try {
            val secureRandom = SecureRandom()
            val length = targetFile.length()
            if (length > 0) {
                overwriteContent(targetFile, length, secureRandom)
            }
            obfuscateFilenameAndDelete(targetFile, secureRandom)
        } catch (_: Exception) {
            false
        }
    }

    private fun overwriteContent(file: File, length: Long, secureRandom: SecureRandom) {
        val bufferSize = 64 * 1024
        val buffer = ByteArray(bufferSize)

        RandomAccessFile(file, "rw").use { raf ->
            val channel = raf.channel
            var bytesWritten = 0L

            raf.seek(0)
            while (bytesWritten < length) {
                secureRandom.nextBytes(buffer)
                val bytesToWrite = minOf(buffer.size.toLong(), length - bytesWritten).toInt()
                raf.write(buffer, 0, bytesToWrite)
                bytesWritten += bytesToWrite
            }

            channel.force(true)
            raf.fd.sync()

            raf.setLength(0)
            channel.force(true)
            raf.fd.sync()
        }

        Arrays.fill(buffer, 0.toByte())
    }

    private fun obfuscateFilenameAndDelete(file: File, secureRandom: SecureRandom): Boolean {
        var currentFile = file
        val parent = currentFile.parentFile ?: return currentFile.delete()

        for (i in 1..5) {
            val newName = generateRandomName(currentFile.name.length.coerceAtLeast(8), secureRandom)
            val renamedFile = File(parent, newName)
            if (currentFile.renameTo(renamedFile)) {
                currentFile = renamedFile
            }
        }

        return currentFile.delete()
    }

    private fun generateRandomName(length: Int, secureRandom: SecureRandom): String {
        val charPool = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        val sb = StringBuilder(length)
        for (i in 0 until length) {
            val randomIndex = secureRandom.nextInt(charPool.length)
            sb.append(charPool[randomIndex])
        }
        return sb.toString()
    }
}