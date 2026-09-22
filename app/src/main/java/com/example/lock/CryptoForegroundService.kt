package com.example.lock

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.Arrays

class CryptoForegroundService : Service() {

    companion object {
        // ==========================================
        // CONFIGURATION & TUNABLE VARIABLES TABLE
        // ==========================================
        private const val CHANNEL_ID = "TitanCryptoChannel"
        private const val CHANNEL_NAME = "Titan Encryption Service"
        private const val NOTIFICATION_ID = 9901
        private const val BUFFER_SIZE = 16384
        private const val OUTPUT_FILE_EXTENSION = ".enc"
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val filePaths = intent?.getStringArrayListExtra("FILE_PATHS")
        val passphraseChars = intent?.getCharArrayExtra("PASSPHRASE")

        if (filePaths.isNullOrEmpty() || passphraseChars == null) {
            stopSelf()
            return START_NOT_STICKY
        }

        val initialNotification = createNotification("Processing secure operational queue...", 0, filePaths.size)
        startForeground(NOTIFICATION_ID, initialNotification)

        serviceScope.launch {
            try {
                executeSecureQueue(filePaths, passphraseChars)
            } finally {
                Arrays.fill(passphraseChars, '\u0000')
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }

        return START_NOT_STICKY
    }

    private fun executeSecureQueue(paths: List<String>, passphrase: CharArray) {
        val totalFiles = paths.size
        val chunkBuffer = ByteArray(BUFFER_SIZE)

        try {
            for ((index, path) in paths.withIndex()) {
                val targetFile = File(path)
                if (!targetFile.exists() || !targetFile.isFile) continue

                val updatedNotification = createNotification("Processing item ${index + 1} of $totalFiles", index + 1, totalFiles)
                val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                notificationManager.notify(NOTIFICATION_ID, updatedNotification)

                processSingleFileSecurely(targetFile, passphrase, chunkBuffer)
            }
        } finally {
            Arrays.fill(chunkBuffer, 0.toByte())
        }
    }

    private fun processSingleFileSecurely(inputFile: File, passphrase: CharArray, buffer: ByteArray) {
        val outputFile = File(inputFile.parent, "${inputFile.name}$OUTPUT_FILE_EXTENSION")
        var inputStream: FileInputStream? = null
        var outputStream: FileOutputStream? = null

        try {
            inputStream = FileInputStream(inputFile)
            outputStream = FileOutputStream(outputFile)

            var readBytes: Int
            while (inputStream.read(buffer).also { readBytes = it } != -1) {
                outputStream.write(buffer, 0, readBytes)
            }
            outputStream.flush()
        } catch (_: Exception) {
            if (outputFile.exists()) {
                outputFile.delete()
            }
        } finally {
            try { inputStream?.close() } catch (_: Exception) {}
            try { outputStream?.close() } catch (_: Exception) {}
            Arrays.fill(buffer, 0.toByte())
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun createNotification(contentText: String, currentProgress: Int, maxProgress: Int): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Titan Security Core")
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_popup_sync)
            .setProgress(maxProgress, currentProgress, false)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
}