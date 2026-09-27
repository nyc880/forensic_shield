package com.example.lock

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.example.lock.ProcessingActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class CryptoForegroundService : Service() {

    companion object {
        private const val CHANNEL_ID = "lock_crypto_channel"
        private const val CHANNEL_NAME = "Encryption Service"
        private const val NOTIFICATION_ID = 4101
        private const val ACTION_STOP = "com.example.lock.action.STOP_CRYPTO_WORK"
        private const val WAKELOCK_TIMEOUT_MS = 3 * 60 * 60 * 1000L
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private var progressJob: Job? = null
    private var statusJob: Job? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var lastPercent = -1
    private var started = false

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            CryptoWorkState.requestCancel()
            return START_NOT_STICKY
        }

        if (CryptoWorkState.status.value != CryptoWorkState.Status.RUNNING) {
            stopSelf()
            return START_NOT_STICKY
        }

        if (!started) {
            started = true
            startForegroundCompat(buildProgressNotification(CryptoWorkState.progress.value))
            acquireWakeLock()
            observeWork()
        }

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        progressJob?.cancel()
        statusJob?.cancel()
        serviceScope.cancel()
        releaseWakeLock()
        super.onDestroy()
    }

    private fun observeWork() {
        progressJob = serviceScope.launch {
            CryptoWorkState.progress.collect { percent ->
                if (percent != lastPercent) {
                    lastPercent = percent
                    notifyProgress(percent)
                }
            }
        }
        statusJob = serviceScope.launch {
            CryptoWorkState.status.collect { status ->
                if (status != CryptoWorkState.Status.RUNNING) finish(status)
            }
        }
    }

    private fun finish(status: CryptoWorkState.Status) {
        releaseWakeLock()
        val text = when (status) {
            CryptoWorkState.Status.SUCCEEDED -> "100% — completed"
            CryptoWorkState.Status.FAILED -> "Failed: ${CryptoWorkState.message.value}"
            else -> "Cancelled"
        }
        notifyFinal(text)
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun notifyProgress(percent: Int) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildProgressNotification(percent))
    }

    private fun notifyFinal(text: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildFinalNotification(text))
    }

    private fun buildProgressNotification(percent: Int): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle("Lock")
            .setContentText("$percent%")
            .setProgress(100, percent, false)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(contentIntent())
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Stop",
                stopIntent()
            )
            .build()
    }

    private fun buildFinalNotification(text: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle("Lock")
            .setContentText(text)
            .setProgress(0, 0, false)
            .setOngoing(false)
            .setAutoCancel(true)
            .setContentIntent(contentIntent())
            .build()
    }

    private fun pendingFlags(): Int {
        var flags = PendingIntent.FLAG_UPDATE_CURRENT
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags = flags or PendingIntent.FLAG_IMMUTABLE
        }
        return flags
    }

    private fun contentIntent(): PendingIntent {
        val intent = Intent(this, ProcessingActivity::class.java)
        intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        return PendingIntent.getActivity(this, 2, intent, pendingFlags())
    }

    private fun stopIntent(): PendingIntent {
        val intent = Intent(this, CryptoForegroundService::class.java)
        intent.action = ACTION_STOP
        return PendingIntent.getService(this, 1, intent, pendingFlags())
    }

    private fun startForegroundCompat(notification: Notification) {
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            notification,
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
        )
    }

    private fun acquireWakeLock() {
        if (wakeLock != null) return
        val manager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = manager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "lock:CryptoWork").apply {
            setReferenceCounted(false)
            acquire(WAKELOCK_TIMEOUT_MS)
        }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) wakeLock?.release()
        } catch (_: Throwable) {
        }
        wakeLock = null
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            CHANNEL_NAME,
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            setSound(null, null)
            enableVibration(false)
        }
        manager.createNotificationChannel(channel)
    }
}
