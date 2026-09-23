package com.example.lock.safe_delete

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.ServiceInfo
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.database.Cursor
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.example.lock.MainActivity
import com.example.lock.R
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File
import java.util.Locale
import kotlin.math.roundToInt

internal data class PurgeProgress(
    val label: String,
    val finishedTargets: Int,
    val totalTargets: Int,
    val perMille: Int,
    val running: Boolean,
    val bytesDestroyed: Long,
    val report: SessionReport?
)

internal object PurgeRuntime {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Any()
    private val observers = LinkedHashSet<(PurgeProgress) -> Unit>()

    private var job: Job? = null
    private var token: AtomicCancellationToken? = null
    private var progress = PurgeProgress("idle", 0, 0, 0, false, 0L, null)

    fun isRunning(): Boolean = synchronized(lock) { job?.isActive == true }

    fun snapshot(): PurgeProgress = synchronized(lock) { progress }

    fun observe(observer: (PurgeProgress) -> Unit) {
        synchronized(lock) { observers.add(observer) }
        observer(snapshot())
    }

    fun unobserve(observer: (PurgeProgress) -> Unit) {
        synchronized(lock) { observers.remove(observer) }
    }

    fun cancel() {
        synchronized(lock) { token?.cancel() }
    }

    fun forgetFinished() {
        synchronized(lock) {
            if (job?.isActive == true) return
            progress = PurgeProgress("idle", 0, 0, 0, false, 0L, null)
        }
    }

    fun start(context: Context, targets: List<DeleteTarget>, options: PurgeOptions) {
        val fresh = AtomicCancellationToken()
        val appContext = context.applicationContext
        synchronized(lock) {
            if (job?.isActive == true) return
            token = fresh
            progress = PurgeProgress("preparing", 0, targets.size, 0, true, 0L, null)
            job = scope.launch {
                val listener = object : ProgressListener {
                    override fun onTargetStart(target: DeleteTarget, index: Int, total: Int) {
                        emit { current ->
                            current.copy(
                                label = "shredding ${target.displayName}",
                                totalTargets = total,
                                running = true
                            )
                        }
                    }

                    override fun onStage(
                        stage: DeletionStage,
                        label: String,
                        processedBytes: Long,
                        totalBytes: Long
                    ) {
                        val fraction = if (totalBytes > 0L) {
                            processedBytes.toDouble() / totalBytes.toDouble()
                        } else {
                            0.0
                        }
                        emit { current ->
                            current.copy(label = label, perMille = perMilleOf(current, fraction), running = true)
                        }
                    }

                    override fun onTargetFinished(report: TargetReport) {
                        emit { current ->
                            val done = current.finishedTargets + 1
                            val fraction = if (current.totalTargets <= 0) {
                                1.0
                            } else {
                                done.toDouble() / current.totalTargets.toDouble()
                            }
                            current.copy(
                                label = "finished ${report.target.displayName}",
                                finishedTargets = done,
                                perMille = (fraction * 1000.0).roundToInt().coerceIn(0, 1000),
                                bytesDestroyed = current.bytesDestroyed + report.bytesOverwritten,
                                running = true
                            )
                        }
                    }
                }

                val report = try {
                    SecureDelete.purge(
                        context = appContext,
                        targets = targets,
                        options = options,
                        listener = listener,
                        cancel = fresh
                    )
                } catch (t: Throwable) {
                    SecureLog.e("purge session failed", t)
                    null
                }

                emit { current ->
                    current.copy(
                        label = when {
                            report == null -> "failed"
                            report.cancelled -> "cancelled"
                            else -> "done"
                        },
                        perMille = if (report == null) current.perMille else 1000,
                        running = false,
                        report = report
                    )
                }
            }
        }
    }

    private fun perMilleOf(current: PurgeProgress, fraction: Double): Int {
        val overall = if (current.totalTargets <= 0) {
            0.0
        } else {
            (current.finishedTargets + fraction.coerceIn(0.0, 1.0)) / current.totalTargets.toDouble()
        }
        return (overall * 1000.0).roundToInt().coerceIn(0, 1000)
    }

    private fun emit(update: (PurgeProgress) -> PurgeProgress) {
        val callbacks: List<(PurgeProgress) -> Unit>
        val value: PurgeProgress
        synchronized(lock) {
            value = update(progress)
            progress = value
            callbacks = observers.toList()
        }
        callbacks.forEach { callback ->
            try {
                callback(value)
            } catch (t: Throwable) {
                SecureLog.w("progress observer failed: ${t.message}")
            }
        }
    }
}

class SafeDeleteActivity : AppCompatActivity() {

    private var progressBar: ProgressBar? = null
    private var statusText: TextView? = null
    private var percentText: TextView? = null
    private var stageText: TextView? = null
    private var btnDone: MaterialButton? = null

    private var options = PurgeOptions.MILITARY

    @Volatile
    private var renderScheduled = false

    private var deepCleanScheduled = false

    private val observer: (PurgeProgress) -> Unit = {
        if (!renderScheduled) {
            renderScheduled = true
            runOnUiThread {
                renderScheduled = false
                render(PurgeRuntime.snapshot())
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_processing)

        progressBar = findViewById(R.id.progressBar)
        statusText = findViewById(R.id.statusText)
        percentText = findViewById(R.id.percentText)
        stageText = findViewById(R.id.stageText)
        btnDone = findViewById(R.id.btnDone)

        SecureDelete.onAppStart(this)

        options = buildOptions()
        val paths = intent.getStringArrayListExtra(EXTRA_SELECTED_FILES) ?: arrayListOf()
        val uris = intent.getStringArrayListExtra(EXTRA_SELECTED_URIS) ?: arrayListOf()
        val targets = buildTargets(paths, uris)

        setInitialState(targets.size)

        btnDone?.setOnClickListener {
            val mainIntent = Intent(this, MainActivity::class.java)
            mainIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            startActivity(mainIntent)
            finish()
        }

        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    if (PurgeRuntime.isRunning()) {
                        PurgeRuntime.cancel()
                        stageText?.text = "cancelling after the current pass"
                    } else {
                        finish()
                    }
                }
            }
        )

        if (savedInstanceState == null) {
            PurgeRuntime.forgetFinished()
            if (targets.isNotEmpty() && !PurgeRuntime.isRunning()) {
                PurgeRuntime.start(this, targets, options)
            } else if (targets.isEmpty()) {
                showResult(emptyReport(options), options)
            }
        }

        PurgeRuntime.observe(observer)
    }

    private fun buildTargets(paths: List<String>, uris: List<String>): List<DeleteTarget> {
        val targets = ArrayList<DeleteTarget>(paths.size + uris.size)
        paths.forEach { path -> targets.add(DeleteTarget.ofPath(path)) }
        uris.forEach { value ->
            val uri = runCatching { Uri.parse(value) }.getOrNull()
            if (uri != null) targets.add(DeleteTarget.ofUri(this, uri))
        }
        return targets
    }

    private fun buildOptions(): PurgeOptions {
        val base = PurgeOptions.MILITARY
        val levelName = intent.getStringExtra(EXTRA_LEVEL)
        val level = runCatching {
            SanitizationLevel.valueOf(levelName ?: base.level.name)
        }.getOrDefault(base.level)

        val verifyName = intent.getStringExtra(EXTRA_VERIFY_MODE)
        val verifyMode = runCatching {
            VerifyMode.valueOf(verifyName ?: base.verifyMode.name)
        }.getOrDefault(base.verifyMode)

        return base.copy(
            level = level,
            verifyMode = verifyMode,
            extendToEraseBoundary = intent.getBooleanExtra(EXTRA_EXTEND, base.extendToEraseBoundary),
            deepClean = intent.getBooleanExtra(EXTRA_DEEP_CLEAN, base.deepClean),
            purgeThumbnails = intent.getBooleanExtra(EXTRA_THUMBNAILS, base.purgeThumbnails),
            eraseMediaStoreRows = intent.getBooleanExtra(EXTRA_METADATA, base.eraseMediaStoreRows)
        )
    }

    private fun setInitialState(targetCount: Int) {
        progressBar?.apply {
            visibility = View.VISIBLE
            isIndeterminate = false
            max = 1000
            progress = 0
        }
        btnDone?.visibility = View.GONE
        stageText?.visibility = View.VISIBLE
        percentText?.visibility = View.VISIBLE
        percentText?.text = "0%"
        statusText?.setTextColor(Color.parseColor("#FF1744"))
        statusText?.text = "Secure Deleting..."
        stageText?.text = "queued $targetCount target(s)"
    }

    private fun render(snapshot: PurgeProgress) {
        val report = snapshot.report
        if (report != null) {
            showResult(report, options)
            return
        }
        progressBar?.visibility = View.VISIBLE
        progressBar?.progress = snapshot.perMille
        percentText?.text = "${(snapshot.perMille / 10.0).roundToInt()}%"
        stageText?.text = snapshot.label
        statusText?.text = if (snapshot.totalTargets > 0) {
            "Securely destroying ${snapshot.finishedTargets}/${snapshot.totalTargets}"
        } else {
            "Securely destroying"
        }
    }

    private fun emptyReport(options: PurgeOptions) = SessionReport(
        reports = emptyList(),
        totalBytesShredded = 0L,
        totalElapsedMs = 0L,
        cancelled = false,
        level = options.level,
        verifyMode = options.verifyMode,
        pressureBytes = 0L
    )

    private fun showResult(report: SessionReport, options: PurgeOptions) {
        progressBar?.visibility = View.GONE
        percentText?.text = "100%"
        val pending = report.pendingTargets
        val weak = report.weakTargets
        val sizeText = formatBytes(report.totalBytesShredded)

        if (report.deepCleanPending && !deepCleanScheduled) {
            deepCleanScheduled = true
            DeepCleanScheduler.ensureScheduled(this)
        }

        val deepCleanText = when {
            report.deepCleanExecuted -> "deepClean=${formatBytes(report.pressureBytes)} churned"
            report.deepCleanPending -> "deepClean=scheduled, runs while charging"
            else -> "deepClean=off"
        }

        val degraded = report.failedTargets.filter { it.gone && !it.alreadyAbsent && !it.weakDeletion }
        val removedCount = report.reports.count { it.gone }

        when {
            report.cancelled || pending.isNotEmpty() -> {
                statusText?.setTextColor(Color.parseColor("#FF3D00"))
                statusText?.text = if (report.cancelled) "Cancelled" else "Completed with pending items"
                val names = pending.take(5).joinToString(", ") { it.target.displayName }
                val extra = if (pending.size > 5) " (+${pending.size - 5} more)" else ""
                stageText?.text = "$removedCount removed, ${pending.size} pending: $names$extra\n" +
                    OUT_OF_SCOPE_NOTE
            }

            report.assurance == AssuranceLevel.WEAK || weak.isNotEmpty() || degraded.isNotEmpty() -> {
                statusText?.setTextColor(Color.parseColor("#FFC400"))
                statusText?.text = when {
                    degraded.isNotEmpty() && weak.isEmpty() ->
                        "Deletion completed with failed stages - review details"

                    weak.isNotEmpty() && degraded.isEmpty() ->
                        "Weak deletion - removed without verified overwrite"

                    else -> "Weak deletion - review details"
                }
                val names = (weak + degraded).take(5).joinToString(", ") { it.target.displayName }
                val extra = if (weak.size + degraded.size > 5) " (+${weak.size + degraded.size - 5} more)" else ""
                stageText?.text = "${report.successCount} fully destroyed, $removedCount removed, " +
                    "${weak.size} weak, ${degraded.size} with failed stages: $names$extra, " +
                    "$sizeText overwritten, $deepCleanText\n" + OUT_OF_SCOPE_NOTE
            }

            else -> {
                statusText?.setTextColor(Color.parseColor("#00E676"))
                statusText?.text = "Deletion completed"
                stageText?.text = ""
            }
        }
        btnDone?.visibility = View.VISIBLE
        btnDone?.text = if (pending.isEmpty()) "DONE" else "REVIEW"
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024L) return "$bytes B"
        val units = listOf("KiB", "MiB", "GiB", "TiB")
        var value = bytes.toDouble() / 1024.0
        var index = 0
        while (value >= 1024.0 && index < units.lastIndex) {
            value /= 1024.0
            index++
        }
        return String.format(Locale.US, "%.2f %s", value, units[index])
    }

    override fun onDestroy() {
        PurgeRuntime.unobserve(observer)
        if (isFinishing && !isChangingConfigurations) {
            PurgeRuntime.forgetFinished()
        }
        super.onDestroy()
    }

    companion object {
        const val EXTRA_SELECTED_FILES = "SELECTED_FILES"
        const val EXTRA_SELECTED_URIS = "SELECTED_URIS"
        const val EXTRA_LEVEL = "SANITIZATION_LEVEL"
        const val EXTRA_VERIFY_MODE = "VERIFY_MODE"
        const val EXTRA_EXTEND = "EXTEND_TO_ERASE_BOUNDARY"
        const val EXTRA_DEEP_CLEAN = "DEEP_CLEAN"
        const val EXTRA_THUMBNAILS = "PURGE_THUMBNAILS"
        const val EXTRA_METADATA = "ERASE_MEDIASTORE_ROWS"

        fun intentFor(
            context: Context,
            files: List<String>,
            uris: List<String>,
            options: PurgeOptions
        ): Intent {
            return Intent(context, SafeDeleteActivity::class.java).apply {
                putStringArrayListExtra(EXTRA_SELECTED_FILES, ArrayList(files))
                putStringArrayListExtra(EXTRA_SELECTED_URIS, ArrayList(uris))
                putExtra(EXTRA_LEVEL, options.level.name)
                putExtra(EXTRA_VERIFY_MODE, options.verifyMode.name)
                putExtra(EXTRA_EXTEND, options.extendToEraseBoundary)
                putExtra(EXTRA_DEEP_CLEAN, options.deepClean)
                putExtra(EXTRA_THUMBNAILS, options.purgeThumbnails)
                putExtra(EXTRA_METADATA, options.eraseMediaStoreRows)
            }
        }

        fun existingFileCount(paths: List<String>): Int = paths.count { File(it).exists() }

        const val OUT_OF_SCOPE_NOTE = "Traces outside this app's control may remain: MediaStore database history, " +
            "other apps' caches, cloud backups and carrier logs. Only a factory reset cryptographically erases the whole volume."
    }
}

class SafeDeleteConfirmActivity : AppCompatActivity() {

    private var titleText: TextView? = null
    private var warningText: TextView? = null
    private var filesCountText: TextView? = null
    private var btnCancel: MaterialButton? = null
    private var btnConfirm: MaterialButton? = null
    private var deepCleanCheck: CheckBox? = null

    private var selectedPaths: ArrayList<String> = arrayListOf()
    private var selectedUris: ArrayList<String> = arrayListOf()
    private var confirmTargetCount = 0
    private var confirmTotalBytes = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_safe_delete_confirm)

        titleText = findViewById(R.id.title_text)
        warningText = findViewById(R.id.warning_text)
        filesCountText = findViewById(R.id.files_count_text)
        btnCancel = findViewById(R.id.btn_cancel)
        btnConfirm = findViewById(R.id.btn_confirm_delete)

        selectedPaths = intent.getStringArrayListExtra(EXTRA_SELECTED_FILES) ?: arrayListOf()
        selectedUris = intent.getStringArrayListExtra(EXTRA_SELECTED_URIS) ?: arrayListOf()

        confirmTotalBytes = selectedPaths.sumOf { sizeOf(File(it)) }
        confirmTargetCount = selectedPaths.size + selectedUris.size

        titleText?.text = "FINAL WARNING"
        titleText?.setTextColor(Color.parseColor("#FF3D00"))

        installDeepCleanOption()

        warningText?.text = buildWarningText(confirmTargetCount, confirmTotalBytes, resolveOptions())

        filesCountText?.text = buildCapabilityText(confirmTargetCount, confirmTotalBytes)

        btnCancel?.setOnClickListener { finish() }

        btnConfirm?.setOnClickListener {
            if (needsSystemDeleteRequest()) {
                launchSystemDeleteRequest()
            } else {
                startShredding(resolveOptions())
            }
        }
    }

    private fun installDeepCleanOption() {
        val checkBox = CheckBox(this).apply {
            text = "Also run free-space deep clean" +
                    "(after deletion, while charging)"
            setTextColor(Color.parseColor("#BDBDBD"))
            isChecked = false
        }
        checkBox.setOnCheckedChangeListener { _, _ ->
            warningText?.text = buildWarningText(confirmTargetCount, confirmTotalBytes, resolveOptions())
        }
        deepCleanCheck = checkBox

        val anchor = btnConfirm ?: btnCancel ?: return
        val parent = anchor.parent as? ViewGroup ?: return
        if (parent is LinearLayout) {
            val index = parent.indexOfChild(anchor)
            if (index >= 0) parent.addView(checkBox, index) else parent.addView(checkBox)
        } else {
            val content = findViewById<ViewGroup>(android.R.id.content)
            val params = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            if (content is android.widget.FrameLayout) {
                val frameParams = android.widget.FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    Gravity.BOTTOM or Gravity.START
                )
                frameParams.setMargins(0, 0, 0, dp(96))
                content.addView(checkBox, frameParams)
            } else {
                content.addView(checkBox, params)
            }
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun resolveOptions(): PurgeOptions {
        val base = PurgeOptions.MILITARY
        val deepCleanRequested = deepCleanCheck?.isChecked == true
        val levelName = intent.getStringExtra(SafeDeleteActivity.EXTRA_LEVEL)
        val verifyName = intent.getStringExtra(SafeDeleteActivity.EXTRA_VERIFY_MODE)
        if (levelName == null && verifyName == null) return base.copy(deepClean = deepCleanRequested)
        val level = runCatching {
            SanitizationLevel.valueOf(levelName ?: base.level.name)
        }.getOrDefault(base.level)
        val verify = runCatching {
            VerifyMode.valueOf(verifyName ?: base.verifyMode.name)
        }.getOrDefault(base.verifyMode)
        return base.copy(level = level, verifyMode = verify, deepClean = deepCleanRequested)
    }

    private fun buildWarningText(count: Int, bytes: Long, options: PurgeOptions): String {
        val mode = when (options.level) {
            SanitizationLevel.QUICK -> "one random pass"
            SanitizationLevel.STANDARD -> "two passes (random then zero)"
            SanitizationLevel.MAXIMUM -> "two passes (random then zero) with read-back verification of the final pass"
            SanitizationLevel.PARANOID -> "three passes including a CSPRNG pass"
        }
        return "The selected files will be deleted permanently and cannot be recovered. Are you sure you want to do this?"
    }

    private fun buildCapabilityText(count: Int, bytes: Long): String {
        val size = formatBytes(bytes)
        return "Targets: $count\nTotal size: $size\n "
    }

    private fun needsSystemDeleteRequest(): Boolean {
        if (Build.VERSION.SDK_INT < 30) return false
        if (TargetResolver.hasAllFilesAccess()) return false
        if (selectedUris.isEmpty()) return false
        return runCatching {
            selectedUris.any { Uri.parse(it).authority == MediaStoreAuthorityCheck.MEDIA }
        }.getOrDefault(false)
    }

    private fun launchSystemDeleteRequest() {
        val mediaUris = selectedUris.mapNotNull { runCatching { Uri.parse(it) }.getOrNull() }
        if (mediaUris.isEmpty()) {
            startShredding(resolveOptions())
            return
        }
        val request = MediaStoreConsent.buildDeleteRequest(this, mediaUris)
        if (request == null) {
            startShredding(resolveOptions())
            return
        }
        btnConfirm?.isEnabled = false
        btnCancel?.isEnabled = false
        if (!MediaStoreConsent.launch(this, request, REQUEST_SYSTEM_DELETE)) {
            btnConfirm?.isEnabled = true
            btnCancel?.isEnabled = true
            startShredding(resolveOptions())
        }
    }

    private fun startShredding(options: PurgeOptions) {
        val paths = ArrayList(selectedPaths)
        val uris = ArrayList(selectedUris)
        val intent = SafeDeleteActivity.intentFor(this, paths, uris, options)
        startActivity(intent)
        finish()
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_SYSTEM_DELETE) return

        if (resultCode == RESULT_OK) {
            startShredding(resolveOptions())
            return
        }

        btnConfirm?.isEnabled = true
        btnCancel?.isEnabled = true
        filesCountText?.text = "System deletion was not confirmed; nothing was destroyed."
    }

    private fun sizeOf(file: File): Long = try {
        when {
            !file.exists() -> 0L
            file.isFile -> file.length()
            else -> {
                var total = 0L
                file.walkBottomUp().take(MAX_SIZE_WALK_NODES).forEach { node ->
                    if (node.isFile) total += node.length()
                }
                total
            }
        }
    } catch (t: Throwable) {
        0L
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024L) return "$bytes B"
        val units = listOf("KiB", "MiB", "GiB", "TiB")
        var value = bytes.toDouble() / 1024.0
        var index = 0
        while (value >= 1024.0 && index < units.lastIndex) {
            value /= 1024.0
            index++
        }
        return String.format(Locale.US, "%.2f %s", value, units[index])
    }

    private object MediaStoreAuthorityCheck {
        val MEDIA: String = android.provider.MediaStore.AUTHORITY
    }

    companion object {
        const val EXTRA_SELECTED_FILES = "SELECTED_FILES"
        const val EXTRA_SELECTED_URIS = "SELECTED_URIS"
        internal const val REQUEST_SYSTEM_DELETE = 4901
        private const val MAX_SIZE_WALK_NODES = 20000
    }
}

class DeepCleanService : Service() {

    private val cancelToken = AtomicCancellationToken()

    @Volatile
    private var worker: Thread? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            cancelToken.cancel()
            return START_NOT_STICKY
        }
        ensureChannel()
        val initial = buildNotification("preparing deep clean", 0, false)
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, initial, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, initial)
        }
        if (worker?.isAlive == true) return START_NOT_STICKY
        cancelToken.reset()
        val thread = Thread {
            val result = DeepCleaner.run(applicationContext, DeepCleanConfig(), cancelToken) { written, budget ->
                val percent = if (budget > 0L) ((written * 100L) / budget).toInt().coerceIn(0, 100) else 0
                post(buildNotification("churning free space to force flash garbage collection", percent, false))
            }
            val text = when {
                cancelToken.isCancelled -> "deep clean cancelled"
                result.skippedReason != null -> {
                    if (result.skippedReason.contains("charging")) {
                        DeepCleanScheduler.ensureScheduled(applicationContext)
                    }
                    "deep clean skipped: ${result.skippedReason}"
                }
                else -> "deep clean finished: ${result.bytesWritten / MIB} MiB churned, " +
                    "${result.fsyncedFiles} fsynced chunk(s), ${result.leftoversRemoved} leftover(s) removed"
            }
            post(buildNotification(text, 100, true))
            stopSelf()
        }
        worker = thread
        thread.start()
        return START_NOT_STICKY
    }

    private fun post(notification: Notification) {
        try {
            manager().notify(NOTIFICATION_ID, notification)
        } catch (t: Throwable) {
            SecureLog.w("deep clean notification failed: ${Sanitizer.of(t)}")
        }
    }

    private fun manager(): NotificationManager =
        getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < 26) return
        try {
            val channel = NotificationChannel(CHANNEL_ID, "Deep clean", NotificationManager.IMPORTANCE_LOW)
            channel.setShowBadge(false)
            manager().createNotificationChannel(channel)
        } catch (t: Throwable) {
            SecureLog.w("notification channel creation failed: ${Sanitizer.of(t)}")
        }
    }

    private fun buildNotification(text: String, percent: Int, finished: Boolean): Notification {
        val stopIntent = Intent(this, DeepCleanService::class.java).setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        builder.setContentTitle("Secure free-space deep clean")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_delete)
            .setOngoing(!finished)
            .setProgress(100, percent, false)
        if (!finished) {
            @Suppress("DEPRECATION")
            builder.addAction(android.R.drawable.ic_menu_close_clear_cancel, "Cancel", stopPending)
        }
        return builder.build()
    }

    companion object {
        const val ACTION_STOP = "com.example.lock.safe_delete.DEEP_CLEAN_STOP"
        private const val CHANNEL_ID = "sd_deep_clean"
        private const val NOTIFICATION_ID = 4902
        private const val MIB = 1024L * 1024L

        fun start(context: Context) {
            val intent = Intent(context, DeepCleanService::class.java)
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.startService(Intent(context, DeepCleanService::class.java).setAction(ACTION_STOP))
        }

        fun cleanupStaleFiles(context: Context): Int = SecureDelete.cleanupStalePressure(context)
    }
}

object DeepCleanScheduler {

    private const val JOB_ID = 4903

    fun ensureScheduled(context: Context): Boolean {
        return try {
            val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler
                ?: return false
            val builder = JobInfo.Builder(
                JOB_ID,
                ComponentName(context, DeepCleanJobService::class.java)
            ).setRequiresCharging(true)
            if (Build.VERSION.SDK_INT >= 26) {
                builder.setRequiresBatteryNotLow(true)
            }
            scheduler.schedule(builder.build()) == JobScheduler.RESULT_SUCCESS
        } catch (t: Throwable) {
            SecureLog.w("deep clean scheduling failed: ${Sanitizer.of(t)}")
            false
        }
    }

    fun cancel(context: Context) {
        try {
            (context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler)?.cancel(JOB_ID)
        } catch (t: Throwable) {
            SecureLog.d("deep clean schedule cancel failed")
        }
    }
}

class DeepCleanJobService : JobService() {

    private val cancelToken = AtomicCancellationToken()

    private companion object {
        const val JOB_MAX_BYTES = 4L * 1024L * 1024L * 1024L
        const val JOB_TIME_BUDGET_MS = 8L * 60L * 1000L
    }

    override fun onStartJob(params: JobParameters?): Boolean {
        cancelToken.reset()
        Thread {
            val result = DeepCleaner.run(
                applicationContext,
                DeepCleanConfig(
                    maxBytes = JOB_MAX_BYTES,
                    maxRunMillis = JOB_TIME_BUDGET_MS,
                    requireCharging = false
                ),
                cancelToken
            ) { _, _ -> }
            val chargingSkip = !result.executed && result.skippedReason?.contains("charging") == true
            if (chargingSkip || result.stoppedByTimeBudget) {
                DeepCleanScheduler.ensureScheduled(applicationContext)
            }
            jobFinished(params, false)
        }.start()
        return true
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        cancelToken.cancel()
        return true
    }
}

class SafeDeleteStartupProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val ctx = context
        if (ctx != null) {
            SecureDelete.onAppStart(ctx)
        }
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<String>?
    ): Int = 0
}

class DeepCleanActivity : Activity() {

    private var statusText: TextView? = null
    private var progress: ProgressBar? = null
    private val handler = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            refresh()
            handler.postDelayed(this, 1000L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pad = (24 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 2, pad, pad)
        }

        val title = TextView(this).apply {
            text = "Free-Space Deep Clean"
            textSize = 20f
            setTextColor(Color.parseColor("#00E676"))
        }

        val info = TextView(this).apply {
            text = "Churns the free space of this volume with fsynced random data to encourage flash " +
                "garbage collection after your deletions. This raises the odds that blocks of previously " +
                "deleted files get erased, but it cannot guarantee it. Runs while charging, may take " +
                "minutes and adds normal flash wear. Progress is shown in the notification."
            setTextColor(Color.parseColor("#BDBDBD"))
        }

        statusText = TextView(this).apply { setTextColor(Color.parseColor("#FFFFFF")) }
        progress = ProgressBar(this).apply {
            isIndeterminate = true
            visibility = View.GONE
        }

        val btnStart = Button(this).apply {
            text = "START DEEP CLEAN"
            setOnClickListener {
                DeepCleanService.start(this@DeepCleanActivity)
                refresh()
            }
        }
        val btnStop = Button(this).apply {
            text = "STOP"
            setOnClickListener {
                DeepCleanService.stop(this@DeepCleanActivity)
                refresh()
            }
        }
        val btnClose = Button(this).apply {
            text = "CLOSE"
            setOnClickListener { finish() }
        }

        root.addView(title)
        root.addView(info)
        root.addView(statusText)
        root.addView(progress)
        root.addView(btnStart)
        root.addView(btnStop)
        root.addView(btnClose)
        setContentView(root)
    }

    override fun onResume() {
        super.onResume()
        handler.post(ticker)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    private fun refresh() {
        val running = DeepCleaner.isRunning()
        progress?.visibility = if (running) View.VISIBLE else View.GONE
        val charging = when (SecureDelete.isDeviceCharging(this)) {
            true -> "yes"
            false -> "no (will defer and reschedule)"
            null -> "unknown"
        }
        statusText?.text = "state: " + (if (running) "running" else "idle") + " | charging: $charging"
    }

    companion object {
        fun intent(context: Context): Intent = Intent(context, DeepCleanActivity::class.java)
    }
}
