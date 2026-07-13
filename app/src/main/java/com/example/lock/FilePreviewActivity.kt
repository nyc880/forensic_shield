package com.example.lock

import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.SurfaceTexture
import android.graphics.pdf.PdfRenderer
import android.media.AudioManager
import android.media.MediaPlayer
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.text.format.Formatter
import android.text.method.ScrollingMovementMethod
import android.view.Surface
import android.view.TextureView
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.SeekBar
import android.widget.TextView
import android.widget.Toast
import com.example.lock.MetadataConfirmActivity
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import java.io.File
import java.util.Locale

class FilePreviewActivity : AppCompatActivity() {

    private lateinit var previewTitle: TextView
    private lateinit var previewDetails: TextView
    private lateinit var imagePreview: ImageView
    private lateinit var videoContainer: View
    private lateinit var videoFrame: FrameLayout
    private lateinit var videoTexture: TextureView
    private lateinit var videoStatus: TextView
    private lateinit var videoPlayPause: Button
    private lateinit var videoSeekBar: SeekBar
    private lateinit var audioContainer: View
    private lateinit var audioTitle: TextView
    private lateinit var audioStatus: TextView
    private lateinit var audioSeekBar: SeekBar
    private lateinit var audioPlayPause: Button
    private lateinit var textPreview: TextView
    private lateinit var pdfImagePreview: ImageView
    private lateinit var genericIcon: ImageView
    private lateinit var genericMessage: TextView
    private lateinit var openExternalButton: Button
    private lateinit var selectCheckBox: CheckBox
    private lateinit var btnDone: Button

    private lateinit var file: File
    private val selectedPaths = HashSet<String>()
    private var mediaPlayer: MediaPlayer? = null
    private var isAudioPrepared = false

    private var videoPlayer: MediaPlayer? = null
    private var isVideoPrepared = false
    private val uiHandler = Handler(Looper.getMainLooper())

    private val progressUpdater = object : Runnable {
        override fun run() {
            updateAudioStatus()
            updateVideoStatus()
            uiHandler.postDelayed(this, 500)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_file_preview)

        previewTitle = findViewById(R.id.preview_title)
        previewDetails = findViewById(R.id.preview_details)
        imagePreview = findViewById(R.id.preview_image)
        videoContainer = findViewById(R.id.preview_video_container)
        videoFrame = findViewById(R.id.preview_video_frame)
        videoTexture = findViewById(R.id.preview_video_texture)
        videoStatus = findViewById(R.id.preview_video_status)
        videoPlayPause = findViewById(R.id.preview_video_play_pause)
        videoSeekBar = findViewById(R.id.preview_video_seekbar)
        audioContainer = findViewById(R.id.preview_audio_container)
        audioTitle = findViewById(R.id.preview_audio_title)
        audioStatus = findViewById(R.id.preview_audio_status)
        audioSeekBar = findViewById(R.id.preview_audio_seekbar)
        audioPlayPause = findViewById(R.id.preview_audio_play_pause)
        textPreview = findViewById(R.id.preview_text)
        pdfImagePreview = findViewById(R.id.preview_pdf_image)
        genericIcon = findViewById(R.id.preview_icon)
        genericMessage = findViewById(R.id.preview_message)
        openExternalButton = findViewById(R.id.preview_open_external)
        selectCheckBox = findViewById(R.id.preview_select_checkbox)
        btnDone = findViewById(R.id.preview_done)

        val path = intent.getStringExtra("file_path")
        if (path.isNullOrEmpty()) {
            finish()
            return
        }

        file = File(path)
        selectedPaths.addAll(intent.getStringArrayListExtra("preselected_files") ?: arrayListOf())

        val type = FileTypeResolver.resolve(file)
        val operationalMode = intent.getStringExtra("crypto_mode") ?: "ENCRYPT"

        previewTitle.text = file.name
        previewDetails.text = "${FileTypeResolver.badge(type, file.extension)} • ${Formatter.formatShortFileSize(this, file.length())}"
        selectCheckBox.isChecked = selectedPaths.contains(file.absolutePath)

        selectCheckBox.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) selectedPaths.add(file.absolutePath) else selectedPaths.remove(file.absolutePath)
        }

        openExternalButton.setOnClickListener {
            openWithExternalApp()
        }

        btnDone.setOnClickListener {
            if (operationalMode == "METADATA") {
                val intent = Intent(this, MetadataConfirmActivity::class.java)
                intent.putStringArrayListExtra("SELECTED_FILES", arrayListOf(file.absolutePath))
                startActivity(intent)
                finish()
                return@setOnClickListener
            }
            val resultIntent = intent
            resultIntent.putStringArrayListExtra("updated_selected_files", ArrayList(selectedPaths))
            setResult(RESULT_OK, resultIntent)
            finish()
        }

        if (operationalMode == "METADATA") {
            btnDone.text = "PROCEED TO STRIP"
            btnDone.setBackgroundColor(android.graphics.Color.parseColor("#54F0A3"))
            btnDone.setTextColor(android.graphics.Color.parseColor("#06120C"))
        }

        uiHandler.post(progressUpdater)
        renderPreview()
    }

    override fun onStop() {
        super.onStop()
        releaseAudio()
        releaseVideo()
    }

    override fun onDestroy() {
        super.onDestroy()
        uiHandler.removeCallbacks(progressUpdater)
    }

    private fun renderPreview() {
        val type = FileTypeResolver.resolve(file)
        hideAll()

        when (type) {
            ResolvedFileType.IMAGE -> showImage()
            ResolvedFileType.VIDEO -> showVideo()
            ResolvedFileType.AUDIO -> showAudio()
            ResolvedFileType.PDF -> showPdf()
            ResolvedFileType.TEXT -> showText()
            else -> showGeneric(file.extension)
        }
    }

    private fun hideAll() {
        imagePreview.visibility = View.GONE
        videoContainer.visibility = View.GONE
        audioContainer.visibility = View.GONE
        textPreview.visibility = View.GONE
        pdfImagePreview.visibility = View.GONE
        genericIcon.visibility = View.GONE
        genericMessage.visibility = View.GONE
        openExternalButton.visibility = View.GONE
    }

    private fun showImage() {
        imagePreview.visibility = View.VISIBLE
        val bitmap = decodeSampledBitmap(file, 1600, 1600)
        imagePreview.setImageBitmap(bitmap)
    }

    private fun showVideo() {
        videoContainer.visibility = View.VISIBLE
        openExternalButton.visibility = View.VISIBLE
        videoPlayPause.text = "Play"
        videoStatus.text = "Loading video..."
        videoSeekBar.progress = 0
        videoSeekBar.max = 100

        videoTexture.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(surface: SurfaceTexture, width: Int, height: Int) {
                prepareVideoPlayer(Surface(surface))
            }
            override fun onSurfaceTextureSizeChanged(surface: SurfaceTexture, width: Int, height: Int) {}
            override fun onSurfaceTextureDestroyed(surface: SurfaceTexture): Boolean {
                releaseVideo()
                return true
            }
            override fun onSurfaceTextureUpdated(surface: SurfaceTexture) {}
        }

        if (videoTexture.isAvailable) {
            prepareVideoPlayer(Surface(videoTexture.surfaceTexture))
        }

        videoPlayPause.setOnClickListener {
            val player = videoPlayer ?: return@setOnClickListener
            if (!isVideoPrepared) return@setOnClickListener
            if (player.isPlaying) {
                player.pause()
                videoPlayPause.text = "Play"
            } else {
                player.start()
                videoPlayPause.text = "Pause"
            }
            updateVideoStatus()
        }

        videoSeekBar.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                if (fromUser && isVideoPrepared) {
                    videoPlayer?.seekTo(progress)
                    updateVideoStatus()
                }
            }
            override fun onStartTrackingTouch(seekBar: SeekBar?) {}
            override fun onStopTrackingTouch(seekBar: SeekBar?) {}
        })
    }

    private fun prepareVideoPlayer(surface: Surface) {
        try {
            releaseVideo()
            videoPlayer = MediaPlayer().apply {
                setAudioStreamType(AudioManager.STREAM_MUSIC)
                setSurface(surface)
                setDataSource(file.absolutePath)
                setOnPreparedListener { mp ->
                    isVideoPrepared = true
                    videoSeekBar.max = mp.duration
                    videoStatus.text = "00:00 / ${formatDuration(mp.duration)}"
                    adjustVideoAspectRatio(mp.videoWidth, mp.videoHeight)
                    seekTo(100)
                }
                setOnVideoSizeChangedListener { _, width, height ->
                    adjustVideoAspectRatio(width, height)
                }
                setOnCompletionListener {
                    videoPlayPause.text = "Play"
                    videoSeekBar.progress = 0
                    videoStatus.text = "00:00 / ${formatDuration(it.duration)}"
                }
                setOnErrorListener { _, _, _ ->
                    videoStatus.text = "Cannot play this video inside the app"
                    true
                }
                prepareAsync()
            }
        } catch (_: Exception) {
            videoStatus.text = "Cannot play this video inside the app"
        }
    }

    private fun adjustVideoAspectRatio(videoWidth: Int, videoHeight: Int) {
        if (videoWidth <= 0 || videoHeight <= 0) return
        videoFrame.post {
            val frameWidth = videoFrame.width
            val frameHeight = videoFrame.height
            if (frameWidth <= 0 || frameHeight <= 0) return@post

            val videoRatio = videoWidth.toFloat() / videoHeight.toFloat()
            val frameRatio = frameWidth.toFloat() / frameHeight.toFloat()
            val layoutParams = videoTexture.layoutParams

            if (videoRatio > frameRatio) {
                layoutParams.width = frameWidth
                layoutParams.height = (frameWidth / videoRatio).toInt()
            } else {
                layoutParams.height = frameHeight
                layoutParams.width = (frameHeight * videoRatio).toInt()
            }

            if (layoutParams is FrameLayout.LayoutParams) {
                layoutParams.gravity = android.view.Gravity.CENTER
            }

            videoTexture.layoutParams = layoutParams
            videoTexture.requestLayout()
        }
    }

    private fun updateVideoStatus() {
        val player = videoPlayer ?: return
        if (!isVideoPrepared) return
        val current = player.currentPosition
        val total = player.duration
        videoSeekBar.progress = current
        videoStatus.text = "${formatDuration(current)} / ${formatDuration(total)}"
    }

    private fun showAudio() {
        audioContainer.visibility = View.VISIBLE
        audioTitle.text = file.name
        audioStatus.text = "Ready to play"
        audioSeekBar.progress = 0
        audioSeekBar.max = 100
        audioPlayPause.text = "Play"
        openExternalButton.visibility = View.VISIBLE

        try {
            releaseAudio()
            mediaPlayer = MediaPlayer().apply {
                setDataSource(file.absolutePath)
                setOnPreparedListener { mp ->
                    isAudioPrepared = true
                    audioSeekBar.max = mp.duration
                    audioStatus.text = "00:00 / ${formatDuration(mp.duration)}"
                }
                setOnCompletionListener {
                    audioPlayPause.text = "Play"
                    audioSeekBar.progress = 0
                    audioStatus.text = "00:00 / ${formatDuration(it.duration)}"
                }
                prepare()
            }
        } catch (_: Exception) {
            audioStatus.text = "Cannot play this audio inside the app"
        }

        audioPlayPause.setOnClickListener {
            val mp = mediaPlayer ?: return@setOnClickListener
            if (!isAudioPrepared) return@setOnClickListener
            if (mp.isPlaying) {
                mp.pause()
                audioPlayPause.text = "Play"
            } else {
                mp.start()
                audioPlayPause.text = "Pause"
            }
            updateAudioStatus()
        }

        audioSeekBar.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
                if (fromUser && isAudioPrepared) {
                    mediaPlayer?.seekTo(progress)
                    updateAudioStatus()
                }
            }
            override fun onStartTrackingTouch(seekBar: SeekBar?) {}
            override fun onStopTrackingTouch(seekBar: SeekBar?) {}
        })
    }

    private fun updateAudioStatus() {
        val mp = mediaPlayer ?: return
        if (!isAudioPrepared) return
        val current = mp.currentPosition
        val total = mp.duration
        audioSeekBar.progress = current
        audioStatus.text = "${formatDuration(current)} / ${formatDuration(total)}"
    }

    private fun showText() {
        textPreview.visibility = View.VISIBLE
        textPreview.movementMethod = ScrollingMovementMethod()
        try {
            textPreview.text = file.readText()
        } catch (_: Exception) {
            textPreview.text = "Unable to read this text file."
        }
    }

    private fun showPdf() {
        pdfImagePreview.visibility = View.VISIBLE
        openExternalButton.visibility = View.VISIBLE
        try {
            val fd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
            val renderer = PdfRenderer(fd)
            if (renderer.pageCount > 0) {
                val page = renderer.openPage(0)
                val bitmap = Bitmap.createBitmap(page.width, page.height, Bitmap.Config.ARGB_8888)
                page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                pdfImagePreview.setImageBitmap(bitmap)
                page.close()
            }
            renderer.close()
            fd.close()
        } catch (_: Exception) {
            openWithExternalApp()
        }
    }

    private fun showGeneric(ext: String) {
        genericIcon.visibility = View.VISIBLE
        genericMessage.visibility = View.VISIBLE
        openExternalButton.visibility = View.VISIBLE
        genericIcon.setImageResource(android.R.drawable.ic_menu_save)
        genericMessage.text = "Preview is not available for this file type (${if (ext.isBlank()) "unknown" else ext.uppercase(Locale.getDefault())})."
    }

    private fun openWithExternalApp() {
        try {
            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val type = when (FileTypeResolver.resolve(file)) {
                ResolvedFileType.VIDEO -> "video/*"
                ResolvedFileType.AUDIO -> "audio/*"
                ResolvedFileType.IMAGE -> "image/*"
                ResolvedFileType.PDF -> "application/pdf"
                ResolvedFileType.TEXT -> "text/*"
                else -> "*/*"
            }
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, type)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(Intent.createChooser(intent, "Open with"))
        } catch (e: ActivityNotFoundException) {
            Toast.makeText(this, "No app found to open this file", Toast.LENGTH_SHORT).show()
        } catch (_: Exception) {
            Toast.makeText(this, "Cannot open this file", Toast.LENGTH_SHORT).show()
        }
    }

    private fun releaseAudio() {
        isAudioPrepared = false
        mediaPlayer?.release()
        mediaPlayer = null
    }

    private fun releaseVideo() {
        isVideoPrepared = false
        videoPlayer?.release()
        videoPlayer = null
        val params = videoTexture.layoutParams
        params.width = ViewGroup.LayoutParams.MATCH_PARENT
        params.height = ViewGroup.LayoutParams.MATCH_PARENT
        videoTexture.layoutParams = params
    }

    private fun formatDuration(ms: Int): String {
        val totalSeconds = ms / 1000
        val minutes = totalSeconds / 60
        val seconds = totalSeconds % 60
        return String.format(Locale.getDefault(), "%02d:%02d", minutes, seconds)
    }

    private fun decodeSampledBitmap(file: File, reqWidth: Int, reqHeight: Int): Bitmap? {
        return try {
            val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(file.absolutePath, options)
            options.inSampleSize = calculateInSampleSize(options, reqWidth, reqHeight)
            options.inJustDecodeBounds = false
            options.inPreferredConfig = Bitmap.Config.RGB_565
            BitmapFactory.decodeFile(file.absolutePath, options)
        } catch (_: Exception) {
            null
        }
    }

    private fun calculateInSampleSize(options: BitmapFactory.Options, reqWidth: Int, reqHeight: Int): Int {
        val height = options.outHeight
        val width = options.outWidth
        var inSampleSize = 1
        if (height > reqHeight || width > reqWidth) {
            val halfHeight = height / 2
            val halfWidth = width / 2
            while ((halfHeight / inSampleSize) >= reqHeight && (halfWidth / inSampleSize) >= reqWidth) {
                inSampleSize *= 2
            }
        }
        return inSampleSize.coerceAtLeast(1)
    }
}