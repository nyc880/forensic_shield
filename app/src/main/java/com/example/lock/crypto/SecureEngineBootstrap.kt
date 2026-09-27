package com.example.lock.crypto

import android.content.Context
import android.util.Log
import java.io.File

object SecureEngineBootstrap {

    private const val TAG = "LOCK_SEC"
    private const val ENC_DIR_NAME = "ENC"
    private const val DEC_DIR_NAME = "DEC"

    private val lock = Any()

    @Volatile
    private var initialized = false

    fun init(context: Context, signaturePinSha256Hex: String? = null) {
        if (initialized) return
        synchronized(lock) {
            if (!initialized) {
                val appContext = context.applicationContext
                try {
                    val engine = MaxEngineAdapter.getInstance(appContext, signaturePinSha256Hex)

                    engine.setReporter { event ->
                        Log.w(TAG, "${event.kind}: ${event.detail}")
                    }

                    val swept = engine.startupMaintenance(
                        listOf(
                            appContext.cacheDir,
                            appContext.filesDir,
                            File(android.os.Environment.getExternalStorageDirectory(), ENC_DIR_NAME),
                            File(android.os.Environment.getExternalStorageDirectory(), DEC_DIR_NAME)
                        )
                    )

                    Log.i(TAG, "Secure engine ready | startup sweep removed=$swept")
                    initialized = true
                } catch (t: Throwable) {
                    Log.e(TAG, "Secure engine bootstrap failed", t)
                }
            }
        }
    }
}
