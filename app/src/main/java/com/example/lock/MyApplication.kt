package com.example.lock

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.view.WindowManager

object AppSecurity {
    // Anti-screenshot master switch: true = block screenshot & screen record for entire app, false = allow
    const val BLOCK_SCREEN_CAPTURE = true
}

class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        com.example.lock.crypto.SecureEngineBootstrap.init(this)
        // ===== TEST =====
        try {
            System.loadLibrary("cvltsec_native")
            android.util.Log.d("LOCK_SEC", "loadLibrary OK")
        } catch (t: Throwable) {
            android.util.Log.e("LOCK_SEC", "loadLibrary FAILED: ${t.javaClass.name}: ${t.message}", t)
        }
        android.util.Log.d("LOCK_SEC", "native available = ${com.example.lock.enc.NativeMemoryManager.isNativeAvailable()}")
        // ===== /TEST =====

        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                applyScreenshotPolicy(activity)
            }
            override fun onActivityStarted(activity: Activity) {
                applyScreenshotPolicy(activity)
            }
            override fun onActivityResumed(activity: Activity) {
                applyScreenshotPolicy(activity)
            }
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}

            private fun applyScreenshotPolicy(activity: Activity) {
                if (AppSecurity.BLOCK_SCREEN_CAPTURE) {
                    activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                } else {
                    activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
            }
        })
    }
}
