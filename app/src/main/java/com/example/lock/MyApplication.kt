package com.example.lock

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.view.WindowManager

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
            }
            override fun onActivityStarted(activity: Activity) {}
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }
}