val bouncyCastleVersion = "1.79"
val argon2Version = "2.7"
val securityCryptoVersion = "1.1.0-alpha06"
val roomVersion = "2.6.1"
val splashScreenVersion = "1.0.1"
val compileSdkVer = 36
val minSdkVer = 26
val targetSdkVer = 36
val jvmTargetVer = "11"

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    id("kotlin-kapt")
}

android {
    namespace = "com.example.lock"
    compileSdk = compileSdkVer

    defaultConfig {
        applicationId = "com.example.lock"
        minSdk = minSdkVer
        targetSdk = targetSdkVer
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        vectorDrawables {
            useSupportLibrary = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = jvmTargetVer
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)

    implementation("androidx.core:core-splashscreen:$splashScreenVersion")

    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    kapt("androidx.room:room-compiler:$roomVersion")

    implementation("org.bouncycastle:bcprov-jdk18on:$bouncyCastleVersion")
    implementation("de.mkammerer:argon2-jvm:$argon2Version")
    implementation("androidx.security:security-crypto:$securityCryptoVersion")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}