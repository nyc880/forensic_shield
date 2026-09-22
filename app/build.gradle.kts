val bouncyCastleVersion = "1.79"
val argon2Version = "2.7"
val securityCryptoVersion = "1.1.0-alpha06"
val roomVersion = "2.6.1"
val splashScreenVersion = "1.0.1"
val exifInterfaceVersion = "1.3.7"
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
            isMinifyEnabled = false
            isDebuggable = true
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

    packaging {
        resources.excludes.add("META-INF/LICENSE.md")
        resources.excludes.add("META-INF/NOTICE.md")
        resources.excludes.add("META-INF/NOTICE")
        resources.excludes.add("META-INF/LICENSE")
        resources.excludes.add("META-INF/DEPENDENCIES")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)

    implementation("androidx.core:core-splashscreen:$splashScreenVersion")
    implementation("androidx.exifinterface:exifinterface:$exifInterfaceVersion")

    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    kapt("androidx.room:room-compiler:$roomVersion")

    implementation("org.apache.commons:commons-imaging:1.0.0-alpha5")

    implementation("androidx.core:core-splashscreen:1.0.1")

    implementation("org.bouncycastle:bcprov-jdk18on:$bouncyCastleVersion")
    implementation("de.mkammerer:argon2-jvm:$argon2Version")
    implementation("androidx.security:security-crypto:$securityCryptoVersion")

    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}