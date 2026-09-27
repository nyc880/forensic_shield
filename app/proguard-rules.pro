-keep class com.example.lock.enc.NativeMemoryManager { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
-keep class org.bouncycastle.crypto.** { *; }
-keep class org.bouncycastle.jcajce.** { *; }
-keep class org.bouncycastle.jce.** { *; }
-keep class org.bouncycastle.util.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn java.awt.**
-dontwarn javax.naming.**
-dontwarn sun.security.**
-keepattributes SourceFile, LineNumberTable
-renamesourcefileattribute SourceFile
-dontwarn org.slf4j.**
-dontwarn com.google.errorprone.**
