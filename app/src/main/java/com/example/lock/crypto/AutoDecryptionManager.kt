package com.example.lock.crypto

import android.content.Context
import java.io.File
import java.util.Arrays

class AutoDecryption(private val context: Context) {

    private var enableEngineFallback: Boolean = true
    private var defaultFallbackEngine: EngineType = EngineType.MAX

    private val mediumManager = MediumEncryptionManager()
    private val maxManager = EncryptionManager()
    private val lightManager = LightEncryptionManager()

    var lastActiveEngine: EngineType? = null
        private set

    fun processAutoDecryption(sourceFile: File, password: String, outputDirectory: File): File? {
        if (!sourceFile.exists()) return null

        val candidateEngines = if (enableEngineFallback) {
            EngineType.detectCandidates(sourceFile)
        } else {
            listOf(EngineType.detectFromFile(sourceFile) ?: defaultFallbackEngine)
        }

        for (engine in candidateEngines) {
            lastActiveEngine = engine
            try {
                val decryptedFile = executeDecryptionForEngine(engine, sourceFile, password, outputDirectory)
                if (decryptedFile != null && decryptedFile.exists()) {
                    return decryptedFile
                }
            } catch (_: Exception) {
                if (!enableEngineFallback) break
            }
        }

        return null
    }

    private fun executeDecryptionForEngine(
        engine: EngineType,
        sourceFile: File,
        password: String,
        outputDirectory: File
    ): File? {
        val passChars = password.toCharArray()
        return try {
            when (engine) {
                EngineType.MAX -> maxManager.decryptFile(
                    inputFile = sourceFile,
                    outputDirectory = outputDirectory,
                    password = passChars
                )
                EngineType.MEDIUM -> mediumManager.decryptFile(
                    inputFile = sourceFile,
                    outputDirectory = outputDirectory,
                    password = passChars
                )
                EngineType.EASY -> lightManager.decryptFile(
                    inputFile = sourceFile,
                    outputDirectory = outputDirectory,
                    password = passChars
                )
            }
        } catch (_: Exception) {
            null
        } finally {
            Arrays.fill(passChars, '\u0000')
        }
    }
}
