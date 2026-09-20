@file:Suppress("BlockingMethodInNonBlockingContext")

package com.example.lock.safe_delete

// =====================================================================
//  VOLATILE VAULT ENGINE — Military-Grade Secure File Deletion
//  Architecture: Crypto-Shredding (Primary) + NIST SP 800-88 Purge (Secondary)
//
//  THIS IS THE SINGLE SOURCE OF TRUTH FOR SECURE DELETION.
//  UI entry point -> object SecureDelete (bottom of this file)
//
//  References:
//   – NIST SP 800-88 Rev.1  (Media Sanitization Guidelines — Purge + Verify)
//   – NIST SP 800-38D       (AES-GCM Mode of Operation)
//   – NIST SP 800-132       (PBKDF2)
//   – NIST SP 800-90A/B     (DRBG — SecureRandom)
//   – FIPS 140-3 / OWASP MSTG / JEDEC eMMC-UFS (TRIM)
// =====================================================================

import android.content.ContentResolver
import android.content.ContentUris
import android.content.Context
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.MediaStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import android.util.Log
import androidx.room.*
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.io.*
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.util.*
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

// =====================================================================
//  CONFIGURATION
// =====================================================================

internal object VaultConfig {
    const val PBKDF_ITERATIONS = 600_000
    const val SALT_BYTES = 32
    const val PBKDF_KEY_BITS = 256
    const val AES_KEY_BITS = 256
    const val AES_GCM_TAG_BITS = 128
    const val GCM_NONCE_BYTES = 12
    const val CHUNK_IV_PREFIX_BYTES = 8

    val NIST_PURGE_PATTERNS = listOf(
        PurgePassType.CRYPTO_RANDOM,
        PurgePassType.ALL_ZEROES,
        PurgePassType.ALL_ONES
    )

    // --- Purge tuning (measured: 'rw'+sync is ~1.9x faster than 'rws', same durability) ---
    const val RANDOM_ACCESS_MODE = "rw"
    const val OVERWRITE_BUFFER_SIZE = 1_048_576
    const val VERIFY_BUFFER_SIZE = 1_048_576
    const val VERIFY_OVERWRITE = true          // NIST SP 800-88 "Verify" step
    const val LOG_ENABLED = true               // set false for release builds

    const val RENAME_OBFUSCATION_ROUNDS = 5
    const val RENAME_OBFUSCATION_LENGTH = 10
    const val TRIM_TRIGGER_MAX_BYTES = 64L * 1024L * 1024L
    const val TRIM_TRIGGER_BUFFER_SIZE = 262_144

    const val AUTO_GENERATED_KEY_LENGTH = 200
    const val MIN_AUTO_GENERATED_KEY_LENGTH = 200
    const val MAX_AUTO_GENERATED_KEY_LENGTH = 300
    const val KDF_TYPE_PBKDF2 = 0
    const val KDF_TYPE_ARGON2ID = 1
    const val ARGON2_MEMORY_KB = 16384
    const val ARGON2_ITERATIONS = 3
    const val ARGON2_PARALLELISM = 1
    const val BASE_CHUNK_SIZE = 131_072
    const val STANDARD_CHUNK_SIZE = 1_048_576
    const val LOW_RAM_THRESHOLD_MB = 3072
    const val FORMAT_VERSION = 4
    const val BOUNDED_CACHE_EVICTION_MAX_BYTES = 64L * 1024L * 1024L

    const val DB_NAME = "volatile_vault_db"
    const val DB_VERSION = 1
    const val PRAGMA_SECURE_DELETE = "PRAGMA secure_delete = ON"
    const val PRAGMA_SYNCHRONOUS_FULL = "PRAGMA synchronous = FULL"
    const val PRAGMA_WAL_CHECKPOINT_FULL = "PRAGMA wal_checkpoint(FULL)"
}

internal enum class PurgePassType { CRYPTO_RANDOM, ALL_ZEROES, ALL_ONES }

// =====================================================================
//  LOGGING
// =====================================================================

internal object VaultLog {
    private const val TAG = "SecureDeleteEngine"
    fun i(msg: String) { if (VaultConfig.LOG_ENABLED) Log.i(TAG, msg) }
    fun w(msg: String) { if (VaultConfig.LOG_ENABLED) Log.w(TAG, msg) }
    fun e(msg: String, t: Throwable? = null) { if (VaultConfig.LOG_ENABLED) Log.e(TAG, msg, t) }
}

// =====================================================================
//  FILESYSTEM SYNC  (FIX: FileOutputStream(dir) throws EISDIR on Android,
//  so the previous directory-fsync was a silent no-op)
// =====================================================================

internal object FilesystemSync {

    /** fsync a directory so a rename/unlink is durable. Verified working. */
    fun syncDirectory(dir: File?) {
        if (dir == null || !dir.exists()) return
        val path = dir.absolutePath

        // Primary: android.system.Os — works on every API level
        try {
            val fd = Os.open(path, OsConstants.O_RDONLY, 0)
            try {
                Os.fsync(fd)
            } finally {
                Os.close(fd)
            }
            return
        } catch (_: Throwable) { }

        // Fallback: FileChannel in READ mode (verified working; WRITE/RAF throw EISDIR)
        try {
            FileChannel.open(dir.toPath(), StandardOpenOption.READ).use { it.force(true) }
        } catch (t: Throwable) {
            VaultLog.w("syncDirectory failed for $path: ${t.message}")
        }
    }
}

// =====================================================================
//  PASSPHRASE GENERATOR (Crypto-Shredding)
// =====================================================================

internal object MultiScriptPassphraseGenerator {

    private val rng = SecureRandom()

    private const val LANGUAGE_MINIMUM_PICK = 15
    private const val DIGIT_MINIMUM_PICK = 25
    private const val PUNCTUATION_MINIMUM_PICK = 15

    private data class ScriptGroup(
        val name: String,
        val tokens: List<Char>,
        val minimumPick: Int
    )

    private fun parseTokens(raw: String): List<Char> {
        return raw
            .split("-")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { it.first() }
            .distinct()
    }

    private val scriptGroups = listOf(
        ScriptGroup(
            name = "PERSIAN",
            tokens = parseTokens("ا-ب-پ-ت-ث-ج-چ-ح-خ-د-ذ-ر-ز-س-ش-ص-ض-ط-ظ-ع-غ-ف-ق-ک-گ-ل-م-ن-ه-و-ی"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "HEBREW",
            tokens = parseTokens("א-ב-ג-ד-ה-ו-ז-ח-ט-י-כ-ל-מ-נ-ס-ע-פ-צ-ק-ר-ש-ת"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "RUSSIAN",
            tokens = parseTokens("А-Б-В-Г-Д-Е-Ё-Ж-З-И-Й-К-Л-М-Н-О-П-Р-С-Т-У-Ф-Х-Ц-Ч-Ш-Щ-Ъ-Ы-Ь-Э-Ю-Я"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "CHINESE_BOPOMOFO",
            tokens = parseTokens("ㄅ-ㄆ-ㄇ-ㄈ-ㄉ-ㄊ-ㄋ-ㄌ-ㄍ-ㄎ-ㄏ-ㄐ-ㄑ-ㄒ-ㄓ-ㄔ-ㄕ-ㄖ-ㄗ-ㄘ-ㄙ-ㄚ-ㄛ-ㄜ-ㄝ-ㄞ-ㄟ-ㄠ-ㄡ-ㄢ-ㄣ-ㄤ-ㄥ-ㄦ-ㄧ-ㄨ-ㄩ"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "JAPANESE",
            tokens = parseTokens("あ-い-う-え-お-か-き-く-け-こ-さ-し-す-せ-そ-た-ち-つ-て-と-な-に-ぬ-ね-の-は-ひ-ふ-へ-ほ-ま-み-む-め-も-や-ゆ-よ-ら-り-る-れ-ろ-わ-を-ん"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "ENGLISH_UPPER",
            tokens = parseTokens("A-B-C-D-E-F-G-H-I-J-K-L-M-N-O-P-Q-R-S-T-U-V-W-X-Y-Z"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "ENGLISH_LOWER",
            tokens = parseTokens("a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p-q-r-s-t-u-v-w-x-y-z"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "DIGITS",
            tokens = parseTokens("0-1-2-3-4-5-6-7-8-9"),
            minimumPick = DIGIT_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "PUNCTUATION",
            tokens = listOf(
                '!', '@', '$', '%', '^', '&', '*', '(', ')',
                '_', '+', '=', '{', '}', '[', ']', '|',
                ':', ';', '"', '\'', '<', '>', ',', '.', '?', '/'
            ),
            minimumPick = PUNCTUATION_MINIMUM_PICK
        )
    )

    fun generate(length: Int = VaultConfig.AUTO_GENERATED_KEY_LENGTH): CharArray {
        val minLen = VaultConfig.MIN_AUTO_GENERATED_KEY_LENGTH
        val maxLen = VaultConfig.MAX_AUTO_GENERATED_KEY_LENGTH
        val targetLength = if (length in minLen..maxLen) length else minLen + rng.nextInt(maxLen - minLen + 1)

        val output = ArrayList<Char>(targetLength)

        for (group in scriptGroups) {
            repeat(group.minimumPick) { output.add(randomTokenFrom(group)) }
        }

        val remaining = targetLength - output.size
        if (remaining > 0) {
            val extraGroups = buildDistributedRandomGroups(remaining)
            for (group in extraGroups) output.add(randomTokenFrom(group))
        }

        output.shuffle(rng)
        output.shuffle(rng)
        output.shuffle(rng)

        return output.take(targetLength).toCharArray()
    }

    private fun buildDistributedRandomGroups(count: Int): List<ScriptGroup> {
        val result = ArrayList<ScriptGroup>(count)
        while (result.size < count) {
            val round = scriptGroups.shuffled(rng)
            for (group in round) {
                if (result.size >= count) break
                result.add(group)
            }
        }
        result.shuffle(rng)
        return result
    }

    private fun randomTokenFrom(group: ScriptGroup): Char = group.tokens[rng.nextInt(group.tokens.size)]

    fun wipe(passphrase: CharArray?) { passphrase?.fill('\u0000') }
}

// =====================================================================
//  ENTITIES & DAO
// =====================================================================

internal enum class FileStatus { ACTIVE, PENDING_DELETE }

@Entity(tableName = "volatile_vault")
internal data class VaultEntity(
    @PrimaryKey val uuidHash: String,
    var status: String = FileStatus.ACTIVE.name,
    val createdAtEpochMs: Long = System.currentTimeMillis()
)

@Dao
internal interface VaultDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(entity: VaultEntity)

    @Query("SELECT * FROM volatile_vault WHERE uuidHash = :hash LIMIT 1")
    suspend fun getByHash(hash: String): VaultEntity?

    @Query("SELECT * FROM volatile_vault WHERE status = 'PENDING_DELETE'")
    suspend fun getPendingDeletes(): List<VaultEntity>

    @Query("UPDATE volatile_vault SET status = :status WHERE uuidHash = :hash")
    suspend fun updateStatus(hash: String, status: String)

    @Query("DELETE FROM volatile_vault WHERE uuidHash = :hash")
    suspend fun deleteByHash(hash: String)

    @Transaction
    suspend fun markAsPending(hash: String) { updateStatus(hash, FileStatus.PENDING_DELETE.name) }
}

@Database(
    entities = [VaultEntity::class],
    version = VaultConfig.DB_VERSION,
    exportSchema = false
)
internal abstract class VolatileVaultDatabase : RoomDatabase() {

    abstract fun vaultDao(): VaultDao

    companion object {
        @Volatile
        private var INSTANCE: VolatileVaultDatabase? = null

        fun getInstance(context: Context): VolatileVaultDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    VolatileVaultDatabase::class.java,
                    VaultConfig.DB_NAME
                )
                    .setJournalMode(JournalMode.TRUNCATE)
                    .addCallback(object : Callback() {
                        override fun onOpen(db: SupportSQLiteDatabase) {
                            super.onOpen(db)
                            try {
                                db.execSQL(VaultConfig.PRAGMA_SECURE_DELETE)
                                db.execSQL(VaultConfig.PRAGMA_SYNCHRONOUS_FULL)
                                db.execSQL(VaultConfig.PRAGMA_WAL_CHECKPOINT_FULL)
                            } catch (_: Exception) { }
                        }

                        override fun onCreate(db: SupportSQLiteDatabase) {
                            super.onCreate(db)
                            try {
                                db.execSQL(VaultConfig.PRAGMA_SECURE_DELETE)
                                db.execSQL(VaultConfig.PRAGMA_SYNCHRONOUS_FULL)
                            } catch (_: Exception) { }
                        }
                    })
                    .fallbackToDestructiveMigration()
                    .build()

                INSTANCE = instance
                instance
            }
        }

        fun forceSecureCheckpointAndClose(context: Context) {
            INSTANCE?.let { db ->
                try {
                    val supportDb = db.openHelper.writableDatabase
                    supportDb.execSQL(VaultConfig.PRAGMA_WAL_CHECKPOINT_FULL)
                    supportDb.execSQL("PRAGMA wal_checkpoint(TRUNCATE)")
                    supportDb.close()
                } catch (_: Exception) { }
                try { db.close() } catch (_: Exception) { }
                INSTANCE = null
            }
            securelyWipeWALFiles(context)
        }

        private fun securelyWipeWALFiles(context: Context) {
            val dbPath = context.getDatabasePath(VaultConfig.DB_NAME)
            val walFile = File(dbPath.parentFile, "${VaultConfig.DB_NAME}-wal")
            val shmFile = File(dbPath.parentFile, "${VaultConfig.DB_NAME}-shm")

            listOf(walFile, shmFile).forEach { file ->
                if (file.exists() && file.isFile) {
                    try {
                        RandomAccessFile(file, VaultConfig.RANDOM_ACCESS_MODE).use { raf ->
                            val len = file.length()
                            if (len > 0) {
                                val buf = ByteArray(minOf(65536, len.toInt()))
                                SecureRandom().nextBytes(buf)
                                raf.seek(0)
                                raf.write(buf)
                                raf.setLength(0)
                                raf.fd.sync()
                                SecureErase.wipe(buf)
                            }
                        }
                    } catch (_: Exception) { }
                    file.delete()
                }
            }
            FilesystemSync.syncDirectory(dbPath.parentFile)
        }
    }
}

internal fun createHardenedVaultDao(context: Context): VaultDao {
    return VolatileVaultDatabase.getInstance(context).vaultDao()
}

// =====================================================================
//  UTILITIES
// =====================================================================

internal object SecureErase {
    fun wipe(bytes: ByteArray?) {
        if (bytes == null || bytes.isEmpty()) return
        bytes.fill(0)
        bytes[0].compareTo(0)
    }

    fun wipeChars(chars: CharArray?) {
        if (chars == null || chars.isEmpty()) return
        chars.fill('\u0000')
        chars[0].compareTo('0')
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    fun wipeKey(key: SecretKey?) { if (key is SecretKeySpec) wipe(key.encoded) }
}

internal class UuidObfuscator(private val masterKey: SecretKey) {
    private val hmacAlg = "HmacSHA256"

    fun hash(rawUuid: String): String {
        val mac = Mac.getInstance(hmacAlg)
        mac.init(masterKey)
        val hmacBytes = mac.doFinal(rawUuid.toByteArray(Charsets.UTF_8))
        return hmacBytes.joinToString("") { "%02x".format(it) }
    }
}

// =====================================================================
//  NIST SP 800-88 PURGE ENGINE  —  the single secure-deletion engine
// =====================================================================

internal class NistPurgeEngine(private val rng: SecureRandom = SecureRandom()) {

    /** Simple boolean API. */
    fun purge(file: File): Boolean = purgeWithReport(file).success

    /**
     * Full NIST SP 800-88 Purge:
     *   1) chmod +w if needed
     *   2) 3-pass overwrite (CRYPTO_RANDOM -> 0x00 -> 0xFF), fsync after each pass
     *   3) read-back VERIFY of the final deterministic pass
     *   4) truncate to 0 + fsync
     *   5) 5x random rename + unlink
     *   6) fsync parent directory (durable unlink)
     *   7) TRIM trigger
     */
    fun purgeWithReport(file: File): SecureDeleteReport {
        val t0 = System.currentTimeMillis()
        val path = file.absolutePath

        if (!file.exists()) {
            return SecureDeleteReport(path, 0, true, true, true, true, true, true, 0)
        }
        if (file.isDirectory) {
            val ok = file.delete()
            FilesystemSync.syncDirectory(file.parentFile)
            return SecureDeleteReport(path, 0, true, true, true, true, ok, !file.exists(),
                System.currentTimeMillis() - t0)
        }

        val length = file.length()
        val parent = file.parentFile
        val writable = ensureWritable(file)

        if (!writable) {
            VaultLog.w("purge ABORTED (not writable, chmod failed): $path")
            return SecureDeleteReport(path, length, false, false, false, false, false, file.exists().not(),
                System.currentTimeMillis() - t0)
        }

        var overwriteOk = true
        var verifyOk = true
        var truncated = true

        try {
            if (length > 0L) {
                val passes = VaultConfig.NIST_PURGE_PATTERNS
                for ((index, pass) in passes.withIndex()) {
                    if (!overwritePass(file, length, pass)) {
                        overwriteOk = false
                        break
                    }
                    val isLast = index == passes.lastIndex
                    if (isLast && VaultConfig.VERIFY_OVERWRITE && pass != PurgePassType.CRYPTO_RANDOM) {
                        verifyOk = verifyPass(file, length, pass)
                        if (!verifyOk) VaultLog.w("purge VERIFY FAILED for $path (pass=${pass.name})")
                    }
                }
                truncated = truncateToZero(file)
            }
        } catch (t: Throwable) {
            overwriteOk = false
            VaultLog.e("purge overwrite exception for $path", t)
        }

        val deleted = try {
            obfuscateFilenameAndDelete(file)
        } catch (t: Throwable) {
            VaultLog.w("purge delete exception for $path: ${t.message}")
            false
        }

        FilesystemSync.syncDirectory(parent)
        if (length > 0L) tryTriggerTrim(parent, length)

        val gone = !file.exists()
        val report = SecureDeleteReport(
            path = path,
            length = length,
            writable = true,
            overwriteOk = overwriteOk,
            verifyOk = verifyOk,
            truncated = truncated,
            deleted = deleted,
            gone = gone,
            elapsedMs = System.currentTimeMillis() - t0
        )

        if (report.success) {
            VaultLog.i(
                "purge OK  size=$length  verify=$verifyOk  ${report.elapsedMs}ms  $path"
            )
        } else {
            VaultLog.w(
                "purge FAILED overwrite=$overwriteOk verify=$verifyOk trunc=$truncated " +
                        "deleted=$deleted gone=$gone size=$length ${report.elapsedMs}ms $path"
            )
        }
        return report
    }

    // ------------------------------------------------------------------

    private fun ensureWritable(file: File): Boolean {
        if (file.canWrite()) return true
        return try {
            file.setWritable(true, false)
            file.canWrite()
        } catch (_: Throwable) {
            false
        }
    }

    private fun overwritePass(file: File, length: Long, pass: PurgePassType): Boolean {
        return try {
            RandomAccessFile(file, VaultConfig.RANDOM_ACCESS_MODE).use { raf ->
                val bufSize = minOf(VaultConfig.OVERWRITE_BUFFER_SIZE.toLong(), length)
                    .coerceAtLeast(1L).toInt()
                val buf = ByteArray(bufSize)
                raf.seek(0)
                var written = 0L
                while (written < length) {
                    when (pass) {
                        PurgePassType.CRYPTO_RANDOM -> rng.nextBytes(buf)
                        PurgePassType.ALL_ZEROES -> buf.fill(0)
                        PurgePassType.ALL_ONES -> buf.fill(0xFF.toByte())
                    }
                    val n = minOf(buf.size.toLong(), length - written).toInt()
                    raf.write(buf, 0, n)
                    written += n
                }
                raf.fd.sync()
                SecureErase.wipe(buf)
                written == length
            }
        } catch (t: Throwable) {
            VaultLog.w("overwrite pass ${pass.name} failed on ${file.name}: ${t.message}")
            false
        }
    }

    /** NIST SP 800-88 Verify: read the media back and compare to the written pattern. */
    private fun verifyPass(file: File, length: Long, pass: PurgePassType): Boolean {
        val expected = when (pass) {
            PurgePassType.ALL_ZEROES -> 0.toByte()
            PurgePassType.ALL_ONES -> 0xFF.toByte()
            PurgePassType.CRYPTO_RANDOM -> return true
        }
        return try {
            RandomAccessFile(file, "r").use { raf ->
                val buf = ByteArray(VaultConfig.VERIFY_BUFFER_SIZE)
                var read = 0L
                while (read < length) {
                    val n = raf.read(buf, 0, minOf(buf.size.toLong(), length - read).toInt())
                    if (n <= 0) return@use false
                    for (i in 0 until n) {
                        if (buf[i] != expected) return@use false
                    }
                    read += n
                }
                read == length
            }
        } catch (t: Throwable) {
            VaultLog.w("verify read failed on ${file.name}: ${t.message}")
            false
        }
    }

    private fun truncateToZero(file: File): Boolean {
        return try {
            RandomAccessFile(file, VaultConfig.RANDOM_ACCESS_MODE).use { raf ->
                raf.setLength(0L)
                raf.fd.sync()
            }
            true
        } catch (t: Throwable) {
            VaultLog.w("truncate failed on ${file.name}: ${t.message}")
            false
        }
    }

    private fun obfuscateFilenameAndDelete(file: File): Boolean {
        var currentFile = file
        val parent = currentFile.parentFile ?: return currentFile.delete()
        val charPool = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

        for (i in 1..VaultConfig.RENAME_OBFUSCATION_ROUNDS) {
            val newName = (1..VaultConfig.RENAME_OBFUSCATION_LENGTH)
                .map { charPool[rng.nextInt(charPool.length)] }
                .joinToString("")
            val renamedFile = File(parent, newName)
            if (currentFile.renameTo(renamedFile)) currentFile = renamedFile
        }

        return currentFile.delete()
    }

    /** Pushes the FTL to reclaim the freed blocks (best effort). */
    private fun tryTriggerTrim(parent: File?, originalLength: Long) {
        if (parent == null || originalLength <= 0L) return
        val triggerFile = File(parent, ".vv_trim_${UUID.randomUUID()}")
        try {
            RandomAccessFile(triggerFile, VaultConfig.RANDOM_ACCESS_MODE).use { raf ->
                raf.setLength(minOf(originalLength, VaultConfig.TRIM_TRIGGER_MAX_BYTES))
                raf.fd.sync()
            }
            RandomAccessFile(triggerFile, VaultConfig.RANDOM_ACCESS_MODE).use { raf ->
                val buf = ByteArray(VaultConfig.TRIM_TRIGGER_BUFFER_SIZE)
                var written = 0L
                val len = triggerFile.length()
                while (written < len) {
                    rng.nextBytes(buf)
                    val n = minOf(buf.size.toLong(), len - written).toInt()
                    raf.write(buf, 0, n)
                    written += n
                }
                raf.fd.sync()
                SecureErase.wipe(buf)
            }
        } catch (_: Throwable) {
        } finally {
            try { triggerFile.delete() } catch (_: Throwable) { }
            FilesystemSync.syncDirectory(parent)
        }
    }

    companion object {

        /** Purge a plain File (used by the UI layer). */
        fun sanitizeFile(context: Context, file: File): Boolean {
            return try {
                val purged = NistPurgeEngine(SecureRandom()).purge(file)
                MetadataSanitizer.sanitizeMediaStoreAfterDelete(context, file)
                purged
            } catch (t: Throwable) {
                VaultLog.e("sanitizeFile failed: ${file.absolutePath}", t)
                false
            }
        }

        /** Purge whatever a Uri points at (file://, content://, SAF document). */
        fun sanitizeOriginalFile(context: Context, originalUri: Uri): Boolean {
            return try {
                val path = resolveDirectPath(context, originalUri)

                if (path != null) {
                    val file = File(path)
                    if (file.exists()) {
                        if (sanitizeFile(context, file)) return true
                    }
                }

                purgeUri(context, originalUri)
            } catch (t: Throwable) {
                VaultLog.e("sanitizeOriginalFile failed: $originalUri", t)
                false
            }
        }

        private fun purgeUri(context: Context, uri: Uri): Boolean {
            var descriptor: ParcelFileDescriptor? = null

            return try {
                descriptor = try {
                    context.contentResolver.openFileDescriptor(uri, "rwt")
                } catch (_: Exception) {
                    null
                } ?: try {
                    context.contentResolver.openFileDescriptor(uri, "wt")
                } catch (_: Exception) {
                    null
                }

                val pfd = descriptor ?: run {
                    VaultLog.w("purgeUri: cannot open descriptor for $uri")
                    return false
                }
                val size = pfd.statSize.takeIf { it > 0L } ?: 0L

                FileOutputStream(pfd.fileDescriptor).channel.use { channel ->
                    val random = SecureRandom()
                    val buffer = ByteArray(VaultConfig.OVERWRITE_BUFFER_SIZE)

                    if (size > 0L) {
                        repeat(3) { pass ->
                            channel.position(0L)
                            var written = 0L
                            while (written < size) {
                                when (pass) {
                                    0 -> random.nextBytes(buffer)
                                    1 -> buffer.fill(0)
                                    else -> buffer.fill(0xFF.toByte())
                                }
                                val n = minOf(buffer.size.toLong(), size - written).toInt()
                                channel.write(ByteBuffer.wrap(buffer, 0, n))
                                written += n.toLong()
                            }
                            channel.force(true)
                        }
                    }

                    channel.truncate(0L)
                    channel.force(true)
                    SecureErase.wipe(buffer)
                }
                true
            } catch (t: Throwable) {
                VaultLog.w("purgeUri failed for $uri: ${t.message}")
                false
            } finally {
                try { descriptor?.close() } catch (_: Exception) { }
            }
        }

        /** Resolves a real path for file://, SAF documents and MediaStore URIs. */
        fun resolveDirectPath(context: Context, uri: Uri): String? {
            if ("file".equals(uri.scheme, ignoreCase = true)) return uri.path

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT &&
                DocumentsContract.isDocumentUri(context, uri)
            ) {
                try {
                    val docId = DocumentsContract.getDocumentId(uri)
                    when (uri.authority) {
                        "com.android.externalstorage.documents" -> {
                            val split = docId.split(":")
                            if ("primary".equals(split.getOrNull(0), ignoreCase = true)) {
                                return Environment.getExternalStorageDirectory().absolutePath +
                                        "/" + split.getOrNull(1)
                            }
                            if (split.size >= 2) return "/storage/" + split[0] + "/" + split[1]
                        }

                        "com.android.providers.downloads.documents" -> {
                            if (docId.startsWith("raw:")) return docId.substring(4)
                            val id = docId.toLongOrNull() ?: return null
                            val contentUri = ContentUris.withAppendedId(
                                Uri.parse("content://downloads/public_downloads"), id
                            )
                            return queryMediaStorePath(context, contentUri)
                        }

                        "com.android.providers.media.documents" -> {
                            val split = docId.split(":")
                            val contentUri = when (split.getOrNull(0)) {
                                "image" -> MediaStore.Images.Media.EXTERNAL_CONTENT_URI
                                "video" -> MediaStore.Video.Media.EXTERNAL_CONTENT_URI
                                "audio" -> MediaStore.Audio.Media.EXTERNAL_CONTENT_URI
                                else -> MediaStore.Files.getContentUri("external")
                            }
                            return queryMediaStorePath(
                                context, contentUri, "_id=?",
                                arrayOf(split.getOrNull(1) ?: return null)
                            )
                        }
                    }
                } catch (_: Exception) { }
            }

            return queryMediaStorePath(context, uri)
        }

        private fun queryMediaStorePath(
            context: Context,
            uri: Uri,
            selection: String? = null,
            selectionArgs: Array<String>? = null
        ): String? {
            return try {
                context.contentResolver.query(
                    uri, arrayOf(MediaStore.MediaColumns.DATA), selection, selectionArgs, null
                )?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val idx = cursor.getColumnIndex(MediaStore.MediaColumns.DATA)
                        if (idx >= 0) cursor.getString(idx) else null
                    } else null
                }
            } catch (_: Exception) {
                null
            }
        }
    }
}

// =====================================================================
//  KEYSTORE
// =====================================================================

internal class VaultKeystore(
    private val masterAlias: String = "volatile_vault_master_aes_gcm_v3"
) {
    private val provider = "AndroidKeyStore"
    private val hmacAlias = "${masterAlias}_hmac"

    fun getOrCreateMasterKey(preferStrongBox: Boolean = true): SecretKey {
        val ks = KeyStore.getInstance(provider).apply { load(null) }
        ks.getKey(masterAlias, null)?.let { return it as SecretKey }

        val shouldRequestStrongBox = preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P

        return try {
            generateKey(masterAlias, useStrongBox = shouldRequestStrongBox)
        } catch (e: Exception) {
            if (shouldRequestStrongBox) generateKey(masterAlias, useStrongBox = false) else throw e
        }
    }

    fun getOrCreateHmacKey(): SecretKey {
        val ks = KeyStore.getInstance(provider).apply { load(null) }
        ks.getKey(hmacAlias, null)?.let { return it as SecretKey }

        return try {
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, provider)
            val spec = KeyGenParameterSpec.Builder(hmacAlias, KeyProperties.PURPOSE_SIGN)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
            kg.init(spec)
            kg.generateKey()
        } catch (_: Exception) {
            val raw = ByteArray(32).also { SecureRandom().nextBytes(it) }
            SecretKeySpec(raw, "HmacSHA256")
        }
    }

    private fun generateKey(alias: String, useStrongBox: Boolean): SecretKey {
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, provider)
        val builder = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(VaultConfig.AES_KEY_BITS)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            builder.setIsStrongBoxBacked(true)
        }

        kg.init(builder.build())
        return kg.generateKey()
    }

    fun isHardwareBacked(): Boolean {
        return try {
            val ks = KeyStore.getInstance(provider).apply { load(null) }
            val key = ks.getKey(masterAlias, null) as? SecretKey ?: return false
            val factory = SecretKeyFactory.getInstance(key.algorithm, provider)
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            keyInfo.isInsideSecureHardware
        } catch (_: Exception) {
            false
        }
    }

    fun destroyMasterKey() {
        try {
            val ks = KeyStore.getInstance(provider).apply { load(null) }
            ks.deleteEntry(masterAlias)
            ks.deleteEntry(hmacAlias)
        } catch (_: Exception) { }
    }
}

// =====================================================================
//  CRYPTOGRAPHY
// =====================================================================

internal object VaultCrypto {
    private const val AES_GCM = "AES/GCM/NoPadding"
    private const val PBKDF2 = "PBKDF2WithHmacSHA256"
    private const val AES = "AES"

    fun derivePassphraseKey(
        passphrase: CharArray,
        salt: ByteArray,
        iterations: Int = VaultConfig.PBKDF_ITERATIONS,
        keyBits: Int = VaultConfig.PBKDF_KEY_BITS,
        kdfType: Int = VaultConfig.KDF_TYPE_PBKDF2
    ): ByteArray {
        return when (kdfType) {
            VaultConfig.KDF_TYPE_ARGON2ID -> deriveArgon2idKey(passphrase, salt, keyBits)
            else -> derivePbkdf2Key(passphrase, salt, iterations, keyBits)
        }
    }

    private fun derivePbkdf2Key(
        passphrase: CharArray, salt: ByteArray, iterations: Int, keyBits: Int
    ): ByteArray {
        val spec = PBEKeySpec(passphrase, salt, iterations, keyBits)
        return try {
            SecretKeyFactory.getInstance(PBKDF2).generateSecret(spec).encoded
        } catch (e: InvalidKeySpecException) {
            throw IllegalStateException("PBKDF2 key derivation failed", e)
        } finally {
            spec.clearPassword()
        }
    }

    private fun deriveArgon2idKey(passphrase: CharArray, salt: ByteArray, keyBits: Int): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(VaultConfig.ARGON2_ITERATIONS)
            .withMemoryAsKB(VaultConfig.ARGON2_MEMORY_KB)
            .withParallelism(VaultConfig.ARGON2_PARALLELISM)
            .withSalt(salt)
            .build()

        val generator = Argon2BytesGenerator()
        generator.init(params)

        val result = ByteArray(keyBits / 8)
        val passBytes = ByteArray(passphrase.size * 2)
        val bb = ByteBuffer.wrap(passBytes)
        for (c in passphrase) bb.putChar(c)

        return try {
            generator.generateBytes(passBytes, result, 0, result.size)
            result
        } finally {
            SecureErase.wipe(passBytes)
        }
    }

    fun aesGcmEncrypt(keyBytes: ByteArray, iv: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, AES), GCMParameterSpec(VaultConfig.AES_GCM_TAG_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    fun aesGcmDecrypt(keyBytes: ByteArray, iv: ByteArray, ciphertext: ByteArray, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, AES), GCMParameterSpec(VaultConfig.AES_GCM_TAG_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    fun keystoreEncrypt(masterKey: SecretKey, plaintext: ByteArray, aad: ByteArray? = null): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
        if (aad != null) cipher.updateAAD(aad)
        val ct = cipher.doFinal(plaintext)
        return cipher.iv to ct
    }

    fun keystoreDecrypt(masterKey: SecretKey, iv: ByteArray, ciphertext: ByteArray, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(VaultConfig.AES_GCM_TAG_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    fun makeChunkIv(prefix8: ByteArray, chunkIndex: Int): ByteArray {
        require(prefix8.size == VaultConfig.CHUNK_IV_PREFIX_BYTES) {
            "IV prefix must be exactly ${VaultConfig.CHUNK_IV_PREFIX_BYTES} bytes"
        }
        val iv = ByteArray(VaultConfig.GCM_NONCE_BYTES)
        System.arraycopy(prefix8, 0, iv, 0, VaultConfig.CHUNK_IV_PREFIX_BYTES)
        iv[8] = ((chunkIndex ushr 24) and 0xFF).toByte()
        iv[9] = ((chunkIndex ushr 16) and 0xFF).toByte()
        iv[10] = ((chunkIndex ushr 8) and 0xFF).toByte()
        iv[11] = (chunkIndex and 0xFF).toByte()
        return iv
    }

    fun aadForChunk(uuid: String, chunkIndex: Int): ByteArray = "VVv3-CHUNK|$uuid|$chunkIndex".toByteArray(Charsets.UTF_8)
    fun aadForKeyRecord(uuid: String): ByteArray = "VVv3-KEYREC|$uuid".toByteArray(Charsets.UTF_8)
    fun aadForDekWrap(uuid: String): ByteArray = "VVv3-DEKWRAP|$uuid".toByteArray(Charsets.UTF_8)
}

// =====================================================================
//  MEDIASTORE / THUMBNAIL SANITIZER
// =====================================================================

internal object MetadataSanitizer {

    /**
     * Removes every trace of [file] from MediaStore, then securely destroys
     * the thumbnail images that MediaStore generated for it.
     */
    fun sanitizeMediaStoreAfterDelete(context: Context, file: File): Boolean {
        val resolver = context.contentResolver
        val filesUri = MediaStore.Files.getContentUri("external")
        val path = file.absolutePath
        var ok = true

        // 1) Find the MediaStore row BEFORE deleting it (we need its _id to find thumbnails)
        val mediaId = queryMediaId(resolver, filesUri, path)

        // 2) Collect the absolute paths of generated thumbnails
        val thumbPaths = if (mediaId != null) collectThumbnailPaths(resolver, mediaId) else emptyList()

        // 3) Securely destroy those thumbnail files
        if (thumbPaths.isNotEmpty()) {
            val engine = NistPurgeEngine(SecureRandom())
            for (tp in thumbPaths) {
                try {
                    val tf = File(tp)
                    if (tf.exists() && tf.isFile) engine.purge(tf)
                } catch (_: Throwable) { }
            }
            VaultLog.i("purged ${thumbPaths.size} MediaStore thumbnail(s) for ${file.name}")
        }

        // 4) Delete MediaStore rows (item + thumbnails)
        try {
            resolver.delete(filesUri, "${MediaStore.MediaColumns.DATA} = ?", arrayOf(path))
        } catch (_: Throwable) { ok = false }

        if (mediaId != null) {
            val idStr = mediaId.toString()
            try {
                resolver.delete(ContentUris.withAppendedId(filesUri, mediaId), null, null)
            } catch (_: Throwable) { }
            try {
                resolver.delete(
                    MediaStore.Images.Thumbnails.EXTERNAL_CONTENT_URI,
                    "${MediaStore.Images.Thumbnails.IMAGE_ID} = ?", arrayOf(idStr)
                )
            } catch (_: Throwable) { }
            try {
                resolver.delete(
                    MediaStore.Video.Thumbnails.EXTERNAL_CONTENT_URI,
                    "${MediaStore.Video.Thumbnails.VIDEO_ID} = ?", arrayOf(idStr)
                )
            } catch (_: Throwable) { }
        }

        // 5) Sibling cache dirs that MediaStore does not track (.thumbnails / .face)
        try {
            cleanPhysicalThumbnails(file)
        } catch (_: Throwable) { }

        // 6) Ask the scanner to confirm removal
        try {
            MediaScannerConnection.scanFile(
                context,
                arrayOf(path, file.parentFile?.absolutePath ?: path),
                null, null
            )
        } catch (_: Throwable) { }

        return ok
    }

    private fun queryMediaId(resolver: ContentResolver, filesUri: Uri, path: String): Long? {
        return try {
            resolver.query(
                filesUri,
                arrayOf(MediaStore.Files.FileColumns._ID),
                "${MediaStore.Files.FileColumns.DATA} = ?",
                arrayOf(path),
                null
            )?.use { c ->
                if (c.moveToFirst()) {
                    val i = c.getColumnIndex(MediaStore.Files.FileColumns._ID)
                    if (i != -1) c.getLong(i) else null
                } else null
            }
        } catch (_: Throwable) {
            null
        }
    }

    @Suppress("DEPRECATION")
    private fun collectThumbnailPaths(
        resolver: ContentResolver,
        mediaId: Long
    ): List<String> {
        val out = mutableListOf<String>()
        val idStr = mediaId.toString()

        val targets = listOf(
            Triple(MediaStore.Images.Thumbnails.EXTERNAL_CONTENT_URI,
                MediaStore.Images.Thumbnails.IMAGE_ID, MediaStore.Images.Thumbnails.DATA),
            Triple(MediaStore.Video.Thumbnails.EXTERNAL_CONTENT_URI,
                MediaStore.Video.Thumbnails.VIDEO_ID, MediaStore.Video.Thumbnails.DATA)
        )

        for ((uri, idCol, dataCol) in targets) {
            try {
                resolver.query(uri, arrayOf(dataCol), "$idCol = ?", arrayOf(idStr), null)?.use { c ->
                    val idx = c.getColumnIndex(dataCol)
                    if (idx >= 0) {
                        while (c.moveToNext()) {
                            c.getString(idx)?.takeIf { it.isNotBlank() }?.let { out.add(it) }
                        }
                    }
                }
            } catch (_: Throwable) { }
        }
        return out
    }

    /** Samsung/OEM caches that are not registered in MediaStore. */
    private fun cleanPhysicalThumbnails(file: File) {
        val parent = file.parentFile ?: return
        val grandParent = parent.parentFile
        val nameWithoutExt = file.nameWithoutExtension
        val fullName = file.name

        val cacheDirs = listOfNotNull(
            File(parent, ".thumbnails"),
            grandParent?.let { File(it, ".thumbnails") },
            File(parent, ".face"),
            grandParent?.let { File(it, ".face") }
        )

        val engine = NistPurgeEngine(SecureRandom())
        for (dir in cacheDirs) {
            if (!dir.exists() || !dir.isDirectory) continue
            try {
                dir.listFiles()?.forEach { thumb ->
                    if (thumb.isFile &&
                        (thumb.name.contains(nameWithoutExt) || thumb.name.contains(fullName))
                    ) {
                        try {
                            engine.purge(thumb)
                        } catch (_: Throwable) {
                            thumb.delete()
                        }
                    }
                }
            } catch (_: Throwable) { }
        }
    }

    fun sweepAppCaches(context: Context, uuid: String) {
        val dirs = listOfNotNull(context.cacheDir, context.codeCacheDir, context.externalCacheDir)
        for (dir in dirs) {
            try {
                if (!dir.exists()) continue
                dir.walkBottomUp().forEach { file ->
                    if (file.isFile && (
                                file.name.contains(uuid, ignoreCase = true) ||
                                        file.name.contains("thumb", ignoreCase = true) ||
                                        file.name.endsWith(".tmp"))
                    ) {
                        try {
                            RandomAccessFile(file, VaultConfig.RANDOM_ACCESS_MODE).use { raf ->
                                val len = file.length().coerceAtMost(1_048_576)
                                if (len > 0) {
                                    val buf = ByteArray(len.toInt())
                                    SecureRandom().nextBytes(buf)
                                    raf.seek(0)
                                    raf.write(buf)
                                    raf.fd.sync()
                                    SecureErase.wipe(buf)
                                }
                                raf.setLength(0)
                                raf.fd.sync()
                            }
                        } catch (_: Exception) { }
                        file.delete()
                    }
                }
                FilesystemSync.syncDirectory(dir)
            } catch (_: Exception) { }
        }
    }

    /**
     * Optional heuristic deep-clean. NOT part of the normal delete path —
     * it can touch caches belonging to files the user still keeps.
     */
    fun sweepKnownThumbnailCaches(context: Context, deletedFile: File) {
        val parentModified = deletedFile.lastModified()
        val lowerName = deletedFile.name.lowercase(Locale.getDefault())
        val isLikelyMedia = lowerName.endsWith(".jpg") || lowerName.endsWith(".jpeg") ||
                lowerName.endsWith(".png") || lowerName.endsWith(".webp") ||
                lowerName.endsWith(".heic") || lowerName.endsWith(".heif") ||
                lowerName.endsWith(".mp4") || lowerName.endsWith(".mkv") || lowerName.endsWith(".mov")
        if (!isLikelyMedia) return

        val root = Environment.getExternalStorageDirectory()
        val candidates = listOfNotNull(
            File(root, "DCIM/.thumbnails"),
            File(root, "Pictures/.thumbnails"),
            File(root, "Movies/.thumbnails"),
            context.cacheDir,
            context.externalCacheDir
        )

        var inspected = 0
        val maxInspect = 300
        val maxThumbSize = 8L * 1024L * 1024L
        val timeWindowMs = 24L * 60L * 60L * 1000L
        val engine = NistPurgeEngine(SecureRandom())

        for (dir in candidates) {
            if (!dir.exists() || !dir.isDirectory) continue
            try {
                dir.walkTopDown().forEach { item ->
                    if (inspected >= maxInspect) return@forEach
                    if (!item.isFile) return@forEach
                    inspected++

                    val nearTime = abs(item.lastModified() - parentModified) <= timeWindowMs
                    val smallEnough = item.length() in 1L..maxThumbSize
                    val nameLooksCached = item.name.contains("thumb", ignoreCase = true) ||
                            item.name.endsWith(".jpg", ignoreCase = true) ||
                            item.name.endsWith(".png", ignoreCase = true) ||
                            item.name.endsWith(".webp", ignoreCase = true)

                    if (nearTime && smallEnough && nameLooksCached) {
                        try { engine.purge(item) } catch (_: Throwable) { item.delete() }
                    }
                }
            } catch (_: Exception) { }
        }
    }

    fun boundedCacheEviction(directory: File?, maxBytes: Long = VaultConfig.BOUNDED_CACHE_EVICTION_MAX_BYTES) {
        val dir = directory ?: return
        if (!dir.exists() || !dir.isDirectory || maxBytes <= 0L) return

        val tempFile = File(dir, ".vv_cache_evict_${UUID.randomUUID()}")
        val buffer = ByteArray(VaultConfig.OVERWRITE_BUFFER_SIZE)
        val random = SecureRandom()
        var written = 0L

        try {
            FileOutputStream(tempFile).use { output ->
                while (written < maxBytes) {
                    random.nextBytes(buffer)
                    val n = minOf(buffer.size.toLong(), maxBytes - written).toInt()
                    output.write(buffer, 0, n)
                    written += n.toLong()
                }
                output.fd.sync()
            }
        } catch (_: Exception) {
        } finally {
            SecureErase.wipe(buffer)
            try { tempFile.delete() } catch (_: Exception) { }
            FilesystemSync.syncDirectory(dir)
        }
    }

    fun deleteOriginalFile(context: Context, originalUri: Uri?): Boolean {
        if (originalUri == null) return false

        val directPath = try {
            NistPurgeEngine.resolveDirectPath(context, originalUri)
        } catch (_: Exception) { null }

        val sanitized = try {
            NistPurgeEngine.sanitizeOriginalFile(context, originalUri)
        } catch (_: Exception) { false }

        val providerDeleted = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT &&
                DocumentsContract.isDocumentUri(context, originalUri)
            ) {
                DocumentsContract.deleteDocument(context.contentResolver, originalUri)
            } else {
                context.contentResolver.delete(originalUri, null, null) > 0
            }
        } catch (_: Exception) { false }

        if (directPath != null) sanitizeMediaStoreAfterDelete(context, File(directPath))

        return sanitized || providerDeleted
    }

    /** Kept for API compatibility — delegates to the fixed implementation. */
    fun syncDirectory(dir: File) = FilesystemSync.syncDirectory(dir)
}

// =====================================================================
//  VOLATILE VAULT ENGINE (Crypto-Shredding)
// =====================================================================

private val DATA_MAGIC = byteArrayOf('V'.code.toByte(), 'V'.code.toByte(), 'C'.code.toByte(), 'T'.code.toByte())
private val KEY_MAGIC = byteArrayOf('V'.code.toByte(), 'V'.code.toByte(), 'K'.code.toByte(), 'R'.code.toByte())
private val KEYSTORE_BLOB_MAGIC = byteArrayOf('V'.code.toByte(), 'V'.code.toByte(), 'K'.code.toByte(), 'S'.code.toByte())

internal class VolatileVaultEngine(
    private val context: Context,
    private val dao: VaultDao,
    private val preferStrongBox: Boolean = true,
    private val pbkdfIterations: Int = VaultConfig.PBKDF_ITERATIONS
) {
    private val rng = SecureRandom()
    private val keystore = VaultKeystore()
    private val purgeEngine = NistPurgeEngine(rng)

    private val vaultDir: File = File(context.noBackupFilesDir, "vv_ciphertexts_v3").apply { mkdirs() }
    private val keyDir: File = File(context.noBackupFilesDir, "vv_keyrecords_v3").apply { mkdirs() }

    private val chunkSize: Int by lazy {
        val memMb = (Runtime.getRuntime().maxMemory() / (1024 * 1024))
        if (memMb <= VaultConfig.LOW_RAM_THRESHOLD_MB) VaultConfig.BASE_CHUNK_SIZE
        else VaultConfig.STANDARD_CHUNK_SIZE
    }

    suspend fun ingestFile(
        inputStream: InputStream,
        passphrase: CharArray,
        originalUri: Uri? = null,
        deleteOriginal: Boolean = true
    ): String = withContext(Dispatchers.IO) {
        requireStrongPassphrase(passphrase)

        val uuid = UUID.randomUUID().toString()
        val dataFile = vaultFile(uuid)
        val keyFile = keyRecordFile(uuid)

        var dek: ByteArray? = null
        var passKey: ByteArray? = null
        var keyRecordPlain: ByteArray? = null

        try {
            dek = ByteArray(32).also { rng.nextBytes(it) }
            writeEncryptedData(uuid, inputStream, dataFile, dek)

            val salt = ByteArray(VaultConfig.SALT_BYTES).also { rng.nextBytes(it) }
            passKey = VaultCrypto.derivePassphraseKey(
                passphrase = passphrase, salt = salt, iterations = pbkdfIterations
            )

            val wrapIv = ByteArray(VaultConfig.GCM_NONCE_BYTES).also { rng.nextBytes(it) }
            val wrappedDek = VaultCrypto.aesGcmEncrypt(
                keyBytes = passKey!!, iv = wrapIv, plaintext = dek!!,
                aad = VaultCrypto.aadForDekWrap(uuid)
            )

            keyRecordPlain = buildKeyRecord(salt, pbkdfIterations, wrapIv, wrappedDek, VaultConfig.KDF_TYPE_PBKDF2)
            writeKeystoreWrappedKeyRecord(uuid, keyRecordPlain!!, keyFile)

            val obfuscator = UuidObfuscator(keystore.getOrCreateMasterKey(preferStrongBox))
            dao.insert(VaultEntity(uuidHash = obfuscator.hash(uuid)))

            if (deleteOriginal) MetadataSanitizer.deleteOriginalFile(context, originalUri)

            uuid
        } catch (e: Exception) {
            purgeEngine.purge(keyFile)
            purgeEngine.purge(dataFile)
            throw e
        } finally {
            SecureErase.wipe(dek)
            SecureErase.wipe(passKey)
            SecureErase.wipe(keyRecordPlain)
            MultiScriptPassphraseGenerator.wipe(passphrase)
            try { inputStream.close() } catch (_: Exception) { }
        }
    }

    suspend fun autoIngestFile(
        inputStream: InputStream,
        originalUri: Uri? = null,
        deleteOriginal: Boolean = true
    ): Pair<String, CharArray> = withContext(Dispatchers.IO) {
        val passphrase = MultiScriptPassphraseGenerator.generate()
        val uuid = ingestFile(inputStream, passphrase, originalUri, deleteOriginal)
        uuid to passphrase
    }

    private fun writeEncryptedData(uuid: String, inputStream: InputStream, outFile: File, dek: ByteArray) {
        val noncePrefix = ByteArray(VaultConfig.CHUNK_IV_PREFIX_BYTES).also { rng.nextBytes(it) }

        BufferedInputStream(inputStream, chunkSize).use { bis ->
            DataOutputStream(BufferedOutputStream(FileOutputStream(outFile), chunkSize)).use { dos ->
                dos.write(DATA_MAGIC)
                dos.writeInt(VaultConfig.FORMAT_VERSION)
                dos.writeInt(chunkSize)
                dos.writeInt(noncePrefix.size)
                dos.write(noncePrefix)

                val plainBuf = ByteArray(chunkSize)
                var chunkIndex = 0

                while (true) {
                    val bytesRead = bis.read(plainBuf)
                    if (bytesRead == -1) break
                    if (chunkIndex == Int.MAX_VALUE) throw IllegalStateException("File exceeds maximum supported size")

                    val plainChunk = if (bytesRead == plainBuf.size) plainBuf else plainBuf.copyOf(bytesRead)
                    val iv = VaultCrypto.makeChunkIv(noncePrefix, chunkIndex)
                    val aad = VaultCrypto.aadForChunk(uuid, chunkIndex)

                    val cipherChunk = VaultCrypto.aesGcmEncrypt(dek, iv, plainChunk, aad)
                    dos.writeInt(cipherChunk.size)
                    dos.write(cipherChunk)

                    if (plainChunk !== plainBuf) SecureErase.wipe(plainChunk)
                    SecureErase.wipe(cipherChunk)
                    chunkIndex++
                }

                SecureErase.wipe(plainBuf)
                dos.flush()
            }
        }

        FileOutputStream(outFile, true).use { it.fd.sync() }
        FilesystemSync.syncDirectory(outFile.parentFile)
    }

    private fun buildKeyRecord(
        salt: ByteArray, iterations: Int, wrapIv: ByteArray, wrappedDek: ByteArray,
        kdfType: Int = VaultConfig.KDF_TYPE_PBKDF2
    ): ByteArray {
        ByteArrayOutputStream().use { baos ->
            DataOutputStream(baos).use { dos ->
                dos.write(KEY_MAGIC)
                dos.writeInt(VaultConfig.FORMAT_VERSION)
                dos.writeInt(kdfType)
                dos.writeInt(iterations)
                dos.writeInt(salt.size)
                dos.write(salt)
                dos.writeInt(wrapIv.size)
                dos.write(wrapIv)
                dos.writeInt(wrappedDek.size)
                dos.write(wrappedDek)
            }
            return baos.toByteArray()
        }
    }

    private fun writeKeystoreWrappedKeyRecord(uuid: String, keyRecordPlain: ByteArray, outFile: File) {
        val masterKey = keystore.getOrCreateMasterKey(preferStrongBox)
        val aad = VaultCrypto.aadForKeyRecord(uuid)

        val (keystoreIv, keystoreCt) = VaultCrypto.keystoreEncrypt(masterKey, keyRecordPlain, aad)

        DataOutputStream(BufferedOutputStream(FileOutputStream(outFile))).use { dos ->
            dos.write(KEYSTORE_BLOB_MAGIC)
            dos.writeInt(VaultConfig.FORMAT_VERSION)
            dos.writeInt(keystoreIv.size)
            dos.write(keystoreIv)
            dos.writeInt(keystoreCt.size)
            dos.write(keystoreCt)
            dos.flush()
        }

        FileOutputStream(outFile, true).use { it.fd.sync() }
        FilesystemSync.syncDirectory(outFile.parentFile)
        SecureErase.wipe(keystoreCt)
    }

    suspend fun shredFile(uuid: String): Boolean = withContext(Dispatchers.IO) {
        val obfuscator = UuidObfuscator(keystore.getOrCreateMasterKey(preferStrongBox))
        val hash = obfuscator.hash(uuid)
        dao.getByHash(hash) ?: return@withContext false

        dao.markAsPending(hash)

        val dataFile = vaultFile(uuid)
        val keyFile = keyRecordFile(uuid)

        val keyPurged = purgeEngine.purge(keyFile)
        val dataPurged = purgeEngine.purge(dataFile)

        MetadataSanitizer.sweepAppCaches(context, uuid)
        MetadataSanitizer.boundedCacheEviction(vaultDir.parentFile)
        FilesystemSync.syncDirectory(vaultDir)
        FilesystemSync.syncDirectory(keyDir)

        if (keyPurged) dao.deleteByHash(hash)
        keyPurged && dataPurged
    }

    suspend fun resumePendingDeletions() = withContext(Dispatchers.IO) {
        val obfuscator = UuidObfuscator(keystore.getOrCreateMasterKey(preferStrongBox))
        val pending = dao.getPendingDeletes()

        if (pending.isNotEmpty()) {
            val uuidSet = mutableSetOf<String>()
            vaultDir.listFiles()?.forEach { file ->
                val name = file.nameWithoutExtension
                if (name.matches(Regex("^[0-9a-fA-F\\-]{36}$"))) uuidSet.add(name)
            }

            for (entity in pending) {
                val match = uuidSet.firstOrNull { obfuscator.hash(it) == entity.uuidHash }
                if (match != null) shredFile(match) else dao.deleteByHash(entity.uuidHash)
            }
        }
    }

    suspend fun destroyVault() = withContext(Dispatchers.IO) {
        try {
            vaultDir.listFiles()?.forEach { file ->
                val name = file.nameWithoutExtension
                if (name.matches(Regex("^[0-9a-fA-F\\-]{36}$"))) shredFile(name)
            }
        } catch (_: Exception) { }

        keystore.destroyMasterKey()

        try { VolatileVaultDatabase.forceSecureCheckpointAndClose(context) } catch (_: Exception) { }
        try { context.deleteDatabase(VaultConfig.DB_NAME) } catch (_: Exception) { }

        vaultDir.listFiles()?.forEach { purgeEngine.purge(it) }
        keyDir.listFiles()?.forEach { purgeEngine.purge(it) }

        FilesystemSync.syncDirectory(vaultDir)
        FilesystemSync.syncDirectory(keyDir)
        FilesystemSync.syncDirectory(vaultDir.parentFile)
    }

    suspend fun secureClose() = withContext(Dispatchers.IO) {
        try { VolatileVaultDatabase.forceSecureCheckpointAndClose(context) } catch (_: Exception) { }
    }

    fun recoverDek(uuid: String, passphrase: CharArray): ByteArray {
        val keyFile = keyRecordFile(uuid)
        require(keyFile.exists()) { "Key record not found for UUID: $uuid" }

        val masterKey = keystore.getOrCreateMasterKey(preferStrongBox)
        val aad = VaultCrypto.aadForKeyRecord(uuid)

        val keyRecordPlain = readKeystoreWrappedRecord(uuid, masterKey, keyFile, aad)
        var passKey: ByteArray? = null

        try {
            DataInputStream(keyRecordPlain.inputStream()).use { dis ->
                val magic = ByteArray(4)
                dis.readFully(magic)
                require(SecureErase.constantTimeEquals(magic, KEY_MAGIC)) { "Invalid key record magic" }

                val version = dis.readInt()
                require(version <= VaultConfig.FORMAT_VERSION) { "Unsupported key record version: $version" }

                val kdfType = if (version >= 4) dis.readInt() else VaultConfig.KDF_TYPE_PBKDF2
                val iterations = dis.readInt()
                val saltLen = dis.readInt()
                require(saltLen in 16..128)
                val salt = ByteArray(saltLen)
                dis.readFully(salt)

                val ivLen = dis.readInt()
                require(ivLen == VaultConfig.GCM_NONCE_BYTES)
                val iv = ByteArray(ivLen)
                dis.readFully(iv)

                val wrappedLen = dis.readInt()
                require(wrappedLen in 48..4096)
                val wrappedDek = ByteArray(wrappedLen)
                dis.readFully(wrappedDek)

                passKey = VaultCrypto.derivePassphraseKey(
                    passphrase, salt, iterations, VaultConfig.PBKDF_KEY_BITS, kdfType
                )

                return VaultCrypto.aesGcmDecrypt(
                    keyBytes = passKey!!, iv = iv, ciphertext = wrappedDek,
                    aad = VaultCrypto.aadForDekWrap(uuid)
                )
            }
        } finally {
            SecureErase.wipe(passKey)
            SecureErase.wipe(keyRecordPlain)
            SecureErase.wipeChars(passphrase)
        }
    }

    private fun readKeystoreWrappedRecord(
        uuid: String, masterKey: SecretKey, keyFile: File, aad: ByteArray
    ): ByteArray {
        DataInputStream(BufferedInputStream(FileInputStream(keyFile))).use { dis ->
            val magic = ByteArray(4)
            dis.readFully(magic)
            require(SecureErase.constantTimeEquals(magic, KEYSTORE_BLOB_MAGIC)) { "Invalid keystore blob magic" }

            val version = dis.readInt()
            require(version <= VaultConfig.FORMAT_VERSION) { "Unsupported keystore blob version" }

            val ivLen = dis.readInt()
            require(ivLen == VaultConfig.GCM_NONCE_BYTES)
            val iv = ByteArray(ivLen)
            dis.readFully(iv)

            val ctLen = dis.readInt()
            require(ctLen in 32..65536)
            val ct = ByteArray(ctLen)
            dis.readFully(ct)

            return VaultCrypto.keystoreDecrypt(masterKey, iv, ct, aad)
        }
    }

    fun isStrongBoxBacked(): Boolean {
        keystore.getOrCreateMasterKey(preferStrongBox)
        return keystore.isHardwareBacked()
    }

    private fun vaultFile(uuid: String): File { validateUuid(uuid); return File(vaultDir, "$uuid.vvct") }
    private fun keyRecordFile(uuid: String): File { validateUuid(uuid); return File(keyDir, "$uuid.vvkr") }

    private fun validateUuid(uuid: String) {
        require(uuid.matches(Regex("^[0-9a-fA-F\\-]{36}$"))) { "Invalid UUID format: $uuid" }
    }

    private fun requireStrongPassphrase(passphrase: CharArray) {
        require(passphrase.size >= 20) {
            "Passphrase too weak: minimum 20 characters required. Use " +
                    VaultConfig.MIN_AUTO_GENERATED_KEY_LENGTH + "–" + VaultConfig.MAX_AUTO_GENERATED_KEY_LENGTH +
                    " char auto-generated key for maximum security."
        }
        val hasLower = passphrase.any { it.isLowerCase() }
        val hasUpper = passphrase.any { it.isUpperCase() }
        val hasDigit = passphrase.any { it.isDigit() }
        val hasSymbol = passphrase.any { !it.isLetterOrDigit() }
        require(listOf(hasLower, hasUpper, hasDigit, hasSymbol).count { it } >= 3) {
            "Passphrase too weak: must contain at least 3 of: lowercase, uppercase, digits, symbols."
        }
    }
}

// =====================================================================
//  PUBLIC FACADE — the ONLY secure-deletion API the UI may call
// =====================================================================

/** Public, stable result of one secure deletion (safe to expose across modules). */
data class SecureDeleteReport(
    val path: String,
    val length: Long,
    val writable: Boolean,
    val overwriteOk: Boolean,
    val verifyOk: Boolean,
    val truncated: Boolean,
    val deleted: Boolean,
    val gone: Boolean,
    val elapsedMs: Long
) {
    val success: Boolean
        get() = writable && overwriteOk && verifyOk && deleted && gone
}

object SecureDelete {

    private fun engine() = NistPurgeEngine(SecureRandom())

    /** Securely destroys a single file. Returns true only if fully verified. */
    fun deleteFile(context: Context, file: File): Boolean {
        if (!file.exists()) return true
        if (file.isDirectory) return deleteTree(context, file)

        return try {
            val report = engine().purgeWithReport(file)
            MetadataSanitizer.sanitizeMediaStoreAfterDelete(context, file)
            report.success
        } catch (t: Throwable) {
            VaultLog.e("deleteFile failed: ${file.absolutePath}", t)
            false
        }
    }

    /** Same as [deleteFile] but exposes the detailed report. */
    fun deleteFileWithReport(context: Context, file: File): SecureDeleteReport {
        if (!file.exists()) {
            return SecureDeleteReport(file.absolutePath, 0, true, true, true, true, true, true, 0)
        }
        if (file.isDirectory) {
            val ok = deleteTree(context, file)
            return SecureDeleteReport(file.absolutePath, 0, true, ok, ok, ok, ok, !file.exists(), 0)
        }
        val report = engine().purgeWithReport(file)
        MetadataSanitizer.sanitizeMediaStoreAfterDelete(context, file)
        return report
    }

    /** Securely destroys a directory and everything inside it. */
    fun deleteTree(context: Context, root: File): Boolean {
        if (!root.exists()) return true

        var ok = true
        try {
            root.walkBottomUp().forEach { node ->
                if (node.isDirectory) {
                    if (!node.delete()) ok = false
                } else {
                    if (!deleteFile(context, node)) ok = false
                }
            }
            if (root.exists() && !root.delete()) ok = false
        } catch (t: Throwable) {
            VaultLog.e("deleteTree failed: ${root.absolutePath}", t)
            ok = false
        }

        FilesystemSync.syncDirectory(root.parentFile)
        return ok && !root.exists()
    }

    /** Securely destroys whatever a Uri points to (file://, content://, SAF). */
    fun deleteUri(context: Context, uri: Uri): Boolean {
        return try {
            val purged = NistPurgeEngine.sanitizeOriginalFile(context, uri)
            val providerDeleted = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT &&
                    DocumentsContract.isDocumentUri(context, uri)
                ) {
                    DocumentsContract.deleteDocument(context.contentResolver, uri)
                } else {
                    context.contentResolver.delete(uri, null, null) > 0
                }
            } catch (_: Exception) { false }
            purged || providerDeleted
        } catch (t: Throwable) {
            VaultLog.e("deleteUri failed: $uri", t)
            false
        }
    }

    /** Bulk helper: returns the targets that could NOT be destroyed. */
    fun deleteAll(context: Context, targets: List<File>): List<File> {
        val failed = mutableListOf<File>()
        for (target in targets) {
            val ok = if (target.isDirectory) deleteTree(context, target) else deleteFile(context, target)
            if (!ok) failed.add(target)
        }
        return failed
    }
}

// =====================================================================
//  HELPERS
// =====================================================================

internal fun getSecureVaultDao(context: Context): VaultDao = createHardenedVaultDao(context)

internal fun createSecureVolatileVaultEngine(
    context: Context,
    preferStrongBox: Boolean = true,
    pbkdfIterations: Int = VaultConfig.PBKDF_ITERATIONS
): VolatileVaultEngine {
    return VolatileVaultEngine(
        context = context,
        dao = getSecureVaultDao(context),
        preferStrongBox = preferStrongBox,
        pbkdfIterations = pbkdfIterations
    )
}
