package com.example.lock.safe_delete

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.io.File
import java.io.RandomAccessFile
import java.security.SecureRandom

internal object LedgerKeyProvider {

    private const val KEY_FILE_NAME = "sd_ledger.key"
    private const val KEY_BYTES = 32

    fun key(context: Context): ByteArray {
        val file = File(context.noBackupFilesDir, KEY_FILE_NAME)
        if (file.exists() && file.length() == KEY_BYTES.toLong()) {
            return try {
                RandomAccessFile(file, "r").use { raf ->
                    val key = ByteArray(KEY_BYTES)
                    raf.readFully(key)
                    key
                }
            } catch (t: Throwable) {
                SecureLog.w("ledger key read failed: ${t.message}")
                ByteArray(0)
            }
        }

        val key = ByteArray(KEY_BYTES)
        SecureRandom().nextBytes(key)
        return try {
            RandomAccessFile(file, "rw").use { raf ->
                raf.setLength(0L)
                raf.write(key)
                raf.fd.sync()
            }
            try {
                android.system.Os.chmod(file.absolutePath, FsOps.MODE_OWNER_READ_WRITE)
            } catch (t: Throwable) {
                SecureLog.d("ledger key chmod skipped")
            }
            FsOps.syncDirectory(file.parentFile)
            key
        } catch (t: Throwable) {
            SecureLog.w("ledger key persist failed: ${t.message}")
            Zeroize.bytes(key)
            ByteArray(0)
        }
    }

    fun destroy(context: Context): Boolean {
        val file = File(context.noBackupFilesDir, KEY_FILE_NAME)
        if (!file.exists()) return true
        var wiped = false
        try {
            RandomAccessFile(file, "rw").use { raf ->
                val length = raf.length()
                if (length > 0L) {
                    val buffer = ByteArray(minOf(length, 4096L).toInt())
                    val rng = SecureRandom()
                    rng.nextBytes(buffer)
                    var position = 0L
                    while (position < length) {
                        raf.seek(position)
                        val size = minOf(buffer.size.toLong(), length - position).toInt()
                        raf.write(buffer, 0, size)
                        position += size
                    }
                    raf.setLength(0L)
                    raf.fd.sync()
                    Zeroize.bytes(buffer)
                    wiped = true
                }
            }
        } catch (t: Throwable) {
            SecureLog.w("ledger key wipe failed: ${t.message}")
        }
        val removed = FsOps.unlink(file)
        FsOps.syncDirectory(file.parentFile)
        return wiped && removed
    }
}

data class LedgerEntry(
    val id: String,
    val timestampMs: Long,
    val length: Long,
    val level: String,
    val passes: Int,
    val verifiedBytes: Long,
    val success: Boolean,
    val fsType: String,
    val residuals: Int
)

internal class SqliteAuditLedger private constructor(context: Context) : AuditSink, AutoCloseable {

    private val helper = object : SQLiteOpenHelper(context.applicationContext, SecureDeleteConfig.LEDGER_DB_NAME, null, DB_VERSION) {
        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL(
                """
                CREATE TABLE IF NOT EXISTS erasure_events (
                    id TEXT PRIMARY KEY,
                    ts INTEGER NOT NULL,
                    identity TEXT NOT NULL,
                    length INTEGER NOT NULL,
                    level TEXT NOT NULL,
                    passes INTEGER NOT NULL,
                    verified INTEGER NOT NULL,
                    success INTEGER NOT NULL,
                    fstype TEXT NOT NULL,
                    residuals INTEGER NOT NULL
                )
                """.trimIndent()
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_events_ts ON erasure_events(ts)")
            applyHardening(db)
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            db.execSQL("DROP TABLE IF EXISTS erasure_events")
            onCreate(db)
        }

        override fun onOpen(db: SQLiteDatabase) {
            if (!db.isReadOnly) applyHardening(db)
        }
    }

    private fun applyHardening(db: SQLiteDatabase) {
        val pragmas = listOf(
            "PRAGMA secure_delete = ON",
            "PRAGMA synchronous = FULL",
            "PRAGMA journal_mode = TRUNCATE",
            "PRAGMA temp_store = MEMORY"
        )
        for (pragma in pragmas) {
            try {
                db.rawQuery(pragma, null).use { cursor ->
                    cursor.moveToFirst()
                }
            } catch (t: Throwable) {
                SecureLog.d("ledger pragma skipped: ${Sanitizer.of(t)}")
            }
        }
    }

    override fun record(event: AuditEvent) {
        try {
            val db = helper.writableDatabase
            val values = ContentValues().apply {
                put("id", event.id)
                put("ts", event.timestampMs)
                put("identity", event.identityHash)
                put("length", event.length)
                put("level", event.level.name)
                put("passes", event.passes)
                put("verified", event.verifiedBytes)
                put("success", if (event.success) 1 else 0)
                put("fstype", event.fsType)
                put("residuals", event.residualCount)
            }
            db.insertWithOnConflict("erasure_events", null, values, SQLiteDatabase.CONFLICT_REPLACE)
            pruneInternal(db)
        } catch (t: Throwable) {
            SecureLog.w("ledger insert failed: ${t.message}")
        }
    }

    fun recent(limit: Int): List<LedgerEntry> {
        val out = mutableListOf<LedgerEntry>()
        var cursor: Cursor? = null
        try {
            cursor = helper.readableDatabase.query(
                "erasure_events",
                arrayOf("id", "ts", "length", "level", "passes", "verified", "success", "fstype", "residuals"),
                null,
                null,
                null,
                null,
                "ts DESC",
                limit.coerceAtLeast(1).toString()
            )
            while (cursor.moveToNext()) {
                out.add(
                    LedgerEntry(
                        id = cursor.getString(0),
                        timestampMs = cursor.getLong(1),
                        length = cursor.getLong(2),
                        level = cursor.getString(3),
                        passes = cursor.getInt(4),
                        verifiedBytes = cursor.getLong(5),
                        success = cursor.getInt(6) == 1,
                        fsType = cursor.getString(7),
                        residuals = cursor.getInt(8)
                    )
                )
            }
        } catch (t: Throwable) {
            SecureLog.w("ledger read failed: ${t.message}")
        } finally {
            try {
                cursor?.close()
            } catch (ignored: Throwable) {
            }
        }
        return out
    }

    fun pendingFailures(limit: Int): List<LedgerEntry> = recent(limit).filter { !it.success }

    private fun pruneInternal(db: SQLiteDatabase) {
        try {
            val count = db.rawQuery("SELECT COUNT(*) FROM erasure_events", null).use { cursor ->
                if (cursor.moveToFirst()) cursor.getLong(0) else 0L
            }
            if (count > SecureDeleteConfig.LEDGER_MAX_ROWS) {
                db.execSQL(
                    "DELETE FROM erasure_events WHERE id IN (" +
                        "SELECT id FROM erasure_events ORDER BY ts ASC LIMIT " +
                        SecureDeleteConfig.LEDGER_PRUNE_BATCH + ")"
                )
            }
        } catch (t: Throwable) {
            SecureLog.d("ledger prune skipped: ${t.message}")
        }
    }

    override fun close() {
        try {
            helper.close()
        } catch (ignored: Throwable) {
        }
    }

    companion object {
        private const val DB_VERSION = 1

        fun open(context: Context): SqliteAuditLedger? {
            if (!SecureDeleteConfig.LEDGER_AVAILABLE) return null
            return try {
                SqliteAuditLedger(context)
            } catch (t: Throwable) {
                SecureLog.w("ledger unavailable: ${Sanitizer.of(t)}")
                null
            }
        }

        fun identityHash(context: Context, value: String): String {
            val key = LedgerKeyProvider.key(context)
            if (key.isEmpty()) {
                SecureLog.w("ledger key unavailable; identity will not be stored")
                return ""
            }
            return try {
                Digest.hmacSha256Hex(key, value.toByteArray(Charsets.UTF_8)).substring(0, 32)
            } finally {
                Zeroize.bytes(key)
            }
        }
    }
}

internal object LedgerMaintenance {

    fun secureDestroy(context: Context): Boolean {
        var ok = true
        val dbFile = context.getDatabasePath(SecureDeleteConfig.LEDGER_DB_NAME)
        val dir = dbFile.parentFile

        val ledger = SqliteAuditLedger.open(context)
        if (ledger != null) {
            try {
                ledger.recent(1)
            } catch (ignored: Throwable) {
            }
            ledger.close()
        }

        val targets = listOf(
            dbFile,
            File(dbFile.absolutePath + "-journal"),
            File(dbFile.absolutePath + "-wal"),
            File(dbFile.absolutePath + "-shm")
        )

        for (file in targets) {
            if (!file.exists()) continue
            ok = wipeFile(file) && ok
        }

        ok = LedgerKeyProvider.destroy(context) && ok
        FsOps.syncDirectory(dir)
        SecureLog.i("ledger destroyed: ok=$ok")
        return ok
    }

    private fun wipeFile(file: File): Boolean {
        val length = file.length()
        var overwritten = false
        try {
            RandomAccessFile(file, "rw").use { raf ->
                if (length > 0L) {
                    val buffer = ByteArray(minOf(length, 65536L).toInt())
                    val rng = SecureRandom()
                    var written = 0L
                    while (written < length) {
                        rng.nextBytes(buffer)
                        raf.seek(written)
                        val size = minOf(buffer.size.toLong(), length - written).toInt()
                        raf.write(buffer, 0, size)
                        written += size
                    }
                    raf.fd.sync()
                    Zeroize.bytes(buffer)
                    overwritten = true
                }
                raf.setLength(0L)
                raf.fd.sync()
            }
        } catch (t: Throwable) {
            SecureLog.w("ledger file wipe failed: ${Sanitizer.of(t, file.absolutePath, file.name)}")
        }
        val removed = FsOps.unlink(file)
        return (overwritten || length == 0L) && removed
    }
}
