package com.example.lock

import android.content.Context
import com.example.lock.safe_delete.CancellationToken
import com.example.lock.safe_delete.PurgeOptions
import com.example.lock.safe_delete.SecureDelete
import com.example.lock.safe_delete.SessionReport
import java.io.File

data class MetadataSafeDeleteResult(
    val success: Boolean,
    val report: SessionReport?,
    val message: String
)

object MetadataSafeDeleteBridge {

    fun secureDelete(
        context: Context,
        file: File,
        cancellationToken: CancellationToken = com.example.lock.safe_delete.NeverCancelled
    ): MetadataSafeDeleteResult {
        if (!com.example.lock.safe_delete.TargetResolver.hasAllFilesAccess()) {
            return MetadataSafeDeleteResult(
                success = false,
                report = null,
                message = "All files access is not granted"
            )
        }

        return try {
            val report = SecureDelete.purgeFiles(
                context = context.applicationContext,
                files = listOf(file),
                options = PurgeOptions.MILITARY,
                cancel = cancellationToken
            )
            val target = report.reports.singleOrNull()
            val success = target?.success == true && target.gone && !target.weakDeletion
            val message = when {
                success -> "secure delete completed"
                target == null -> "secure delete returned no target report"
                target.error != null -> target.error
                    ?: "secure delete failed"
                target.alreadyAbsent -> "original file was already absent"
                else -> "secure delete did not reach a verified gone state"
            }
            MetadataSafeDeleteResult(success, report, message)
        } catch (e: Exception) {
            MetadataSafeDeleteResult(
                success = false,
                report = null,
                message = e.message ?: e.javaClass.simpleName
            )
        }
    }
}
