package com.example.lock.safe_delete

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

internal interface PatternGenerator {
    val label: String
    val verifiable: Boolean
    fun fill(buffer: ByteArray, offsetInStream: Long, length: Int)
}

internal class ZeroGenerator : PatternGenerator {
    override val label: String = "zeroes"
    override val verifiable: Boolean = true

    override fun fill(buffer: ByteArray, offsetInStream: Long, length: Int) {
        java.util.Arrays.fill(buffer, 0, length, 0)
    }
}

internal class OnesGenerator : PatternGenerator {
    override val label: String = "ones"
    override val verifiable: Boolean = true

    override fun fill(buffer: ByteArray, offsetInStream: Long, length: Int) {
        java.util.Arrays.fill(buffer, 0, length, 0xFF.toByte())
    }
}

internal class AesCtrGenerator(key: ByteArray, override val label: String) : PatternGenerator {

    override val verifiable: Boolean = true

    private val cipher: Cipher = Cipher.getInstance("AES/ECB/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
    }

    private var counterScratch: ByteArray = ByteArray(MAX_BLOCKS_PER_CALL * BLOCK_BYTES)
    private var streamScratch: ByteArray = ByteArray(MAX_BLOCKS_PER_CALL * BLOCK_BYTES)

    override fun fill(buffer: ByteArray, offsetInStream: Long, length: Int) {
        if (length <= 0) return

        val firstBlockIndex = offsetInStream / BLOCK_BYTES
        val intraBlockOffset = (offsetInStream % BLOCK_BYTES).toInt()
        var blockIndex = firstBlockIndex
        var produced = 0

        if (intraBlockOffset != 0) {
            val usable = minOf(BLOCK_BYTES - intraBlockOffset, length)
            if (usable <= 0) return
            val stream = keystream(blockIndex, 1)
            System.arraycopy(
                stream, intraBlockOffset, buffer, 0, minOf(usable, BLOCK_BYTES - intraBlockOffset)
            )
            produced = minOf(usable, BLOCK_BYTES - intraBlockOffset)
            blockIndex++
        }

        while (produced < length) {
            val remaining = length - produced
            val blocksNeeded = (remaining + BLOCK_BYTES - 1) / BLOCK_BYTES
            val blocks = minOf(blocksNeeded, MAX_BLOCKS_PER_CALL)
            val stream = keystream(blockIndex, blocks)
            val usable = minOf(blocks * BLOCK_BYTES, remaining)
            System.arraycopy(stream, 0, buffer, produced, usable)
            produced += usable
            blockIndex += blocks
        }
    }

    private fun keystream(startBlockIndex: Long, blockCount: Int): ByteArray {
        val total = blockCount * BLOCK_BYTES
        if (counterScratch.size < total) {
            counterScratch = ByteArray(total)
            streamScratch = ByteArray(total)
        }
        var index = startBlockIndex
        var cursor = 0
        repeat(blockCount) {
            writeCounterBlock(counterScratch, cursor, index)
            index++
            cursor += BLOCK_BYTES
        }
        cipher.doFinal(counterScratch, 0, total, streamScratch, 0)
        return streamScratch
    }

    private fun writeCounterBlock(destination: ByteArray, offset: Int, counter: Long) {
        for (i in 0 until 8) {
            destination[offset + i] = 0
        }
        var value = counter
        for (i in 15 downTo 8) {
            destination[offset + i] = (value and 0xFF).toByte()
            value = value ushr 8
        }
    }

    companion object {
        private const val BLOCK_BYTES = 16
        private const val MAX_BLOCKS_PER_CALL = 4096
    }
}

internal class OsRandomGenerator(private val rng: SecureRandom) : PatternGenerator {
    override val label: String = "os-random"
    override val verifiable: Boolean = false

    override fun fill(buffer: ByteArray, offsetInStream: Long, length: Int) {
        if (length <= 0) return
        if (length == buffer.size) {
            rng.nextBytes(buffer)
            return
        }
        val temp = ByteArray(length)
        rng.nextBytes(temp)
        System.arraycopy(temp, 0, buffer, 0, length)
        Zeroize.bytes(temp)
    }
}

data class VerifyOutcome(
    val ok: Boolean,
    val bytesVerified: Long,
    val firstMismatchOffset: Long,
    val reason: String? = null
)

internal class OverwriteEngine(
    private val level: SanitizationLevel,
    private val verifyMode: VerifyMode,
    private val rng: SecureRandom,
    private val bufferBytes: Int = SecureDeleteConfig.overwriteBufferBytes(),
    private val verifyBufferBytes: Int = SecureDeleteConfig.verifyBufferBytes()
) {

    fun passSpecs(): List<PassSpec> = SecureDeleteConfig.passesFor(level, verifyMode)

    fun newGenerator(spec: PassSpec): PatternGenerator = when (spec.pattern) {
        PassPattern.ZEROES -> ZeroGenerator()
        PassPattern.ONES -> OnesGenerator()
        PassPattern.OS_RANDOM -> OsRandomGenerator(rng)
        PassPattern.DETERMINISTIC_RANDOM -> {
            val key = ByteArray(32)
            rng.nextBytes(key)
            AesCtrGenerator(key, spec.label)
        }
    }

    fun overwrite(
        channel: FileChannel,
        length: Long,
        spec: PassSpec,
        generator: PatternGenerator,
        cancel: CancellationToken,
        onProgress: (Long) -> Unit
    ): Boolean {
        if (length <= 0L) return true
        val buffer = ByteArray(bufferBytes.coerceAtLeast(SecureDeleteConfig.PATTERN_BLOCK_BYTES))
        val wrapper = ByteBuffer.wrap(buffer)
        var offset = 0L

        return try {
            channel.position(0L)
            while (offset < length) {
                if (cancel.isCancelled) {
                    Zeroize.bytes(buffer)
                    return false
                }
                val size = minOf(buffer.size.toLong(), length - offset).toInt()
                generator.fill(buffer, offset, size)
                wrapper.clear()
                wrapper.limit(size)
                var written = 0
                while (written < size) {
                    wrapper.position(written)
                    val wrote = channel.write(wrapper)
                    if (wrote <= 0) {
                        Zeroize.bytes(buffer)
                        SecureLog.w("short write at offset ${offset + written} of ${spec.label}")
                        return false
                    }
                    written += wrote
                }
                offset += size
                onProgress(offset)
            }
            FsOps.force(channel)
            true
        } catch (t: Throwable) {
            SecureLog.e("overwrite pass ${spec.label} failed: ${t.message}", t)
            false
        } finally {
            Zeroize.bytes(buffer)
        }
    }

    fun verify(
        channel: FileChannel,
        length: Long,
        generator: PatternGenerator,
        cancel: CancellationToken,
        onProgress: (Long) -> Unit
    ): VerifyOutcome {
        if (length <= 0L) return VerifyOutcome(true, 0L, -1L)
        if (!generator.verifiable) {
            return VerifyOutcome(false, 0L, -1L, "pattern ${generator.label} is not reproducible")
        }

        val expected = ByteArray(verifyBufferBytes.coerceAtLeast(SecureDeleteConfig.PATTERN_BLOCK_BYTES))
        val actual = ByteArray(expected.size)
        val readBuffer = ByteBuffer.wrap(actual)
        var offset = 0L

        return try {
            channel.position(0L)
            while (offset < length) {
                if (cancel.isCancelled) {
                    return VerifyOutcome(false, offset, -1L, "cancelled")
                }
                val size = minOf(expected.size.toLong(), length - offset).toInt()
                generator.fill(expected, offset, size)

                readBuffer.clear()
                readBuffer.limit(size)
                var read = 0
                while (read < size) {
                    val got = channel.read(readBuffer)
                    if (got <= 0) break
                    read += got
                }
                if (read < size) {
                    return VerifyOutcome(
                        false,
                        offset,
                        offset + read,
                        "short read at offset ${offset + read}"
                    )
                }
                for (i in 0 until size) {
                    if (expected[i] != actual[i]) {
                        return VerifyOutcome(false, offset + i, offset + i, "mismatch")
                    }
                }
                offset += size
                onProgress(offset)
            }
            VerifyOutcome(true, offset, -1L)
        } catch (t: Throwable) {
            SecureLog.e("verify failed: ${t.message}", t)
            VerifyOutcome(false, offset, -1L, t.message)
        } finally {
            Zeroize.bytes(expected)
            Zeroize.bytes(actual)
        }
    }

    fun level(): SanitizationLevel = level

    fun verifyMode(): VerifyMode = verifyMode
}
