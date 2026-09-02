package com.example.lock.crypto

import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.SecureRandom
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class MediumShortEncryptionEngine(
    private val maxPlaintextBytes: Int = DEFAULT_MAX_PLAINTEXT_BYTES
) {

    companion object {
        private const val VERSION: Byte = 0x07
        private const val SALT_BYTES = 16
        private const val NONCE_BYTES = 12
        private const val KEY_BYTES = 32
        private const val TAG_BITS = 128
        private const val HEADER_BYTES = 1 + SALT_BYTES + NONCE_BYTES

        private const val FLAG_UNCOMPRESSED: Byte = 0x00
        private const val FLAG_COMPRESSED: Byte = 0x01

        private val DOMAIN_INFO = "com.example.lock.MSE.v7.aes-gcm".toByteArray(Charsets.US_ASCII)
        private val DOMAIN_AAD = "com.example.lock.MSE.v7.aad".toByteArray(Charsets.US_ASCII)

        const val DEFAULT_MAX_PLAINTEXT_BYTES = 2 * 1024 * 1024

        private const val PBKDF2_ROUNDS = 600_000
        private const val PBKDF2_ALGO = "PBKDF2WithHmacSHA512"
    }

    private val random = SecureRandom()

    fun encrypt(plainText: String, password: CharArray): String {
        var raw: ByteArray? = null
        var candidate: ByteArray? = null
        var stored: ByteArray? = null
        var payload: ByteArray? = null
        var padded: ByteArray? = null
        var salt: ByteArray? = null
        var nonce: ByteArray? = null
        var header: ByteArray? = null
        var aad: ByteArray? = null
        var master: ByteArray? = null
        var encKey: ByteArray? = null
        var ciphertext: ByteArray? = null
        var packet: ByteArray? = null

        try {
            raw = plainText.toByteArray(Charsets.UTF_8)
            require(raw.size <= maxPlaintextBytes)

            candidate = gzipCompress(raw)
            val flag: Byte
            if (candidate != null && candidate.size + 1 < raw.size) {
                stored = candidate
                candidate = null
                flag = FLAG_COMPRESSED
            } else {
                wipe(candidate)
                stored = raw
                raw = null
                flag = FLAG_UNCOMPRESSED
            }

            payload = ByteArray(1 + stored!!.size)
            payload[0] = flag
            System.arraycopy(stored, 0, payload, 1, stored.size)

            padded = pad(payload)
            wipe(payload)
            payload = null

            salt = ByteArray(SALT_BYTES)
            nonce = ByteArray(NONCE_BYTES)
            random.nextBytes(salt)
            random.nextBytes(nonce)

            header = ByteArray(HEADER_BYTES)
            header[0] = VERSION
            System.arraycopy(salt, 0, header, 1, SALT_BYTES)
            System.arraycopy(nonce, 0, header, 1 + SALT_BYTES, NONCE_BYTES)

            aad = buildAad(header)
            master = derivePbkdf2(password, salt)
            encKey = hkdfExpand(master, DOMAIN_INFO, KEY_BYTES)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encKey, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(aad)
            ciphertext = cipher.doFinal(padded)

            packet = ByteArray(header.size + ciphertext.size)
            System.arraycopy(header, 0, packet, 0, header.size)
            System.arraycopy(ciphertext, 0, packet, header.size, ciphertext.size)

            return Base64.encodeToString(packet, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        } finally {
            wipe(raw)
            wipe(candidate)
            wipe(stored)
            wipe(payload)
            wipe(padded)
            wipe(salt)
            wipe(nonce)
            wipe(header)
            wipe(aad)
            wipe(master)
            wipe(encKey)
            wipe(ciphertext)
            wipe(packet)
            password.fill('\u0000')
        }
    }

    fun decrypt(encryptedBase64: String, password: CharArray): String? {
        var packet: ByteArray? = null
        var header: ByteArray? = null
        var salt: ByteArray? = null
        var nonce: ByteArray? = null
        var aad: ByteArray? = null
        var ciphertext: ByteArray? = null
        var master: ByteArray? = null
        var encKey: ByteArray? = null
        var decrypted: ByteArray? = null
        var unpadded: ByteArray? = null
        var finalBytes: ByteArray? = null

        return try {
            if (encryptedBase64.isEmpty()) return null
            packet = Base64.decode(encryptedBase64, Base64.URL_SAFE or Base64.NO_WRAP)
            if (packet.size < HEADER_BYTES + 16) return null
            if (packet[0] != VERSION) return null

            header = packet.copyOfRange(0, HEADER_BYTES)
            salt = header.copyOfRange(1, 1 + SALT_BYTES)
            nonce = header.copyOfRange(1 + SALT_BYTES, HEADER_BYTES)
            ciphertext = packet.copyOfRange(HEADER_BYTES, packet.size)

            aad = buildAad(header)
            master = derivePbkdf2(password, salt)
            encKey = hkdfExpand(master, DOMAIN_INFO, KEY_BYTES)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(encKey, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(aad)
            decrypted = cipher.doFinal(ciphertext)

            unpadded = unpad(decrypted) ?: return null
            if (unpadded.isEmpty()) return null

            val flag = unpadded[0]
            val storedData = unpadded.copyOfRange(1, unpadded.size)

            finalBytes = when (flag) {
                FLAG_UNCOMPRESSED -> {
                    if (storedData.size > maxPlaintextBytes) return null
                    storedData
                }
                FLAG_COMPRESSED -> {
                    try {
                        gzipDecompressBounded(storedData, maxPlaintextBytes)
                    } catch (_: Exception) {
                        return null
                    }
                }
                else -> return null
            }

            decodeUtf8Strict(finalBytes)
        } catch (_: Exception) {
            null
        } finally {
            wipe(packet)
            wipe(header)
            wipe(salt)
            wipe(nonce)
            wipe(aad)
            wipe(ciphertext)
            wipe(master)
            wipe(encKey)
            wipe(decrypted)
            wipe(unpadded)
            wipe(finalBytes)
            password.fill('\u0000')
        }
    }

    private fun buildAad(header: ByteArray): ByteArray {
        val out = ByteArray(DOMAIN_AAD.size + header.size)
        System.arraycopy(DOMAIN_AAD, 0, out, 0, DOMAIN_AAD.size)
        System.arraycopy(header, 0, out, DOMAIN_AAD.size, header.size)
        return out
    }

    private fun derivePbkdf2(password: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(password, salt, PBKDF2_ROUNDS, KEY_BYTES * 8)
        var tmp: ByteArray? = null
        return try {
            tmp = SecretKeyFactory.getInstance(PBKDF2_ALGO).generateSecret(spec).encoded
            tmp.copyOf()
        } finally {
            spec.clearPassword()
            wipe(tmp)
        }
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        val out = ByteArray(outLen)
        var prev = ByteArray(0)
        var pos = 0
        var ctr = 1
        try {
            while (pos < outLen) {
                mac.init(SecretKeySpec(prk, "HmacSHA512"))
                mac.update(prev)
                mac.update(info)
                mac.update(ctr.toByte())
                val block = mac.doFinal()
                val cp = minOf(block.size, outLen - pos)
                System.arraycopy(block, 0, out, pos, cp)
                wipe(prev)
                prev = block
                pos += cp
                ctr++
            }
            return out
        } catch (t: Throwable) {
            out.fill(0)
            throw t
        } finally {
            wipe(prev)
        }
    }

    private fun pad(data: ByteArray): ByteArray {
        val bucket = when {
            data.size < 512 -> 64
            data.size < 2048 -> 128
            else -> 256
        }
        var padLen = bucket - (data.size % bucket)
        if (padLen == 0) padLen = bucket
        val out = ByteArray(data.size + padLen)
        System.arraycopy(data, 0, out, 0, data.size)
        out[out.lastIndex] = padLen.toByte()
        return out
    }

    private fun unpad(data: ByteArray): ByteArray? {
        if (data.isEmpty()) return null
        val padLen = data.last().toInt() and 0xFF
        if (padLen !in 1..256) return null
        if (padLen > data.size) return null
        val end = data.size - padLen
        if (end < 1) return null
        var bad = 0
        for (i in end until data.lastIndex) {
            bad = bad or (data[i].toInt() and 0xFF)
        }
        if (bad != 0) return null
        return data.copyOfRange(0, end)
    }

    private fun gzipCompress(data: ByteArray): ByteArray? {
        return try {
            val bos = ByteArrayOutputStream(data.size)
            GZIPOutputStream(bos).use { it.write(data) }
            val b = bos.toByteArray()
            if (b.size >= data.size) null else b
        } catch (_: Exception) {
            null
        }
    }

    private fun gzipDecompressBounded(data: ByteArray, max: Int): ByteArray {
        val bos = ByteArrayOutputStream(minOf(8192, max))
        val buf = ByteArray(8192)
        var total = 0
        GZIPInputStream(ByteArrayInputStream(data)).use { gz ->
            while (true) {
                val n = gz.read(buf)
                if (n < 0) break
                if (n == 0) continue
                total = Math.addExact(total, n)
                if (total > max) throw IllegalArgumentException("too large")
                bos.write(buf, 0, n)
            }
        }
        return bos.toByteArray()
    }

    private fun decodeUtf8Strict(bytes: ByteArray): String {
        val dec = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return dec.decode(ByteBuffer.wrap(bytes)).toString()
    }

    private fun wipe(b: ByteArray?) {
        b?.fill(0)
    }
}