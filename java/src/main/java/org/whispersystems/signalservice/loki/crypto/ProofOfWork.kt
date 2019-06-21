package org.whispersystems.signalservice.loki.crypto

import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.loki.api.LokiAPI
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * Based on the desktop messenger's proof of work implementation. For more information, see libloki/proof-of-work.js.
 */
object ProofOfWork {

    // region Settings
    private val nonceSize = 8
    // endregion

    // region Implementation
    @kotlin.ExperimentalUnsignedTypes
    fun calculate(data: String, hexEncodedPublicKey: String, timestamp: Long, ttl: Int): String? {
        try {
            val sha512 = MessageDigest.getInstance("SHA-512")
            val payload = createPayload(hexEncodedPublicKey, data, timestamp, ttl)
            val target = calculateTarget(ttl, payload.size)
            var currentTrialValue = ULong.MAX_VALUE
            var nonce: Long = 0
            val initialHash = sha512.digest(payload)
            while (currentTrialValue > target) {
                nonce += 1
                // This is different from bitmessage's PoW implementation
                // newHash = hash(nonce + hash(data)) → hash(nonce + initialHash)
                val newHash = sha512.digest(nonce.toByteArray() + initialHash)
                currentTrialValue = newHash.sliceArray(0 until 8).toULong()
            }
            return Base64.encodeBytes(nonce.toByteArray())
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    private fun createPayload(hexEncodedPublicKey: String, data: String, timestamp: Long, ttl: Int): ByteArray  {
        return (timestamp.toString() + ttl.toString() + hexEncodedPublicKey + data).toByteArray()
    }

    @kotlin.ExperimentalUnsignedTypes
    private fun calculateTarget(ttl: Int, payloadSize: Int): ULong {
        val x1 = BigInteger.valueOf(2).pow(16) - 1.toBigInteger()
        val x2 = BigInteger.valueOf(2).pow(64) - 1.toBigInteger()
        val size = (payloadSize + nonceSize).toBigInteger()
        val ttlInSeconds = (ttl / 1000).toBigInteger()
        val x3 = (ttlInSeconds * size) / x1
        val x4 = size + x3
        val x5 = LokiAPI.powDifficulty.toBigInteger() * x4
        return (x2 / x5).toULong()
    }
    // endregion
}

// region Convenience
@kotlin.ExperimentalUnsignedTypes
private fun BigInteger.toULong() = toLong().toULong()
private fun Long.toByteArray() = ByteBuffer.allocate(8).putLong(this).array()
@kotlin.ExperimentalUnsignedTypes
private fun ByteArray.toULong() = ByteBuffer.wrap(this).long.toULong()
// endregion