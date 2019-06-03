package org.whispersystems.signalservice.loki.crypto

import org.whispersystems.signalservice.internal.util.Base64
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * Based on the desktop messenger's proof of work implementation.
 * Ref: libloki/proof-of-work.js
 */
object ProofOfWork {
    private val nonceSize = 8

    private val nonceTrialCount = 10 // TODO: Implement dynamic POW from service node

    /**
     * Calculate a proof of work with the given configuration (based on https://bitmessage.org/wiki/Proof_of_work).
     *
     * @param data The message data.
     * @param hexEncodedPublicKey The message recipient's hex encoded public key.
     * @param timestamp The message timestamp in milliseconds.
     * @param ttl Int The message time to live in milliseconds.
     * @return String? A nonce or `nil` if the nonce couldn't be calculated.
     */
    @kotlin.ExperimentalUnsignedTypes
    fun calculate(data: String, hexEncodedPublicKey: String, timestamp: Long, ttl: Int): String? {
        try {
            val sha512 = MessageDigest.getInstance("SHA-512")

            val payload = createPayload(hexEncodedPublicKey, data, timestamp, ttl)
            val target = calculateTarget(ttl, payload.size, nonceTrialCount)

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
        val payloadAsString = timestamp.toString() + ttl.toString() + hexEncodedPublicKey + data
        return payloadAsString.toByteArray()
    }

    @kotlin.ExperimentalUnsignedTypes
    private fun calculateTarget(ttl: Int, payloadSize: Int, nonceTrialCount: Int): ULong {
        val two16 = BigInteger.valueOf(2).pow(16) - 1.toBigInteger()
        val two64 = BigInteger.valueOf(2).pow(64) - 1.toBigInteger()

        val totalSize = (payloadSize + nonceSize).toBigInteger()
        val ttlInSeconds = (ttl / 1000).toBigInteger()

        val intermediate1 = (ttlInSeconds * totalSize) / two16
        val intermediate2 = totalSize + intermediate1
        val denominator = nonceTrialCount.toBigInteger() * intermediate2

        return (two64 / denominator).toULong()
    }
}

// region Convenience
@kotlin.ExperimentalUnsignedTypes
private fun BigInteger.toULong() = toLong().toULong()
private fun Long.toByteArray() = ByteBuffer.allocate(8).putLong(this).array()
@kotlin.ExperimentalUnsignedTypes
private fun ByteArray.toULong() = ByteBuffer.wrap(this).long.toULong()
// endregion