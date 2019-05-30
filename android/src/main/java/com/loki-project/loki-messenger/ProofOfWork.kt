package com.`loki-project`.`loki-messenger`

import android.util.Base64
import org.whispersystems.signalservice.BuildConfig
import java.lang.Exception
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest

// Custom extensions
private fun Long.toByteArray() = ByteBuffer.allocate(8).putLong(this).array()
private fun ByteArray.toLong() = ByteBuffer.wrap(this).long
private fun ByteArray.toULong() = this.toLong().toULong()

/**
 * The main proof of work logic.
 *
 * This was copied from the desktop messenger.
 * Ref: libloki/proof-of-work.js
 */
object ProofOfWork {
    private const val nonceLength = 8
    private val nonceTrials: Int
        get() = when {
            BuildConfig.DEBUG -> 10
            else -> 100
        }

    /**
     * Calculate a proof of work with the given configuration
     * @param data The data
     * @param pubKey A hex encoded pubKey
     * @param timestamp The timestamp in milliseconds
     * @param ttl Int The time to live in milliseconds
     * @return String? A nonce string or nil if it failed
     */
    fun calculate(data: String, pubKey: String, timestamp: Long, ttl: Int): String? {
        try {
            val sha512 = MessageDigest.getInstance("SHA-512")

            // PoW calculations
            val payload = createPayload(pubKey, data, timestamp, ttl)
            val target = calculateTarget(ttl, payloadLength = payload.size, nonceTrials = nonceTrials)

            // Start with the max value
            var trialValue = ULong.MAX_VALUE
            val initialHash = sha512.digest(payload)
            var nonce: Long = 0

            while (trialValue > target) {
                // Increment nonce
                nonce += 1

                // This is different to the bitmessage PoW
                // resultHash = hash(nonce + hash(data)) ==> hash(nonce + initialHash)
                val resultHash = sha512.digest(nonce.toByteArray() + initialHash)
                val trialValueArray = resultHash.sliceArray(IntRange(0, 7))
                trialValue = trialValueArray.toULong()
            }

            return Base64.encodeToString(nonce.toByteArray(), Base64.DEFAULT)
        } catch (e: Exception) {
            e.printStackTrace()
        }

        return null
    }

    private fun createPayload(pubKey: String, data: String, timestamp: Long, ttl: Int): ByteArray  {
        val payloadString = timestamp.toString() + ttl.toString() + pubKey + data
        return payloadString.toByteArray()
    }

    private fun calculateTarget(ttl: Int, payloadLength: Int, nonceTrials: Int): ULong {
        val two16 = BigInteger.valueOf(2).pow(16) - 1.toBigInteger()
        val two64 = BigInteger.valueOf(2).pow(64) - 1.toBigInteger()

        // Do all the calculations
        val totalLength = (payloadLength + nonceLength).toBigInteger()
        val ttlInSeconds = (ttl / 1000).toBigInteger()
        val ttlMult = ttlInSeconds * totalLength

        // ULong values
        val innerFrac = ttlMult / two16
        val lenPlusInnerFrac = totalLength + innerFrac
        val denominator = nonceTrials.toBigInteger() * lenPlusInnerFrac

        return (two64 / denominator).toLong().toULong()
    }
}