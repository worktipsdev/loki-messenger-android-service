package org.whispersystems.signalservice.loki.api

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Hex
import org.whispersystems.signalservice.loki.utilities.removing05PrefixIfNeeded

public data class LokiGroupMessage(
    public val serverID: Long?,
    public val hexEncodedPublicKey: String,
    public val displayName: String,
    public val body: String,
    public val timestamp: Long,
    public val type: String,
    public val quote: Quote?,
    public val signature: Signature?
) {

    // region Settings
    companion object {
        private val curve = Curve25519.getInstance(Curve25519.BEST)
        private val signatureVersion: Long = 1
    }
    // endregion

    // region Types
    public data class Quote(
        public val quotedMessageTimestamp: Long,
        public val quoteeHexEncodedPublicKey: String,
        public val quotedMessageBody: String,
        public val quotedMessageServerID: Long? = null
    )

    public data class Signature(
        public val data: ByteArray,
        public val version: Long
    )
    // endregion

    // region Initialization
    constructor(hexEncodedPublicKey: String, displayName: String, body: String, timestamp: Long, type: String, quote: Quote?)
        : this(null, hexEncodedPublicKey, displayName, body, timestamp, type, quote, null)
    // endregion

    // region Crypto
    internal fun sign(privateKey: ByteArray): LokiGroupMessage? {
        val data = getValidationData(signatureVersion)
        if (data == null) {
            Log.d("Loki", "Failed to sign group chat message.")
            return null
        }
        try {
            val signatureData = curve.calculateSignature(privateKey, data)
            val signature = Signature(signatureData, signatureVersion)
            return copy(signature = signature)
        } catch(e: Exception) {
            Log.d("Loki", "Failed to sign group chat message due to error: ${e.message}.")
            return null
        }
    }

    internal fun hasValidSignature(): Boolean {
        if (signature == null) { return false }
        val data = getValidationData(signature.version) ?: return false
        val publicKey = Hex.fromStringCondensed(hexEncodedPublicKey.removing05PrefixIfNeeded())
        try {
            return curve.verifySignature(publicKey, data, signature.data)
        } catch(e: Exception) {
            Log.d("Loki", "Failed to verify group chat message due to error: ${e.message}.")
            return false
        }
    }
    // endregion

    // region Parsing
    internal fun toJSON(): Map<String, Any> {
        val value = mutableMapOf<String, Any>( "timestamp" to timestamp )
        if (quote != null) {
            value["quote"] = mapOf( "id" to quote.quotedMessageTimestamp, "author" to quote.quoteeHexEncodedPublicKey, "text" to quote.quotedMessageBody )
        }
        if (signature != null) {
            value["sig"] = Hex.toStringCondensed(signature.data)
            value["sigver"] = signature.version
        }
        val annotation = mapOf( "type" to type, "value" to value )
        val result = mutableMapOf( "text" to body, "annotations" to listOf( annotation ) )
        if (quote?.quotedMessageServerID != null) {
            result["reply_to"] = quote.quotedMessageServerID
        }
        return result
    }
    // endregion

    // region Convenience
    private fun getValidationData(signatureVersion: Long): ByteArray? {
        var string = "${body.trim()}$timestamp)"
        if (quote != null) {
            string += "${quote.quotedMessageTimestamp}${quote.quoteeHexEncodedPublicKey}${quote.quotedMessageBody.trim()}"
            if (quote.quotedMessageServerID != null) {
                string += "${quote.quotedMessageServerID}"
            }
        }
        string += "$signatureVersion"
        try {
            return string.toByteArray(Charsets.UTF_8)
        } catch (exception: Exception) {
            return null
        }
    }
    // endregion
}
