package org.whispersystems.signalservice.loki.api

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Hex
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.utilities.removing05PrefixIfNeeded

public data class LokiGroupMessage(
    public val serverID: Long?,
    public val hexEncodedPublicKey: String,
    public val displayName: String,
    public val body: String,
    public val timestamp: Long,
    public val type: String,
    public val quote: Quote?,
    public val signature: String?,
    public val signatureVersion: Int?
) {
    private val curve = Curve25519.getInstance(Curve25519.BEST)

    // region Settings
    companion object {
        private val signatureVersion = 1
    }
    // endregion

    // region Types
    public data class Quote(
        public val quotedMessageTimestamp: Long,
        public val quoteeHexEncodedPublicKey: String,
        public val quotedMessageBody: String,
        public val quotedMessageServerID: Long? = null
    ) {
        internal fun toJSON(): Map<String, Any> {
            return mapOf( "id" to quotedMessageTimestamp, "author" to quoteeHexEncodedPublicKey, "text" to quotedMessageBody )
        }
    }
    // endregion

    // region Initialization
    constructor(hexEncodedPublicKey: String, displayName: String, body: String, timestamp: Long, type: String, quote: Quote?)
        : this(null, hexEncodedPublicKey, displayName, body, timestamp, type, quote, null, null)

    constructor(hexEncodedPublicKey: String, displayName: String, body: String, timestamp: Long, type: String, quote: Quote?, signature: String? = null, signatureVersion: Int? = null)
        : this(null, hexEncodedPublicKey, displayName, body, timestamp, type, quote, signature, signatureVersion)
    // endregion

    // region Crypto
    internal fun sign(privateKey: ByteArray): LokiGroupMessage? {
        val unsignedMessage = copy(signature = null, signatureVersion = null)
        val objectToSign = unsignedMessage.toJSON().toMutableMap()
        objectToSign["version"] = Companion.signatureVersion
        val unsignedJSON = JsonUtil.toJson(sort(objectToSign))
        try {
            val signature = curve.calculateSignature(privateKey, unsignedJSON.toByteArray())
            return copy(signature = Hex.toStringCondensed(signature), signatureVersion = Companion.signatureVersion)
        } catch(e: Exception) {
            Log.w("Loki", "Failed to sign group chat message due to error: ${e.message}.")
            return null
        }
    }

    internal fun hasValidSignature(): Boolean {
        if (signature == null || signatureVersion == null) { return false }
        val unsignedMessage = copy(signature = null, signatureVersion = null)
        val objectToCompare = unsignedMessage.toJSON().toMutableMap()
        objectToCompare["version"] = signatureVersion
        val json = JsonUtil.toJson(sort(objectToCompare))
        val publicKey = Hex.fromStringCondensed(hexEncodedPublicKey.removing05PrefixIfNeeded())
        try {
            return curve.verifySignature(publicKey, json.toByteArray(), Hex.fromStringCondensed(signature))
        } catch(e: Exception) {
            Log.w("Loki", "Failed to verify group chat message due to error: ${e.message}.")
            return false
        }
    }
    // endregion

    // region Parsing
    internal fun toJSON(): Map<String, Any> {
        val annotationAsJSON = mutableMapOf<String, Any>( "timestamp" to timestamp )
        if (quote != null) { annotationAsJSON["quote"] = quote.toJSON() }
        if (signature != null && signatureVersion != null) {
            annotationAsJSON["sig"] = signature
            annotationAsJSON["sigver"] = signatureVersion
        }
        val annotation = mapOf( "type" to type, "value" to annotationAsJSON )
        val annotations = listOf( annotation ).sortedBy { it["type"] as? String }
        val json = mutableMapOf( "text" to body, "annotations" to annotations )
        if (quote?.quotedMessageServerID != null) { json["reply_to"] = quote.quotedMessageServerID }
        return json
    }

    internal fun toJSONString(): String {
        return JsonUtil.toJson(toJSON())
    }
    // endregion
}

// region Sorting
fun <T: Any> sort(item: T): T {
    return try {
        if (item is Map<*,*>) {
            val map = item as Map<Comparable<Any>, Any>
            return map.mapValues { sort(it.value) }.toSortedMap() as T
        } else if (item is List<*>) {
            return (item as List<Any>).map { sort(it) } as T
        }
        item
    } catch (e: Exception) {
        item
    }
}
// endregion