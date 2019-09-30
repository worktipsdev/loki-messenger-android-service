package org.whispersystems.signalservice.loki.api

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Hex
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.utilities.remove05PrefixIfNeeded

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
    companion object {
        private val signatureVersion = 1
    }

    private val curve = Curve25519.getInstance(Curve25519.BEST)

    public data class Quote(
        public val quotedMessageTimestamp: Long,
        public val quoteeHexEncodedPublicKey: String,
        public val quotedMessageBody: String,
        public val quotedMessageServerId: Long? = null
    ) {
        internal fun jsonMap(): Map<String, Any> {
            return mapOf("id" to quotedMessageTimestamp, "author" to quoteeHexEncodedPublicKey, "text" to quotedMessageBody)
        }
    }

    constructor(hexEncodedPublicKey: String, displayName: String, body: String, timestamp: Long, type: String, quote: Quote?)
        : this(null, hexEncodedPublicKey, displayName, body, timestamp, type, quote, null, null)

    constructor(hexEncodedPublicKey: String, displayName: String, body: String, timestamp: Long, type: String, quote: Quote?, signature: String? = null, signatureVersion: Int? = null)
        : this(null, hexEncodedPublicKey, displayName, body, timestamp, type, quote, signature, signatureVersion)

    private fun jsonMap(): Map<String, Any> {
        val annotationValue = mutableMapOf<String, Any>("timestamp" to timestamp)
        if (quote != null) { annotationValue["quote"] = quote.jsonMap() }

        // Add in signature and the version if we have it
        if (signature != null && signatureVersion != null) {
            annotationValue["sig"] = signature
            annotationValue["sigver"] = signatureVersion
        }

        val annotation = sortedMapOf("type" to type, "value" to annotationValue.toSortedMap())
        val sortedList = listOf(annotation).sortedBy { it["type"] as? String }
        val map = mutableMapOf("text" to body, "annotations" to sortedList)

        if (quote?.quotedMessageServerId != null) { map["reply_to"] = quote.quotedMessageServerId }
        return map.toSortedMap()
    }

    internal fun sign(privateKey: ByteArray): LokiGroupMessage? {
        val unsigned = copy(signature = null, signatureVersion = null)

        val objectToSign = unsigned.jsonMap().toMutableMap()
        objectToSign["version"] = Companion.signatureVersion

        val unsignedJson = JsonUtil.toJson(objectToSign)
        return try {
            val signature = curve.calculateSignature(privateKey, unsignedJson.toByteArray())
            copy(signature = Hex.toStringCondensed(signature), signatureVersion = Companion.signatureVersion)
        } catch(e: Exception) {
            Log.w("Loki", "Failed to sign LokiGroupMessage. ${e.message}")
            null
        }
    }

    internal fun verify(): Boolean {
        if (signature == null || signatureVersion == null) { return false }
        val unsigned = copy(signature = null, signatureVersion = null)
        val objectToCompare = unsigned.jsonMap().toMutableMap()
        objectToCompare["version"] = signatureVersion
        val json = JsonUtil.toJson(objectToCompare.toSortedMap())

        val pubKey = Hex.fromStringCondensed(hexEncodedPublicKey.remove05PrefixIfNeeded())
        return try {
            curve.verifySignature(pubKey, json.toByteArray(), Hex.fromStringCondensed(signature))
        } catch(e: Exception) {
            Log.w("Loki", "Failed to verify LokiGroupMessage. ${e.message}")
            false
        }
    }

    internal fun toJSON(): String {
        return JsonUtil.toJson(jsonMap())
    }
}