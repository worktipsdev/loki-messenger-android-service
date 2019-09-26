package org.whispersystems.signalservice.loki.api

import org.whispersystems.signalservice.internal.util.JsonUtil

public data class LokiGroupMessage(
    public val serverID: Long?,
    public val hexEncodedPublicKey: String,
    public val displayName: String,
    public val body: String,
    public val timestamp: Long,
    public val type: String,
    public val quote: Quote?
) {

    public data class Quote(
        public val quotedMessageTimestamp: Long,
        public val quoteeHexEncodedPublicKey: String,
        public val quotedMessageBody: String
    ) {
        internal fun jsonMap(): Map<String, Any> {
            return mapOf("id" to quotedMessageTimestamp, "author" to quoteeHexEncodedPublicKey, "text" to quotedMessageBody)
        }
    }

    constructor(hexEncodedPublicKey: String, displayName: String, body: String, timestamp: Long, type: String, quote: Quote?)
        : this(null, hexEncodedPublicKey, displayName, body, timestamp, type, quote)

    internal fun toJSON(): String {
        val annotationValue = mutableMapOf("timestamp" to timestamp, "from" to displayName, "source" to hexEncodedPublicKey)
        if (quote != null) { annotationValue["quote"] = quote.jsonMap() }
        val annotation = mapOf("type" to type, "value" to annotationValue)
        val map = mapOf("text" to body, "annotations" to listOf(annotation))

        return JsonUtil.toJson(map)
    }
}