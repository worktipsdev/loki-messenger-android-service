package org.whispersystems.signalservice.loki.api

public data class LokiGroupMessage(
        public val serverID: Long?,
        public val hexEncodedPublicKey: String,
        public val displayName: String,
        public val body: String,
        public val timestamp: Long,
        public val type: String,
        public val isDeleted: Boolean
) {

    constructor(hexEncodedPublicKey: String, displayName: String, body: String, timestamp: Long, type: String)
        : this(null, hexEncodedPublicKey, displayName, body, timestamp, type, false)

    internal fun toJSON(): String {
        val intermediate = "{ \"timestamp\" : $timestamp, \"from\" : \"$displayName\", \"source\" : \"$hexEncodedPublicKey\" }"
        return "{ \"text\" : \"$body\", \"annotations\" : [ { \"type\" : \"$type\", \"value\" : $intermediate } ] }"
    }
}