package org.whispersystems.signalservice.loki.api

public data class LokiGroupMessage(
        public val id: String?,
        public val hexEncodedPublicKey: String,
        public val displayName: String,
        public val body: String,
        public var timestamp: Long
) {

    constructor(hexEncodedPublicKey: String, displayName: String, body: String, timestamp: Long)
        : this(null, hexEncodedPublicKey, displayName, body, timestamp)

    internal fun toJSON(): String {
        val intermediate = "{ \"timestamp\" : $timestamp, \"from\" : \"$displayName\", \"source\" : \"$hexEncodedPublicKey\" }"
        return "{ \"text\" : \"$body\", \"annotations\" : [ { \"type\" : \"network.loki.messenger.publicChat\", \"value\" : $intermediate } ] }"
    }
}