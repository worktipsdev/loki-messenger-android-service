package org.whispersystems.signalservice.loki.api

internal data class LokiGroupMessage(
        internal val id: String?,
        internal val hexEncodedPublicKey: String,
        internal val displayName: String,
        internal val body: String,
        internal var timestamp: Long
) {

    constructor(hexEncodedPublicKey: String, displayName: String, body: String, timestamp: Long)
        : this(null, hexEncodedPublicKey, displayName, body, timestamp)

    internal fun toJSON(): String {
        val intermediate = "{ \"timestamp\" : $timestamp, \"from\" : \"$displayName\", \"source\" : \"$hexEncodedPublicKey\" }"
        return "{ \"text\" : \"$body\", \"annotations\" : [ { \"type\" : \"network.loki.messenger.publicChat\", \"value\" : $intermediate } ] }"
    }
}