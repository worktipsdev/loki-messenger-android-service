package org.whispersystems.signalservice.loki.api

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

        internal fun toJSON(): String {
            return "{ \"id\" : $quotedMessageTimestamp, \"author\" : \"$quoteeHexEncodedPublicKey\", \"text\" : \"$quotedMessageBody\" }"
        }
    }

    constructor(hexEncodedPublicKey: String, displayName: String, body: String, timestamp: Long, type: String, quote: Quote?)
        : this(null, hexEncodedPublicKey, displayName, body, timestamp, type, quote)

    internal fun toJSON(): String {
        var intermediate = "{ "
        intermediate += "\"timestamp\" : $timestamp, \"from\" : \"$displayName\", \"source\" : \"$hexEncodedPublicKey\""
        if (quote != null) {
            intermediate += ", "
            intermediate += "\"quote\" : ${quote.toJSON()}"
        }
        intermediate += " }"
        return "{ \"text\" : \"$body\", \"annotations\" : [ { \"type\" : \"$type\", \"value\" : $intermediate } ] }"
    }
}