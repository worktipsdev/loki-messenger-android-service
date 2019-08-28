package org.whispersystems.signalservice.loki.api

public data class LokiGroupChat(
    public val id: String,
    public val serverID: Long,
    public val server: String,
    public val displayName: String,
    public val isDeletable: Boolean
) {

    constructor(serverID: Long, server: String, displayName: String, isDeletable: Boolean)
        : this("$server.$serverID", serverID, server, displayName, isDeletable)
}