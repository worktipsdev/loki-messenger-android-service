package org.whispersystems.signalservice.loki.api

import org.whispersystems.signalservice.internal.util.JsonUtil

public data class LokiPublicChat(
    public val channel: Long,
    private val serverURL: String,
    public val displayName: String,
    public val isDeletable: Boolean
) {
    public val server get() = serverURL.toLowerCase()
    public val id get() = "$server.$channel"

    companion object {

        @JvmStatic fun fromJSON(jsonAsString: String): LokiPublicChat? {
            try {
                val json = JsonUtil.fromJson(jsonAsString)
                val channel = json.get("channel").asLong()
                val server = json.get("server").asText().toLowerCase()
                val displayName = json.get("displayName").asText()
                val isDeletable = json.get("isDeletable").asBoolean()
                return LokiPublicChat(channel, server, displayName, isDeletable)
            } catch (e: Exception) {
                return null
            }
        }
    }

    public fun toJSON(): Map<String, Any> {
        return mapOf( "channel" to channel, "server" to server, "displayName" to displayName, "isDeletable" to isDeletable )
    }
}
