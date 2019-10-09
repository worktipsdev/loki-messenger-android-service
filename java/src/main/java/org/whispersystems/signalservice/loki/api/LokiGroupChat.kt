package org.whispersystems.signalservice.loki.api

import org.whispersystems.signalservice.internal.util.JsonUtil

public data class LokiGroupChat(
    public val channel: Long,
    public var server: String,
    public val displayName: String,
    public val isDeletable: Boolean
) {
    public val id get() = "$server.$channel"

    companion object {
        fun defaultChats(isDebug: Boolean = false): List<LokiGroupChat> {
            val list = mutableListOf<LokiGroupChat>(
                LokiGroupChat(1, "https://chat.lokinet.org", "Loki Public Chat", true)
            )

            if (isDebug) {
                list.add(LokiGroupChat(1, "https://chat-dev.lokinet.org", "Loki Dev Chat", true))
            }

            return list
        }

        fun fromJSON(string: String): LokiGroupChat? {
            return try {
                val node = JsonUtil.fromJson(string)
                val channel = node.get("channel").asLong()
                val server = node.get("server").asText()
                val displayName = node.get("displayName").asText()
                val isDeletable = node.get("isDeletable").asBoolean()

                LokiGroupChat(channel, server, displayName, isDeletable)
            } catch (e: Exception) {
                null
            }
        }
    }

    init {
      this.server = server.toLowerCase()
    }

    public fun toJSON(): Map<String, Any> {
        return mapOf("channel" to channel, "server" to server, "displayName" to displayName, "isDeletable" to isDeletable)
    }
}