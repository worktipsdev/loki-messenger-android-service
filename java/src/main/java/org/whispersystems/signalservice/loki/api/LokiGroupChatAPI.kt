package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.then
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.messaging.LokiUserDatabaseProtocol
import org.whispersystems.signalservice.loki.utilities.Analytics
import org.whispersystems.signalservice.loki.utilities.prettifiedDescription
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded
import java.text.SimpleDateFormat
import java.util.*

class LokiGroupChatAPI(private val userHexEncodedPublicKey: String, private val userPrivateKey: ByteArray, private val apiDatabase: LokiAPIDatabaseProtocol, private val userDatabase: LokiUserDatabaseProtocol): LokiDotNetAPI(userHexEncodedPublicKey, userPrivateKey, apiDatabase) {

    companion object {
        private val moderators: HashMap<String, HashMap<Long, Set<String>>> = hashMapOf() // Server URL to (channel ID to set of moderator IDs)

        // region Settings
        private val fallbackBatchCount = 20
        private val maxRetryCount = 8
        var isDebugMode = false
        // endregion

        // region Public Chat
        @JvmStatic
        public val publicChatServer get() = if (isDebugMode) "https://chat-dev.lokinet.org" else "https://chat.lokinet.org"
        @JvmStatic
        public val publicChatMessageType = "network.loki.messenger.publicChat"
        @JvmStatic
        public val publicChatServerID: Long = 1
        // endregion

        // region Convenience
        public fun isUserModerator(hexEncodedPublicKey: String, group: Long, server: String): Boolean {
            if (moderators[server] != null && moderators[server]!![group] != null) {
                return moderators[server]!![group]!!.contains(hexEncodedPublicKey)
            }
            return false
        }
        // endregion
    }

    // region Public API
    public fun getMessages(group: Long, server: String): Promise<List<LokiGroupMessage>, Exception> {
        Log.d("Loki", "Getting messages for group chat with ID: $group on server: $server.")
        var parameters = mutableMapOf<String, Any>("include_annotations" to 1)
        val lastMessageServerID = apiDatabase.getLastMessageServerID(group, server)
        if (lastMessageServerID != null) {
            parameters["since_id"] = lastMessageServerID
        } else {
            parameters["count"] = fallbackBatchCount
        }

        return get(server, "/channels/$group/messages", parameters).then { response ->
            try {
                val bodyAsString = response.body()!!.string()
                val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                val messagesAsJSON = body["data"] as List<*>
                val messages = messagesAsJSON.mapNotNull { messageAsJSON ->
                    try {
                        val x1 = messageAsJSON as Map<*, *>
                        val isDeleted = (x1["is_deleted"] as? Int == 1)
                        if (isDeleted) { return@mapNotNull null }
                        val x2 = x1["annotations"] as List<*>
                        val x3 = x2.first() as Map<*, *>
                        val x4 = x3["value"] as Map<*, *>
                        val serverID = x1["id"] as? Long ?: (x1["id"] as Int).toLong()
                        val hexEncodedPublicKey = x4["source"] as String
                        val displayName = x4["from"] as String
                        @Suppress("NAME_SHADOWING") val body = x1["text"] as String
                        val timestamp = x4["timestamp"] as Long
                        @Suppress("NAME_SHADOWING") val lastMessageServerID = apiDatabase.getLastMessageServerID(group, server)
                        if (serverID > lastMessageServerID ?: 0) { apiDatabase.setLastMessageServerID(group, server, serverID) }
                        val quoteAsJSON = x4["quote"] as? Map<*, *>
                        val quotedMessageTimestamp = quoteAsJSON?.get("id") as? Long ?: (quoteAsJSON?.get("id") as? Int)?.toLong()
                        val quoteeHexEncodedPublicKey = quoteAsJSON?.get("author") as? String
                        val quotedMessageBody = quoteAsJSON?.get("text") as? String
                        val quote: LokiGroupMessage.Quote?
                        if (quotedMessageTimestamp != null && quoteeHexEncodedPublicKey != null && quotedMessageBody != null) {
                            quote = LokiGroupMessage.Quote(quotedMessageTimestamp, quoteeHexEncodedPublicKey, quotedMessageBody)
                        } else {
                            quote = null
                        }
                        LokiGroupMessage(serverID, hexEncodedPublicKey, displayName, body, timestamp, publicChatMessageType, quote)
                    } catch (exception: Exception) {
                        Log.d("Loki", "Couldn't parse message for group chat with ID: $group on server: $server from: ${messageAsJSON?.prettifiedDescription() ?: "null"}.")
                        return@mapNotNull null
                    }
                }.sortedBy { it.timestamp }
                messages
            } catch (exception: Exception) {
                Log.d("Loki", "Couldn't parse messages for group chat with ID: $group on server: $server.")
                throw exception
            }
        }
    }

    public fun getDeletedMessageServerIDs(group: Long, server: String): Promise<List<Long>, Exception> {
        Log.d("Loki", "Getting deleted messages for group chat with ID: $group on server: $server.")
        val queryParameters = mutableMapOf<String, Any>()
        val lastDeletionServerID = apiDatabase.getLastDeletionServerID(group, server)
        if (lastDeletionServerID != null) {
            queryParameters["since_id"] = lastDeletionServerID
        } else {
            queryParameters["count"] = fallbackBatchCount
        }

        return get(server, "loki/v1/channel/$group/deletes", queryParameters).then { response ->
            try {
                val bodyAsString = response.body()!!.string()
                val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                val deletions = body["data"] as List<*>
                val deletedMessageServerIDs = deletions.mapNotNull { deletionAsString ->
                    try {
                        val deletion = deletionAsString as Map<*, *>
                        val serverID = deletion["id"] as? Long ?: (deletion["id"] as Int).toLong()
                        val messageServerID = deletion["message_id"] as? Long ?: (deletion["message_id"] as Int).toLong()
                        @Suppress("NAME_SHADOWING") val lastDeletionServerID = apiDatabase.getLastDeletionServerID(group, server)
                        if (serverID > (lastDeletionServerID ?: 0)) { apiDatabase.setLastDeletionServerID(group, server, serverID) }
                        messageServerID
                    } catch (exception: Exception) {
                        Log.d("Loki", "Couldn't parse deleted message for group chat with ID: $group on server: $server from: ${deletionAsString?.prettifiedDescription() ?: "null"}.")
                        return@mapNotNull null
                    }
                }
                deletedMessageServerIDs
            } catch (exception: Exception) {
                Log.d("Loki", "Couldn't parse deleted messages for group chat with ID: $group on server: $server.")
                throw exception
            }
        }
    }

    public fun sendMessage(message: LokiGroupMessage, group: Long, server: String): Promise<LokiGroupMessage, Exception> {
        return retryIfNeeded(maxRetryCount) {
            Log.d("Loki", "Sending message to group chat with ID: $group on server: $server.")
            post(server, "/channels/$group/messages", message.toJSON()).then { response ->
                try {
                    val bodyAsString = response.body()!!.string()
                    @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                    val messageAsJSON = body["data"] as Map<*, *>
                    val serverID = messageAsJSON["id"] as? Long ?: (messageAsJSON["id"] as Int).toLong()
                    val displayName = userDatabase.getDisplayName(userHexEncodedPublicKey) ?: "Anonymous"
                    val text = messageAsJSON["text"] as String
                    val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
                    val dateAsString = messageAsJSON["created_at"] as String
                    val timestamp = format.parse(dateAsString).time
                    @Suppress("NAME_SHADOWING") val message = LokiGroupMessage(serverID, userHexEncodedPublicKey, displayName, text, timestamp, publicChatMessageType, message.quote)
                    message
                } catch (exception: Exception) {
                    Log.d("Loki", "Couldn't parse message for group chat with ID: $group on server: $server.")
                    throw exception
                }
            }.get()
        }.success {
            Analytics.shared.track("Group Message Sent")
        }.fail {
            Analytics.shared.track("Failed to Send Group Message")
        }
    }

    public fun deleteMessage(messageServerID: Long, group: Long, server: String, isSentByUser: Boolean): Promise<Long, Exception> {
        return retryIfNeeded(maxRetryCount) {
            val isModerationRequest = !isSentByUser
            Log.d("Loki", "Deleting message with ID: $messageServerID from group chat with ID: $group on server: $server (isModerationRequest = $isModerationRequest).")
            val endpoint = if (isSentByUser) "channels/$group/messages/$messageServerID" else "loki/v1/moderation/message/$messageServerID"
            delete(server, endpoint).then {
                Log.d("Loki", "Deleted message with ID: $messageServerID on server: $server.")
                messageServerID
            }.get()
        }
    }

    public fun getModerators(group: Long, server: String): Promise<Set<String>, Exception> {
        return get(server, "loki/v1/channel/$group/get_moderators").then { response ->
            try {
                val bodyAsString = response.body()!!.string()
                @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                @Suppress("UNCHECKED_CAST") val moderators = body["moderators"] as? List<String>
                val moderatorsAsSet = moderators.orEmpty().toSet()
                if (Companion.moderators[server] != null) {
                    Companion.moderators[server]!![group] = moderatorsAsSet
                } else {
                    Companion.moderators[server] = hashMapOf( group to moderatorsAsSet )
                }
                moderatorsAsSet
            } catch (exception: Exception) {
                Log.d("Loki", "Couldn't parse moderators for group chat with ID: $group on server: $server.")
                throw exception
            }
        }
    }
    // endregion
}