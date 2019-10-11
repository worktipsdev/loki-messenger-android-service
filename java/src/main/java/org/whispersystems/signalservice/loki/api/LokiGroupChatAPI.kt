package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.functional.map
import nl.komponents.kovenant.then
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Hex
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.messaging.LokiUserDatabaseProtocol
import org.whispersystems.signalservice.loki.utilities.Analytics
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded
import java.text.SimpleDateFormat
import java.util.*

class LokiGroupChatAPI(private val userHexEncodedPublicKey: String, private val userPrivateKey: ByteArray, private val apiDatabase: LokiAPIDatabaseProtocol, private val userDatabase: LokiUserDatabaseProtocol) : LokiDotNetAPI(userHexEncodedPublicKey, userPrivateKey, apiDatabase) {

    companion object {
        private val moderators: HashMap<String, HashMap<Long, Set<String>>> = hashMapOf() // Server URL to (channel ID to set of moderator IDs)

        // region Settings
        private val fallbackBatchCount = 256
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
        val parameters = mutableMapOf<String, Any>("include_annotations" to 1)
        val lastMessageServerID = apiDatabase.getLastMessageServerID(group, server)
        if (lastMessageServerID != null) {
            parameters["since_id"] = lastMessageServerID
        } else {
            parameters["count"] = fallbackBatchCount
        }
        return execute(HTTPVerb.GET, server, "channels/$group/messages", false, parameters).then { response ->
            try {
                val bodyAsString = response.body()!!.string()
                val body = JsonUtil.fromJson(bodyAsString)
                val data = body.get("data")
                val messages = data.mapNotNull { message ->
                    try {
                        val isDeleted = message.has("is_deleted") && message.get("is_deleted").asBoolean(false)
                        if (isDeleted) { return@mapNotNull null }
                        // Ignore messages without annotations
                        if (!message.hasNonNull("annotations")) { return@mapNotNull null }
                        val annotation = message.get("annotations").find {
                            (it.get("type").asText("") == publicChatMessageType) && it.hasNonNull("value")
                        } ?: return@mapNotNull null
                        val value = annotation.get("value")
                        val serverID = message.get("id").asLong()
                        val hexEncodedSignature = value.get("sig").asText()
                        val signatureVersion = value.get("sigver").asLong()
                        val signature = LokiGroupMessage.Signature(Hex.fromStringCondensed(hexEncodedSignature), signatureVersion)
                        val user = message.get("user")
                        val hexEncodedPublicKey = user.get("username").asText()
                        val displayName = if (user.hasNonNull("name")) user.get("name").asText() else "Anonymous"
                        @Suppress("NAME_SHADOWING") val body = message.get("text").asText()
                        val timestamp = value.get("timestamp").asLong()
                        @Suppress("NAME_SHADOWING") val lastMessageServerID = apiDatabase.getLastMessageServerID(group, server)
                        if (serverID > lastMessageServerID ?: 0) { apiDatabase.setLastMessageServerID(group, server, serverID) }
                        var quote: LokiGroupMessage.Quote? = null
                        if (value.hasNonNull("quote")) {
                            val replyTo = if (message.hasNonNull("reply_to")) message.get("reply_to").asLong() else null
                            val quoteAnnotation = value.get("quote")
                            val quoteTimestamp = quoteAnnotation.get("id").asLong()
                            val author = quoteAnnotation.get("author").asText()
                            val text = quoteAnnotation.get("text").asText()
                            quote = if (quoteTimestamp > 0L && author != null && text != null) LokiGroupMessage.Quote(quoteTimestamp, author, text, replyTo) else null
                        }
                        // Verify the message
                        val groupMessage = LokiGroupMessage(serverID, hexEncodedPublicKey, displayName, body, timestamp, publicChatMessageType, quote, signature)
                        if (groupMessage.hasValidSignature()) groupMessage else null
                    } catch (exception: Exception) {
                        Log.d("Loki", "Couldn't parse message for group chat with ID: $group on server: $server from: ${JsonUtil.toJson(message)}. Exception: ${exception.message}")
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
        val parameters = mutableMapOf<String, Any>()
        val lastDeletionServerID = apiDatabase.getLastDeletionServerID(group, server)
        if (lastDeletionServerID != null) {
            parameters["since_id"] = lastDeletionServerID
        } else {
            parameters["count"] = fallbackBatchCount
        }
        return execute(HTTPVerb.GET, server, "loki/v1/channel/$group/deletes", false, parameters).then { response ->
            try {
                val bodyAsString = response.body()!!.string()
                val body = JsonUtil.fromJson(bodyAsString)
                val deletedMessageServerIDs = body.get("data").mapNotNull { deletion ->
                    try {
                        val serverID = deletion.get("id").asLong()
                        val messageServerID = deletion.get("message_id").asLong()
                        @Suppress("NAME_SHADOWING") val lastDeletionServerID = apiDatabase.getLastDeletionServerID(group, server)
                        if (serverID > (lastDeletionServerID ?: 0)) { apiDatabase.setLastDeletionServerID(group, server, serverID) }
                        messageServerID
                    } catch (exception: Exception) {
                        Log.d("Loki", "Couldn't parse deleted message for group chat with ID: $group on server: $server. ${exception.message}")
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
        val signedMessage = message.sign(userPrivateKey) ?: return Promise.ofFail(LokiAPI.Error.MessageSigningFailed)
        return retryIfNeeded(maxRetryCount) {
            Log.d("Loki", "Sending message to group chat with ID: $group on server: $server.")
            val parameters = signedMessage.toJSON()
            execute(HTTPVerb.POST, server, "channels/$group/messages", parameters = parameters).then { response ->
                try {
                    val bodyAsString = response.body()!!.string()
                    val body = JsonUtil.fromJson(bodyAsString)
                    val data = body.get("data")
                    val serverID = data.get("id").asLong()
                    val displayName = userDatabase.getDisplayName(userHexEncodedPublicKey) ?: "Anonymous"
                    val text = data.get("text").asText()
                    val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
                    val dateAsString = data.get("created_at").asText()
                    val timestamp = format.parse(dateAsString).time
                    @Suppress("NAME_SHADOWING") val message = LokiGroupMessage(serverID, userHexEncodedPublicKey, displayName, text, timestamp, publicChatMessageType, message.quote, signedMessage.signature)
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
            execute(HTTPVerb.DELETE, server, endpoint).then {
                Log.d("Loki", "Deleted message with ID: $messageServerID on server: $server.")
                messageServerID
            }.get()
        }
    }

    public fun getModerators(group: Long, server: String): Promise<Set<String>, Exception> {
        return execute(HTTPVerb.GET, server, "loki/v1/channel/$group/get_moderators", false).then { response ->
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

    public fun setDisplayName(newDisplayName: String?, server: String): Promise<Unit, Exception> {
        Log.d("Loki", "Updating display name on server: $server.")
        val parameters = mapOf( "name" to (newDisplayName ?: "") )
        return execute(HTTPVerb.PATCH, server, "users/me", parameters = parameters).map { Unit }
    }
    // endregion
}