package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.then
import okhttp3.*
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.Hex
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.crypto.DiffieHellman
import org.whispersystems.signalservice.loki.messaging.LokiUserDatabaseProtocol
import org.whispersystems.signalservice.loki.utilities.Analytics
import org.whispersystems.signalservice.loki.utilities.prettifiedDescription
import org.whispersystems.signalservice.loki.utilities.removing05PrefixIfNeeded
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*

// TODO: Get rid of the duplication around making HTTP requests

public class LokiGroupChatAPI(private val userHexEncodedPublicKey: String, private val userPrivateKey: ByteArray, private val apiDatabase: LokiAPIDatabaseProtocol, private val userDatabase: LokiUserDatabaseProtocol) {

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

    // region Private API
    private fun requestNewAuthToken(server: String): Promise<String, Exception> {
        Log.d("Loki", "Requesting group chat auth token for server: $server.")
        val queryParameters = "pubKey=$userHexEncodedPublicKey"
        val url = "$server/loki/v1/get_challenge?$queryParameters"
        val request = Request.Builder().url(url).get()
        val connection = OkHttpClient()
        val deferred = deferred<String, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
                        try {
                            val bodyAsString = response.body()!!.string()
                            @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString)
                            val base64EncodedChallenge = body.get("cipherText64").asText()
                            val challenge = Base64.decode(base64EncodedChallenge)
                            val base64EncodedServerPublicKey =body.get("serverPubKey64").asText()
                            var serverPublicKey = Base64.decode(base64EncodedServerPublicKey)
                            // Discard the "05" prefix if needed
                            if (serverPublicKey.count() == 33) {
                                val hexEncodedServerPublicKey = Hex.toStringCondensed(serverPublicKey)
                                serverPublicKey = Hex.fromStringCondensed(hexEncodedServerPublicKey.removing05PrefixIfNeeded())
                            }
                            // The challenge is prefixed by the 16 bit IV
                            val tokenAsData = DiffieHellman.decrypt(challenge, serverPublicKey, userPrivateKey)
                            val token = tokenAsData.toString(Charsets.UTF_8)
                            deferred.resolve(token)
                        } catch (exception: Exception) {
                            Log.d("Loki", "Couldn't parse group chat auth token for server: $server due to error: ${exception.message}.")
                            deferred.reject(exception)
                        }
                    }
                    else -> {
                        Log.d("Loki", "Couldn't reach group chat server: $server.")
                        deferred.reject(LokiAPI.Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach group chat server: $server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    private fun submitToken(token: String, server: String): Promise<String, Exception> {
        Log.d("Loki", "Submitting group chat auth token for server: $server.")
        val url = "$server/loki/v1/submit_challenge"
        val parameters = JsonUtil.toJson(mapOf( "pubKey" to userHexEncodedPublicKey, "token" to token ))
        val body = RequestBody.create(MediaType.get("application/json"), parameters)
        val request = Request.Builder().url(url).post(body)
        val connection = OkHttpClient()
        val deferred = deferred<String, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> deferred.resolve(token)
                    else -> {
                        Log.d("Loki", "Couldn't reach group chat server: $server.")
                        deferred.reject(LokiAPI.Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach group chat server: $server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    private fun getAuthToken(server: String): Promise<String, Exception> {
        val token = apiDatabase.getGroupChatAuthToken(server)
        if (token != null) {
            return Promise.of(token)
        } else {
            return requestNewAuthToken(server).bind { submitToken(it, server) }.then { token ->
                apiDatabase.setGroupChatAuthToken(server, token)
                token
            }
        }
    }
    // endregion

    // region Public API
    public fun getMessages(group: Long, server: String): Promise<List<LokiGroupMessage>, Exception> {
        Log.d("Loki", "Getting messages for group chat with ID: $group on server: $server.")
        var queryParameters = "include_annotations=1"
        val lastMessageServerID = apiDatabase.getLastMessageServerID(group, server)
        if (lastMessageServerID != null) {
            queryParameters += "&since_id=$lastMessageServerID"
        } else {
            queryParameters += "&count=-$fallbackBatchCount"
        }
        val url = "$server/channels/$group/messages?$queryParameters"
        val request = Request.Builder().url(url).get()
        val connection = OkHttpClient()
        val deferred = deferred<List<LokiGroupMessage>, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
                        try {
                            val bodyAsString = response.body()!!.string()
                            @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString)
                            val messagesAsJSON = body.get("data")
                            val messages = messagesAsJSON.mapNotNull { message ->
                                try {
                                    val isDeleted = message.has("is_deleted") && message.get("is_deleted").asBoolean(false)
                                    if (isDeleted) { return@mapNotNull null }
                                    if (!message.hasNonNull("annotations")) { return@mapNotNull null }
                                    val annotation = message.get("annotations").find {
                                        it.get("type").asText("") == publicChatMessageType && it.hasNonNull("value")
                                    }
                                    if (annotation == null) { return@mapNotNull null }
                                    val annotationValue = annotation.get("value")
                                    val serverID = message.get("id").asLong()
                                    val signatureData = Hex.fromStringCondensed(annotationValue.get("sig").asText())
                                    val signatureVersion = annotationValue.get("sigver").asLong()
                                    val signature = LokiGroupMessage.Signature(signatureData, signatureVersion)
                                    val user = message.get("user")
                                    val hexEncodedPublicKey = user.get("username").asText()
                                    val displayName = if (user.hasNonNull("name")) user.get("name").asText() else "Anonymous"
                                    @Suppress("NAME_SHADOWING") val body = message.get("text").asText()
                                    val timestamp = annotationValue.get("timestamp").asLong()
                                    @Suppress("NAME_SHADOWING") val lastMessageServerID = apiDatabase.getLastMessageServerID(group, server)
                                    if (serverID > lastMessageServerID ?: 0) { apiDatabase.setLastMessageServerID(group, server, serverID) }
                                    var quote: LokiGroupMessage.Quote? = null
                                    if (annotationValue.hasNonNull("quote")) {
                                        val quotedMessageServerID = if (message.hasNonNull("reply_to")) message.get("reply_to").asLong() else null
                                        val quoteAsJSON = annotationValue.get("quote")
                                        val quotedMessageTimestamp = quoteAsJSON.get("id").asLong()
                                        val quoteeHexEncodedPublicKey = quoteAsJSON.get("author").asText()
                                        val quotedMessageBody = quoteAsJSON.get("text").asText()
                                        if (quotedMessageTimestamp > 0L && quoteeHexEncodedPublicKey != null && quotedMessageBody != null) {
                                            quote = LokiGroupMessage.Quote(quotedMessageTimestamp, quoteeHexEncodedPublicKey, quotedMessageBody, quotedMessageServerID)
                                        }
                                    }
                                    val groupMessage = LokiGroupMessage(serverID, hexEncodedPublicKey, displayName, body, timestamp, publicChatMessageType, quote, signature)
                                    if (groupMessage.hasValidSignature()) groupMessage else null
                                } catch (exception: Exception) {
                                    Log.d("Loki", "Couldn't parse message for group chat with ID: $group on server: $server from: ${JsonUtil.toJson(message)} due to error: ${exception.message}.")
                                    return@mapNotNull null
                                }
                            }.sortedBy { it.timestamp }
                            deferred.resolve(messages)
                        } catch (exception: Exception) {
                            Log.d("Loki", "Couldn't parse messages for group chat with ID: $group on server: $server.")
                            deferred.reject(exception)
                        }
                    }
                    else -> {
                        Log.d("Loki", "Couldn't reach group chat server: $server.")
                        deferred.reject(LokiAPI.Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach group chat server: $server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    public fun getDeletedMessageServerIDs(group: Long, server: String): Promise<List<Long>, Exception> {
        Log.d("Loki", "Getting deleted messages for group chat with ID: $group on server: $server.")
        val queryParameters: String
        val lastDeletionServerID = apiDatabase.getLastDeletionServerID(group, server)
        if (lastDeletionServerID != null) {
            queryParameters = "since_id=$lastDeletionServerID"
        } else {
            queryParameters = "count=$fallbackBatchCount"
        }
        val url = "$server/loki/v1/channel/$group/deletes?$queryParameters"
        val request = Request.Builder().url(url).get()
        val connection = OkHttpClient()
        val deferred = deferred<List<Long>, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
                        try {
                            val bodyAsString = response.body()!!.string()
                            @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString)
                            val deletedMessageServerIDs = body.get("data").mapNotNull { deletion ->
                                try {
                                    val serverID = deletion.get("id").asLong()
                                    val messageServerID = deletion.get("message_id").asLong()
                                    @Suppress("NAME_SHADOWING") val lastDeletionServerID = apiDatabase.getLastDeletionServerID(group, server)
                                    if (serverID > (lastDeletionServerID ?: 0)) { apiDatabase.setLastDeletionServerID(group, server, serverID) }
                                    messageServerID
                                } catch (exception: Exception) {
                                    Log.d("Loki", "Couldn't parse deleted message for group chat with ID: $group on server: $server from: ${deletion?.prettifiedDescription() ?: "null"} due to error: ${exception.message}.")
                                    return@mapNotNull null
                                }
                            }
                            deferred.resolve(deletedMessageServerIDs)
                        } catch (exception: Exception) {
                            Log.d("Loki", "Couldn't parse deleted messages for group chat with ID: $group on server: $server.")
                            deferred.reject(exception)
                        }
                    }
                    else -> {
                        Log.d("Loki", "Couldn't reach group chat server: $server.")
                        deferred.reject(LokiAPI.Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach group chat server: $server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    public fun sendMessage(message: LokiGroupMessage, group: Long, server: String): Promise<LokiGroupMessage, Exception> {
        // There's apparently a condition under which the promise below gets resolved multiple times, causing a crash. The
        // !deferred.promise.isDone() checks are a quick workaround for this but obviously don't fix the underlying issue.
        val signedMessage = message.sign(userPrivateKey) ?: return Promise.ofFail(LokiAPI.Error.MessageSigningFailed)
        return retryIfNeeded(maxRetryCount) {
            getAuthToken(server).bind { token ->
                Log.d("Loki", "Sending message to group chat with ID: $group on server: $server.")
                val url = "$server/channels/$group/messages"
                val parameters = JsonUtil.toJson(signedMessage.toJSON())
                val body = RequestBody.create(MediaType.get("application/json"), parameters)
                val request = Request.Builder().url(url).header("Authorization", "Bearer $token").post(body)
                val connection = OkHttpClient()
                val deferred = deferred<LokiGroupMessage, Exception>()
                connection.newCall(request.build()).enqueue(object : Callback {

                    override fun onResponse(call: Call, response: Response) {
                        when (response.code()) {
                            200 -> {
                                try {
                                    val bodyAsString = response.body()!!.string()
                                    @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString)
                                    val messageAsJSON = body.get("data")
                                    val serverID = messageAsJSON.get("id").asLong()
                                    val displayName = userDatabase.getDisplayName(userHexEncodedPublicKey) ?: "Anonymous"
                                    val text = messageAsJSON.get("text").asText()
                                    val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
                                    val dateAsString = messageAsJSON.get("created_at").asText()
                                    val timestamp = format.parse(dateAsString).time
                                    @Suppress("NAME_SHADOWING") val message = LokiGroupMessage(serverID, userHexEncodedPublicKey, displayName, text, timestamp, publicChatMessageType, signedMessage.quote, signedMessage.signature)
                                    if (!deferred.promise.isDone()) { deferred.resolve(message) }
                                } catch (exception: Exception) {
                                    Log.d("Loki", "Couldn't parse message for group chat with ID: $group on server: $server.")
                                    if (!deferred.promise.isDone()) { deferred.reject(exception) }
                                }
                            }
                            401 -> {
                                Log.d("Loki", "Group chat token for: $server expired; dropping it.")
                                apiDatabase.setGroupChatAuthToken(server, null)
                                if (!deferred.promise.isDone()) { deferred.reject(LokiAPI.Error.TokenExpired) }
                            }
                            else -> {
                                Log.d("Loki", "Couldn't reach group chat server: $server.")
                                if (!deferred.promise.isDone()) { deferred.reject(LokiAPI.Error.Generic) }
                            }
                        }
                    }

                    override fun onFailure(call: Call, exception: IOException) {
                        Log.d("Loki", "Couldn't reach group chat server: $server.")
                        if (!deferred.promise.isDone()) { deferred.reject(exception) }
                    }
                })
                deferred.promise
            }.get()
        }.success {
            Analytics.shared.track("Group Message Sent")
        }.fail {
            Analytics.shared.track("Failed to Send Group Message")
        }
    }

    public fun deleteMessage(messageServerID: Long, group: Long, server: String, isSentByUser: Boolean): Promise<Long, Exception> {
        return retryIfNeeded(maxRetryCount) {
            getAuthToken(server).bind { token ->
                val isModerationRequest = !isSentByUser
                Log.d("Loki", "Deleting message with ID: $messageServerID from group chat with ID: $group on server: $server (isModerationRequest = $isModerationRequest).")
                val url = if (isSentByUser) "$server/channels/$group/messages/$messageServerID" else "$server/loki/v1/moderation/message/$messageServerID"
                val request = Request.Builder().url(url).header("Authorization", "Bearer $token").delete()
                val connection = OkHttpClient()
                val deferred = deferred<Long, Exception>()
                connection.newCall(request.build()).enqueue(object : Callback {

                    override fun onResponse(call: Call, response: Response) {
                        when (response.code()) {
                            200 -> {
                                Log.d("Loki", "Deleted message with ID: $messageServerID on server: $server.")
                                deferred.resolve(messageServerID)
                            }
                            else -> {
                                Log.d("Loki", "Couldn't reach group chat server: $server.")
                                deferred.reject(LokiAPI.Error.Generic)
                            }
                        }
                    }

                    override fun onFailure(call: Call, exception: IOException) {
                        Log.d("Loki", "Couldn't reach group chat server: $server.")
                        deferred.reject(exception)
                    }
                })
                deferred.promise
            }.get()
        }
    }

    public fun getModerators(group: Long, server: String): Promise<Set<String>, Exception> {
        val url = "$server/loki/v1/channel/$group/get_moderators"
        val request = Request.Builder().url(url)
        val connection = OkHttpClient()
        val deferred = deferred<Set<String>, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
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
                            deferred.resolve(moderatorsAsSet)
                        } catch (exception: Exception) {
                            Log.d("Loki", "Couldn't parse moderators for group chat with ID: $group on server: $server.")
                            deferred.reject(exception)
                        }
                    }
                    else -> {
                        Log.d("Loki", "Couldn't reach group chat server: $server.")
                        deferred.reject(LokiAPI.Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach group chat server: $server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    public fun setDisplayName(newDisplayName: String?, server: String): Promise<Unit, Exception> {
        Log.d("Loki", "Updating display name on server: $server.")
        return getAuthToken(server).bind { token ->
            val url = "$server/users/me"
            val parameters = "{ \"name\" : ${newDisplayName ?: ""} }"
            val body = RequestBody.create(MediaType.get("application/json"), parameters)
            val request = Request.Builder().url(url).header("Authorization", "Bearer $token").patch(body)
            val connection = OkHttpClient()
            val deferred = deferred<Unit, Exception>()
            connection.newCall(request.build()).enqueue(object : Callback {

                override fun onResponse(call: Call, response: Response) {
                    when (response.code()) {
                        200 -> deferred.resolve(Unit)
                        else -> {
                            Log.d("Loki", "Couldn't update display name due to error: ${response.code()}.")
                            deferred.reject(LokiAPI.Error.Generic)
                        }
                    }
                }

                override fun onFailure(call: Call, exception: IOException) {
                    Log.d("Loki", "Couldn't update display name due to error: $exception.")
                    deferred.reject(exception)
                }
            })
            deferred.promise
        }
    }
    // endregion
}