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
import org.whispersystems.signalservice.loki.utilities.prettifiedDescription
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*

// TODO: Get rid of the duplication around making HTTP requests

public class LokiGroupChatAPI(private val userHexEncodedPublicKey: String, private val userPrivateKey: ByteArray, private val apiDatabase: LokiAPIDatabaseProtocol, private val userDatabase: LokiUserDatabaseProtocol) {

    companion object {
        @JvmStatic
        public val serverURL = "https://chat.lokinet.org"
        private val fallbackBatchCount = 20
        private var lastFetchedMessageID: Long? = null
        @JvmStatic
        public val publicChatMessageType = "network.loki.messenger.publicChat"
        @JvmStatic
        public val publicChatID: Long = 1
        private val maxRetryCount = 4
    }

    private fun getTokenFromServer(): Promise<String, Exception> {
        Log.d("Loki", "Getting group chat auth token.")
        val url = "$serverURL/loki/v1/get_challenge?pubKey=$userHexEncodedPublicKey"
        val request = Request.Builder().url(url).get()
        val connection = OkHttpClient()
        val deferred = deferred<String, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
                        try {
                            val bodyAsString = response.body()!!.string()
                            @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                            val base64EncodedChallenge = body["cipherText64"] as String
                            val challenge = Base64.decode(base64EncodedChallenge)
                            val base64EncodedServerPublicKey = body["serverPubKey64"] as String
                            var serverPublicKey = Base64.decode(base64EncodedServerPublicKey)
                            // Discard the "05" prefix if needed
                            if (serverPublicKey.count() == 33) {
                                val hexEncodedServerPublicKey = Hex.toStringCondensed(serverPublicKey)
                                serverPublicKey = Hex.fromStringCondensed(hexEncodedServerPublicKey.removePrefix("05"))
                            }
                            // The challenge is prefixed by the 16 bit IV
                            val tokenAsData = DiffieHellman.decrypt(challenge, serverPublicKey, userPrivateKey)
                            val token = tokenAsData.toString(Charsets.UTF_8)
                            deferred.resolve(token)
                        } catch (exception: Exception) {
                            Log.d("Loki", "Couldn't parse auth token.")
                            deferred.reject(exception)
                        }
                    }
                    else -> {
                        Log.d("Loki", "Couldn't reach group chat server.")
                        deferred.reject(LokiAPI.Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach group chat server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    private fun submitToken(token: String): Promise<String, Exception> {
        Log.d("Loki", "Submitting group chat auth token.")
        val url = "$serverURL/loki/v1/submit_challenge"
        val parameters = "{ \"pubKey\" : \"$userHexEncodedPublicKey\", \"token\" : \"$token\" }"
        val body = RequestBody.create(MediaType.get("application/json"), parameters)
        val request = Request.Builder().url(url).post(body)
        val connection = OkHttpClient()
        val deferred = deferred<String, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> deferred.resolve(token)
                    else -> {
                        Log.d("Loki", "Couldn't reach group chat server.")
                        deferred.reject(LokiAPI.Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach group chat server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    private fun getToken(): Promise<String, Exception> {
        val token = apiDatabase.getGroupChatAuthToken(serverURL)
        if (token != null) {
            return Promise.of(token)
        } else {
            return getTokenFromServer().bind { submitToken(it) }.then { token ->
                apiDatabase.setGroupChatAuthToken(token, serverURL)
                token
            }
        }
    }

    public fun getMessages(groupID: Long, batchStartMessageID: Long? = null): Promise<List<LokiGroupMessage>, Exception> {
        Log.d("Loki", "Getting messages for group chat with ID: $groupID.")
        var queryParameters = "include_annotations=1&is_deleted=true"
        val lastFetchedMessageID = lastFetchedMessageID
        when {
            batchStartMessageID != null -> queryParameters += "&since_id=$batchStartMessageID"
            lastFetchedMessageID != null -> queryParameters += "&since_id=$lastFetchedMessageID"
            else -> queryParameters += "&count=-$fallbackBatchCount"
        }
        val url = "$serverURL/channels/$groupID/messages?$queryParameters"
        val request = Request.Builder().url(url).get()
        val connection = OkHttpClient()
        val deferred = deferred<List<LokiGroupMessage>, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
                        try {
                            val bodyAsString = response.body()!!.string()
                            val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                            val messagesAsJSON = body["data"] as List<*>
                            val messages = messagesAsJSON.mapNotNull { messageAsJSON ->
                                try {
                                    val x1 = messageAsJSON as Map<*, *>
                                    val x2 = x1["annotations"] as List<*>
                                    val x3 = x2.first() as Map<*, *>
                                    val x4 = x3["value"] as Map<*, *>
                                    val serverID = x1["id"] as? Long ?: (x1["id"] as Int).toLong()
                                    val hexEncodedPublicKey = x4["source"] as String
                                    if (hexEncodedPublicKey == userHexEncodedPublicKey) return@mapNotNull null
                                    val displayName = x4["from"] as String
                                    @Suppress("NAME_SHADOWING") val body = x1["text"] as String
                                    val timestamp = x4["timestamp"] as Long
                                    if (serverID > lastFetchedMessageID ?: 0) { Companion.lastFetchedMessageID = serverID }
                                    val isDeleted = x1["is_deleted"] as? Boolean ?: false
                                    LokiGroupMessage(serverID, hexEncodedPublicKey, displayName, body, timestamp, publicChatMessageType, isDeleted)
                                } catch (exception: Exception) {
                                    Log.d("Loki", "Couldn't parse message from: ${messageAsJSON?.prettifiedDescription() ?: "null"}.")
                                    return@mapNotNull null
                                }
                            }
                            deferred.resolve(messages)
                        } catch (exception: Exception) {
                            Log.d("Loki", "Couldn't parse messages for group chat with ID: $groupID.")
                            deferred.reject(exception)
                        }
                    }
                    else -> {
                        Log.d("Loki", "Couldn't reach group chat server.")
                        deferred.reject(LokiAPI.Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach group chat server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    public fun sendMessage(message: LokiGroupMessage, groupID: Long): Promise<LokiGroupMessage, Exception> {
        return retryIfNeeded(maxRetryCount) {
            getToken().bind { token ->
                Log.d("Loki", "Sending message to group chat with ID: $groupID.")
                val url = "$serverURL/channels/$groupID/messages"
                val parameters = message.toJSON()
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
                                    @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                                    val messageAsJSON = body["data"] as Map<*, *>
                                    val serverID = messageAsJSON["id"] as? Long ?: (messageAsJSON["id"] as Int).toLong()
                                    val displayName = userDatabase.getDisplayName(userHexEncodedPublicKey) ?: "Anonymous"
                                    val text = messageAsJSON["text"] as String
                                    val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
                                    val dateAsString = messageAsJSON["created_at"] as String
                                    val timestamp = format.parse(dateAsString).time
                                    @Suppress("NAME_SHADOWING") val message = LokiGroupMessage(serverID, userHexEncodedPublicKey, displayName, text, timestamp, publicChatMessageType, false)
                                    deferred.resolve(message)
                                } catch (exception: Exception) {
                                    Log.d("Loki", "Couldn't parse message for group chat with ID: $groupID.")
                                    deferred.reject(exception)
                                }
                            }
                            401 -> {
                                Log.d("Loki", "Group chat token expired; dropping it.")
                                apiDatabase.setGroupChatAuthToken(null, serverURL)
                            }
                            else -> {
                                Log.d("Loki", "Couldn't reach group chat server.")
                                deferred.reject(LokiAPI.Error.Generic)
                            }
                        }
                    }

                    override fun onFailure(call: Call, exception: IOException) {
                        Log.d("Loki", "Couldn't reach group chat server.")
                        deferred.reject(exception)
                    }
                })
                deferred.promise
            }.get()
        }
    }

    public fun deleteMessage(messageID: Long, groupID: Long): Promise<Long, Exception> {
        return retryIfNeeded(maxRetryCount) {
            getToken().bind { token ->
                Log.d("Loki", "Deleting message with ID: $messageID from group chat with ID: $groupID.")
                val url = "$serverURL/channels/$groupID/messages/$messageID"
                val request = Request.Builder().url(url).header("Authorization", "Bearer $token").delete()
                val connection = OkHttpClient()
                val deferred = deferred<Long, Exception>()
                connection.newCall(request.build()).enqueue(object : Callback {

                    override fun onResponse(call: Call, response: Response) {
                        when (response.code()) {
                            200 -> {
                                deferred.resolve(messageID)
                            }
                            else -> {
                                Log.d("Loki", "Couldn't reach group chat server.")
                                deferred.reject(LokiAPI.Error.Generic)
                            }
                        }
                    }

                    override fun onFailure(call: Call, exception: IOException) {
                        Log.d("Loki", "Couldn't reach group chat server.")
                        deferred.reject(exception)
                    }
                })
                deferred.promise
            }.get()
        }
    }
}