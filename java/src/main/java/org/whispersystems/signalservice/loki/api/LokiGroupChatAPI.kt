package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.then
import nl.komponents.kovenant.unwrap
import okhttp3.*
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.messaging.LokiUserDatabaseProtocol
import org.whispersystems.signalservice.loki.utilities.DiffeHellman
import org.whispersystems.signalservice.loki.utilities.prettifiedDescription
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*

val String.hexAsByteArray inline get() = this.chunked(2).map { it.toUpperCase().toInt(16).toByte() }.toByteArray()

public class LokiGroupChatAPI(private val userHexEncodedPublicKey: String, private val userPrivateKey: ByteArray, private val userDatabase: LokiUserDatabaseProtocol) {

    companion object {
        @JvmStatic
        public val serverURL = "https://chat.lokinet.org"
        private val batchCount = 8
        @JvmStatic
        public val publicChatMessageType = "network.loki.messenger.publicChat"
        @JvmStatic
        public val publicChatID: Long = 1
    }

    private fun fetchToken(): Promise<String, Exception> {
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
                            val cipherText64 = body["cipherText64"] as String
                            val cipherText = Base64.decode(cipherText64)

                            val serverPubKey64 = body["serverPubKey64"] as String
                            var serverPubKey = Base64.decode(serverPubKey64)

                            // If we have length 33 pubkey that means that it's prefixed with 05
                            if (serverPubKey.count() == 33) {
                                val hex = serverPubKey.joinToString("") { String.format("%02x", it) }
                                serverPubKey = hex.removePrefix("05").hexAsByteArray
                            }

                            val tokenData = DiffeHellman.decrypt(cipherText, serverPubKey, userPrivateKey)
                            val token = tokenData.toString(Charsets.UTF_8)

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
        val parameters = "{ \"pubKey\" : \"$userHexEncodedPublicKey\" \"token\" : \"$token\" }"
        val body = RequestBody.create(MediaType.get("application/json"), parameters)
        val request = Request.Builder().url(url).post(body)
        val connection = OkHttpClient()
        val deferred = deferred<String, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
                        deferred.resolve(token)
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

    private fun getToken(): Promise<String, Exception> {
        val userToken = userDatabase.getToken(serverURL)
        return if (userToken == null)
            fetchToken().then { submitToken(it) }.unwrap().then { token ->
                userDatabase.setToken(token, serverURL)
                token
            } else Promise.of(userToken)
    }

    public fun getMessages(groupID: Long): Promise<List<LokiGroupMessage>, Exception> {
        Log.d("Loki", "Getting messages for group chat with ID: $groupID.")
        val queryParameters = "include_annotations=1&count=-$batchCount"
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
                                    LokiGroupMessage(serverID, hexEncodedPublicKey, displayName, body, timestamp, publicChatMessageType)
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
        return getToken().then { token ->
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
                                @Suppress("NAME_SHADOWING") val message = LokiGroupMessage(serverID, userHexEncodedPublicKey, displayName, text, timestamp, publicChatMessageType)
                                deferred.resolve(message)
                            } catch (exception: Exception) {
                                Log.d("Loki", "Couldn't parse message for group chat with ID: $groupID.")
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
            deferred.promise
        }.unwrap()
    }
}