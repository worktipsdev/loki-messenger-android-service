package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.deferred
import okhttp3.*
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.JsonUtil
import java.io.IOException

internal class LokiGroupChatAPI {

    companion object {
        private val serverURL = "https://chat.lokinet.org"
        private val pollInterval = 5
        private val batchCount = 20
    }

    public fun getMessages(channelID: String): RawResponsePromise {
        Log.d("Loki", "Getting messages for group chat with ID: $channelID.")
        val queryParameters = "include_annotations=1&count=-$batchCount"
        val url = "$serverURL/channels/$channelID/messages?$queryParameters"
        val request = Request.Builder().url(url).get()
        val connection = OkHttpClient()
        val deferred = deferred<RawResponse, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
                        val bodyAsString = response.body()!!.string()
                        @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                        deferred.resolve(body)
                    }
                    else -> {
                        Log.d("Loki", "Couldn't reach group chat server.")
                        deferred.reject(LokiAPI.Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    public fun sendMessage(message: LokiGroupMessage, channelID: String): RawResponsePromise {
        Log.d("Loki", "Sending message to group chat with ID: $channelID.")
        val url = "$serverURL/channels/$channelID/messages"
        val parameters = message.toJSON()
        val body = RequestBody.create(MediaType.get("application/json"), parameters)
        val request = Request.Builder().url(url).post(body)
        val connection = OkHttpClient()
        val deferred = deferred<RawResponse, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
                        val bodyAsString = response.body()!!.string()
                        @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                        deferred.resolve(body)
                    }
                    else -> {
                        Log.d("Loki", "Couldn't reach group chat server.")
                        deferred.reject(LokiAPI.Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }
}