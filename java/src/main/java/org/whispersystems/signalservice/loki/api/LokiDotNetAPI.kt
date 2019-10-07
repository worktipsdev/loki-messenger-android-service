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
import org.whispersystems.signalservice.loki.utilities.removing05PrefixIfNeeded
import java.io.IOException

/**
 * This is meant to be used as an Abstract Base Class
 */
open class LokiDotNetAPI(private val userHexEncodedPublicKey: String, private val userPrivateKey: ByteArray, private val apiDatabase: LokiAPIDatabaseProtocol) {

    // region Token
    private fun requestNewAuthToken(server: String): Promise<String, Exception> {
        Log.d("Loki", "Requesting auth token for server: $server.")
        val queryParameters = "pubKey=$userHexEncodedPublicKey"
        val url = "$server/loki/v1/get_challenge?$queryParameters"
        val request = Request.Builder().url(url).get()
        val connection = OkHttpClient()
        val deferred = deferred<String, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    in 200..299 -> {
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
                                serverPublicKey = Hex.fromStringCondensed(hexEncodedServerPublicKey.removing05PrefixIfNeeded())
                            }
                            // The challenge is prefixed by the 16 bit IV
                            val tokenAsData = DiffieHellman.decrypt(challenge, serverPublicKey, userPrivateKey)
                            val token = tokenAsData.toString(Charsets.UTF_8)
                            deferred.resolve(token)
                        } catch (exception: Exception) {
                            Log.d("Loki", "Couldn't parse auth token for server: $server.")
                            deferred.reject(exception)
                        }
                    }
                    else -> {
                        Log.d("Loki", "Couldn't reach server: $server.")
                        deferred.reject(LokiAPI.Error.HTTPRequestFailed(response.code()))
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach server: $server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    private fun submitToken(token: String, server: String): Promise<String, Exception> {
        Log.d("Loki", "Submitting auth token for server: $server.")
        val url = "$server/loki/v1/submit_challenge"
        val parameters = "{ \"pubKey\" : \"$userHexEncodedPublicKey\", \"token\" : \"$token\" }"
        val body = RequestBody.create(MediaType.get("application/json"), parameters)
        val request = Request.Builder().url(url).post(body)
        val connection = OkHttpClient()
        val deferred = deferred<String, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    in 200..299 -> deferred.resolve(token)
                    else -> {
                        Log.d("Loki", "Couldn't reach server: $server.")
                        deferred.reject(LokiAPI.Error.HTTPRequestFailed(response.code()))
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach server: $server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    protected fun getAuthToken(server: String): Promise<String, Exception> {
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

    // region Requests

    private fun perform(request: Request): Promise<Response, Exception> {
        val connection = OkHttpClient()
        val deferred = deferred<Response, Exception>()

        connection.newCall(request).enqueue(object : Callback {
            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    in 200..299 -> deferred.resolve(response)
                    401 -> deferred.reject(LokiAPI.Error.TokenExpired)
                    else -> deferred.reject(LokiAPI.Error.HTTPRequestFailed(response.code()))
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach dot net server: ${request.url()}.")
                deferred.reject(exception)
            }
        })

        return deferred.promise
    }

    private fun performAuthorised(server: String, requestBlock: (Request.Builder) -> Request): Promise<Response, Exception> {
        return getAuthToken(server).bind { token ->
            val builder = Request.Builder().header("Authorization", "Bearer $token")
            perform(requestBlock(builder))
        }.fail { error ->
            if (error is LokiAPI.Error.TokenExpired) {
                apiDatabase.setGroupChatAuthToken(server, null)
            }
        }
    }

    internal fun get(server: String, endpoint: String, parameters: Map<String, Any> = mapOf()): Promise<Response, Exception> {
        val queryParameters = parameters.map { "${it.key}=${it.value}" }.joinToString("&")
        var url = "$server/$endpoint"
        var completeUrl = if (queryParameters.isEmpty()) url else "$url?$queryParameters"
        val request = Request.Builder().url(completeUrl).get()
        return perform(request.build())
    }

    internal fun post(server: String, endpoint: String, parameters: String): Promise<Response, Exception> {
        return performAuthorised(server) { builder ->
            val url = "$server/$endpoint"
            val body = RequestBody.create(MediaType.get("application/json"), parameters)
            builder.url(url).post(body).build()
        }
    }

    internal fun patch(server: String, endpoint: String, parameters: String): Promise<Response, Exception> {
        return performAuthorised(server) { builder ->
            val url = "$server/$endpoint"
            val body = RequestBody.create(MediaType.get("application/json"), parameters)
            builder.url(url).patch(body).build()
        }
    }

    internal fun delete(server: String, endpoint: String): Promise<Response, Exception> {
        return performAuthorised(server) { builder ->
            val url = "$server/$endpoint"
            builder.url(url).delete().build()
        }
    }

    internal fun setSelfAnnotation(server: String, type: String, value: Any?): Promise<Response, Exception> {
        val annotation = mutableMapOf<String, Any>("type" to type)
        if (value != null) { annotation["value"] = value }
        val json = mutableMapOf("annotations" to listOf(annotation))
        val parameter = JsonUtil.toJson(json)
        return patch(server, "users/me", parameter)
    }
    // endregion
}