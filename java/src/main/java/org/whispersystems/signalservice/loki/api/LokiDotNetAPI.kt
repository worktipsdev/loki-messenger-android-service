package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.functional.map
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
 * Abstract base class that provides utilities for .NET based APIs.
 */
open class LokiDotNetAPI(private val userHexEncodedPublicKey: String, private val userPrivateKey: ByteArray, private val apiDatabase: LokiAPIDatabaseProtocol) {

    internal enum class HTTPVerb { GET, PUT, POST, DELETE, PATCH }

    // region Types
    public sealed class Error(val description: String) : Exception() {
        object Generic : Error("An error occurred.")
        object ParsingFailed : Error("Failed to parse object from JSON.")
    }
    // endregion

    public fun getAuthToken(server: String): Promise<String, Exception> {
        val token = apiDatabase.getAuthToken(server)
        return if (token != null) {
            Promise.of(token)
        } else {
            requestNewAuthToken(server).bind { submitAuthToken(it, server) }.then { newToken ->
                apiDatabase.setAuthToken(server, newToken)
                newToken
            }
        }
    }

    private fun requestNewAuthToken(server: String): Promise<String, Exception> {
        Log.d("Loki", "Requesting auth token for server: $server.")
        val queryParameters = "pubKey=$userHexEncodedPublicKey"
        val url = "$server/loki/v1/get_challenge?$queryParameters"
        val request = Request.Builder().url(url).get()
        return execute(request.build(), server).map { response ->
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
                token
            } catch (exception: Exception) {
                Log.d("Loki", "Couldn't parse auth token for server: $server.")
                throw exception
            }
        }
    }

    private fun submitAuthToken(token: String, server: String): Promise<String, Exception> {
        Log.d("Loki", "Submitting auth token for server: $server.")
        val url = "$server/loki/v1/submit_challenge"
        val parameters = mapOf("pubKey" to userHexEncodedPublicKey, "token" to token)
        val body = RequestBody.create(MediaType.get("application/json"), JsonUtil.toJson(parameters))
        val request = Request.Builder().url(url).post(body)
        return execute(request.build(), server).map { token }
    }

    internal fun execute(verb: HTTPVerb, server: String, endpoint: String, parameters: Map<String, Any> = mapOf()): Promise<Response, Exception> {
        val sanitizedEndpoint = endpoint.removePrefix("/")
        var url = "$server/$sanitizedEndpoint"
        if (verb == HTTPVerb.GET) {
            val queryParameters = parameters.map { "${it.key}=${it.value}" }.joinToString("&")
            if (queryParameters.isNotEmpty()) {
                url += "?$queryParameters"
            }
            val request = Request.Builder().url(url)
            return execute(request.build(), server)
        } else {
            val parametersAsJSON = JsonUtil.toJson(parameters)
            val body = RequestBody.create(MediaType.get("application/json"), parametersAsJSON)
            var request = Request.Builder().url(url)
            request = when (verb) {
                HTTPVerb.GET -> request.get()
                HTTPVerb.DELETE -> request.delete()
                HTTPVerb.PUT -> request.put(body)
                HTTPVerb.POST -> request.post(body)
                HTTPVerb.PATCH -> request.patch(body)
            }
            return getAuthenticatedRequest(request, server).bind { execute(it.build(), server) }
        }
    }

    internal fun getAuthenticatedRequest(builder: Request.Builder, server: String): Promise<Request.Builder, Exception> {
        return getAuthToken(server).map { token -> builder.header("Authorization", "Bearer $token") }
    }

    private fun execute(request: Request, server: String): Promise<Response, Exception> {
        val connection = OkHttpClient()
        return execute(connection, request, server)
    }

    internal fun execute(connection: OkHttpClient, request: Request, server: String): Promise<Response, Exception> {
        val deferred = deferred<Response, Exception>()
        connection.newCall(request).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    in 200..299 -> deferred.resolve(response)
                    401 -> {
                        apiDatabase.setAuthToken(server, null)
                        deferred.reject(LokiAPI.Error.TokenExpired)
                    }
                    else -> deferred.reject(LokiAPI.Error.HTTPRequestFailed(response.code()))
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                Log.d("Loki", "Couldn't reach server: $server.")
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    internal fun setSelfAnnotation(server: String, type: String, newValue: Any?): Promise<Response, Exception> {
        val annotation = mutableMapOf<String, Any>( "type" to type )
        if (newValue != null) { annotation["value"] = newValue }
        val parameters = mapOf( "annotations" to listOf( annotation ) )
        return execute(HTTPVerb.PATCH, server, "users/me", parameters)
    }
}