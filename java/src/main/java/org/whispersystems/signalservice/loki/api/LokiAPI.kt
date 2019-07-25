package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.all
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.functional.map
import nl.komponents.kovenant.task
import okhttp3.*
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Envelope
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.messaging.LokiMessageWrapper
import org.whispersystems.signalservice.loki.messaging.SignalMessageInfo
import org.whispersystems.signalservice.loki.utilities.prettifiedDescription
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

class LokiAPI(private val userHexEncodedPublicKey: String, private val database: LokiAPIDatabaseProtocol) {

    // region Settings
    internal companion object {
        private val version = "v1"
        private val maxRetryCount = 2
        private val defaultTimeout: Long = 20
        private val longPollingTimeout: Long = 40
        internal val defaultMessageTTL = 24 * 60 * 60 * 1000
        internal var powDifficulty = 100
    }
    // endregion

    // region Types
    sealed class Error(val description: String) : Exception() {
        object Generic : Error("An error occurred.")
        /**
         * Only applicable to snode targets as proof of work isn't required for P2P messaging.
         */
        object ProofOfWorkCalculationFailed : Error("Failed to calculate proof of work.")
        object MessageConversionFailed : Error("Failed to convert Signal message to Loki message.")
        object SnodeMigrated : Error("The snode previously associated with the given public key has migrated to a different swarm.")
        object InsufficientProofOfWork : Error("The proof of work is insufficient.")
    }
    // endregion

    // region Clearnet Setup
    fun getClearnetConnection(timeout: Long): OkHttpClient {
        val trustManager = object : X509TrustManager {

            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authorizationType: String?) { }
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authorizationType: String?) { }
            override fun getAcceptedIssuers(): Array<X509Certificate> { return arrayOf() }
        }
        val sslContext = SSLContext.getInstance("SSL")
        sslContext.init(null, arrayOf( trustManager ), SecureRandom())
        return OkHttpClient().newBuilder()
                .sslSocketFactory(sslContext.socketFactory, trustManager)
                .hostnameVerifier { _, _ -> true }
                .connectTimeout(timeout, TimeUnit.SECONDS)
                .readTimeout(timeout, TimeUnit.SECONDS)
                .writeTimeout(timeout, TimeUnit.SECONDS)
                .build()
    }
    // endregion

    // region Internal API
    /**
     * `hexEncodedPublicKey` is the hex encoded public key of the user the call is associated with. This is needed for swarm cache maintenance.
     */
    internal fun invoke(method: LokiAPITarget.Method, target: LokiAPITarget, hexEncodedPublicKey: String,
        parameters: Map<String, String>, headers: Headers? = null, timeout: Long? = null): RawResponsePromise {
        val url = "${target.address}:${target.port}/storage_rpc/$version"
        val body = RequestBody.create(MediaType.get("application/json"), "{ \"method\" : \"${method.rawValue}\", \"params\" : ${JsonUtil.toJson(parameters)} }")
        val request = Request.Builder().url(url).post(body)
        if (headers != null) { request.headers(headers) }
        val headersDescription = headers?.toMultimap()?.mapValues { it.value.prettifiedDescription() }?.prettifiedDescription() ?: "no custom headers specified"
        val connection = getClearnetConnection(timeout ?: defaultTimeout)
        Log.d("Loki", "Invoking ${method.rawValue} on $target with ${parameters.prettifiedDescription()} ($headersDescription).")
        fun dropSnodeIfNeeded() {
            val oldFailureCount = LokiSwarmAPI.failureCount[target] ?: 0
            val newFailureCount = oldFailureCount + 1
            LokiSwarmAPI.failureCount[target] = newFailureCount
            Log.d("Loki", "Couldn't reach snode at $target; setting failure count to $newFailureCount.")
            if (newFailureCount >= LokiSwarmAPI.failureThreshold) {
                Log.d("Loki", "Failure threshold reached for: $target; dropping it.")
                LokiSwarmAPI(database).dropIfNeeded(target, hexEncodedPublicKey) // Remove it from the swarm cache associated with the given public key
                LokiSwarmAPI.randomSnodePool.remove(target) // Remove it from the random snode pool
                LokiSwarmAPI.failureCount[target] = 0
            }
        }
        val deferred = deferred<Map<*, *>, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
                        val jsonAsString = response.body()!!.string()
                        @Suppress("NAME_SHADOWING") val json = JsonUtil.fromJson(jsonAsString, Map::class.java)
                        deferred.resolve(json)
                    }
                    400 -> dropSnodeIfNeeded()
                    421 -> {
                        // The snode isn't associated with the given public key anymore
                        Log.d("Loki", "Invalidating swarm for: $hexEncodedPublicKey.")
                        LokiSwarmAPI(database).dropIfNeeded(target, hexEncodedPublicKey)
                        deferred.reject(Error.SnodeMigrated)
                    }
                    432 -> {
                        // The PoW difficulty is too low
                        val jsonAsString = response.body()!!.string()
                        @Suppress("NAME_SHADOWING") val json = JsonUtil.fromJson(jsonAsString, Map::class.java)
                        val powDifficulty = json?.get("difficulty") as? Int
                        if (powDifficulty != null) {
                            Log.d("Loki", "Setting proof of work difficulty to $powDifficulty.")
                            LokiAPI.powDifficulty = powDifficulty
                        } else {
                            Log.d("Loki", "Failed to update proof of work difficulty.")
                        }
                        deferred.reject(Error.InsufficientProofOfWork)
                    }
                    500 -> dropSnodeIfNeeded()
                    503 -> dropSnodeIfNeeded()
                    else -> {
                        Log.d("Loki", "Unhandled response code: ${response.code()}.")
                        deferred.reject(Error.Generic)
                    }
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                if (exception is ConnectException || exception is SocketTimeoutException) {
                    dropSnodeIfNeeded()
                } else {
                    Log.d("Loki", "Unhandled exception: $exception.")
                }
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }

    internal fun getRawMessages(target: LokiAPITarget, useLongPolling: Boolean): RawResponsePromise {
        val lastHashValue = database.getLastMessageHashValue(target) ?: ""
        val parameters = mapOf( "pubKey" to userHexEncodedPublicKey, "lastHash" to lastHashValue )
        val headers: Headers? = if (useLongPolling) Headers.of("X-Loki-Long-Poll", "true") else null
        val timeout: Long? = if (useLongPolling) longPollingTimeout else null
        return invoke(LokiAPITarget.Method.GetMessages, target, userHexEncodedPublicKey, parameters, headers, timeout)
    }
    // endregion

    // region Public API
    fun getMessages(): MessageListPromise {
        return retryIfNeeded(maxRetryCount) {
            LokiSwarmAPI(database).getSingleTargetSnode(userHexEncodedPublicKey).bind { targetSnode ->
                getRawMessages(targetSnode, false).map { parseRawMessagesResponse(it, targetSnode) }
            }.get()
        }
    }

    @kotlin.ExperimentalUnsignedTypes
    fun sendSignalMessage(message: SignalMessageInfo, onP2PSuccess: () -> Unit): Promise<Set<RawResponsePromise>, Exception> {
        val lokiMessage = LokiMessage.from(message) ?: return task { throw Error.MessageConversionFailed }
        val destination = lokiMessage.destination
        fun sendLokiMessage(lokiMessage: LokiMessage, target: LokiAPITarget): RawResponsePromise {
            val parameters = lokiMessage.toJSON()
            return invoke(LokiAPITarget.Method.SendMessage, target, destination, parameters)
        }
        fun sendLokiMessageUsingSwarmAPI(): Promise<Set<RawResponsePromise>, Exception> {
            return retryIfNeeded(maxRetryCount) {
                val powPromise = lokiMessage.calculatePoW()
                val swarmPromise = LokiSwarmAPI(database).getTargetSnodes(destination)
                all(powPromise, swarmPromise).map {
                    val lokiMessageWithPoW = it[0] as LokiMessage
                    val swarm = it[1] as List<*>
                    swarm.map {
                        sendLokiMessage(lokiMessageWithPoW, it as LokiAPITarget).map { rawResponse ->
                            val json = rawResponse as? Map<*, *>
                            val powDifficulty = json?.get("difficulty") as? Int
                            if (powDifficulty != null) {
                                if (powDifficulty != LokiAPI.powDifficulty) {
                                    Log.d("Loki", "Setting proof of work difficulty to $powDifficulty.")
                                    LokiAPI.powDifficulty = powDifficulty
                                }
                            } else {
                                Log.d("Loki", "Failed to update proof of work difficulty from: ${rawResponse.prettifiedDescription()}.")
                            }
                            rawResponse
                        }
                    }.toSet()
                }.get()
            }
        }
        val peer = LokiP2PAPI.shared.peerInfo[destination]
        if (peer != null && (lokiMessage.isPing || peer.isOnline)) {
            val target = LokiAPITarget(peer.address, peer.port)
            val deferred = deferred<Set<RawResponsePromise>, Exception>()
            retryIfNeeded(maxRetryCount) {
                task { listOf(target) }.map { it.map { sendLokiMessage(lokiMessage, it) } }.map { it.toSet() }.get()
            }.success {
                LokiP2PAPI.shared.mark(true, destination)
                onP2PSuccess()
                deferred.resolve(it)
            }.fail {
                LokiP2PAPI.shared.mark(false, destination)
                if (lokiMessage.isPing) {
                    Log.d("Loki", "Failed to ping $destination; marking contact as offline.")
                }
                sendLokiMessageUsingSwarmAPI().success { deferred.resolve(it) }.fail { deferred.reject(it) }
            }
            return deferred.promise
        } else {
            return sendLokiMessageUsingSwarmAPI()
        }
    }
    // endregion

    // region Parsing

    // The parsing utilities below use a best attempt approach to parsing; they warn for parsing failures but don't throw exceptions.

    internal fun parseRawMessagesResponse(rawResponse: RawResponse, target: LokiAPITarget): List<Envelope> {
        val messages = rawResponse["messages"] as? List<*>
        if (messages != null) {
            updateLastMessageHashValueIfPossible(target, messages)
            val newRawMessages = removeDuplicates(messages)
            val newMessages = parseEnvelopes(newRawMessages)
            val newMessageCount = newMessages.count()
            if (newMessageCount == 1) {
                Log.d("Loki", "Retrieved 1 new message.")
            } else if (newMessageCount != 0) {
                Log.d("Loki", "Retrieved $newMessageCount new messages.")
            }
            return newMessages
        } else {
            return listOf()
        }
    }

    private fun updateLastMessageHashValueIfPossible(target: LokiAPITarget, rawMessages: List<*>) {
        val lastMessageAsJSON = rawMessages.lastOrNull() as? Map<*, *>
        val hashValue = lastMessageAsJSON?.get("hash") as? String
        if (hashValue != null) {
            database.setLastMessageHashValue(target, hashValue)
        } else if (rawMessages.isNotEmpty()) {
            Log.d("Loki", "Failed to update last message hash value from: ${rawMessages.prettifiedDescription()}.")
        }
    }

    private fun removeDuplicates(rawMessages: List<*>): List<*> {
        val receivedMessageHashValues = database.getReceivedMessageHashValues()?.toMutableSet() ?: mutableSetOf()
        return rawMessages.filter { rawMessage ->
            val rawMessageAsJSON = rawMessage as? Map<*, *>
            val hashValue = rawMessageAsJSON?.get("hash") as? String
            if (hashValue != null) {
                val isDuplicate = receivedMessageHashValues.contains(hashValue)
                receivedMessageHashValues.add(hashValue)
                database.setReceivedMessageHashValues(receivedMessageHashValues)
                !isDuplicate
            } else {
                Log.d("Loki", "Missing hash value for message: ${rawMessage?.prettifiedDescription()}.")
                false
            }
        }
    }

    private fun parseEnvelopes(rawMessages: List<*>): List<Envelope> {
        return rawMessages.mapNotNull { rawMessage ->
            val rawMessageAsJSON = rawMessage as? Map<*, *>
            val base64EncodedData = rawMessageAsJSON?.get("data") as? String
            val data = base64EncodedData?.let { Base64.decode(it) }
            if (data != null) {
                try {
                    LokiMessageWrapper.unwrap(data)
                } catch (e: Exception) {
                    Log.d("Loki", "Failed to unwrap data for message: ${rawMessage.prettifiedDescription()}.")
                    null
                }
            } else {
                Log.d("Loki", "Failed to decode data for message: ${rawMessage?.prettifiedDescription()}.")
                null
            }
        }
    }
    // endregion
}

// region Convenience
typealias RawResponse = Map<*, *>
typealias MessageListPromise = Promise<List<Envelope>, Exception>
typealias RawResponsePromise = Promise<RawResponse, Exception>
// endregion