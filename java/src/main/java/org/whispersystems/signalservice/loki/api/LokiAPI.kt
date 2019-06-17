package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.all
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.map
import nl.komponents.kovenant.task
import okhttp3.*
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Envelope
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.messaging.LokiMessageWrapper
import org.whispersystems.signalservice.loki.messaging.SignalMessageInfo
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded
import java.io.IOException
import java.util.concurrent.TimeUnit

class LokiAPI(private val hexEncodedPublicKey: String, private val database: LokiAPIDatabaseProtocol) {

    private val connection by lazy { OkHttpClient() }
    private val longPoller: LokiLongPolling = LokiLongPolling(hexEncodedPublicKey, this, database)

    // region Settings
    internal companion object {
        private val version = "v1"
        private val maxRetryCount = 3
        internal val defaultMessageTTL = 1 * 24 * 60 * 60 * 1000
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
    }
    // endregion

    // region Internal API
    /**
     * `hexEncodedPublicKey` is the hex encoded public key of the user the call is associated with. This is needed for swarm cache maintenance.
     */
    internal fun invoke(method: LokiAPITarget.Method, target: LokiAPITarget, hexEncodedPublicKey: String, parameters: Map<String, String>): RawResponsePromise {
        return invoke(LokiRequest(method, target, hexEncodedPublicKey, parameters))
    }

    internal fun invoke(lokiRequest: LokiRequest): RawResponsePromise {
        var client = connection

        val url = "${lokiRequest.target.address}:${lokiRequest.target.port}/$version/storage_rpc"
        val body = RequestBody.create(MediaType.get("application/json"), "{ \"method\" : \"${lokiRequest.method.rawValue}\", \"params\" : ${JsonUtil.toJson(lokiRequest.parameters)} }")
        val builder = Request.Builder().url(url).post(body)
        if (lokiRequest.headers != null) { builder.headers(lokiRequest.headers) }
        if (lokiRequest.timeout != null) {
            client = OkHttpClient().newBuilder().connectTimeout(lokiRequest.timeout, TimeUnit.SECONDS).build()
        }

        val request = builder.build()
        val deferred = deferred<Map<*, *>, Exception>()
        client.newCall(request).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    200 -> {
                        val bodyAsString = response.body()!!.string()
                        @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                        deferred.resolve(body)
                    }
                    421 -> {
                        // The snode isn't associated with the given public key anymore
                        println("[Loki] Invalidating swarm for: $hexEncodedPublicKey.")
                        LokiSwarmAPI(database).dropIfNeeded(lokiRequest.target, hexEncodedPublicKey)
                        deferred.reject(Error.SnodeMigrated)
                    }
                    else -> deferred.reject(Error.Generic)
                }
            }

            override fun onFailure(call: Call, exception: IOException) {
                deferred.reject(exception)
            }
        })
        return deferred.promise
    }
    // endregion

    // region Public API
    fun getMessages(): Promise<Set<MessageListPromise>, Exception> {
        return retryIfNeeded(maxRetryCount) {
            LokiSwarmAPI(database).getTargetSnodes(hexEncodedPublicKey).map { targetSnodes ->
                targetSnodes.map { targetSnode ->
                    getRawMessages(targetSnode, false).map { parseRawMessagesResponse(it, targetSnode) }
                }
            }.map { it.toSet() }.get()
        }
    }

    fun getRawMessages(target: LokiAPITarget, useLongPolling: Boolean): RawResponsePromise {
        val lastHashValue = database.getLastMessageHashValue(target) ?: ""
        val parameters = mapOf( "pubKey" to hexEncodedPublicKey, "lastHash" to lastHashValue )

        var headers: Headers? = null
        var timeout: Long? = null
        if (useLongPolling) {
            headers = Headers.Builder().add("X-Loki-Long-Poll", "true").build()
            timeout = 40 // 40 second timeout
        }

        val request = LokiRequest(LokiAPITarget.Method.GetMessages, target, hexEncodedPublicKey, parameters, headers, timeout)
        return invoke(request)
    }

    fun parseRawMessagesResponse(rawResponse: RawResponse, target: LokiAPITarget): List<Envelope> {
        val messages = rawResponse["messages"] as? List<*>
        if (messages != null) {
            updateLastMessageHashValueIfPossible(target, messages)
            val newRawMessages = removeDuplicates(messages)
            return parseEnvelopes(newRawMessages)
        }

        return listOf()
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
            val powPromise = lokiMessage.calculatePoW()
            val swarmPromise = LokiSwarmAPI(database).getTargetSnodes(destination)
            return retryIfNeeded(maxRetryCount) {
                all(powPromise, swarmPromise).map {
                    val lokiMessageWithPoW = it[0] as LokiMessage
                    val swarm = it[1] as List<*>
                    swarm.map { sendLokiMessage(lokiMessageWithPoW, it as LokiAPITarget) }.toSet()
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
                LokiP2PAPI.shared.mark(isOnline = true, hexEncodedPublicKey = destination)
                onP2PSuccess()
                deferred.resolve(it)
            }.fail {
                LokiP2PAPI.shared.mark(isOnline = false, hexEncodedPublicKey = destination)
                if (lokiMessage.isPing) {
                    println("[Loki] Failed to ping $destination; marking contact as offline.")
                }
                sendLokiMessageUsingSwarmAPI().success { deferred.resolve(it) }.fail { deferred.reject(it) }
            }
            return deferred.promise
        } else {
            return sendLokiMessageUsingSwarmAPI()
        }
    }

    fun startLongPollingIfNecessary() {
        longPoller.startIfNecessary()
    }

    fun stopLongPolling() {
        longPoller.stop()
    }
    // endregion

    // region Parsing
    private fun updateLastMessageHashValueIfPossible(target: LokiAPITarget, rawMessages: List<*>) {
        val lastMessageAsJSON = rawMessages.last() as? Map<*, *>
        val hashValue = lastMessageAsJSON?.get("hash") as? String
        if (hashValue != null) {
            database.setLastMessageHashValue(target, hashValue)
        } else if (rawMessages.isNotEmpty()) {
            println("[Loki] Failed to update last message hash value from: $rawMessages.")
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
                println("[Loki] Missing hash value for message: $rawMessage.")
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
                    println("[Loki] Failed to unwrap data for message: $rawMessage.")
                    null
                }
            } else {
                println("[Loki] Failed to decode data for message: $rawMessage.")
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

internal data class LokiRequest(
    val method: LokiAPITarget.Method,
    val target: LokiAPITarget,
    val hexEncodedPublicKey: String,
    val parameters: Map<String, String>,
    val headers: Headers?,
    val timeout: Long?
){
    constructor(method: LokiAPITarget.Method, target: LokiAPITarget, hexEncodedPublicKey: String, parameters: Map<String, String>): this(method, target, hexEncodedPublicKey, parameters, null, null)
}
// endregion