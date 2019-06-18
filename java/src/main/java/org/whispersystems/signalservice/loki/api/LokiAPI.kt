package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.all
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.map
import nl.komponents.kovenant.task
import okhttp3.*
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Envelope
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.messaging.LokiMessageWrapper
import org.whispersystems.signalservice.loki.messaging.SignalMessageInfo
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded
import java.io.IOException
import java.util.concurrent.TimeUnit

class LokiAPI(private val hexEncodedPublicKey: String, internal val database: LokiAPIDatabaseProtocol) {
    // region Settings
    internal companion object {
        private val version = "v1"
        private val maxRetryCount = 3
        private val defaultTimeout: Long = 40
        private val longPollingTimeout: Long = 40
        internal val defaultMessageTTL = 1 * 24 * 60 * 60 * 1000
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

    // region Internal API
    /**
     * `hexEncodedPublicKey` is the hex encoded public key of the user the call is associated with. This is needed for swarm cache maintenance.
     */
    internal fun invoke(method: LokiAPITarget.Method, target: LokiAPITarget, hexEncodedPublicKey: String,
        parameters: Map<String, String>, headers: Headers? = null, timeout: Long? = null): RawResponsePromise {
        val url = "${target.address}:${target.port}/$version/storage_rpc"
        val body = RequestBody.create(MediaType.get("application/json"), "{ \"method\" : \"${method.rawValue}\", \"params\" : ${JsonUtil.toJson(parameters)} }")
        val request = Request.Builder().url(url).post(body)
        if (headers != null) { request.headers(headers) }
        val headersDescription = headers?.toString() ?: "no custom headers specified"
        val connection = OkHttpClient().newBuilder().connectTimeout(timeout ?: defaultTimeout, TimeUnit.SECONDS).build()
        Log.d("Loki", "Invoking ${method.rawValue} on $target with $parameters ($headersDescription).")
        val deferred = deferred<Map<*, *>, Exception>()
        connection.newCall(request.build()).enqueue(object : Callback {

            override fun onResponse(call: Call, response: Response) {
                when (response.code()) {
                    // TODO: Handle network errors
                    200 -> {
                        val bodyAsString = response.body()!!.string()
                        @Suppress("NAME_SHADOWING") val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
                        deferred.resolve(body)
                    }
                    421 -> {
                        // The snode isn't associated with the given public key anymore
                        println("[Loki] Invalidating swarm for: $hexEncodedPublicKey.")
                        LokiSwarmAPI(database).dropIfNeeded(target, hexEncodedPublicKey)
                        deferred.reject(Error.SnodeMigrated)
                    }
                    432 -> {
                        // The PoW difficulty is too low
                        // TODO: Update the PoW difficulty from the response body
                        deferred.reject(Error.InsufficientProofOfWork)
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

    internal fun getRawMessages(target: LokiAPITarget, useLongPolling: Boolean): RawResponsePromise {
        val lastHashValue = database.getLastMessageHashValue(target) ?: ""
        val parameters = mapOf( "pubKey" to hexEncodedPublicKey, "lastHash" to lastHashValue )
        val headers: Headers? = if (useLongPolling) Headers.of("X-Loki-Long-Poll", "true") else null
        val timeout: Long? = if (useLongPolling) longPollingTimeout else null
        return invoke(LokiAPITarget.Method.GetMessages, target, hexEncodedPublicKey, parameters, headers, timeout)
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
                    swarm.map {
                        sendLokiMessage(lokiMessageWithPoW, it as LokiAPITarget).map { rawResponse ->
                            val json = rawResponse as? Map<*, *>
                            val powDifficulty = json?.get("difficulty") as? Int
                            if (powDifficulty != null && powDifficulty != LokiAPI.powDifficulty) {
                                Log.d("Loki", "Setting PoW difficulty to $powDifficulty.")
                                LokiAPI.powDifficulty = powDifficulty
                            } else {
                                Log.d("Loki", "Failed to update PoW difficulty from: $rawResponse.")
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
    // endregion

    // region Parsing
    internal fun parseRawMessagesResponse(rawResponse: RawResponse, target: LokiAPITarget): List<Envelope> {
        val messages = rawResponse["messages"] as? List<*>
        if (messages != null) {
            updateLastMessageHashValueIfPossible(target, messages)
            val newRawMessages = removeDuplicates(messages)
            return parseEnvelopes(newRawMessages)
        } else {
            return listOf()
        }
    }

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
// endregion