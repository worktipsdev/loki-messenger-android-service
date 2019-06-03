package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.all
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.map
import nl.komponents.kovenant.task
import okhttp3.*
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Envelope
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded
import java.io.IOException

class LokiAPI(private val hexEncodedPublicKey: String, private val database: LokiAPIDatabaseProtocol) {

    private val connection by lazy { OkHttpClient() }

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
        val url = "${target.address}:${target.port}/$version/storage_rpc"
        val body = FormBody.Builder()
        body.add("method", method.rawValue)
        body.add("params", JsonUtil.toJson(parameters))
        val request = Request.Builder().url(url).post(body.build()).build()
        val deferred = deferred<Map<*, *>, Exception>()
        connection.newCall(request).enqueue(object : Callback {

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
                        LokiSwarmAPI(database).dropIfNeeded(target, hexEncodedPublicKey)
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
                    val lastHashValue = database.getLastMessageHashValue(targetSnode) ?: ""
                    val parameters = mapOf("pubKey" to hexEncodedPublicKey, "lastHash" to lastHashValue)
                    invoke(LokiAPITarget.Method.GetMessages, targetSnode, hexEncodedPublicKey, parameters).map { rawResponse ->
                        val json = rawResponse as? Map<*, *>
                        val rawMessages = json?.get("messages") as? List<*>
                        if (json != null && rawMessages != null) {
                            updateLastMessageHashValueIfPossible(targetSnode, rawMessages)
                            val newRawMessages = removeDuplicates(rawMessages)
                            parseEnvelopes(newRawMessages)
                        } else {
                            listOf()
                        }
                    }
                }
            }.map { it.toSet() }.get()
        }
    }

    @kotlin.ExperimentalUnsignedTypes
    fun sendSignalMessage(signalMessage: Map<*, *>, timestamp: Int, onP2PSuccess: () -> Unit): Promise<Set<RawResponsePromise>, Exception> {
        val lokiMessage = LokiMessage.from(signalMessage)
                ?: return task { throw Error.MessageConversionFailed }
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
    // endregion

    // region Parsing
    private fun updateLastMessageHashValueIfPossible(target: LokiAPITarget, rawMessages: List<*>) {
        val lastMessage = rawMessages.last() as? Map<*, *>
        val hashValue = lastMessage?.get("hash") as? String
        if (hashValue != null) {
            database.setLastMessageHashValue(target, hashValue)
        } else {
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
        return listOf() // TODO: Implement
    }
    // endregion
}

// region Convenience
typealias RawResponse = Map<*, *>
typealias MessageListPromise = Promise<List<Envelope>, Exception>
typealias RawResponsePromise = Promise<RawResponse, Exception>
// endregion