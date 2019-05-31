package com.`loki-project`.`loki-messenger`

import android.util.Log
import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.all
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.map
import nl.komponents.kovenant.task
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Envelope

class LokiAPI(private val hexEncodedPublicKey: String) {

    // region Settings
    private val version = "v1"
    private val maxRetryCount = 3
    private val defaultMessageTTL = 1 * 24 * 60 * 60 * 1000
    // endregion

    // region Types
    sealed class Error(val description: String) : Exception() {
        /**
         * Only applicable to snode targets as proof of work isn't required for P2P messaging.
         */
        object ProofOfWorkCalculationFailed : Error("Failed to calculate proof of work.")
        object MessageConversionFailed : Error("Failed to convert Signal message to Loki message.")
    }
    // endregion

    // region Internal API
    /**
     * `hexEncodedPublicKey` is the hex encoded public key of the user the call is associated with. This is needed for swarm cache maintenance.
     */
    internal fun invoke(method: LokiAPITarget.Method, target: LokiAPITarget, hexEncodedPublicKey: String, parameters: Map<String, Any>): Promise<Any, Exception> {
        return task { Unit }
    }
    // endregion

    // region Public API
    fun getMessages(): Promise<Set<MessageListPromise>, Exception> {
        return LokiSwarmAPI.getTargetSnodes(hexEncodedPublicKey).map { targetSnodes ->
            targetSnodes.map { targetSnode ->
                val lastHashValue = ""
                val parameters = mapOf( "pubKey" to hexEncodedPublicKey, "lastHash" to lastHashValue )
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
        }.map { it.toSet() }
    }

    @kotlin.ExperimentalUnsignedTypes
    fun sendSignalMessage(signalMessage: Map<*, *>, timestamp: Int, onP2PSuccess: () -> Unit): Promise<Set<RawResponsePromise>, Exception> {
        val lokiMessage = LokiMessage.from(signalMessage) ?: return task { throw Error.MessageConversionFailed }
        val destination = lokiMessage.destination
        fun sendLokiMessage(lokiMessage: LokiMessage, target: LokiAPITarget): RawResponsePromise {
            val parameters = lokiMessage.toJSON()
            return invoke(LokiAPITarget.Method.SendMessage, target, destination, parameters)
        }
        fun sendLokiMessageUsingSwarmAPI(): Promise<Set<RawResponsePromise>, Exception> {
            val powPromise = lokiMessage.calculatePoW()
            val swarmPromise = LokiSwarmAPI.getTargetSnodes(destination)
            return all(powPromise, swarmPromise).map {
                val lokiMessageWithPoW = it[0] as LokiMessage
                val swarm = it[1] as List<*>
                swarm.map { sendLokiMessage(lokiMessageWithPoW, it as LokiAPITarget) }.toSet()
            }
        }
        val p2pAPI = LokiP2PAPI(destination)
        val peer = p2pAPI.peerInfo[destination]
        if (peer != null && (lokiMessage.isPing || peer.isOnline)) {
            val target = LokiAPITarget(peer.address, peer.port)
            val deferred = deferred<Set<RawResponsePromise>, Exception>()
            task { listOf( target ) }.map { it.map { sendLokiMessage(lokiMessage, it) } }.map { it.toSet() }.success {
                p2pAPI.markAsOnline(destination)
                onP2PSuccess()
                deferred.resolve(it)
            }.fail {
                p2pAPI.markAsOffline(destination)
                if (lokiMessage.isPing) {
                    Log.w("Loki", "Failed to ping $destination; marking contact as offline.")
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
        // TODO: Implement
    }

    private fun removeDuplicates(rawMessages: List<*>): List<*> {
        return listOf<Map<String, Any>>()
    }

    private fun parseEnvelopes(rawMessages: List<*>): List<Envelope> {
        return listOf()
    }
    // endregion
}

// region Convenience
typealias RawResponse = Any
typealias MessageListPromise = Promise<List<Envelope>, Exception>
typealias RawResponsePromise = Promise<RawResponse, Exception>
// endregion