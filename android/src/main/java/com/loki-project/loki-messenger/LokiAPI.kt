package com.`loki-project`.`loki-messenger`

import nl.komponents.kovenant.Promise
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
    sealed class Error(val description: String) : java.lang.Error() {
        /**
         * Only applicable to snode targets as proof of work isn't required for P2P messaging.
         */
        object ProofOfWorkCalculationFailed : Error("Failed to calculate proof of work.")
        object MessageConversionFailed : Error("Failed to convert Signal message to Loki message.")
    }
    // endregion

    // region Internal API
    /**
     * `hexEncodedPublicKey` is used for swarm cache management.
     */
    internal fun invoke(method: LokiAPITarget.Method, target: LokiAPITarget, hexEncodedPublicKey: String, parameters: Map<String, Any>): Promise<Any, Exception> {
        return task { Unit }
    }
    // endregion

    // region Public API
    fun getMessages(): Promise<Set<Promise<List<Envelope>, Exception>>, Exception> {
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