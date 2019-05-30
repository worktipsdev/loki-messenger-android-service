package com.`loki-project`.`loki-messenger`

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.functional.map
import nl.komponents.kovenant.task
import nl.komponents.kovenant.then
import java.security.SecureRandom

internal object LokiSwarmAPI {

    // region Settings
    private val minimumSnodeCount = 2 // TODO: For debugging purposes
    private val targetSnodeCount = 3 // TODO: For debugging purposes
    private val defaultSnodePort = 8080
    // endregion

    // region Caching
    private val swarmCache = mutableMapOf<String, List<LokiAPITarget>>()
    // endregion

    // region Internal API
    private fun getRandomSnode(): Promise<LokiAPITarget, Exception> {
        return task {
            LokiAPITarget("http://13.236.173.190", defaultSnodePort) // TODO: For debugging purposes
        }
    }

    private fun getSwarm(hexEncodedPublicKey: String): Promise<List<LokiAPITarget>, Exception> {
        val cachedSwarm = swarmCache[hexEncodedPublicKey]
        if (cachedSwarm != null && cachedSwarm.size >= minimumSnodeCount) {
            val cachedSwarmCopy = mutableListOf<LokiAPITarget>() // Workaround for a Kotlin compiler issue
            cachedSwarmCopy.addAll(cachedSwarm)
            return task { cachedSwarmCopy }
        } else {
            val parameters = mapOf( "pubKey" to hexEncodedPublicKey )
            return getRandomSnode().bind {
                LokiAPI(hexEncodedPublicKey).invoke(LokiAPITarget.Method.GetSwarm, it, hexEncodedPublicKey, parameters)
            }.map {
                parseTargets(it)
            }.success {
                swarmCache[hexEncodedPublicKey] = it
            }
        }
    }
    // endregion

    // region Public API
    internal fun getTargetSnodes(hexEncodedPublicKey: String): Promise<List<LokiAPITarget>, Exception> {
        // SecureRandom() should be cryptographically secure
        return getSwarm(hexEncodedPublicKey).then { it.shuffled(SecureRandom()).take(targetSnodeCount) }
    }
    // endregion

    // region Parsing
    private fun parseTargets(rawResponse: Any): List<LokiAPITarget> {
        return List(3) { LokiAPITarget("http://13.236.173.190", defaultSnodePort) }
    }
    // endregion
}