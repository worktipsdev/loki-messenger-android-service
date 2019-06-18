package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.functional.map
import nl.komponents.kovenant.task
import nl.komponents.kovenant.then
import java.security.SecureRandom

internal class LokiSwarmAPI(private val database: LokiAPIDatabaseProtocol) {

    // region Settings
    private val minimumSnodeCount = 2 // TODO: For debugging purposes
    private val targetSnodeCount = 3 // TODO: For debugging purposes
    private val defaultSnodePort = 8080
    // endregion

    // region Caching
    internal fun dropIfNeeded(target: LokiAPITarget, hexEncodedPublicKey: String) {
        val swarm = database.getSwarmCache(hexEncodedPublicKey)?.toMutableList()
        if (swarm != null && swarm.contains(target)) {
            swarm.remove(target)
            database.setSwarmCache(hexEncodedPublicKey, swarm)
        }
    }
    // endregion

    // region Internal API
    private fun getRandomSnode(): Promise<LokiAPITarget, Exception> {
        return task {
            LokiAPITarget("http://13.236.173.190", defaultSnodePort) // TODO: For debugging purposes
        }
    }

    internal fun getSwarm(hexEncodedPublicKey: String): Promise<List<LokiAPITarget>, Exception> {
        val cachedSwarm = database.getSwarmCache(hexEncodedPublicKey)
        if (cachedSwarm != null && cachedSwarm.size >= minimumSnodeCount) {
            val cachedSwarmCopy = mutableListOf<LokiAPITarget>() // Workaround for a Kotlin compiler issue
            cachedSwarmCopy.addAll(cachedSwarm)
            return task { cachedSwarmCopy }
        } else {
            val parameters = mapOf( "pubKey" to hexEncodedPublicKey )
            return getRandomSnode().bind {
                LokiAPI(hexEncodedPublicKey, database).invoke(LokiAPITarget.Method.GetSwarm, it, hexEncodedPublicKey, parameters)
            }.map {
                parseTargets(it)
            }.success {
                database.setSwarmCache(hexEncodedPublicKey, it)
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