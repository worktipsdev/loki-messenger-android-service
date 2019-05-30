package com.`loki-project`.`loki-messenger`

import java.security.SecureRandom

object LokiSwarmAPI {

    // region Settings
    private val minimumSnodeCount = 2
    private val targetSnodeCount = 3
    private val defaultSnodePort = 8080
    // endregion

    // region Caching
    private val swarmCache = mutableMapOf<String, List<LokiAPITarget>>()
    // endregion

    // region Internal API
    private fun getRandomSnode(): LokiAPITarget {
        return LokiAPITarget("http://13.236.173.190", defaultSnodePort)
    }

    private fun getSwarm(hexEncodedPublicKey: String): List<LokiAPITarget> {
        val cachedSwarm = swarmCache[hexEncodedPublicKey]
        if (cachedSwarm != null && cachedSwarm.size >= minimumSnodeCount) {
            return cachedSwarm
        } else {
            val parameters = mapOf( "pubKey" to hexEncodedPublicKey )
            val randomSnode = getRandomSnode()
            LokiAPI(hexEncodedPublicKey).invoke(LokiAPITarget.Method.GetSwarm, randomSnode, hexEncodedPublicKey, parameters)
            val swarm = parseTargets()
            swarmCache[hexEncodedPublicKey] = swarm
            return swarm
        }
    }
    // endregion

    // region Public API
    fun getTargetSnodes(hexEncodedPublicKey: String): List<LokiAPITarget> {
        // SecureRandom() should be cryptographically secure
        return getSwarm(hexEncodedPublicKey).shuffled(SecureRandom()).take(targetSnodeCount)
    }
    // endregion

    // region Parsing
    private fun parseTargets(): List<LokiAPITarget> {
        return List(3) { LokiAPITarget("http://13.236.173.190", defaultSnodePort) }
    }
    // endregion
}