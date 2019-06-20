package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.*
import nl.komponents.kovenant.functional.bind
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.loki.utilities.prettifiedDescription
import java.security.SecureRandom

private class PromiseCanceledException : Exception("Promise canceled.")

class LokiLongPoller(private val hexEncodedPublicKey: String, private val database: LokiAPIDatabaseProtocol) {
    private var hasStarted: Boolean = false
    private var hasStopped: Boolean = false
    private var connections: Set<Promise<*, Exception>> = setOf()
    private val usedSnodes: MutableSet<LokiAPITarget> = mutableSetOf()

    // region Settings
    companion object {
        private val connectionCount = 3
    }
    // endregion

    // region Public API
    fun startIfNeeded() {
        if (hasStarted) { return }
        Log.d("Loki", "Started long polling.")
        hasStarted = true
        hasStopped = false
        openConnections()
    }

    fun stopIfNeeded() {
        if (hasStopped) { return }
        Log.d("Loki", "Stopped long polling.")
        hasStarted = false
        hasStopped = true
        connections.forEach { Kovenant.cancel(it, PromiseCanceledException()) }
        usedSnodes.clear()
    }
    // endregion

    // region Private API
    private fun openConnections() {
        if (hasStopped) { return }
        LokiSwarmAPI(database).getSwarm(hexEncodedPublicKey).bind {
            usedSnodes.clear()
            connections = (0 until connectionCount).map {
                val deferred = deferred<Unit, Exception>()
                openConnectionToNextSnode(deferred)
                deferred.promise
            }.toSet()
            all(connections.toList(), cancelOthersOnError = false)
        }.always {
            openConnections()
        }
    }

    private fun openConnectionToNextSnode(deferred: Deferred<Unit, Exception>) {
        val swarm = database.getSwarmCache(hexEncodedPublicKey)?.toSet() ?: setOf()
        val unusedSnodes = swarm.subtract(usedSnodes)
        if (unusedSnodes.isNotEmpty()) {
            val index = SecureRandom().nextInt(unusedSnodes.size)
            val nextSnode = unusedSnodes.elementAt(index)
            usedSnodes.add(nextSnode)
            Log.d("Loki", "Opening long polling connection to $nextSnode.")
            longPoll(nextSnode, deferred).fail { exception ->
                if (exception is PromiseCanceledException) {
                    Log.d("Loki", "Long polling connection to $nextSnode canceled.")
                } else {
                    Log.d("Loki", "Long polling connection to $nextSnode failed; dropping it and switching to next snode.")
                    LokiSwarmAPI(database).dropIfNeeded(nextSnode, hexEncodedPublicKey)
                    openConnectionToNextSnode(deferred)
                }
            }
        } else {
            deferred.resolve()
        }
    }

    private fun longPoll(target: LokiAPITarget, deferred: Deferred<Unit, Exception>): Promise<Unit, Exception> {
        return LokiAPI(hexEncodedPublicKey, database).getRawMessages(target, true).bind { rawResponse ->
            if (deferred.promise.isDone()) {
                // The long polling connection has been canceled; don't recurse
                task { Unit }
            } else {
                val messages = LokiAPI(hexEncodedPublicKey, database).parseRawMessagesResponse(rawResponse, target)
                Log.d("Loki", "Retrieved messages: ${messages.prettifiedDescription()}.")
                longPoll(target, deferred)
            }
        }
    }
    // endregion
}