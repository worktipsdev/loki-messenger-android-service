package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.*
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded

private class CancelledException: Exception("Cancelled")

class LokiLongPoller(private val hexEncodedPublicKey: String, private val api: LokiAPI, private val database: LokiAPIDatabaseProtocol) {
    private val swarmAPI = LokiSwarmAPI(database)

    // region Settings
    private var isLongPolling: Boolean = false
    private var shouldStopPolling: Boolean = false
    private val usedSnodes: MutableList<LokiAPITarget> = mutableListOf()
    private val ongoingConnections: MutableList<Promise<*, Exception>> = mutableListOf()
    // endregion

    fun startIfNecessary() {
        if (isLongPolling) { return }
        isLongPolling = true
        shouldStopPolling = false

        Log.i("LOKI", "Started long polling")

        longPoll()
    }

    fun stop() {
        shouldStopPolling = true
        isLongPolling = false
        usedSnodes.clear()
        cancelAllPromises()
    }

    private fun cancelAllPromises() {
        ongoingConnections.forEach { Kovenant.cancel(it, CancelledException()) }
        ongoingConnections.clear()
    }

    private fun getUnusedSnodes(): List<LokiAPITarget> {
        val swarm = database.getSwarmCache(hexEncodedPublicKey) ?: listOf()
        return swarm.filter { !usedSnodes.contains(it) }
    }

    private fun longPoll() {
        if (shouldStopPolling) { return }

        swarmAPI.getSwarm(hexEncodedPublicKey).then {
            val connections = 3
            for (i in 0 until connections) {
                val promise = openConnection()
                ongoingConnections.add(promise)
            }

            all(ongoingConnections, cancelOthersOnError = false)
        }.always {
            // Since all promises are complete, we can clear the cancels
            cancelAllPromises()

            // Keep long polling until it's stopped
            longPoll()
        }
    }

    private fun openConnection(): Promise<Unit, Exception> {
        val deferred = deferred<Unit, Exception> {
            Log.i("LOKI", "Cancelled open connection")
        }

        connectToNextSnode(deferred)

        return deferred.promise
    }

    private fun connectToNextSnode(deferred: Deferred<Unit, Exception>) {
        if (deferred.promise.isDone()) { return }

        // Get the next snode
        val nextSnode = getUnusedSnodes().firstOrNull()
        if (nextSnode == null) {
            // No more snodes left, terminate connection
            deferred.resolve()
            return
        }

        // Add the snode to the used array
        usedSnodes.add(nextSnode)

        getMessagesInfinitely(nextSnode, deferred.promise).fail {
            // If we got an error and we haven't cancelled, connect to the next snode
            // We also want to remove the current snode from our cache
            if (!deferred.promise.isDone()) {
                swarmAPI.dropIfNeeded(nextSnode, hexEncodedPublicKey)
                connectToNextSnode(deferred)
            }
        }
    }

    private fun getMessagesInfinitely(target: LokiAPITarget, deferredPromise: Promise<Unit, Exception>): Promise<Unit, Unit> {
        return retryIfNeeded(maxRetryCount = 3) {
            api.getRawMessages(target, true).then { rawResponse ->
                if (deferredPromise.isDone()) {
                    // We have cancelled, just return success
                    return@then Any()
                } else {
                    val messages = api.parseRawMessagesResponse(rawResponse, target)
                    // TODO: Notify of new messages?

                    return@then getMessagesInfinitely(target, deferredPromise)
                }
            }
        }.unwrap().toVoid()
    }
}