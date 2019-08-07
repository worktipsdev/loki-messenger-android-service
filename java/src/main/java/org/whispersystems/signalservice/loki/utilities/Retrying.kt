package org.whispersystems.signalservice.loki.utilities

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.task
import java.util.*

fun <T> retryIfNeeded(maxRetryCount: Int, retryInterval: Long = 1 * 1000, body: () -> T): Promise<T, Exception> {
    var retryCount = 0
    val deferred = deferred<T, Exception>()
    val thread = Thread.currentThread()
    fun retryIfNeeded() {
        task { body() }.success {
            deferred.resolve(it)
        }.fail {
            if (retryCount == maxRetryCount) {
                deferred.reject(it)
            } else {
                retryCount += 1
                Timer().schedule(object : TimerTask() {

                    override fun run() {
                        thread.run { retryIfNeeded() }
                    }
                }, retryInterval)
            }
        }
    }
    retryIfNeeded()
    return deferred.promise
}
