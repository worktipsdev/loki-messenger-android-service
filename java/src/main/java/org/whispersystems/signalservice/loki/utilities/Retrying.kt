package org.whispersystems.signalservice.loki.utilities

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.task

fun <T> retryIfNeeded(maxRetryCount: Int, body: () -> T): Promise<T, Exception> {
    var retryCount = 0
    val deferred = deferred<T, Exception>()
    fun retryIfNeeded() {
        task { body() }.success {
            deferred.resolve(it)
        }.fail {
            if (retryCount == maxRetryCount) {
                deferred.reject(it)
            } else {
                retryCount += 1
                retryIfNeeded()
            }
        }
    }
    retryIfNeeded()
    return deferred.promise
}
