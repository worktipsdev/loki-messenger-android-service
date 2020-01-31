package org.whispersystems.signalservice.loki.utilities

interface Broadcaster {

    fun broadcast(event: String, long: Long)
}