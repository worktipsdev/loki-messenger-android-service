package org.whispersystems.signalservice.loki.utilities

import kotlin.concurrent.timer

class Poller(private val interval: Long, private val onPoll: () -> Unit) {
    private var isStarted = false

    fun startIfNeeded() {
        if (isStarted) { return }
        timer(period = interval) { onPoll() }
        isStarted = true
    }
}