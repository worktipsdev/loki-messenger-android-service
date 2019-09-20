package org.whispersystems.signalservice.loki.api

import java.util.*
import kotlin.concurrent.schedule

class LokiDeviceLinkingSession(private val delegate: LokiDeviceLinkingSessionDelegate) {

    private val listeningTimeout: Long = 60 * 1000
    private var timerTask: TimerTask? = null

    val isListeningForLinkingRequest: Boolean
        get() = timerTask != null

    fun startListeningForLinkingRequests() {
        if (isListeningForLinkingRequest) {
            return
        }

        timerTask = Timer("DeviceLinkingTimer").schedule(listeningTimeout) {
            delegate.onDeviceLinkingTimeout()
            stopListeningForLinkingRequests()
        }
    }

    fun receivedLinkingRequest(authorisation: LokiPairingAuthorisation) {
        if (!isListeningForLinkingRequest) {
            return
        }
        delegate.onDeviceLinkingRequestReceived(authorisation)
    }

    fun stopListeningForLinkingRequests() {
        timerTask?.cancel()
        timerTask = null
    }
}