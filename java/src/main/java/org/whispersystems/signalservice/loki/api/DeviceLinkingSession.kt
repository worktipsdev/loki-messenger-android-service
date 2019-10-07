package org.whispersystems.signalservice.loki.api

class DeviceLinkingSession {
    private val listeners = mutableListOf<DeviceLinkingSessionListener>()
    var isListeningForLinkingRequests: Boolean = false
        private set

    companion object {
        val shared = DeviceLinkingSession()
    }

    fun addListener(listener: DeviceLinkingSessionListener) {
        listeners.add(listener)
    }

    fun removeListener(listener: DeviceLinkingSessionListener) {
        listeners.remove(listener)
    }

    fun startListeningForLinkingRequests() {
        isListeningForLinkingRequests = true
    }

    fun stopListeningForLinkingRequests() {
        isListeningForLinkingRequests = false
    }

    fun processLinkingRequest(authorisation: PairingAuthorisation) {
        if (!isListeningForLinkingRequests || !authorisation.verify()) { return }
        listeners.forEach { it.requestUserAuthorization(authorisation) }
    }

    fun processLinkingAuthorization(authorisation: PairingAuthorisation) {
        if (!isListeningForLinkingRequests || !authorisation.verify()) { return }
        listeners.forEach { it.onDeviceLinkRequestAuthorized(authorisation) }
    }
}