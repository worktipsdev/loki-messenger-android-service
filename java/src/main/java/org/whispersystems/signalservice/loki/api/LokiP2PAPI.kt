package org.whispersystems.signalservice.loki.api

import java.util.*
import kotlin.concurrent.timer

class LokiP2PAPI private constructor(private val hexEncodedPublicKey: String, private val onPeerConnectionStatusChanged: (Boolean, String) -> Void, private val delegate: LokiP2PAPIDelegate) {
    internal val peerInfo = mutableMapOf<String, PeerInfo>()
    private val pingIntervals = mutableMapOf<String, Int>()
    private val timers = mutableMapOf<String, Timer>()

    // region Settings
    /**
     * The pinging interval for offline users.
     */
    private val offlinePingInterval = 2 * 60
    // endregion

    // region Types
    internal data class PeerInfo(val hexEncodedPublicKey: String, val address: String, val port: Int, val isOnline: Boolean)
    // endregion

    // region Initialization
    companion object {
        private var isConfigured = false

        lateinit var shared: LokiP2PAPI

        /**
         * Must be called before `LokiAPI` is used.
         */
        fun configure(hexEncodedPublicKey: String, onPeerConnectionStatusChanged: (Boolean, String) -> Void, delegate: LokiP2PAPIDelegate) {
            if (isConfigured) { throw Exception("It's illegal to call LokiP2PAPI.configure(...) more than once.") }
            shared = LokiP2PAPI(hexEncodedPublicKey, onPeerConnectionStatusChanged, delegate)
            isConfigured = true
        }
    }
    // endregion

    // region Public API
    fun handlePeerInfoReceived(hexEncodedPublicKey: String, address: String, port: Int, isP2PMessage: Boolean) {
        // Avoid peers pinging eachother at the same time by staggering their timers
        val pingInterval = if (hexEncodedPublicKey < this.hexEncodedPublicKey) 1 * 60 else 2 * 60
        pingIntervals[hexEncodedPublicKey] = pingInterval
        val oldPeerInfo = peerInfo[hexEncodedPublicKey]
        val newPeerInfo = PeerInfo(hexEncodedPublicKey, address, port, false)
        peerInfo[hexEncodedPublicKey] = newPeerInfo
        // Ping the peer back and mark them online based on the result of that call if either:
        // • We didn't know about the peer at all, i.e. no P2P connection was established yet during this session
        // • The message wasn't a P2P message, i.e. no P2P connection was established yet during this session or it was dropped for some reason
        // • The peer was marked offline before; test the new P2P connection
        // • The peer's address and/or port changed; test the new P2P connection
        if (oldPeerInfo == null || !isP2PMessage || !oldPeerInfo.isOnline || oldPeerInfo.address != address || oldPeerInfo.port != port) {
            delegate.ping(hexEncodedPublicKey)
        } else {
            mark(isOnline = true, hexEncodedPublicKey = hexEncodedPublicKey)
        }
    }

    fun mark(isOnline: Boolean, hexEncodedPublicKey: String) {
        val oldTimer = timers[hexEncodedPublicKey]
        oldTimer?.cancel()
        val pingInterval = if (isOnline) { pingIntervals[hexEncodedPublicKey]!! } else { offlinePingInterval }
        val newTimer = timer(period = pingInterval.toLong()) { delegate.ping(hexEncodedPublicKey) }
        timers[hexEncodedPublicKey] = newTimer
        val updatedPeerInfo = peerInfo[hexEncodedPublicKey]!!.copy(isOnline = isOnline)
        peerInfo[hexEncodedPublicKey] = updatedPeerInfo
        onPeerConnectionStatusChanged(isOnline, hexEncodedPublicKey)
    }
    // endregion
}