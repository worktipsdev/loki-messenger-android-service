package com.`loki-project`.`loki-messenger`

import java.util.*

class LokiP2PAPI(private val hexEncodedPublicKey: String) {
    private val peerInfo = mutableMapOf<String, PeerInfo>()
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

    // region Public API
    fun handlePeerInfoReceived(hexEncodedPublicKey: String, address: String, port: Int, isP2PMessage: Boolean) {
        val pingInterval = if (hexEncodedPublicKey < this.hexEncodedPublicKey) 1 * 60 else 2 * 60
        pingIntervals[hexEncodedPublicKey] = pingInterval
        val oldPeerInfo = peerInfo[hexEncodedPublicKey]
        val newPeerInfo = PeerInfo(hexEncodedPublicKey, address, port, false)
        peerInfo[hexEncodedPublicKey] = newPeerInfo
        // Send our info back to the peer if either:
        // • We didn't know about the peer, i.e. we didn't establish a P2P connection yet in this session
        // • The message wasn't a P2P message, i.e. no P2P connection was established in this session or it was dropped for some reason
        // • The peer was marked as offline before; in this case we want to test the newly established P2P connection
        // • The peer's details changed; we want to test the updated P2P connection
        if (oldPeerInfo == null || !isP2PMessage || !oldPeerInfo.isOnline || oldPeerInfo.address != address || oldPeerInfo.port != port) {
            ping(hexEncodedPublicKey)
            markAsOffline(hexEncodedPublicKey)
        } else {
            markAsOnline(hexEncodedPublicKey)
        }
    }


    fun ping(hexEncodedPublicKey: String) {
        // TODO: Implement
    }

    fun markAsOnline(hexEncodedPublicKey: String) {
        // TODO: Implement
    }

    fun markAsOffline(hexEncodedPublicKey: String) {
        // TODO: Implement
    }
    // endregion
}