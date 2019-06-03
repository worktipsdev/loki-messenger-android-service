package org.whispersystems.signalservice.loki

interface LokiP2PAPIDelegate {

    fun ping(hexEncodedPublicKey: String)
}