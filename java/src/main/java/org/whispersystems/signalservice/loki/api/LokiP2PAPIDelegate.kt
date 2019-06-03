package org.whispersystems.signalservice.loki.api

interface LokiP2PAPIDelegate {

    fun ping(hexEncodedPublicKey: String)
}