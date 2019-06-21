package org.whispersystems.signalservice.loki.api

interface LokiP2PAPIDelegate {

    fun ping(contactHexEncodedPublicKey: String)
}