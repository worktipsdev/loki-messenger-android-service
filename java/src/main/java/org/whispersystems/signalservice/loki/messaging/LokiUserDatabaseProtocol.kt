package org.whispersystems.signalservice.loki.messaging

interface LokiUserDatabaseProtocol {

    fun getDisplayName(hexEncodedPublicKey: String): String?
}