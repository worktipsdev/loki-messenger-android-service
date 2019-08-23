package org.whispersystems.signalservice.loki.messaging

interface LokiUserDatabaseProtocol {

    fun getDisplayName(hexEncodedPublicKey: String): String?
    fun getToken(serverUrl: String): String?
    fun setToken(token: String, serverUrl: String)
}