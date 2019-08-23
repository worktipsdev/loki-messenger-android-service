package org.whispersystems.signalservice.loki.messaging

interface LokiUserDatabaseProtocol {

    fun getDisplayName(hexEncodedPublicKey: String): String?
    fun getToken(server: String): String?
    fun setToken(token: String, server: String)
}