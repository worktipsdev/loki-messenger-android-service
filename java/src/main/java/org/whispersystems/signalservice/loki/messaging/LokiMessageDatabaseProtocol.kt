package org.whispersystems.signalservice.loki.messaging

interface LokiMessageDatabaseProtocol {

    fun getQuoteServerID(quoteID: Long, quoteeHexEncodedPublicKey: String): Long?
    fun setServerID(messageID: Long, serverID: Long)
    fun setFriendRequestStatus(messageID: Long, friendRequestStatus: LokiMessageFriendRequestStatus)
}