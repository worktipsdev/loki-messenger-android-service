package org.whispersystems.signalservice.loki.messaging

interface LokiMessageDatabaseProtocol {
    fun getServerIDFromQuote(quoteID: Long, author: String): Long?
    fun setServerID(messageID: Long, serverID: Long)
    fun setFriendRequestStatus(messageID: Long, friendRequestStatus: LokiMessageFriendRequestStatus)
}