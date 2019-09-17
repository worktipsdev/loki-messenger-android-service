package org.whispersystems.signalservice.loki.messaging

interface LokiMessageDatabaseProtocol {

    fun setServerID(messageID: Long, serverID: Long)
    fun setFriendRequestStatus(messageID: Long, friendRequestStatus: LokiMessageFriendRequestStatus)
}