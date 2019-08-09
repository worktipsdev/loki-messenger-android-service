package org.whispersystems.signalservice.loki.messaging

interface LokiMessageDatabaseProtocol {

    fun setServerID(messageID: Long, serverID: Long)
    fun getFriendRequestStatus(messageID: Long): LokiMessageFriendRequestStatus
    fun setFriendRequestStatus(messageID: Long, friendRequestStatus: LokiMessageFriendRequestStatus)
}