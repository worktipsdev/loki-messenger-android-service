package org.whispersystems.signalservice.loki.messaging

interface LokiMessageDatabaseProtocol {

    fun getFriendRequestStatus(messageID: Long): LokiMessageFriendRequestStatus
    fun setFriendRequestStatus(messageID: Long, friendRequestStatus: LokiMessageFriendRequestStatus)
}