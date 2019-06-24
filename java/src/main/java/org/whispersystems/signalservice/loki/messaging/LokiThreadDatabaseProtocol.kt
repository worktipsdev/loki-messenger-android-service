package org.whispersystems.signalservice.loki.messaging

interface LokiThreadDatabaseProtocol {

    fun getThreadID(messageID: Long): Long
    fun getFriendRequestStatus(threadID: Long): LokiThreadFriendRequestStatus
    fun setFriendRequestStatus(threadID: Long, friendRequestStatus: LokiThreadFriendRequestStatus)
}