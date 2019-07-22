package org.whispersystems.signalservice.loki.messaging

interface LokiThreadDatabaseProtocol {

    fun getThreadID(messageID: Long): Long
    fun setFriendRequestStatus(threadID: Long, friendRequestStatus: LokiThreadFriendRequestStatus)
    fun getSessionResetStatus(threadID: Long): LokiThreadSessionResetStatus
    fun setSessionResetStatus(threadID: Long, sessionResetStatus: LokiThreadSessionResetStatus)
}