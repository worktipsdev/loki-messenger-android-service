package org.whispersystems.signalservice.loki.messaging

interface LokiThreadDatabaseProtocol {

    fun getThreadID(messageID: Long): Long
    fun setFriendRequestStatus(threadID: Long, friendRequestStatus: LokiThreadFriendRequestStatus)

    fun getSessionResetState(threadID: Long): LokiThreadSessionResetState
    fun setSessionResetState(threadID: Long, sessionResetState: LokiThreadSessionResetState)
}