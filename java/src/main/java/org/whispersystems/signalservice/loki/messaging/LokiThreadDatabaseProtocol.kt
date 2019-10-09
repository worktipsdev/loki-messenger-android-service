package org.whispersystems.signalservice.loki.messaging

import org.whispersystems.signalservice.loki.api.LokiGroupChat

interface LokiThreadDatabaseProtocol {

    fun getThreadID(hexEncodedPublicKey: String): Long
    fun setFriendRequestStatus(threadID: Long, friendRequestStatus: LokiThreadFriendRequestStatus)
    fun getSessionResetStatus(threadID: Long): LokiThreadSessionResetStatus
    fun setSessionResetStatus(threadID: Long, sessionResetStatus: LokiThreadSessionResetStatus)
    fun getGroupChat(threadID: Long): LokiGroupChat?
    fun setGroupChat(groupChat: LokiGroupChat, threadID: Long)
    fun removeGroupChat(threadID: Long)
}