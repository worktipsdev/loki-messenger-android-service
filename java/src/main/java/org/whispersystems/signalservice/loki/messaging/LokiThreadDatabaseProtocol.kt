package org.whispersystems.signalservice.loki.messaging

import org.whispersystems.signalservice.loki.api.LokiPublicChat

interface LokiThreadDatabaseProtocol {

    fun getThreadID(hexEncodedPublicKey: String): Long
    fun setFriendRequestStatus(threadID: Long, friendRequestStatus: LokiThreadFriendRequestStatus)
    fun getSessionResetStatus(threadID: Long): LokiThreadSessionResetStatus
    fun setSessionResetStatus(threadID: Long, sessionResetStatus: LokiThreadSessionResetStatus)
    fun getPublicChat(threadID: Long): LokiPublicChat?
    fun setPublicChat(publicChat: LokiPublicChat, threadID: Long)
    fun removePublicChat(threadID: Long)
}