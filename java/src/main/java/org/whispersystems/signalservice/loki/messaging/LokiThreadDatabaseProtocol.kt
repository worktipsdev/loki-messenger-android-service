package org.whispersystems.signalservice.loki.messaging

import org.whispersystems.libsignal.loki.LokiSessionResetProtocol
import org.whispersystems.signalservice.loki.api.LokiPublicChat

interface LokiThreadDatabaseProtocol: LokiSessionResetProtocol {

    fun getThreadID(hexEncodedPublicKey: String): Long
    fun setFriendRequestStatus(threadID: Long, friendRequestStatus: LokiThreadFriendRequestStatus)
    fun getPublicChat(threadID: Long): LokiPublicChat?
    fun setPublicChat(publicChat: LokiPublicChat, threadID: Long)
    fun removePublicChat(threadID: Long)
}
