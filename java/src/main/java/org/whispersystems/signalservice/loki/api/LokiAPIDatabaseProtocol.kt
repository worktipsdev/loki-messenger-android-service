package org.whispersystems.signalservice.loki.api

interface LokiAPIDatabaseProtocol {

    fun getSwarmCache(hexEncodedPublicKey: String): Set<LokiAPITarget>?
    fun setSwarmCache(hexEncodedPublicKey: String, newValue: Set<LokiAPITarget>)
    fun getLastMessageHashValue(target: LokiAPITarget): String?
    fun setLastMessageHashValue(target: LokiAPITarget, newValue: String)
    fun getReceivedMessageHashValues(): Set<String>?
    fun setReceivedMessageHashValues(newValue: Set<String>)
    fun getGroupChatAuthToken(serverURL: String): String?
    fun setGroupChatAuthToken(serverURL: String, newValue: String?)
    fun getLastMessageServerID(groupID: Long): Long?
    fun setLastMessageServerID(groupID: Long, newValue: Long)
    fun getFirstMessageServerID(groupID: Long): Long?
    fun setFirstMessageServerID(groupID: Long, newValue: Long)
}