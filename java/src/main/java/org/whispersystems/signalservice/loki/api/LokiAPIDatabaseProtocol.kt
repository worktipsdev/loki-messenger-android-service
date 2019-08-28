package org.whispersystems.signalservice.loki.api

interface LokiAPIDatabaseProtocol {

    fun getSwarmCache(hexEncodedPublicKey: String): Set<LokiAPITarget>?
    fun setSwarmCache(hexEncodedPublicKey: String, newValue: Set<LokiAPITarget>)
    fun getLastMessageHashValue(target: LokiAPITarget): String?
    fun setLastMessageHashValue(target: LokiAPITarget, newValue: String)
    fun getReceivedMessageHashValues(): Set<String>?
    fun setReceivedMessageHashValues(newValue: Set<String>)
    fun getGroupChatAuthToken(server: String): String?
    fun setGroupChatAuthToken(server: String, newValue: String?)
    fun getLastMessageServerID(group: Long, server: String): Long?
    fun setLastMessageServerID(group: Long, server: String, newValue: Long)
    fun getFirstMessageServerID(group: Long, server: String): Long?
    fun setFirstMessageServerID(group: Long, server: String, newValue: Long)
}