package org.whispersystems.signalservice.loki.api

interface LokiAPIDatabaseProtocol {

    fun getSwarmCache(hexEncodedPublicKey: String): Set<LokiAPITarget>?
    fun setSwarmCache(hexEncodedPublicKey: String, newValue: Set<LokiAPITarget>)
    fun getLastMessageHashValue(target: LokiAPITarget): String?
    fun setLastMessageHashValue(target: LokiAPITarget, newValue: String)
    fun getReceivedMessageHashValues(): Set<String>?
    fun setReceivedMessageHashValues(newValue: Set<String>)
    fun getAuthToken(server: String): String?
    fun setAuthToken(server: String, newValue: String?)
    fun getLastMessageServerID(group: Long, server: String): Long?
    fun setLastMessageServerID(group: Long, server: String, newValue: Long)
    fun getLastDeletionServerID(group: Long, server: String): Long?
    fun setLastDeletionServerID(group: Long, server: String, newValue: Long)
    fun getDeviceLinks(hexEncodedPublicKey: String): Set<DeviceLink>
    fun clearDeviceLinks(hexEncodedPublicKey: String)
    fun addDeviceLink(deviceLink: DeviceLink)
    fun removeDeviceLink(deviceLink: DeviceLink)
    fun setUserCount(userCount: Int, group: Long, server: String)
}
