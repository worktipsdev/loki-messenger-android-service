package org.whispersystems.signalservice.loki.api

interface LokiAPIDatabaseProtocol {

    fun getSwarmCache(hexEncodedPublicKey: String): List<LokiAPITarget>?
    fun setSwarmCache(hexEncodedPublicKey: String, newValue: List<LokiAPITarget>)
    fun getLastMessageHashValue(target: LokiAPITarget): String?
    fun setLastMessageHashValue(target: LokiAPITarget, newValue: String)
    fun getReceivedMessageHashValues(): Set<String>?
    fun setReceivedMessageHashValues(newValue: Set<String>)
}