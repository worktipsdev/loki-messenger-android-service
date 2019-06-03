package org.whispersystems.signalservice.loki.api

interface LokiAPIDatabaseProtocol {

    fun getSwarmCache(): Map<String, List<LokiAPITarget>>?
    fun setSwarmCache(newValue: Map<String, List<LokiAPITarget>>)
    fun getLastMessageHashValue(target: LokiAPITarget): String?
    fun setLastMessageHashValue(target: LokiAPITarget, newValue: String)
    fun getReceivedMessageHashValues(): Set<String>?
    fun setReceivedMessageHashValues(newValue: Set<String>)
}