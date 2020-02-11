package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.functional.map

object LokiDeviceLinkUtilities {

    fun getMasterHexEncodedPublicKey(hexEncodedPublicKey: String): Promise<String?, Exception> {
        return LokiFileServerAPI.shared.getDeviceLinks(hexEncodedPublicKey).map (LokiFileServerAPI.shared.workContext) { deviceLinks ->
            deviceLinks.find { it.slaveHexEncodedPublicKey == hexEncodedPublicKey }?.masterHexEncodedPublicKey
        }
    }

    fun getSlaveHexEncodedPublicKeys(hexEncodedPublicKey: String): Promise<Set<String>, Exception> {
        return LokiFileServerAPI.shared.getDeviceLinks(hexEncodedPublicKey).map (LokiFileServerAPI.shared.workContext) { deviceLinks ->
            deviceLinks.filter { it.masterHexEncodedPublicKey == hexEncodedPublicKey }.map { it.slaveHexEncodedPublicKey }.toSet()
        }
    }

    fun getAllLinkedDeviceHexEncodedPublicKeys(hexEncodedPublicKey: String): Promise<Set<String>, Exception> {
        return getMasterHexEncodedPublicKey(hexEncodedPublicKey).bind(LokiFileServerAPI.shared.workContext) { masterHexEncodedPublicKey ->
            LokiFileServerAPI.shared.getDeviceLinks(masterHexEncodedPublicKey ?: hexEncodedPublicKey)
        }.map(LokiFileServerAPI.shared.workContext) { deviceLinks ->
            val result = deviceLinks.flatMap { listOf( it.masterHexEncodedPublicKey, it.slaveHexEncodedPublicKey ) }.toMutableSet()
            result.add(hexEncodedPublicKey)
            result
        }
    }
}
