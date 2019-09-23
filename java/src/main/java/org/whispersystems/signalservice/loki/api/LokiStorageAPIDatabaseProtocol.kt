package org.whispersystems.signalservice.loki.api

interface LokiStorageAPIDatabaseProtocol {
    fun getPrimaryDevice(secondaryDevicePubKey: String): String?
    fun getSecondaryDevices(primaryDevicePubKey: String): List<String>
    fun insertOrUpdatePairingAuthorisation(authorisation: LokiPairingAuthorisation)
    fun removePairingAuthorisations(pubKey: String)
}