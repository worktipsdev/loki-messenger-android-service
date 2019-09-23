package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise

class LokiStorageAPI(private val database: LokiStorageAPIDatabaseProtocol) {

  // region Initialization
  companion object {
    private var isConfigured = false

    lateinit var shared: LokiStorageAPI

    /**
     * Must be called before `LokiAPI` is used.
     */
    fun configure(database: LokiStorageAPIDatabaseProtocol) {
      if (isConfigured) { return }
      shared = LokiStorageAPI(database)
      isConfigured = true
    }
  }
  // endregion

  fun fetchDeviceMappings(pubKey: String) {
    // TODO: Implement
  }

  fun getPrimaryDevice(secondaryDevicePubKey: String): Promise<String?, Exception> {
    // TODO: Implement lazy fetching after every x minutes
    return Promise.of(database.getPrimaryDevice(secondaryDevicePubKey))
  }

  fun getSecondaryDevices(primaryDevicePubKey: String): Promise<List<String>, Exception> {
    // TODO: Implement lazy fetching after every x minutes
    return Promise.of(database.getSecondaryDevices(primaryDevicePubKey))
  }
}