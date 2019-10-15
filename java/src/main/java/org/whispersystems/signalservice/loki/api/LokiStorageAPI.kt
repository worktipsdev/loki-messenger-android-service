package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.functional.map
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded

class LokiStorageAPI(private val server: String, private val userHexEncodedPublicKey: String, private val userPrivateKey: ByteArray, private val database: LokiAPIDatabaseProtocol) : LokiDotNetAPI(userHexEncodedPublicKey, userPrivateKey, database) {

  companion object {
    // region Settings
    private val maxRetryCount = 8
    private val lastDeviceLinkUpdate = hashMapOf<String, Long>()
    private val deviceMappingUpdateInterval = 8 * 60 * 1000
    private val deviceMappingType = "network.loki.messenger.devicemapping"
    // endregion

    // region Initialization
    lateinit var shared: LokiStorageAPI

    /**
     * Must be called before `LokiAPI` is used.
     */
    fun configure(isDebugMode: Boolean, userHexEncodedPublicKey: String,  userPrivateKey: ByteArray, database: LokiAPIDatabaseProtocol) {
      if (::shared.isInitialized) { return }
      // TODO: Re-enable when we have dev file server
      val server = if (false && isDebugMode) "https://file-dev.lokinet.org" else "https://file.lokinet.org"
      shared = LokiStorageAPI(server, userHexEncodedPublicKey, userPrivateKey, database)
    }
    // endregion
  }

  // region Private API
  private fun fetchDeviceMappings(hexEncodedPublicKey: String): Promise<List<PairingAuthorisation>, Exception> {
    val parameters = mapOf( "include_user_annotations" to 1 )
    return execute(HTTPVerb.GET, server, "users/@$hexEncodedPublicKey", false, parameters).map { rawResponse ->
      try {
        val bodyAsString = rawResponse.body()!!.string()
        val body = JsonUtil.fromJson(bodyAsString)
        val data = body.get("data")
        if (data == null) {
          Log.d("Loki", "Couldn't parse device mappings for user: $hexEncodedPublicKey from: $rawResponse.")
          throw Error.ParsingFailed
        }
        val annotations = data.get("annotations")
        val deviceMappingAnnotation = annotations.find { annotation ->
            annotation.get("type").asText() == deviceMappingType
        }
        if (deviceMappingAnnotation == null) {
          Log.d("Loki", "Couldn't parse device mappings for user: $hexEncodedPublicKey from: $rawResponse.")
          throw Error.ParsingFailed
        }
        val value = deviceMappingAnnotation.get("value")
        val authorisationsAsJSON = value.get("authorisations")
        authorisationsAsJSON.mapNotNull { authorisationAsJSON ->
          try {
            val primaryDevicePublicKey = authorisationAsJSON.get("primaryDevicePubKey").asText()
            val secondaryDevicePublicKey = authorisationAsJSON.get("secondaryDevicePubKey").asText()
            var requestSignature: ByteArray? = null
            var grantSignature: ByteArray? = null
            if (authorisationAsJSON.hasNonNull("requestSignature")) {
              val base64EncodedSignature = authorisationAsJSON.get("requestSignature").asText()
              requestSignature = Base64.decode(base64EncodedSignature)
            }
            if (authorisationAsJSON.hasNonNull("grantSignature")) {
              val base64EncodedSignature = authorisationAsJSON.get("grantSignature").asText()
              grantSignature = Base64.decode(base64EncodedSignature)
            }
            val authorisation = PairingAuthorisation(primaryDevicePublicKey, secondaryDevicePublicKey, requestSignature, grantSignature)
            val isValid = authorisation.verify()
            if (!isValid) {
              Log.d("Loki", "Invalid authorisation received: $authorisationAsJSON.")
              return@mapNotNull null
            }
            authorisation
          } catch (e: Exception) {
            Log.d("Loki", "Failed to parse device mapping for $hexEncodedPublicKey from $authorisationAsJSON due to error: $e.")
            null
          }
        }
      } catch (exception: Exception) {
        Log.d("Loki", "Failed to parse device mappings for: $hexEncodedPublicKey from $rawResponse due to error: $exception.")
        throw Error.ParsingFailed
      }
    }
  }

  private fun fetchAndSaveDeviceMappings(hexEncodedPublicKey: String): Promise<List<PairingAuthorisation>, Exception> {
    return fetchDeviceMappings(hexEncodedPublicKey).success { authorisations ->
      database.removePairingAuthorisations(hexEncodedPublicKey)
      authorisations.forEach { database.insertOrUpdatePairingAuthorisation(it) }
    }
  }
  // endregion

  // region Public API
  fun getDeviceMappings(hexEncodedPublicKey: String, skipCache: Boolean = false): Promise<List<PairingAuthorisation>, Exception> {
    val databaseAuthorisations = database.getPairingAuthorisations(hexEncodedPublicKey)
    val now = System.currentTimeMillis()
    val hasCacheExpired = !lastDeviceLinkUpdate.containsKey(hexEncodedPublicKey) || (now - lastDeviceLinkUpdate[hexEncodedPublicKey]!! > deviceMappingUpdateInterval)
    val isSelf = (hexEncodedPublicKey == userHexEncodedPublicKey) // Don't rely on the server for the user's own device mapping
    if (!isSelf && (hasCacheExpired || skipCache)) {
      val deferred = deferred<List<PairingAuthorisation>, Exception>()
      // Try and fetch the device mappings, otherwise fall back to database
      fetchAndSaveDeviceMappings(hexEncodedPublicKey).success { authorisations ->
        lastDeviceLinkUpdate[hexEncodedPublicKey] = now
        deferred.resolve(authorisations)
      }.fail {
        // If we errored out due to a parsing failure then don't immediately re-fetch
        if (it is Error.ParsingFailed) { lastDeviceLinkUpdate[hexEncodedPublicKey] = now }
        deferred.resolve(databaseAuthorisations)
      }
      return deferred.promise
    } else {
      return Promise.of(databaseAuthorisations)
    }
  }

  fun getPrimaryDevicePublicKey(hexEncodedPublicKey: String): Promise<String?, Exception> {
    return getDeviceMappings(hexEncodedPublicKey).map { authorisations ->
      val pairing = authorisations.find { it.secondaryDevicePublicKey == hexEncodedPublicKey }
      pairing?.primaryDevicePublicKey
    }
  }

  fun getSecondaryDevicePublicKeys(hexEncodedPublicKey: String): Promise<List<String>, Exception> {
    return getDeviceMappings(hexEncodedPublicKey).map { authorisations ->
      authorisations.filter { it.primaryDevicePublicKey == hexEncodedPublicKey }.map { it.secondaryDevicePublicKey }
    }
  }

  fun getAllDevicePublicKeys(hexEncodedPublicKey: String): Promise<Set<String>, Exception> {
    return getDeviceMappings(hexEncodedPublicKey).map { authorisations ->
      val publicKeys = authorisations.flatMap { listOf(it.primaryDevicePublicKey, it.secondaryDevicePublicKey) }.toSet()
      publicKeys.plus(hexEncodedPublicKey)
    }
  }

  fun updateUserDeviceMappings(): Promise<Unit, Exception> {
    return getDeviceMappings(userHexEncodedPublicKey).bind { authorisations ->
      // We are a primary device if an authorisation has us listed as one
      val isPrimary = authorisations.find { it.primaryDevicePublicKey == userHexEncodedPublicKey } != null
      retryIfNeeded(maxRetryCount) {
        val authorisationsAsJSON = authorisations.map { it.toJSON() }
        val value = if (authorisations.count() > 0) mapOf( "isPrimary" to isPrimary, "authorisations" to authorisationsAsJSON ) else null
        setSelfAnnotation(server, deviceMappingType, value).get()
      }
    }.map { Unit }
  }
  // endregion
}