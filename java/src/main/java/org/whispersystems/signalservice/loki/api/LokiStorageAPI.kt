package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.functional.map
import nl.komponents.kovenant.toSuccessVoid
import nl.komponents.kovenant.unwrap
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded

class LokiStorageAPI(private val server: String, private val userHexEncodedPublicKey: String, private val userPrivateKey: ByteArray, private val database: LokiAPIDatabaseProtocol) {

  companion object {
    // region Initialization
    private var isConfigured = false

    lateinit var shared: LokiStorageAPI

    /**
     * Must be called before `LokiAPI` is used.
     */
    fun configure(userHexEncodedPublicKey: String,  userPrivateKey: ByteArray, database: LokiAPIDatabaseProtocol) {
      if (isConfigured) { return }
      shared = LokiStorageAPI(serverUrl, userHexEncodedPublicKey, userPrivateKey, database)
      isConfigured = true
    }
    // endregion

    // TODO: In the future we should be able to switch servers
    public val serverUrl = ""

    private val maxRetryCount = 8
    private val lastFetchedCache = hashMapOf<String, Long>()
    private val cacheTime = 5 * 60 * 1000 // 5 minutes

    private val deviceMappingAnnotationKey = "network.loki.messenger.devicemapping"
  }

  private val dotNetAPI = LokiDotNetAPI(userHexEncodedPublicKey, userPrivateKey, database)

  private fun fetchDeviceMappings(pubKey: String): Promise<List<LokiPairingAuthorisation>, Exception> {
    return dotNetAPI.get(server, "users/@$pubKey", mapOf("include_user_annotations" to 1)).map { response ->
      try {
        val bodyAsString = response.body()!!.string()
        val body = JsonUtil.fromJson(bodyAsString, Map::class.java)
        val data = body["data"] as Map<*, *>
        val annotations = data["annotations"] as List<Map<*,*>>
        val deviceMappingAnnotation = annotations.find { annotation ->
            val type = annotation["type"] as? String
            (type != null && type == deviceMappingAnnotationKey)
        }

        val authorisations = deviceMappingAnnotation!!["authorisations"] as List<*>
        authorisations.mapNotNull {
          try {
            val authorisation = it as Map<*,*>
            val primaryDevicePubKey = authorisation["primaryDevicePubKey"] as String
            val secondaryDevicePubKey = authorisation["secondaryDevicePubKey"] as String

            val requestSignatureString = authorisation["requestSignature"] as? String
            val grantSignatureString = authorisation["grantSignature"] as? String

            var requestSignature: ByteArray? = null
            var grantSignature: ByteArray? = null

            if (requestSignatureString != null) { requestSignature = Base64.decode(requestSignatureString) }
            if (grantSignatureString != null) { grantSignature = Base64.decode(grantSignatureString) }

            val pairing = LokiPairingAuthorisation(primaryDevicePubKey, secondaryDevicePubKey, requestSignature, grantSignature)
            if (!pairing.verify()) {
              Log.d("Loki", "Invalid authorisation received: $authorisation")
              return@mapNotNull null
            }

            pairing
          } catch (e: Exception) {
            Log.d("Loki", "Failed to parse device mapping for $pubKey on server: $server: $e")
            null
          }
        }
      } catch (exception: Exception) {
        Log.d("Loki", "Couldn't parse device mappings for user: $pubKey on server: $server.")
        throw exception
      }
    }
  }

  // Use this if we need information about failure (e.g http error etc)
  fun fetchAndSaveDeviceMappings(pubKey: String): Promise<List<LokiPairingAuthorisation>, Exception> {
    return fetchDeviceMappings(pubKey).success { authorisations ->
      // Update database
      database.removePairingAuthorisations(pubKey)
      authorisations.forEach { database.insertOrUpdatePairingAuthorisation(it) }
    }
  }

  // Fetch the device mapping from the server and cache it. If fetching fails then it will return the old mappings from the database.
  fun getDeviceMappings(pubKey: String, skipCache: Boolean = false): Promise<List<LokiPairingAuthorisation>, Exception> {
    val databaseAuthorisations = database.getPairingAuthorisations(pubKey)

    val now = System.currentTimeMillis()
    val hasCacheExpired = skipCache || !lastFetchedCache.containsKey(pubKey) || (now - lastFetchedCache[pubKey]!!) > cacheTime

    // We should always keep track of our own mappings and not rely on the server
    val isOurOwnPubKey = pubKey == userHexEncodedPublicKey

    // If our cache has expired then we need to fetch from the server
    // If that fails then give the user the authorisations in the database
    if (!isOurOwnPubKey && hasCacheExpired) {
      val deferred = deferred<List<LokiPairingAuthorisation>, Exception>()

      fetchAndSaveDeviceMappings(pubKey).success { authorisations ->
        // Update cache time
        lastFetchedCache[pubKey] = now

        deferred.resolve(authorisations)
      }.fail {
        Log.d("Loki", "Failed to fetch device mappings for $pubKey")
        // Fall back to database
        deferred.resolve(databaseAuthorisations)
      }

      return deferred.promise
    }

    return Promise.of(databaseAuthorisations)
  }

  fun getPrimaryDevice(secondaryDevicePubKey: String): Promise<String?, Exception> {
    return getDeviceMappings(secondaryDevicePubKey).map { authorisations ->
      val pairing = authorisations.find { it.secondaryDevicePubKey == secondaryDevicePubKey }
      pairing?.primaryDevicePubKey
    }
  }

  fun getSecondaryDevices(primaryDevicePubKey: String): Promise<List<String>, Exception> {
    return getDeviceMappings(primaryDevicePubKey).map { authorisations ->
      authorisations.filter { it.primaryDevicePubKey == primaryDevicePubKey }.map { it.secondaryDevicePubKey }
    }
  }

  fun updateOurDeviceMappings(): Promise<Unit, Exception> {
    // 1. Get our own mappings
    // 2. Check if we're primary
    // 3. update the server
    return getDeviceMappings(userHexEncodedPublicKey).bind { authorisations ->
      // We are a primary device if an authorisation has us listed as one
      val isPrimary = authorisations.find { it.primaryDevicePubKey == userHexEncodedPublicKey } != null
      retryIfNeeded(maxRetryCount) {
        val authorisationsJson = authorisations.map { it.toJSON() }
        val json = mapOf("isPrimary" to isPrimary.int, "authorisations" to authorisationsJson)
        val value = if (authorisations.count() > 0) JsonUtil.toJson(json) else null
        dotNetAPI.setSelfAnnotation(server, deviceMappingAnnotationKey, value)
      }
    }.unwrap().toSuccessVoid()
  }
}

val Boolean.int
  get() = if (this) 1 else 0