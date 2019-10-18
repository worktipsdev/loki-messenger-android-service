package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.functional.map
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.libsignal.util.Pair
import org.whispersystems.signalservice.api.messages.SignalServiceAttachment
import org.whispersystems.signalservice.api.push.exceptions.NonSuccessfulResponseCodeException
import org.whispersystems.signalservice.api.push.exceptions.PushNetworkException
import org.whispersystems.signalservice.internal.push.PushAttachmentData
import org.whispersystems.signalservice.internal.push.http.DigestingRequestBody
import org.whispersystems.signalservice.internal.push.http.OutputStreamFactory
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.internal.util.concurrent.SettableFuture
import org.whispersystems.signalservice.loki.utilities.retryIfNeeded
import java.io.*
import java.util.concurrent.TimeUnit

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

    @Throws(PushNetworkException::class)
    fun fetchAttachment(destination: File, url: String, maxSizeBytes: Int, listener: SignalServiceAttachment.ProgressListener?) {
      try {
        val outputStream = FileOutputStream(destination)
        fetchAttachment(outputStream, url, maxSizeBytes, listener)
      } catch (e: IOException) {
        throw PushNetworkException(e)
      }
    }

    @Throws(PushNetworkException::class, NonSuccessfulResponseCodeException::class)
    fun fetchAttachment(outputStream: OutputStream, url: String, maxSizeBytes: Int, listener: SignalServiceAttachment.ProgressListener?) {
      val connection = OkHttpClient()
          .newBuilder()
          .connectTimeout(30, TimeUnit.SECONDS)
          .readTimeout(30, TimeUnit.SECONDS)
          .build()

      val request = Request.Builder().url(url).get()

      try {
        val response = connection.newCall(request.build()).execute()
        if (response.isSuccessful) {
          val body = response.body() ?: throw PushNetworkException("No response body!")

          if (body.contentLength() > maxSizeBytes) throw PushNetworkException("Response exceeds max size!")

          val input = body.byteStream()
          val buffer = ByteArray(32768)

          // Read bytes to output stream
          var bytesCopied = 0
          var bytes = input.read(buffer)
          while (bytes >= 0) {
            outputStream.write(buffer, 0, bytes)
            bytesCopied += bytes
            if (bytesCopied > maxSizeBytes) throw PushNetworkException("Response exceeded max size!")
            listener?.onAttachmentProgress(body.contentLength(), bytesCopied.toLong())
            bytes = input.read(buffer)
          }
        } else {
          throw NonSuccessfulResponseCodeException("Response: $response")
        }
      } catch (e: IOException) {
        throw if (e is NonSuccessfulResponseCodeException) e else PushNetworkException(e)
      }
    }
  }

  // region Private API
  private fun fetchDeviceMappings(hexEncodedPublicKey: String): Promise<List<PairingAuthorisation>, Exception> {
    val parameters = mapOf( "include_user_annotations" to 1 )
    return execute(HTTPVerb.GET, server, "users/@$hexEncodedPublicKey", parameters).map { rawResponse ->
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

  @Throws(PushNetworkException::class, NonSuccessfulResponseCodeException::class)
  fun uploadAttachment(attachment: PushAttachmentData): Pair<String, ByteArray> {
    return upload(attachment.data, "application/octet-stream", attachment.dataSize, attachment.outputStreamFactory, attachment.listener)
  }

  @Throws(PushNetworkException::class, NonSuccessfulResponseCodeException::class)
  fun upload(data: InputStream, contentType: String, length: Long, outputStreamFactory: OutputStreamFactory, progressListener: SignalServiceAttachment.ProgressListener): Pair<String, ByteArray> {
    // This function just mimicks what signal does in PushServiceSocket
    // We are doing it this way to minimize any breaking changes that we need to make to shim our file servers in
    val connection = OkHttpClient()
        .newBuilder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    val file = DigestingRequestBody(data, outputStreamFactory, contentType, length, progressListener)
    val requestBody = MultipartBody.Builder ()
        .setType(MultipartBody.FORM)
        .addFormDataPart("type", "network.loki")
        .addFormDataPart("Content-Type", contentType)
        .addFormDataPart("content", "attachment", file)
        .build()

    val request = Request.Builder().url("$server/files").post(requestBody)
    val future = SettableFuture<Pair<String, ByteArray>>()

    // Execute promise
    getAuthenticatedRequest(request, server).bind { execute(connection, it.build(), server) }.map { response ->
      val bodyAsString = response.body()!!.string()
      val body = JsonUtil.fromJson(bodyAsString)
      val bodyData = body.get("data")
      if (bodyData == null) {
        Log.d("Loki", "Couldn't parse attachment url from: $response.")
        throw Error.ParsingFailed
      }
      val url = bodyData.get("url").asText()
      if (url.isEmpty()) {
        throw Error("Invalid url returned from server")
      }

      Pair(url, file.transmittedDigest)
    }.success {
      future.set(it)
    }.fail {
      future.setException(it)
    }

    // Return back synchronized future
    try {
      return future.get()
    } catch (e: Exception) {
      val error = e.cause ?: e
      if (error is LokiAPI.Error.HTTPRequestFailed) {
        throw NonSuccessfulResponseCodeException("Request returned with ${error.code}")
      }
      throw PushNetworkException(e)
    }
  }
  // endregion
}