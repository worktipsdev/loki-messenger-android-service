package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Kovenant
import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.functional.map
import okhttp3.MediaType
import okhttp3.Request
import okhttp3.RequestBody
import okio.Buffer
import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.Hex
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.crypto.DiffieHellman
import org.whispersystems.signalservice.loki.utilities.createContext
import java.io.IOException
import java.util.*

internal class LokiSnodeProxy(private val target: LokiAPITarget, timeout: Long) : LokiHTTPClient(timeout) {

    private val keyPair by lazy { curve.generateKeyPair() }

    // region Settings
    companion object {
        private val kContext = Kovenant.createContext("proxyContext", 8)
        private val curve = Curve25519.getInstance(Curve25519.BEST)
    }
    // endregion

    // region Error
    sealed class Error(val description: String) : Exception() {
        class TargetPublicKeySetMissing(target: LokiAPITarget) : Error("Missing public key set for: $target.")
        object FailedToBuildRequestBody : Error("Failed to build request body")
    }
    // endregion

    // region Convenience
    private fun getBodyAsString(request: Request): String {
        try {
            val copy = request.newBuilder().build()
            val buffer = Buffer()
            val body = copy.body()!!
            val charset = body.contentType()?.charset() ?: Charsets.UTF_8
            body.writeTo(buffer)
            return buffer.readString(charset)
        } catch (e: IOException) {
            throw Error.FailedToBuildRequestBody
        }
    }

    private fun getCanonicalHeaders(request: Request): Map<String, Any> {
        val map = mutableMapOf<String, Any>()
        val headers = request.headers()
        for (name in headers.names()) {
            val value = headers.get(name)
            if (value != null) {
                if (value.toLowerCase(Locale.US) == "true" || value.toLowerCase(Locale.US) == "false") {
                    map[name] = value.toBoolean()
                } else if (value.toIntOrNull() != null) {
                    map[name] = value.toInt()
                } else {
                    map[name] = value
                }
            }
        }
        return map
    }
    // endregion

    // region Proxying
    override fun execute(request: Request): Promise<Response, Exception> {
        val targetHexEncodedPublicKeySet = target.publicKeySet ?: return Promise.ofFail(Error.TargetPublicKeySetMissing(target))
        val symmetricKey = curve.calculateAgreement(Hex.fromStringCondensed(targetHexEncodedPublicKeySet.encryptionKey), keyPair.privateKey)
        val requestBodyAsString = getBodyAsString(request)
        val canonicalRequestHeaders = getCanonicalHeaders(request)
        lateinit var proxy: LokiAPITarget
        return LokiSwarmAPI.getRandomSnode().bind(kContext) { p ->
            proxy = p
            val url = "${proxy.address}:${proxy.port}/proxy"
            Log.d("Loki", "Proxying request to $target through $proxy.")
            val unencryptedProxyRequestBody = mapOf( "method" to request.method(), "body" to requestBodyAsString, "headers" to canonicalRequestHeaders )
            val ivAndCipherText = DiffieHellman.encrypt(JsonUtil.toJson(unencryptedProxyRequestBody).toByteArray(Charsets.UTF_8), symmetricKey)
            val proxyRequest = Request.Builder()
                .url(url)
                .post(RequestBody.create(MediaType.get("application/octet-stream"), ivAndCipherText))
                .header("X-Sender-Public-Key", Hex.toStringCondensed(keyPair.publicKey))
                .header("X-Target-Snode-Key", targetHexEncodedPublicKeySet.idKey)
                .build()
            execute(proxyRequest, getClearnetConnection())
        }.map(kContext) { response ->
            if (response.code() == 404) {
                // Prune snodes that don't implement the proxying endpoint
                LokiSwarmAPI.randomSnodePool.remove(proxy)
            }
            var bodyAsString: String? = null
            var statusCode = response.code()
            if (response.body() != null) {
                if (response.isSuccessful) {
                    val base64EncodedBody = response.body()!!.string()
                    val cipherText = Base64.decode(base64EncodedBody)
                    val bodyAsData = DiffieHellman.decrypt(cipherText, symmetricKey)
                    val body = bodyAsData.toString(Charsets.UTF_8)
                    val json = JsonUtil.fromJson(body)
                    statusCode = json.get("status").asInt()
                    if (json.hasNonNull("body")) {
                        bodyAsString = json.get("body").asText()
                    } else {
                        bodyAsString = body
                    }
                } else {
                    bodyAsString = response.body()!!.string()
                }
            }
            return@map Response(statusCode in 200..299, statusCode, bodyAsString)
        }
    }
    // endregion
}
