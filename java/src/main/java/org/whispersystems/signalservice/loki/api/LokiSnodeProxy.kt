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

internal class LokiSnodeProxy(private val target: LokiAPITarget, timeout: Long) : LokiHttpClient(timeout) {
    companion object {
        private val kContext = Kovenant.createContext("proxyContext", 8)
        private val curve = Curve25519.getInstance(Curve25519.BEST)
    }

    sealed class Error(val description: String) : Exception() {
        class InvalidPublicKey(target: LokiAPITarget) : Error("Invalid public key found on $target: ${target.publicKeys}")
        object FailedToBuildRequestBody : Error("Failed to build request body")
    }

    private val keyPair = curve.generateKeyPair()

    // region Private functions
    private fun getBody(request: Request): String {
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

    private fun getHeaders(request: Request): Map<String, Any> {
        val map = mutableMapOf<String, Any>()
        val headers = request.headers()
        for (name in headers.names()) {
            val value = headers.get(name)
            if (value != null) {
                if (value.toLowerCase(Locale.getDefault()) == "true" || value.toLowerCase(Locale.getDefault()) == "false") {
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

    override fun execute(request: Request): Promise<Response, Exception> {
        val targetHexEncodedPublicKeys = target.publicKeys ?: return Promise.ofFail(Error.InvalidPublicKey(target))
        val symmetricKey = curve.calculateAgreement(Hex.fromStringCondensed(targetHexEncodedPublicKeys.encryption), keyPair.privateKey)

        lateinit var randomSnode: LokiAPITarget
        return LokiSwarmAPI.getRandomSnode().bind(kContext) { random ->
            randomSnode = random
            val url = "${randomSnode.address}:${randomSnode.port}/proxy"
            Log.d("LokiSnodeProxy", "Proxy snode request to $target via $randomSnode")

            val body = mapOf("method" to request.method(), "body" to getBody(request), "headers" to getHeaders(request))
            val ivAndCipherText = DiffieHellman.encrypt(JsonUtil.toJson(body).toByteArray(Charsets.UTF_8), symmetricKey)
            val proxyRequest = Request.Builder()
                .url(url)
                .post(RequestBody.create(MediaType.get("application/octet-stream"), ivAndCipherText))
                .header("X-Sender-Public-Key", Hex.toStringCondensed(keyPair.publicKey))
                .header("X-Target-Snode-Key", targetHexEncodedPublicKeys.identification)
                .build()

            execute(proxyRequest, getClearnetConnection())
        }.map(kContext) { response ->
            Log.d("LokiSnodeProxy", "Received response from proxy: $response")

            // If we can't hit the proxy endpoint then we should use another valid snode
            if (response.code() == 404) {
                LokiSwarmAPI.randomSnodePool.remove(randomSnode)
            }

            // Extract the body if possible
            var body: String? = null
            var code = response.code()
            if (response.body() != null) {
                body = if (response.isSuccessful) {
                    val base64 = response.body()!!.string()
                    val cipherText = Base64.decode(base64)
                    val decrypted = DiffieHellman.decrypt(cipherText, symmetricKey)
                    val responseBody = decrypted.toString(Charsets.UTF_8)
                    val json = JsonUtil.fromJson(responseBody)
                    code = json.get("status").asInt()
                    if (json.hasNonNull("body")) {
                        json.get("body").asText()
                    } else {
                        responseBody
                    }
                } else {
                    response.body()!!.string()
                }
            }
            return@map Response(code in 200..299, code, body)
        }
    }
}
