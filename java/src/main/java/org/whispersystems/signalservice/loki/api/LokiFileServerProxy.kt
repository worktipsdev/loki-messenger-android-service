package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.functional.bind
import nl.komponents.kovenant.functional.map
import okhttp3.MediaType
import okhttp3.MultipartBody
import okhttp3.Request
import okhttp3.RequestBody
import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.Hex
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.crypto.DiffieHellman
import org.whispersystems.signalservice.loki.utilities.recover
import org.whispersystems.signalservice.loki.utilities.removing05PrefixIfNeeded

internal class LokiFileServerProxy(val server: String) : LokiHTTPClient(60) {
    companion object {
        // The loki file server public keys are hard coded for now
        private val lokiServerPublicKey = Base64.decode("BWJQnVm97sQE3Q1InB4Vuo+U/T1hmwHBv0ipkiv8tzEc").removing05PrefixIfNeeded()
        private val curve = Curve25519.getInstance(Curve25519.BEST)
    }

    private val isLokiServer = server.contains("file.lokinet.org", true) || server.contains("file-dev.lokinet.org", true)
    private val keyPair = curve.generateKeyPair()

    override fun execute(request: Request): Promise<Response, Exception> {
        if (!isLokiServer) { return super.execute(request) }
        val symmetricKey = curve.calculateAgreement(lokiServerPublicKey, keyPair.privateKey)

        return LokiSwarmAPI.getRandomSnode().bind { randomSnode ->
            val url =  "${randomSnode.address}:${randomSnode.port}/file_proxy"
            Log.d("LokiFileServerProxy", "Proxying request to $server via $randomSnode")
            val bodyAsString = getBodyAsString(request)
            val canonicalHeaders = getCanonicalHeaders(request)
            val endpoint = request.url().toString().removePrefix(server).removePrefix("/")
            val body = mapOf("body" to bodyAsString, "endpoint" to endpoint, "method" to request.method(), "headers" to canonicalHeaders)
            val ivAndCipherText = DiffieHellman.encrypt(JsonUtil.toJson(body).toByteArray(Charsets.UTF_8), symmetricKey)
            val params = mapOf( "cipherText64" to Base64.encodeBytes(ivAndCipherText) )
            val headers = mapOf( "X-Loki-File-Server-Ephemeral-Key" to getBase64PublicKey(keyPair.publicKey))
            val proxyRequest = Request.Builder()
                .url(url)
                .post(RequestBody.create(MediaType.get("application/json"), JsonUtil.toJson(params)))
                .header("X-Loki-File-Server-Target", "/loki/v1/secure_rpc")
                .header("X-Loki-File-Server-Verb", "POST")
                .header("X-Loki-File-Server-Headers", JsonUtil.toJson(headers))
                .header("Connection", "close")
                .build()
            execute(proxyRequest, getClearnetConnection())
        }.map { response ->
            var code = response.code()
            var body: String? = response.body()?.string()
            if (response.isSuccessful && body != null) {
                try {
                    val json = JsonUtil.fromJson(body)
                    code = json.get("meta").get("code").asInt()
                    if (code in 200..299) {
                        val base64Data = json.get("data").asText()
                        val ivAndCipherText = Base64.decode(base64Data)
                        val decrypted = DiffieHellman.decrypt(ivAndCipherText, symmetricKey)
                        body = decrypted.toString(Charsets.UTF_8)
                    }
                } catch (e: Error) {
                    code = -1
                    body = "Failed to parse JSON"
                }
            }
            return@map Response(code in 200..299, code, body)
        }.recover { exception ->
            throw exception
        }
    }

    private fun getBase64PublicKey(data: ByteArray): String {
        var string = Hex.toStringCondensed(data)
        // File server expects a 05 public key
        if (data.size == 32) { string = "05$string" }
        val sessionPublicKey = Hex.fromStringCondensed(string)
        return Base64.encodeBytes(sessionPublicKey)
    }

    override fun getBodyAsString(request: Request): Any? {
        val requestBody = request.body()
        val body = super.getBodyAsString(request)
        if (requestBody is MultipartBody && body is String) {
            val data = body.toByteArray()
            return mapOf("fileUpload" to Base64.encodeBytes(data))
        }
        return body
    }

    override fun getCanonicalHeaders(request: Request): Map<String, Any> {
        val headers = super.getCanonicalHeaders(request).toMutableMap()
        // Add any multi-part headers to the original request
        val body = request.body()
        if (body is MultipartBody) {
            headers["content-length"] = body.contentLength()
            val contentType = body.contentType()
            if (contentType != null) {
                headers["content-type"] = contentType.toString()
            }
        }
        return headers
    }
}
