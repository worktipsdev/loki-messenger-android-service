package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.deferred
import nl.komponents.kovenant.functional.map
import okhttp3.OkHttpClient
import okhttp3.Request
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

internal open class LokiHttpClient(private val timeout: Long) {

    data class Response(val success: Boolean, val code: Int, val body: String?)

    companion object {
        // region Settings
        internal val okHTTPCache = hashMapOf<Long, OkHttpClient>()
        // endregion
    }

    // region Clearnet Setup
    fun getClearnetConnection(): OkHttpClient {
        var connection = okHTTPCache[timeout]
        if (connection == null) {
            val trustManager = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authorizationType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authorizationType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> {
                    return arrayOf()
                }
            }
            val sslContext = SSLContext.getInstance("SSL")
            sslContext.init(null, arrayOf(trustManager), SecureRandom())
            connection = OkHttpClient().newBuilder()
                .sslSocketFactory(sslContext.socketFactory, trustManager)
                .hostnameVerifier { _, _ -> true }
                .connectTimeout(timeout, TimeUnit.SECONDS)
                .readTimeout(timeout, TimeUnit.SECONDS)
                .writeTimeout(timeout, TimeUnit.SECONDS)
                .build()
            okHTTPCache[timeout] = connection
        }
        return connection!!
    }
    // endregion

    internal fun execute(request: Request, client: OkHttpClient): Promise<okhttp3.Response, Exception> {
        val deferred = deferred<okhttp3.Response, Exception>()
        Thread {
            try {
                val response = client.newCall(request).execute()
                deferred.resolve(response)
            } catch (e: Exception) {
                deferred.reject(e)
            }
        }.start()
        return deferred.promise
    }

    open fun execute(request: Request): Promise<Response, Exception> {
        val connection = getClearnetConnection()
        return execute(request, connection).map {
            Response(it.isSuccessful, it.code(), it.body()?.string())
        }
    }
}
