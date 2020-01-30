package org.whispersystems.signalservice.loki.api

import nl.komponents.kovenant.Promise
import nl.komponents.kovenant.functional.map
import okhttp3.Request
import org.whispersystems.signalservice.internal.util.JsonUtil

object LokiRSSProxy {
    fun fetch(url: String): Promise<String, Exception> {
        var client = LokiHTTPClient(60)
        val builder = Request.Builder().url(url).get()
        val rssMap = mapOf("messenger-updates/feed" to "loki/v1/rss/messenger", "loki.network/feed" to "loki/v1/rss/loki")
        for (mapping in rssMap) {
            if (url.toLowerCase().contains(mapping.key)) {
                val fileServer = "https://file.lokinet.org"
                builder.url("$fileServer/${mapping.value}")
                client = LokiFileServerProxy(fileServer)
                break
            }
        }
        return client.execute(builder.build()).map { response ->
            if (!response.isSuccess) {
                throw LokiAPI.Error.HTTPRequestFailed(response.statusCode)
            }
            val body = response.body ?: throw LokiAPI.Error.InvalidBody
            val json = JsonUtil.fromJson(body)
            json.get("data").asText()
        }
    }
}
