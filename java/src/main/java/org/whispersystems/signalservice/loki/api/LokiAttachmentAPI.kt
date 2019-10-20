package org.whispersystems.signalservice.loki.api

import okhttp3.OkHttpClient
import okhttp3.Request
import org.whispersystems.signalservice.api.messages.SignalServiceAttachment
import org.whispersystems.signalservice.api.push.exceptions.NonSuccessfulResponseCodeException
import org.whispersystems.signalservice.api.push.exceptions.PushNetworkException
import org.whispersystems.signalservice.internal.push.PushAttachmentData
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.TimeUnit

object LokiAttachmentAPI {
  fun fetchAttachment(destination: File, url: String, maxSizeBytes: Int, listener: SignalServiceAttachment.ProgressListener?) {
    try {
      val outputStream = FileOutputStream(destination)
      fetchAttachment(outputStream, url, maxSizeBytes, listener)
    } catch (e: IOException) {
      throw PushNetworkException(e)
    }
  }

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

  fun uploadAttachment(server: String, attachment: PushAttachmentData): Triple<Long, String, ByteArray> {
    // Even though we're using LokiStorageAPI to do uploading, this will upload to the correct server
    return LokiStorageAPI.shared.uploadAttachment(server, attachment)
  }
}