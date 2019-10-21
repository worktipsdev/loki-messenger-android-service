package org.whispersystems.signalservice.loki.api

import okhttp3.OkHttpClient
import okhttp3.Request
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.api.messages.SignalServiceAttachment
import org.whispersystems.signalservice.api.push.exceptions.PushNetworkException
import org.whispersystems.signalservice.internal.push.PushAttachmentData
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.TimeUnit

object LokiAttachmentAPI {

  fun getAttachment(destination: File, url: String, maxByteCount: Int, listener: SignalServiceAttachment.ProgressListener?) {
    try {
      val outputStream = FileOutputStream(destination)
      getAttachment(outputStream, url, maxByteCount, listener)
    } catch (e: IOException) {
      throw PushNetworkException(e)
    }
  }

  fun getAttachment(outputStream: OutputStream, url: String, maxByteCount: Int, listener: SignalServiceAttachment.ProgressListener?) {
    val connection = OkHttpClient()
        .newBuilder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()
    val request = Request.Builder().url(url).get()
    try {
      val response = connection.newCall(request.build()).execute()
      if (response.isSuccessful) {
        val body = response.body()
        if (body == null) {
          Log.d("Loki", "Couldn't parse attachment.")
          throw LokiAPI.Error.ParsingFailed
        }
        if (body.contentLength() > maxByteCount) {
          Log.d("Loki", "Attachment size limit exceeded.")
          throw LokiAPI.Error.MaxSizeExceeded
        }
        val input = body.byteStream()
        val buffer = ByteArray(32768)
        var bytesCopied = 0
        var bytes = input.read(buffer)
        while (bytes >= 0) {
          outputStream.write(buffer, 0, bytes)
          bytesCopied += bytes
          if (bytesCopied > maxByteCount) {
            Log.d("Loki", "Attachment size limit exceeded.")
            throw LokiAPI.Error.MaxSizeExceeded
          }
          listener?.onAttachmentProgress(body.contentLength(), bytesCopied.toLong())
          bytes = input.read(buffer)
        }
      } else {
        Log.d("Loki", "Couldn't parse attachment due to error: ${response.code()}.")
        throw LokiAPI.Error.HTTPRequestFailed(response.code())
      }
    } catch (e: Exception) {
      Log.d("Loki", "Couldn't parse attachment.")
      throw LokiAPI.Error.Generic
    }
  }

  fun uploadAttachment(server: String, attachment: PushAttachmentData): Triple<Long, String, ByteArray> {
    // Even though we're using LokiStorageAPI to do uploading, this will upload to the correct server
    return LokiStorageAPI.shared.uploadAttachment(server, attachment)
  }
}