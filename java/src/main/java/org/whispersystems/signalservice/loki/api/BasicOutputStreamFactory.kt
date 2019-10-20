package org.whispersystems.signalservice.loki.api

import org.whispersystems.signalservice.api.crypto.DigestingOutputStream
import org.whispersystems.signalservice.internal.push.http.OutputStreamFactory
import java.io.OutputStream

class BasicOutputStreamFactory : OutputStreamFactory {
  override fun createFor(wrap: OutputStream?): DigestingOutputStream {
    return object : DigestingOutputStream(wrap) {}
  }
}