package org.whispersystems.signalservice.loki.utilities

import org.whispersystems.signalservice.api.crypto.DigestingOutputStream
import org.whispersystems.signalservice.internal.push.http.OutputStreamFactory
import java.io.OutputStream

class BasicOutputStreamFactory : OutputStreamFactory {

  override fun createFor(outputStream: OutputStream?): DigestingOutputStream {
    return object : DigestingOutputStream(outputStream) { }
  }
}