package org.whispersystems.signalservice.loki.api

interface LokiDeviceLinkingSessionDelegate {
  fun onDeviceLinkingRequestReceived(pubKey: String)
  fun onDeviceLinkingTimeout()
}