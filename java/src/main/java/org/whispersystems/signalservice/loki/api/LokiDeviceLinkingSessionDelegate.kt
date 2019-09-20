package org.whispersystems.signalservice.loki.api

interface LokiDeviceLinkingSessionDelegate {
  fun onDeviceLinkingRequestReceived(authorisation: LokiPairingAuthorisation)
  fun onDeviceLinkingTimeout()
}