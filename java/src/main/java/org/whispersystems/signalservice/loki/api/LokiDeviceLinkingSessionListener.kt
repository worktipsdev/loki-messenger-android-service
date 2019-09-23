package org.whispersystems.signalservice.loki.api

interface LokiDeviceLinkingSessionListener {
  fun onDeviceLinkingRequestReceived(authorisation: LokiPairingAuthorisation)
}