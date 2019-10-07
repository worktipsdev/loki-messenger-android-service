package org.whispersystems.signalservice.loki.api

interface DeviceLinkingSessionListener {

  fun requestUserAuthorization(authorisation: PairingAuthorisation) {}
  fun onDeviceLinkRequestAuthorized(authorisation: PairingAuthorisation) {}
}