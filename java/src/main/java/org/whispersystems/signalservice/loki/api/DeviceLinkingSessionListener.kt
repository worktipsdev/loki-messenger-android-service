package org.whispersystems.signalservice.loki.api

interface DeviceLinkingSessionListener {

  fun requestUserAuthorization(authorisation: DeviceLink) {}
  fun onDeviceLinkRequestAuthorized(authorisation: DeviceLink) {}
}
