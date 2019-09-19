package org.whispersystems.signalservice.loki.api

public data class LokiPairingAuthorisation(
    public val primaryDevicePubKey: String,
    public val secondaryDevicePubKey: String,
    public val requestSignature: ByteArray?,
    public val grantSignature: ByteArray?
) {
  public val isGranted: Boolean
    get() = grantSignature != null
}