package org.whispersystems.signalservice.loki.messages

data class LokiServiceAddressMessage(val p2pAddress: String, val p2pPort: Int) {
}