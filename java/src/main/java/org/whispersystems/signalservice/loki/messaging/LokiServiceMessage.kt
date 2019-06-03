package org.whispersystems.signalservice.loki.messaging

data class LokiServiceMessage(var preKeyBundleMessage: LokiServicePreKeyBundleMessage?, var addressMessage: LokiServiceAddressMessage?)

data class LokiServiceAddressMessage(val p2pAddress: String, val p2pPort: Int)

data class LokiServicePreKeyBundleMessage(
        val identityKey: ByteArray,
        val deviceID: Int,
        val preKeyID: Int,
        val signedKeyID: Int,
        val preKey: ByteArray,
        val signedKey: ByteArray,
        val signature: ByteArray
)