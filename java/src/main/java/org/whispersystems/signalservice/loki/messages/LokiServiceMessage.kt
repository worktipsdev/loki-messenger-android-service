package org.whispersystems.signalservice.loki.messages

data class LokiServiceMessage(var preKeyBundleMessage: LokiServicePreKeyBundleMessage?, var addressMessage: LokiServiceAddressMessage?)

// region - Loki Address
data class LokiServiceAddressMessage(val p2pAddress: String, val p2pPort: Int)
// endregion

// region - Loki PreKeyBundle
data class LokiServicePreKeyBundleMessage(
        val identityKey: ByteArray,
        val deviceID: Int,
        val prekeyID: Int,
        val signedKeyID: Int,
        val prekey: ByteArray,
        val signedKey: ByteArray,
        val signature: ByteArray
)
// endregion