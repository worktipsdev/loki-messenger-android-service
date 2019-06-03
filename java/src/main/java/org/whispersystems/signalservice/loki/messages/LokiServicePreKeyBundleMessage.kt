package org.whispersystems.signalservice.loki.messages

data class LokiServicePreKeyBundleMessage(
        val identityKey: ByteArray,
        val deviceID: Int,
        val prekeyID: Int,
        val signedKeyID: Int,
        val prekey: ByteArray,
        val signedKey: ByteArray,
        val signature: ByteArray
) {
}