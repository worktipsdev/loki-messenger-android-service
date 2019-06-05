package org.whispersystems.signalservice.loki.utilities

import org.whispersystems.libsignal.IdentityKeyPair
import org.whispersystems.libsignal.SignalProtocolAddress

val SignalProtocolAddress.publicKey: ByteArray
    get() {
        var address = this.name
        if (address.count() == 66) {
            address = address.removePrefix("05")
        }
        return address.convertHexStringToByteArray()
    }

private fun String.convertHexStringToByteArray(): ByteArray {
    val result = ByteArray(length / 2)
    val hexCharacters = "0123456789ABCDEF".toCharArray()
    for (i in 0 until length step 2) {
        val firstIndex = hexCharacters.indexOf(this[i])
        val secondIndex = hexCharacters.indexOf(this[i + 1])
        val octet = firstIndex.shl(4).or(secondIndex)
        result[i.shr(1)] = octet.toByte()
    }
    return result
}

val IdentityKeyPair.hexEncodedPublicKey: String
    get() {
        // Prefixing with "05" is necessary for what seems to be a sort of Signal public key versioning system
        return "05" + publicKey.serialize().joinToString("") { String.format("%02X", it) }
    }

val IdentityKeyPair.hexEncodedPrivateKey: String
    get() = privateKey.serialize().joinToString("") { String.format("%02X", it) }