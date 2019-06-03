package org.whispersystems.signalservice.loki.utilities

import org.whispersystems.libsignal.SignalProtocolAddress

fun SignalProtocolAddress.publicKey(): ByteArray {
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