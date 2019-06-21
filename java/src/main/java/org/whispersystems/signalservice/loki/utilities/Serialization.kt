package org.whispersystems.signalservice.loki.utilities

import org.whispersystems.libsignal.IdentityKeyPair

val IdentityKeyPair.hexEncodedPublicKey: String
    get() = publicKey.serialize().joinToString("") { String.format("%02X", it) }

val IdentityKeyPair.hexEncodedPrivateKey: String
    get() = privateKey.serialize().joinToString("") { String.format("%02X", it) }