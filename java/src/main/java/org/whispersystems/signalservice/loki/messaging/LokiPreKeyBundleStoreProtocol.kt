package org.whispersystems.signalservice.loki.messaging

import org.whispersystems.libsignal.state.PreKeyBundle

interface LokiPreKeyBundleStoreProtocol {

    fun getPreKeyBundle(hexEncodedPublicKey: String): PreKeyBundle?
    fun removePreKeyBundle(hexEncodedPublicKey: String)
}