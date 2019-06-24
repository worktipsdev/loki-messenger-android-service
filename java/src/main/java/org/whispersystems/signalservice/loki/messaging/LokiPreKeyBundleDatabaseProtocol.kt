package org.whispersystems.signalservice.loki.messaging

import org.whispersystems.libsignal.state.PreKeyBundle

interface LokiPreKeyBundleDatabaseProtocol {

    fun getPreKeyBundle(hexEncodedPublicKey: String): PreKeyBundle?
    fun removePreKeyBundle(hexEncodedPublicKey: String)
}