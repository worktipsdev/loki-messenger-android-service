package org.whispersystems.signalservice.loki.messaging

import org.whispersystems.libsignal.state.PreKeyBundle

/**
 * An interface describing the local storage of `PreKeyBundle`s for Loki use.
 */
interface LokiPreKeyBundleStore {

    fun getPreKeyBundle(pubKey: String): PreKeyBundle?
    fun removePreKeyBundle(pubKey: String)
}