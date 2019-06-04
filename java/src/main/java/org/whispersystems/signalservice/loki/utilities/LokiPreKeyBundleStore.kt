package org.whispersystems.signalservice.loki.utilities

import org.whispersystems.libsignal.state.PreKeyBundle

/**
 * An interface describing the local storage of `PreKeyBundle` for loki use.
 */
interface LokiPreKeyBundleStore {
    fun getPreKeyBundle(pubKey: String): PreKeyBundle?
    fun removePreKeyBundle(pubKey: String)
}