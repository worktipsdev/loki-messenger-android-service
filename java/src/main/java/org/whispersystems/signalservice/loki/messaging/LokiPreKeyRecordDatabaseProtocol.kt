package org.whispersystems.signalservice.loki.messaging

import org.whispersystems.libsignal.state.PreKeyRecord

interface LokiPreKeyRecordDatabaseProtocol {

    fun getPreKey(hexEncodedPublicKey: String): PreKeyRecord?
}