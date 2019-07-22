package org.whispersystems.signalservice.loki.messaging
import org.whispersystems.libsignal.state.SessionStore

interface LokiSessionDatabaseProtocol : SessionStore {
    
    fun archiveAllSessions(hexEncodedPublicKey: String)
}