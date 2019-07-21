package org.whispersystems.signalservice.loki.messaging
import org.whispersystems.libsignal.state.SessionStore

interface LokiSessionProtocol : SessionStore {
    
    fun archiveAllSessions(name: String)
}