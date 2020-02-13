package org.whispersystems.libsignal.loki

interface LokiSessionResetProtocol {
    fun getSessionResetStatus(hexEncodedPublicKey: String): LokiSessionResetStatus
    fun setSessionResetStatus(hexEncodedPublicKey: String, sessionResetStatus: LokiSessionResetStatus)
}
