package org.whispersystems.signalservice.loki.messaging

enum class LokiThreadSessionResetState(val rawValue: Int) {
    // No ongoing session reset
    NONE(0),
    // We initiated a session reset
    INITIATED(1),
    // We received a session reset
    REQUEST_RECEIVED(2),
}