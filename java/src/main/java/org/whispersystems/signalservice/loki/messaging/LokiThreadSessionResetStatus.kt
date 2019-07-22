package org.whispersystems.signalservice.loki.messaging

enum class LokiThreadSessionResetStatus(val rawValue: Int) {
    NONE(0),
    IN_PROGRESS(1),
    REQUEST_RECEIVED(2)
}