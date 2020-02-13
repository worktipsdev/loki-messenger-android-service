package org.whispersystems.libsignal.loki

enum class LokiSessionResetStatus(val rawValue: Int) {
    NONE(0),
    IN_PROGRESS(1),
    REQUEST_RECEIVED(2)
}
