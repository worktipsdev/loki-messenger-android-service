package org.whispersystems.signalservice.loki.api

public data class LokiGroupChat(
        public val id: String,
        public val serverID: Long,
        public val server: String,
        public val displayName: String,
        public val isDeletable: Boolean
)