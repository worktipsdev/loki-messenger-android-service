package org.whispersystems.signalservice.loki.api

public data class LokiRSSFeed(
    public val id: String,
    public val url: String,
    public val displayName: String,
    public val isDeletable: Boolean
)