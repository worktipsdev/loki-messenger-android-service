package org.whispersystems.signalservice.loki.utilities

fun Map<*, *>.prettifiedDescription(): String {
    return "[ " + map { entry ->
        val keyDescription = entry.key.toString()
        var valueDescription = entry.value.toString()
        if (valueDescription.isEmpty()) { valueDescription = "\"\"" }
        val maxLength = 20
        val truncatedValueDescription = if (valueDescription.length > maxLength) {
            valueDescription.substring(0 until maxLength) + "..."
        } else {
            valueDescription
        }
        "$keyDescription : $truncatedValueDescription"
    }.joinToString(", ") + " ]"
}