package org.whispersystems.signalservice.loki.utilities

fun Map<*, *>.prettifiedDescription(): String {
    return "[ " + map { entry ->
        val keyDescription = entry.key.toString()
        val valueDescription = entry.value.toString()
        val maxLength = 20
        val truncatedValueDescription = if (valueDescription.length > maxLength) {
            valueDescription.substring(0 until maxLength) + "..."
        } else {
            valueDescription
        }
        "$keyDescription : $truncatedValueDescription"
    }.joinToString(", ") + " ]"
}