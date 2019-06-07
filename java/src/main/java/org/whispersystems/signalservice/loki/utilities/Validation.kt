package org.whispersystems.signalservice.loki.utilities

object PublicKeyValidation {

    @JvmStatic
    fun isValid(candidate: String): Boolean {
        val hexCharacters = "0123456789ABCDEF".toSet()
        val isValidHexEncoding = hexCharacters.containsAll(candidate.toSet())
        val hasValidLength = candidate.length == 66
        val hasValidPrefix = candidate.startsWith("05")
        return isValidHexEncoding && hasValidLength && hasValidPrefix
    }
}