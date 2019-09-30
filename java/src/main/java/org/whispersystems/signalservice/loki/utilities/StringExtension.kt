package org.whispersystems.signalservice.loki.utilities

fun String.remove05PrefixIfNeeded(): String {
  return if (length == 66) removePrefix("05") else this
}