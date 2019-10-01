package org.whispersystems.signalservice.loki.utilities

fun String.removing05PrefixIfNeeded(): String {
  return if (length == 66) removePrefix("05") else this
}