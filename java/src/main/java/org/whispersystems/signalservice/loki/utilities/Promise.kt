@file:JvmName("PromiseUtil")
package org.whispersystems.signalservice.loki.utilities

import nl.komponents.kovenant.Promise

fun <V, E: Throwable> Promise<V, E>.get(defaultValue: V): V {
  return try {
    this.get()
  } catch (e: Exception) {
    defaultValue
  }
}