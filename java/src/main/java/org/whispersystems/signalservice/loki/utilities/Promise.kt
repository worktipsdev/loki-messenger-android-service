@file:JvmName("PromiseUtil")
package org.whispersystems.signalservice.loki.utilities

import nl.komponents.kovenant.Promise
import org.whispersystems.libsignal.logging.Log

fun <V, E: Throwable> Promise<V, E>.get(defaultValue: V): V {
  return try {
    get()
  } catch (e: Exception) {
    defaultValue
  }
}

fun <V, E> Promise<V, E>.successBackground(callback: (value: V) -> Unit): Promise<V, E> {
  Thread {
    try {
      callback(get())
    } catch (e: Exception) {
      Log.w("Promise", "Failed to execute task in background: ${e.message}")
    }
  }.start()

  return this
}