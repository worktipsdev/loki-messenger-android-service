package org.whispersystems.signalservice.loki.utilities

import nl.komponents.kovenant.Promise
import org.whispersystems.signalservice.internal.util.concurrent.SettableFuture
import java.util.concurrent.ExecutionException

fun <V, E: Throwable> Promise<V, E>.sync(): V {
  val future = SettableFuture<V>()
  this.success { future.set(it) }.fail { future.setException(it) }

  try {
    return future.get()
  } catch (e: ExecutionException) {
    throw e.cause ?: e
  } catch (e: Exception) {
    throw e
  }
}

fun <V, E: Throwable> Promise<V, E>.sync(defaultValue: V): V {
  return try {
    this.sync()
  } catch (e: Exception) {
    defaultValue
  }
}