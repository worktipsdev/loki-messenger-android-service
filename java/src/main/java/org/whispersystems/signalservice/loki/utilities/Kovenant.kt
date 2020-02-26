package org.whispersystems.signalservice.loki.utilities

import nl.komponents.kovenant.Context
import nl.komponents.kovenant.Kovenant
import nl.komponents.kovenant.buildDispatcher
import org.whispersystems.libsignal.logging.Log
import kotlin.math.max

// Try to use all available threads minus one for the callback
private val recommendedThreadCount: Int
    get() = Runtime.getRuntime().availableProcessors() - 1

fun Kovenant.createContext(contextName: String, threadCount: Int = max(recommendedThreadCount, 1)): Context {
  return createContext {
    callbackContext.dispatcher = buildDispatcher {
      name = "${contextName}CallbackDispatcher"
      // Ref: http://kovenant.komponents.nl/api/core_usage/#execution-order
      // Having 1 concurrent task ensures we have in-order callback handling
      concurrentTasks = 1
    }
    workerContext.dispatcher = buildDispatcher {
      name = "${contextName}WorkerDispatcher"
      concurrentTasks = threadCount
    }
    multipleCompletion = { lhs, rhs ->
      Log.d("Loki", "Promise resolved more than once (first with $lhs, then with $rhs); ignoring $rhs.")
    }
  }
}
