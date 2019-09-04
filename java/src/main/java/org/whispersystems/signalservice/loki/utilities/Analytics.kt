package org.whispersystems.signalservice.loki.utilities

final class Analytics {
    lateinit var trackImplementation: (String) -> Unit // Set in ApplicationContext.java

    companion object {
        val shared = Analytics()
    }

    fun track(event: String) {
        trackImplementation(event)
    }
}