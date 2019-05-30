package com.`loki-project`.`loki-messenger`

class LokiAPI(val hexEncodedPublicKey: String) {

    // region Settings
    private val version = "v1"
    private val maxRetryCount = 3
    private val defaultMessageTTL = 1 * 24 * 60 * 60 * 1000
    // endregion

    // region Types
    sealed class Error(val description: String) : java.lang.Error() {
        /**
         * Only applicable to snode targets as proof of work isn't required for P2P messaging.
         */
        object ProofOfWorkCalculationFailed : Error("Failed to calculate proof of work.")
        object MessageConversionFailed : Error("Failed to convert Signal message to Loki message.")
    }
    // endregion

    // region Internal API
    internal fun invoke(method: LokiAPITarget.Method, target: LokiAPITarget, hexEncodedPublicKey: String, parameters: Map<String, Any>) {
        // TODO: Implement
    }
    // endregion

    // region Public API
    fun getMessages() {

    }
}