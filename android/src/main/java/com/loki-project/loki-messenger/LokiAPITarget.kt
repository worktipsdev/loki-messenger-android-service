package com.`loki-project`.`loki-messenger`

class LokiAPITarget(val address: String, val port: Int) {

    internal enum class Method(val rawValue: String) {
        /**
         * Only supported by snode targets.
         */
        GetSwarm("get_snodes_for_pubkey"),
        /**
         * Only supported by snode targets.
         */
        GetMessages("retrieve"),
        SendMessage("store")
    }

}