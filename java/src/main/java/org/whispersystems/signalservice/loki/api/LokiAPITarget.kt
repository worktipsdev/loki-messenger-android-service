package org.whispersystems.signalservice.loki.api

class LokiAPITarget(val address: String, val port: Int, val publicKeySet: KeySet?) {

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

    data class KeySet(val idKey: String, val encryptionKey: String)

    override fun equals(other: Any?): Boolean {
        return if (other is LokiAPITarget) {
            address == other.address && port == other.port
        } else {
            false
        }
    }

    override fun hashCode(): Int {
        return address.hashCode() xor port.hashCode()
    }

    override fun toString(): String { return "$address:$port" }
}
