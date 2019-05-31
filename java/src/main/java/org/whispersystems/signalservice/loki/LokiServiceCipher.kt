package org.whispersystems.signalservice.loki

import org.whispersystems.libsignal.SignalProtocolAddress
import org.whispersystems.libsignal.protocol.CiphertextMessage
import org.whispersystems.libsignal.state.SignalProtocolStore
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher
import org.whispersystems.signalservice.api.push.SignalServiceAddress
import org.whispersystems.signalservice.internal.push.OutgoingPushMessage
import org.whispersystems.signalservice.internal.push.PushTransportDetails
import org.whispersystems.signalservice.internal.util.Base64

/**
 * This is just an extension class to `SignalServiceCipher`
 */
class LokiServiceCipher(
        private val localAddress: SignalServiceAddress,
        private val signalProtocolStore: SignalProtocolStore
        ) : SignalServiceCipher(localAddress, signalProtocolStore, null) {

    /**
     * Encrypt a message with the FallBackSessionCipher
     * @param destination SignalProtocolAddress The destination
     * @param unpaddedMessage ByteArray The unpadded message
     * @return OutgoingPushMessage The outgoing message
     */
    fun encryptWithFallbackCipher(destination: SignalProtocolAddress, unpaddedMessage: ByteArray): OutgoingPushMessage {
        val fallBackCipher = FallBackSessionCipher(signalProtocolStore, destination)
        val transportDetails = PushTransportDetails(fallBackCipher.getSessionVersion())
        val message = fallBackCipher.encrypt(transportDetails.getPaddedMessageBody(unpaddedMessage))
        val body = Base64.encodeBytes(message)

        // TODO: Replace `WHISPER_TYPE` with our own friend request message type
        return OutgoingPushMessage(CiphertextMessage.WHISPER_TYPE, destination.deviceId, 0, body)
    }
}