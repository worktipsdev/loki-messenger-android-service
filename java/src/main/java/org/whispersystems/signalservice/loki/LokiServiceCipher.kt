package org.whispersystems.signalservice.loki

import org.whispersystems.libsignal.InvalidMessageException
import org.whispersystems.libsignal.SignalProtocolAddress
import org.whispersystems.libsignal.protocol.CiphertextMessage
import org.whispersystems.libsignal.state.SignalProtocolStore
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope
import org.whispersystems.signalservice.api.push.SignalServiceAddress
import org.whispersystems.signalservice.internal.push.OutgoingPushMessage
import org.whispersystems.signalservice.internal.push.PushTransportDetails
import org.whispersystems.signalservice.internal.util.Base64

/**
 * This is just an extension class to `SignalServiceCipher`.
 * Anything that `SignalServiceCipher` does, this class will also do it.
 *
 * The only change that has been made is adding custom `decrypt` logic
 */
class LokiServiceCipher(
        private val localAddress: SignalServiceAddress,
        private val signalProtocolStore: SignalProtocolStore
        ) : SignalServiceCipher(localAddress, signalProtocolStore, null) {

    /**
     * Encrypt a message with the FallBackSessionCipher
     * @param destination SignalProtocolAddress The destination
     * @param unpaddedMessage ByteArray The un-padded message
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

    /**
     * Decrypt the envelope.
     * If the envelope is a `FriendRequest` then we decrypt using `FallBackSessionCipher`.
     * Otherwise we fallback to using the Signal implementation.
     */
    override fun decrypt(envelope: SignalServiceEnvelope, ciphertext: ByteArray): Plaintext {
        return if (envelope.isFriendRequest) decryptFriendRequest(envelope, ciphertext) else super.decrypt(envelope, ciphertext)
    }

    /**
     * Decrypt the friend request using `FallBackSessionCipher`
     */
    private fun decryptFriendRequest(envelope: SignalServiceEnvelope, ciphertext: ByteArray): Plaintext {
        val sourceAddress = SignalProtocolAddress(envelope.source, envelope.sourceDevice)
        val fallBackCipher = FallBackSessionCipher(signalProtocolStore, sourceAddress)

        // Decrypt and un-pad
        val paddedMessage = fallBackCipher.decrypt(ciphertext) ?: throw InvalidMessageException("Failed to decrypt friend request message using FallBackSessionCipher.")
        val transportDetails = PushTransportDetails(fallBackCipher.getSessionVersion())
        val data = transportDetails.getStrippedPaddingMessageBody(paddedMessage)

        val metadata = Metadata(envelope.source, envelope.sourceDevice, envelope.timestamp, false)
        return Plaintext(metadata, data)
    }
}