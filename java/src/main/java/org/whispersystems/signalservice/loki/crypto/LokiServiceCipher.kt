package org.whispersystems.signalservice.loki.crypto

import org.signal.libsignal.metadata.certificate.CertificateValidator
import org.whispersystems.libsignal.InvalidMessageException
import org.whispersystems.libsignal.SignalProtocolAddress
import org.whispersystems.libsignal.state.SignalProtocolStore
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope
import org.whispersystems.signalservice.api.push.SignalServiceAddress
import org.whispersystems.signalservice.internal.push.OutgoingPushMessage
import org.whispersystems.signalservice.internal.push.PushTransportDetails
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Envelope.Type
import org.whispersystems.signalservice.internal.util.Base64

/**
 * The only difference between this and `SignalServiceCipher` is the custom encryption/decryption logic.
 */
class LokiServiceCipher(address: SignalServiceAddress, private val signalProtocolStore: SignalProtocolStore, certificateValidator: CertificateValidator?)
    : SignalServiceCipher(address, signalProtocolStore, certificateValidator) {

    // region Convenience
    private val userPrivateKey get() = signalProtocolStore.identityKeyPair.privateKey.serialize()
    // endregion

    // region Initialization
    constructor(address: SignalServiceAddress, signalProtocolStore: SignalProtocolStore) : this(address, signalProtocolStore, null)
    // endregion

    // region Implementation
    fun encrypt(address: SignalProtocolAddress, unpaddedMessageBody: ByteArray): OutgoingPushMessage {
        val cipher = FallbackSessionCipher(userPrivateKey, address.name)
        val transportDetails = PushTransportDetails(FallbackSessionCipher.sessionVersion)
        val bytes = cipher.encrypt(transportDetails.getPaddedMessageBody(unpaddedMessageBody))
        return OutgoingPushMessage(Type.FRIEND_REQUEST_VALUE, address.deviceId, 0, Base64.encodeBytes(bytes))
    }

    /**
     * Decrypt the given `SignalServiceEnvelope` using a `FallbackSessionCipher` if it's a friend request and default Signal decryption otherwise.
     */
    override fun decrypt(envelope: SignalServiceEnvelope, bytes: ByteArray): Plaintext {
        if (envelope.isFriendRequest) {
            val cipher = FallbackSessionCipher(userPrivateKey, envelope.source)
            val paddedMessageBody = cipher.decrypt(bytes) ?: throw InvalidMessageException("Failed to decrypt friend request message.")
            val transportDetails = PushTransportDetails(FallbackSessionCipher.sessionVersion)
            val unpaddedMessage = transportDetails.getStrippedPaddingMessageBody(paddedMessageBody)
            val metadata = Metadata(envelope.source, envelope.sourceDevice, envelope.timestamp, false)
            return Plaintext(metadata, unpaddedMessage)
        } else {
            return super.decrypt(envelope, bytes)
        }
    }
    // endregion
}