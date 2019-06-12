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
class LokiServiceCipher(localAddress: SignalServiceAddress, private val signalProtocolStore: SignalProtocolStore, certificateValidator: CertificateValidator?)
    : SignalServiceCipher(localAddress, signalProtocolStore, certificateValidator) {

    private val userPrivateKey: ByteArray get() = signalProtocolStore.identityKeyPair.privateKey.serialize()

    constructor(localAddress: SignalServiceAddress, signalProtocolStore: SignalProtocolStore) : this(localAddress, signalProtocolStore, null)

    fun encryptUsingFallbackSessionCipher(address: SignalProtocolAddress, unpaddedMessage: ByteArray): OutgoingPushMessage {
        val fallbackCipher = FallbackSessionCipher(userPrivateKey, address.name)
        val transportDetails = PushTransportDetails(fallbackCipher.sessionVersion)
        val encryptedBody = fallbackCipher.encrypt(transportDetails.getPaddedMessageBody(unpaddedMessage))
        return OutgoingPushMessage(Type.FRIEND_REQUEST_VALUE, address.deviceId, 0, Base64.encodeBytes(encryptedBody))
    }

    /**
     * Decrypt the given `SignalServiceEnvelope` using a `FallbackSessionCipher` if it's a friend request and default Signal decryption otherwise.
     */
    override fun decrypt(envelope: SignalServiceEnvelope, ciphertext: ByteArray): Plaintext {
        if (envelope.isFriendRequest) {
            val fallbackCipher = FallbackSessionCipher(userPrivateKey, envelope.source)

            // Decrypt and un-pad
            val paddedMessage = fallbackCipher.decrypt(ciphertext) ?: throw InvalidMessageException("Failed to decrypt friend request message.")
            val transportDetails = PushTransportDetails(fallbackCipher.sessionVersion)
            val unpaddedMessage = transportDetails.getStrippedPaddingMessageBody(paddedMessage)

            val metadata = Metadata(envelope.source, envelope.sourceDevice, envelope.timestamp, false)
            return Plaintext(metadata, unpaddedMessage)
        } else {
            return super.decrypt(envelope, ciphertext)
        }
    }
}