package org.whispersystems.signalservice.loki.crypto

import org.signal.libsignal.metadata.certificate.CertificateValidator
import org.whispersystems.libsignal.InvalidMessageException
import org.whispersystems.libsignal.loki.FallbackSessionCipher
import org.whispersystems.libsignal.loki.LokiSessionResetProtocol
import org.whispersystems.libsignal.state.SignalProtocolStore
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope
import org.whispersystems.signalservice.api.push.SignalServiceAddress
import org.whispersystems.signalservice.internal.push.PushTransportDetails

class LokiServiceCipher(localAddress: SignalServiceAddress, private val signalProtocolStore: SignalProtocolStore, lokiSessionResetProtocol: LokiSessionResetProtocol, certificateValidator: CertificateValidator?) : SignalServiceCipher(localAddress, signalProtocolStore, lokiSessionResetProtocol, certificateValidator) {

    private val userPrivateKey get() = signalProtocolStore.identityKeyPair.privateKey.serialize()

    override fun decrypt(envelope: SignalServiceEnvelope, ciphertext: ByteArray): Plaintext {
        return if (envelope.isFriendRequest) decryptFriendRequest(envelope, ciphertext) else super.decrypt(envelope, ciphertext)
    }

    private fun decryptFriendRequest(envelope: SignalServiceEnvelope, ciphertext: ByteArray): Plaintext {
        val cipher = FallbackSessionCipher(userPrivateKey, envelope.source)
        val paddedMessageBody = cipher.decrypt(ciphertext) ?: throw InvalidMessageException("Failed to decrypt friend request message.")
        val transportDetails = PushTransportDetails(FallbackSessionCipher.sessionVersion)
        val unpaddedMessageBody = transportDetails.getStrippedPaddingMessageBody(paddedMessageBody)
        val metadata = Metadata(envelope.source, envelope.sourceDevice, envelope.timestamp, false, true)
        return Plaintext(metadata, unpaddedMessageBody)
    }
}
