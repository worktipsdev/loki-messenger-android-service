package org.whispersystems.signalservice.loki.crypto

import org.signal.libsignal.metadata.SealedSessionCipher
import org.signal.libsignal.metadata.certificate.CertificateValidator
import org.whispersystems.libsignal.InvalidMessageException
import org.whispersystems.libsignal.SignalProtocolAddress
import org.whispersystems.libsignal.loki.FallbackSessionCipher
import org.whispersystems.libsignal.loki.LokiFriendRequestMessage
import org.whispersystems.libsignal.protocol.PreKeySignalMessage
import org.whispersystems.libsignal.state.SignalProtocolStore
import org.whispersystems.libsignal.util.guava.Optional
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccess
import org.whispersystems.signalservice.api.messages.SignalServiceContent
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope
import org.whispersystems.signalservice.api.push.SignalServiceAddress
import org.whispersystems.signalservice.internal.push.OutgoingPushMessage
import org.whispersystems.signalservice.internal.push.PushTransportDetails
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Envelope.Type
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.loki.messaging.LokiPreKeyRecordDatabaseProtocol
import org.whispersystems.signalservice.loki.messaging.LokiThreadDatabaseProtocol

class LokiServiceCipher(localAddress: SignalServiceAddress, private val signalProtocolStore: SignalProtocolStore, private val threadDatabase: LokiThreadDatabaseProtocol? = null,
        private val preKeyRecordDatabase: LokiPreKeyRecordDatabaseProtocol? = null, certificateValidator: CertificateValidator? = null) : SignalServiceCipher(localAddress, signalProtocolStore, certificateValidator) {

    private val userPrivateKey get() = signalProtocolStore.identityKeyPair.privateKey.serialize()

    fun encryptFriendRequest(destination: SignalProtocolAddress, unidentifiedAccess: Optional<UnidentifiedAccess>,unpaddedMessageBody: ByteArray): OutgoingPushMessage {
        val cipher = FallbackSessionCipher(userPrivateKey, destination.name)
        val transportDetails = PushTransportDetails(FallbackSessionCipher.sessionVersion)
        val bytes = cipher.encrypt(transportDetails.getPaddedMessageBody(unpaddedMessageBody)) ?: ByteArray(0)
        if (unidentifiedAccess.isPresent) {
            val sessionCipher = SealedSessionCipher(signalProtocolStore, destination)
            val message = LokiFriendRequestMessage(bytes)
            val ciphertext = sessionCipher.encrypt(destination, unidentifiedAccess.get().unidentifiedCertificate, message)
            return OutgoingPushMessage(Type.UNIDENTIFIED_SENDER_VALUE, destination.deviceId, 0, Base64.encodeBytes(ciphertext))
        }
        return OutgoingPushMessage(Type.FRIEND_REQUEST_VALUE, destination.deviceId, 0, Base64.encodeBytes(bytes))
    }

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

    fun validateBackgroundMessage(content: SignalServiceContent, ciphertext: ByteArray) {
        val preKeyRecord = preKeyRecordDatabase!!.getPreKeyRecord(content.sender)
        check(preKeyRecord != null) { "Received a background message from a user without an associated pre key record." }
        val message = PreKeySignalMessage(ciphertext)
        check(preKeyRecord.id == (message.preKeyId.orNull() ?: -1)) { "Received a background message from an unknown source." }
    }
}
