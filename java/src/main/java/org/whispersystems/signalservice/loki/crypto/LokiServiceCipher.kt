package org.whispersystems.signalservice.loki.crypto

import org.signal.libsignal.metadata.certificate.CertificateValidator
import org.whispersystems.libsignal.InvalidMessageException
import org.whispersystems.libsignal.SignalProtocolAddress
import org.whispersystems.libsignal.protocol.PreKeySignalMessage
import org.whispersystems.libsignal.state.SessionState
import org.whispersystems.libsignal.state.SignalProtocolStore
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope
import org.whispersystems.signalservice.api.push.SignalServiceAddress
import org.whispersystems.signalservice.internal.push.OutgoingPushMessage
import org.whispersystems.signalservice.internal.push.PushTransportDetails
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.Envelope.Type
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.loki.messaging.LokiPreKeyRecordDatabaseProtocol
import org.whispersystems.signalservice.loki.messaging.LokiThreadDatabaseProtocol
import org.whispersystems.signalservice.loki.messaging.LokiThreadSessionResetStatus

/**
 * The only difference between this and `SignalServiceCipher` is the custom encryption/decryption logic.
 */
class LokiServiceCipher(localAddress: SignalServiceAddress, private val signalProtocolStore: SignalProtocolStore, private val threadDatabase: LokiThreadDatabaseProtocol? = null,
        private val preKeyRecordDatabase: LokiPreKeyRecordDatabaseProtocol? = null, certificateValidator: CertificateValidator? = null) : SignalServiceCipher(localAddress, signalProtocolStore, certificateValidator) {

    // region Convenience
    private val userPrivateKey get() = signalProtocolStore.identityKeyPair.privateKey.serialize()
    // endregion

    // region Implementation
    fun encryptFriendRequest(destination: SignalProtocolAddress, unpaddedMessageBody: ByteArray): OutgoingPushMessage {
        val cipher = FallbackSessionCipher(userPrivateKey, destination.name)
        val transportDetails = PushTransportDetails(FallbackSessionCipher.sessionVersion)
        val bytes = cipher.encrypt(transportDetails.getPaddedMessageBody(unpaddedMessageBody))
        return OutgoingPushMessage(Type.FRIEND_REQUEST_VALUE, destination.deviceId, 0, Base64.encodeBytes(bytes))
    }

    /**
     * Decrypt the given `SignalServiceEnvelope` using a `FallbackSessionCipher` if it's a friend request and default Signal decryption otherwise.
     */
    override fun decrypt(envelope: SignalServiceEnvelope, ciphertext: ByteArray): Plaintext {
        return if (envelope.isFriendRequest) decryptFriendRequest(envelope, ciphertext) else lokiDecrypt(envelope, ciphertext)
    }

    private fun decryptFriendRequest(envelope: SignalServiceEnvelope, ciphertext: ByteArray): Plaintext {
        val cipher = FallbackSessionCipher(userPrivateKey, envelope.source)
        val paddedMessageBody = cipher.decrypt(ciphertext) ?: throw InvalidMessageException("Failed to decrypt friend request message.")
        val transportDetails = PushTransportDetails(FallbackSessionCipher.sessionVersion)
        val unpaddedMessageBody = transportDetails.getStrippedPaddingMessageBody(paddedMessageBody)
        val metadata = Metadata(envelope.source, envelope.sourceDevice, envelope.timestamp, false)
        return Plaintext(metadata, unpaddedMessageBody)
    }

    private fun lokiDecrypt(envelope: SignalServiceEnvelope, ciphertext: ByteArray): Plaintext {
        val sessionStatus = getSessionStatus(envelope) // The status can change during decryption
        val plainText = super.decrypt(envelope, ciphertext)
        if (sessionStatus == null && envelope.isPreKeySignalMessage) {
            validateSilentMessage(envelope, ciphertext)
        }
        handleSessionResetRequestIfNeeded(envelope, sessionStatus)
        return plainText
    }

    private fun getSessionStatus(envelope: SignalServiceEnvelope): SessionState? {
        val address = SignalProtocolAddress(envelope.source, envelope.sourceDevice)
        val sessionRecord = signalProtocolStore.loadSession(address)
        val sessionStatus = sessionRecord.sessionState
        return if (sessionStatus.hasSenderChain()) sessionStatus else null
    }

    private fun validateSilentMessage(envelope: SignalServiceEnvelope, ciphertext: ByteArray) {
        val preKeyRecord = preKeyRecordDatabase!!.getPreKeyRecord(envelope.source)
        check(preKeyRecord != null) {
            "Received a friend request from a user without an associated pre key bundle."
        }
        val message = PreKeySignalMessage(ciphertext)
        check(preKeyRecord.id == (message.preKeyId ?: -1)) {
            "Received a friend request accepted message from an unknown source."
        }
    }

    private fun handleSessionResetRequestIfNeeded(envelope: SignalServiceEnvelope, oldSessionStatus: SessionState?) {
        if (oldSessionStatus == null) return
        val threadID = threadDatabase!!.getThreadID(envelope.source)
        val sessionResetStatus = threadDatabase!!.getSessionResetStatus(threadID)
        if (sessionResetStatus == LokiThreadSessionResetStatus.NONE) return
        val isSessionResetRequest = (sessionResetStatus == LokiThreadSessionResetStatus.REQUEST_RECEIVED)
        val currentSessionStatus = getSessionStatus(envelope)
        val address = SignalProtocolAddress(envelope.source, envelope.sourceDevice)
        if (currentSessionStatus == null || currentSessionStatus.aliceBaseKey?.contentEquals(oldSessionStatus.aliceBaseKey) != true) {
            if (isSessionResetRequest) {
                // The other user used an old session to contact us; wait for them to switch to a new one.
                resetSession(oldSessionStatus, address)
            } else {
                // Our session reset was successful; we initiated one and got a new session back from the other user.
                deleteAllSessionsExcept(currentSessionStatus, address)
                // TODO: Notify session reset success
            }
        } else if (isSessionResetRequest) {
            // Our session reset was successful; we received a message with the same session from the other user.
            deleteAllSessionsExcept(oldSessionStatus, address)
            // TODO: Notify session reset success
        }
    }

    private fun resetSession(status: SessionState, address: SignalProtocolAddress) {
        val session = signalProtocolStore.loadSession(address)
        session.previousSessionStates.removeAll { it.aliceBaseKey?.contentEquals(status.aliceBaseKey) ?: false }
        session.promoteState(status) // This archives the old status
        signalProtocolStore.storeSession(address, session)
    }

    private fun deleteAllSessionsExcept(status: SessionState?, address: SignalProtocolAddress) {
        val session = signalProtocolStore.loadSession(address)
        session.removePreviousSessionStates()
        session.setState(status ?: SessionState())
        signalProtocolStore.storeSession(address, session)
    }
    // endregion
}