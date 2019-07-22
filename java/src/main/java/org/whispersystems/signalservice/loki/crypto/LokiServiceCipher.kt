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
import org.whispersystems.signalservice.loki.messaging.LokiThreadSessionResetState

/**
 * The only difference between this and `SignalServiceCipher` is the custom encryption/decryption logic.
 */
class LokiServiceCipher(
        localAddress: SignalServiceAddress,
        private val signalProtocolStore: SignalProtocolStore,
        private val threadDatabase: LokiThreadDatabaseProtocol,
        private val preKeyRecordDatabase: LokiPreKeyRecordDatabaseProtocol,
        certificateValidator: CertificateValidator?)
    : SignalServiceCipher(localAddress, signalProtocolStore, certificateValidator) {

    // region Convenience
    private val userPrivateKey get() = signalProtocolStore.identityKeyPair.privateKey.serialize()
    // endregion

    // region Initialization
    constructor(
            localAddress: SignalServiceAddress,
            signalProtocolStore: SignalProtocolStore,
            threadDatabase: LokiThreadDatabaseProtocol,
            preKeyRecordDatabase: LokiPreKeyRecordDatabaseProtocol
    ) : this(localAddress, signalProtocolStore, threadDatabase, preKeyRecordDatabase,null)
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
        if (envelope.isFriendRequest) {
            return decryptFriendRequest(envelope, ciphertext)
        } else {
            return decryptMessage(envelope, ciphertext)
        }
    }
    // endregion

    private fun decryptFriendRequest(envelope: SignalServiceEnvelope, ciphertext: ByteArray): Plaintext {
        val cipher = FallbackSessionCipher(userPrivateKey, envelope.source)
        val paddedMessageBody = cipher.decrypt(ciphertext) ?: throw InvalidMessageException("Failed to decrypt friend request message.")
        val transportDetails = PushTransportDetails(FallbackSessionCipher.sessionVersion)
        val unpaddedMessageBody = transportDetails.getStrippedPaddingMessageBody(paddedMessageBody)
        val metadata = Metadata(envelope.source, envelope.sourceDevice, envelope.timestamp, false)
        return Plaintext(metadata, unpaddedMessageBody)
    }

    private fun decryptMessage(envelope: SignalServiceEnvelope, ciphertext: ByteArray): Plaintext {
        // Our state before we decrypt the message
        val state = getCurrentSessionState(envelope)

        // While decrypting out state may change internally
        val plainText = super.decrypt(envelope, ciphertext)

        // Loki: Verify incoming friend request message
        if (state == null) {
            verifyFriendRequestAcceptPreKeyMessage(envelope, ciphertext)
        }

        // Loki: Handle any session resets
        handleSessionReset(envelope, state)

       return plainText
    }

    private fun getCurrentSessionState(envelope: SignalServiceEnvelope): SessionState? {
        val address = SignalProtocolAddress(envelope.source, envelope.sourceDevice)
        val record = signalProtocolStore.loadSession(address)
        val state = record.sessionState

        if (!state.hasSenderChain()) return null
        return state
    }

    private fun handleSessionReset(envelope: SignalServiceEnvelope, previousState: SessionState?) {
        // Don't bother doing anything if we didn't have a session before
        if (previousState == null) return

        val threadId = threadDatabase.getThreadID(envelope.source)
        val resetState = threadDatabase.getSessionResetState(threadId)

        // Bail early if no session reset is in progress
        if (resetState == LokiThreadSessionResetState.NONE) return

        val sessionResetReceived = resetState == LokiThreadSessionResetState.REQUEST_RECEIVED
        val currentState = getCurrentSessionState(envelope)

        // Check if our previous state and our current state differ
        if (currentState == null || !(currentState.aliceBaseKey?.contentEquals(previousState.aliceBaseKey) ?: false)) {
            if (sessionResetReceived) {
                // The other user used an old session to contact us.
                // Wait for them to use a new one
                restoreSession(previousState, envelope)
            } else {
                // Our session reset went through successfully
                // We had initiated a session reset and got a different session back from the user
                deleteAllSessionsExcept(currentState, envelope)
                // TODO: Notify session reset success
            }
        } else if (sessionResetReceived) {
            // Our session reset went through successfully
            // We got a message with the same session from the other user
            deleteAllSessionsExcept(previousState, envelope)
            // TODO: Notify session reset success
        }
    }

    private fun restoreSession(state: SessionState, envelope: SignalServiceEnvelope) {
        val address = SignalProtocolAddress(envelope.source, envelope.sourceDevice)
        val record = signalProtocolStore.loadSession(address)

        // Remove the state from previous session states
        record.previousSessionStates.removeAll { it.aliceBaseKey?.contentEquals(state.aliceBaseKey) ?: false }

        // Promote it so the previous state gets archived
        record.promoteState(state)

        signalProtocolStore.storeSession(address, record)
    }

    private fun deleteAllSessionsExcept(state: SessionState?, envelope: SignalServiceEnvelope) {
        val address = SignalProtocolAddress(envelope.source, envelope.sourceDevice)
        val record = signalProtocolStore.loadSession(address)
        record.removePreviousSessionStates()
        record.setState(state ?: SessionState())
        signalProtocolStore.storeSession(address, record)
    }

    private fun verifyFriendRequestAcceptPreKeyMessage(envelope: SignalServiceEnvelope, ciphertext: ByteArray) {
        if (!envelope.isPreKeySignalMessage()) return

        val storedPreKey = preKeyRecordDatabase.getPreKey(envelope.source)
        check(storedPreKey != null) {
            "Received a friend request from a public key for which no pre key bundle was created"
        }

        val message = PreKeySignalMessage(ciphertext)
        check(storedPreKey.id == (message.preKeyId ?: -1)) {
            "Received a PreKeyWhisperMessage (friend request accept) from an unknown source."
        }
    }
}