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

class LokiServiceCipher(localAddress: SignalServiceAddress, private val signalProtocolStore: SignalProtocolStore, private val threadDatabase: LokiThreadDatabaseProtocol? = null,
        private val preKeyRecordDatabase: LokiPreKeyRecordDatabaseProtocol? = null, certificateValidator: CertificateValidator? = null) : SignalServiceCipher(localAddress, signalProtocolStore, certificateValidator) {

    private val userPrivateKey get() = signalProtocolStore.identityKeyPair.privateKey.serialize()

    fun encryptFriendRequest(destination: SignalProtocolAddress, unpaddedMessageBody: ByteArray): OutgoingPushMessage {
        val cipher = FallbackSessionCipher(userPrivateKey, destination.name)
        val transportDetails = PushTransportDetails(FallbackSessionCipher.sessionVersion)
        val bytes = cipher.encrypt(transportDetails.getPaddedMessageBody(unpaddedMessageBody))
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
        val metadata = Metadata(envelope.source, envelope.sourceDevice, envelope.timestamp, false)
        return Plaintext(metadata, unpaddedMessageBody)
    }

    fun getSessionStatus(envelope: SignalServiceEnvelope): SessionState? {
        val address = SignalProtocolAddress(envelope.source, envelope.sourceDevice)
        val sessionRecord = signalProtocolStore.loadSession(address)
        val session = sessionRecord.sessionState
        return if (session.hasSenderChain()) session else null
    }

    fun validateBackgroundMessage(envelope: SignalServiceEnvelope, ciphertext: ByteArray) {
        val preKeyRecord = preKeyRecordDatabase!!.getPreKeyRecord(envelope.source)
        check(preKeyRecord != null) { "Received a background message from a user without an associated pre key record." }
        val message = PreKeySignalMessage(ciphertext)
        check(preKeyRecord.id == (message.preKeyId.orNull() ?: -1)) { "Received a background message from an unknown source." }
    }

    fun handleSessionResetRequestIfNeeded(envelope: SignalServiceEnvelope, oldSession: SessionState?) {
        if (oldSession == null) return
        threadDatabase!!
        val threadID = threadDatabase.getThreadID(envelope.source)
        val currentSessionResetStatus = threadDatabase.getSessionResetStatus(threadID)
        if (currentSessionResetStatus == LokiThreadSessionResetStatus.NONE) return
        val currentSession = getSessionStatus(envelope)
        val address = SignalProtocolAddress(envelope.source, envelope.sourceDevice)
        fun restoreOldSession() {
            val session = signalProtocolStore.loadSession(address)
            session.previousSessionStates.removeAll { it.aliceBaseKey?.contentEquals(oldSession.aliceBaseKey) ?: false }
            session.promoteState(oldSession)
            signalProtocolStore.storeSession(address, session)
        }
        fun deleteAllSessionsExcept(session: SessionState?) {
            val sessionRecord = signalProtocolStore.loadSession(address)
            sessionRecord.removePreviousSessionStates()
            sessionRecord.setState(session ?: SessionState())
            signalProtocolStore.storeSession(address, sessionRecord)
        }
        if (currentSession == null || currentSession.aliceBaseKey?.contentEquals(oldSession.aliceBaseKey) != true) {
            if (currentSessionResetStatus == LokiThreadSessionResetStatus.REQUEST_RECEIVED) {
                // The other user used an old session to contact us; wait for them to switch to a new one.
                restoreOldSession()
            } else {
                // Our session reset was successful; we initiated one and got a new session back from the other user.
                deleteAllSessionsExcept(currentSession)
                threadDatabase.setSessionResetStatus(threadID, LokiThreadSessionResetStatus.NONE)
            }
        } else if (currentSessionResetStatus == LokiThreadSessionResetStatus.REQUEST_RECEIVED) {
            // Our session reset was successful; we received a message with the same session from the other user.
            deleteAllSessionsExcept(oldSession)
            threadDatabase.setSessionResetStatus(threadID, LokiThreadSessionResetStatus.NONE)
        }
    }
}