package org.whispersystems.signalservice.loki.api

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.push.SignalServiceProtos
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.JsonUtil


typealias LokiPairingAuthorisationType = SignalServiceProtos.PairingAuthorisationMessage.Type

data class LokiPairingAuthorisation(val primaryDevicePubKey: String, val secondaryDevicePubKey: String, val requestSignature: ByteArray?, val grantSignature: ByteArray?) {
    constructor(message: SignalServiceProtos.PairingAuthorisationMessage) : this(
            message.primaryDevicePubKey,
            message.secondaryDevicePubKey,
            if (message.hasRequestSignature()) message.requestSignature.toByteArray() else null,
            if (message.hasGrantSignature()) message.grantSignature.toByteArray() else null
    )

    enum class Type(val rawValue: Int) { REQUEST(1), GRANT(2) }

    val type: Type
        get() = when (grantSignature) {
            null -> Type.REQUEST
            else -> Type.GRANT
        }

    private val curve = Curve25519.getInstance(Curve25519.BEST)

    fun verify(): Boolean {
        // It's only valid if we have signatures!
        if (requestSignature == null && grantSignature == null) {
            return false
        }

        val signature = if (type == Type.REQUEST) requestSignature else grantSignature
        val issuer = if (type == Type.REQUEST) secondaryDevicePubKey else primaryDevicePubKey
        val target = if (type == Type.REQUEST) primaryDevicePubKey else secondaryDevicePubKey

        val data = target.hexAsByteArray + ByteArray(1) { type.rawValue.toByte() }

        return try {
            curve.verifySignature(issuer.removePrefix("05").hexAsByteArray, data, signature)
        } catch (e: Exception) {
            Log.w("LOKI", e.message)
            false
        }
    }

    fun toJSON(): String {
        val map = mutableMapOf("primaryDevicePubKey" to primaryDevicePubKey, "secondaryDevicePubKey" to secondaryDevicePubKey)
        if (requestSignature != null) { map["requestSignature"] = Base64.encodeBytes(requestSignature) }
        if (grantSignature != null) { map["grantSignature"] = Base64.encodeBytes(grantSignature) }
        return JsonUtil.toJson(map)
    }
}

// region Helper
val String.hexAsByteArray inline get() = this.chunked(2).map { it.toUpperCase().toInt(16).toByte() }.toByteArray()
// endregion