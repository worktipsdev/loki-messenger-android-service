package org.whispersystems.signalservice.loki.api

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.push.SignalServiceProtos
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.Hex
import org.whispersystems.signalservice.internal.util.JsonUtil
import org.whispersystems.signalservice.loki.utilities.removing05PrefixIfNeeded
import java.util.*

data class LokiPairingAuthorisation(val primaryDevicePubKey: String, val secondaryDevicePubKey: String, val requestSignature: ByteArray?, val grantSignature: ByteArray?) {
    constructor(primaryDevicePubKey: String, secondaryDevicePubKey: String): this(primaryDevicePubKey, secondaryDevicePubKey, null, null)
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

    fun sign(type: Type, privateKey: ByteArray): LokiPairingAuthorisation? {
        val target = if (type == Type.REQUEST) primaryDevicePubKey else secondaryDevicePubKey
        val message = Hex.fromStringCondensed(target) + ByteArray(1) { type.rawValue.toByte() }

        return try {
            val signature = curve.calculateSignature(privateKey, message)
            if (type == Type.REQUEST) copy(requestSignature = signature) else copy(grantSignature = signature)
        } catch (e: Exception) {
            null
        }
    }

    fun verify(): Boolean {
        // It's only valid if we have signatures!
        if (requestSignature == null && grantSignature == null) {
            return false
        }

        val signature = if (type == Type.REQUEST) requestSignature else grantSignature
        val issuer = if (type == Type.REQUEST) secondaryDevicePubKey else primaryDevicePubKey
        val target = if (type == Type.REQUEST) primaryDevicePubKey else secondaryDevicePubKey

        return try {
            val data = Hex.fromStringCondensed(target) + ByteArray(1) { type.rawValue.toByte() }
            val issuerData = Hex.fromStringCondensed(issuer.removing05PrefixIfNeeded())
            curve.verifySignature(issuerData, data, signature)
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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other?.javaClass != javaClass) return false

        other as LokiPairingAuthorisation

        return (primaryDevicePubKey == other.primaryDevicePubKey && secondaryDevicePubKey == other.secondaryDevicePubKey && Arrays.equals(requestSignature, other.requestSignature) && Arrays.equals(grantSignature, other.grantSignature))
    }
}