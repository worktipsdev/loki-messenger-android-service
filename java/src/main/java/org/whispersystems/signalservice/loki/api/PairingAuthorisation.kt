package org.whispersystems.signalservice.loki.api

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.logging.Log
import org.whispersystems.signalservice.internal.util.Base64
import org.whispersystems.signalservice.internal.util.Hex
import org.whispersystems.signalservice.loki.utilities.removing05PrefixIfNeeded
import java.util.*

data class PairingAuthorisation(val primaryDevicePublicKey: String, val secondaryDevicePublicKey: String, val requestSignature: ByteArray?, val grantSignature: ByteArray?) {
    private val curve = Curve25519.getInstance(Curve25519.BEST)

    val type: Type
        get() = when (grantSignature) {
            null -> Type.REQUEST
            else -> Type.GRANT
        }

    enum class Type(val rawValue: Int) { REQUEST(1), GRANT(2) }

    constructor(primaryDevicePubKey: String, secondaryDevicePubKey: String) : this(primaryDevicePubKey, secondaryDevicePubKey, null, null)

    fun sign(type: Type, privateKey: ByteArray): PairingAuthorisation? {
        val target = if (type == Type.REQUEST) primaryDevicePublicKey else secondaryDevicePublicKey
        val data = Hex.fromStringCondensed(target) + ByteArray(1) { type.rawValue.toByte() }
        try {
            val signature = curve.calculateSignature(privateKey, data)
            return if (type == Type.REQUEST) copy(requestSignature = signature) else copy(grantSignature = signature)
        } catch (e: Exception) {
            return null
        }
    }

    fun verify(): Boolean {
        if (requestSignature == null && grantSignature == null) { return false }
        val signature = if (type == Type.REQUEST) requestSignature else grantSignature
        val issuer = if (type == Type.REQUEST) secondaryDevicePublicKey else primaryDevicePublicKey
        val target = if (type == Type.REQUEST) primaryDevicePublicKey else secondaryDevicePublicKey
        return try {
            val data = Hex.fromStringCondensed(target) + ByteArray(1) { type.rawValue.toByte() }
            val issuerPublicKey = Hex.fromStringCondensed(issuer.removing05PrefixIfNeeded())
            curve.verifySignature(issuerPublicKey, data, signature)
        } catch (e: Exception) {
            Log.w("LOKI", e.message)
            false
        }
    }

    fun toJSON(): Map<String, Any> {
        val result = mutableMapOf( "primaryDevicePubKey" to primaryDevicePublicKey, "secondaryDevicePubKey" to secondaryDevicePublicKey )
        if (requestSignature != null) { result["requestSignature"] = Base64.encodeBytes(requestSignature) }
        if (grantSignature != null) { result["grantSignature"] = Base64.encodeBytes(grantSignature) }
        return result
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (!(other is PairingAuthorisation)) return false
        return (primaryDevicePublicKey == other.primaryDevicePublicKey && secondaryDevicePublicKey == other.secondaryDevicePublicKey
            && Arrays.equals(requestSignature, other.requestSignature) && Arrays.equals(grantSignature, other.grantSignature))
    }
}