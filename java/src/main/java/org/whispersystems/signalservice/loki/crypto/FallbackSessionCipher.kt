package org.whispersystems.signalservice.loki.crypto

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.util.Hex
import org.whispersystems.signalservice.internal.util.Util
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A session cipher that uses the current user's private key along with a contact's public key to encrypt data.
 */
class FallbackSessionCipher(private val userPrivateKey: ByteArray, private val hexEncodedContactPublicKey: String) {

    // region Convenience
    private val contactPublicKey by lazy {
        var hexEncodedContactPublicKey = hexEncodedContactPublicKey
        if (hexEncodedContactPublicKey.length == 66) {
            hexEncodedContactPublicKey = hexEncodedContactPublicKey.removePrefix("05")
        }
        Hex.fromStringCondensed(hexEncodedContactPublicKey)
    }

    private val symmetricKey: ByteArray?
        get() {
            try {
                val curve = Curve25519.getInstance(Curve25519.BEST)
                return curve.calculateAgreement(contactPublicKey, userPrivateKey)
            } catch (e: Exception) {
                e.printStackTrace()
                return null
            }
        }
    // endregion

    // region Settings
    companion object {
        private val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val sessionVersion = 3
        private val ivLength = 16
    }
    // endregion

    // region Encryption
    fun encrypt(paddedMessageBody: ByteArray): ByteArray? {
        val symmetricKey = symmetricKey ?: return null
        try {
            return encryptUsingDiffieHellman(paddedMessageBody, symmetricKey)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    private fun encryptUsingDiffieHellman(paddedMessageBody: ByteArray, symmetricKey: ByteArray): ByteArray {
        val iv = Util.getSecretBytes(ivLength)
        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(symmetricKey, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec)
        val encryptedMessageBody = cipher.doFinal(paddedMessageBody) 
        return iv + encryptedMessageBody
    }
    // endregion

    // region Decryption
    fun decrypt(bytes: ByteArray): ByteArray? {
        val symmetricKey = symmetricKey ?: return null
        try {
            return decryptUsingDiffieHellman(bytes, symmetricKey)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    private fun decryptUsingDiffieHellman(bytes: ByteArray, symmetricKey: ByteArray): ByteArray {
        val iv = bytes.sliceArray(0 until ivLength)
        val encryptedMessageBody = bytes.sliceArray(ivLength until bytes.size)
        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(symmetricKey, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec)
        return cipher.doFinal(encryptedMessageBody)
    }
    // endregion
}
