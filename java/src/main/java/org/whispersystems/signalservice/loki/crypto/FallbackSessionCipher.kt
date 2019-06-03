package org.whispersystems.signalservice.loki.crypto

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.signalservice.internal.util.Util
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A session cipher that uses the current user's private key along with a contact's public key to encrypt data.
 *
 * `contactPublicKey` is the public key of the contact with whom the session is being established.
 */
class FallbackSessionCipher(private val userPrivateKey: ByteArray, private val contactPublicKey: ByteArray) {

    /// Used for both encryption and decryption
    private val symmetricKey: ByteArray?
        get() {
            try {
                val curve = Curve25519.getInstance(Curve25519.BEST)
                return curve.calculateAgreement(contactPublicKey, userPrivateKey)
            } catch (e: Exception) {
                e.printStackTrace()
            }
            return null
        }

    // region Settings
    private val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val sessionVersion = 3
    private val ivLength = 16
    // endregion

    // region Encryption
    fun encrypt(paddedMessage: ByteArray): ByteArray? {
        val symmetricKey = symmetricKey ?: return null
        try {
            return diffieHellmanEncrypt(paddedMessage, symmetricKey)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    private fun diffieHellmanEncrypt(paddedMessage: ByteArray, symmetricKey: ByteArray): ByteArray {
        val iv = Util.getRandomLengthBytes(ivLength)
        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(symmetricKey, "AES")

        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec)
        val cipherText = cipher.doFinal(paddedMessage)

        // Combine IV and encrypted message
        return iv + cipherText
    }
    // endregion

    // region Decryption
    fun decrypt(cipherText: ByteArray): ByteArray? {
        val symmetricKey = symmetricKey ?: return null
        try {
            return diffieHellmanDecrypt(cipherText, symmetricKey)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    private fun diffieHellmanDecrypt(cipherText: ByteArray, symmetricKey: ByteArray): ByteArray {
        val iv = cipherText.sliceArray(0 until ivLength)
        val encryptedMessage = cipherText.sliceArray(ivLength until cipherText.size)

        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(symmetricKey, "AES")

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec)
        return cipher.doFinal(encryptedMessage)
    }
    // endregion
}
