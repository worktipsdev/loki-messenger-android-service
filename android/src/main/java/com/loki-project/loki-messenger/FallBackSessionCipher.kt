package com.`loki-project`.`loki-messenger`

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.libsignal.SignalProtocolAddress
import org.whispersystems.libsignal.state.IdentityKeyStore
import org.whispersystems.signalservice.internal.util.Util
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A Fallback session cipher which uses the a public key to encrypt data
 * @property identityKeyStore IdentityKeyStore The identity key store
 * @property remoteAddress SignalProtocolAddress The remote address
 */
class FallBackSessionCipher(private val identityKeyStore: IdentityKeyStore, private val remoteAddress: SignalProtocolAddress) {
    // The length of the iv
    private val ivLength = 16

    // Our identity key
    private val userIdentityKey = identityKeyStore.identityKeyPair

    // Our cipher
    private val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

    // A symmetric key used for encryption and decryption
    private val symmetricKey: ByteArray?
        get() {
            try {
                val curve = Curve25519.getInstance(Curve25519.BEST)
                val pubKey = remoteAddress.pubKeyData()
                val privKey = userIdentityKey.privateKey.serialize()
                return curve.calculateAgreement(pubKey, privKey)
            } catch (e: Exception) {
                e.printStackTrace()
            }
            return null
        }

    /**
     * Encrypt a message
     * @param paddedMessage ByteArray The padded message
     * @return ByteArray? The encrypted message or null if something went wrong
     */
    fun encrypt(paddedMessage: ByteArray): ByteArray? {
        val symmetricKey = symmetricKey
        if (symmetricKey != null) {
            try {
                return diffieHellmanEncrypt(paddedMessage, symmetricKey)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
        return null
    }

    /**
     * Decrypt a message
     * @param cipherText ByteArray The message cipher text
     * @return ByteArray? The decrypted message or null if something went wrong
     */
    fun decrypt(cipherText: ByteArray): ByteArray? {
        val symmetricKey = symmetricKey
        if (symmetricKey != null) {
            try {
                return diffieHellmanDecrypt(cipherText, symmetricKey)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
        return null
    }

    private fun diffieHellmanEncrypt(paddedMessage: ByteArray, symmetricKey: ByteArray): ByteArray {
        val iv = Util.getRandomLengthBytes(ivLength)
        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(symmetricKey, "AES")

        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec)
        val cipherText = cipher.doFinal(paddedMessage)

        // Combine IV and encrypted part
        return iv + cipherText
    }

    private fun diffieHellmanDecrypt(cipherText: ByteArray, symmetricKey: ByteArray): ByteArray {
        val iv = cipherText.sliceArray(0 until ivLength)
        val encryptedMessage = cipherText.sliceArray(ivLength until cipherText.size)

        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(symmetricKey, "AES")

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec)
        return cipher.doFinal(encryptedMessage)
    }
}

// region Private extensions

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()

private fun String.hexStringToByteArray(): ByteArray {
    val result = ByteArray(length / 2)

    for (i in 0 until length step 2) {
        val firstIndex = HEX_CHARS.indexOf(this[i]);
        val secondIndex = HEX_CHARS.indexOf(this[i + 1]);

        val octet = firstIndex.shl(4).or(secondIndex)
        result.set(i.shr(1), octet.toByte())
    }

    return result
}

private fun SignalProtocolAddress.pubKeyData(): ByteArray {
    var address = this.name
    if (address.count() == 66) {
        address = address.removePrefix("05")
    }
    return address.hexStringToByteArray()
}

// endregion
