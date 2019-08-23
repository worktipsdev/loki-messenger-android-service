package org.whispersystems.signalservice.loki.utilities

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.signalservice.internal.util.Util
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object DiffeHellman {

    // region Settings
    @JvmStatic private val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    @JvmStatic private val curve = Curve25519.getInstance(Curve25519.BEST)
    @JvmStatic private val ivLength = 16
    // endregion

    @JvmStatic @Throws
    fun encrypt(plainText: ByteArray, symmetricKey: ByteArray): ByteArray {
        val iv = Util.getSecretBytes(ivLength)
        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(symmetricKey, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec)
        val encryptedMessageBody = cipher.doFinal(plainText)
        return iv + encryptedMessageBody
    }

    @JvmStatic @Throws
    fun encrypt(plainText: ByteArray, publicKey: ByteArray, privateKey: ByteArray): ByteArray {
        val symmetricKey = curve.calculateAgreement(publicKey, privateKey)
        return encrypt(plainText, symmetricKey)
    }

    @JvmStatic @Throws
    fun decrypt(cipherText: ByteArray, symmetricKey: ByteArray): ByteArray {
        val iv = cipherText.sliceArray(0 until ivLength)
        val encryptedMessageBody = cipherText.sliceArray(ivLength until cipherText.size)
        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(symmetricKey, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec)
        return cipher.doFinal(encryptedMessageBody)
    }

    @JvmStatic @Throws
    fun decrypt(cipherText: ByteArray, publicKey: ByteArray, privateKey: ByteArray): ByteArray {
        val symmetricKey = curve.calculateAgreement(publicKey, privateKey)
        return decrypt(cipherText, symmetricKey)
    }
}