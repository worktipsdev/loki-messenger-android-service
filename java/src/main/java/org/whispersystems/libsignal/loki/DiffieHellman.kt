package org.whispersystems.libsignal.loki

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.signalservice.internal.util.Util
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object DiffieHellman {

    @JvmStatic private val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    @JvmStatic private val curve = Curve25519.getInstance(Curve25519.BEST)
    @JvmStatic private val ivLength = 16

    @JvmStatic @Throws
    fun encrypt(plainTextData: ByteArray, symmetricKey: ByteArray): ByteArray {
        val iv = Util.getSecretBytes(ivLength)
        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(symmetricKey, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec)
        val encryptedMessageBody = cipher.doFinal(plainTextData)
        return iv + encryptedMessageBody
    }

    @JvmStatic @Throws
    fun encrypt(plainTextData: ByteArray, publicKey: ByteArray, privateKey: ByteArray): ByteArray {
        val symmetricKey = curve.calculateAgreement(publicKey, privateKey)
        return encrypt(plainTextData, symmetricKey)
    }

    @JvmStatic @Throws
    fun decrypt(encryptedData: ByteArray, symmetricKey: ByteArray): ByteArray {
        val iv = encryptedData.sliceArray(0 until ivLength)
        val encryptedMessageBody = encryptedData.sliceArray(ivLength until encryptedData.size)
        val ivSpec = IvParameterSpec(iv)
        val secretKeySpec = SecretKeySpec(symmetricKey, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec)
        return cipher.doFinal(encryptedMessageBody)
    }

    @JvmStatic @Throws
    fun decrypt(encryptedData: ByteArray, publicKey: ByteArray, privateKey: ByteArray): ByteArray {
        val symmetricKey = curve.calculateAgreement(publicKey, privateKey)
        return decrypt(encryptedData, symmetricKey)
    }
}
