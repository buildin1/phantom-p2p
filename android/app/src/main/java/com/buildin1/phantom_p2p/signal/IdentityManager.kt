package com.buildin1.phantom_p2p.signal

import android.content.Context
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.KeyPairGenerator
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * 管理本地 Ed25519 身份密钥对，持久化到 SharedPreferences（Base64 存储）。
 * 首次运行时自动生成，后续每次读取相同密钥。
 */
class IdentityManager(context: Context) {

    private val prefs = context.getSharedPreferences("phantom_identity", Context.MODE_PRIVATE)
    private val spec = EdDSANamedCurveTable.getByName("Ed25519")

    /** Ed25519 私钥（32 字节 seed） */
    val privateKey: EdDSAPrivateKey

    /** Ed25519 公钥（32 字节） */
    val publicKey: EdDSAPublicKey

    /** 公钥原始字节（发给服务器用） */
    val publicKeyBytes: ByteArray

    init {
        val seedKey = "identity_seed"
        val existingSeed = prefs.getString(seedKey, null)

        val seed: ByteArray = if (existingSeed != null) {
            android.util.Base64.decode(existingSeed, android.util.Base64.DEFAULT)
        } else {
            val random = SecureRandom()
            ByteArray(32).also {
                random.nextBytes(it)
                prefs.edit().putString(seedKey, android.util.Base64.encodeToString(it, android.util.Base64.DEFAULT)).apply()
            }
        }

        val privSpec = EdDSAPrivateKeySpec(seed, spec)
        privateKey = EdDSAPrivateKey(privSpec)
        val pubSpec = EdDSAPublicKeySpec(privateKey.abyte, spec)
        publicKey = EdDSAPublicKey(pubSpec)
        publicKeyBytes = publicKey.abyte
    }

    /**
     * 对 nonce 签名，返回 64 字节 Ed25519 签名。
     */
    fun sign(nonce: ByteArray): ByteArray {
        val engine = EdDSAEngine(MessageDigest.getInstance("SHA-512"))
        engine.initSign(privateKey)
        engine.update(nonce)
        return engine.sign()
    }

    /**
     * 返回公钥的十六进制前缀（16 字符），用于显示用户 ID。
     */
    fun userId(): String = publicKeyBytes.take(8).joinToString("") { "%02x".format(it) }
}
