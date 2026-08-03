package com.buildin1.phantom_p2p

import android.content.Context
import android.util.Base64
import android.util.Log
import java.io.File

/**
 * 把设备身份密钥从 Kotlin 侧搬到 Rust 侧。
 *
 * 控制面下沉后，签名由 `phantom_core::identity` 负责，它从
 * `<dataDir>/identity.key` 读取 **32 字节裸 seed**。而老版本的
 * `IdentityManager` 把同一个 seed 以 Base64 存在 SharedPreferences
 * (`phantom_identity` / `identity_seed`) 里。
 *
 * 两边存的是同一个东西：Ed25519 的 32 字节私钥种子。
 * `EdDSAPrivateKeySpec(seed)` 与 Rust 的 `SigningKey::from_bytes(seed)`
 * 派生出的公钥逐字节相同，所以搬过去之后 user_id 不变。
 *
 * **不迁移的后果不是报错，而是静默换身份**——Rust 找不到 identity.key 就会
 * 直接生成一把新的，用户的固定 IP、房间归属全部失效，而且没有任何提示。
 * 因此这一步必须在 `NativeSession.nativeInit()` **之前**完成。
 */
object IdentityMigration {

    private const val TAG = "IdentityMigration"
    private const val LEGACY_PREFS = "phantom_identity"
    private const val LEGACY_SEED_KEY = "identity_seed"
    private const val RUST_KEY_FILE = "identity.key"
    private const val ED25519_SEED_SIZE = 32

    /**
     * 幂等：目标文件已存在就直接返回，不会覆盖 Rust 已经在用的密钥。
     *
     * 旧的 SharedPreferences 条目**故意保留不删**——万一需要回退到旧版本，
     * 那边还能读到同一把密钥。多留一份 seed 的代价远小于把用户身份弄丢。
     *
     * @return true 表示本次执行了迁移；false 表示无需迁移或无可迁移的密钥
     */
    fun migrateIfNeeded(context: Context, dataDir: File): Boolean {
        val target = File(dataDir, RUST_KEY_FILE)
        if (target.exists()) {
            return false
        }

        val encoded = context
            .getSharedPreferences(LEGACY_PREFS, Context.MODE_PRIVATE)
            .getString(LEGACY_SEED_KEY, null)
        if (encoded.isNullOrBlank()) {
            // 全新安装，没有历史身份，交给 Rust 自行生成即可
            return false
        }

        val seed = try {
            Base64.decode(encoded, Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, "旧身份密钥 Base64 解码失败，将由 Rust 重新生成", e)
            return false
        }

        if (seed.size != ED25519_SEED_SIZE) {
            Log.e(TAG, "旧身份密钥长度异常 (${seed.size} 字节)，将由 Rust 重新生成")
            return false
        }

        return try {
            dataDir.mkdirs()
            // 先写临时文件再改名：中途被杀不会留下半个密钥文件，
            // 那会让 Rust 判定长度异常并重新生成。
            val temp = File(dataDir, "$RUST_KEY_FILE.tmp")
            temp.writeBytes(seed)
            if (!temp.renameTo(target)) {
                temp.delete()
                Log.e(TAG, "身份密钥迁移失败：无法重命名到 ${target.path}")
                return false
            }
            Log.i(TAG, "设备身份已迁移至 ${target.path}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "身份密钥迁移失败", e)
            false
        }
    }
}
