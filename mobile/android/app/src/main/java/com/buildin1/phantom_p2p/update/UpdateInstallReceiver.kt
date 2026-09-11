package com.buildin1.phantom_p2p.update

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.util.Log
import android.widget.Toast

/**
 * 接收 [PackageInstaller] 的安装结果。
 *
 * ## 为什么必须有这个类
 *
 * `session.commit()` 要一个 `IntentSender`。没有它系统无法回报结果 ——
 * 用户点了「安装」之后，应用这边对成功还是失败一无所知，只能干等。
 *
 * ## STATUS_PENDING_USER_ACTION 是正常路径，不是错误
 *
 * 首次安装时系统需要用户确认（尤其是还没授予「允许安装未知应用」的情况），
 * 这时回来的是 [PackageInstaller.STATUS_PENDING_USER_ACTION]，里面带着一个
 * 要用户点的 Intent。**必须把它启动起来**，否则安装会静默停在这里 ——
 * 表现为"点了更新什么也没发生"。
 */
class UpdateInstallReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_INSTALL_RESULT) return

        val status = intent.getIntExtra(
            PackageInstaller.EXTRA_STATUS,
            PackageInstaller.STATUS_FAILURE,
        )
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty()

        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                if (confirm == null) {
                    Log.e(TAG, "系统要求用户确认，但没给确认 Intent")
                    return
                }
                // 从 Receiver 上下文启动 Activity 必须带 NEW_TASK。
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                runCatching { context.startActivity(confirm) }
                    .onFailure { Log.e(TAG, "无法唤起安装确认页", it) }
            }

            PackageInstaller.STATUS_SUCCESS -> {
                Log.i(TAG, "安装成功")
            }

            else -> {
                // 最常见的失败是签名不一致（INSTALL_FAILED_UPDATE_INCOMPATIBLE）：
                // 新包不是用同一个密钥签的。这种情况用户自己无解，必须说清楚。
                Log.e(TAG, "安装失败 status=$status: $message")
                val hint = if (message.contains("UPDATE_INCOMPATIBLE", ignoreCase = true)) {
                    "安装包签名与当前版本不一致，请前往官网下载"
                } else {
                    "安装失败：${message.ifEmpty { "未知原因" }}"
                }
                Toast.makeText(context, hint, Toast.LENGTH_LONG).show()
            }
        }
    }

    companion object {
        const val ACTION_INSTALL_RESULT = "com.buildin1.phantom_p2p.INSTALL_RESULT"
        private const val TAG = "UpdateInstall"
    }
}
