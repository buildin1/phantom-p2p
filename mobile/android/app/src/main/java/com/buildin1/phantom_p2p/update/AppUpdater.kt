package com.buildin1.phantom_p2p.update

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.content.pm.PackageInstaller
import android.os.Build
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * 云端下发的版本通告。
 *
 * [mandatory] 为 true 表示当前版本已低于服务端声明的 `min_supported`，
 * 界面要弹「当前版本已失效，请及时更新」。
 */
data class AppUpdateInfo(
    val platform: String,
    val latestVersion: String,
    val minSupported: String,
    val downloadUrl: String,
    /** 安装包的 SHA-256，小写十六进制 64 位。 */
    val sha256: String,
    val notes: String,
    val mandatory: Boolean,
)

/** 更新的进行状态。 */
sealed interface UpdateState {
    data object Idle : UpdateState
    data class Downloading(val percent: Int, val bytes: Long, val total: Long) : UpdateState
    data object Verifying : UpdateState
    /** 包已就绪，正在唤起系统安装器。 */
    data object Installing : UpdateState
    data class Failed(val reason: String) : UpdateState
}

/**
 * 应用内更新。
 *
 * ## 为什么可以这么做
 *
 * 此应用不上架 Google Play（国内用不了），所以不受 Play 的自更新政策限制。
 * 上架的应用这么做会被下架。
 *
 * ## 三条不能省的约束
 *
 * 1. **SHA-256 必须校验。** 没有校验的自动安装等于把设备交给任何能劫持
 *    下载的人。校验不过就删包，绝不唤起安装器。
 * 2. **新包必须用同一个签名密钥。** 签名不一致时系统会拒绝安装（报
 *    `INSTALL_FAILED_UPDATE_INCOMPATIBLE`），用户只能卸载重装、数据全丢。
 *    密钥见 `mobile/android/phantom-release.jks`，备份在
 *    `C:\Users\dahai\PhantomKeystoreBackup\`。
 * 3. **必须走 [PackageInstaller]，不能 Intent 一个 `file://` 路径。**
 *    Android 7 起 `file://` URI 会触发 `FileUriExposedException`。
 *
 * ## 用户一定会看到的一步
 *
 * Android 8+ 要求用户在系统设置里单独为本应用打开「允许安装未知应用」。
 * 第一次更新时会跳到系统设置页 —— 这个体验绕不过去，只能提前说清楚。
 */
class AppUpdater(private val context: Context) {

    private val _state = MutableStateFlow<UpdateState>(UpdateState.Idle)
    val state: StateFlow<UpdateState> = _state.asStateFlow()

    private val _pending = MutableStateFlow<AppUpdateInfo?>(null)

    /** 当前待处理的更新通告；没有则为 null。 */
    val pending: StateFlow<AppUpdateInfo?> = _pending.asStateFlow()

    fun offer(info: AppUpdateInfo) {
        _pending.value = info
    }

    /** 用户选择「以后再说」。强制更新不允许忽略。 */
    fun dismiss() {
        if (_pending.value?.mandatory == true) return
        _pending.value = null
    }

    /**
     * 系统是否允许本应用安装 APK。
     *
     * 返回 false 时要先把用户送到系统设置页授权，见 [unknownSourcesSettingsIntent]。
     */
    fun canInstallPackages(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.packageManager.canRequestPackageInstalls()
        } else {
            true
        }

    /** 跳转到「允许安装未知应用」的系统设置页。 */
    fun unknownSourcesSettingsIntent(): Intent? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Intent(
                android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                android.net.Uri.parse("package:${context.packageName}"),
            )
        } else {
            null
        }

    /**
     * 下载 → 校验 → 唤起安装。
     *
     * 全程在 IO 线程；进度通过 [state] 回传。任何一步失败都会清理掉半成品，
     * 不留下一个可能被下次误用的残包。
     */
    suspend fun download(info: AppUpdateInfo) = withContext(Dispatchers.IO) {
        // 落在应用私有的 cache 里：不需要存储权限，卸载时系统自动清掉。
        val target = File(context.cacheDir, "update-${info.latestVersion}.apk")
        runCatching { target.delete() }

        try {
            _state.value = UpdateState.Downloading(0, 0, 0)

            val connection = (URL(info.downloadUrl).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 30_000
                instanceFollowRedirects = true
            }
            connection.connect()

            if (connection.responseCode !in 200..299) {
                fail(target, "下载失败：服务器返回 ${connection.responseCode}")
                return@withContext
            }

            val total = connection.contentLengthLong
            var written = 0L
            // 一边落盘一边算摘要：读两遍文件在低端机上是可感知的多出来的几秒。
            val digest = MessageDigest.getInstance("SHA-256")

            connection.inputStream.use { input ->
                target.outputStream().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        output.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
                        written += read
                        val percent = if (total > 0) (written * 100 / total).toInt() else 0
                        _state.value = UpdateState.Downloading(percent, written, total)
                    }
                }
            }

            _state.value = UpdateState.Verifying
            val actual = digest.digest().joinToString("") { "%02x".format(it) }
            if (!actual.equals(info.sha256, ignoreCase = true)) {
                // 这不是"重试一下就好"的错误：要么包被改过，要么发布信息配错了。
                // 两种情况都绝不能安装。
                Log.e(TAG, "SHA-256 不匹配：期望 ${info.sha256}，实际 $actual")
                fail(target, "安装包校验失败，已丢弃。请稍后重试或前往官网下载。")
                return@withContext
            }

            _state.value = UpdateState.Installing
            install(target)
        } catch (e: Exception) {
            Log.e(TAG, "更新失败", e)
            fail(target, "更新失败：${e.message ?: "网络异常"}")
        }
    }

    private fun fail(target: File, reason: String) {
        runCatching { target.delete() }
        _state.value = UpdateState.Failed(reason)
    }

    /**
     * 把 APK 交给系统安装器。
     *
     * 用 [PackageInstaller] 的会话模式：把字节写进会话再 commit，
     * 全程不暴露文件路径，也就不需要 FileProvider 授权那一套。
     */
    private fun install(apk: File) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(
            PackageInstaller.SessionParams.MODE_FULL_INSTALL
        )

        var sessionId = -1
        try {
            sessionId = installer.createSession(params)
            installer.openSession(sessionId).use { session ->
                session.openWrite("phantom", 0, apk.length()).use { output ->
                    apk.inputStream().use { it.copyTo(output) }
                    session.fsync(output)
                }
                session.commit(installIntentSender(sessionId))
            }
        } catch (e: Exception) {
            Log.e(TAG, "唤起安装失败", e)
            if (sessionId >= 0) runCatching { installer.abandonSession(sessionId) }
            _state.value = UpdateState.Failed("唤起安装失败：${e.message ?: "未知错误"}")
        }
    }

    private fun installIntentSender(sessionId: Int): IntentSender {
        val intent = Intent(context, UpdateInstallReceiver::class.java).apply {
            action = UpdateInstallReceiver.ACTION_INSTALL_RESULT
        }
        // FLAG_MUTABLE 是必需的：系统要往这个 Intent 里塞安装结果。
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        return PendingIntent.getBroadcast(context, sessionId, intent, flags).intentSender
    }

    private companion object {
        const val TAG = "AppUpdater"
    }
}
