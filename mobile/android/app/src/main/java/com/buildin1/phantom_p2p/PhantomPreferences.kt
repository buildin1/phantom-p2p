package com.buildin1.phantom_p2p

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import androidx.core.content.edit
import com.buildin1.phantom_p2p.engine.RecentRoom
import com.buildin1.phantom_p2p.ui.screens.SettingsUiState
import java.util.concurrent.TimeUnit

/**
 * 本机偏好。
 *
 * 刻意不放身份密钥：那个由 Rust 侧的 `identity.rs` 持有并写在应用私有目录，
 * 走 SharedPreferences 会跟着云备份跑到另一台设备上，两台机器顶同一个 user_id。
 * 备份排除规则见 `res/xml/data_extraction_rules.xml`。
 */
class PhantomPreferences(private val context: Context) {

    private val sp = context.getSharedPreferences("phantom", Context.MODE_PRIVATE)

    /**
     * 写入系统剪贴板。
     *
     * 放在这里而不是界面层：复制房间码/邀请链接是 ViewModel 的动作，
     * 而 ViewModel 不该直接持有 Context —— 它已经通过本类拿到了。
     *
     * Android 13+ 系统自己会弹一个复制成功的浮层，应用再弹一次 Snackbar
     * 就是重复反馈，所以调用方要据此决定要不要提示。
     */
    fun copyToClipboard(label: String, text: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        clipboard?.setPrimaryClip(ClipData.newPlainText(label, text))
    }

    /**
     * 读系统剪贴板里的纯文本；没有或读不到返回 null。
     *
     * Android 10 起只有获得焦点的前台应用才读得到剪贴板 —— 这正是我们的场景
     * （用户刚点了「粘贴邀请链接」），但读不到时必须给得出提示，不能静默失败。
     */
    fun readClipboardText(): String? {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val clip = clipboard?.primaryClip ?: return null
        if (clip.itemCount == 0) return null
        return clip.getItemAt(0)?.coerceToText(context)?.toString()?.trim()?.takeIf {
            it.isNotEmpty()
        }
    }

    /** 系统是否会自己给出复制成功的视觉反馈（Android 13 起会）。 */
    val systemShowsCopyFeedback: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU

    val rememberRoomCode: Boolean get() = sp.getBoolean(KEY_REMEMBER_ROOM, true)
    val autoConnect: Boolean get() = sp.getBoolean(KEY_AUTO_CONNECT, false)
    val notificationActions: Boolean get() = sp.getBoolean(KEY_NOTIF_ACTIONS, true)
    val nickname: String get() = sp.getString(KEY_NICKNAME, null) ?: defaultNickname()

    fun setRememberRoomCode(value: Boolean) = sp.edit { putBoolean(KEY_REMEMBER_ROOM, value) }
    fun setAutoConnect(value: Boolean) = sp.edit { putBoolean(KEY_AUTO_CONNECT, value) }
    fun setNotificationActions(value: Boolean) = sp.edit { putBoolean(KEY_NOTIF_ACTIONS, value) }
    fun setNickname(value: String) = sp.edit { putString(KEY_NICKNAME, value.trim()) }

    /** 最近房间，最多 3 条，最新在前。存成 `code:timestamp` 一行一条。 */
    fun recentRooms(): List<RecentRoom> =
        sp.getStringSet(KEY_RECENT_ROOMS, emptySet())
            .orEmpty()
            .mapNotNull { entry ->
                val code = entry.substringBefore(':')
                val at = entry.substringAfter(':', "").toLongOrNull() ?: return@mapNotNull null
                code to at
            }
            .sortedByDescending { it.second }
            .take(3)
            .map { (code, at) -> RecentRoom(code, relativeHint(at)) }

    fun pushRecentRoom(code: String) {
        val now = System.currentTimeMillis()
        val kept = sp.getStringSet(KEY_RECENT_ROOMS, emptySet())
            .orEmpty()
            .filterNot { it.substringBefore(':') == code }
        sp.edit { putStringSet(KEY_RECENT_ROOMS, (kept + "$code:$now").toSet()) }
    }

    fun snapshot(): SettingsUiState = SettingsUiState(
        nickname = nickname,
        // 真实设备 ID 由 Rust 侧的身份密钥派生（公钥前 4 字节的十六进制）。
        // FFI 落地前先给一个稳定占位，免得每次进设置页都变一个数字。
        deviceId = sp.getString(KEY_DEVICE_ID, null) ?: placeholderDeviceId(),
        rememberRoomCode = rememberRoomCode,
        autoConnectOnLaunch = autoConnect,
        notificationActions = notificationActions,
        alwaysOnVpnEnabled = isAlwaysOnVpnEnabled(),
        batteryOptimizationIgnored = isBatteryOptimizationIgnored(),
        versionName = BuildConfig.VERSION_NAME,
        versionCode = BuildConfig.VERSION_CODE,
        devTools = BuildConfig.DEV_TOOLS,
    )

    /**
     * 本应用是否被设为 always-on VPN。
     *
     * 系统没有公开 API 直接问「我是不是 always-on」，只能通过
     * [VpnService.prepare] 返回 null（说明已授权且当前生效）来间接判断，
     * 这不完全等价——用户手动授权过也会返回 null。真实实现应改为读
     * `Settings.Secure.ALWAYS_ON_VPN_APP`，但那需要系统权限。
     * 因此这里保守返回 false，让引导始终可见，宁可多提示一次。
     */
    private fun isAlwaysOnVpnEnabled(): Boolean = false

    private fun isBatteryOptimizationIgnored(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return true
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return false
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    private fun placeholderDeviceId(): String {
        val existing = sp.getString(KEY_DEVICE_ID, null)
        if (existing != null) return existing
        val generated = (1..8).map { "0123456789abcdef".random() }.joinToString("")
        sp.edit { putString(KEY_DEVICE_ID, generated) }
        return generated
    }

    private fun defaultNickname(): String = "玩家${(1000..9999).random()}"

    private fun relativeHint(atMillis: Long): String {
        val days = TimeUnit.MILLISECONDS.toDays(System.currentTimeMillis() - atMillis)
        return when {
            days <= 0 -> "今天"
            days == 1L -> "昨天"
            days < 7 -> "${days}天前"
            else -> "更早"
        }
    }

    private companion object {
        const val KEY_REMEMBER_ROOM = "remember_room_code"
        const val KEY_AUTO_CONNECT = "auto_connect"
        const val KEY_NOTIF_ACTIONS = "notification_actions"
        const val KEY_NICKNAME = "nickname"
        const val KEY_RECENT_ROOMS = "recent_rooms"
        const val KEY_DEVICE_ID = "device_id_placeholder"
    }
}
