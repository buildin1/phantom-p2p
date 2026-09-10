package com.buildin1.phantom_p2p.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import com.buildin1.phantom_p2p.BuildConfig
import com.buildin1.phantom_p2p.MainActivity
import com.buildin1.phantom_p2p.R

/**
 * 虚拟网卡宿主。
 *
 * ## 职责边界
 *
 * 这个服务**只做三件事**：建立并持有 tun fd、维持前台通知、管理进程存活。
 * 信令、打洞、QUIC、加密、抗丢包全部在 Rust 侧（`phantom-core`），
 * 一个字节的包处理逻辑都不该出现在这个文件里。
 *
 * ## fd 交给 Rust，不逐包过 JNI
 *
 * [establish] 返回的 [ParcelFileDescriptor] 会 `detachFd()` 之后交给 Rust，
 * 由 `crates/core/src/tun_android.rs` 用 `AsyncFd` 直接读写。
 *
 * 旧版本走的是另一条路：每个包都回调进 Kotlin 再送回 Rust。1160 字节 MTU 下
 * 满速时每秒几万次 JNI 往返，是自己给自己造的性能坑。这里不重蹈覆辙。
 *
 * ## 旧版本踩过的坑，逐条对应
 *
 * 1. `foregroundServiceType` 用 `systemExempted`，不是 `specialUse`（见 Manifest）
 * 2. [onStartCommand] 返回 [START_STICKY]，与后台存活目标一致
 * 3. [onRevoke] 必须实现——用户在系统设置关掉 VPN、或别的 VPN 抢占时系统调它
 * 4. MTU 用 [BuildConfig.TUN_MTU]（1160），与 core 的 `TUN_MTU` 同源
 * 5. WakeLock 真的获取，不是只在 Manifest 里声明权限
 */
class PhantomVpnService : VpnService() {

    private var tunInterface: ParcelFileDescriptor? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                teardown()
                stopSelf()
                return START_NOT_STICKY
            }
        }

        startForeground(NOTIFICATION_ID, buildNotification(TunnelNotice.Connecting))
        acquireWakeLock()

        // START_STICKY：进程被系统回收后重建服务。
        // 旧版本用的是 START_NOT_STICKY，注释还写着「进程被杀后不自动重启」——
        // 那和「后台保活」这个产品目标直接冲突。
        return START_STICKY
    }

    /**
     * 建立虚拟网卡并把 fd 交出去。
     *
     * 调用方是引擎层：房间的子网与本机虚拟 IP 由服务端分配，必须等那一步完成
     * 才能建网卡，所以不能在 [onStartCommand] 里做。
     *
     * @return 已 detach 的裸 fd，失败时 -1。所有权转移给调用方（最终是 Rust）。
     */
    fun establishTunnel(
        localVirtualIp: String,
        subnetPrefixLength: Int,
        routes: List<Route>,
    ): Int {
        teardownTunOnly()

        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .addAddress(localVirtualIp, subnetPrefixLength)
            // MTU 必须与 core 的 TUN_MTU 一致。QUIC datagram 的可用载荷实测是
            // 1162 字节，设成 1500 会让每个满载包都超出上限，表现为稳定丢包。
            .setMtu(BuildConfig.TUN_MTU)
            .setBlocking(false)

        routes.forEach { builder.addRoute(it.address, it.prefixLength) }

        // 让本应用自己的流量绕开这条隧道，否则信令与打洞的包会灌回自己，
        // 形成回环。注意这只覆盖本进程；Rust 侧新建的 socket 还要各自
        // 走 protect()，见 ProtectedSocketFactory。
        runCatching { builder.addDisallowedApplication(packageName) }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        val pfd = runCatching { builder.establish() }.getOrNull()
        if (pfd == null) {
            Log.e(TAG, "establish() 返回 null：授权可能已被撤销")
            return -1
        }

        tunInterface = pfd
        updateNotification(TunnelNotice.Connected(localVirtualIp))
        // detachFd 之后 ParcelFileDescriptor 不再拥有这个 fd，
        // 关闭责任转移给 Rust 侧的 PlatformTun::close()。
        return pfd.detachFd()
    }

    /**
     * 保护一个 socket 使其绕开隧道。
     *
     * Rust 侧每建一个 UDP socket 都要回调到这里——`phantom-core` 里有十几处
     * `UdpSocket::bind`（ice / network / punch / stun / tunnel / udp_tunnel），
     * 漏掉任何一个，那条打洞流量就会被自己的隧道吞掉。
     */
    fun protectSocket(fd: Int): Boolean = protect(fd)

    /**
     * 用户在系统设置里关闭了 VPN，或另一个 VPN 应用抢占了。
     *
     * 不实现这个回调，资源不会释放，界面状态也会和系统实际状态脱节——
     * 用户会看到「已连接」但什么都不通。
     */
    override fun onRevoke() {
        Log.w(TAG, "VPN 授权被撤销")
        teardown()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        teardown()
        super.onDestroy()
    }

    // -----------------------------------------------------------------------

    private fun teardown() {
        teardownTunOnly()
        releaseWakeLock()
    }

    private fun teardownTunOnly() {
        runCatching { tunInterface?.close() }
        tunInterface = null
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(POWER_SERVICE) as? PowerManager ?: return
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKELOCK_TAG).apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseWakeLock() {
        runCatching { wakeLock?.takeIf { it.isHeld }?.release() }
        wakeLock = null
    }

    // -----------------------------------------------------------------------
    // 通知
    // -----------------------------------------------------------------------

    sealed interface TunnelNotice {
        data object Connecting : TunnelNotice
        data class Connected(val virtualIp: String) : TunnelNotice
    }

    private fun updateNotification(notice: TunnelNotice) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(notice))
    }

    private fun buildNotification(notice: TunnelNotice): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnect = PendingIntent.getService(
            this,
            1,
            Intent(this, PhantomVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val (title, text) = when (notice) {
            TunnelNotice.Connecting ->
                getString(R.string.notif_connecting_title) to ""
            is TunnelNotice.Connected ->
                getString(R.string.notif_connected_title) to notice.virtualIp
        }

        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(openApp)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(
                Notification.Action.Builder(
                    null,
                    getString(R.string.notif_action_disconnect),
                    disconnect,
                ).build()
            )
            .build()
    }

    private fun createNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.channel_tunnel_name),
            // LOW：常驻通知不该发声或震动，它只是个状态显示。
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.channel_tunnel_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    /** 一条路由。Guest 通常只需要 Host 的 /32，Host 需要整个 /24。 */
    data class Route(val address: String, val prefixLength: Int)

    companion object {
        private const val TAG = "PhantomVpn"
        private const val CHANNEL_ID = "tunnel_status"
        private const val NOTIFICATION_ID = 0x9001
        private const val WAKELOCK_TAG = "phantom:tunnel"

        const val ACTION_DISCONNECT = "com.buildin1.phantom_p2p.DISCONNECT"
        const val ACTION_RECONNECT = "com.buildin1.phantom_p2p.RECONNECT"
    }
}
