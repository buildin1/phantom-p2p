package com.buildin1.phantom_p2p

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.buildin1.phantom_p2p.data.NativeQuicStreamBridge
import com.buildin1.phantom_p2p.data.TcpVpnEngine
import com.buildin1.phantom_p2p.data.TunnelStreamBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import com.buildin1.phantom_p2p.data.NativePacketBridge
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicLong

class PhantomVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var activeMode: String = MODE_IDLE
    private var activeEndpoint: String = ""
    private var activeRelayToken: String = ""
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var udpSocket: DatagramSocket? = null
    private var uplinkJob: Job? = null
    private var downlinkJob: Job? = null
    private var tcpEngine: TcpVpnEngine? = null
    private var tcpBridge: TunnelStreamBridge? = null
    @Volatile
    private var remoteAddress: InetSocketAddress? = null
    @Volatile
    private var activeTransport: String = TRANSPORT_TCP
    private val txBytes = AtomicLong(0)
    private val rxBytes = AtomicLong(0)
    @Volatile
    private var startedAtMs: Long = 0L
    @Volatile
    private var lastPersistMs: Long = 0L
    /** ICE 打洞成功的本地 UDP 端口。
     *  VPN socket 必须绑定到此端口，才能复用已开出的 NAT hole。 */
    @Volatile
    private var p2pLocalPort: Int = 0
    /** true = 本设备是 guest，TUN 地址 10.219.0.2；false = host，TUN 地址 10.219.0.1 */
    @Volatile
    private var isGuestRole: Boolean = false
    @Volatile private var overlayLocalIp: String = "10.219.0.1"
    @Volatile private var overlayPeerIp: String = "10.219.0.2"
    @Volatile private var overlaySubnet: String = "10.219.0.0/24"

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand action=${intent?.action ?: "null"} startId=$startId")
        runCatching {
            when (intent?.action) {
                ACTION_STOP -> stopVpn(removeService = true)
                ACTION_CONFIGURE_OVERLAY -> {
                    val local = intent.getStringExtra(EXTRA_OVERLAY_LOCAL).orEmpty()
                    val subnet = intent.getStringExtra(EXTRA_OVERLAY_SUBNET).orEmpty()
                    val peer = intent.getStringExtra(EXTRA_OVERLAY_PEER).orEmpty()
                    val guest = intent.getBooleanExtra(EXTRA_IS_GUEST, false)
                    if (local.isNotBlank() && subnet.isNotBlank() && peer.isNotBlank()) {
                        startForegroundNotification()
                        configureOverlay(local, subnet, peer, guest)
                    }
                }
                ACTION_ATTACH_P2P -> {
                    val isGuest = intent.getBooleanExtra(EXTRA_IS_GUEST, false)
                    val host = intent.getStringExtra(EXTRA_HOST).orEmpty()
                    val port = intent.getIntExtra(EXTRA_PORT, 0)
                    val localPort = intent.getIntExtra(EXTRA_LOCAL_PORT, 0)
                    activeTransport = intent.getStringExtra(EXTRA_TRANSPORT) ?: TRANSPORT_TCP
                    if (host.isNotBlank() && port > 0) {
                        p2pLocalPort = localPort  // 必须在 bindDataPlane 之前设置
                        startForegroundNotification()
                        establishTunForRole(isGuest)  // guest=10.219.0.2, host=10.219.0.1
                        bindDataPlane(mode = MODE_P2P, endpoint = "$host:$port")
                    } else {
                        Log.w(TAG, "忽略无效 P2P 数据面: host=$host port=$port")
                    }
                }
                ACTION_ATTACH_RELAY -> {
                    val isGuest = intent.getBooleanExtra(EXTRA_IS_GUEST, false)
                    val relayAddr = intent.getStringExtra(EXTRA_RELAY_ADDR).orEmpty()
                    activeRelayToken = intent.getStringExtra(EXTRA_RELAY_TOKEN).orEmpty()
                    activeTransport = intent.getStringExtra(EXTRA_TRANSPORT) ?: TRANSPORT_TCP
                    if (relayAddr.isNotBlank()) {
                        startForegroundNotification()
                        establishTunForRole(isGuest)
                        bindDataPlane(mode = MODE_RELAY, endpoint = relayAddr)
                    } else {
                        Log.w(TAG, "忽略无效中继数据面: relayAddr is blank")
                    }
                }
                ACTION_CLEAR_BINDING -> {
                    startForegroundNotification()
                    activeTransport = TRANSPORT_TCP
                    bindDataPlane(mode = MODE_IDLE, endpoint = "")
                }
                else -> startVpn()
            }
        }.onFailure { error ->
            Log.e(TAG, "VPN service command failed: ${error.message}", error)
            bindDataPlane(mode = MODE_IDLE, endpoint = "")
        }
        // START_NOT_STICKY：进程被系统杀掉后不自动重启。
        // 房间状态（ViewModel）同样随进程消失，服务无意义地重启只会造成 VPN 在非房间状态下启动。
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopVpn(removeService = false)
        ioScope.cancel()
        super.onDestroy()
    }

    private fun startVpn() {
        if (vpnInterface != null) {
            persistRunningState(true)
            refreshNotification()
            return
        }

        startForegroundNotification()

        // 手动启动时只建立一个不接管外部流量的占位接口；P2P/中继 attach 会直接建立角色 TUN。
        vpnInterface = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(1500)
            .addAddress("10.219.0.1", 32)
            .addRoute("10.219.0.1", 32)
            .establish()

        persistRunningState(vpnInterface != null)
        if (vpnInterface == null) {
            Log.e(TAG, "VPN 占位 TUN 建立失败")
            stopVpn(removeService = true)
        } else {
            if (startedAtMs <= 0L) {
                startedAtMs = System.currentTimeMillis()
            }
            persistStats(force = true)
            refreshNotification()
        }
    }

    private fun startForegroundNotification() {
        createNotificationChannel()
        val notification = buildNotification()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun stopVpn(removeService: Boolean) {
        stopDataPlaneLoops()
        vpnInterface?.close()
        vpnInterface = null
        persistRunningState(false)
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putBoolean(KEY_OVERLAY_READY, false)
            .apply()
        if (removeService) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
        activeMode = MODE_IDLE
        activeEndpoint = ""
        activeRelayToken = ""
        activeTransport = TRANSPORT_TCP
        remoteAddress = null
        startedAtMs = 0L
        txBytes.set(0)
        rxBytes.set(0)
        persistStats(force = true)
    }

    private fun bindDataPlane(mode: String, endpoint: String) {
        activeMode = mode
        activeEndpoint = endpoint
        remoteAddress = parseEndpoint(endpoint)
        if (mode == MODE_IDLE || remoteAddress == null) {
            stopDataPlaneLoops()
        } else {
            if (startedAtMs <= 0L) {
                startedAtMs = System.currentTimeMillis()
            }
            startDataPlaneLoops()
        }
        persistBindingState(mode, endpoint)
        persistStats(force = true)
        refreshNotification()
    }

    private fun startDataPlaneLoops() {
        val vpn = vpnInterface ?: return
        if (remoteAddress == null) return  // 无有效端点

        if (activeTransport == TRANSPORT_TCP) {
            startPacketDataPlane(vpn)
            return
        }

        if (udpSocket == null) {
            val bindPort = p2pLocalPort
            val socket = runCatching {
                if (bindPort > 0) {
                    DatagramSocket(null).apply {
                        reuseAddress = true
                        bind(java.net.InetSocketAddress(bindPort))
                        soTimeout = 400
                    }
                } else {
                    DatagramSocket().apply {
                        soTimeout = 400
                        reuseAddress = true
                    }
                }
            }.onFailure { error ->
                Log.e(TAG, "UDP 数据面端口绑定失败 localPort=$bindPort: ${error.message}", error)
            }.getOrNull() ?: run {
                p2pLocalPort = 0
                bindDataPlane(mode = MODE_IDLE, endpoint = "")
                return
            }
            p2pLocalPort = 0  // 重置，下次重新设置
            protect(socket)
            udpSocket = socket
        }

        val socket = udpSocket ?: return

        if (uplinkJob?.isActive != true) {
            val tunIn = FileInputStream(vpn.fileDescriptor)
            uplinkJob = ioScope.launch {
                // 在 IO 线程解析域名（parseEndpoint 用 createUnresolved 跳过主线程 DNS）
                val resolvedRemote: InetSocketAddress = run {
                    val r = remoteAddress ?: return@run null
                    if (!r.isUnresolved) r
                    else try {
                        InetSocketAddress(InetAddress.getByName(r.hostName), r.port)
                            .also { remoteAddress = it }  // 缓存已解析地址
                    } catch (_: Exception) { null }
                } ?: run { runCatching { tunIn.close() }; return@launch }

                val buffer = ByteArray(TUN_BUFFER_SIZE)
                try {
                    while (isActive) {
                        val read = tunIn.read(buffer)
                        if (read <= 0) continue
                        val frame = buildUdpFrame(buffer, read)
                        socket.send(DatagramPacket(frame, frame.size, resolvedRemote))
                        txBytes.addAndGet(read.toLong())
                        maybePersistStats()
                    }
                } catch (_: Exception) {
                    // service stop / interface close
                } finally {
                    runCatching { tunIn.close() }
                }
            }
        }

        if (downlinkJob?.isActive != true) {
            val tunOut = FileOutputStream(vpn.fileDescriptor)
            downlinkJob = ioScope.launch {
                val buffer = ByteArray(TUN_BUFFER_SIZE)
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    while (isActive) {
                        try {
                            socket.receive(packet)
                            val payload = parseUdpFrame(packet.data, packet.offset, packet.length)
                            if (payload != null) {
                                tunOut.write(payload)
                                tunOut.flush()
                                rxBytes.addAndGet(payload.size.toLong())
                                maybePersistStats()
                            }
                        } catch (_: SocketTimeoutException) {
                            maybePersistStats()
                        }
                    }
                } catch (_: Exception) {
                    // service stop / interface close
                } finally {
                    runCatching { tunOut.close() }
                }
            }
        }
    }

    private fun stopDataPlaneLoops() {
        uplinkJob?.cancel()
        uplinkJob = null
        downlinkJob?.cancel()
        downlinkJob = null
        tcpEngine?.close()
        tcpEngine = null
        (tcpBridge as? NativeQuicStreamBridge)?.close()
        tcpBridge = null
        runCatching { udpSocket?.close() }
        udpSocket = null
    }

    private fun startTcpDataPlane(vpn: ParcelFileDescriptor) {
        if (uplinkJob?.isActive == true) return

        uplinkJob = ioScope.launch {
            var tunIn: FileInputStream? = null
            var tunOut: FileOutputStream? = null
            var engine: TcpVpnEngine? = null
            try {
                Log.i(TAG, "启动 TCP 数据面 mode=$activeMode endpoint=$activeEndpoint localPort=$p2pLocalPort isGuest=$isGuestRole")
                tunIn = FileInputStream(vpn.fileDescriptor)
                tunOut = FileOutputStream(vpn.fileDescriptor)
                val bridge = NativeQuicStreamBridge.createOrPending(
                    service = this@PhantomVpnService,
                    mode = activeMode,
                    endpoint = activeEndpoint,
                    relayToken = activeRelayToken,
                    localPort = p2pLocalPort,
                    isGuest = isGuestRole,
                    onLog = { Log.w(TAG, it) }
                )
                p2pLocalPort = 0
                tcpBridge = bridge
                engine = TcpVpnEngine.forTun(
                    tunOut = tunOut,
                    bridge = bridge,
                    onBytesTx = { txBytes.addAndGet(it.toLong()); maybePersistStats() },
                    onBytesRx = { rxBytes.addAndGet(it.toLong()); maybePersistStats() },
                    onLog = { Log.w(TAG, it) }
                )
                tcpEngine = engine
                Log.i(TAG, "TCP 数据面已启动")
                val buffer = ByteArray(TUN_BUFFER_SIZE)
                while (isActive) {
                    val read = tunIn.read(buffer)
                    if (read <= 0) continue
                    if (!engine.handlePacket(buffer, read)) {
                        Log.d(TAG, "忽略非 TCP/IPv4 TUN 包 length=$read")
                    }
                }
            } catch (error: Exception) {
                if (isActive) {
                    Log.e(TAG, "TCP 数据面异常停止: ${error.message}", error)
                    recordDataPlaneFailure("TCP 数据面异常: ${error.message}")
                }
            } finally {
                runCatching { tunIn?.close() }
                runCatching { tunOut?.close() }
                engine?.close()
            }
        }
    }

    private fun startPacketDataPlane(vpn: ParcelFileDescriptor) {
        if (uplinkJob?.isActive == true) return
        uplinkJob = ioScope.launch {
            var tunIn: java.io.FileInputStream? = null
            var tunOut: FileOutputStream? = null
            var bridge: NativePacketBridge? = null
            try {
                tunIn = java.io.FileInputStream(vpn.fileDescriptor)
                tunOut = FileOutputStream(vpn.fileDescriptor)
                bridge = NativePacketBridge.create(
                    this@PhantomVpnService,
                    activeMode,
                    activeEndpoint,
                    activeRelayToken,
                    p2pLocalPort,
                    isGuestRole,
                    onPacket = { packet ->
                        runCatching {
                            synchronized(this@PhantomVpnService) {
                                tunOut?.write(packet)
                                tunOut?.flush()
                            }
                            rxBytes.addAndGet(packet.size.toLong())
                        }.onFailure { Log.w(TAG, "写回 VPN TUN 失败: ${it.message}") }
                    },
                    onLog = { Log.w(TAG, it) }
                ) ?: error("native packet bridge unavailable")
                p2pLocalPort = 0
                val buffer = ByteArray(TUN_BUFFER_SIZE)
                while (isActive) {
                    val read = tunIn.read(buffer)
                    if (read < 20) continue
                    bridge.writePacket(buffer.copyOf(read))
                    txBytes.addAndGet(read.toLong())
                }
            } catch (error: Exception) {
                if (isActive) {
                    Log.e(TAG, "IPv4 packet data plane stopped: ${error.message}", error)
                    recordDataPlaneFailure("relay/P2P 数据面异常: ${error.message}")
                }
            } finally {
                bridge?.close()
                runCatching { tunIn?.close() }
                runCatching { tunOut?.close() }
            }
        }
    }

    /**
     * 根据角色建立 VPN TUN 接口。
     *   Guest: tun=10.219.0.2/32, route=10.219.0.1/32  （游戏流量 → host）
     *   Host : tun=10.219.0.1/32, route=10.219.0.2/32  （回程流量 → guest）
     * 调用前确保 startForegroundNotification() 已完成前台服务注册。
     * 旧的 I/O 协程和 UDP socket 均关闭，bindDataPlane() 会重新创建。
     */
    private fun establishTunForRole(isGuest: Boolean) {
        isGuestRole = isGuest
        val localIp = overlayLocalIp
        val peerIp = overlayPeerIp

        stopDataPlaneLoops()       // 停止 I/O 协程并关闭旧 socket
        vpnInterface?.close()      // 关闭旧 TUN fd
        vpnInterface = null

        vpnInterface = runCatching {
            Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(1500)
                .addAddress(localIp, 32)
                .addRoute(
                    if (isGuest) peerIp else overlaySubnet.substringBefore('/').substringBeforeLast('.') + ".0",
                    if (isGuest) 32 else 24
                )
                .establish()
        }.onFailure { error ->
            Log.e(TAG, "VPN TUN 建立失败 local=$localIp peer=$peerIp: ${error.message}", error)
        }.getOrNull()

        if (vpnInterface == null) {
            stopVpn(removeService = true)
        } else {
            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
                .putBoolean(KEY_OVERLAY_READY, true)
                .apply()
            Log.i(TAG, "VPN TUN 已建立 local=$localIp peer=$peerIp")
            persistRunningState(true)
            refreshNotification()
        }
    }

    private fun configureOverlay(localIp: String, subnet: String, peerIp: String, isGuest: Boolean) {
        overlayLocalIp = localIp
        overlayPeerIp = peerIp
        val prefix = subnet.substringBefore('/').substringBeforeLast('.')
        overlaySubnet = "$prefix.0/24"
        establishTunForRole(isGuest)
    }

    private fun parseEndpoint(endpoint: String): InetSocketAddress? {
        val trimmed = endpoint.trim()
        if (trimmed.isEmpty()) return null
        val idx = trimmed.lastIndexOf(':')
        if (idx <= 0 || idx >= trimmed.length - 1) return null
        val host = trimmed.substring(0, idx).trim().removePrefix("[").removeSuffix("]")
        val port = trimmed.substring(idx + 1).toIntOrNull() ?: return null
        if (host.isBlank() || port !in 1..65535) return null
        // createUnresolved 避免在 onStartCommand（主线程）做 DNS 查询导致闪退
        // 实际解析在 IO 协程的 startDataPlaneLoops 内进行
        return InetSocketAddress.createUnresolved(host, port)
    }

    private fun buildUdpFrame(packet: ByteArray, length: Int): ByteArray {
        val frame = ByteArray(6 + length)
        frame[0] = 'P'.code.toByte()
        frame[1] = 'P'.code.toByte()
        frame[2] = '6'.code.toByte()
        frame[3] = 'U'.code.toByte()
        frame[4] = ((length ushr 8) and 0xFF).toByte()
        frame[5] = (length and 0xFF).toByte()
        packet.copyInto(frame, 6, 0, length)
        return frame
    }

    private fun parseUdpFrame(data: ByteArray, offset: Int, length: Int): ByteArray? {
        if (length < 6) return null
        if (data[offset] != 'P'.code.toByte() || data[offset + 1] != 'P'.code.toByte() || data[offset + 2] != '6'.code.toByte() || data[offset + 3] != 'U'.code.toByte()) return null
        val payloadLength = ((data[offset + 4].toInt() and 0xFF) shl 8) or (data[offset + 5].toInt() and 0xFF)
        if (payloadLength < 0 || payloadLength > length - 6) return null
        return data.copyOfRange(offset + 6, offset + 6 + payloadLength)
    }

    private fun maybePersistStats() {
        val now = System.currentTimeMillis()
        if (now - lastPersistMs >= STATS_PERSIST_INTERVAL_MS) {
            persistStats(force = false)
        }
    }

    private fun persistStats(force: Boolean) {
        val now = System.currentTimeMillis()
        if (!force && now - lastPersistMs < STATS_PERSIST_INTERVAL_MS) return
        lastPersistMs = now

        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putLong(KEY_TX_BYTES, txBytes.get())
            .putLong(KEY_RX_BYTES, rxBytes.get())
            .putLong(KEY_STARTED_AT_MS, startedAtMs)
            .apply()
    }

    private fun buildNotification() = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
        .setSmallIcon(R.drawable.ic_nav_connect)
        .setContentTitle(getString(R.string.vpn_notification_title))
        .setContentText(notificationText())
        .setContentIntent(mainActivityPendingIntent())
        .setOngoing(true)
        .setSilent(true)
        .build()

    private fun refreshNotification() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification())
    }

    private fun notificationText(): String {
        if (activeMode == MODE_P2P && activeEndpoint.isNotBlank()) {
            return "P2P 数据面: $activeEndpoint"
        }
        if (activeMode == MODE_RELAY && activeEndpoint.isNotBlank()) {
            return "中继数据面: $activeEndpoint"
        }
        return getString(R.string.vpn_notification_text)
    }

    private fun mainActivityPendingIntent(): PendingIntent {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntentFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        return PendingIntent.getActivity(this, 0, intent, pendingIntentFlags)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        val existing = manager.getNotificationChannel(NOTIFICATION_CHANNEL_ID)
        if (existing != null) return

        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.vpn_notification_channel),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.vpn_notification_channel_desc)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun persistRunningState(isRunning: Boolean) {
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_VPN_RUNNING, isRunning)
            .apply()
    }

    private fun persistBindingState(mode: String, endpoint: String) {
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_DATA_MODE, mode)
            .putString(KEY_DATA_ENDPOINT, endpoint)
            .apply()
    }

    /**
     * 数据面（P2P/中继）异常终止时的统一复位入口：
     * 1) 记录失败时间戳 + 原因到 SharedPreferences，供 AppViewModel 轮询感知并结束"连接中"loading。
     * 2) 复位 bindDataPlane 到 MODE_IDLE，避免服务停留在半死不活的状态。
     * 修复 relay 卡死问题的核心：此前 startPacketDataPlane 的 catch 块只打日志、不复位，
     * 导致 UI 侧 isJoining 永久为 true。
     */
    private fun recordDataPlaneFailure(reason: String) {
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putLong(KEY_DATA_PLANE_FAILURE_EPOCH, System.currentTimeMillis())
            .putString(KEY_DATA_PLANE_FAILURE_REASON, reason)
            .apply()
        bindDataPlane(mode = MODE_IDLE, endpoint = "")
    }

    companion object {
        private const val ACTION_START = "com.buildin1.phantom_p2p.action.START_VPN"
        private const val ACTION_STOP = "com.buildin1.phantom_p2p.action.STOP_VPN"
        private const val ACTION_ATTACH_P2P = "com.buildin1.phantom_p2p.action.ATTACH_P2P"
        private const val ACTION_ATTACH_RELAY = "com.buildin1.phantom_p2p.action.ATTACH_RELAY"
        private const val ACTION_CONFIGURE_OVERLAY = "com.buildin1.phantom_p2p.action.CONFIGURE_OVERLAY"
        private const val ACTION_CLEAR_BINDING = "com.buildin1.phantom_p2p.action.CLEAR_BINDING"
        private const val PREFS_NAME = "phantom_runtime"
        private const val KEY_VPN_RUNNING = "vpn_running"
        private const val KEY_OVERLAY_READY = "overlay_ready"
        private const val KEY_DATA_MODE = "vpn_data_mode"
        private const val KEY_DATA_ENDPOINT = "vpn_data_endpoint"
        private const val KEY_TX_BYTES = "vpn_tx_bytes"
        private const val KEY_RX_BYTES = "vpn_rx_bytes"
        private const val KEY_STARTED_AT_MS = "vpn_started_at_ms"
        private const val KEY_DATA_PLANE_FAILURE_EPOCH = "vpn_data_plane_failure_epoch"
        private const val KEY_DATA_PLANE_FAILURE_REASON = "vpn_data_plane_failure_reason"
        private const val EXTRA_HOST = "extra_host"
        private const val EXTRA_PORT = "extra_port"
        private const val EXTRA_LOCAL_PORT = "extra_local_port"  // ICE 打洞端口
        private const val EXTRA_RELAY_ADDR = "extra_relay_addr"
        private const val EXTRA_RELAY_TOKEN = "extra_relay_token"
        private const val EXTRA_IS_GUEST = "extra_is_guest"      // true=guest(10.219.0.2) false=host(10.219.0.1)
        private const val EXTRA_TRANSPORT = "extra_transport"
        private const val EXTRA_OVERLAY_LOCAL = "extra_overlay_local"
        private const val EXTRA_OVERLAY_SUBNET = "extra_overlay_subnet"
        private const val EXTRA_OVERLAY_PEER = "extra_overlay_peer"
        private const val NOTIFICATION_CHANNEL_ID = "phantom_vpn"
        private const val NOTIFICATION_ID = 2201
        private const val TUN_BUFFER_SIZE = 64 * 1024
        private const val STATS_PERSIST_INTERVAL_MS = 1000L
        private const val MODE_IDLE = "idle"
        private const val MODE_P2P = "p2p"
        private const val MODE_RELAY = "relay"
        private const val TAG = "PhantomVpnService"
        const val TRANSPORT_TCP = "tcp"
        const val TRANSPORT_UDP = "udp"

        data class RuntimeStats(
            val txBytes: Long,
            val rxBytes: Long,
            val startedAtMs: Long,
            val mode: String,
            val endpoint: String
        )

        fun start(context: Context) {
            val intent = Intent(context, PhantomVpnService::class.java).apply {
                action = ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, PhantomVpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }

        fun attachP2P(context: Context, host: String, port: Int, localPort: Int = 0, isGuest: Boolean = false, transport: String = TRANSPORT_TCP) {
            val intent = Intent(context, PhantomVpnService::class.java).apply {
                action = ACTION_ATTACH_P2P
                putExtra(EXTRA_HOST, host)
                putExtra(EXTRA_PORT, port)
                if (localPort > 0) putExtra(EXTRA_LOCAL_PORT, localPort)
                putExtra(EXTRA_IS_GUEST, isGuest)
                putExtra(EXTRA_TRANSPORT, transport.lowercase())
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun configureOverlay(context: Context, localIp: String, subnet: String, peerIp: String, isGuest: Boolean) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(KEY_OVERLAY_READY, false)
                .apply()
            val intent = Intent(context, PhantomVpnService::class.java).apply {
                action = ACTION_CONFIGURE_OVERLAY
                putExtra(EXTRA_OVERLAY_LOCAL, localIp)
                putExtra(EXTRA_OVERLAY_SUBNET, subnet)
                putExtra(EXTRA_OVERLAY_PEER, peerIp)
                putExtra(EXTRA_IS_GUEST, isGuest)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent)
            else context.startService(intent)
        }

        fun attachRelay(context: Context, relayAddr: String, relayToken: String = "", isGuest: Boolean = false, transport: String = TRANSPORT_TCP) {
            val intent = Intent(context, PhantomVpnService::class.java).apply {
                action = ACTION_ATTACH_RELAY
                putExtra(EXTRA_RELAY_ADDR, relayAddr)
                putExtra(EXTRA_RELAY_TOKEN, relayToken)
                putExtra(EXTRA_IS_GUEST, isGuest)
                putExtra(EXTRA_TRANSPORT, transport.lowercase())
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun clearBinding(context: Context) {
            val intent = Intent(context, PhantomVpnService::class.java).apply {
                action = ACTION_CLEAR_BINDING
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun isRunning(context: Context): Boolean {
            return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(KEY_VPN_RUNNING, false)
        }

        fun isOverlayReady(context: Context): Boolean = context
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_OVERLAY_READY, false)

        /**
         * 读取最近一次数据面异常复位的时间戳（ms，0 表示从未发生）与原因。
         * AppViewModel 在下发 P2P/中继数据面后据此轮询，一旦时间戳晚于下发时刻，
         * 说明数据面已异常复位，需要结束"连接中"loading 并提示用户，而不是无限挂起。
         */
        fun readDataPlaneFailure(context: Context): Pair<Long, String> {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getLong(KEY_DATA_PLANE_FAILURE_EPOCH, 0L) to
                prefs.getString(KEY_DATA_PLANE_FAILURE_REASON, "").orEmpty()
        }

        fun readRuntimeStats(context: Context): RuntimeStats {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return RuntimeStats(
                txBytes = prefs.getLong(KEY_TX_BYTES, 0L),
                rxBytes = prefs.getLong(KEY_RX_BYTES, 0L),
                startedAtMs = prefs.getLong(KEY_STARTED_AT_MS, 0L),
                mode = prefs.getString(KEY_DATA_MODE, MODE_IDLE).orEmpty(),
                endpoint = prefs.getString(KEY_DATA_ENDPOINT, "").orEmpty()
            )
        }
    }
}
