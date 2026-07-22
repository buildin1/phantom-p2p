package com.buildin1.phantom_p2p

import android.app.Application
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.buildin1.phantom_p2p.signal.AdvancedPortMapping
import com.buildin1.phantom_p2p.signal.IceEngine
import com.buildin1.phantom_p2p.signal.IdentityManager
import com.buildin1.phantom_p2p.signal.RoomTransport
import com.buildin1.phantom_p2p.signal.ServerMessage
import com.buildin1.phantom_p2p.signal.SignalManager
import com.buildin1.phantom_p2p.signal.StunClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.net.InetSocketAddress

// ──────────────────────────────────────────────
// Data models
// ──────────────────────────────────────────────

data class LogEntry(val time: String, val level: String, val module: String, val text: String)

enum class ConnectionState { DISCONNECTED, CONNECTING, CONNECTED, AUTHENTICATED }

enum class PortStatus { PENDING, READY }

data class StunMapping(val server: String, val mapping: String, val rttMs: Long)

data class AppSettings(
    val signal: String = USER_MODE_LOCKED_SIGNAL,
    val gamePort: Int = 25565,
    val guestPort: Int = 25642,
    val preferUdp: Boolean = false,
    val relayFallback: Boolean = true,
    val forceRelay: Boolean = false,
    val autoRelay: Boolean = true,
    val autoConnect: Boolean = true,
    val preferIpv6: Boolean = false,
    val verbose: Boolean = false
)

data class AppState(
    // Connection
    val connectionState: ConnectionState = ConnectionState.DISCONNECTED,
    val sessionId: String? = null,
    val userId: String? = null,
    // Room
    val roomCode: String? = null,
    val isHost: Boolean = false,
    val hostActive: Boolean = false,
    val guestActive: Boolean = false,
    val isJoining: Boolean = false,  // 正在加入房间（单击连接到 guestActive/失败之间）
    val roomTransport: RoomTransport = RoomTransport.UDP,
    // Advanced / multi-port
    val isAdvancedMode: Boolean = false,
    val useMultiPort: Boolean = false,
    val advancedPorts: List<Int> = emptyList(),
    val advancedMainPort: Int = 0,
    val portTunnelStatus: Map<Int, PortStatus> = emptyMap(),
    // Guest connection
    val peerSessionId: String? = null,
    val hostGamePort: Int = 0,
    val guestLocalPort: Int = 0,
    val guestAddr: String = "127.0.0.1:----",
    val connectionMode: String = "---",
    val latencyMs: Int = 0,
    val uploadBps: Long = 0,
    val downloadBps: Long = 0,
    val uptimeSeconds: Long = 0,
    // NAT / Diag
    val natType: String = "--",
    val mappingBehavior: String = "--",
    val filteringBehavior: String = "--",
    val portPattern: String = "--",
    val confidence: String = "--",
    val publicAddress: String = "--",
    val upnpStatus: String = "--",
    val ipv6Status: String = "--",
    val networkPriority: String = "--",
    val stunMappings: List<StunMapping> = emptyList(),
    val diagBusy: Boolean = false,
    val diagProgress: Int = 0,
    val diagProgressMsg: String = ""
)

const val USER_MODE_LOCKED_SIGNAL = "ws://qx.coreyuan.cn:10112/ws"

class AppViewModel(application: Application) : AndroidViewModel(application), SignalManager.SignalListener {

    val identity = IdentityManager(application)
    private val prefs = application.getSharedPreferences("phantom_settings", android.content.Context.MODE_PRIVATE)
    private val logStore = LogStore(application)

    private val _state = MutableLiveData(AppState())
    val state: LiveData<AppState> = _state

    private val _logs = MutableLiveData<List<LogEntry>>(emptyList())
    val logs: LiveData<List<LogEntry>> = _logs

    private val _settings = MutableLiveData(loadSettingsFromPrefs())
    val settings: LiveData<AppSettings> = _settings

    private var signalManager: SignalManager? = null
    private val iceEngine = IceEngine()
    private var iceSession: IceEngine.LocalIceSession? = null
    private var advancedMappings: List<AdvancedPortMapping> = emptyList()
    private var relayPreAllocated: ServerMessage.RelayPreAllocated? = null
    private var relayFallbackJob: Job? = null
    private var statsJob: Job? = null
    private var lastStatsTxBytes: Long = 0L
    private var lastStatsRxBytes: Long = 0L
    private var pendingAction: PendingAction? = null

    // VPN 权限申请：仅在创建/加入房间时触发，避免启动时骚扰用户
    private val _vpnPermissionNeeded = MutableLiveData<Intent?>()
    val vpnPermissionNeeded: LiveData<Intent?> = _vpnPermissionNeeded
    private var pendingVpnAction: (() -> Unit)? = null

    // 导航指令：当作为 Guest 成功建立连接后，通知 Activity 跳转指定 tab (R.id.*)
    private val _navigateToTab = MutableLiveData<Int?>()
    val navigateToTab: LiveData<Int?> = _navigateToTab

    fun clearNavigateToTab() { _navigateToTab.value = null }

    private sealed class PendingAction {
        data class CreateRoom(val gamePort: Int, val transport: RoomTransport) : PendingAction()
        data class CreateAdvancedRoom(val ports: List<Int>, val mainPort: Int, val transport: RoomTransport) : PendingAction()
        data class JoinRoom(val roomCode: String) : PendingAction()
    }

    var portTablePage: Int = 0

    // ── Settings ──

    private fun loadSettingsFromPrefs() = AppSettings(
        signal = prefs.getString("signal", USER_MODE_LOCKED_SIGNAL) ?: USER_MODE_LOCKED_SIGNAL,
        gamePort = prefs.getInt("game_port", 25565),
        guestPort = prefs.getInt("guest_port", 25642),
        preferUdp = prefs.getBoolean("prefer_udp", false),
        relayFallback = prefs.getBoolean("relay_fallback", true),
        forceRelay = prefs.getBoolean("force_relay", false),
        autoRelay = prefs.getBoolean("auto_relay", true),
        autoConnect = prefs.getBoolean("auto_connect", true),
        preferIpv6 = prefs.getBoolean("prefer_ipv6", false),
        verbose = prefs.getBoolean("verbose", false)
    )

    fun saveSettings(s: AppSettings) {
        prefs.edit()
            .putString("signal", s.signal)
            .putInt("game_port", s.gamePort)
            .putInt("guest_port", s.guestPort)
            .putBoolean("prefer_udp", s.preferUdp)
            .putBoolean("relay_fallback", s.relayFallback)
            .putBoolean("force_relay", s.forceRelay)
            .putBoolean("auto_relay", s.autoRelay)
            .putBoolean("auto_connect", s.autoConnect)
            .putBoolean("prefer_ipv6", s.preferIpv6)
            .putBoolean("verbose", s.verbose)
            .apply()
        _settings.postValue(s)
        addLog("设置已保存", "INFO", "system")
    }

    fun resetSettings() {
        saveSettings(AppSettings())
        addLog("设置已恢复默认", "WARN", "system")
    }

    // ── Connection ──

    fun ensureConnected() {
        val s = _state.value ?: return
        if (s.connectionState == ConnectionState.DISCONNECTED) connectSignal()
    }

    fun connectSignal() {
        val url = _settings.value?.signal ?: USER_MODE_LOCKED_SIGNAL
        if (signalManager == null) signalManager = SignalManager(identity, this)
        updateState { it.copy(connectionState = ConnectionState.CONNECTING) }
        signalManager!!.connect(url)
        addLog("正在连接 $url", "INFO", "system")
    }

    fun disconnectSignal() {
        signalManager?.disconnect()
        signalManager = null
        pendingAction = null
        cancelRelayFallback()
        stopStatsSampling(reset = true)
        relayPreAllocated = null
        advancedMappings = emptyList()
        clearIceSession()
        updateState {
            it.copy(
                connectionState = ConnectionState.DISCONNECTED,
                sessionId = null, roomCode = null,
                hostActive = false, guestActive = false,
                isAdvancedMode = false, advancedPorts = emptyList(),
                portTunnelStatus = emptyMap(),
                uploadBps = 0,
                downloadBps = 0,
                uptimeSeconds = 0
            )
        }
    }

    // ── Room ──

    fun createRoom(gamePort: Int = -1, transport: RoomTransport? = null) {
        val port = if (gamePort > 0) gamePort else (_settings.value?.gamePort ?: 25565)
        val tx = transport ?: defaultRoomTransport()
        checkVpnThenRun {
            if (!isSignalAuthenticated()) {
                pendingAction = PendingAction.CreateRoom(port, tx)
                ensureConnected()
                addLog("等待鉴权完成后创建房间（端口 $port, $tx）", "INFO", "host")
                return@checkVpnThenRun
            }
            signalManager?.createRoom(port, tx)
            addLog("正在创建房间（端口 $port, $tx）", "INFO", "host")
        }
    }

    private fun defaultRoomTransport(): RoomTransport {
        if (BuildConfig.FLAVOR != "dev") return RoomTransport.TCP
        return if (_settings.value?.preferUdp == true) RoomTransport.UDP else RoomTransport.TCP
    }

    fun createAdvancedRoom(ports: List<Int>, mainPort: Int, transport: RoomTransport) {
        checkVpnThenRun {
            if (!isSignalAuthenticated()) {
                pendingAction = PendingAction.CreateAdvancedRoom(ports, mainPort, transport)
                ensureConnected()
                addLog("等待鉴权完成后创建高级房间（主端口 $mainPort）", "INFO", "host")
                return@checkVpnThenRun
            }
            signalManager?.createAdvancedRoom(ports, mainPort, transport)
            addLog("正在创建高级房间（主端口 $mainPort, 共 ${ports.size} 个端口）", "INFO", "host")
        }
    }

    fun joinRoom(roomCode: String) {
        val code = roomCode.trim().uppercase()
        updateState { it.copy(isJoining = true) }
        checkVpnThenRun {
            if (!isSignalAuthenticated()) {
                pendingAction = PendingAction.JoinRoom(code)
                ensureConnected()
                addLog("等待鉴权完成后加入房间 $code", "INFO", "guest")
                return@checkVpnThenRun
            }
            if (code.endsWith("-A")) {
                signalManager?.joinAdvancedRoom(code)
                updateState { it.copy(isAdvancedMode = true) }
            } else {
                signalManager?.joinRoom(code)
            }
            addLog("正在加入房间 $code", "INFO", "guest")
        }
    }

    /**
     * VPN 权限检查 + 启动保活服务，然后执行房间操作。
     * - 已授权：直接启动服务并执行 action
     * - 未授权：保存 action，向 Activity 发送 VPN 授权 Intent
     */
    private fun checkVpnThenRun(action: () -> Unit) {
        val app = getApplication<Application>()
        val vpnIntent = VpnService.prepare(app)
        if (vpnIntent == null) {
            // 权限已授予，直接执行操作。
            // VPN 服务将在 P2P/中继就绪时才启动（maybeAttachVpnP2P / maybeAttachVpnRelay），
            // 避免 ICE/STUN 阶段 TUN 接口干扰 UDP 路由。
            action()
        } else {
            pendingVpnAction = action
            _vpnPermissionNeeded.postValue(vpnIntent)
        }
    }

    /** Activity 收到 VPN 授权结果后调用（RESULT_OK） */
    fun onVpnGranted() {
        pendingVpnAction?.invoke()
        pendingVpnAction = null
        _vpnPermissionNeeded.postValue(null)
    }

    /** Activity 收到 VPN 授权拒绝后调用 —— 不保活但仍允许操作（用户自担风险） */
    fun onVpnDenied() {
        pendingVpnAction?.invoke()
        pendingVpnAction = null
        _vpnPermissionNeeded.postValue(null)
    }

    fun closeRoom() {
        signalManager?.closeRoom()
        cancelRelayFallback()
        stopStatsSampling(reset = true)
        relayPreAllocated = null
        advancedMappings = emptyList()
        updateState {
            it.copy(
                roomCode = null, isHost = false, hostActive = false,
                isAdvancedMode = false, advancedPorts = emptyList(),
                advancedMainPort = 0, portTunnelStatus = emptyMap(),
                guestAddr = "127.0.0.1:----", connectionMode = "---",
                latencyMs = 0, guestLocalPort = 0, hostGamePort = 0,
                uploadBps = 0, downloadBps = 0, uptimeSeconds = 0
            )
        }
        stopVpnService()
        clearIceSession()
        addLog("已关闭房间", "WARN", "host")
    }

    fun leaveRoom() {
        signalManager?.leaveRoom()
        cancelRelayFallback()
        stopStatsSampling(reset = true)
        relayPreAllocated = null
        advancedMappings = emptyList()
        updateState {
            it.copy(
                roomCode = null, isHost = false, guestActive = false,
                isAdvancedMode = false, advancedPorts = emptyList(),
                portTunnelStatus = emptyMap(), guestAddr = "127.0.0.1:----",
                connectionMode = "---", latencyMs = 0, guestLocalPort = 0, hostGamePort = 0,
                uploadBps = 0, downloadBps = 0, uptimeSeconds = 0
            )
        }
        stopVpnService()
        clearIceSession()
        addLog("已离开房间", "WARN", "guest")
    }

    // ── Advanced mode ──

    fun setMultiPort(enabled: Boolean) {
        updateState { it.copy(useMultiPort = enabled) }
        if (!enabled) updateState { it.copy(advancedPorts = emptyList(), advancedMainPort = 0) }
    }

    fun parseAndSetPorts(spec: String): Int {
        val ports = parsePortSpec(spec)
        if (ports.isNotEmpty()) updateState { it.copy(advancedPorts = ports, advancedMainPort = ports[0]) }
        return ports.size
    }

    fun updatePortStatus(port: Int, status: PortStatus) {
        val map = (_state.value?.portTunnelStatus ?: emptyMap()).toMutableMap()
        map[port] = status
        updateState { it.copy(portTunnelStatus = map.toMap()) }
    }

    // ── NAT Diagnosis ──

    fun runDiagnosis() {
        if (_state.value?.diagBusy == true) return
        updateState { it.copy(diagBusy = true, diagProgress = 5, diagProgressMsg = "初始化…") }
        addLog("开始网络诊断…", "INFO", "system")
        viewModelScope.launch(Dispatchers.IO) {
            try {
                updateState { it.copy(diagProgress = 20, diagProgressMsg = "探测 STUN 服务器…") }
                val result = StunClient { msg -> addLog(msg, "WARN", "stun") }.detectNat()
                updateState {
                    it.copy(
                        diagProgress = 100, diagProgressMsg = "诊断完成", diagBusy = false,
                        natType = result.natType,
                        mappingBehavior = result.mappingBehavior,
                        filteringBehavior = result.filteringBehavior,
                        portPattern = result.portPattern,
                        confidence = result.confidence,
                        publicAddress = if (result.externalIp.isEmpty()) "--" else "${result.externalIp}:${result.externalPort}",
                        upnpStatus = "不可用", ipv6Status = "不可用",
                        networkPriority = result.networkPriority,
                        stunMappings = result.probes.mapIndexed { i, p ->
                            StunMapping("STUN-${i + 1} ${p.server}", "${p.externalIp}:${p.externalPort}", p.rttMs)
                        }
                    )
                }
                addLog("诊断完成: ${result.natType}", "INFO", "system")
            } catch (e: Exception) {
                updateState { it.copy(diagBusy = false, diagProgress = 0, diagProgressMsg = "检测失败", natType = "检测失败") }
                addLog("诊断失败: ${e.message}", "ERROR", "system")
            }
        }
    }

    // ── SignalListener ──

    override fun onConnected(sessionId: String) {
        updateState { it.copy(connectionState = ConnectionState.CONNECTED, sessionId = sessionId) }
    }

    override fun onAuthenticated(userId: String) {
        updateState { it.copy(connectionState = ConnectionState.AUTHENTICATED, userId = userId) }
        addLog("认证成功", "INFO", "system")
        runPendingActionIfAny()
    }

    override fun onAuthFailed(reason: String) {
        updateState { it.copy(connectionState = ConnectionState.DISCONNECTED) }
        pendingAction = null
        addLog("认证失败: $reason", "ERROR", "system")
    }

    override fun onRoomCreated(roomCode: String, transport: RoomTransport) {
        updateState { it.copy(roomCode = roomCode, isHost = true, hostActive = true, guestActive = false, roomTransport = transport) }
        addLog("房间已创建: $roomCode", "INFO", "host")
    }

    override fun onJoinOk(roomCode: String, guestLocalPort: Int, hostGamePort: Int, transport: RoomTransport) {
        advancedMappings = emptyList()
        updateState {
            it.copy(
                roomCode = roomCode, isHost = false, roomTransport = transport,
                hostGamePort = hostGamePort,
                guestLocalPort = guestLocalPort, guestAddr = "10.219.0.1:$hostGamePort",
                connectionMode = "连接中"  // isJoining 保持 true，等到 P2P/中继真正建立时才清除
            )
        }
        addLog("加入成功, 本地端口 $guestLocalPort", "INFO", "guest")
        startIceNegotiation(reuseExisting = false)
    }

    override fun onJoinFailed(reason: String) {
        updateState { it.copy(guestActive = false, isJoining = false, connectionMode = "---") }
        addLog("加入失败: $reason", "ERROR", "guest")
    }

    override fun onPeerJoined(peerSessionId: String, guestCount: Int) {
        updateState { it.copy(peerSessionId = peerSessionId) }
        addLog("玩家加入 (共 $guestCount 人)", "INFO", "host")
        if (_state.value?.isAdvancedMode == true) {
            val ports = _state.value?.advancedPorts.orEmpty().ifEmpty {
                listOfNotNull(_state.value?.advancedMainPort?.takeIf { it > 0 })
            }
            ports.forEach { updatePortStatus(it, PortStatus.PENDING) }
        }
        startIceNegotiation(reuseExisting = true)
    }

    override fun onPeerLeft(peerSessionId: String, guestCount: Int) {
        addLog("玩家离开 (剩 $guestCount 人)", "WARN", "host")
    }

    override fun onRoomClosed(reason: String) {
        cancelRelayFallback()
        stopStatsSampling(reset = true)
        relayPreAllocated = null
        advancedMappings = emptyList()
        updateState { it.copy(roomCode = null, isHost = false, hostActive = false, guestActive = false, connectionMode = "---") }
        stopVpnService()
        clearIceSession()
        addLog("房间已关闭", "WARN", "system")
    }

    override fun onPeerCandidates(msg: ServerMessage.PeerCandidates) {
        cancelRelayFallback()
        val h = msg.candidates.count { it.ctype == "host" }
        val s = msg.candidates.count { it.ctype == "server_reflexive" }
        addLog("ICE候选: host=$h srflx=$s", "INFO", "system")
        updateState { it.copy(peerSessionId = msg.peerSessionId, connectionMode = "ICE 打洞中") }

        viewModelScope.launch(Dispatchers.IO) {
            val session = ensureIceSession(reuseExisting = true)
            if (session == null) {
                addLog("ICE 启动失败：本地候选未准备好", "ERROR", "ice")
                return@launch
            }

            val result = iceEngine.runConnectivityChecks(session.socket, msg.candidates, msg.startAtMs)
            if (result.success) {
                updateState {
                    val modeText = if (msg.roomTransport == RoomTransport.UDP) "P2P-UDP" else "P2P-TCP"
                    it.copy(
                        guestActive = !it.isHost || it.guestActive,
                        isJoining = false,
                        connectionMode = modeText,
                        latencyMs = result.latencyMs,
                        peerSessionId = msg.peerSessionId
                    )
                }
                if (!_state.value!!.isHost) _navigateToTab.postValue(R.id.nav_connect)
                if (msg.portTag > 0) {
                    markPortReadyByTag(msg.portTag)
                }
                addLog("ICE 打洞成功: ${result.peerAddress} RTT=${result.latencyMs}ms", "INFO", "ice")
                maybeAttachVpnP2P(result.peerAddress)
                startStatsSampling()
            } else {
                updateState { it.copy(connectionMode = "ICE 失败") }
                addLog(result.reason, "WARN", "ice")
                val settings = _settings.value
                if (settings?.forceRelay == true || settings?.relayFallback == true || settings?.autoRelay == true) {
                    signalManager?.requestRelay()
                    updateState { it.copy(connectionMode = "请求中继…") }
                    addLog("已请求中继回退", "INFO", "ice")
                }
            }
        }
    }

    override fun onRelayPreAllocated(msg: ServerMessage.RelayPreAllocated) {
        relayPreAllocated = msg
        addLog("中继已预分配: ${msg.relayAddr}", "INFO", "system")
    }

    override fun onRelayReady(msg: ServerMessage.RelayReady) {
        cancelRelayFallback()
        clearIceSession()  // P2P 已放弃，释放 ICE socket
        updateState { it.copy(connectionMode = "中继", guestActive = true, isJoining = false) }
        addLog("中继已就绪: ${msg.relayAddr}:${msg.relayUdpPort}", "INFO", "system")
        maybeAttachVpnRelay(msg.relayAddr, msg.relayQuicPort, msg.relayUdpPort, msg.token)
        startStatsSampling()
        _navigateToTab.postValue(R.id.nav_connect)
    }

    override fun onError(message: String) {
        updateState { it.copy(isJoining = false) }
        addLog("服务器错误: $message", "ERROR", "system")
    }

    override fun onDisconnected(code: Int, reason: String) {
        cancelRelayFallback()
        stopStatsSampling(reset = true)
        relayPreAllocated = null
        advancedMappings = emptyList()
        updateState { it.copy(connectionState = ConnectionState.DISCONNECTED, hostActive = false, guestActive = false) }
        stopVpnService()
        clearIceSession()
        addLog("信令断开: $reason", "WARN", "system")
        if (_settings.value?.autoConnect == true) connectSignal()
    }

    override fun onLog(message: String) {
        addLog(message, "INFO", "signal")
    }

    override fun onAdvancedRoomCreated(roomCode: String, transport: RoomTransport, mainPort: Int, allPorts: List<Int>) {
        advancedMappings = emptyList()
        val initialStatus = allPorts.associateWith { PortStatus.PENDING }
        updateState {
            it.copy(
                roomCode = roomCode, isHost = true, hostActive = true, guestActive = false,
                isAdvancedMode = true, roomTransport = transport,
                advancedMainPort = mainPort, advancedPorts = allPorts,
                portTunnelStatus = initialStatus
            )
        }
        addLog("高级房间已创建: $roomCode (${allPorts.size}端口)", "INFO", "host")
    }

    override fun onAdvancedJoinOk(roomCode: String, hostSessionId: String, transport: RoomTransport, portMappings: List<AdvancedPortMapping>) {
        advancedMappings = portMappings
        val initialStatus = portMappings.associate { it.hostPort to PortStatus.PENDING }
        updateState {
            it.copy(
                roomCode = roomCode, isHost = false, guestActive = true, isJoining = false,
                isAdvancedMode = true, roomTransport = transport,
                portTunnelStatus = initialStatus, peerSessionId = hostSessionId,
                connectionMode = "建立中"
            )
        }
        addLog("高级房间加入成功: $roomCode, ${portMappings.size}个端口", "INFO", "guest")
        startIceNegotiation(reuseExisting = false)
    }

    private fun startIceNegotiation(reuseExisting: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            val session = ensureIceSession(reuseExisting) ?: return@launch
            updateState { it.copy(connectionMode = "等待对端 ICE…") }

            val current = _state.value
            val isAdvanced = current?.isAdvancedMode == true
            val tags = if (isAdvanced) {
                if (current?.isHost == true) {
                    current.advancedPorts.ifEmpty {
                        listOfNotNull(current.advancedMainPort.takeIf { it > 0 })
                    }
                } else {
                    advancedMappings.map { it.hostPort }.distinct().ifEmpty {
                        listOfNotNull(current?.advancedMainPort?.takeIf { it > 0 })
                    }
                }
            } else {
                emptyList()
            }

            if (tags.isEmpty()) {
                signalManager?.sendIceCandidates(session.candidates, session.ufrag, session.pwd, session.natType)
                addLog("已上报 ${session.candidates.size} 个 ICE 候选，等待对端…", "INFO", "ice")
            } else {
                tags.forEach { tag ->
                    signalManager?.sendIceCandidatesTagged(
                        session.candidates,
                        session.ufrag,
                        session.pwd,
                        session.natType,
                        tag
                    )
                }
                addLog("已上报 tagged ICE 候选: ${tags.size} 组", "INFO", "ice")
            }

            scheduleRelayFallback("未收到 PeerCandidates")
        }
    }

    private suspend fun ensureIceSession(reuseExisting: Boolean): IceEngine.LocalIceSession? {
        if (reuseExisting) {
            iceSession?.let { return it }
        } else {
            clearIceSession()
        }

        return runCatching {
            iceEngine.gatherCandidates()
        }.onSuccess { session ->
            iceSession = session
            addLog("ICE 候选收集完成: ${session.candidates.size} 个, NAT=${session.natType}", "INFO", "ice")
        }.onFailure { error ->
            addLog("ICE 候选收集失败: ${error.message}", "ERROR", "ice")
        }.getOrNull()
    }

    private fun clearIceSession() {
        iceEngine.close(iceSession)
        iceSession = null
    }

    private fun maybeAttachVpnP2P(peer: InetSocketAddress?) {
        val app = getApplication<Application>()
        if (peer == null) return
        if (VpnService.prepare(app) != null) {
            addLog("VPN 未授权，暂不下发 P2P 数据面", "WARN", "vpn")
            return
        }

        // 获取 ICE 打洞 socket 使用的本地端口，VPN 服务必须绑定到同一端口，
        // 才能复用已经通过 NAT hole punch 开通的 NAT hole。
        val iceLocalPort = iceSession?.socket?.localPort ?: 0
        // 关闭 ICE socket，释放端口让 VPN 服务绑定（两个 socket 不能同时持有同一端口）。
        // NAT hole 在 UDP 静默后通常保持 30s~300s，关闭后立即重绑不会丢失通路。
        clearIceSession()

        val host = peer.address?.hostAddress ?: peer.hostString
        val isGuest = !(_state.value?.isHost ?: true)
        val transport = if (_state.value?.roomTransport == RoomTransport.UDP) {
            PhantomVpnService.TRANSPORT_UDP
        } else {
            PhantomVpnService.TRANSPORT_TCP
        }
        PhantomVpnService.attachP2P(app, host, peer.port, iceLocalPort, isGuest = isGuest, transport = transport)
        addLog("VPN 数据面已绑定 P2P: $host:${peer.port} (本地端口 $iceLocalPort)", "INFO", "vpn")
    }

    private fun maybeAttachVpnRelay(relayAddr: String, relayQuicPort: Int, relayUdpPort: Int, token: String) {
        val app = getApplication<Application>()
        if (relayAddr.isBlank()) return
        if (VpnService.prepare(app) != null) {
            addLog("VPN 未授权，暂不下发中继数据面", "WARN", "vpn")
            return
        }

        val isGuest = !(_state.value?.isHost ?: true)
        val transport = if (_state.value?.roomTransport == RoomTransport.UDP) {
            PhantomVpnService.TRANSPORT_UDP
        } else {
            PhantomVpnService.TRANSPORT_TCP
        }
        val relayPort = if (transport == PhantomVpnService.TRANSPORT_TCP) relayQuicPort else relayUdpPort
        if (relayPort !in 1..65535) return
        PhantomVpnService.attachRelay(app, "$relayAddr:$relayPort", token, isGuest = isGuest, transport = transport)
        addLog("VPN 数据面已绑定中继: $relayAddr:$relayPort", "INFO", "vpn")
    }

    /** 房间关闭时停止 VPN 前台服务（进程可被系统回收） */
    private fun stopVpnService() {
        val app = getApplication<Application>()
        if (VpnService.prepare(app) != null) return  // 未授权，无需停止
        PhantomVpnService.stop(app)
    }

    private fun isSignalAuthenticated(): Boolean {
        val s = _state.value
        return s?.connectionState == ConnectionState.AUTHENTICATED && signalManager?.isAuthenticated == true
    }

    private fun runPendingActionIfAny() {
        val action = pendingAction ?: return
        pendingAction = null

        when (action) {
            is PendingAction.CreateRoom -> {
                signalManager?.createRoom(action.gamePort, action.transport)
                addLog("鉴权完成，开始创建房间（端口 ${action.gamePort}, ${action.transport}）", "INFO", "host")
            }

            is PendingAction.CreateAdvancedRoom -> {
                signalManager?.createAdvancedRoom(action.ports, action.mainPort, action.transport)
                addLog("鉴权完成，开始创建高级房间（主端口 ${action.mainPort}）", "INFO", "host")
            }

            is PendingAction.JoinRoom -> {
                if (action.roomCode.endsWith("-A")) {
                    signalManager?.joinAdvancedRoom(action.roomCode)
                    updateState { it.copy(isAdvancedMode = true) }
                } else {
                    signalManager?.joinRoom(action.roomCode)
                }
                addLog("鉴权完成，开始加入房间 ${action.roomCode}", "INFO", "guest")
            }
        }
    }

    private fun markPortReadyByTag(portTag: Int) {
        val stateNow = _state.value ?: return
        if (!stateNow.isAdvancedMode) return

        val directPort = stateNow.portTunnelStatus.keys.firstOrNull { it == portTag }
        if (directPort != null) {
            updatePortStatus(directPort, PortStatus.READY)
            return
        }

        val mapped = advancedMappings.firstOrNull { it.hostPort == portTag }
        if (mapped != null) {
            updatePortStatus(mapped.hostPort, PortStatus.READY)
        }
    }

    private fun scheduleRelayFallback(reason: String) {
        cancelRelayFallback()
        val settings = _settings.value ?: return
        if (!(settings.forceRelay || settings.relayFallback || settings.autoRelay)) return

        relayFallbackJob = viewModelScope.launch(Dispatchers.IO) {
            delay(8000)  // 8s：给双方足够时间完成 ICE 候选收集和交换（STUN 最多 9s 超时）
            val st = _state.value ?: return@launch
            if (st.roomCode.isNullOrBlank()) return@launch
            if (st.connectionMode.startsWith("P2P") || st.connectionMode.startsWith("中继")) return@launch

            signalManager?.requestRelay()
            updateState { it.copy(connectionMode = "请求中继…") }
            addLog("[兜底] $reason，自动请求中继", "WARN", "ice")
        }
    }

    private fun cancelRelayFallback() {
        relayFallbackJob?.cancel()
        relayFallbackJob = null
    }

    private fun startStatsSampling() {
        if (statsJob?.isActive == true) return
        val app = getApplication<Application>()
        val snapshot = PhantomVpnService.readRuntimeStats(app)
        lastStatsTxBytes = snapshot.txBytes
        lastStatsRxBytes = snapshot.rxBytes

        statsJob = viewModelScope.launch(Dispatchers.IO) {
            while (true) {
                val stats = PhantomVpnService.readRuntimeStats(app)
                val nowTx = stats.txBytes
                val nowRx = stats.rxBytes
                val upBps = (nowTx - lastStatsTxBytes).coerceAtLeast(0)
                val downBps = (nowRx - lastStatsRxBytes).coerceAtLeast(0)
                val uptime = if (stats.startedAtMs > 0L) {
                    ((System.currentTimeMillis() - stats.startedAtMs) / 1000L).coerceAtLeast(0)
                } else {
                    0L
                }

                lastStatsTxBytes = nowTx
                lastStatsRxBytes = nowRx

                updateState {
                    it.copy(
                        uploadBps = upBps,
                        downloadBps = downBps,
                        uptimeSeconds = uptime
                    )
                }

                delay(1000)
            }
        }
    }

    private fun stopStatsSampling(reset: Boolean) {
        statsJob?.cancel()
        statsJob = null
        if (reset) {
            updateState { it.copy(uploadBps = 0, downloadBps = 0, uptimeSeconds = 0) }
        }
    }

    // ── Helpers ──

    private fun updateState(transform: (AppState) -> AppState) {
        val current = _state.value ?: AppState()
        _state.postValue(transform(current))
    }

    fun addLog(text: String, level: String = "INFO", module: String = "system") {
        val time = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
        val current = _logs.value ?: emptyList()
        _logs.postValue((current + LogEntry(time, level, module, text)).takeLast(500))
        runCatching {
            logStore.append(level, module, text)
        }
    }

    fun getLogFilePath(): String = logStore.path()

    fun getLogTail(maxLines: Int = 200): String = logStore.readTailLines(maxLines)

    override fun onCleared() {
        super.onCleared()
        cancelRelayFallback()
        stopStatsSampling(reset = false)
        clearIceSession()
        signalManager?.destroy()
    }
}

// ── Port spec parser matching PC's parsePortSpec ──
fun parsePortSpec(str: String): List<Int> {
    val result = mutableListOf<Int>()
    val seen = mutableSetOf<Int>()
    for (part in str.split(Regex("[\\s,，]+"))) {
        val m = Regex("""^(\d+)\s*[-–]\s*(\d+)$""").matchEntire(part.trim())
        if (m != null) {
            val lo = m.groupValues[1].toInt(); val hi = m.groupValues[2].toInt()
            if (lo in 1..65535 && hi in 1..65535 && lo <= hi)
                for (p in lo..hi) { if (seen.add(p)) result.add(p) }
        } else {
            val p = part.trim().toIntOrNull() ?: continue
            if (p in 1..65535 && seen.add(p)) result.add(p)
        }
    }
    return result
}

