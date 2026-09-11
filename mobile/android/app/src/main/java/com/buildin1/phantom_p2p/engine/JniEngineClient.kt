package com.buildin1.phantom_p2p.engine

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject

/**
 * 真引擎。把 Rust 推上来的事件流翻成 [EngineClient] 的状态。
 *
 * ## 为什么是「翻译」而不是「转发」
 *
 * Rust 侧发的是**协议层**事件（`signal:join_ok`、`punch:phase`、
 * `tunnel:started`），界面要的是**状态机**。中间这一层的职责就是把前者
 * 归约成后者——而且归约规则只有这一处，界面不需要知道任何协议细节。
 *
 * 这也是为什么 [ConnectionState] 是密封类型而不是字符串：旧版本用自由文本
 * 同时做展示和判断，改一处崩另一处。
 */
class JniEngineClient(
    private val scope: CoroutineScope,
    private val signalUrl: String,
    private val logDir: String,
    private val dataDir: String,
    private val devMode: Boolean,
) : EngineClient {

    private val _state = MutableStateFlow<ConnectionState>(ConnectionState.Idle)
    override val state: StateFlow<ConnectionState> = _state.asStateFlow()

    private val _members = MutableStateFlow<List<RoomMember>>(emptyList())
    override val members: StateFlow<List<RoomMember>> = _members.asStateFlow()

    private val _linkStats = MutableStateFlow(LinkStats.EMPTY)
    override val linkStats: StateFlow<LinkStats> = _linkStats.asStateFlow()

    private val _networkProfile = MutableStateFlow<NetworkProfile?>(null)
    override val networkProfile: StateFlow<NetworkProfile?> = _networkProfile.asStateFlow()

    /** 建房/入房的应答要等信令回来，用它把异步事件接回 suspend 调用。 */
    private val pendingRoomCode = MutableStateFlow<String?>(null)

    private var statsJob: Job? = null
    private var started = false

    /** 最近一次的房间上下文，重试和成员构造要用。 */
    private var roomCode: String? = null
    private var isHost = false
    private var selfVirtualIp: String = ""
    private var hostVirtualIp: String = ""
    private var connectingSince = 0L
    private val latencyHistory = ArrayDeque<Int>()

    /**
     * 启动引擎并开始消费事件。幂等——VpnService 可能被系统重启多次。
     */
    fun start(): Boolean {
        if (started) return true
        if (!PhantomEngine.init(logDir, dataDir, devMode)) {
            _state.value = ConnectionState.Failed(null, FailureReason.Unknown)
            return false
        }
        started = true

        scope.launch {
            PhantomEngine.events.collect { event -> handle(event) }
        }
        PhantomEngine.nativeConnectSignal(signalUrl)
        startStatsPolling()
        return true
    }

    // -----------------------------------------------------------------------
    // EngineClient
    // -----------------------------------------------------------------------

    override suspend fun createRoom(): Result<String> {
        if (!start()) return Result.failure(IllegalStateException("引擎未就绪"))
        pendingRoomCode.value = null
        isHost = true
        connectingSince = System.currentTimeMillis()
        _state.value = ConnectionState.Connecting("", PunchPhase.Probing, 0)
        PhantomEngine.nativeCreateRoom()

        // 服务端分配房间码要一个往返。等不到就当失败——界面此时正显示
        // 「正在创建房间」，不能无限转下去。
        val code = withTimeoutOrNull(SIGNAL_TIMEOUT_MS) {
            pendingRoomCode.first { !it.isNullOrEmpty() }
        }
        return if (!code.isNullOrEmpty()) {
            Result.success(code)
        } else {
            _state.value = ConnectionState.Failed(null, FailureReason.SignalUnavailable)
            Result.failure(IllegalStateException("建房超时"))
        }
    }

    override suspend fun joinRoom(roomCode: String): Result<Unit> {
        if (!start()) return Result.failure(IllegalStateException("引擎未就绪"))
        isHost = false
        this.roomCode = roomCode
        connectingSince = System.currentTimeMillis()
        _state.value = ConnectionState.Connecting(roomCode, PunchPhase.Probing, 0)
        PhantomEngine.nativeJoinRoom(roomCode)
        return Result.success(Unit)
    }

    override suspend fun leaveRoom() {
        PhantomEngine.nativeLeaveRoom()
        resetRoom()
    }

    override suspend fun disconnect() {
        PhantomEngine.nativeDisconnect()
        resetRoom()
    }

    override suspend fun retry() {
        val code = roomCode ?: return
        if (isHost) createRoom() else joinRoom(code)
    }

    override suspend fun probeNetwork() {
        if (!start()) return
        // 真跑一次 STUN 探测，结果通过 net:profile 事件回来。
        // 需要信令已连接：STUN 地址由服务端下发，客户端不内置任何地址。
        PhantomEngine.nativeProbeNetwork()
    }

    override suspend fun uploadLogs(reason: String): Result<Long> {
        PhantomEngine.nativeUploadLogs(reason)
        // 结果通过 log:uploaded / log:upload_failed 事件回来，这里不阻塞等待。
        return Result.success(0L)
    }

    // -----------------------------------------------------------------------
    // 事件归约
    // -----------------------------------------------------------------------

    private fun handle(event: EngineEvent) {
        val json = runCatching { JSONObject(event.payload) }.getOrNull()

        when (event.name) {
            "signal:room_created" -> {
                val code = json?.optString("room_code").orEmpty()
                roomCode = code
                isHost = true
                selfVirtualIp = json?.optString("virtual_ip").orEmpty()
                hostVirtualIp = selfVirtualIp
                pendingRoomCode.value = code
                _state.value = ConnectionState.Connecting(
                    code, PunchPhase.EstablishingTunnel, elapsed()
                )
                rebuildMembers()
            }

            "signal:join_ok" -> {
                val code = json?.optString("room_code").orEmpty()
                roomCode = code
                isHost = false
                selfVirtualIp = json?.optString("virtual_ip").orEmpty()
                hostVirtualIp = json?.optString("host_virtual_ip").orEmpty()
                _state.value = ConnectionState.Connecting(code, PunchPhase.Probing, elapsed())
                rebuildMembers()
            }

            "signal:join_failed" -> {
                _state.value = ConnectionState.Failed(roomCode, FailureReason.RoomGone)
            }

            "signal:version_mismatch" -> {
                _state.value = ConnectionState.Failed(roomCode, FailureReason.VersionMismatch)
            }

            "signal:room_closed" -> resetRoom()

            "signal:peer_joined" -> {
                val id = json?.optString("peer_session_id").orEmpty()
                if (id.isNotEmpty()) knownPeers.add(id)
                rebuildMembers()
            }

            "signal:peer_left" -> {
                knownPeers.remove(json?.optString("peer_session_id"))
                rebuildMembers()
            }

            "punch:phase" -> handlePunchPhase(event.payload)

            "tunnel:started" -> {
                // 载荷是裸字符串 "P2P" 或 "Relay"。
                //
                // 这是全应用最需要小心的一处映射：Relay 在界面上仍然叫
                // 「P2P 直连」，只是传输后缀是 QUIC。内部必须精确区分
                // （遥测、日志、中继回收都依赖它），但界面不出现「中继」二字。
                val mode = event.payload.trim('"')
                val transport = if (mode == "Relay") Transport.Quic else Transport.Udp
                _state.value = ConnectionState.Connected(
                    roomCode = roomCode.orEmpty(),
                    transport = transport,
                    localVirtualIp = selfVirtualIp,
                    peerVirtualIp = hostVirtualIp,
                    connectedSinceMillis = System.currentTimeMillis(),
                )
                rebuildMembers(transport)
            }

            "tunnel:failed" -> {
                Log.w(TAG, "隧道建立失败: ${event.payload}")
                // 不立刻判死：P2P 失败之后还有中继回退，Rust 侧会继续尝试。
                // 只有信令也断了才算真失败。
            }

            "tun:ready" -> {
                selfVirtualIp = json?.optString("my_ip").orEmpty().ifEmpty { selfVirtualIp }
                hostVirtualIp = json?.optString("host_ip").orEmpty().ifEmpty { hostVirtualIp }
                _networkProfile.value = (_networkProfile.value ?: defaultProfile())
                    .copy(mtu = TUN_MTU)
                rebuildMembers()
            }

            "tun:failed" -> {
                _state.value = ConnectionState.Failed(roomCode, FailureReason.VpnPermissionDenied)
            }

            "signal:status" -> {
                val signalState = json?.optString("state").orEmpty()
                if (signalState.equals("disconnected", ignoreCase = true) &&
                    _state.value is ConnectionState.Connecting
                ) {
                    _state.value =
                        ConnectionState.Failed(roomCode, FailureReason.SignalUnavailable)
                }
            }

            "net:profile" -> {
                if (json != null) {
                    _networkProfile.value = NetworkProfile(
                        // class 是策略用的三分类（Cone / LinearSymmetric /
                        // RandomSymmetric），detail 才是给人看的细分类名。
                        // 诊断页显示 detail，读不到时退回三分类。
                        natClass = parseNatClass(
                            json.optString("nat_detail"),
                            json.optString("nat_class"),
                        ),
                        mappingStable = json.optBoolean("mapping_stable", false),
                        ipv6Available = json.optBoolean("has_ipv6", false),
                        mtu = json.optInt("mtu", TUN_MTU),
                    )
                }
            }

            "log:uploaded", "log:upload_failed" -> {
                Log.i(TAG, "${event.name}: ${event.payload}")
            }
        }
    }

    /**
     * `PunchPhase` 是 Rust 的外部标签枚举：无字段的变体序列化成裸字符串
     * （`"Probing"`），带字段的序列化成单键对象（`{"Failed":{"reason":..}}`）。
     * 两种形态都要认。
     */
    private fun handlePunchPhase(payload: String) {
        val code = roomCode.orEmpty()
        val trimmed = payload.trim()

        if (trimmed.startsWith("\"")) {
            val phase = when (trimmed.trim('"')) {
                "Probing" -> PunchPhase.Probing
                "WaitingPeer" -> PunchPhase.WaitingPeer
                "Punching" -> PunchPhase.Punching
                else -> return
            }
            if (_state.value !is ConnectionState.Connected) {
                _state.value = ConnectionState.Connecting(code, phase, elapsed())
            }
            return
        }

        val obj = runCatching { JSONObject(trimmed) }.getOrNull() ?: return
        when {
            obj.has("Success") -> {
                // 成功只是打通了 UDP，隧道还要再建一步。
                // 真正的「已连接」由 tunnel:started 决定。
                if (_state.value !is ConnectionState.Connected) {
                    _state.value = ConnectionState.Connecting(
                        code, PunchPhase.EstablishingTunnel, elapsed()
                    )
                }
            }

            obj.has("Failed") -> {
                // 打洞失败不等于连接失败——接下来会落中继。保持在连接中，
                // 让界面继续转，等 tunnel:started 或信令断开来定论。
                val reason = obj.optJSONObject("Failed")?.optString("reason").orEmpty()
                Log.i(TAG, "打洞失败，等待中继回退: $reason")
                if (_state.value !is ConnectionState.Connected) {
                    _state.value = ConnectionState.Connecting(
                        code, PunchPhase.EstablishingTunnel, elapsed()
                    )
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 统计
    // -----------------------------------------------------------------------

    private fun startStatsPolling() {
        statsJob?.cancel()
        statsJob = scope.launch {
            while (isActive) {
                if (PhantomEngine.nativeIsTunnelLive()) {
                    parseStats(PhantomEngine.nativeStatsJson())
                }
                delay(1_000)
            }
        }
    }

    private fun parseStats(json: String) {
        val obj = runCatching { JSONObject(json) }.getOrNull() ?: return
        val latency = obj.optLong("latency", -1).toInt().takeIf { it >= 0 }
        if (latency != null) {
            latencyHistory.addLast(latency)
            while (latencyHistory.size > 60) latencyHistory.removeFirst()
        }
        _linkStats.value = LinkStats(
            latencyMillis = latency,
            lossPercent = obj.optDouble("packet_loss", Double.NaN)
                .takeIf { !it.isNaN() }
                ?.let { it * 100 },
            upMbps = obj.optDouble("upload_mbps", Double.NaN).takeIf { !it.isNaN() },
            downMbps = obj.optDouble("download_mbps", Double.NaN).takeIf { !it.isNaN() },
            latencyHistory = latencyHistory.toList(),
        )
    }

    // -----------------------------------------------------------------------
    // 成员
    //
    // Rust 侧不维护成员名册（服务端也只发 session_id），所以这里按已知信息
    // 拼：本机 + peer_joined 收到的 session_id。昵称等服务端支持后再补。
    // -----------------------------------------------------------------------

    private val knownPeers = linkedSetOf<String>()

    private fun rebuildMembers(transport: Transport? = null) {
        if (roomCode == null) {
            _members.value = emptyList()
            return
        }
        val current = (_state.value as? ConnectionState.Connected)?.transport ?: transport
        val list = mutableListOf(
            RoomMember(
                id = "self",
                displayName = "这台设备",
                virtualIp = selfVirtualIp.ifEmpty { "—" },
                isHost = isHost,
                isSelf = true,
                latencyMillis = null,
                transport = null,
            )
        )
        if (!isHost && hostVirtualIp.isNotEmpty()) {
            list += RoomMember(
                id = "host",
                displayName = "房主",
                virtualIp = hostVirtualIp,
                isHost = true,
                isSelf = false,
                latencyMillis = _linkStats.value.latencyMillis,
                transport = current,
            )
        }
        knownPeers.forEachIndexed { index, id ->
            list += RoomMember(
                id = id,
                displayName = "队友 ${index + 1}",
                virtualIp = "—",
                isHost = false,
                isSelf = false,
                latencyMillis = null,
                transport = current,
            )
        }
        _members.value = list
    }

    private fun resetRoom() {
        roomCode = null
        knownPeers.clear()
        selfVirtualIp = ""
        hostVirtualIp = ""
        latencyHistory.clear()
        _state.value = ConnectionState.Idle
        _members.value = emptyList()
        _linkStats.value = LinkStats.EMPTY
    }

    /**
     * 把 Rust 的 NAT 分类翻成界面用的枚举。
     *
     * 优先用 detail（细分类，如 `port_restricted_cone`），它才是用户看得懂的；
     * detail 缺失时退回 class 那个三分类。
     */
    private fun parseNatClass(detail: String?, klass: String?): NatClass = when {
        detail?.contains("port_restricted", ignoreCase = true) == true ->
            NatClass.PortRestrictedCone
        detail?.contains("restricted", ignoreCase = true) == true -> NatClass.RestrictedCone
        detail?.contains("full", ignoreCase = true) == true -> NatClass.FullCone
        detail?.contains("symmetric", ignoreCase = true) == true -> NatClass.Symmetric
        klass.equals("Cone", ignoreCase = true) -> NatClass.FullCone
        klass?.contains("Symmetric", ignoreCase = true) == true -> NatClass.Symmetric
        else -> NatClass.Unknown
    }

    private fun elapsed() = System.currentTimeMillis() - connectingSince

    private fun defaultProfile() = NetworkProfile(
        natClass = NatClass.Unknown,
        mappingStable = false,
        ipv6Available = false,
        mtu = TUN_MTU,
    )

    private companion object {
        const val TAG = "JniEngineClient"
        const val SIGNAL_TIMEOUT_MS = 15_000L

        /** 与 core 的 tun_bridge::TUN_MTU 同源，见 BuildConfig.TUN_MTU。 */
        const val TUN_MTU = 1160
    }
}
