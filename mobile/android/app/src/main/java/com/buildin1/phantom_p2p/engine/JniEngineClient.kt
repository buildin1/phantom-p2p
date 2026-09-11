package com.buildin1.phantom_p2p.engine

import android.util.Log
import com.buildin1.phantom_p2p.update.AppUpdateInfo
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

    private val _inviteToken = MutableStateFlow<InviteToken?>(null)
    override val inviteToken: StateFlow<InviteToken?> = _inviteToken.asStateFlow()

    private val _diagnostics = MutableStateFlow<NetworkDiagnostics?>(null)
    override val diagnostics: StateFlow<NetworkDiagnostics?> = _diagnostics.asStateFlow()

    private val _diagnosticsProgress = MutableStateFlow<DiagnosticsProgress?>(null)
    override val diagnosticsProgress: StateFlow<DiagnosticsProgress?> =
        _diagnosticsProgress.asStateFlow()

    private val _diagnosticsError = MutableStateFlow<String?>(null)
    override val diagnosticsError: StateFlow<String?> = _diagnosticsError.asStateFlow()

    private val _appUpdate = MutableStateFlow<AppUpdateInfo?>(null)
    override val appUpdate: StateFlow<AppUpdateInfo?> = _appUpdate.asStateFlow()

    /** 建房/入房的应答要等信令回来，用它把异步事件接回 suspend 调用。 */
    private val pendingRoomCode = MutableStateFlow<String?>(null)

    /** 信令是否已完成鉴权。房间类命令必须等它为 true 才能发。 */
    private val authenticated = MutableStateFlow(false)

    private var statsJob: Job? = null
    private var collecting = false
    private var signalStarted = false

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
        if (!PhantomEngine.init(logDir, dataDir, devMode)) {
            _state.value = ConnectionState.Failed(null, FailureReason.Unknown)
            return false
        }

        // 事件收集只能起一次 —— 起两遍每条事件都会被归约两次。
        // 它跟信令连接是两件事：断开重连时信令要重建，收集器不用。
        if (!collecting) {
            collecting = true
            scope.launch {
                // 每条事件单独兜异常。
                //
                // 不兜的话，`handle()` 抛一次 —— 一个 optString 拿到非字符串、
                // 一个枚举没覆盖到 —— 整个收集协程就死了，此后**所有**事件
                // 都不再处理：signal:auth_ok 收不到、awaitAuthenticated 永远
                // 超时、界面永远停在「连接服务器」，只能杀进程。
                // 一条事件处理失败是小事，收集器停摆是致命的。
                PhantomEngine.events.collect { event ->
                    runCatching { handle(event) }.onFailure {
                        Log.e(TAG, "处理事件 ${event.name} 失败: ${event.payload}", it)
                    }
                }
            }
            startStatsPolling()
        }

        if (!signalStarted) {
            signalStarted = true
            PhantomEngine.nativeConnectSignal(signalUrl)
        }
        return true
    }

    // -----------------------------------------------------------------------
    // EngineClient
    // -----------------------------------------------------------------------

    /**
     * 等到信令鉴权完成。
     *
     * **这是首次建房失败的根因所在。** `start()` 里的 `nativeConnectSignal`
     * 是异步的：建 WebSocket、收 AuthChallenge、签名回传、服务端验签，
     * 实测要一个往返（约 1 秒）。在那之前任何 CreateRoom / JoinRoom 发出去
     * 都会在 Rust 侧 `signal.send()` 处失败，而那个错误只写了日志、没有回到
     * 界面 —— 于是界面一直转到 15 秒超时，用户看到的是"卡在探测网络环境"。
     *
     * 服务端日志能直接印证：第一次的 CreateRoom 根本没抵达。
     */
    private suspend fun awaitAuthenticated(): Boolean {
        if (authenticated.value) return true
        val ok = withTimeoutOrNull(SIGNAL_TIMEOUT_MS) {
            authenticated.first { it }
        } != null
        if (!ok) {
            // 等超时说明这一轮信令没建起来。必须把 signalStarted 解锁，
            // 否则下次 start() 会以为"已经连过了"而跳过 nativeConnectSignal，
            // 于是永远等一个不会再来的 auth_ok —— 用户只能杀后台重开。
            Log.w(TAG, "等待信令鉴权超时，解锁 signalStarted 以便下次重连")
            signalStarted = false
        }
        return ok
    }

    override suspend fun createRoom(): Result<String> {
        if (!start()) return Result.failure(IllegalStateException("引擎未就绪"))
        pendingRoomCode.value = null
        isHost = true
        connectingSince = System.currentTimeMillis()

        // 阶段文案要诚实：这时候还在连服务器，不是在探测网络。
        _state.value = ConnectionState.Connecting("", PunchPhase.ConnectingSignal, 0)
        if (!awaitAuthenticated()) {
            _state.value = ConnectionState.Failed(null, FailureReason.SignalUnavailable)
            return Result.failure(IllegalStateException("连接服务器超时"))
        }

        _state.value = ConnectionState.Connecting("", PunchPhase.Probing, elapsed())
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

        _state.value = ConnectionState.Connecting(roomCode, PunchPhase.ConnectingSignal, 0)
        if (!awaitAuthenticated()) {
            _state.value = ConnectionState.Failed(roomCode, FailureReason.SignalUnavailable)
            return Result.failure(IllegalStateException("连接服务器超时"))
        }

        _state.value = ConnectionState.Connecting(roomCode, PunchPhase.Probing, elapsed())
        PhantomEngine.nativeJoinRoom(roomCode)
        return Result.success(Unit)
    }

    override suspend fun joinByToken(token: String): Result<Unit> {
        if (!start()) return Result.failure(IllegalStateException("引擎未就绪"))
        isHost = false
        // 房间码要等服务端在 join_ok 里告诉我们 —— 令牌解析是服务端的事。
        this.roomCode = null
        connectingSince = System.currentTimeMillis()

        _state.value = ConnectionState.Connecting("", PunchPhase.ConnectingSignal, 0)
        if (!awaitAuthenticated()) {
            _state.value = ConnectionState.Failed(null, FailureReason.SignalUnavailable)
            return Result.failure(IllegalStateException("连接服务器超时"))
        }

        _state.value = ConnectionState.Connecting("", PunchPhase.Probing, elapsed())
        PhantomEngine.nativeJoinByToken(token)
        return Result.success(Unit)
    }

    override suspend fun requestInviteToken(refresh: Boolean) {
        if (!authenticated.value) return
        if (refresh) _inviteToken.value = null
        PhantomEngine.nativeRequestInviteToken(refresh)
    }

    override suspend fun leaveRoom() {
        PhantomEngine.nativeLeaveRoom()
        resetRoom()
    }

    override suspend fun disconnect() {
        PhantomEngine.nativeDisconnect()
        // 信令也断了，鉴权随之失效。下次 start() 必须重新连 ——
        // 不复位的话后续建房会一直等一个永远不会再来的 auth_ok。
        signalStarted = false
        authenticated.value = false
        resetRoom()
    }

    override suspend fun retry() {
        val code = roomCode ?: return
        if (isHost) createRoom() else joinRoom(code)
    }

    override suspend fun probeNetwork() {
        if (!start()) {
            // 引擎都没起来就别装作在检测。以前这里直接 return，界面毫无反应。
            _diagnosticsError.value = "引擎未就绪，请重启应用后再试"
            return
        }
        // 已经在跑就不要再叠一次：三轮 STUN 采样要十几秒，重复触发会让
        // 两次进度事件互相覆盖，进度条来回跳。
        if (_diagnosticsProgress.value != null) return

        _diagnosticsError.value = null
        // 先手动置一个 0%，让动画立刻起来 —— 等第一个 net:progress 事件从
        // Rust 回来要一小会儿，那段空窗期正是用户觉得"点了没反应"的地方。
        _diagnosticsProgress.value = DiagnosticsProgress(0, "准备检测", 15)
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
            "signal:auth_ok" -> authenticated.value = true

            "signal:auth_failed" -> {
                authenticated.value = false
                // 同 awaitAuthenticated 里的理由：不解锁就再也不会重连。
                signalStarted = false
                _state.value = ConnectionState.Failed(roomCode, FailureReason.SignalUnavailable)
            }

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
                // 建完房立刻要一张邀请，用户进房间页时二维码已经是现成的 ——
                // 点开二维码才去要，就要先看一秒空白。
                PhantomEngine.nativeRequestInviteToken(false)
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
                if (id.isNotEmpty()) {
                    knownPeers.add(id)
                    // 对端虚拟 IP 现在由服务端在 peer_joined 里带过来了。
                    // 老服务端不带这个字段，取到空串 —— 成员列表退回显示 "—"，
                    // 与改动前一致，不会因此出错。
                    val ip = json?.optString("virtual_ip").orEmpty()
                    if (ip.isNotEmpty()) peerVirtualIps[id] = ip
                }
                rebuildMembers()
            }

            "signal:peer_left" -> {
                val id = json?.optString("peer_session_id")
                knownPeers.remove(id)
                peerVirtualIps.remove(id)
                rebuildMembers()
            }

            "signal:invite_token" -> {
                val token = json?.optString("token").orEmpty()
                val code = json?.optString("room_code").orEmpty()
                if (token.isNotEmpty()) {
                    _inviteToken.value = InviteToken(token = token, roomCode = code)
                }
            }

            "signal:invite_token_invalid" -> {
                _inviteToken.value = null
                _state.value = ConnectionState.Failed(roomCode, FailureReason.RoomGone)
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

                // 房主的虚拟网卡起来 = 房间真的开了，此刻就该进稳定态。
                //
                // 之前只认 tunnel:started，而那个事件要等对端接通才发 ——
                // 房主建完房没人进来就永远停在「正在准备房间」。服务端那边
                // 房间其实早就开了（收到了 HostReady），纯粹是界面没跟上。
                //
                // Guest 不走这条：它的 tun:ready 紧跟着 tunnel:started，
                // 让后者带上真实的传输方式即可。
                if (isHost && _state.value !is ConnectionState.Connected) {
                    _state.value = ConnectionState.Connected(
                        roomCode = roomCode.orEmpty(),
                        transport = null, // 还没有队友，谈不上用哪种传输
                        localVirtualIp = selfVirtualIp,
                        peerVirtualIp = selfVirtualIp,
                        connectedSinceMillis = System.currentTimeMillis(),
                    )
                }
                rebuildMembers()
            }

            "tun:failed" -> {
                _state.value = ConnectionState.Failed(roomCode, FailureReason.VpnPermissionDenied)
            }

            "signal:status" -> {
                // 必须读 state_key，不能读 state。
                // state 是 core 的 Display 输出，是给人看的中文（"未连接"/"已连接"），
                // 拿它去比 "disconnected" 永远不相等 —— 断线检测曾经整个是死的。
                val signalState = json?.optString("state_key").orEmpty()
                if (signalState.equals("disconnected", ignoreCase = true)) {
                    // 连接断了鉴权就作废。不清这个标记的话，重连之后
                    // awaitAuthenticated 会立刻放行，而命令仍然发不出去。
                    authenticated.value = false
                    signalStarted = false
                    if (_state.value is ConnectionState.Connecting) {
                        _state.value =
                            ConnectionState.Failed(roomCode, FailureReason.SignalUnavailable)
                    }
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

            "net:progress" -> {
                val percent = json?.optInt("progress", 0) ?: 0
                _diagnosticsProgress.value = DiagnosticsProgress(
                    percent = percent.coerceIn(0, 100),
                    stage = json?.optString("stage").orEmpty(),
                    etaSeconds = json?.optInt("eta_seconds", 0) ?: 0,
                )
            }

            "net:diagnostics" -> {
                if (json != null) {
                    _diagnostics.value = parseDiagnostics(json)
                    _diagnosticsError.value = null
                }
                // 结果到手，进度条收工。放在这里而不是等 100% 那条进度事件：
                // 事件是 DROP_OLDEST 的共享流，最后那条理论上可能被挤掉，
                // 而结果事件一定在结果到达时才发。
                _diagnosticsProgress.value = null
            }

            "net:failed" -> {
                _diagnosticsProgress.value = null
                _diagnosticsError.value = json?.optString("reason")
                    ?.takeIf { it.isNotEmpty() } ?: "检测失败"
            }

            "signal:app_update" -> {
                if (json == null) return
                val url = json.optString("download_url")
                val sha = json.optString("sha256")
                // 校验值不合法就当这条通告不存在。没有 sha256 的自动安装
                // 等于把设备交给任何能劫持下载的人 —— 宁可不提示更新。
                val shaLooksValid = sha.length == 64 && sha.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
                if (url.isEmpty() || !shaLooksValid) {
                    Log.w(TAG, "版本通告缺少合法的下载地址或 sha256，忽略")
                    return
                }
                _appUpdate.value = AppUpdateInfo(
                    platform = json.optString("platform"),
                    latestVersion = json.optString("latest_version"),
                    minSupported = json.optString("min_supported"),
                    downloadUrl = url,
                    sha256 = sha,
                    notes = json.optString("notes"),
                    mandatory = json.optBoolean("mandatory", false),
                )
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

    /** session_id -> 对端虚拟 IP。服务端在 `peer_joined` 里下发。 */
    private val peerVirtualIps = mutableMapOf<String, String>()

    /**
     * 把 `net:diagnostics` 的载荷翻成 [NetworkDiagnostics]。
     *
     * 字段名与 PC 端 `NetworkInfo` 的序列化名一一对应，改一边必须改另一边。
     */
    private fun parseDiagnostics(json: JSONObject): NetworkDiagnostics {
        val details = json.optJSONArray("stun_details")
        val stunDetails = buildList {
            for (i in 0 until (details?.length() ?: 0)) {
                val item = details?.optJSONObject(i) ?: continue
                add(
                    StunDetail(
                        server = item.optString("server"),
                        mapping = item.optString("mapping"),
                        rttMillis = item.optInt("rtt_ms", 0),
                        socket = item.optString("socket"),
                        round = item.optInt("round", 0),
                    )
                )
            }
        }
        return NetworkDiagnostics(
            natType = json.optString("nat_type"),
            natTypeKey = json.optString("nat_type_key"),
            natDifficulty = json.optString("nat_difficulty"),
            externalIp = json.optString("external_ip"),
            externalPort = json.optInt("external_port", 0),
            upnp = json.optBoolean("upnp", false),
            upnpPort = json.optInt("upnp_port", 0),
            ipv6 = json.optBoolean("ipv6", false),
            ipv6Addr = json.optString("ipv6_addr"),
            localIp = json.optString("local_ip"),
            localPort = json.optInt("local_port", 0),
            stunDetails = stunDetails,
            portPattern = json.optString("port_pattern"),
            mappingBehavior = json.optString("mapping_behavior"),
            filteringBehavior = json.optString("filtering_behavior"),
            confidence = json.optString("confidence"),
            rounds = json.optInt("diagnostics_rounds", 0),
            networkPriority = json.optString("network_priority"),
            mtu = json.optInt("mtu", TUN_MTU),
        )
    }

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
                // 服务端在 peer_joined 里带了虚拟 IP；老服务端不带，退回 "—"。
                virtualIp = peerVirtualIps[id]?.takeIf { it.isNotEmpty() } ?: "—",
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
        peerVirtualIps.clear()
        // 令牌跟随房间：房间没了，手上这张邀请也就作废了。
        _inviteToken.value = null
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
