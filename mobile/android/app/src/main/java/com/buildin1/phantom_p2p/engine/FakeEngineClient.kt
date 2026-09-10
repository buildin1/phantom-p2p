package com.buildin1.phantom_p2p.engine

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlin.random.Random

/**
 * 假引擎。
 *
 * Rust 侧的 FFI 还没做，但界面必须现在就能跑起来看——这个实现按真实时序演一遍
 * 完整流程：探测 0.4s、交换线路 0.9s、打洞、建隧道，接通后延迟指标持续抖动。
 *
 * 它同时是 `@Preview` 的数据源，以及 UI 单测的替身。**真 FFI 落地后这个类不删**：
 * 它是唯一能在没有网络、没有对端、没有信令服务器的情况下驱动全部界面状态的东西。
 */
class FakeEngineClient(
    private val scope: CoroutineScope,
    /** 演到最后是成功还是失败，调试不同分支用。 */
    private val outcome: Outcome = Outcome.SucceedDirect,
) : EngineClient {

    enum class Outcome {
        /** 打洞成功，真直连。 */
        SucceedDirect,

        /** 打洞失败落中继——界面仍显示「P2P 直连 (QUIC)」。 */
        SucceedRelayed,

        /** 彻底没接通。 */
        Fail,
    }

    private val _state = MutableStateFlow<ConnectionState>(ConnectionState.Idle)
    override val state: StateFlow<ConnectionState> = _state.asStateFlow()

    private val _members = MutableStateFlow<List<RoomMember>>(emptyList())
    override val members: StateFlow<List<RoomMember>> = _members.asStateFlow()

    private val _linkStats = MutableStateFlow(LinkStats.EMPTY)
    override val linkStats: StateFlow<LinkStats> = _linkStats.asStateFlow()

    private val _networkProfile = MutableStateFlow<NetworkProfile?>(null)
    override val networkProfile: StateFlow<NetworkProfile?> = _networkProfile.asStateFlow()

    private var scriptJob: Job? = null
    private var statsJob: Job? = null
    private var lastRoomCode: String? = null

    override suspend fun createRoom(): Result<String> {
        val code = randomRoomCode()
        runScript(code, asHost = true)
        return Result.success(code)
    }

    override suspend fun joinRoom(roomCode: String): Result<Unit> {
        runScript(roomCode.uppercase(), asHost = false)
        return Result.success(Unit)
    }

    override suspend fun leaveRoom() {
        scriptJob?.cancel()
        statsJob?.cancel()
        _state.value = ConnectionState.Idle
        _members.value = emptyList()
        _linkStats.value = LinkStats.EMPTY
    }

    override suspend fun disconnect() = leaveRoom()

    override suspend fun retry() {
        lastRoomCode?.let { runScript(it, asHost = false) }
    }

    override suspend fun probeNetwork() {
        _networkProfile.value = null
        delay(700)
        _networkProfile.value = SAMPLE_PROFILE
    }

    override suspend fun uploadLogs(reason: String): Result<Long> {
        delay(900)
        return Result.success(6_291_456L)
    }

    // -----------------------------------------------------------------------

    private fun runScript(roomCode: String, asHost: Boolean) {
        lastRoomCode = roomCode
        scriptJob?.cancel()
        statsJob?.cancel()

        scriptJob = scope.launch {
            val startedAt = System.currentTimeMillis()

            suspend fun advance(phase: PunchPhase, holdMillis: Long) {
                val stepStart = System.currentTimeMillis()
                while (isActive && System.currentTimeMillis() - stepStart < holdMillis) {
                    _state.value = ConnectionState.Connecting(
                        roomCode = roomCode,
                        phase = phase,
                        elapsedMillis = System.currentTimeMillis() - startedAt,
                    )
                    // 100ms 一跳，够「已用 1.8s」这个数字看起来是活的，
                    // 又不至于让整屏每帧重组。
                    delay(100)
                }
            }

            advance(PunchPhase.Probing, 400)
            advance(PunchPhase.WaitingPeer, 900)
            advance(PunchPhase.Punching, 1_100)

            if (outcome == Outcome.Fail) {
                _state.value = ConnectionState.Failed(roomCode, FailureReason.PeerUnreachable)
                _members.value = emptyList()
                return@launch
            }

            advance(PunchPhase.EstablishingTunnel, 500)

            val transport =
                if (outcome == Outcome.SucceedRelayed) Transport.Quic else Transport.Udp
            val selfIp = if (asHost) "10.66.0.1" else "10.66.0.2"
            val hostIp = "10.66.0.1"

            _state.value = ConnectionState.Connected(
                roomCode = roomCode,
                transport = transport,
                localVirtualIp = selfIp,
                peerVirtualIp = hostIp,
                connectedSinceMillis = System.currentTimeMillis(),
            )
            _members.value = sampleMembers(selfIp, asHost, transport)
            startStatsTicker()
        }
    }

    private fun startStatsTicker() {
        statsJob = scope.launch {
            val history = ArrayDeque<Int>()
            repeat(60) { history.addLast(11 + Random.nextInt(0, 5)) }
            while (isActive) {
                history.addLast(11 + Random.nextInt(0, 5))
                while (history.size > 60) history.removeFirst()
                _linkStats.value = LinkStats(
                    latencyMillis = history.last(),
                    lossPercent = Random.nextDouble(0.0, 0.6),
                    upMbps = 1.0 + Random.nextDouble(0.0, 0.6),
                    downMbps = 3.0 + Random.nextDouble(0.0, 1.0),
                    latencyHistory = history.toList(),
                )
                delay(1_000)
            }
        }
    }

    private fun sampleMembers(selfIp: String, asHost: Boolean, transport: Transport) = listOf(
        RoomMember(
            id = "self",
            displayName = "这台设备",
            virtualIp = selfIp,
            isHost = asHost,
            isSelf = true,
            latencyMillis = null,
            transport = null,
        ),
        RoomMember(
            id = "chen",
            displayName = "老陈",
            virtualIp = "10.66.0.1",
            isHost = !asHost,
            isSelf = false,
            latencyMillis = 12,
            transport = transport,
        ),
        RoomMember(
            id = "qi",
            displayName = "阿祈",
            virtualIp = "10.66.0.3",
            isHost = false,
            isSelf = false,
            latencyMillis = 28,
            transport = Transport.Quic,
        ),
    )

    private fun randomRoomCode(): String =
        (1..6).map { ROOM_CODE_ALPHABET.random() }.joinToString("")

    companion object {
        /** 与服务端一致：去掉 0/O/1/I 这些念出来会歧义的字符。 */
        private const val ROOM_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

        val SAMPLE_PROFILE = NetworkProfile(
            natClass = NatClass.PortRestrictedCone,
            mappingStable = true,
            ipv6Available = true,
            mtu = 1160,
        )

        /** 给 @Preview 用的静态快照，不需要协程作用域。 */
        val PREVIEW_STATS = LinkStats(
            latencyMillis = 12,
            lossPercent = 0.3,
            upMbps = 1.2,
            downMbps = 3.4,
            latencyHistory = listOf(
                14, 13, 15, 12, 14, 11, 13, 10, 14, 12,
                15, 11, 13, 10, 12, 11, 14, 10, 12, 9,
                13, 11, 12, 10, 13, 12, 11, 13, 10, 12,
            ),
        )
    }
}
