package com.buildin1.phantom_p2p.engine

import kotlinx.coroutines.flow.StateFlow

/**
 * 引擎门面 —— 界面层与 Rust 之间唯一的接缝。
 *
 * ## 为什么先有接口、后有实现
 *
 * `crates/core` 里的 `SessionRuntime` 与 `crates/mobile` 的 FFI 导出面都还没做
 * （见仓库根的移动端勘定）。但界面消费的是**事件流的形状**，不是 FFI 的调用约定，
 * 所以这个接口现在就能定死：等 FFI 落地时换掉实现即可，UI 一行不用动。
 *
 * 反过来说，这个接口就是给 Rust 侧的需求清单——FFI 导出面至少要覆盖这些方法
 * 和 [state] / [members] / [linkStats] 三条状态流。
 *
 * ## 线程约定
 *
 * 所有 `suspend` 方法可以从主线程调用，实现负责切到自己的线程。
 * 三条 [StateFlow] 只在主线程收集，实现必须保证发射线程安全。
 */
interface EngineClient {

    /** 连接状态机。界面的唯一真相来源。 */
    val state: StateFlow<ConnectionState>

    /** 当前房间成员。未在房间时为空表。 */
    val members: StateFlow<List<RoomMember>>

    /** 链路指标。未接通时为 [LinkStats.EMPTY]。 */
    val linkStats: StateFlow<LinkStats>

    /** 本机网络环境画像，诊断页用。 */
    val networkProfile: StateFlow<NetworkProfile?>

    /**
     * 建房。返回房间码。
     *
     * Host 的虚拟网卡在这一步就要建起来——`TunBridge` 是先建 TUN 再接对端，
     * 房间建好但 TUN 没起，后面 guest 接进来会没有落点。
     */
    suspend fun createRoom(): Result<String>

    /** 加入房间。 */
    suspend fun joinRoom(roomCode: String): Result<Unit>

    /** 离开当前房间，但保留信令连接。 */
    suspend fun leaveRoom()

    /** 断开一切：隧道、房间、信令。 */
    suspend fun disconnect()

    /** 失败后重试当前房间。 */
    suspend fun retry()

    /** 重新跑一次网络环境探测，诊断页那个动作。 */
    suspend fun probeNetwork()

    /** 打包并上传日志，返回服务端受理的字节数。 */
    suspend fun uploadLogs(reason: String): Result<Long>
}

/** 房间成员。 */
data class RoomMember(
    val id: String,
    val displayName: String,
    val virtualIp: String,
    val isHost: Boolean,
    val isSelf: Boolean,
    /** 本机到该成员的往返延迟；本机自己与尚未接通的成员为 null。 */
    val latencyMillis: Int?,
    /** 与该成员之间的传输方式；未接通为 null。 */
    val transport: Transport?,
)

/** 链路指标。 */
data class LinkStats(
    val latencyMillis: Int?,
    val lossPercent: Double?,
    val upMbps: Double?,
    val downMbps: Double?,
    /** 近 60 秒延迟采样，画火花线用。最新值在末尾。 */
    val latencyHistory: List<Int>,
) {
    companion object {
        val EMPTY = LinkStats(null, null, null, null, emptyList())
    }
}

/** 网络环境画像。 */
data class NetworkProfile(
    val natClass: NatClass,
    /** 多次 STUN 探测的公网映射是否一致。不一致说明是对称型行为。 */
    val mappingStable: Boolean,
    val ipv6Available: Boolean,
    /** 与 core 的 `tun_bridge::TUN_MTU` 同源。 */
    val mtu: Int,
)

enum class NatClass {
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    Unknown,
    ;

    val displayLabel: String
        get() = when (this) {
            FullCone -> "完全锥型"
            RestrictedCone -> "受限锥型"
            PortRestrictedCone -> "端口受限锥型"
            Symmetric -> "对称型"
            Unknown -> "未知"
        }
}
