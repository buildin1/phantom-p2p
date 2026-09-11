package com.buildin1.phantom_p2p.engine

import com.buildin1.phantom_p2p.update.AppUpdateInfo
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

    /** 本机网络环境画像，连接过程中顺带得到的轻量版。 */
    val networkProfile: StateFlow<NetworkProfile?>

    /** 最近一次完整诊断的结果，还没跑过为 null。 */
    val diagnostics: StateFlow<NetworkDiagnostics?>

    /** 诊断进行中的进度；不在跑时为 null。界面靠它出检测动画。 */
    val diagnosticsProgress: StateFlow<DiagnosticsProgress?>

    /** 最近一次诊断的失败原因，成功或未跑过为 null。 */
    val diagnosticsError: StateFlow<String?>

    /**
     * 云端下发的版本通告，没有则为 null。
     *
     * 服务端在鉴权后按平台与版本判断要不要发 —— 版本策略全在服务端，
     * 调整策略不需要发客户端。
     */
    val appUpdate: StateFlow<AppUpdateInfo?>

    /**
     * 当前房间的邀请令牌，没有时为 null。二维码与分享链接的内容。
     *
     * 令牌由**服务端**签发，客户端不参与生成。曾经考虑过客户端自己把房间码
     * 编码成一长串，被否掉了：加入房间本来就要联网，"必须离线解码"这个约束
     * 不存在；而且信令服务端是开源的，客户端再藏一份密钥是双重无意义。
     * 安全性来自随机数与服务端状态，不来自算法保密。
     */
    val inviteToken: StateFlow<InviteToken?>

    /**
     * 索要邀请失败的原因；成功或未索要过为 null。
     *
     * 主要覆盖一个具体场景：**新客户端连到了没更新的信令服务端**。
     * 老服务端不认识 `RequestInviteToken`，只会在自己日志里 warn 一行、
     * 连接照常 —— 于是客户端永远等不到应答，二维码卡在「正在生成」。
     * 超时后把它翻成一句人话，让用户改用房间码。
     */
    val inviteError: StateFlow<String?>

    /**
     * 建房。返回房间码。
     *
     * Host 的虚拟网卡在这一步就要建起来——`TunBridge` 是先建 TUN 再接对端，
     * 房间建好但 TUN 没起，后面 guest 接进来会没有落点。
     */
    suspend fun createRoom(): Result<String>

    /** 加入房间。 */
    suspend fun joinRoom(roomCode: String): Result<Unit>

    /**
     * 用邀请令牌加入房间（扫码或点深链进来的路径）。
     *
     * 与 [joinRoom] 是同一条流程，只是不需要人去念那 6 位房间码。
     */
    suspend fun joinByToken(token: String): Result<Unit>

    /**
     * 索要当前房间的邀请令牌（仅房主有效）。
     *
     * @param refresh true 时先作废旧令牌再签发 —— 「二维码截图发错群了」时用。
     */
    suspend fun requestInviteToken(refresh: Boolean = false)

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

/**
 * 一张有效的邀请。
 *
 * [uri] 是二维码与分享链接的实际内容。用自定义 scheme 而不是 https：
 * 走 https 要自建 web 落地页、配 Android App Links 校验和 iOS AASA 文件，
 * 还会把信令域名印在每一张二维码上。代价是没装应用的人扫了没反应 ——
 * 这是自定义 scheme 的固有取舍，已确认接受。
 */
data class InviteToken(
    val token: String,
    val roomCode: String,
) {
    val uri: String get() = "$SCHEME_PREFIX$token"

    companion object {
        const val SCHEME_PREFIX = "phantom://j/"

        /** 从扫码/深链拿到的文本里抽出令牌；不是本应用的邀请则返回 null。 */
        fun parse(raw: String): String? {
            val text = raw.trim()
            val token = when {
                text.startsWith(SCHEME_PREFIX, ignoreCase = true) ->
                    text.removePrefix(SCHEME_PREFIX).removePrefix("/")
                // 裸令牌：用户从别处复制了一串过来，也认。
                else -> text
            }.uppercase().filter(Char::isLetterOrDigit)
            return token.takeIf { it.length == TOKEN_LENGTH }
        }

        /** 与服务端 `issue_invite_token` 的长度一致，改一处必须改两处。 */
        const val TOKEN_LENGTH = 20
    }
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

/**
 * 完整的网络诊断报告。
 *
 * 与 PC 端 `NetworkInfo`（`src-tauri/src/lib.rs`）一一对应，底层用的也是
 * core 里的同几个函数（`stun::query_dual_async` / `nat::analyze_multi_round`
 * / `network::detect_upnp` / `network::detect_local_network`），所以两端的
 * 结论必然一致 —— 用户拿手机和电脑各测一次，看到的不该是两套说法。
 *
 * 与 [NetworkProfile] 的分工：后者是**连接过程中**顺带得到的轻量画像，
 * 打洞策略用；这个是**用户主动点「重新检测」**时跑的完整报告，给人看。
 */
data class NetworkDiagnostics(
    val natType: String,
    val natTypeKey: String,
    val natDifficulty: String,
    val externalIp: String,
    val externalPort: Int,
    val upnp: Boolean,
    val upnpPort: Int,
    val ipv6: Boolean,
    val ipv6Addr: String,
    val localIp: String,
    val localPort: Int,
    val stunDetails: List<StunDetail>,
    val portPattern: String,
    val mappingBehavior: String,
    val filteringBehavior: String,
    val confidence: String,
    val rounds: Int,
    val networkPriority: String,
    val mtu: Int,
)

/** 单台 STUN 服务器的一次采样。 */
data class StunDetail(
    val server: String,
    val mapping: String,
    val rttMillis: Int,
    /** 采样用的是哪个 socket（A / B）。两者映射端口是否一致是判型的直接证据。 */
    val socket: String,
    val round: Int,
)

/** 诊断的实时进度。null 表示当前没有在跑。 */
data class DiagnosticsProgress(
    /** 0..100 */
    val percent: Int,
    val stage: String,
    val etaSeconds: Int,
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
