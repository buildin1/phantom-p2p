package com.buildin1.phantom_p2p.engine

/**
 * 连接状态机。
 *
 * **这是一个密封类型，不是字符串。** 旧版本用一个自由文本 `connectionMode`
 * 同时做展示和判断，结果是展示逻辑和业务判断改一处崩另一处。这里把两件事
 * 彻底分开：状态机只描述事实，界面文案一律从它派生（见 [displayTitle]）。
 */
sealed interface ConnectionState {

    /** 未连接。没有房间，也没有隧道。 */
    data object Idle : ConnectionState

    /** 正在接通。[phase] 驱动接线台构件的推进动效。 */
    data class Connecting(
        val roomCode: String,
        val phase: PunchPhase,
        val elapsedMillis: Long,
    ) : ConnectionState

    /** 已接通。 */
    data class Connected(
        val roomCode: String,
        val transport: Transport,
        val localVirtualIp: String,
        val peerVirtualIp: String,
        val connectedSinceMillis: Long,
    ) : ConnectionState

    /** 没能接通。[reason] 只用于选文案，真实原因进日志。 */
    data class Failed(
        val roomCode: String?,
        val reason: FailureReason,
    ) : ConnectionState
}

/**
 * 打洞阶段。对应 core 的 `puncher::PunchPhase`，但**用户可见文案是另一套**：
 * 界面上说「正在接通」，不说「打洞」「ICE」「候选」这些词。
 */
enum class PunchPhase {
    /** 探测本机网络环境（NAT 画像、STUN 映射）。 */
    Probing,

    /** 已上报画像，等对端就位。 */
    WaitingPeer,

    /** 正在打洞。 */
    Punching,

    /** 通道已通，正在建隧道与虚拟网卡。 */
    EstablishingTunnel,
    ;

    /** 界面文案。刻意说人话——用户不需要知道 ICE 是什么。 */
    val displayLabel: String
        get() = when (this) {
            Probing -> "探测网络环境"
            WaitingPeer -> "与对端交换线路"
            Punching -> "正在接通"
            EstablishingTunnel -> "建立隧道"
        }
}

/**
 * 传输方式。
 *
 * **这是整个界面层最需要小心的一个类型。**
 *
 * 内部必须精确区分直连与中继：遥测、日志、中继槽位回收、静默升级重试全都依赖它。
 * 但界面上两者一律显示「P2P 直连」，只有括号里的后缀不同——[Udp] 是真直连，
 * [Quic] 实际走中继。这是刻意设计，不是缺陷：出现「中继」二字会给用户造成
 * 「我这条是次一等的连接」的心理阻碍，而绝大多数用户并不需要知道这个区别。
 *
 * 因此：**界面任何位置不得出现「中继」字样**，开发者通过传输后缀与日志解码。
 */
enum class Transport {
    /** 真 P2P 直连。 */
    Udp,

    /** 经中继转发。界面上仍然叫「P2P 直连」，只是后缀是 QUIC。 */
    Quic,
    ;

    /** 主状态文案。两者都是「P2P 直连」，只有后缀不同。 */
    val displayLabel: String
        get() = when (this) {
            Udp -> "P2P 直连 (UDP)"
            Quic -> "P2P 直连 (QUIC)"
        }

    /** 成员行右下角那个短标签。 */
    val shortLabel: String
        get() = when (this) {
            Udp -> "UDP"
            Quic -> "QUIC"
        }
}

/** 失败原因。只用来选一段可执行的建议文案，不向用户暴露错误码。 */
enum class FailureReason {
    /** 打洞与中继都没成功。 */
    PeerUnreachable,

    /** 信令连不上。 */
    SignalUnavailable,

    /** 房间码不存在或已关闭。 */
    RoomGone,

    /** 用户拒绝了 VPN 权限。 */
    VpnPermissionDenied,

    /** 服务端说协议版本对不上。 */
    VersionMismatch,

    /** 其余：真实原因在日志里。 */
    Unknown,
    ;

    val displayTitle: String
        get() = when (this) {
            PeerUnreachable -> "没能接通"
            SignalUnavailable -> "连不上服务器"
            RoomGone -> "房间不在了"
            VpnPermissionDenied -> "需要 VPN 权限"
            VersionMismatch -> "需要更新"
            Unknown -> "没能接通"
        }

    /** 说清下一步怎么办。不道歉、不含糊、不抛错误码。 */
    val displayAdvice: String
        get() = when (this) {
            PeerUnreachable -> "对方网络暂时不可达，可以再试一次"
            SignalUnavailable -> "检查一下网络，稍后再试"
            RoomGone -> "房主可能已经关闭了房间，跟他要个新房间码"
            VpnPermissionDenied -> "接通需要建立本机虚拟网卡，在系统弹窗里点「确定」即可"
            VersionMismatch -> "服务端已经升级，请更新到最新版本"
            Unknown -> "可以再试一次，或到诊断页反馈问题"
        }
}

/** 主状态标题。界面上那行大字全部走这里，不要在页面里各写各的。 */
val ConnectionState.displayTitle: String
    get() = when (this) {
        is ConnectionState.Idle -> "线路空闲"
        is ConnectionState.Connecting -> phase.displayLabel
        is ConnectionState.Connected -> transport.displayLabel
        is ConnectionState.Failed -> reason.displayTitle
    }

/**
 * 当前房间码。
 *
 * **注意这里覆盖了 Connecting 状态。** 建房时房间码在服务端应答的那一刻就有了，
 * 但隧道要再过一两秒才建好。只认 Connected 的话，用户点完「创建房间」跳到房间页
 * 会看到「还没有加入房间」的空态 —— 看起来就像创建失败了。
 */
val ConnectionState.roomCode: String?
    get() = when (this) {
        is ConnectionState.Idle -> null
        is ConnectionState.Connecting -> roomCode
        is ConnectionState.Connected -> roomCode
        is ConnectionState.Failed -> roomCode
    }

/** 顶栏那颗状态药丸的文案。 */
val ConnectionState.pillLabel: String
    get() = when (this) {
        is ConnectionState.Idle, is ConnectionState.Failed -> "未连接"
        is ConnectionState.Connecting -> "连接中"
        is ConnectionState.Connected -> "已连接"
    }
