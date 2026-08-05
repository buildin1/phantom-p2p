//! 幻梦P2P 共享消息协议
//!
//! 客户端和服务端共用的消息类型定义。
//! 序列化使用 MessagePack (rmp-serde)，比 JSON 更小更快。
//!
//! # 协议版本
//!
//! 本协议**不做向后兼容**。版本不匹配时服务端直接拒绝并要求升级，
//! 而不是维护兼容层——兼容层会迅速堆成无法维护的代码。
//! 见 [`PROTOCOL_VERSION`]。
//!
//! # 打洞三阶段
//!
//! ```text
//! 阶段一  客户端 NatProfileReport  →  服务端凑齐双方  →  PunchPlan（策略+角色+参数）
//! 阶段二  客户端 StrategyCandidates →  服务端转发      →  （仅困难组合需要）
//! 阶段三  服务端 PunchStart（统一起始时刻）→  双方定向打洞  →  PunchReport（遥测）
//! ```
//!
//! 简单组合（IPv6 直连 / 同网段 / 双 Cone）跳过阶段二，
//! 服务端在下发 PunchPlan 后立即下发 PunchStart。

use serde::{Deserialize, Serialize};

/// 协议版本号。
///
/// 客户端在 [`ClientMessage::Auth`] 中声明，服务端不匹配则回
/// [`ServerMessage::VersionMismatch`]。**任何消息结构变更都必须递增此值**，
/// 否则会出现难以定位的反序列化失败。
///
/// - `4`：数据面引入中继 DATAGRAM 转发。中继必须转发 DATAGRAM，
///   旧中继无法承载新数据面，故递增版本挡住不匹配的组合。
/// - `5`：新增中继补包求援（`RelayAssistRequest` 等）。丢包修复本身靠
///   **带内探测**协商（见 `phantom_core::repair`），与旧客户端可自动回退；
///   但求援需要服务端参与带宽调度，旧服务端不认识这些消息。
pub const PROTOCOL_VERSION: u32 = 5;

// ============================================================
// ICE 候选
// ============================================================

/// ICE 候选地址类型（RFC 8445 §5.1.1）
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateType {
    /// 主机候选：本机实际网卡 IP
    Host,
    /// 服务器反射候选：通过 STUN 探测到的公网 IP:port
    ServerReflexive,
    /// 中继候选：通过 TURN/中继服务器分配
    Relay,
    /// 策略候选：按打洞策略生成的预测/撒网目标，或本端新开 socket 的映射
    Strategy,
}

/// ICE 候选地址（RFC 8445 §5.1.1）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    /// 候选 IP 地址
    pub ip: String,
    /// 候选端口
    pub port: u16,
    /// 候选类型
    pub ctype: CandidateType,
    /// ICE 优先级（RFC 8445 §5.1.2.1）
    pub priority: u32,
    /// 候选基础标识（同源候选相同）
    pub foundation: String,
}

/// 预分配中继信息（客户端侧缓存用）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPreAllocInfo {
    pub room_code: String,
    pub relay_addr: String,
    pub token: String,
}

// ============================================================
// NAT 分类与画像
// ============================================================

/// NAT 分类（**策略选择专用的三分类**）
///
/// 打洞策略只关心"端口能不能预测"，锥形 NAT 的三个子类（NAT1/2/3）
/// 在打洞时行为一致，分得更细没有收益。细分类仅用于展示与遥测，
/// 见 [`NatProfile::detail`]。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NatClass {
    /// 锥形：端点无关映射，出口端口对所有目标一致
    Cone,
    /// 线性对称：每个目标一个新端口，但**步进可预测**
    LinearSymmetric,
    /// 随机对称：每个目标一个新端口且**不可预测**
    RandomSymmetric,
    /// 探测失败或数据不足
    Unknown,
}

impl NatClass {
    /// 是否为对称 NAT（出口端口随目标变化）
    pub fn is_symmetric(&self) -> bool {
        matches!(self, NatClass::LinearSymmetric | NatClass::RandomSymmetric)
    }

    /// 出口端口是否可被对端预测
    pub fn is_predictable(&self) -> bool {
        matches!(self, NatClass::Cone | NatClass::LinearSymmetric)
    }
}

/// 网络接入类型（遥测维度）
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkType {
    Ethernet,
    Wifi,
    Cellular,
    Unknown,
}

/// 本端 NAT 画像——阶段一上报的核心数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatProfile {
    /// 策略选择用的三分类
    pub class: NatClass,
    /// 细分类展示名（如 "port_restricted_cone"），仅用于展示与遥测
    pub detail: String,
    /// 最近一次 STUN 探测到的映射端口，端口预测的基准
    pub base_port: u16,
    /// 线性步进；`0` 表示不适用（非线性对称）
    pub step: i32,
    /// 步进判定置信度 `0.0..=1.0`
    pub step_confidence: f32,
    /// 探测采样到的端口序列，供服务端复核与遥测
    pub sample_ports: Vec<u16>,
    /// 探测到的公网 IPv4
    pub public_ip: Option<String>,
    /// 是否有可用的全局 IPv6（**已验证连通**，不只是有地址）
    pub has_ipv6: bool,
    /// 全局 IPv6 地址列表
    pub ipv6_addrs: Vec<String>,
    /// 接入类型
    pub network_type: NetworkType,
    /// 本端到信令服务器的实测 RTT（毫秒），供服务端计算同步窗口
    pub signal_rtt_ms: u32,
    /// 本端为本次会话生成的**临时** X25519 公钥。
    ///
    /// NatProfile 本就会经服务端双向转发给对端，是天然的密钥交换载体。
    /// 双方各自与对端公钥做 DH，派生出 overlay 数据面的会话密钥——
    /// 中继模式下 QUIC 是逐跳加密的，中继能看到明文，
    /// 机密性必须由 overlay 这一层提供。
    #[serde(with = "serde_bytes_array_32")]
    pub eph_public: [u8; 32],
    /// 用长期 Ed25519 身份密钥对 `eph_public` 的签名。
    ///
    /// 必需：信令服务器同时也是中继运营方，若临时公钥不签名，
    /// 它可以替换双方公钥完成中间人攻击。
    #[serde(with = "serde_bytes_array_64")]
    pub eph_signature: [u8; 64],
    /// 本端长期身份公钥，供对端验签
    #[serde(with = "serde_bytes_array_32")]
    pub identity_public: [u8; 32],
}

// ============================================================
// 打洞策略矩阵
// ============================================================

/// 打洞策略。命名方向为 **本端 → 对端**。
///
/// 完整语义见《修复策略与需求分析》§3.3。三条关键原则：
///
/// - **原则 A**：可预测的一侧必须"安静"——每向一个新目标发包就推进自己的
///   端口计数器，会让对端的预测作废。见 [`PunchParams::quiet`]。
/// - **原则 B**：撒网成本不对称——锥形侧撒 K 个目标只需 1 个 socket，
///   对称侧则需要 K 个 socket。所以撒网由锥形侧承担。
/// - **原则 C**：撒网只是"开门"，让对端的包能穿过本端 NAT 的入向过滤；
///   真正建立连接靠 triggered check（从收到的包里学到对端真实地址后立即回包）。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PunchStrategy {
    /// IPv6 直连：无 NAT，只需打开双方状态防火墙
    DirectIpv6,
    /// 同一公网出口，尝试内网直连
    DirectLan,
    /// 双锥形：双方端口都固定且已知，最简单
    ConeToCone,
    /// #1 本端锥形 → 对端线性对称：本端按步进预测对端端口
    ConeToLinear,
    /// #2 本端线性对称 → 对端锥形：**本端必须安静**，只打对端固定端口
    LinearToCone,
    /// #3 本端锥形 → 对端随机对称：本端向对端大范围撒网
    ConeToRandom,
    /// #4 本端随机对称 → 对端锥形：**本端开 N 个 socket** 打对端固定端口
    RandomToCone,
    /// #5 双线性对称：双方各自预测对方，双方都必须安静
    BothLinear,
    /// #6 本端线性 → 对端随机：本端少量 socket 撒网，需控制端口漂移
    LinearToRandom,
    /// #7 本端随机 → 对端线性：本端开 N 个 socket 打对端预测端口
    RandomToLinear,
    /// #8 双随机对称：生日悖论双向撒网，成本最高
    BothRandom,
    /// 无法打洞，直接走中继
    RelayOnly,
}

impl PunchStrategy {
    /// 按 (本端, 对端) NAT 分类选择策略。
    ///
    /// 这是策略矩阵的**唯一真相来源**，服务端与客户端共用，保证两侧一致。
    /// `ipv6_both` / `same_public_ip` 为快速通道条件，优先级最高。
    pub fn select(
        local: NatClass,
        remote: NatClass,
        ipv6_both: bool,
        same_public_ip: bool,
    ) -> PunchStrategy {
        if ipv6_both {
            return PunchStrategy::DirectIpv6;
        }
        if same_public_ip {
            return PunchStrategy::DirectLan;
        }
        use NatClass::*;
        match (local, remote) {
            // 任一侧探测失败：按最保守的锥形处理，仍然值得一试
            (Unknown, _) | (_, Unknown) => PunchStrategy::ConeToCone,
            (Cone, Cone) => PunchStrategy::ConeToCone,
            (Cone, LinearSymmetric) => PunchStrategy::ConeToLinear,
            (LinearSymmetric, Cone) => PunchStrategy::LinearToCone,
            (Cone, RandomSymmetric) => PunchStrategy::ConeToRandom,
            (RandomSymmetric, Cone) => PunchStrategy::RandomToCone,
            (LinearSymmetric, LinearSymmetric) => PunchStrategy::BothLinear,
            (LinearSymmetric, RandomSymmetric) => PunchStrategy::LinearToRandom,
            (RandomSymmetric, LinearSymmetric) => PunchStrategy::RandomToLinear,
            (RandomSymmetric, RandomSymmetric) => PunchStrategy::BothRandom,
        }
    }

    /// 本策略下，本端是否需要新建额外 socket（决定是否走阶段二二次交换）
    pub fn needs_strategy_candidates(&self) -> bool {
        PunchParams::for_strategy(*self).local_socket_count > 1
    }

    /// 供遥测使用的稳定字符串标识
    pub fn as_str(&self) -> &'static str {
        match self {
            PunchStrategy::DirectIpv6 => "direct_ipv6",
            PunchStrategy::DirectLan => "direct_lan",
            PunchStrategy::ConeToCone => "cone_to_cone",
            PunchStrategy::ConeToLinear => "cone_to_linear",
            PunchStrategy::LinearToCone => "linear_to_cone",
            PunchStrategy::ConeToRandom => "cone_to_random",
            PunchStrategy::RandomToCone => "random_to_cone",
            PunchStrategy::BothLinear => "both_linear",
            PunchStrategy::LinearToRandom => "linear_to_random",
            PunchStrategy::RandomToLinear => "random_to_linear",
            PunchStrategy::BothRandom => "both_random",
            PunchStrategy::RelayOnly => "relay_only",
        }
    }
}

/// 目标端口的生成方式
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetPortMode {
    /// 对端端口固定且已知，只打这一个
    Fixed,
    /// 按对端的 `base_port + k * step` 线性预测
    LinearPredict,
    /// 对端端口不可预测，大范围撒网
    RandomSpray,
}

/// 本端在本次打洞中的行为参数（由服务端按策略下发）
///
/// 参数取值目前是**待标定的起点值**，不是 UU 的实测值——
/// UU 的数值常量编译成立即数，逆向拿不到。标定方法见《任务清单》C6。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PunchParams {
    /// 本端需要新建的 socket 数量；`1` 表示复用已有的探测 socket
    pub local_socket_count: u16,
    /// 目标端口生成方式
    pub target_port_mode: TargetPortMode,
    /// 目标端口数量（预测深度或撒网宽度）
    pub target_port_count: u16,
    /// 每轮发包间隔（毫秒）
    pub send_interval_ms: u32,
    /// 打洞总窗口（毫秒）
    pub window_ms: u32,
    /// **原则 A**：为 true 时本端必须安静——
    /// 除策略指定的目标外禁止任何额外发包，否则会推乱自己的端口计数器，
    /// 导致对端对本端的预测失效。
    pub quiet: bool,
}

impl PunchParams {
    /// 取本端在该策略下的参数。策略方向为"本端 → 对端"，
    /// 因此对端的参数由服务端用镜像策略单独计算。
    pub fn for_strategy(strategy: PunchStrategy) -> PunchParams {
        use PunchStrategy::*;
        use TargetPortMode::*;
        // 基准值：间隔 20ms、窗口 12s（12s 与 UU 一致，是逆向实证）
        const INTERVAL: u32 = 20;
        const WINDOW: u32 = 12_000;
        let (sockets, mode, count, quiet) = match strategy {
            // ---- 快速通道：目标明确，无需撒网 ----
            DirectIpv6 | DirectLan | ConeToCone => (1, Fixed, 1, false),

            // ---- 锥形侧：撒网便宜（1 socket 发多包），由它承担撒网 ----
            ConeToLinear => (1, LinearPredict, 16, false),
            ConeToRandom => (1, RandomSpray, 64, false),

            // ---- 对称侧对锥形：本端端口不可控，靠 socket 数量堆概率 ----
            // 对端锥形端口固定，所以目标只有一个，全部 socket 打同一目标
            RandomToCone => (32, Fixed, 1, false),
            // 线性对称侧必须安静：只用 1 个 socket，让对端能预测本端端口
            LinearToCone => (1, Fixed, 1, true),

            // ---- 双线性：双方各自预测对方，双方都安静 ----
            BothLinear => (1, LinearPredict, 16, true),

            // ---- 线性 ↔ 随机 混合 ----
            // 线性侧：socket 数必须受控，每多一个都会推进端口计数器
            LinearToRandom => (4, RandomSpray, 64, false),
            // 随机侧：多开 socket，打对端的预测端口
            RandomToLinear => (32, LinearPredict, 16, false),

            // ---- 双随机：生日悖论，双向撒网，成本最高 ----
            BothRandom => (32, RandomSpray, 64, false),

            // ---- 不打洞 ----
            RelayOnly => (0, Fixed, 0, false),
        };
        PunchParams {
            local_socket_count: sockets,
            target_port_mode: mode,
            target_port_count: count,
            send_interval_ms: INTERVAL,
            window_ms: WINDOW,
            quiet,
        }
    }
}

// ============================================================
// 服务端下发的网络配置
// ============================================================

/// STUN 服务器条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StunServerInfo {
    /// 主机名或 IP
    pub host: String,
    /// 端口
    pub port: u16,
    /// 是否为自建服务器（自建优先使用）
    pub is_self_hosted: bool,
}

/// 服务端下发的网络配置。
///
/// **客户端不得内置任何端口常量或 STUN 地址**，一律由此下发，
/// 便于部署方通过服务端 config 调整而无需重新发版。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// STUN 服务器列表，按优先级排序（自建在前）
    pub stun_servers: Vec<StunServerInfo>,
    /// 中继服务器地址
    pub relay_addr: String,
    /// 中继 QUIC 端口（全局单端口，所有房间共用）
    pub relay_quic_port: u16,
}

// ============================================================
// 遥测：结构化打洞记录
// ============================================================

/// 打洞结果
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PunchOutcome {
    /// P2P 直连成功
    P2pSuccess,
    /// 打洞窗口超时
    PunchTimeout,
    /// 检测到防火墙阻断，主动放弃
    FirewallBlocked,
    /// STUN 探测失败，拿不到 srflx 候选
    NoSrflx,
    /// 策略判定为不可打洞
    StrategyUnsupported,
    /// 已回退到中继
    RelayFallback,
}

/// 一次打洞尝试的完整结构化记录。
///
/// **一次连接尝试产出一条记录**，而不是散落几百行文本日志。
/// 这是服务端聚合分析的输入，用于回答"每种 NAT 组合的真实成功率是多少"。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchRecord {
    /// 关联本次尝试的唯一 ID（由服务端在 PunchPlan 中下发）
    pub attempt_id: String,
    pub room_code: String,
    pub peer_session_id: String,
    /// 本端是否为 Host
    pub is_host: bool,

    // ---- NAT 与网络环境 ----
    pub local_nat_class: NatClass,
    pub local_nat_detail: String,
    pub remote_nat_class: NatClass,
    pub local_network_type: NetworkType,
    /// 本端公网出口 IP（完整上报，用于 ISP/地域维度分析）
    pub local_public_ip: Option<String>,
    pub local_has_ipv6: bool,
    pub remote_has_ipv6: bool,

    // ---- 策略 ----
    pub strategy: PunchStrategy,
    pub params: PunchParams,
    pub local_candidate_count: u16,
    pub remote_candidate_count: u16,

    // ---- 结果 ----
    pub outcome: PunchOutcome,
    /// 成功时最终选中的候选类型
    pub selected_candidate_type: Option<CandidateType>,
    /// 失败时的补充说明
    pub failure_detail: Option<String>,

    // ---- 分阶段计时（毫秒）----
    /// NAT 探测 + 基础候选收集耗时
    pub gather_ms: u32,
    /// 信令 RTT
    pub signal_rtt_ms: u32,
    /// 双方实际启动打洞的时刻偏差（衡量同步质量）
    pub punch_start_skew_ms: i32,
    /// 从开始打洞到连通的耗时
    pub p2p_establish_ms: u32,
    /// 从发起连接到最终可用的总耗时
    pub total_ms: u32,

    // ---- 链路质量 ----
    pub final_rtt_ms: u32,
    pub loss_rate: f32,

    // ---- 环境 ----
    pub client_version: String,
    pub os: String,
}

// ============================================================
// 客户端 → 服务端 消息
// ============================================================

/// serde 辅助：将 [u8; 32] 作为字节序列（而非数组）序列化
mod serde_bytes_array_32 {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(bytes.as_slice(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let bytes: serde_bytes::ByteBuf = serde_bytes::deserialize(d)?;
        let v = bytes.into_vec();
        v.try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

/// serde 辅助：将 [u8; 64] 作为字节序列（而非数组）序列化
mod serde_bytes_array_64 {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(bytes.as_slice(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: serde_bytes::ByteBuf = serde_bytes::deserialize(d)?;
        let v = bytes.into_vec();
        v.try_into()
            .map_err(|_| D::Error::custom("expected 64 bytes"))
    }
}

/// 客户端发往服务端的消息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum ClientMessage {
    /// 心跳。携带客户端时间戳，供双方测算信令 RTT 与时钟偏差
    /// （C3.7 自适应同步窗口依赖它）。
    #[serde(rename = "ping")]
    Ping { client_time_ms: u64 },

    /// 创建房间
    #[serde(rename = "create_room")]
    CreateRoom,

    /// Host TUN is ready and the room can accept guests.
    #[serde(rename = "host_ready")]
    HostReady,

    /// 加入房间
    #[serde(rename = "join_room")]
    JoinRoom { room_code: String },

    /// 离开当前房间
    #[serde(rename = "leave_room")]
    LeaveRoom,

    /// 关闭房间（仅 host 可操作）
    #[serde(rename = "close_room")]
    CloseRoom,

    /// 鉴权响应（签名 nonce）。同时声明协议版本供服务端校验。
    #[serde(rename = "auth")]
    Auth {
        #[serde(with = "serde_bytes_array_32")]
        public_key: [u8; 32],
        #[serde(with = "serde_bytes_array_64")]
        signature: [u8; 64],
        /// 客户端协议版本，见 [`PROTOCOL_VERSION`]
        protocol_version: u32,
        /// 客户端展示版本（如 "2.7.7"），仅用于遥测与提示
        client_version: String,
    },

    /// 请求中继（打洞失败后）
    #[serde(rename = "relay_request")]
    RelayRequest,

    /// **阶段一**：上报本端 NAT 画像与基础候选（host + srflx）。
    ///
    /// 此处**不得包含**任何预测/撒网候选——那些要等服务端下发策略后，
    /// 在阶段二用 [`ClientMessage::StrategyCandidates`] 上报。
    #[serde(rename = "nat_profile")]
    NatProfileReport {
        /// Host 面向特定 Guest 上报时填写；Guest 上报填 None
        #[serde(default)]
        target_peer_session_id: Option<String>,
        profile: NatProfile,
        base_candidates: Vec<IceCandidate>,
    },

    /// **阶段二**：上报按策略生成的候选（含本端新建 socket 的映射）
    #[serde(rename = "strategy_candidates")]
    StrategyCandidates {
        target_peer_session_id: String,
        attempt_id: String,
        candidates: Vec<IceCandidate>,
    },

    /// **阶段三之后**：上报本次打洞的结构化结果（成功失败都要报）
    #[serde(rename = "punch_report")]
    PunchReport { record: PunchRecord },

    /// 请求服务端触发静默中继升级
    #[serde(rename = "relay_upgrade_request")]
    RelayUpgradeRequest,

    /// 求援：P2P 直连丢包已经补不回来了，申请借用中继**只用来补包**。
    ///
    /// 与 [`RelayUpgradeRequest`] 的区别是不切走全部流量：原包继续走 P2P，
    /// 只有补包走中继。同样丢包程度下中继带宽占用低数倍，
    /// 所以服务端能同时照顾更多房间。
    #[serde(rename = "relay_assist_request")]
    RelayAssistRequest {
        /// 本端观测到的入方向丢包率（万分之一），供服务端评估该放行多少
        loss_bp: u16,
    },

    /// 补包不再需要中继（链路恢复），主动交还额度
    #[serde(rename = "relay_assist_release")]
    RelayAssistRelease,

    /// Request a persistent virtual address for future Host rooms.
    #[serde(rename = "request_fixed_host_ip")]
    RequestFixedHostIp,

    /// Release the persistent Host virtual address.
    #[serde(rename = "release_fixed_host_ip")]
    ReleaseFixedHostIp,

    /// Query the persistent Host virtual address.
    #[serde(rename = "get_fixed_host_ip")]
    GetFixedHostIp,

    /// 请求一个日志上传凭据（用户主动"反馈问题"时触发）。
    ///
    /// 服务端校验通过后回 [`ServerMessage::RequestLogUpload`]，
    /// 其中带一次性 URL；客户端再走独立 HTTP POST 上传日志包，
    /// 不占用信令连接。
    #[serde(rename = "request_log_upload")]
    RequestLogUpload { reason: String },

    /// 上报本次连接最终采用的模式（"p2p" 或 "relay"）。
    ///
    /// 服务端收到 `"p2p"` 时**必须释放该房间预分配的中继槽位**，
    /// 否则中继消耗量会等于房间总数而非失败房间数。
    #[serde(rename = "report_connection_mode")]
    ReportConnectionMode { mode: String },
}

// ============================================================
// 服务端 → 客户端 消息
// ============================================================

/// 服务端发往客户端的消息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum ServerMessage {
    /// 连接成功，返回 session_id 与服务端协议版本
    #[serde(rename = "welcome")]
    Welcome {
        session_id: String,
        protocol_version: u32,
    },

    /// 心跳响应，回显客户端时间戳并附带服务端时间
    #[serde(rename = "pong")]
    Pong {
        client_time_ms: u64,
        server_time_ms: u64,
    },

    /// 协议版本不匹配——**不提供兼容层**，客户端必须升级
    #[serde(rename = "version_mismatch")]
    VersionMismatch {
        server_protocol_version: u32,
        client_protocol_version: u32,
        message: String,
    },

    /// 房间创建成功
    #[serde(rename = "room_created")]
    RoomCreated {
        room_code: String,
        subnet: String,
        virtual_ip: String,
    },

    /// 加入房间成功
    #[serde(rename = "join_ok")]
    JoinOk {
        room_code: String,
        host_session_id: String,
        /// 分配的虚拟子网段（如 "10.0.1" 表示 10.0.1.0/24）
        subnet: String,
        virtual_ip: String,
        host_virtual_ip: String,
    },

    /// 加入房间失败
    #[serde(rename = "join_failed")]
    JoinFailed { reason: String },

    /// 有新的 guest 加入（通知 host）
    #[serde(rename = "peer_joined")]
    PeerJoined {
        peer_session_id: String,
        guest_count: usize,
    },

    /// 有 guest 离开（通知 host）
    #[serde(rename = "peer_left")]
    PeerLeft {
        peer_session_id: String,
        guest_count: usize,
    },

    /// 房间被 host 关闭（通知 guest）
    #[serde(rename = "room_closed")]
    RoomClosed { reason: String },

    /// 通用错误
    #[serde(rename = "error")]
    Error { message: String },

    /// 鉴权挑战
    #[serde(rename = "auth_challenge")]
    AuthChallenge {
        #[serde(with = "serde_bytes_array_32")]
        nonce: [u8; 32],
    },

    /// 鉴权成功
    #[serde(rename = "auth_ok")]
    AuthOk { user_id: String },

    /// 下发网络配置（STUN 列表、中继地址与端口）。
    /// 鉴权成功后立即下发，配置变更时可重复下发。
    #[serde(rename = "network_config")]
    NetworkConfigUpdate { config: NetworkConfig },

    /// Persistent Host address status.
    #[serde(rename = "fixed_host_ip_status")]
    FixedHostIpStatus {
        enabled: bool,
        virtual_ip: Option<String>,
    },

    /// 鉴权失败
    #[serde(rename = "auth_failed")]
    AuthFailed { reason: String },

    /// 中继就绪
    #[serde(rename = "relay_ready")]
    RelayReady {
        room_code: String,
        relay_addr: String,
        relay_quic_port: u16,
        token: String,
    },

    /// 中继预分配完成
    #[serde(rename = "relay_pre_allocated")]
    RelayPreAllocated {
        room_code: String,
        relay_addr: String,
        relay_quic_port: u16,
        token: String,
    },

    /// 求援获准：可以借用中继补包
    #[serde(rename = "relay_assist_granted")]
    RelayAssistGranted {
        relay_addr: String,
        relay_quic_port: u16,
        token: String,
    },

    /// 求援被拒（通常是中继带宽已经排满）。
    ///
    /// 被拒不是错误：客户端退回纯 P2P 补包，尽力而为。
    /// 带宽是中继的硬约束，宁可让一个房间体验差一点，
    /// 也不能让所有房间一起被拖垮。
    #[serde(rename = "relay_assist_denied")]
    RelayAssistDenied { reason: String },

    /// **阶段一响应**：下发打洞计划（策略、本端参数、对端画像）。
    ///
    /// `needs_strategy_candidates` 为 false 时（快速通道），
    /// 服务端会紧接着下发 [`ServerMessage::PunchStart`]，客户端无需阶段二。
    #[serde(rename = "punch_plan")]
    PunchPlan {
        peer_session_id: String,
        attempt_id: String,
        strategy: PunchStrategy,
        /// 本端参数（对端的参数由对端自己收到，两者是镜像关系）
        params: PunchParams,
        /// 对端 NAT 画像，供本端生成预测/撒网目标
        peer_profile: NatProfile,
        /// 是否需要走阶段二二次交换
        needs_strategy_candidates: bool,
    },

    /// **阶段三**：下发对端完整候选，双方同时开打
    #[serde(rename = "punch_start")]
    PunchStart {
        peer_session_id: String,
        attempt_id: String,
        peer_candidates: Vec<IceCandidate>,
        /// **收到本消息后再等多少毫秒开始打洞**。
        ///
        /// 不用绝对时间戳：那要求两端与服务端的墙钟一致，而客户端时钟
        /// 偏差会**直接等量地破坏同步**——实测偏差曾达 3.5 秒，
        /// 远超同步窗口本身。
        ///
        /// 服务端为每一端单独计算：从统一的目标时刻减去**该端自己的**
        /// 单程延迟（RTT/2），于是 RTT 大的一方等得少、小的一方等得多，
        /// 两端实际起跑时刻对齐，且完全不依赖任何一方的时钟。
        start_delay_ms: u32,
    },

    /// 请求客户端上传完整日志包（排障用，走独立 HTTP POST）
    #[serde(rename = "request_log_upload")]
    RequestLogUpload { upload_url: String, reason: String },
}

// ============================================================
// 序列化/反序列化辅助函数
// ============================================================

/// 将消息序列化为 MessagePack 二进制
pub fn serialize<T: Serialize>(msg: &T) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec_named(msg)
}

/// 从 MessagePack 二进制反序列化消息
pub fn deserialize<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::from_slice(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> NatProfile {
        NatProfile {
            eph_public: [1u8; 32],
            eph_signature: [2u8; 64],
            identity_public: [3u8; 32],
            class: NatClass::Cone,
            detail: "port_restricted_cone".to_string(),
            base_port: 51820,
            step: 0,
            step_confidence: 0.0,
            sample_ports: vec![51820, 51820, 51820],
            public_ip: Some("1.2.3.4".to_string()),
            has_ipv6: false,
            ipv6_addrs: Vec::new(),
            network_type: NetworkType::Ethernet,
            signal_rtt_ms: 42,
        }
    }

    #[test]
    fn test_client_message_roundtrip() {
        let msg = ClientMessage::CreateRoom;
        let bytes = serialize(&msg).unwrap();
        let decoded: ClientMessage = deserialize(&bytes).unwrap();
        match decoded {
            ClientMessage::CreateRoom => {}
            _ => panic!("消息类型不匹配"),
        }
    }

    #[test]
    fn nat_profile_report_roundtrip() {
        let msg = ClientMessage::NatProfileReport {
            target_peer_session_id: Some("guest-42".to_string()),
            profile: sample_profile(),
            base_candidates: Vec::new(),
        };
        let bytes = serialize(&msg).unwrap();
        let decoded: ClientMessage = deserialize(&bytes).unwrap();
        match decoded {
            ClientMessage::NatProfileReport {
                target_peer_session_id,
                profile,
                ..
            } => {
                assert_eq!(target_peer_session_id.as_deref(), Some("guest-42"));
                assert_eq!(profile.class, NatClass::Cone);
                assert_eq!(profile.base_port, 51820);
            }
            _ => panic!("unexpected message"),
        }
    }

    #[test]
    fn punch_plan_roundtrip() {
        let msg = ServerMessage::PunchPlan {
            peer_session_id: "host-1".to_string(),
            attempt_id: "att-1".to_string(),
            strategy: PunchStrategy::RandomToCone,
            params: PunchParams::for_strategy(PunchStrategy::RandomToCone),
            peer_profile: sample_profile(),
            needs_strategy_candidates: true,
        };
        let bytes = serialize(&msg).unwrap();
        match deserialize::<ServerMessage>(&bytes).unwrap() {
            ServerMessage::PunchPlan {
                strategy, params, ..
            } => {
                assert_eq!(strategy, PunchStrategy::RandomToCone);
                assert_eq!(params.local_socket_count, 32);
                assert_eq!(params.target_port_mode, TargetPortMode::Fixed);
            }
            _ => panic!("unexpected message"),
        }
    }

    #[test]
    fn version_mismatch_roundtrip() {
        let msg = ServerMessage::VersionMismatch {
            server_protocol_version: PROTOCOL_VERSION,
            client_protocol_version: 1,
            message: "请升级客户端".to_string(),
        };
        let bytes = serialize(&msg).unwrap();
        match deserialize::<ServerMessage>(&bytes).unwrap() {
            ServerMessage::VersionMismatch {
                server_protocol_version,
                client_protocol_version,
                ..
            } => {
                assert_eq!(server_protocol_version, PROTOCOL_VERSION);
                assert_eq!(client_protocol_version, 1);
            }
            _ => panic!("unexpected message"),
        }
    }

    #[test]
    fn ping_pong_carries_timestamps() {
        let ping = ClientMessage::Ping {
            client_time_ms: 1_700_000_000_000,
        };
        let bytes = serialize(&ping).unwrap();
        match deserialize::<ClientMessage>(&bytes).unwrap() {
            ClientMessage::Ping { client_time_ms } => {
                assert_eq!(client_time_ms, 1_700_000_000_000)
            }
            _ => panic!("unexpected message"),
        }

        let pong = ServerMessage::Pong {
            client_time_ms: 1_700_000_000_000,
            server_time_ms: 1_700_000_000_050,
        };
        let bytes = serialize(&pong).unwrap();
        match deserialize::<ServerMessage>(&bytes).unwrap() {
            ServerMessage::Pong {
                client_time_ms,
                server_time_ms,
            } => {
                assert_eq!(server_time_ms - client_time_ms, 50);
            }
            _ => panic!("unexpected message"),
        }
    }

    // ---- 策略矩阵：8 种组合 + 快速通道 ----

    #[test]
    fn strategy_matrix_covers_all_nat_pairs() {
        use NatClass::*;
        use PunchStrategy as S;
        let cases = [
            (Cone, Cone, S::ConeToCone),
            (Cone, LinearSymmetric, S::ConeToLinear),
            (LinearSymmetric, Cone, S::LinearToCone),
            (Cone, RandomSymmetric, S::ConeToRandom),
            (RandomSymmetric, Cone, S::RandomToCone),
            (LinearSymmetric, LinearSymmetric, S::BothLinear),
            (LinearSymmetric, RandomSymmetric, S::LinearToRandom),
            (RandomSymmetric, LinearSymmetric, S::RandomToLinear),
            (RandomSymmetric, RandomSymmetric, S::BothRandom),
        ];
        for (local, remote, expected) in cases {
            assert_eq!(
                PunchStrategy::select(local, remote, false, false),
                expected,
                "({local:?}, {remote:?}) 的策略选择不正确"
            );
        }
    }

    #[test]
    fn fast_paths_take_priority_over_nat_matrix() {
        use NatClass::*;
        // IPv6 双方可用时，即使双随机对称也走 IPv6 直连
        assert_eq!(
            PunchStrategy::select(RandomSymmetric, RandomSymmetric, true, false),
            PunchStrategy::DirectIpv6
        );
        // 同公网出口走内网直连
        assert_eq!(
            PunchStrategy::select(RandomSymmetric, RandomSymmetric, false, true),
            PunchStrategy::DirectLan
        );
        // IPv6 优先级高于同网段
        assert_eq!(
            PunchStrategy::select(Cone, Cone, true, true),
            PunchStrategy::DirectIpv6
        );
    }

    #[test]
    fn unknown_nat_falls_back_to_cone_attempt() {
        use NatClass::*;
        // 探测失败不等于放弃，仍按最乐观的锥形试一次
        assert_eq!(
            PunchStrategy::select(Unknown, RandomSymmetric, false, false),
            PunchStrategy::ConeToCone
        );
        assert_eq!(
            PunchStrategy::select(Cone, Unknown, false, false),
            PunchStrategy::ConeToCone
        );
    }

    #[test]
    fn strategy_selection_is_mirror_symmetric() {
        use NatClass::*;
        // 一侧算出 A→B，另一侧必须算出 B→A，否则双方角色分工会冲突
        let classes = [Cone, LinearSymmetric, RandomSymmetric];
        for local in classes {
            for remote in classes {
                let here = PunchStrategy::select(local, remote, false, false);
                let there = PunchStrategy::select(remote, local, false, false);
                if local == remote {
                    assert_eq!(here, there, "同类组合两侧策略应相同");
                } else {
                    assert_ne!(
                        here, there,
                        "({local:?},{remote:?}) 与其镜像应是不同的有向策略"
                    );
                }
            }
        }
    }

    /// **原则 A**：线性对称一侧必须安静，否则会推乱自己的端口计数器，
    /// 让对端的预测失效。这是与网络拥塞无关的纯自伤。
    #[test]
    fn linear_symmetric_side_must_stay_quiet() {
        let p = PunchParams::for_strategy(PunchStrategy::LinearToCone);
        assert!(p.quiet, "线性对称→锥形时本端必须安静");
        assert_eq!(p.local_socket_count, 1, "安静方只能用 1 个 socket");

        let p = PunchParams::for_strategy(PunchStrategy::BothLinear);
        assert!(p.quiet, "双线性对称时双方都必须安静");
        assert_eq!(p.local_socket_count, 1);
    }

    /// **原则 B**：撒网成本不对称——锥形侧 1 个 socket 就能撒 K 个目标，
    /// 对称侧撒 K 个目标需要 K 个 socket。所以撒网由锥形侧承担。
    #[test]
    fn spraying_is_assigned_to_the_cone_side() {
        // 锥形侧：单 socket 大范围撒网
        let cone = PunchParams::for_strategy(PunchStrategy::ConeToRandom);
        assert_eq!(cone.local_socket_count, 1);
        assert_eq!(cone.target_port_mode, TargetPortMode::RandomSpray);
        assert!(cone.target_port_count >= 32);

        // 随机对称侧：多 socket，但目标是对端那一个固定端口
        let sym = PunchParams::for_strategy(PunchStrategy::RandomToCone);
        assert!(sym.local_socket_count >= 16);
        assert_eq!(sym.target_port_mode, TargetPortMode::Fixed);
        assert_eq!(sym.target_port_count, 1);
    }

    #[test]
    fn fast_path_strategies_need_no_second_exchange() {
        for s in [
            PunchStrategy::DirectIpv6,
            PunchStrategy::DirectLan,
            PunchStrategy::ConeToCone,
            PunchStrategy::ConeToLinear,
            PunchStrategy::ConeToRandom,
            PunchStrategy::LinearToCone,
            PunchStrategy::BothLinear,
        ] {
            assert!(
                !s.needs_strategy_candidates(),
                "{s:?} 只用一个 socket，不该触发阶段二"
            );
        }
        for s in [
            PunchStrategy::RandomToCone,
            PunchStrategy::RandomToLinear,
            PunchStrategy::BothRandom,
            PunchStrategy::LinearToRandom,
        ] {
            assert!(
                s.needs_strategy_candidates(),
                "{s:?} 需要新建 socket，必须走阶段二"
            );
        }
    }

    #[test]
    fn strategy_str_ids_are_unique() {
        let all = [
            PunchStrategy::DirectIpv6,
            PunchStrategy::DirectLan,
            PunchStrategy::ConeToCone,
            PunchStrategy::ConeToLinear,
            PunchStrategy::LinearToCone,
            PunchStrategy::ConeToRandom,
            PunchStrategy::RandomToCone,
            PunchStrategy::BothLinear,
            PunchStrategy::LinearToRandom,
            PunchStrategy::RandomToLinear,
            PunchStrategy::BothRandom,
            PunchStrategy::RelayOnly,
        ];
        let mut ids: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "策略字符串标识必须唯一（遥测按它聚合）");
    }

    #[test]
    fn punch_record_roundtrip() {
        let record = PunchRecord {
            attempt_id: "att-1".to_string(),
            room_code: "X7K9M2".to_string(),
            peer_session_id: "s_1".to_string(),
            is_host: true,
            local_nat_class: NatClass::LinearSymmetric,
            local_nat_detail: "symmetric_incremental".to_string(),
            remote_nat_class: NatClass::Cone,
            local_network_type: NetworkType::Wifi,
            local_public_ip: Some("1.2.3.4".to_string()),
            local_has_ipv6: true,
            remote_has_ipv6: false,
            strategy: PunchStrategy::LinearToCone,
            params: PunchParams::for_strategy(PunchStrategy::LinearToCone),
            local_candidate_count: 4,
            remote_candidate_count: 6,
            outcome: PunchOutcome::P2pSuccess,
            selected_candidate_type: Some(CandidateType::ServerReflexive),
            failure_detail: None,
            gather_ms: 380,
            signal_rtt_ms: 42,
            punch_start_skew_ms: -12,
            p2p_establish_ms: 240,
            total_ms: 900,
            final_rtt_ms: 38,
            loss_rate: 0.001,
            client_version: "2.7.7".to_string(),
            os: "windows".to_string(),
        };
        let msg = ClientMessage::PunchReport { record };
        let bytes = serialize(&msg).unwrap();
        match deserialize::<ClientMessage>(&bytes).unwrap() {
            ClientMessage::PunchReport { record } => {
                assert_eq!(record.outcome, PunchOutcome::P2pSuccess);
                assert_eq!(record.strategy, PunchStrategy::LinearToCone);
                assert!(record.params.quiet);
                assert_eq!(record.punch_start_skew_ms, -12);
            }
            _ => panic!("unexpected message"),
        }
    }

    #[test]
    fn network_config_roundtrip() {
        let msg = ServerMessage::NetworkConfigUpdate {
            config: NetworkConfig {
                stun_servers: vec![StunServerInfo {
                    host: "stun.example.com".to_string(),
                    port: 3478,
                    is_self_hosted: true,
                }],
                relay_addr: "1.2.3.4".to_string(),
                relay_quic_port: 443,
            },
        };
        let bytes = serialize(&msg).unwrap();
        match deserialize::<ServerMessage>(&bytes).unwrap() {
            ServerMessage::NetworkConfigUpdate { config } => {
                assert_eq!(config.relay_quic_port, 443);
                assert!(config.stun_servers[0].is_self_hosted);
            }
            _ => panic!("unexpected message"),
        }
    }

    #[test]
    fn test_server_message_roundtrip() {
        let msg = ServerMessage::RoomCreated {
            room_code: "X7K9M2".to_string(),
            subnet: "172.16.1".to_string(),
            virtual_ip: "172.16.1.1".to_string(),
        };
        let bytes = serialize(&msg).unwrap();
        let decoded: ServerMessage = deserialize(&bytes).unwrap();
        match decoded {
            ServerMessage::RoomCreated {
                room_code,
                subnet,
                virtual_ip,
            } => {
                assert_eq!(room_code, "X7K9M2");
                assert_eq!(subnet, "172.16.1");
                assert_eq!(virtual_ip, "172.16.1.1");
            }
            _ => panic!("消息类型不匹配"),
        }
    }

    #[test]
    fn test_join_ok_roundtrip() {
        let msg = ServerMessage::JoinOk {
            room_code: "ABC123".to_string(),
            host_session_id: "sess_host_001".to_string(),
            subnet: "10.0.1".to_string(),
            virtual_ip: "10.0.1.2".to_string(),
            host_virtual_ip: "10.0.1.1".to_string(),
        };
        let bytes = serialize(&msg).unwrap();
        let decoded: ServerMessage = deserialize(&bytes).unwrap();
        match decoded {
            ServerMessage::JoinOk {
                room_code,
                host_session_id,
                subnet,
                virtual_ip,
                host_virtual_ip,
            } => {
                assert_eq!(room_code, "ABC123");
                assert_eq!(host_session_id, "sess_host_001");
                assert_eq!(subnet, "10.0.1");
                assert_eq!(virtual_ip, "10.0.1.2");
                assert_eq!(host_virtual_ip, "10.0.1.1");
            }
            _ => panic!("消息类型不匹配"),
        }
    }

    #[test]
    fn test_peer_joined_roundtrip() {
        let msg = ServerMessage::PeerJoined {
            peer_session_id: "sess_guest_001".to_string(),
            guest_count: 3,
        };
        let bytes = serialize(&msg).unwrap();
        let decoded: ServerMessage = deserialize(&bytes).unwrap();
        match decoded {
            ServerMessage::PeerJoined {
                peer_session_id,
                guest_count,
            } => {
                assert_eq!(peer_session_id, "sess_guest_001");
                assert_eq!(guest_count, 3);
            }
            _ => panic!("消息类型不匹配"),
        }
    }

    #[test]
    fn test_report_connection_mode_roundtrip() {
        let msg = ClientMessage::ReportConnectionMode {
            mode: "p2p".to_string(),
        };
        let bytes = serialize(&msg).unwrap();
        let decoded: ClientMessage = deserialize(&bytes).unwrap();
        match decoded {
            ClientMessage::ReportConnectionMode { mode } => assert_eq!(mode, "p2p"),
            _ => panic!("消息类型不匹配"),
        }
    }

    #[test]
    fn test_fixed_host_ip_messages_roundtrip() {
        for msg in [
            ClientMessage::RequestFixedHostIp,
            ClientMessage::ReleaseFixedHostIp,
            ClientMessage::GetFixedHostIp,
        ] {
            let bytes = serialize(&msg).unwrap();
            let _: ClientMessage = deserialize(&bytes).unwrap();
        }

        let msg = ServerMessage::FixedHostIpStatus {
            enabled: true,
            virtual_ip: Some("172.24.0.1".to_string()),
        };
        let bytes = serialize(&msg).unwrap();
        match deserialize::<ServerMessage>(&bytes).unwrap() {
            ServerMessage::FixedHostIpStatus {
                enabled,
                virtual_ip,
            } => {
                assert!(enabled);
                assert_eq!(virtual_ip.as_deref(), Some("172.24.0.1"));
            }
            _ => panic!("unexpected message"),
        }
    }
}
