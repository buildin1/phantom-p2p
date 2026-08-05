//! 服务端配置加载
//!
//! 从 `config.toml` 加载配置，缺省值在 Default impl 中定义。
//! 查找顺序：
//! 1. 命令行参数 `--config <path>`
//! 2. 当前工作目录下的 `config.toml`
//! 3. 可执行文件同级目录下的 `config.toml`
//! 4. 全部使用默认值

use serde::Deserialize;
use std::path::PathBuf;
use tracing::{info, warn};

/// 顶层配置
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub signal: SignalConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub port_allocation: PortAllocationConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub stun: StunConfig,
    #[serde(default)]
    pub log_upload: LogUploadConfig,
}

/// 日志包接收服务配置。
///
/// 观测模型是集中式的——用户不会主动收集日志，排障靠客户端上报。
#[derive(Debug, Clone, Deserialize)]
pub struct LogUploadConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 监听地址
    #[serde(default = "default_log_upload_bind")]
    pub bind: String,
    /// 下发给客户端的可访问基址（含协议与端口）。
    /// 留空则用 `http://<relay.public_addr>:<bind 端口>` 推导。
    #[serde(default)]
    pub public_base: String,
    /// 日志包落盘目录
    #[serde(default = "default_log_store")]
    pub store_dir: String,
}

/// 自建 STUN 服务配置。
///
/// 自建 STUN 是打洞链路的关键一环：公共 STUN 一旦不可用，
/// 客户端就拿不到 srflx 候选，**必然落中继**。实测三台境外公共 STUN
/// 曾在单次会话内全部超时。
#[derive(Debug, Clone, Deserialize)]
pub struct StunConfig {
    /// 是否启用自建 STUN
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 主端口
    #[serde(default = "default_stun_port")]
    pub port: u16,
    /// 备用端口。
    ///
    /// **判定 NAT 映射行为至少需要两个不同的目标端点**——
    /// 客户端从同一个 socket 分别打这两个端口，
    /// 比较返回的映射端口是否一致，才能区分锥形与对称。
    /// 只有单端口时无法完成这个判定。
    #[serde(default = "default_stun_alt_port")]
    pub alt_port: u16,
    /// 公网地址（下发给客户端）。留空则复用 `relay.public_addr`。
    #[serde(default)]
    pub public_addr: String,
    /// 备用的第三方公共 STUN 服务器，自建不可用时兜底。
    /// 格式 `"host:port"`。
    #[serde(default)]
    pub fallback_servers: Vec<String>,
}

/// 信令服务器配置
#[derive(Debug, Clone, Deserialize)]
pub struct SignalConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_signal_port")]
    pub port: u16,
}

/// 中继服务器配置
#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    #[serde(default = "default_relay_addr")]
    pub public_addr: String,
    /// **全局唯一的中继 QUIC 端口**。
    ///
    /// 所有房间共用这一个端口——房间路由靠流内 token，端口不参与识别，
    /// 每房间一个端口是历史遗留的冗余维度，还把并发上限人为限制在端口数上。
    ///
    /// 默认 443/UDP：受限网络（企业、校园、酒店）普遍放行，
    /// 而中继连不上就意味着彻底失败，穿透率在这里很关键。
    /// 注意 TCP/443 与 UDP/443 是两套端口空间，不冲突。
    #[serde(default = "default_relay_quic_port")]
    pub quic_port: u16,
    #[serde(default = "default_token_ttl")]
    pub token_ttl_secs: u64,
    /// 同时允许多少个房间借用中继**补包**。
    ///
    /// 中继的硬约束是带宽而不是连接数，所以这里用并发授权数给带宽封顶：
    /// 补包只占丢包率那一小部分流量（30% 丢包的 5Mbps 房间约 1.5Mbps），
    /// 比整体切中继省数倍，同样的带宽能照顾更多房间。
    /// 排满之后新的求援会被拒绝，客户端退回纯 P2P 补包，尽力而为——
    /// 宁可让一个房间体验差一点，也不能让所有房间一起被拖垮。
    #[serde(default = "default_max_assist_rooms")]
    pub max_assist_rooms: usize,
}

/// 端口分配配置
#[derive(Debug, Clone, Deserialize)]
pub struct PortAllocationConfig {
    #[serde(default = "default_guest_port_start")]
    pub guest_port_start: u16,
    #[serde(default = "default_guest_port_end")]
    pub guest_port_end: u16,
}

/// 鉴权配置
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// 只读管理面板配置
#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    /// 是否启用管理面板（默认关闭，需要自建者显式开启）
    #[serde(default)]
    pub enabled: bool,
    /// 管理面板监听地址。
    /// 默认仅监听本机回环地址；如需公网/内网其它主机访问，
    /// 由自建者自行改为 "0.0.0.0:PORT" 并自行负责相应的安全防护。
    #[serde(default = "default_admin_bind")]
    pub bind: String,
}

// --- 默认值函数 ---

fn default_bind() -> String {
    "0.0.0.0".to_string()
}
fn default_signal_port() -> u16 {
    10209
}
fn default_relay_addr() -> String {
    "127.0.0.1".to_string()
}
fn default_relay_quic_port() -> u16 {
    443
}
fn default_stun_port() -> u16 {
    3478
}
fn default_stun_alt_port() -> u16 {
    3479
}
fn default_log_upload_bind() -> String {
    "0.0.0.0:10211".to_string()
}
fn default_log_store() -> String {
    "log_uploads".to_string()
}
fn default_guest_port_start() -> u16 {
    25600
}
fn default_guest_port_end() -> u16 {
    25700
}
fn default_token_ttl() -> u64 {
    120
}
/// 按 50Mbps 中继、单房间补包约 1.5Mbps 估算，留足余量取 24
fn default_max_assist_rooms() -> usize {
    24
}
fn default_true() -> bool {
    true
}
fn default_admin_bind() -> String {
    "127.0.0.1:10210".to_string()
}

// --- Default impls ---

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            signal: SignalConfig::default(),
            relay: RelayConfig::default(),
            auth: AuthConfig::default(),
            port_allocation: PortAllocationConfig::default(),
            admin: AdminConfig::default(),
            stun: StunConfig::default(),
            log_upload: LogUploadConfig::default(),
        }
    }
}

impl Default for LogUploadConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: default_log_upload_bind(),
            public_base: String::new(),
            store_dir: default_log_store(),
        }
    }
}

impl LogUploadConfig {
    /// 下发给客户端的基址。未显式配置时按中继公网地址 + 监听端口推导，
    /// 避免部署方漏配导致客户端拿到 `0.0.0.0` 这种传不上去的地址。
    pub fn effective_base(&self, relay_addr: &str) -> String {
        if !self.public_base.trim().is_empty() {
            return self.public_base.trim_end_matches('/').to_string();
        }
        let port = self
            .bind
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(10211);
        format!("http://{}:{}", relay_addr, port)
    }
}

impl Default for SignalConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_signal_port(),
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            public_addr: default_relay_addr(),
            quic_port: default_relay_quic_port(),
            token_ttl_secs: default_token_ttl(),
            max_assist_rooms: default_max_assist_rooms(),
        }
    }
}

impl Default for StunConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_stun_port(),
            alt_port: default_stun_alt_port(),
            public_addr: String::new(),
            fallback_servers: Vec::new(),
        }
    }
}

impl StunConfig {
    /// 对外公布的 STUN 地址，未单独配置时复用中继的公网地址
    pub fn effective_addr(&self, relay_addr: &str) -> String {
        if self.public_addr.trim().is_empty() {
            relay_addr.to_string()
        } else {
            self.public_addr.clone()
        }
    }
}

impl Default for PortAllocationConfig {
    fn default() -> Self {
        Self {
            guest_port_start: default_guest_port_start(),
            guest_port_end: default_guest_port_end(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
        }
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_admin_bind(),
        }
    }
}

/// 计算 `config.toml` 的候选查找路径（与 `load_config` 的查找顺序一致）。
fn config_search_candidates() -> Vec<PathBuf> {
    // 1. 命令行 --config <path>
    let args: Vec<String> = std::env::args().collect();
    let custom_path = args
        .windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| PathBuf::from(&w[1]));

    // 2. 查找顺序
    if let Some(p) = custom_path {
        vec![p]
    } else {
        let mut v = vec![PathBuf::from("config.toml")];
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                v.push(dir.join("config.toml"));
            }
        }
        // 也检查 server/ 子目录（开发时 cwd 可能在项目根）
        v.push(PathBuf::from("server/config.toml"));
        v
    }
}

/// 返回 `config.toml` 实际所在（或将要生成）的目录，供同目录下的其它运行期文件
/// （如管理面板凭据文件 `admin.credential`）复用。找不到已存在的 `config.toml` 时，
/// 退回当前工作目录（即 `save_default_config` 生成默认配置文件的位置）。
pub fn find_config_dir() -> PathBuf {
    config_search_candidates()
        .into_iter()
        .find(|p| p.exists())
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// 加载配置文件
pub fn load_config() -> ServerConfig {
    let candidates = config_search_candidates();

    for path in &candidates {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(content) => match toml::from_str::<ServerConfig>(&content) {
                    Ok(cfg) => {
                        info!("[配置] 已加载: {}", path.display());
                        return cfg;
                    }
                    Err(e) => {
                        warn!("[配置] 解析 {} 失败: {}，使用默认值", path.display(), e);
                    }
                },
                Err(e) => {
                    warn!("[配置] 读取 {} 失败: {}", path.display(), e);
                }
            }
        }
    }

    info!("[配置] 未找到 config.toml，使用默认值并生成配置文件");

    // 生成默认配置文件
    let default_config = ServerConfig::default();
    if let Err(e) = save_default_config(&default_config) {
        warn!("[配置] 生成默认配置文件失败: {}", e);
    }

    default_config
}

/// 保存默认配置到文件
fn save_default_config(config: &ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from("config.toml");

    let content = format!(
        r#"# 幻梦P2P 信令服务器配置
# 自动生成于首次启动

[signal]
# 监听地址（0.0.0.0 表示监听所有网卡）
bind = "{}"
# 信令端口
port = {}

[relay]
# 中继服务器公网地址（客户端连接用）
public_addr = "{}"
# 全局唯一的中继 QUIC 端口，所有房间共用（房间靠流内 token 路由，端口不参与识别）。
# 默认 443/UDP：受限网络普遍放行，中继连不上等于彻底失败，穿透率在这里很关键。
# 注意 TCP/443 与 UDP/443 是两套端口空间，不冲突。
quic_port = {}
# 中继令牌有效期（秒）
token_ttl_secs = {}

[stun]
# 是否启用自建 STUN。强烈建议开启——公共 STUN 一旦不可用，
# 客户端拿不到 srflx 候选就必然落中继。
enabled = {}
# STUN 主端口
port = {}
# STUN 备用端口。判定 NAT 映射行为至少需要两个不同的目标端点，
# 客户端分别打这两个端口比较映射是否一致，才能区分锥形与对称。
alt_port = {}
# 对外公布的 STUN 地址，留空则复用 relay.public_addr
public_addr = "{}"
# 第三方公共 STUN 兜底（格式 "host:port"），自建不可用时使用
fallback_servers = []

[log_upload]
# 是否启用日志包接收服务（关掉就无法远程排障）
enabled = {}
# 接收服务监听地址
bind = "{}"
# 下发给客户端的可访问基址；留空则按 http://<relay.public_addr>:<端口> 推导
public_base = "{}"
# 日志包落盘目录，按 user_id 分子目录存放
store_dir = "{}"

[port_allocation]
# 客人端口分配范围
guest_port_start = {}
guest_port_end = {}

[auth]
# 是否启用鉴权
enabled = {}

[admin]
# 是否启用只读管理面板（默认关闭，需要自建者显式开启）
enabled = {}
# 管理面板监听地址（默认仅本机可访问；如需公网/内网其它主机访问，
# 请自行改为例如 "0.0.0.0:10210"，并自行负责相应的安全防护，这是你的选择而非默认行为）
bind = "{}"
"#,
        config.signal.bind,
        config.signal.port,
        config.relay.public_addr,
        config.relay.quic_port,
        config.relay.token_ttl_secs,
        config.stun.enabled,
        config.stun.port,
        config.stun.alt_port,
        config.stun.public_addr,
        config.log_upload.enabled,
        config.log_upload.bind,
        config.log_upload.public_base,
        config.log_upload.store_dir,
        config.port_allocation.guest_port_start,
        config.port_allocation.guest_port_end,
        config.auth.enabled,
        config.admin.enabled,
        config.admin.bind,
    );

    std::fs::write(&path, content)?;
    info!("[配置] 已生成默认配置文件: {}", path.display());
    Ok(())
}
