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
    #[serde(default = "default_relay_port_start")]
    pub port_start: u16,
    #[serde(default = "default_relay_port_end")]
    pub port_end: u16,
    #[serde(default = "default_token_ttl")]
    pub token_ttl_secs: u64,
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
fn default_relay_port_start() -> u16 {
    10113
}
fn default_relay_port_end() -> u16 {
    10213
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
        }
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
            port_start: default_relay_port_start(),
            port_end: default_relay_port_end(),
            token_ttl_secs: default_token_ttl(),
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
# 中继端口池范围（单池，按房间协议动态调度）
port_start = {}
port_end = {}
# 中继令牌有效期（秒）
token_ttl_secs = {}

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
        config.relay.port_start,
        config.relay.port_end,
        config.relay.token_ttl_secs,
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
