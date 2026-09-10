use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;

/// 宿主注入的配置根目录。只在移动端使用。
static CONFIG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// 指定配置与数据的存放根目录。
///
/// 移动端必须在引擎启动前调用一次：Android 上传 `context.filesDir`。
/// 桌面端不要调用，让它走 `dirs::config_dir()` 的默认位置 —— 改了会让
/// 老用户的配置和身份密钥集体搬家，等于换了个身份。
pub fn set_config_dir(dir: PathBuf) {
    if CONFIG_DIR.set(dir).is_err() {
        tracing::warn!("[配置] 配置目录已设置过，忽略重复设置");
    }
}

/// 配置与数据的根目录。
fn config_dir() -> PathBuf {
    if let Some(dir) = CONFIG_DIR.get() {
        return dir.clone();
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("phantom-p2p")
}

/// 用户模式固定信令地址（不允许被普通用户修改）
pub const USER_MODE_SIGNAL_SERVER: &str = env!("OFFICIAL_SIGNAL_SERVER");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    /// 信令服务器地址
    pub signal_server: String,
    /// 用户名
    pub username: String,
    /// 最后使用的房间码
    pub last_room_code: Option<String>,
    /// 是否启用 UPnP
    pub enable_upnp: bool,
    /// 是否启用 STUN
    pub enable_stun: bool,
    /// 开发者模式
    pub dev_mode: bool,
    /// 是否强制中继（跳过打洞）
    pub force_relay_mode: bool,
    /// 默认房间传输协议（tcp/udp）
    pub default_room_transport: String,
    /// 用户模式固定信令地址（用于前后端统一显示与强制策略）
    pub user_mode_signal_server: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            signal_server: USER_MODE_SIGNAL_SERVER.to_string(),
            username: format!("玩家{}", rand::random::<u16>()),
            last_room_code: None,
            enable_upnp: true,
            enable_stun: true,
            dev_mode: false,
            force_relay_mode: false,
            default_room_transport: "tcp".to_string(),
            user_mode_signal_server: USER_MODE_SIGNAL_SERVER.to_string(),
        }
    }
}

impl ClientConfig {
    /// 根据当前运行模式强制修正配置项
    pub fn apply_mode_policy(&mut self) {
        self.user_mode_signal_server = USER_MODE_SIGNAL_SERVER.to_string();
        self.default_room_transport = if self.default_room_transport.eq_ignore_ascii_case("udp") {
            "udp".to_string()
        } else {
            "tcp".to_string()
        };

        if !crate::DEV_MODE.load(Ordering::Relaxed) {
            self.signal_server = USER_MODE_SIGNAL_SERVER.to_string();
            self.force_relay_mode = false;
            self.dev_mode = false;
        }
    }

    /// 获取配置文件路径
    ///
    /// 桌面端走 `dirs::config_dir()`。移动端那里没有对应概念，必须由宿主
    /// 用 [`set_config_dir`] 显式注入（Android 是 `filesDir`），否则会落到
    /// 进程当前目录 —— 在 Android 上那是 `/`，不可写。
    pub fn config_path() -> PathBuf {
        let config_dir = config_dir();
        fs::create_dir_all(&config_dir).ok();
        config_dir.join("config.toml")
    }

    /// 加载配置
    pub fn load() -> Self {
        let path = Self::config_path();

        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => match toml::from_str(&content) {
                    Ok(config) => {
                        tracing::info!("已加载配置: {:?}", path);
                        return config;
                    }
                    Err(e) => {
                        tracing::warn!("配置文件解析失败: {}, 使用默认配置", e);
                    }
                },
                Err(e) => {
                    tracing::warn!("读取配置文件失败: {}, 使用默认配置", e);
                }
            }
        }

        // 返回默认配置并保存
        let config = Self::default();
        config.save().ok();
        config
    }

    /// 保存配置
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::config_path();
        let content = toml::to_string_pretty(self)?;
        fs::write(&path, content)?;
        tracing::info!("配置已保存: {:?}", path);
        Ok(())
    }
}

/// 根据运行模式返回最终可用的信令地址
pub fn runtime_signal_server(requested_url: &str) -> String {
    if crate::DEV_MODE.load(Ordering::Relaxed) {
        let trimmed = requested_url.trim();
        if trimmed.is_empty() {
            USER_MODE_SIGNAL_SERVER.to_string()
        } else {
            trimmed.to_string()
        }
    } else {
        USER_MODE_SIGNAL_SERVER.to_string()
    }
}

/// 将信令地址脱敏为 `协议://********` 形式
pub fn redact_signal_url(signal_url: &str) -> String {
    if crate::DEV_MODE.load(Ordering::Relaxed) {
        return signal_url.to_string();
    }

    if let Some((scheme, _rest)) = signal_url.split_once("://") {
        format!("{}://********", scheme)
    } else {
        "********".to_string()
    }
}
