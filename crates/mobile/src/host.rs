//! 宿主接口：`SessionRuntime` 需要平台提供的能力。
//!
//! 这一层刻意做得很薄。移动端与桌面端的差别其实只有三件事：
//!
//! 1. **事件往哪送** —— 桌面端 emit 给前端，Android 走 JNI 回调
//! 2. **虚拟网卡谁建** —— 桌面端 core 自己建，Android 只有 `VpnService` 有权限
//! 3. **文件放哪** —— 桌面端有 `dirs::config_dir()`，Android 得由宿主给
//!
//! 除此之外的一切（打洞、隧道、加密、抗丢包）都直接用 `phantom-core`，
//! 与 PC 同一份代码。

use std::path::PathBuf;

/// 建立虚拟网卡的请求。
///
/// 房间的子网与本机虚拟 IP 由服务端在建房/入房时分配，所以这些参数直到
/// 那一刻才知道 —— 这正是 Android 不能在启动时就把网卡建好的原因。
#[derive(Debug, Clone)]
pub struct TunRequest {
    /// 本机虚拟 IP，如 `10.66.0.2`
    pub address: String,
    /// 前缀长度。Host 拿固定 IP 时是 32，其余是 24。
    pub prefix_len: u8,
    /// 需要路由进隧道的网段。**必须在 establish 之前给全** ——
    /// `VpnService.Builder` 一旦 establish 就无法追加路由。
    pub routes: Vec<(String, u8)>,
    /// 与 core 的 `tun_bridge::TUN_MTU` 同源。
    pub mtu: u16,
}

/// 平台宿主。
pub trait RuntimeHost: Send + Sync + 'static {
    /// 把一条事件送给界面。`payload` 是 JSON。
    fn emit(&self, event: &str, payload: serde_json::Value);

    /// 让系统建立虚拟网卡，返回**已经 detach 的**裸 fd。
    ///
    /// 返回 `Err` 表示用户拒绝了 VPN 权限，或者系统拒绝建立。
    fn establish_tun(&self, request: &TunRequest) -> Result<i32, String>;

    /// 保护一个 socket 使其绕开本机隧道（`VpnService.protect`）。
    fn protect_socket(&self, fd: i32) -> bool;

    /// 日志根目录。Android 走 `getExternalFilesDir()` —— 写进 `filesDir`
    /// 的话没 root 根本看不到，而界面按约定隐藏了链路的真实性质，
    /// 日志是唯一的诊断入口。
    fn log_dir(&self) -> PathBuf;

    /// 数据目录：身份密钥、风控自校准数据库。绝不参与云备份。
    fn data_dir(&self) -> PathBuf;
}
