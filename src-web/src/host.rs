//! headless 客户端的 [`RuntimeHost`] 实现。
//!
//! 编排逻辑住在 `phantom_core::runtime`，三端共用；这里只回答宿主特有的三个
//! 问题：事件往哪送（broadcast 通道，再由 web_server 转成 WebSocket 推送）、
//! 日志写哪里、以及房主就绪时往终端打印什么。

use phantom_core::runtime::{default_log_directory, RuntimeHost, UiEvent};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;

pub struct WebHost {
    events: broadcast::Sender<UiEvent>,
    /// 仅用于终端里那行 Overlay WebUI 提示。
    web_port: u16,
}

impl WebHost {
    pub fn new(web_port: u16) -> Arc<Self> {
        let (events, _) = broadcast::channel(512);
        Arc::new(Self { events, web_port })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.events.subscribe()
    }
}

impl RuntimeHost for WebHost {
    fn emit(&self, event: &str, data: Value) {
        // headless 端没有界面，房主信息直接打到终端——这是用户拿到房间号的唯一途径。
        if event == "room:host_ready" {
            let field = |key: &str| {
                data.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            let virtual_ip = field("virtual_ip");
            println!();
            println!("Room code:        {}", field("room_code"));
            println!("Host virtual IP:  {}", virtual_ip);
            println!("Overlay WebUI:    http://{}:{}", virtual_ip, self.web_port);
            println!();
        }

        // 没有订阅者时 send 返回 Err，属于正常情况（界面还没连上），忽略即可。
        let _ = self.events.send(UiEvent {
            event: event.to_string(),
            data,
        });
    }

    fn log_dir(&self) -> PathBuf {
        default_log_directory()
    }
}
