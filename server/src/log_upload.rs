//! 日志包接收服务
//!
//! 客户端把整个 `log/` 目录打包成 zip，经**独立 HTTP POST** 上传。
//! 不走信令 WebSocket 是因为日志包可能几 MB，
//! 塞进信令连接会阻塞打洞协商这类时延敏感的消息。
//!
//! # 凭据
//!
//! 上传 URL 里带一次性 token，由信令服务在客户端请求（或服务端主动索取）
//! 时签发，绑定 user_id 并带过期时间。这样：
//!
//! * 无凭据者无法上传，避免磁盘被灌满；
//! * 落盘时能按 user_id 归类，不必信任客户端自报的身份。

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use tracing::{error, info, warn};

/// 单个日志包体积上限，与客户端 `MAX_PACKAGE_BYTES` 对齐
const MAX_UPLOAD_BYTES: usize = 32 * 1024 * 1024;
/// 凭据有效期。够用户点一次"反馈"并完成上传即可，不必更长。
const TOKEN_TTL: Duration = Duration::from_secs(600);

struct PendingToken {
    user_id: String,
    reason: String,
    issued_at: Instant,
}

#[derive(Clone)]
pub struct UploadRegistry {
    inner: Arc<Mutex<HashMap<String, PendingToken>>>,
    store_dir: PathBuf,
    public_base: String,
}

impl UploadRegistry {
    pub fn new(store_dir: PathBuf, public_base: String) -> Self {
        let _ = std::fs::create_dir_all(&store_dir);
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            store_dir,
            public_base,
        }
    }

    /// 签发一次性上传 URL
    pub async fn issue(&self, user_id: &str, reason: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut map = self.inner.lock().await;
        // 顺手清掉过期凭据，避免长期运行时无界增长
        map.retain(|_, t| t.issued_at.elapsed() < TOKEN_TTL);
        map.insert(
            token.clone(),
            PendingToken {
                user_id: user_id.to_string(),
                reason: reason.to_string(),
                issued_at: Instant::now(),
            },
        );
        format!("{}/logs/{}", self.public_base.trim_end_matches('/'), token)
    }

    /// 校验并消耗凭据（一次性）
    async fn consume(&self, token: &str) -> Option<(String, String)> {
        let mut map = self.inner.lock().await;
        let entry = map.get(token)?;
        if entry.issued_at.elapsed() >= TOKEN_TTL {
            map.remove(token);
            return None;
        }
        let out = (entry.user_id.clone(), entry.reason.clone());
        map.remove(token);
        Some(out)
    }
}

/// 启动接收服务
pub async fn start(bind: &str, registry: UploadRegistry) -> Result<(), String> {
    let app = Router::new()
        .route("/logs/:token", post(receive))
        .with_state(registry);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("日志上传服务绑定 {} 失败: {}", bind, e))?;
    info!("[日志上报] 接收服务监听 {}", bind);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            error!("[日志上报] 服务退出: {}", e);
        }
    });
    Ok(())
}

async fn receive(
    State(reg): State<UploadRegistry>,
    AxumPath(token): AxumPath<String>,
    body: Bytes,
) -> (StatusCode, String) {
    if body.len() > MAX_UPLOAD_BYTES {
        warn!("[日志上报] 拒绝超限上传 {} 字节", body.len());
        return (StatusCode::PAYLOAD_TOO_LARGE, "日志包过大".into());
    }
    // 校验前不落盘：无效凭据一律不占磁盘
    let Some((user_id, reason)) = reg.consume(&token).await else {
        warn!("[日志上报] 凭据无效或已过期");
        return (StatusCode::UNAUTHORIZED, "凭据无效或已过期".into());
    };
    // 内容嗅探：只接受真正的 zip，挡掉误投与灌垃圾
    if body.len() < 4 || &body[..2] != b"PK" {
        warn!("[日志上报] {} 上传的不是 zip，丢弃", user_id);
        return (StatusCode::BAD_REQUEST, "内容不是 zip".into());
    }

    let dir = reg.store_dir.join(&user_id);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        error!("[日志上报] 创建目录失败: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "存储失败".into());
    }
    let name = format!("{}.zip", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"));
    let path = dir.join(&name);
    match std::fs::write(&path, &body) {
        Ok(()) => {
            info!(
                "[日志上报] 已收到 {} 的日志包 {} ({} 字节, 原因: {})",
                user_id,
                name,
                body.len(),
                reason
            );
            (StatusCode::OK, "OK".into())
        }
        Err(e) => {
            error!("[日志上报] 写入 {:?} 失败: {}", path, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "存储失败".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> UploadRegistry {
        let dir = std::env::temp_dir().join(format!("phantom-srv-upload-{}", std::process::id()));
        UploadRegistry::new(dir, "http://example.com:10211".into())
    }

    #[tokio::test]
    async fn issued_token_is_single_use() {
        let reg = registry();
        let url = reg.issue("user-a", "反馈").await;
        let token = url.rsplit('/').next().unwrap().to_string();

        let first = reg.consume(&token).await;
        assert_eq!(first.as_ref().map(|(u, _)| u.as_str()), Some("user-a"));
        assert!(
            reg.consume(&token).await.is_none(),
            "凭据必须一次性，否则可被重复灌数据"
        );
    }

    #[tokio::test]
    async fn unknown_token_is_rejected() {
        let reg = registry();
        assert!(reg.consume("not-a-real-token").await.is_none());
    }

    #[tokio::test]
    async fn issued_url_points_at_the_upload_route() {
        let reg = registry();
        let url = reg.issue("user-b", "服务端索取").await;
        assert!(
            url.starts_with("http://example.com:10211/logs/"),
            "URL 应指向 /logs/:token，实际为 {url}"
        );
    }

    #[tokio::test]
    async fn reason_is_carried_through_to_storage_time() {
        let reg = registry();
        let url = reg.issue("user-c", "打洞持续失败").await;
        let token = url.rsplit('/').next().unwrap().to_string();
        let (_, reason) = reg.consume(&token).await.unwrap();
        assert_eq!(reason, "打洞持续失败", "原因要一路带到落盘日志，便于归类");
    }
}
