//! 只读管理面板
//!
//! 提供一个基于 axum 的只读 HTTP 面板，用于展示当前信令服务器的在线连接情况
//! （用户、房间、连接地址、IP 归属地、P2P/中继模式、在线时长）。
//!
//! 设计要点：
//! - 默认关闭（`admin.enabled = false`），需要自建者显式开启。
//! - 默认只监听 `127.0.0.1`（`admin.bind`），公网访问需要自建者自行改配置并自行负责安全防护。
//! - 首次启动且尚未设置访问密码时，在控制台交互式提示设置一个密码，
//!   使用 Argon2id 单向哈希后存入本地凭据文件（`admin.credential`，与 config.toml 同目录）。
//!   服务端从不持有可还原为明文的密钥，因此天然没有"找回密码"功能——
//!   忘记密码只能删除凭据文件后重启服务端重新设置。
//! - 登录成功后签发一个随机 token，通过 httpOnly Cookie 下发，
//!   服务端在内存里维护 token -> 过期时间（12 小时）的映射。
//! - IP 归属地由后台任务每 30 秒批量查询一次 ip-api.com（免费批量接口），
//!   结果缓存 1 小时，`GET /api/sessions` 直接读缓存，不做同步查询。

use crate::config::ServerConfig;
use crate::SharedState;
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{error, info, warn};

/// 会话 token 有效期（12 小时）
const TOKEN_TTL: Duration = Duration::from_secs(12 * 3600);
/// IP 归属地批量查询周期
const GEO_POLL_INTERVAL: Duration = Duration::from_secs(30);
/// IP 归属地缓存 TTL（归属地几乎不变，尽量避免触发 ip-api.com 的限速）
const GEO_CACHE_TTL: Duration = Duration::from_secs(3600);
/// ip-api.com /batch 接口单次请求最多 100 个 IP
const GEO_BATCH_SIZE: usize = 100;

/// IP 归属地信息
#[derive(Debug, Clone, Serialize)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    /// 国家代码转换出的 emoji 国旗
    pub flag: Option<String>,
}

type GeoCache = Arc<Mutex<HashMap<String, (GeoInfo, Instant)>>>;
type TokenStore = Arc<Mutex<HashMap<String, Instant>>>;

#[derive(Clone)]
struct AdminState {
    app_state: SharedState,
    tokens: TokenStore,
    password_hash: Arc<String>,
    geo_cache: GeoCache,
}

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

#[derive(Serialize)]
struct SessionView {
    user_id: String,
    addr: String,
    room_code: Option<String>,
    role: Option<String>,
    connected_secs: u64,
    mode: String,
    geo: Option<GeoInfo>,
}

/// 若配置启用了管理面板，则完成凭据初始化并在后台启动 HTTP 服务与 geoip 轮询任务。
/// 任何初始化失败都只会跳过管理面板（打日志），不会影响信令/中继服务本身。
pub fn maybe_start(cfg: &Arc<ServerConfig>, app_state: SharedState) {
    if !cfg.admin.enabled {
        info!("[admin] 管理面板未启用（admin.enabled = false），跳过");
        return;
    }

    let password_hash = match load_or_create_credential() {
        Ok(hash) => hash,
        Err(e) => {
            error!("[admin] 管理员凭据初始化失败，管理面板未启动: {}", e);
            return;
        }
    };

    let state = AdminState {
        app_state: app_state.clone(),
        tokens: Arc::new(Mutex::new(HashMap::new())),
        password_hash: Arc::new(password_hash),
        geo_cache: Arc::new(Mutex::new(HashMap::new())),
    };

    start_geo_task(app_state, state.geo_cache.clone());

    let bind = cfg.admin.bind.clone();
    let router = build_router(state);
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(&bind).await {
            Ok(listener) => {
                info!("[admin] 管理面板已启动: http://{}", bind);
                if let Err(e) = axum::serve(listener, router).await {
                    error!("[admin] 服务异常退出: {}", e);
                }
            }
            Err(e) => {
                error!("[admin] 绑定 {} 失败，管理面板未启动: {}", bind, e);
            }
        }
    });
}

fn build_router(state: AdminState) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/api/login", post(login_handler))
        .route("/api/sessions", get(sessions_handler))
        .with_state(state)
}

async fn index_handler() -> impl IntoResponse {
    Html(include_str!("../static/admin-dashboard.html"))
}

async fn login_handler(
    State(state): State<AdminState>,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    if !verify_password(&state.password_hash, &body.password) {
        warn!("[admin] 登录失败：密码不正确");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "密码不正确"})),
        )
            .into_response();
    }

    let token = generate_token();
    let expiry = Instant::now() + TOKEN_TTL;
    state.tokens.lock().await.insert(token.clone(), expiry);

    let cookie = format!(
        "admin_token={}; HttpOnly; Path=/; Max-Age={}; SameSite=Strict",
        token,
        TOKEN_TTL.as_secs()
    );

    let mut response = Json(json!({"ok": true})).into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().insert(header::SET_COOKIE, value);
        }
        Err(e) => {
            error!("[admin] 生成 Set-Cookie 失败: {}", e);
        }
    }
    response
}

async fn sessions_handler(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_authorized(&state, &headers).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
            .into_response();
    }

    let app_state = state.app_state.lock().await;
    let geo_cache = state.geo_cache.lock().await;
    let now = Instant::now();

    let views: Vec<SessionView> = app_state
        .sessions
        .values()
        .map(|session| {
            let ip = session.addr.ip().to_string();
            let geo = geo_cache.get(&ip).map(|(info, _)| info.clone());
            SessionView {
                user_id: session.user_id.clone().unwrap_or_else(|| "-".to_string()),
                addr: session.addr.to_string(),
                room_code: session.room_code.clone(),
                role: session.role.as_ref().map(|role| match role {
                    crate::Role::Host => "host".to_string(),
                    crate::Role::Guest => "guest".to_string(),
                }),
                connected_secs: now
                    .saturating_duration_since(session.connected_at)
                    .as_secs(),
                mode: session
                    .connection_mode
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                geo,
            }
        })
        .collect();

    Json(views).into_response()
}

// ============================================================
// 鉴权 / 凭据
// ============================================================

fn credential_path() -> PathBuf {
    crate::config::find_config_dir().join("admin.credential")
}

/// 加载已有的凭据文件，或在首次启动时于控制台交互式提示设置密码。
fn load_or_create_credential() -> Result<String, String> {
    let path = credential_path();
    if path.exists() {
        let hash = std::fs::read_to_string(&path)
            .map_err(|e| format!("读取凭据文件 {} 失败: {}", path.display(), e))?;
        let hash = hash.trim().to_string();
        if hash.is_empty() {
            return Err(format!("凭据文件 {} 为空", path.display()));
        }
        info!("[admin] 已加载管理员凭据: {}", path.display());
        return Ok(hash);
    }

    println!();
    println!("============================================================");
    println!(" 幻梦P2P 管理面板 — 首次启动，需要设置访问密码");
    println!("============================================================");
    println!(
        "检测到 admin.enabled = true，但尚未找到凭据文件: {}",
        path.display()
    );
    println!("请设置一个用于登录只读管理面板的访问密码。");
    println!("注意：该密码仅以单向哈希（Argon2id）形式保存，服务端不保存明文，");
    println!("      也没有\"找回密码\"功能——如需更换，删除凭据文件后重启服务端即可重新设置。");
    println!();

    loop {
        let pw1 = rpassword::prompt_password("请输入新密码: ")
            .map_err(|e| format!("读取密码输入失败: {}", e))?;
        if pw1.trim().is_empty() {
            println!("密码不能为空，请重新输入。");
            continue;
        }
        let pw2 = rpassword::prompt_password("请再次输入以确认: ")
            .map_err(|e| format!("读取密码输入失败: {}", e))?;
        if pw1 != pw2 {
            println!("两次输入不一致，请重新输入。");
            continue;
        }

        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(pw1.as_bytes(), &salt)
            .map_err(|e| format!("密码哈希失败: {}", e))?
            .to_string();

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("创建凭据目录 {} 失败: {}", parent.display(), e))?;
            }
        }
        std::fs::write(&path, &hash)
            .map_err(|e| format!("写入凭据文件 {} 失败: {}", path.display(), e))?;
        println!("密码已设置，凭据已保存到 {}", path.display());
        println!();
        return Ok(hash);
    }
}

fn verify_password(stored_hash: &str, candidate: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(candidate.as_bytes(), &parsed)
            .is_ok(),
        Err(e) => {
            error!("[admin] 凭据文件内容不是有效的密码哈希: {}", e);
            false
        }
    }
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(name).and_then(|s| s.strip_prefix('=')) {
            return Some(rest.to_string());
        }
    }
    None
}

async fn is_authorized(state: &AdminState, headers: &HeaderMap) -> bool {
    let Some(token) = extract_cookie(headers, "admin_token") else {
        return false;
    };
    let mut tokens = state.tokens.lock().await;
    match tokens.get(&token) {
        Some(expiry) if *expiry > Instant::now() => true,
        Some(_) => {
            tokens.remove(&token);
            false
        }
        None => false,
    }
}

// ============================================================
// IP 归属地批量查询（ip-api.com）
// ============================================================

fn start_geo_task(app_state: SharedState, geo_cache: GeoCache) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(GEO_POLL_INTERVAL);
        loop {
            ticker.tick().await;

            let all_ips: Vec<String> = {
                let st = app_state.lock().await;
                let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
                for session in st.sessions.values() {
                    set.insert(session.addr.ip().to_string());
                }
                set.into_iter().collect()
            };
            if all_ips.is_empty() {
                continue;
            }

            let need_lookup: Vec<String> = {
                let cache = geo_cache.lock().await;
                let now = Instant::now();
                all_ips
                    .into_iter()
                    .filter(|ip| match cache.get(ip) {
                        Some((_, cached_at)) => now.duration_since(*cached_at) > GEO_CACHE_TTL,
                        None => true,
                    })
                    .collect()
            };
            if need_lookup.is_empty() {
                continue;
            }

            for chunk in need_lookup.chunks(GEO_BATCH_SIZE) {
                let chunk_vec = chunk.to_vec();
                let result =
                    tokio::task::spawn_blocking(move || query_ip_api_batch(&chunk_vec)).await;
                match result {
                    Ok(Ok(entries)) => {
                        let mut cache = geo_cache.lock().await;
                        let now = Instant::now();
                        for (ip, info) in entries {
                            cache.insert(ip, (info, now));
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("[admin][geoip] 批量查询失败: {}", e);
                    }
                    Err(e) => {
                        warn!("[admin][geoip] 后台任务异常: {}", e);
                    }
                }
            }
        }
    });
}

/// 同步调用 ip-api.com 批量接口（需要在 spawn_blocking 中运行）
fn query_ip_api_batch(ips: &[String]) -> Result<Vec<(String, GeoInfo)>, String> {
    let body: Vec<serde_json::Value> = ips
        .iter()
        .map(|ip| {
            json!({
                "query": ip,
                "fields": "status,message,country,countryCode,regionName,city,isp,query",
            })
        })
        .collect();

    let response = ureq::post("http://ip-api.com/batch")
        .send_json(serde_json::Value::Array(body))
        .map_err(|e| format!("请求 ip-api.com 失败: {}", e))?;

    let payload: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("解析 ip-api.com 响应失败: {}", e))?;

    let entries = payload
        .as_array()
        .ok_or_else(|| "ip-api.com 响应格式不是数组".to_string())?;

    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let status = entry.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if status != "success" {
            continue;
        }
        let query_ip = entry
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if query_ip.is_empty() {
            continue;
        }
        let country = entry
            .get("country")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let region = entry
            .get("regionName")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let city = entry
            .get("city")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let isp = entry
            .get("isp")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let flag = entry
            .get("countryCode")
            .and_then(|v| v.as_str())
            .map(country_code_to_flag);

        out.push((
            query_ip,
            GeoInfo {
                country,
                region,
                city,
                isp,
                flag,
            },
        ));
    }

    Ok(out)
}

/// ISO 3166-1 alpha-2 国家代码 -> unicode regional indicator 组成的国旗 emoji
fn country_code_to_flag(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| {
            let base = 0x1F1E6u32; // 🇦，regional indicator symbol letter A
            let offset = c.to_ascii_uppercase() as u32 - 'A' as u32;
            char::from_u32(base + offset).unwrap_or(c)
        })
        .collect()
}
