// Web 服务器模块 - 用于 Linux Headless 模式
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Web 服务器状态
pub struct WebServerState {
    // 这里可以共享 Tauri 的核心逻辑
    // 例如：pub core: Arc<Mutex<PhantomP2PCore>>,
}

/// 启动 Web 服务器
pub async fn start_web_server(bind_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(Mutex::new(WebServerState {}));

    let app = Router::new()
        // 主页
        .route("/", get(serve_index))
        // API 接口
        .route("/api/invoke/:command", post(handle_invoke))
        .route("/api/ws", get(handle_websocket))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    println!("🌐 Web UI 已启动: http://{}", bind_addr);
    println!("📱 请在浏览器中访问上述地址");

    axum::serve(listener, app).await?;
    Ok(())
}

/// 提供 index.html（嵌入到二进制文件中）
async fn serve_index() -> Html<&'static str> {
    // 使用 include_str! 将 dist/index.html 嵌入到二进制文件中
    // 注意：需要先运行 npm run build 生成 dist/index.html
    // 路径相对于 src-tauri/src/web_server.rs
    const INDEX_HTML: &str = include_str!("../../dist/index.html");
    Html(INDEX_HTML)
}

/// 处理 Tauri invoke 命令（HTTP API）
async fn handle_invoke(
    axum::extract::Path(command): axum::extract::Path<String>,
    State(_state): State<Arc<Mutex<WebServerState>>>,
    Json(payload): Json<Value>,
) -> Response {
    // 这里调用与 Tauri 相同的核心逻辑
    // 例如：
    // match command.as_str() {
    //     "create_room" => { /* ... */ },
    //     "join_room" => { /* ... */ },
    //     _ => { /* ... */ }
    // }

    Json(serde_json::json!({
        "status": "ok",
        "command": command,
        "payload": payload
    }))
    .into_response()
}

/// 处理 WebSocket 连接（用于事件推送）
async fn handle_websocket(
    ws: WebSocketUpgrade,
    State(_state): State<Arc<Mutex<WebServerState>>>,
) -> Response {
    ws.on_upgrade(|socket| handle_socket(socket))
}

async fn handle_socket(mut socket: WebSocket) {
    // 模拟 Tauri 的事件系统
    // 可以推送 signal:status, tunnel:started 等事件
    while let Some(Ok(msg)) = socket.recv().await {
        if let Message::Text(text) = msg {
            println!("收到消息: {}", text);
            // 回复消息
            let _ = socket
                .send(Message::Text(
                    serde_json::json!({
                        "event": "pong",
                        "data": text
                    })
                    .to_string(),
                ))
                .await;
        }
    }
}
