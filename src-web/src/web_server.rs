use crate::runtime::HeadlessRuntime;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[derive(Clone)]
struct WebState {
    runtime: Arc<HeadlessRuntime>,
}

pub async fn start_web_server(
    bind_addr: SocketAddr,
    runtime: Arc<HeadlessRuntime>,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = WebState {
        runtime: runtime.clone(),
    };
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/invoke/:command", post(handle_invoke))
        .route("/api/ws", get(handle_websocket))
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        .with_state(state);

    let local_listener = tokio::net::TcpListener::bind(bind_addr).await?;
    println!("Local WebUI:      http://{}", bind_addr);
    let local_app = app.clone();
    tokio::spawn(async move {
        if let Err(error) = axum::serve(local_listener, local_app).await {
            tracing::error!("local WebUI stopped: {}", error);
        }
    });

    let mut overlay_rx = runtime.overlay_receiver();
    let mut overlay_task: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        overlay_rx.changed().await?;
        if let Some(task) = overlay_task.take() {
            task.abort();
        }
        let Some(ip) = *overlay_rx.borrow() else {
            continue;
        };
        if bind_addr.ip() == IpAddr::V4(ip) {
            continue;
        }
        let overlay_addr = SocketAddr::new(IpAddr::V4(ip), bind_addr.port());
        match tokio::net::TcpListener::bind(overlay_addr).await {
            Ok(listener) => {
                let overlay_app = app.clone();
                overlay_task = Some(tokio::spawn(async move {
                    if let Err(error) = axum::serve(listener, overlay_app).await {
                        tracing::error!("Overlay WebUI stopped: {}", error);
                    }
                }));
            }
            Err(error) => tracing::error!("bind Overlay WebUI {}: {}", overlay_addr, error),
        }
    }
}

async fn serve_index() -> Html<&'static str> {
    Html(include_str!("../../dist/index.html"))
}

async fn handle_invoke(
    Path(command): Path<String>,
    State(state): State<WebState>,
    Json(payload): Json<Value>,
) -> Response {
    match state.runtime.invoke(&command, payload).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({"error": error}))).into_response(),
    }
}

async fn handle_websocket(ws: WebSocketUpgrade, State(state): State<WebState>) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state.runtime))
}

async fn handle_socket(socket: WebSocket, runtime: Arc<HeadlessRuntime>) {
    let (mut sender, mut receiver) = socket.split();
    for event in runtime.snapshot().await {
        let Ok(text) = serde_json::to_string(&event) else {
            continue;
        };
        if sender.send(Message::Text(text)).await.is_err() {
            return;
        }
    }

    let mut events = runtime.subscribe();
    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Ok(event) => {
                        let Ok(text) = serde_json::to_string(&event) else { continue; };
                        if sender.send(Message::Text(text)).await.is_err() { break; }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            message = receiver.next() => {
                match message {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}
