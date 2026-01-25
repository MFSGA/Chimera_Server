use std::{collections::HashSet, net::SocketAddr, time::Duration};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time,
};
use tracing::error;

use crate::traffic;

const RESOURCE_CONNECTION_COUNT: &str = "chimera://status/connection_count";
const PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone)]
pub struct McpServerConfig {
    pub listen: SocketAddr,
    pub path: String,
    pub update_interval: Duration,
}

#[derive(Clone)]
struct AppState {
    update_tx: watch::Sender<u64>,
}

pub async fn start_mcp_server(config: McpServerConfig) -> std::io::Result<JoinHandle<()>> {
    let McpServerConfig {
        listen,
        path,
        update_interval,
    } = config;
    let path = normalize_path(path);

    let initial = traffic::active_connection_count() as u64;
    let (update_tx, _update_rx) = watch::channel(initial);
    let update_tx_task = update_tx.clone();
    tokio::spawn(async move {
        let mut last = initial;
        let mut interval = time::interval(update_interval);
        loop {
            interval.tick().await;
            let current = traffic::active_connection_count() as u64;
            if current != last {
                last = current;
                let _ = update_tx_task.send(current);
            }
        }
    });

    let state = AppState { update_tx };
    let router = Router::new()
        .route(&path, get(mcp_ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    Ok(tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router).await {
            error!("mcp server exited: {}", err);
        }
    }))
}

fn normalize_path(path: String) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/mcp".to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    }
}

async fn mcp_ws_handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();

    let send_task = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if ws_sender.send(message).await.is_err() {
                break;
            }
        }
    });

    let mut subscriptions = HashSet::new();
    let mut update_rx = state.update_tx.subscribe();

    loop {
        let subscribed = subscriptions.contains(RESOURCE_CONNECTION_COUNT);
        tokio::select! {
            maybe_msg = ws_receiver.next() => {
                match maybe_msg {
                    Some(Ok(message)) => {
                        if !handle_incoming(message, &out_tx, &mut subscriptions) {
                            break;
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
            changed = update_rx.changed(), if subscribed => {
                if changed.is_err() {
                    break;
                }
                let notification = json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {
                        "uri": RESOURCE_CONNECTION_COUNT,
                    },
                });
                send_json(&out_tx, notification);
            }
        }
    }

    send_task.abort();
}

fn handle_incoming(
    message: Message,
    out_tx: &mpsc::UnboundedSender<Message>,
    subscriptions: &mut HashSet<String>,
) -> bool {
    match message {
        Message::Text(text) => {
            let value: Value = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(_) => {
                    send_error(out_tx, Value::Null, -32700, "parse error");
                    return true;
                }
            };
            let jsonrpc = value.get("jsonrpc").and_then(|v| v.as_str());
            let method = value.get("method").and_then(|v| v.as_str());
            let id = value.get("id").cloned();
            let params = value.get("params");

            if jsonrpc != Some("2.0") {
                send_error(out_tx, id.unwrap_or(Value::Null), -32600, "invalid request");
                return true;
            }

            let Some(method) = method else {
                send_error(out_tx, id.unwrap_or(Value::Null), -32600, "invalid request");
                return true;
            };

            match method {
                "initialize" => {
                    if let Some(id) = id {
                        let result = json!({
                            "protocolVersion": PROTOCOL_VERSION,
                            "capabilities": {
                                "resources": {
                                    "subscribe": true,
                                },
                            },
                            "serverInfo": {
                                "name": env!("CARGO_PKG_NAME"),
                                "version": env!("CARGO_PKG_VERSION"),
                            },
                        });
                        send_result(out_tx, id, result);
                    }
                }
                "ping" => {
                    if let Some(id) = id {
                        send_result(out_tx, id, json!({}));
                    }
                }
                "resources/list" => {
                    if let Some(id) = id {
                        let result = json!({
                            "resources": [
                                {
                                    "uri": RESOURCE_CONNECTION_COUNT,
                                    "name": "connection_count",
                                    "mimeType": "application/json",
                                    "description": "Active connection count",
                                }
                            ],
                        });
                        send_result(out_tx, id, result);
                    }
                }
                "resources/read" => {
                    if let Some(id) = id {
                        let Some(uri) = extract_uri(params) else {
                            send_error(out_tx, id, -32602, "missing uri");
                            return true;
                        };
                        if uri != RESOURCE_CONNECTION_COUNT {
                            send_error(out_tx, id, -32602, "unsupported uri");
                            return true;
                        }
                        let payload = json!({
                            "count": traffic::active_connection_count(),
                        });
                        let result = json!({
                            "contents": [
                                {
                                    "uri": RESOURCE_CONNECTION_COUNT,
                                    "mimeType": "application/json",
                                    "text": payload.to_string(),
                                }
                            ],
                        });
                        send_result(out_tx, id, result);
                    }
                }
                "resources/subscribe" => {
                    if let Some(id) = id {
                        let Some(uri) = extract_uri(params) else {
                            send_error(out_tx, id, -32602, "missing uri");
                            return true;
                        };
                        if uri == RESOURCE_CONNECTION_COUNT {
                            subscriptions.insert(uri);
                        }
                        send_result(out_tx, id, json!({}));
                    }
                }
                "resources/unsubscribe" => {
                    if let Some(id) = id {
                        let Some(uri) = extract_uri(params) else {
                            send_error(out_tx, id, -32602, "missing uri");
                            return true;
                        };
                        subscriptions.remove(&uri);
                        send_result(out_tx, id, json!({}));
                    }
                }
                "notifications/initialized" => {}
                _ => {
                    if let Some(id) = id {
                        send_error(out_tx, id, -32601, "method not found");
                    }
                }
            }
            true
        }
        Message::Ping(payload) => {
            let _ = out_tx.send(Message::Pong(payload));
            true
        }
        Message::Pong(_) => true,
        Message::Binary(_) => true,
        Message::Close(_) => false,
    }
}

fn extract_uri(params: Option<&Value>) -> Option<String> {
    let params = params?;
    params
        .get("uri")
        .and_then(|v| v.as_str())
        .map(|uri| uri.to_string())
}

fn send_result(out_tx: &mpsc::UnboundedSender<Message>, id: Value, result: Value) {
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    });
    send_json(out_tx, response);
}

fn send_error(out_tx: &mpsc::UnboundedSender<Message>, id: Value, code: i32, message: &str) {
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    });
    send_json(out_tx, response);
}

fn send_json(out_tx: &mpsc::UnboundedSender<Message>, value: Value) {
    if let Ok(text) = serde_json::to_string(&value) {
        let _ = out_tx.send(Message::Text(text.into()));
    }
}
