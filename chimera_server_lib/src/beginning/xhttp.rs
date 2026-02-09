use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap},
    sync::{Arc, RwLock},
    task::Poll,
};

use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{self, HeaderMap, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use futures::StreamExt;
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Mutex};
use tokio_util::io::ReaderStream;
use tracing::error;

use crate::{
    address::BindLocation,
    config::server_config::{ServerConfig, ServerProxyConfig, XhttpMode, XhttpServerConfig},
    handler::tcp::{tcp_handler::TcpServerHandler, tcp_handler_util::create_tcp_server_handler},
};

pub async fn start_xhttp_server(
    config: ServerConfig,
) -> std::io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        ..
    } = config;

    let ServerProxyConfig::Xhttp {
        config: xhttp_config,
        inner,
    } = protocol
    else {
        return Err(std::io::Error::other("invalid protocol for xhttp server"));
    };

    let bind_addr = match bind_location {
        BindLocation::Address(address) => address.to_socket_addr()?,
    };

    let mut join_handles = Vec::with_capacity(2);
    let upstream = match (xhttp_config.upstream.clone(), inner) {
        (Some(upstream), None) => upstream,
        (None, Some(inner_protocol)) => {
            let inner_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let inner_upstream = inner_listener.local_addr()?.to_string();
            let mut rules_stack = vec![];
            let inner_handler: Arc<Box<dyn TcpServerHandler>> = Arc::new(
                create_tcp_server_handler(*inner_protocol, &tag, &mut rules_stack),
            );

            let inner_handle = tokio::spawn(async move {
                if let Err(err) = super::run_tcp_server(inner_listener, inner_handler).await {
                    error!("xhttp inner tcp server stopped with error: {}", err);
                }
            });
            join_handles.push(inner_handle);
            inner_upstream
        }
        (Some(_), Some(_)) => {
            return Err(std::io::Error::other(
                "invalid xhttp config: upstream and inner protocol cannot both be set",
            ));
        }
        (None, None) => {
            return Err(std::io::Error::other(
                "invalid xhttp config: upstream is missing",
            ));
        }
    };

    let state = AppState::new(xhttp_config, upstream);

    let router = Router::new()
        .route("/*rest", get(down_handler).post(up_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router).await {
            error!("xhttp server exited: {}", err);
        }
    });
    join_handles.push(handle);
    Ok(join_handles)
}

#[derive(Clone)]
struct AppState {
    upstream: String,
    host: Option<String>,
    path_prefix: String,
    mode: XhttpMode,
    min_padding: usize,
    max_padding: usize,
    response_headers: Arc<HashMap<String, String>>,
    sessions: SessionStore,
}

impl AppState {
    fn new(config: XhttpServerConfig, upstream: String) -> Self {
        Self {
            upstream,
            host: config.host,
            path_prefix: config.path,
            mode: config.mode,
            min_padding: config.min_padding,
            max_padding: config.max_padding,
            response_headers: Arc::new(config.headers),
            sessions: SessionStore::new(),
        }
    }

    fn validate_host(&self, header_host: Option<&str>) -> bool {
        match (&self.host, header_host) {
            (None, _) => true,
            (Some(expected), Some(actual)) => {
                let normalized = actual
                    .split(':')
                    .next()
                    .map(|h| h.to_ascii_lowercase())
                    .unwrap_or_default();
                &normalized == expected
            }
            _ => false,
        }
    }

    fn strip_prefix(&self, request_path: &str) -> Option<String> {
        if self.path_prefix == "/" {
            return Some(request_path.trim_start_matches('/').to_string());
        }

        let prefix = format!("{}/", self.path_prefix.trim_end_matches('/'));
        if request_path.starts_with(&prefix) {
            Some(request_path[prefix.len()..].to_string())
        } else {
            None
        }
    }

    fn padding_in_range(&self, len: usize) -> bool {
        len >= self.min_padding && len <= self.max_padding
    }

    async fn acquire_session(&self, session_id: &str) -> Result<Arc<Mutex<Session>>, ()> {
        self.sessions.acquire(session_id, &self.upstream).await
    }

    async fn upsert_session(&self, session_id: String) -> Result<Arc<Mutex<Session>>, ()> {
        self.sessions
            .acquire(session_id.as_str(), &self.upstream)
            .await
    }
}

#[derive(serde::Deserialize)]
struct DownQuery {
    #[serde(default)]
    x_padding: Option<String>,
}

async fn down_handler(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    headers: HeaderMap,
    Query(params): Query<DownQuery>,
) -> Response<Body> {
    let host_header = headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok());

    if !state.validate_host(host_header) {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    }

    let request_path = format!("/{}", rest);
    let Some(remainder) = state.strip_prefix(&request_path) else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    };

    let session_id = remainder.trim_matches('/');
    if session_id.is_empty() || session_id.contains('/') {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap();
    }

    let mut padding_len = params.x_padding.as_deref().map(|s| s.len()).unwrap_or(0);
    if padding_len == 0 {
        padding_len = headers
            .get(http::header::REFERER)
            .and_then(|value| value.to_str().ok())
            .and_then(referer_padding_length)
            .unwrap_or(0);
    }

    if !state.padding_in_range(padding_len) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap();
    }

    let Ok(upload_socket) = state.acquire_session(session_id).await else {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .unwrap();
    };

    let Some(reader) = upload_socket.lock().await.raw_reader.take() else {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .unwrap();
    };

    let mut session_guard = Some(SessionDropGuard {
        store: state.sessions.clone(),
        session_id: session_id.to_string(),
    });

    let stream = ReaderStream::new(reader).chain(futures::stream::poll_fn(move |_| {
        let _ = session_guard.take();
        Poll::Ready(None)
    }));

    let mut response_builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Accel-Buffering", "no")
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST");

    for (key, value) in state.response_headers.iter() {
        if let Ok(header_name) = http::header::HeaderName::try_from(key.as_str()) {
            if let Ok(header_value) = http::header::HeaderValue::from_str(value) {
                response_builder = response_builder.header(header_name, header_value);
            }
        }
    }

    response_builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        })
}

async fn up_handler(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if !matches!(state.mode, XhttpMode::Auto | XhttpMode::PacketUp) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap();
    }

    let host_header = headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok());

    if !state.validate_host(host_header) {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    }

    let request_path = format!("/{}", rest);
    let Some(remainder) = state.strip_prefix(&request_path) else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    };

    let mut segments = remainder.split('/').filter(|segment| !segment.is_empty());
    let Some(session_id) = segments.next() else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap();
    };

    let Some(seq_str) = segments.next() else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap();
    };

    let Ok(seq) = seq_str.parse::<u64>() else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap();
    };

    let Ok(upload_socket) = state.upsert_session(session_id.to_string()).await else {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .unwrap();
    };

    let mut upload_socket = upload_socket.lock().await;
    upload_socket.packet_queue.push(Packet { seq, data: body });

    loop {
        let Some(peeked) = upload_socket.packet_queue.peek() else {
            break;
        };

        if peeked.seq > upload_socket.next_seq {
            break;
        }

        let packet = upload_socket.packet_queue.pop().unwrap();
        if packet.seq == upload_socket.next_seq {
            if let Err(err) = upload_socket.raw_writer.write_all(&packet.data).await {
                error!("failed to write to upstream: {}", err);
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::empty())
                    .unwrap();
            }
            upload_socket.next_seq += 1;
        }
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

struct SessionDropGuard {
    store: SessionStore,
    session_id: String,
}

impl Drop for SessionDropGuard {
    fn drop(&mut self) {
        self.store.remove(&self.session_id);
    }
}

#[derive(Clone)]
struct SessionStore {
    inner: Arc<RwLock<HashMap<String, Arc<Mutex<Session>>>>>,
}

impl SessionStore {
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn acquire(&self, session_id: &str, upstream: &str) -> Result<Arc<Mutex<Session>>, ()> {
        if let Some(existing) = self.inner.read().unwrap().get(session_id) {
            return Ok(existing.clone());
        }

        let upstream_conn = match TcpStream::connect(upstream).await {
            Ok(stream) => stream,
            Err(err) => {
                error!("failed to connect upstream {}: {}", upstream, err);
                return Err(());
            }
        };
        upstream_conn.set_nodelay(true).ok();
        let (reader, writer) = upstream_conn.into_split();
        let session = Arc::new(Mutex::new(Session::new(reader, writer)));

        Ok(self
            .inner
            .write()
            .unwrap()
            .insert(session_id.to_string(), session.clone())
            .unwrap_or(session))
    }

    fn remove(&self, session_id: &str) {
        self.inner.write().unwrap().remove(session_id);
    }
}

struct Session {
    raw_reader: Option<tokio::net::tcp::OwnedReadHalf>,
    raw_writer: tokio::net::tcp::OwnedWriteHalf,
    next_seq: u64,
    packet_queue: BinaryHeap<Packet>,
}

impl Session {
    fn new(
        reader: tokio::net::tcp::OwnedReadHalf,
        writer: tokio::net::tcp::OwnedWriteHalf,
    ) -> Self {
        Self {
            raw_reader: Some(reader),
            raw_writer: writer,
            next_seq: 0,
            packet_queue: BinaryHeap::new(),
        }
    }
}

struct Packet {
    data: Bytes,
    seq: u64,
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}

impl Eq for Packet {}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Packet {
    fn cmp(&self, other: &Self) -> Ordering {
        other.seq.cmp(&self.seq)
    }
}

fn referer_padding_length(referer: &str) -> Option<usize> {
    let query = referer.splitn(2, '?').nth(1)?;
    for pair in query.split('&') {
        let (key, value) = match pair.split_once('=') {
            Some(result) => result,
            None => continue,
        };
        if key == "x_padding" {
            return Some(value.len());
        }
    }
    None
}
