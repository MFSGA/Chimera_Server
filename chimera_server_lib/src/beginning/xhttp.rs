use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    fs,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    header,
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    sync::Mutex,
    time::{Duration, sleep},
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use tracing::{debug, error};

use crate::{
    address::BindLocation,
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::{ServerConfig, ServerProxyConfig, XhttpServerConfig},
    handler::tcp::{
        tcp_handler::TcpServerHandler, tcp_handler_util::create_tcp_server_handler,
    },
    resolver::{NativeResolver, Resolver},
};
#[cfg(feature = "tls")]
use crate::{
    config::server_config::TlsServerConfig, util::rustls_util::create_server_config,
};

use super::process_stream;

const XHTTP_PIPE_CAPACITY: usize = 64 * 1024;

type ResponseBody = UnsyncBoxBody<Bytes, Infallible>;

pub async fn start_xhttp_server(
    config: ServerConfig,
) -> std::io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        ..
    } = config;

    let listener_config = parse_listener_protocol(protocol)?;

    let bind_addr = match bind_location {
        BindLocation::Address(address) => address.to_socket_addr()?,
    };

    let mut rules_stack = vec![];
    let server_handler = Arc::new(create_tcp_server_handler(
        listener_config.inner,
        &tag,
        &mut rules_stack,
    ));
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let state = Arc::new(AppState::new(
        listener_config.xhttp_config,
        server_handler,
        resolver,
    ));
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let tls_acceptor = listener_config.tls_acceptor.clone();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    error!("xhttp accept failed: {}", err);
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);

            let state = state.clone();
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                #[cfg(feature = "tls")]
                if let Some(acceptor) = tls_acceptor {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            serve_http_connection(tls_stream, state, peer_addr)
                                .await;
                        }
                        Err(err) => {
                            error!("xhttp tls accept {} failed: {}", peer_addr, err);
                        }
                    }
                    return;
                }

                serve_http_connection(stream, state, peer_addr).await;
            });
        }
    });

    Ok(vec![handle])
}

struct XhttpListenerConfig {
    xhttp_config: XhttpServerConfig,
    inner: ServerProxyConfig,
    #[cfg(feature = "tls")]
    tls_acceptor: Option<TlsAcceptor>,
    #[cfg(not(feature = "tls"))]
    tls_acceptor: Option<()>,
}

fn parse_listener_protocol(
    protocol: ServerProxyConfig,
) -> std::io::Result<XhttpListenerConfig> {
    match protocol {
        ServerProxyConfig::Xhttp { config, inner } => Ok(XhttpListenerConfig {
            xhttp_config: config,
            inner: *inner,
            tls_acceptor: None,
        }),
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(TlsServerConfig {
            certificate_path,
            private_key_path,
            mut alpn_protocols,
            inner,
        }) => match *inner {
            ServerProxyConfig::Xhttp { config, inner } => {
                if alpn_protocols.is_empty() {
                    alpn_protocols.push("h2".to_string());
                } else if !alpn_protocols.iter().any(|proto| proto == "h2") {
                    alpn_protocols.push("h2".to_string());
                }

                let cert_bytes = fs::read(&certificate_path)?;
                let key_bytes = fs::read(&private_key_path)?;
                let tls_config = create_server_config(
                    &cert_bytes,
                    &key_bytes,
                    &alpn_protocols,
                    &[],
                );

                Ok(XhttpListenerConfig {
                    xhttp_config: config,
                    inner: *inner,
                    tls_acceptor: Some(TlsAcceptor::from(Arc::new(tls_config))),
                })
            }
            _ => Err(std::io::Error::other(
                "invalid tls-wrapped protocol for xhttp server",
            )),
        },
        _ => Err(std::io::Error::other("invalid protocol for xhttp server")),
    }
}

async fn serve_http_connection<IO>(
    io: IO,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let builder = auto::Builder::new(TokioExecutor::new());
    let service =
        service_fn(move |request| handle_request(request, state.clone(), peer_addr));

    if let Err(err) = builder.serve_connection(io, service).await {
        error!("xhttp connection {} exited: {}", peer_addr, err);
    }
}

#[derive(Clone)]
struct AppState {
    host: Option<String>,
    base_path: String,
    min_padding: usize,
    max_padding: usize,
    max_each_post_bytes: usize,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    sessions: SessionStore,
}

impl AppState {
    fn new(
        config: XhttpServerConfig,
        server_handler: Arc<Box<dyn TcpServerHandler>>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self {
            host: config.host,
            base_path: normalize_base_path(config.path),
            min_padding: config.min_padding,
            max_padding: config.max_padding,
            max_each_post_bytes: config.max_each_post_bytes,
            server_handler,
            resolver,
            sessions: SessionStore::new(
                Duration::from_secs(config.session_ttl_secs),
                config.max_buffered_posts,
            ),
        }
    }

    fn validate_host(&self, header_host: Option<&str>) -> bool {
        match (&self.host, header_host) {
            (None, _) => true,
            (Some(expected), Some(actual)) => {
                let normalized = actual
                    .split(':')
                    .next()
                    .map(|host| host.to_ascii_lowercase())
                    .unwrap_or_default();
                &normalized == expected
            }
            _ => false,
        }
    }

    fn validate_padding(
        &self,
        path_query: Option<&str>,
        headers: &hyper::HeaderMap,
    ) -> bool {
        let padding_len = path_query.and_then(query_padding_length).or_else(|| {
            headers
                .get(header::REFERER)
                .and_then(|value| value.to_str().ok())
                .and_then(referer_padding_length)
        });

        let Some(padding_len) = padding_len else {
            return true;
        };

        padding_len >= self.min_padding && padding_len <= self.max_padding
    }
}

async fn handle_request(
    request: Request<Incoming>,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) -> Result<Response<ResponseBody>, Infallible> {
    let host_header = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    let authority_host = request.uri().authority().map(|value| value.as_str());
    let request_host = host_header.or(authority_host);

    if !state.validate_host(request_host)
        || !state.validate_padding(request.uri().query(), request.headers())
    {
        debug!(
            method = %request.method(),
            path = %request.uri().path(),
            query = ?request.uri().query(),
            host = ?request_host,
            "xhttp request rejected by host/padding validation"
        );
        return Ok(simple_response(StatusCode::NOT_FOUND));
    }

    let path = request.uri().path().to_string();
    if !matches_base_path(&path, &state.base_path) {
        debug!(
            method = %request.method(),
            path = %path,
            base_path = %state.base_path,
            "xhttp request rejected by path validation"
        );
        return Ok(simple_response(StatusCode::NOT_FOUND));
    }
    let (session_id, seq) = extract_meta_path(&path, &state.base_path);

    let response = match *request.method() {
        Method::GET => match session_id {
            Some(session_id) if seq.is_none() => {
                handle_stream_down(state, session_id, peer_addr).await
            }
            _ => simple_response(StatusCode::METHOD_NOT_ALLOWED),
        },
        Method::POST => match (session_id, seq) {
            (None, None) => handle_stream_one(request, state, peer_addr).await,
            (Some(session_id), Some(seq)) => {
                handle_packet_up(request, state, session_id, seq, peer_addr).await
            }
            _ => simple_response(StatusCode::METHOD_NOT_ALLOWED),
        },
        _ => simple_response(StatusCode::METHOD_NOT_ALLOWED),
    };

    Ok(response)
}

async fn handle_stream_one(
    request: Request<Incoming>,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) -> Response<ResponseBody> {
    let (client_upload, server_read) = duplex(XHTTP_PIPE_CAPACITY);
    let (server_write, client_download) = duplex(XHTTP_PIPE_CAPACITY);
    let logical_stream = XhttpLogicalStream::new(server_read, server_write);

    spawn_handler_stream(logical_stream, state.clone(), peer_addr);

    let mut upload_writer = client_upload;
    let mut body = request.into_body();
    tokio::spawn(async move {
        while let Some(frame_result) = body.frame().await {
            match frame_result {
                Ok(frame) => {
                    if let Some(chunk) = frame.data_ref()
                        && upload_writer.write_all(chunk).await.is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = upload_writer.shutdown().await;
    });

    reader_response(StatusCode::OK, client_download)
}

async fn handle_stream_down(
    state: Arc<AppState>,
    session_id: String,
    peer_addr: std::net::SocketAddr,
) -> Response<ResponseBody> {
    let session = state.sessions.get_or_create(&session_id);
    session.fully_connected.store(true, Ordering::Release);

    if let Some(stream) = session.take_handler_stream().await {
        spawn_handler_stream(stream, state.clone(), peer_addr);
    }

    let Some(reader) = session.take_downlink_reader().await else {
        return simple_response(StatusCode::CONFLICT);
    };

    let sessions = state.sessions.clone();
    let session_id_for_drop = session_id.clone();
    let body_stream = ReaderStream::new(reader).filter_map(move |result| {
        let sessions = sessions.clone();
        let session_id = session_id_for_drop.clone();
        async move {
            match result {
                Ok(bytes) => Some(Ok(Frame::data(bytes))),
                Err(err) => {
                    error!("xhttp stream-down read failed: {}", err);
                    sessions.remove(&session_id).await;
                    None
                }
            }
        }
    });

    stream_response(StatusCode::OK, body_stream.boxed())
}

async fn handle_packet_up(
    request: Request<Incoming>,
    state: Arc<AppState>,
    session_id: String,
    seq: String,
    peer_addr: std::net::SocketAddr,
) -> Response<ResponseBody> {
    let Ok(seq) = seq.parse::<u64>() else {
        return simple_response(StatusCode::BAD_REQUEST);
    };

    let collected = match request.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return simple_response(StatusCode::BAD_REQUEST),
    };
    if collected.len() > state.max_each_post_bytes {
        return simple_response(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let session = state.sessions.get_or_create(&session_id);
    if let Some(stream) = session.take_handler_stream().await {
        spawn_handler_stream(stream, state.clone(), peer_addr);
    }

    let mut upload_state = session.upload.lock().await;
    match upload_state.packet_queue.push_packet(seq, collected) {
        Ok(()) => {}
        Err(QueueError::TooManyBuffered) => {
            return simple_response(StatusCode::CONFLICT);
        }
    }

    while let Some(chunk) = upload_state.packet_queue.pop_ready() {
        if let Err(err) = upload_state.writer.write_all(&chunk).await {
            error!("xhttp packet-up write failed: {}", err);
            state.sessions.remove(&session_id).await;
            return simple_response(StatusCode::BAD_GATEWAY);
        }
    }

    simple_response(StatusCode::OK)
}

fn spawn_handler_stream(
    stream: XhttpLogicalStream,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
) {
    tokio::spawn(async move {
        if let Err(err) = process_stream(
            stream,
            state.server_handler.clone(),
            state.resolver.clone(),
            peer_addr,
        )
        .await
        {
            error!("xhttp logical stream {} failed: {}", peer_addr, err);
        }
    });
}

fn reader_response(
    status: StatusCode,
    reader: DuplexStream,
) -> Response<ResponseBody> {
    let body_stream = ReaderStream::new(reader).filter_map(|result| async move {
        match result {
            Ok(bytes) => Some(Ok(Frame::data(bytes))),
            Err(err) => {
                error!("xhttp response read failed: {}", err);
                None
            }
        }
    });
    stream_response(status, body_stream.boxed())
}

fn stream_response<S>(status: StatusCode, body_stream: S) -> Response<ResponseBody>
where
    S: futures::Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + 'static,
{
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-accel-buffering", "no")
        .body(BodyExt::boxed_unsync(StreamBody::new(body_stream)))
        .unwrap_or_else(|_| simple_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn simple_response(status: StatusCode) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(BodyExt::boxed_unsync(Empty::<Bytes>::new()))
        .unwrap()
}

#[derive(Clone)]
struct SessionStore {
    inner: Arc<RwLock<HashMap<String, Arc<XhttpSession>>>>,
    ttl: Duration,
    max_buffered_posts: usize,
}

impl SessionStore {
    fn new(ttl: Duration, max_buffered_posts: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            max_buffered_posts,
        }
    }

    fn get_or_create(&self, session_id: &str) -> Arc<XhttpSession> {
        if let Some(existing) = self.inner.read().unwrap().get(session_id) {
            return existing.clone();
        }

        let session = Arc::new(XhttpSession::new(self.max_buffered_posts));
        let inserted = self
            .inner
            .write()
            .unwrap()
            .entry(session_id.to_string())
            .or_insert_with(|| session.clone())
            .clone();
        self.spawn_ttl_cleanup(session_id.to_string());
        inserted
    }

    async fn remove(&self, session_id: &str) {
        self.inner.write().unwrap().remove(session_id);
    }

    fn spawn_ttl_cleanup(&self, session_id: String) {
        let ttl = self.ttl;
        let store = self.clone();
        tokio::spawn(async move {
            sleep(ttl).await;

            let session = { store.inner.read().unwrap().get(&session_id).cloned() };

            if let Some(session) = session
                && !session.fully_connected.load(Ordering::Acquire)
            {
                store.remove(&session_id).await;
            }
        });
    }
}

struct XhttpSession {
    upload: Mutex<UploadState>,
    downlink_reader: Mutex<Option<DuplexStream>>,
    handler_stream: Mutex<Option<XhttpLogicalStream>>,
    fully_connected: AtomicBool,
}

impl XhttpSession {
    fn new(max_buffered_posts: usize) -> Self {
        let (client_upload, server_read) = duplex(XHTTP_PIPE_CAPACITY);
        let (server_write, client_download) = duplex(XHTTP_PIPE_CAPACITY);

        Self {
            upload: Mutex::new(UploadState {
                writer: client_upload,
                packet_queue: PacketQueue::new(max_buffered_posts),
            }),
            downlink_reader: Mutex::new(Some(client_download)),
            handler_stream: Mutex::new(Some(XhttpLogicalStream::new(
                server_read,
                server_write,
            ))),
            fully_connected: AtomicBool::new(false),
        }
    }

    async fn take_handler_stream(&self) -> Option<XhttpLogicalStream> {
        self.handler_stream.lock().await.take()
    }

    async fn take_downlink_reader(&self) -> Option<DuplexStream> {
        self.downlink_reader.lock().await.take()
    }
}

struct UploadState {
    writer: DuplexStream,
    packet_queue: PacketQueue,
}

struct XhttpLogicalStream {
    reader: DuplexStream,
    writer: DuplexStream,
}

impl XhttpLogicalStream {
    fn new(reader: DuplexStream, writer: DuplexStream) -> Self {
        Self { reader, writer }
    }
}

impl AsyncRead for XhttpLogicalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpLogicalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl AsyncPing for XhttpLogicalStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for XhttpLogicalStream {}

struct PacketQueue {
    next_seq: u64,
    buffered: BTreeMap<u64, Bytes>,
    ready: Vec<Bytes>,
    max_buffered_posts: usize,
}

impl PacketQueue {
    fn new(max_buffered_posts: usize) -> Self {
        Self {
            next_seq: 0,
            buffered: BTreeMap::new(),
            ready: Vec::new(),
            max_buffered_posts,
        }
    }

    fn push_packet(&mut self, seq: u64, data: Bytes) -> Result<(), QueueError> {
        if seq < self.next_seq {
            return Ok(());
        }
        if self.buffered.len() >= self.max_buffered_posts
            && !self.buffered.contains_key(&seq)
        {
            return Err(QueueError::TooManyBuffered);
        }

        self.buffered.insert(seq, data);
        while let Some(chunk) = self.buffered.remove(&self.next_seq) {
            self.ready.push(chunk);
            self.next_seq += 1;
        }

        Ok(())
    }

    fn pop_ready(&mut self) -> Option<Bytes> {
        if self.ready.is_empty() {
            return None;
        }
        Some(self.ready.remove(0))
    }
}

enum QueueError {
    TooManyBuffered,
}

fn normalize_base_path(mut path: String) -> String {
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    path
}

fn extract_meta_path(
    request_path: &str,
    base_path: &str,
) -> (Option<String>, Option<String>) {
    let trimmed_base_path = base_path.trim_end_matches('/');
    if request_path == trimmed_base_path {
        return (None, None);
    }

    let tail = &request_path[base_path.len()..];
    let mut segments = tail.split('/').filter(|segment| !segment.is_empty());
    let session_id = segments.next().map(ToOwned::to_owned);
    let seq = segments.next().map(ToOwned::to_owned);
    (session_id, seq)
}

fn matches_base_path(request_path: &str, base_path: &str) -> bool {
    let trimmed_base_path = base_path.trim_end_matches('/');
    request_path == trimmed_base_path || request_path.starts_with(base_path)
}

fn query_padding_length(query: &str) -> Option<usize> {
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key == "x_padding" {
            return Some(value.len());
        }
    }
    None
}

fn referer_padding_length(referer: &str) -> Option<usize> {
    let query = referer.split_once('?')?.1;
    query_padding_length(query)
}
