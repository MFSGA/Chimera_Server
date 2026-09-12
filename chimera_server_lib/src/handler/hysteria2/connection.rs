use std::{
    collections::HashMap,
    convert::TryFrom,
    future::{Future, poll_fn},
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{
    RecvStream as H3RecvStream, SendStream as H3SendStream, SendStreamUnframed,
};
use h3_quinn::BidiStream;
use http::{Request, Response, StatusCode};
use rand::{
    RngExt,
    // distributions::{Alphanumeric, DistString},
    distr::{Alphanumeric, SampleString},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    task::JoinSet,
};
use tracing::{debug, warn};

#[cfg(test)]
use std::path::Path;

use crate::{
    address::NetLocation,
    config::server_config::{Hysteria2Client, Hysteria2ServerConfig},
    outbound::connect_tcp_outbound_with_vless_route,
    resolver::Resolver,
    runtime::DataPlaneRuntime,
    traffic::{
        MeteredStream, TrafficContext, TrafficDirection, register_connection,
    },
};

const AUTH_URI: &str = "https://hysteria/auth";
const AUTH_HEADER: &str = "Hysteria-Auth";
const CLIENT_CC_RX_HEADER: &str = "Hysteria-CC-RX";
const UDP_SUPPORT_HEADER: &str = "Hysteria-UDP";
const PADDING_HEADER: &str = "Hysteria-Padding";
const SUCCESS_STATUS: u16 = 233;
const TCP_REQUEST_ID: u64 = 0x401;
const MAX_ADDRESS_LEN: usize = 2048;
const MAX_TCP_REQUEST_PADDING_LEN: u64 = 4096;
const PADDING_SCRATCH_LEN: usize = 1024;
const TCP_SUCCESS_STATUS: u8 = 0x00;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
// Match Shoes/sing-box: unauthenticated Hysteria2 QUIC connections only get a
// short window to complete the HTTP/3 authentication exchange.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);
const CLOSE_ERR_CODE_OK: u32 = 0x100;

#[derive(Clone)]
struct AuthContext {
    client: Hysteria2Client,
    udp_enabled: bool,
    vless_route: u32,
    xray_compat: bool,
}

struct AuthInfo {
    client: Hysteria2Client,
    client_rx_limit: Option<u64>,
    vless_route: u32,
}

#[derive(Debug)]
struct HysteriaUserState {
    clients: Vec<Hysteria2Client>,
    masked_ids: HashMap<[u8; 16], String>,
}

#[derive(Debug)]
pub(crate) struct HysteriaUserStore {
    state: RwLock<HysteriaUserState>,
}

impl HysteriaUserStore {
    pub(crate) fn new(clients: Vec<Hysteria2Client>) -> Self {
        let mut state = HysteriaUserState {
            clients: Vec::with_capacity(clients.len()),
            masked_ids: HashMap::new(),
        };
        for client in clients {
            if client.xray_uuid_route {
                upsert_xray_hysteria_user(&mut state, client);
            } else {
                state.clients.push(client);
            }
        }
        Self {
            state: RwLock::new(state),
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<Hysteria2Client> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clients
            .clone()
    }

    pub(crate) fn add_user(&self, client: Hysteria2Client) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        upsert_xray_hysteria_user(&mut state, client);
    }

    pub(crate) fn remove_user_by_email(&self, email: &str) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(index) = state.clients.iter().position(|client| {
            client.xray_uuid_route && client.email.as_deref().unwrap_or("") == email
        }) else {
            return;
        };
        let client = state.clients.remove(index);
        if let Some((masked_id, _)) = xray_uuid_auth_key(&client.password) {
            // Xray deletes the secondary UUID index directly. It does not
            // restore an older user that shared the same masked ID.
            state.masked_ids.remove(&masked_id);
        }
    }

    fn match_auth(
        &self,
        provided: &str,
        xray_compat: bool,
    ) -> Option<(Hysteria2Client, u32)> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let xray_has_users =
            xray_compat && state.clients.iter().any(|client| client.xray_uuid_route);

        if let Some(client) = state
            .clients
            .iter()
            .rev()
            .find(|client| {
                !client.xray_uuid_route
                    && (!xray_has_users || !client.xray_transport_auth_fallback)
                    && client.password == provided
            })
            .cloned()
        {
            return Some((client, 0));
        }

        if let Some((masked_id, vless_route)) = xray_uuid_auth_key(provided) {
            let auth = state.masked_ids.get(&masked_id)?;
            let client = state
                .clients
                .iter()
                .rev()
                .find(|client| client.xray_uuid_route && client.password == *auth)?
                .clone();
            return Some((client, vless_route));
        }

        state
            .clients
            .iter()
            .rev()
            .find(|client| client.xray_uuid_route && client.password == provided)
            .cloned()
            .map(|client| (client, 0))
    }
}

fn upsert_xray_hysteria_user(
    state: &mut HysteriaUserState,
    client: Hysteria2Client,
) {
    state.clients.retain(|existing| {
        !existing.xray_uuid_route || existing.password != client.password
    });
    if let Some((masked_id, _)) = xray_uuid_auth_key(&client.password) {
        state.masked_ids.insert(masked_id, client.password.clone());
    }
    state.clients.push(client);
}

fn hysteria2_traffic_context(
    client: &Hysteria2Client,
    inbound_tag: &str,
    peer_addr: SocketAddr,
    runtime: &DataPlaneRuntime,
) -> TrafficContext {
    let identity = client
        .email
        .clone()
        .unwrap_or_else(|| client.password.clone());
    let mut context = TrafficContext::new("hysteria2")
        .with_identity(identity)
        .with_inbound_tag(inbound_tag.to_string())
        .with_client_ip(peer_addr.ip())
        .with_user_level(client.level);
    runtime.apply_traffic_stats_policy(&mut context);
    context
}

pub async fn process_hysteria2_connection(
    resolver: Arc<dyn Resolver>,
    config: Arc<Hysteria2ServerConfig>,
    tx_bps: Arc<AtomicU64>,
    connection: quinn::Connection,
    inbound_tag: Arc<String>,
    runtime: DataPlaneRuntime,
    xray_proxy_transport: Option<Arc<XrayProxyTransport>>,
) -> std::io::Result<()> {
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());
    let mut h3_conn = h3::server::Connection::new(h3_quinn_connection)
        .await
        .map_err(|err| {
            Error::other(format!("hysteria2 H3 driver creation failed: {err}"))
        })?;
    debug!("hysteria2 QUIC established");
    debug!("hysteria2 H3 driver created");

    let user_store = runtime.hysteria_user_store(inbound_tag.as_str());
    let auth_ctx = match await_authentication(
        auth_hysteria2_connection(
            &mut h3_conn,
            config.as_ref(),
            user_store.as_deref(),
            tx_bps.clone(),
            xray_proxy_transport.as_deref(),
        ),
        config.xray_compat,
    )
    .await
    {
        Ok(auth_ctx) => auth_ctx,
        Err(err) => {
            let kind = err.kind();
            let reason: &[u8] = if kind == ErrorKind::TimedOut {
                b"auth timeout"
            } else {
                b"auth failed"
            };
            connection.close(CLOSE_ERR_CODE_OK.into(), reason);
            return Err(Error::new(
                kind,
                format!("hysteria2 authentication failed: {err}"),
            ));
        }
    };

    // Keep post-authentication custom Hysteria2 streams under the same H3
    // connection owner that handled authentication. Modern Xray dispatches its
    // 0x401 TCP streams through the HTTP/3 stream queue; a second raw Quinn
    // accept loop can race that queue and lose streams.
    let udp_idle_timeout = config
        .xray_udp_idle_timeout_secs
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs);
    let peer_addr = connection.remote_address();

    if auth_ctx.udp_enabled {
        tokio::try_join!(
            drive_tcp_streams(
                &mut h3_conn,
                resolver.clone(),
                &auth_ctx,
                inbound_tag.clone(),
                peer_addr,
                runtime.clone(),
            ),
            drive_udp_datagrams(
                connection,
                resolver,
                &auth_ctx,
                inbound_tag,
                runtime,
                udp_idle_timeout,
            ),
        )
        .map(|_| ())
    } else {
        drive_tcp_streams(
            &mut h3_conn,
            resolver,
            &auth_ctx,
            inbound_tag,
            peer_addr,
            runtime,
        )
        .await
    }
}

fn configured_auth_timeout(xray_compat: bool) -> Option<Duration> {
    (!xray_compat).then_some(AUTH_TIMEOUT)
}

async fn await_authentication<F, T>(
    future: F,
    xray_compat: bool,
) -> std::io::Result<T>
where
    F: Future<Output = std::io::Result<T>>,
{
    match configured_auth_timeout(xray_compat) {
        Some(timeout) => {
            tokio::time::timeout(timeout, future).await.map_err(|_| {
                Error::new(ErrorKind::TimedOut, "authentication timeout")
            })?
        }
        None => future.await,
    }
}

async fn auth_hysteria2_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    config: &Hysteria2ServerConfig,
    user_store: Option<&HysteriaUserStore>,
    tx_bps: Arc<AtomicU64>,
    xray_proxy_transport: Option<&XrayProxyTransport>,
) -> std::io::Result<AuthContext> {
    loop {
        match h3_conn.accept().await.map_err(map_h3_error)? {
            Some(resolver) => {
                let (req, mut stream) =
                    resolver.resolve_request().await.map_err(|err| {
                        Error::other(format!(
                            "hysteria2 auth resolve_request failed: {err}"
                        ))
                    })?;
                debug!(method = %req.method(), uri = %req.uri(), "hysteria2 auth request received");
                let request_method = req.method().clone();
                let request_uri = req.uri().clone();
                let request_headers = req.headers().clone();
                let auth_result = match user_store {
                    Some(store) => validate_auth_request_with_store(
                        req,
                        store,
                        config.xray_compat,
                    ),
                    None => validate_auth_request(
                        req,
                        config.clients.as_ref(),
                        config.xray_compat,
                    ),
                };
                match auth_result {
                    Ok(auth_info) => {
                        let (actual_tx, response_rx, response_rx_auto) =
                            resolve_bandwidth_settings(
                                config,
                                auth_info.client_rx_limit,
                            );
                        let congestion_tx = resolve_congestion_tx_bps(
                            config,
                            auth_info.client_rx_limit,
                            actual_tx,
                        );
                        tx_bps.store(congestion_tx, Ordering::Relaxed);
                        debug!(status = SUCCESS_STATUS, "hysteria2 auth accepted");
                        send_auth_success(
                            &mut stream,
                            config.udp_enabled,
                            response_rx,
                            response_rx_auto,
                            config.xray_compat,
                        )
                        .await
                        .map_err(|err| {
                            Error::other(format!(
                                "hysteria2 auth response failed: {err}"
                            ))
                        })?;
                        debug!("hysteria2 auth response finished");
                        return Ok(AuthContext {
                            client: auth_info.client,
                            udp_enabled: config.udp_enabled,
                            vless_route: auth_info.vless_route,
                            xray_compat: config.xray_compat,
                        });
                    }
                    Err(reject) => {
                        match &reject {
                            AuthReject::NotAuthRequest => {}
                            AuthReject::Unauthorized(msg) => {
                                warn!("hysteria2 auth rejected: {}", msg);
                            }
                        }
                        send_auth_reject_response(
                            &mut stream,
                            &request_method,
                            &request_uri,
                            &request_headers,
                            config,
                            xray_proxy_transport,
                        )
                        .await?;
                    }
                }
            }
            None => {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "h3 connection closed before authentication",
                ));
            }
        }
    }
}

mod tcp_stream;
use tcp_stream::*;

#[derive(Debug)]
enum AuthReject {
    NotAuthRequest,
    Unauthorized(&'static str),
}

fn resolve_congestion_tx_bps(
    config: &Hysteria2ServerConfig,
    client_rx_limit: Option<u64>,
    shoes_tx_bps: u64,
) -> u64 {
    match config.xray_congestion.as_deref() {
        None if config.xray_compat => 0,
        None => shoes_tx_bps,
        Some("reno") | Some("bbr") => 0,
        Some("") | Some("brutal") => {
            let up = config.xray_brutal_up.unwrap_or(0);
            let down = client_rx_limit.unwrap_or(0);
            if up == 0 || down == 0 {
                0
            } else {
                up.min(down)
            }
        }
        Some("force-brutal") => config.xray_brutal_up.unwrap_or(0),
        Some(_) => unreachable!("validated Xray congestion mode"),
    }
}

fn resolve_bandwidth_settings(
    config: &Hysteria2ServerConfig,
    client_rx_limit: Option<u64>,
) -> (u64, u64, bool) {
    if config.xray_compat || config.xray_congestion.is_some() {
        return (
            client_rx_limit.unwrap_or(0),
            config.xray_brutal_down.unwrap_or(0),
            false,
        );
    }
    if config.ignore_client_bandwidth {
        return (0, config.bandwidth.max_rx, true);
    }

    let mut actual_tx = client_rx_limit.unwrap_or(0);
    if actual_tx > 0
        && config.bandwidth.max_tx > 0
        && actual_tx > config.bandwidth.max_tx
    {
        actual_tx = config.bandwidth.max_tx;
    }

    (actual_tx, config.bandwidth.max_rx, false)
}

fn validate_auth_request(
    req: Request<()>,
    clients: &[Hysteria2Client],
    xray_compat: bool,
) -> Result<AuthInfo, AuthReject> {
    validate_auth_request_with_match(req, xray_compat, |provided| {
        match_hysteria_auth(provided, clients, xray_compat)
    })
}

fn validate_auth_request_with_store(
    req: Request<()>,
    store: &HysteriaUserStore,
    xray_compat: bool,
) -> Result<AuthInfo, AuthReject> {
    validate_auth_request_with_match(req, xray_compat, |provided| {
        store.match_auth(provided, xray_compat)
    })
}

fn validate_auth_request_with_match<F>(
    req: Request<()>,
    xray_compat: bool,
    match_auth: F,
) -> Result<AuthInfo, AuthReject>
where
    F: FnOnce(&str) -> Option<(Hysteria2Client, u32)>,
{
    let is_auth_request = if xray_compat {
        req.method() == http::Method::POST
            && req.uri().authority().map(|authority| authority.as_str())
                == Some("hysteria")
            && xray_auth_path_matches(req.uri().path())
    } else {
        req.method() == http::Method::POST && req.uri() == AUTH_URI
    };
    if !is_auth_request {
        return Err(AuthReject::NotAuthRequest);
    }

    let headers = req.headers();
    let provided = match headers.get(AUTH_HEADER) {
        Some(value) => value
            .to_str()
            .map_err(|_| AuthReject::Unauthorized("invalid auth header"))?,
        None if xray_compat => "",
        None => return Err(AuthReject::Unauthorized("missing auth header")),
    };

    let (client, vless_route) =
        match_auth(provided).ok_or(AuthReject::Unauthorized("password mismatch"))?;

    // Xray ignores Hysteria-CC-RX parse errors, while shoes does not consume
    // this header at all. Treat malformed values as an unspecified/zero limit
    // instead of rejecting an otherwise valid authentication request.
    let client_rx_limit = headers
        .get(CLIENT_CC_RX_HEADER)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            (!value.eq_ignore_ascii_case("auto"))
                .then(|| value.parse::<u64>().ok())
                .flatten()
        });

    Ok(AuthInfo {
        client,
        client_rx_limit,
        vless_route,
    })
}

fn xray_auth_path_matches(path: &str) -> bool {
    const AUTH_PATH: &[u8] = b"/auth";
    let raw = path.as_bytes();
    let mut raw_index = 0usize;
    let mut decoded_index = 0usize;

    while raw_index < raw.len() {
        let byte = if raw[raw_index] == b'%' {
            if raw_index + 2 >= raw.len() {
                return false;
            }
            let Some(high) = hex_nibble(raw[raw_index + 1]) else {
                return false;
            };
            let Some(low) = hex_nibble(raw[raw_index + 2]) else {
                return false;
            };
            raw_index += 3;
            (high << 4) | low
        } else {
            let byte = raw[raw_index];
            raw_index += 1;
            byte
        };

        if AUTH_PATH.get(decoded_index).copied() != Some(byte) {
            return false;
        }
        decoded_index += 1;
    }

    decoded_index == AUTH_PATH.len()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn match_hysteria_auth(
    provided: &str,
    clients: &[Hysteria2Client],
    xray_compat: bool,
) -> Option<(Hysteria2Client, u32)> {
    // Xray consults transport-level `hysteriaSettings.auth` only while its
    // inbound user validator is empty. A dynamic AddUser therefore disables
    // the fallback until the last real user is removed again.
    let xray_has_users = xray_compat
        && clients
            .iter()
            .any(|client| !client.xray_transport_auth_fallback);

    // Chimera's shoes/native `id` credentials and Xray's transport auth
    // fallback remain exact even when they happen to look like UUIDs.
    if let Some(client) = clients
        .iter()
        .rev()
        .find(|client| {
            !client.xray_uuid_route
                && (!xray_has_users || !client.xray_transport_auth_fallback)
                && client.password == provided
        })
        .cloned()
    {
        return Some((client, 0));
    }

    if let Some((provided_key, vless_route)) = xray_uuid_auth_key(provided) {
        // Xray's UUID validator stores the masked ID in a map, so later users
        // replace earlier users that share the same bytes outside 6..=7.
        if let Some(client) = clients.iter().rev().find_map(|client| {
            if !client.xray_uuid_route {
                return None;
            }
            let (configured_key, _) = xray_uuid_auth_key(&client.password)?;
            (configured_key == provided_key).then(|| client.clone())
        }) {
            return Some((client, vless_route));
        }
    }

    // Non-UUID Xray auth follows the same last-write-wins user-map behavior.
    clients
        .iter()
        .rev()
        .find(|client| client.xray_uuid_route && client.password == provided)
        .cloned()
        .map(|client| (client, 0))
}

fn xray_uuid_auth_key(auth: &str) -> Option<([u8; 16], u32)> {
    let uuid = uuid::Uuid::parse_str(auth).ok()?;
    let mut key = *uuid.as_bytes();
    let vless_route = u16::from_be_bytes([key[6], key[7]]) as u32;
    key[6] = 0;
    key[7] = 0;
    Some((key, vless_route))
}

fn build_auth_success_response(
    udp_enabled: bool,
    server_rx_limit: u64,
    rx_auto: bool,
    xray_compat: bool,
) -> std::io::Result<Response<()>> {
    let padding = random_auth_padding(xray_compat);
    let cc_rx_value = if !xray_compat {
        // Shoes always advertises zero receive bandwidth in its auth response,
        // regardless of the local bandwidth settings used by Chimera.
        "0".to_string()
    } else if rx_auto {
        "auto".to_string()
    } else {
        server_rx_limit.to_string()
    };
    let mut response = Response::builder()
        .status(
            StatusCode::from_u16(SUCCESS_STATUS).expect("valid hysteria2 status"),
        )
        .header(
            UDP_SUPPORT_HEADER,
            if udp_enabled { "true" } else { "false" },
        )
        .header(CLIENT_CC_RX_HEADER, cc_rx_value.as_str())
        .header(PADDING_HEADER, &padding)
        .body(())
        .map_err(Error::other)?;
    if xray_compat {
        // Xray's quic-go response writer adds Content-Length: 0 when an
        // empty handler response completes. Shoes sends the h3 response as
        // built and therefore leaves Content-Length absent.
        response.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("0"),
        );
        xray_response_add_date(&mut response)?;
    }
    Ok(response)
}

async fn send_auth_success(
    stream: &mut h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    udp_enabled: bool,
    server_rx_limit: u64,
    rx_auto: bool,
    xray_compat: bool,
) -> std::io::Result<()> {
    let response = build_auth_success_response(
        udp_enabled,
        server_rx_limit,
        rx_auto,
        xray_compat,
    )?;
    stream.send_response(response).await.map_err(map_h3_error)?;
    stream.finish().await.map_err(map_h3_error)
}

fn xray_response_add_date(response: &mut Response<()>) -> std::io::Result<()> {
    if !response.headers().contains_key(http::header::DATE) {
        let date = xray_format_http_date(std::time::SystemTime::now());
        response.headers_mut().insert(
            http::header::DATE,
            http::HeaderValue::from_str(&date).map_err(Error::other)?,
        );
    }
    Ok(())
}

fn xray_string_masquerade_response(
    method: &http::Method,
    masquerade: &crate::config::server_config::Hysteria2MasqueradeStringConfig,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let body = Bytes::copy_from_slice(masquerade.content.as_bytes());
    let status = if masquerade.status_code == 0 {
        StatusCode::OK
    } else {
        StatusCode::from_u16(masquerade.status_code as u16).map_err(Error::other)?
    };
    let mut response = Response::builder()
        .status(status)
        .body(())
        .map_err(Error::other)?;
    for (name, value) in &masquerade.headers {
        let name =
            http::HeaderName::from_bytes(name.as_bytes()).map_err(Error::other)?;
        let value = http::HeaderValue::from_str(value).map_err(Error::other)?;
        response.headers_mut().insert(name, value);
    }

    xray_response_add_date(&mut response)?;

    let body_allowed = !(status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED);
    let written_len = if body_allowed { body.len() } else { 0 };
    if !response
        .headers()
        .contains_key(http::header::CONTENT_LENGTH)
    {
        response.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&written_len.to_string())
                .map_err(Error::other)?,
        );
    }
    if method != http::Method::HEAD
        && body_allowed
        && !body.is_empty()
        && !response.headers().contains_key(http::header::CONTENT_TYPE)
        && response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .is_none_or(|value| value.as_bytes().is_empty())
    {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(xray_detect_content_type(
                &body[..body.len().min(512)],
            )),
        );
    }

    Ok((response, body_allowed.then_some(body)))
}

fn auth_reject_response(
    xray_compat: bool,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    if xray_compat {
        let body = Bytes::from_static(b"404 page not found\n");
        let mut response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header("x-content-type-options", "nosniff")
            .header(http::header::CONTENT_LENGTH, body.len().to_string())
            .body(())
            .map_err(Error::other)?;
        xray_response_add_date(&mut response)?;
        Ok((response, Some(body)))
    } else {
        // Shoes sends the h3 response exactly as built, so an empty reject
        // response does not gain an implicit Content-Length header.
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .map_err(Error::other)?;
        Ok((response, None))
    }
}

async fn send_auth_reject_response(
    stream: &mut h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    method: &http::Method,
    uri: &http::Uri,
    request_headers: &http::HeaderMap,
    config: &Hysteria2ServerConfig,
    xray_proxy_transport: Option<&XrayProxyTransport>,
) -> std::io::Result<()> {
    let (mut response, body) = if let Some(masquerade) =
        config.xray_masquerade_file.as_ref()
    {
        xray_file_masquerade_response(method, uri, request_headers, &masquerade.dir)
            .await?
    } else if let Some(masquerade) = config.xray_masquerade_proxy.as_ref() {
        let mut request_body = BytesMut::new();
        while let Some(mut data) = stream.recv_data().await.map_err(map_h3_error)? {
            request_body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        match xray_proxy_transport {
            Some(transport) => {
                xray_proxy_masquerade_response_with_transport(
                    method,
                    uri,
                    request_headers,
                    request_body.freeze(),
                    masquerade,
                    transport,
                )
                .await?
            }
            None => {
                xray_proxy_masquerade_response(
                    method,
                    uri,
                    request_headers,
                    request_body.freeze(),
                    masquerade,
                )
                .await?
            }
        }
    } else if let Some(masquerade) = config.xray_masquerade_string.as_ref() {
        xray_string_masquerade_response(method, masquerade)?
    } else {
        auth_reject_response(config.xray_compat)?
    };
    if config.xray_compat {
        xray_response_add_date(&mut response)?;
    }
    stream.send_response(response).await.map_err(map_h3_error)?;
    if method != http::Method::HEAD
        && let Some(body) = body
    {
        stream.send_data(body).await.map_err(map_h3_error)?;
    }
    stream.finish().await.map_err(map_h3_error)
}

mod proxy_masquerade;
use proxy_masquerade::*;

pub(crate) fn build_xray_proxy_transport(
    masquerade: Option<
        &crate::config::server_config::Hysteria2MasqueradeProxyConfig,
    >,
) -> std::io::Result<Option<Arc<XrayProxyTransport>>> {
    build_xray_proxy_transport_impl(masquerade)
}

mod file_masquerade;
use file_masquerade::*;

fn random_auth_padding(xray_compat: bool) -> String {
    let mut rng = rand::rng();
    let len = if xray_compat {
        rng.random_range(256..2048)
    } else {
        rng.random_range(1..80)
    };
    Alphanumeric.sample_string(&mut rng, len)
}

fn map_h3_error<E>(err: E) -> std::io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    Error::other(err)
}

mod udp_session;
use udp_session::*;

pub(super) fn decode_varint_from_slice(
    data: &[u8],
) -> std::io::Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "varint truncated in hysteria2 datagram",
        ));
    }

    let first = data[0];
    let prefix = first >> 6;
    if prefix > 3 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("invalid hysteria2 varint prefix in datagram: {prefix}"),
        ));
    }
    let bytes = match prefix {
        0 => 1usize,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if data.len() < bytes {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "varint truncated in hysteria2 datagram",
        ));
    }

    let mut value = (first & 0x3f) as u64;
    for &byte in &data[1..bytes] {
        value = (value << 8) | u64::from(byte);
    }

    let numeric = usize::try_from(value).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "varint too large in hysteria2 datagram",
        )
    })?;

    Ok((numeric, bytes))
}

pub(super) fn push_varint(buf: &mut Vec<u8>, value: u64) -> std::io::Result<()> {
    if value <= 0x3f {
        buf.push(value as u8);
    } else if value <= 0x3fff {
        buf.push(0x40 | ((value >> 8) as u8 & 0x3f));
        buf.push((value & 0xff) as u8);
    } else if value <= 0x3fff_ffff {
        buf.push(0x80 | ((value >> 24) as u8 & 0x3f));
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else if value <= 0x3fff_ffff_ffff_ffff {
        buf.push(0xc0 | ((value >> 56) as u8 & 0x3f));
        buf.push((value >> 48) as u8);
        buf.push((value >> 40) as u8);
        buf.push((value >> 32) as u8);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "varint value too large",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
