use std::{
    collections::{hash_map::Entry, HashMap},
    convert::TryFrom,
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use h3_quinn::BidiStream;
use http::{Request, Response, StatusCode};
use rand::{
    // distributions::{Alphanumeric, DistString},
    Rng, distr::{Alphanumeric, SampleString},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
};
use tracing::{debug, warn};

use crate::{
    address::NetLocation,
    config::server_config::Hysteria2Client,
    resolver::{resolve_single_address, Resolver},
    traffic::{record_transfer, TrafficContext},
};

const AUTH_PATH: &str = "/auth";
const AUTH_HEADER: &str = "Hysteria-Auth";
const CLIENT_CC_RX_HEADER: &str = "Hysteria-CC-RX";
const UDP_SUPPORT_HEADER: &str = "Hysteria-UDP";
const PADDING_HEADER: &str = "Hysteria-Padding";
const SUCCESS_STATUS: u16 = 233;
const TCP_REQUEST_ID: u64 = 0x401;
const MAX_ADDRESS_LEN: usize = 1024;
const PADDING_SCRATCH_LEN: usize = 1024;
const TCP_SUCCESS_STATUS: u8 = 0x00;
const TCP_ERROR_STATUS: u8 = 0x01;

#[derive(Clone)]
struct AuthContext {
    client: Hysteria2Client,
    #[allow(unused)]
    client_rx_limit: Option<u64>,
    udp_enabled: bool,
}

pub async fn process_hysteria2_connection(
    resolver: Arc<dyn Resolver>,
    clients: Arc<Vec<Hysteria2Client>>,
    conn: quinn::Incoming,
) -> std::io::Result<()> {
    let connection = conn.await?;

    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());
    let mut h3_conn = h3::server::Connection::new(h3_quinn_connection)
        .await
        .map_err(map_h3_error)?;

    let auth_ctx = auth_hysteria2_connection(&mut h3_conn, clients.clone()).await?;

    let http3_task = tokio::spawn(async move {
        if let Err(err) = drain_http3_requests(h3_conn).await {
            debug!("HTTP/3 request loop ended: {}", err);
        }
    });

    let proxy_result = if auth_ctx.udp_enabled {
        tokio::try_join!(
            drive_tcp_streams(connection.clone(), resolver.clone(), &auth_ctx),
            drive_udp_datagrams(connection, resolver.clone()),
        )
        .map(|_| ())
    } else {
        drive_tcp_streams(connection, resolver.clone(), &auth_ctx).await
    };

    let _ = http3_task.await;

    proxy_result
}

async fn auth_hysteria2_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    clients: Arc<Vec<Hysteria2Client>>,
) -> std::io::Result<AuthContext> {
    loop {
        match h3_conn.accept().await.map_err(map_h3_error)? {
            Some(resolver) => {
                let (req, mut stream) = resolver.resolve_request().await.map_err(map_h3_error)?;
                match validate_auth_request(req, clients.as_ref()) {
                    Ok(auth_ctx) => {
                        send_auth_success(&mut stream, auth_ctx.udp_enabled).await?;
                        return Ok(auth_ctx);
                    }
                    Err(AuthReject::NotAuthRequest) => {
                        send_simple_response(&mut stream, StatusCode::NOT_FOUND).await?;
                    }
                    Err(AuthReject::Unauthorized(msg)) => {
                        warn!("hysteria2 auth rejected: {}", msg);
                        send_simple_response(&mut stream, StatusCode::FORBIDDEN).await?;
                    }
                    Err(AuthReject::BadRequest(msg)) => {
                        warn!("hysteria2 auth request invalid: {}", msg);
                        send_simple_response(&mut stream, StatusCode::BAD_REQUEST).await?;
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

async fn drain_http3_requests(
    mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes>,
) -> std::io::Result<()> {
    while let Some(resolver) = h3_conn.accept().await.map_err(map_h3_error)? {
        let (req, mut stream) = resolver.resolve_request().await.map_err(map_h3_error)?;
        debug!(
            "received non-auth hysteria2 request: {} {}",
            req.method(),
            req.uri()
        );
        if let Err(err) = send_simple_response(&mut stream, StatusCode::NOT_FOUND).await {
            warn!("failed to respond to HTTP/3 request: {}", err);
            break;
        }
    }
    Ok(())
}

async fn drive_tcp_streams(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
    auth_ctx: &AuthContext,
) -> std::io::Result<()> {
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let resolver = resolver.clone();
                let client = auth_ctx.client.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_tcp_stream(send, recv, resolver, client).await {
                        debug!("hysteria2 tcp stream ended with error: {}", err);
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => return Ok(()),
            Err(err) => {
                return Err(Error::new(ErrorKind::Other, err));
            }
        }
    }
}

async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    resolver: Arc<dyn Resolver>,
    client: Hysteria2Client,
) -> std::io::Result<()> {
    let request = TcpRequest::read(&mut recv).await?;
    let target = if request.target.address().is_hostname() {
        resolve_single_address(&resolver, &request.target).await?
    } else {
        request.target.to_socket_addr()?
    };

    let tcp_stream = match tokio::net::TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(err) => {
            warn!("failed to connect to {}: {}", request.target, err);
            let _ = send_tcp_response(&mut send, TCP_ERROR_STATUS, "connect failed").await;
            let _ = send.finish();
            return Err(err);
        }
    };

    send_tcp_response(&mut send, TCP_SUCCESS_STATUS, "").await?;

    let context_identity = client
        .email
        .clone()
        .or_else(|| client.flow.clone())
        .unwrap_or(client.password.clone());
    let context = TrafficContext::new("hysteria2").with_identity(context_identity);

    proxy_tcp(send, recv, tcp_stream, context).await
}

struct TcpRequest {
    target: NetLocation,
}

impl TcpRequest {
    async fn read(stream: &mut quinn::RecvStream) -> std::io::Result<Self> {
        let request_id = read_varint(stream).await?;
        if request_id != TCP_REQUEST_ID {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unexpected hysteria2 request type: {:#x}", request_id),
            ));
        }

        let address_len = read_varint(stream).await?;
        if address_len > MAX_ADDRESS_LEN as u64 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "request address too long",
            ));
        }
        let address_len = address_len as usize;
        let mut address_bytes = vec![0; address_len];
        stream
            .read_exact(&mut address_bytes)
            .await
            .map_err(|err| Error::new(ErrorKind::Other, err))?;
        let address = String::from_utf8(address_bytes)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        let target = NetLocation::from_str(&address, None)?;

        let padding_len = read_varint(stream).await?;
        let padding_len = usize::try_from(padding_len)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "padding length too large"))?;
        skip_padding(stream, padding_len).await?;

        Ok(Self { target })
    }
}

async fn proxy_tcp(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    tcp_stream: tokio::net::TcpStream,
    context: TrafficContext,
) -> std::io::Result<()> {
    let mut quic_stream = QuicStream { send, recv };
    let mut tcp_stream = tcp_stream;
    match tokio::io::copy_bidirectional(&mut quic_stream, &mut tcp_stream).await {
        Ok((client_to_server, server_to_client)) => {
            debug!(
                "hysteria2 tcp stream forwarded {} bytes client->server and {} bytes server->client",
                client_to_server,
                server_to_client
            );
            record_transfer(Some(context), client_to_server, server_to_client);
            Ok(())
        }
        Err(err) => Err(err),
    }
}

struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send)
            .poll_flush(cx)
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send)
            .poll_shutdown(cx)
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }
}

enum AuthReject {
    NotAuthRequest,
    Unauthorized(&'static str),
    BadRequest(&'static str),
}

fn validate_auth_request(
    req: Request<()>,
    clients: &[Hysteria2Client],
) -> Result<AuthContext, AuthReject> {
    if req.method() != http::Method::POST || req.uri().path() != AUTH_PATH {
        return Err(AuthReject::NotAuthRequest);
    }

    let headers = req.headers();
    let provided = headers
        .get(AUTH_HEADER)
        .ok_or(AuthReject::Unauthorized("missing auth header"))?;
    let provided = provided
        .to_str()
        .map_err(|_| AuthReject::Unauthorized("invalid auth header"))?;

    let provided = provided.trim();

    let client = clients
        .iter()
        .find(|client| client.password == provided)
        .cloned()
        .ok_or(AuthReject::Unauthorized("password mismatch"))?;

    let client_rx_limit = match headers.get(CLIENT_CC_RX_HEADER) {
        Some(value) if !value.is_empty() => match value.to_str() {
            Ok(val) => {
                if val.eq_ignore_ascii_case("auto") {
                    None
                } else {
                    Some(
                        val.parse::<u64>()
                            .map_err(|_| AuthReject::BadRequest("invalid cc header"))?,
                    )
                }
            }
            Err(_) => return Err(AuthReject::BadRequest("invalid cc header")),
        },
        _ => None,
    };

    Ok(AuthContext {
        client,
        client_rx_limit,
        udp_enabled: true,
    })
}

async fn send_auth_success(
    stream: &mut h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    udp_enabled: bool,
) -> std::io::Result<()> {
    let padding = random_padding();
    let response = Response::builder()
        .status(StatusCode::from_u16(SUCCESS_STATUS).expect("valid hysteria2 status"))
        .header(
            UDP_SUPPORT_HEADER,
            if udp_enabled { "true" } else { "false" },
        )
        .header(CLIENT_CC_RX_HEADER, "0")
        .header(PADDING_HEADER, &padding)
        .header(http::header::CONTENT_LENGTH, "0")
        .body(())
        .map_err(|err| Error::new(ErrorKind::Other, err))?;
    stream.send_response(response).await.map_err(map_h3_error)?;
    stream.finish().await.map_err(map_h3_error)
}

async fn send_simple_response(
    stream: &mut h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    status: StatusCode,
) -> std::io::Result<()> {
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_LENGTH, "0")
        .body(())
        .map_err(|err| Error::new(ErrorKind::Other, err))?;
    stream.send_response(response).await.map_err(map_h3_error)?;
    stream.finish().await.map_err(map_h3_error)
}

fn random_padding() -> String {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(16..=64);
    Alphanumeric.sample_string(&mut rng, len)
}

fn map_h3_error<E>(err: E) -> std::io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    Error::new(ErrorKind::Other, err)
}

async fn read_varint(stream: &mut quinn::RecvStream) -> std::io::Result<u64> {
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .map_err(|err| Error::new(ErrorKind::Other, err))?;
    let prefix = first[0] >> 6;
    let mut value = (first[0] & 0x3f) as u64;
    let remaining = match prefix {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => 7,
        _ => unreachable!(),
    };

    if remaining > 0 {
        let mut buf = [0u8; 8];
        stream
            .read_exact(&mut buf[..remaining])
            .await
            .map_err(|err| Error::new(ErrorKind::Other, err))?;
        for &byte in &buf[..remaining] {
            value = (value << 8) | u64::from(byte);
        }
    }

    Ok(value)
}

async fn skip_padding(stream: &mut quinn::RecvStream, mut len: usize) -> std::io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    let mut scratch = [0u8; PADDING_SCRATCH_LEN];
    while len > 0 {
        let take = scratch.len().min(len);
        stream
            .read_exact(&mut scratch[..take])
            .await
            .map_err(|err| Error::new(ErrorKind::Other, err))?;
        len -= take;
    }
    Ok(())
}

async fn send_tcp_response(
    stream: &mut quinn::SendStream,
    status: u8,
    message: &str,
) -> std::io::Result<()> {
    let message_bytes = message.as_bytes();
    let mut buf = Vec::with_capacity(1 + message_bytes.len() + 16);
    buf.push(status);
    push_varint(&mut buf, message_bytes.len() as u64)?;
    buf.extend_from_slice(message_bytes);
    push_varint(&mut buf, 0)?;
    stream
        .write_all(&buf)
        .await
        .map_err(|err| Error::new(ErrorKind::Other, err))?;
    stream
        .flush()
        .await
        .map_err(|err| Error::new(ErrorKind::Other, err))
}

async fn drive_udp_datagrams(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let mut sessions: HashMap<u32, UdpSession> = HashMap::new();

    loop {
        let data = match connection.read_datagram().await {
            Ok(data) => data,
            Err(quinn::ConnectionError::ApplicationClosed { .. })
            | Err(quinn::ConnectionError::ConnectionClosed { .. }) => return Ok(()),
            Err(err) => return Err(Error::new(ErrorKind::Other, err)),
        };

        if data.len() < 9 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "hysteria2 datagram too short",
            ));
        }

        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let fragment_id = data[6];
        let fragment_count = data[7];

        let (address_len, varint_len) = decode_varint_from_slice(&data[8..])?;
        if address_len == 0 || address_len > MAX_ADDRESS_LEN {
            warn!(
                "Ignoring hysteria2 UDP packet {} with invalid address length {}",
                session_id, address_len
            );
            continue;
        }

        let address_start = 8 + varint_len;
        let payload_start = address_start + address_len;
        if data.len() < payload_start {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "hysteria2 datagram truncated before payload",
            ));
        }

        let address_bytes = data.slice(address_start..payload_start);
        let payload_fragment = data.slice(payload_start..);

        let address_str = match std::str::from_utf8(&address_bytes) {
            Ok(addr) => addr,
            Err(err) => {
                warn!("Ignoring hysteria2 UDP packet with invalid UTF-8: {}", err);
                continue;
            }
        };

        let remote_location = match NetLocation::from_str(address_str, None) {
            Ok(loc) => loc,
            Err(err) => {
                warn!(
                    "Failed to parse hysteria2 UDP address {}: {}",
                    address_str, err
                );
                continue;
            }
        };

        let session = match sessions.entry(session_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let session = create_udp_session(
                    session_id,
                    remote_location.clone(),
                    resolver.clone(),
                    connection.clone(),
                )
                .await?;
                entry.insert(session)
            }
        };

        if remote_location != session.last_location {
            let updated_addr = resolve_single_address(&resolver, &remote_location).await?;
            session.last_location = remote_location.clone();
            session.last_socket_addr = updated_addr;
        }

        let complete_payload = if fragment_count == 0 {
            warn!(
                "Ignoring hysteria2 UDP packet {} with zero fragments",
                session_id
            );
            continue;
        } else if fragment_count == 1 {
            payload_fragment
        } else {
            if fragment_id as usize >= fragment_count as usize {
                warn!(
                    "Ignoring hysteria2 UDP packet {} with invalid fragment id {}",
                    session_id, fragment_id
                );
                continue;
            }

            let entry = session
                .fragments
                .entry(packet_id)
                .or_insert_with(|| FragmentedPacket {
                    fragment_count,
                    fragment_received: 0,
                    packet_len: 0,
                    received: vec![None; fragment_count as usize],
                    remote_location: remote_location.clone(),
                });

            if entry.fragment_count != fragment_count {
                warn!(
                    "Mismatched fragment count for hysteria2 UDP packet {}",
                    session_id
                );
                session.fragments.remove(&packet_id);
                continue;
            }

            if entry.received[fragment_id as usize].is_some() {
                warn!(
                    "Duplicate fragment {} for hysteria2 UDP packet {}",
                    fragment_id, session_id
                );
                session.fragments.remove(&packet_id);
                continue;
            }

            entry.fragment_received += 1;
            entry.packet_len += payload_fragment.len();
            entry.received[fragment_id as usize] = Some(payload_fragment);

            if entry.fragment_received != entry.fragment_count {
                continue;
            }

            let FragmentedPacket {
                remote_location: remembered_location,
                received,
                packet_len,
                ..
            } = session.fragments.remove(&packet_id).unwrap();

            let mut assembled = BytesMut::with_capacity(packet_len);
            for fragment in received.into_iter() {
                if let Some(bytes) = fragment {
                    assembled.extend_from_slice(&bytes);
                }
            }

            if remembered_location != session.last_location {
                let updated_addr = resolve_single_address(&resolver, &remembered_location).await?;
                session.last_location = remembered_location;
                session.last_socket_addr = updated_addr;
            }

            assembled.freeze()
        };

        if let Err(err) = session
            .socket
            .send_to(complete_payload.as_ref(), session.last_socket_addr)
            .await
        {
            warn!(
                "Failed to forward hysteria2 UDP payload for session {}: {}",
                session_id, err
            );
        }
    }
}

struct UdpSession {
    socket: Arc<UdpSocket>,
    fragments: HashMap<u16, FragmentedPacket>,
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: NetLocation,
}

async fn create_udp_session(
    session_id: u32,
    remote_location: NetLocation,
    resolver: Arc<dyn Resolver>,
    connection: quinn::Connection,
) -> std::io::Result<UdpSession> {
    let remote_addr = resolve_single_address(&resolver, &remote_location).await?;
    let bind_addr: SocketAddr = if remote_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let socket_for_task = socket.clone();
    let connection_for_task = connection.clone();

    tokio::spawn(async move {
        if let Err(err) =
            run_udp_remote_to_local_loop(session_id, connection_for_task, socket_for_task).await
        {
            debug!(
                "hysteria2 UDP remote-to-local loop for session {} ended: {}",
                session_id, err
            );
        }
    });

    Ok(UdpSession {
        socket,
        fragments: HashMap::new(),
        last_location: remote_location,
        last_socket_addr: remote_addr,
    })
}

async fn run_udp_remote_to_local_loop(
    session_id: u32,
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| Error::new(ErrorKind::Other, "peer does not support datagrams"))?
        as usize;

    let mut next_packet_id: u16 = 0;
    let mut buf = vec![0u8; 65535];

    loop {
        let (payload_len, src_addr) = socket.recv_from(&mut buf).await.map_err(|err| {
            Error::new(
                ErrorKind::Other,
                format!("failed to receive hysteria2 UDP payload: {}", err),
            )
        })?;

        let address_bytes = Bytes::from(src_addr.to_string().into_bytes());
        let mut address_len_buf = Vec::with_capacity(8);
        push_varint(&mut address_len_buf, address_bytes.len() as u64)?;
        let address_len_bytes = Bytes::from(address_len_buf);

        let header_overhead = 4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();
        if header_overhead >= max_datagram_size {
            warn!(
                "hysteria2 UDP datagram header larger than max datagram size ({} >= {})",
                header_overhead, max_datagram_size
            );
            continue;
        }

        let available_payload = max_datagram_size - header_overhead;
        if available_payload == 0 {
            warn!("hysteria2 UDP available payload is zero, skipping packet");
            continue;
        }

        if payload_len <= available_payload {
            let mut datagram = BytesMut::with_capacity(header_overhead + payload_len);
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&next_packet_id.to_be_bytes());
            datagram.extend_from_slice(&[0, 1]);
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[..payload_len]);

            connection
                .send_datagram(datagram.freeze())
                .map_err(|err| Error::new(ErrorKind::Other, err))?;
        } else {
            let fragment_count = (payload_len + available_payload - 1) / available_payload;
            if fragment_count > u8::MAX as usize {
                warn!(
                    "hysteria2 UDP packet too large to fragment ({} fragments)",
                    fragment_count
                );
                continue;
            }

            for fragment_id in 0..fragment_count {
                let start = fragment_id * available_payload;
                let end = std::cmp::min(start + available_payload, payload_len);

                let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&next_packet_id.to_be_bytes());
                datagram.extend_from_slice(&[fragment_id as u8, fragment_count as u8]);
                datagram.extend_from_slice(&address_len_bytes);
                datagram.extend_from_slice(&address_bytes);
                datagram.extend_from_slice(&buf[start..end]);

                connection
                    .send_datagram(datagram.freeze())
                    .map_err(|err| Error::new(ErrorKind::Other, err))?;
            }
        }

        next_packet_id = next_packet_id.wrapping_add(1);
    }
}

fn decode_varint_from_slice(data: &[u8]) -> std::io::Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "varint truncated in hysteria2 datagram",
        ));
    }

    let first = data[0];
    let prefix = first >> 6;
    let bytes = match prefix {
        0 => 1,
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

fn push_varint(buf: &mut Vec<u8>, value: u64) -> std::io::Result<()> {
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
