#![cfg(feature = "vless")]

use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::io::ReadBuf;
use tracing::warn;

use crate::{
    async_stream::AsyncStream,
    config::server_config::{VlessFallback, VlessUser},
    resolver::{NativeResolver, Resolver},
    traffic::{AccessTransport, TrafficContext},
    util::prefixed_stream::PrefixedStream,
};

mod fallback;
pub(crate) mod protocol;
mod reality_vision_stream;
#[cfg(feature = "tls")]
mod tls_vision;
mod udp_stream;
mod vision;
mod vision_pad;
mod vision_stream;
mod vision_tls;
mod vision_unpad;

use self::{
    fallback::{
        extend_prefix_for_path, read_vless_auth_prefix, select_vless_fallback,
        vless_fallback_result,
    },
    protocol::{
        COMMAND_MUX, COMMAND_TCP, ParsedVlessHeader, XTLS_VISION_FLOW,
        read_request_header,
    },
    udp_stream::VlessUdpStream,
};
use super::{
    tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
    xudp::message_stream::XudpMessageStream,
};
use vision_pad::{append_with_command, append_with_uuid_and_command};
use vision_unpad::{UnpadCommand, VisionUnpadder};

#[cfg(feature = "tls")]
pub(crate) use tls_vision::VisionRecordIo;
#[cfg(feature = "tls")]
pub(crate) use vision::{
    ParsedVisionUser, parse_vision_users, setup_tls_vision_server_stream,
};
pub use vision::{VisionVlessTcpHandler, setup_reality_mixed_vless_server_stream};

const SERVER_RESPONSE_HEADER: &[u8] = &[0u8, 0u8];

#[derive(Debug)]
pub struct VlessTcpHandler {
    users: Vec<(Box<[u8]>, String, String, String)>,
    fallbacks: Vec<VlessFallback>,
    inbound_tag: String,
}

impl VlessTcpHandler {
    pub fn new(users: &[VlessUser], inbound_tag: &str) -> Self {
        Self::new_with_fallbacks(users, &[], inbound_tag)
    }

    pub fn new_with_fallbacks(
        users: &[VlessUser],
        fallbacks: &[VlessFallback],
        inbound_tag: &str,
    ) -> Self {
        Self {
            users: users
                .iter()
                .map(|user| {
                    (
                        parse_hex(&user.user_id),
                        user.user_label.clone(),
                        user.flow.clone(),
                        user.user_id.clone(),
                    )
                })
                .collect(),
            fallbacks: fallbacks.to_vec(),
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

pub fn users_require_vision(users: &[VlessUser]) -> bool {
    users.iter().any(|user| user.flow == XTLS_VISION_FLOW)
}

impl VlessTcpHandler {
    async fn setup_server_stream_with_metadata(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        server_name: &str,
        alpn: &str,
        resolver: Arc<dyn Resolver>,
    ) -> std::io::Result<TcpServerSetupResult> {
        if !self.fallbacks.is_empty() {
            let (mut prefix, candidate) =
                read_vless_auth_prefix(&mut server_stream).await;
            let authenticated = candidate.is_some_and(|candidate| {
                self.users.iter().any(|(stored_user_id, _, _, _)| {
                    stored_user_id.len() == 16
                        && stored_user_id.as_ref() == candidate.as_slice()
                })
            });
            if !authenticated {
                extend_prefix_for_path(
                    &mut server_stream,
                    &mut prefix,
                    &self.fallbacks,
                )
                .await;
                let fallback = select_vless_fallback(
                    &self.fallbacks,
                    server_name,
                    alpn,
                    &prefix,
                )
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no VLESS fallback matched the unauthenticated request",
                    )
                })?;
                return Ok(vless_fallback_result(fallback, prefix, server_stream));
            }

            // Authentication is now established. Replay the prefix into the
            // regular parser; all later malformed fields must fail rather than
            // being disguised as unauthenticated fallback traffic.
            server_stream = Box::new(PrefixedStream::new(prefix, server_stream));
        }

        let ParsedVlessHeader {
            user_id,
            flow: request_flow,
            command,
            remote_location,
        } = read_request_header(&mut server_stream).await?;
        let matched_user = self.users.iter().find(|(stored_user_id, _, _, _)| {
            stored_user_id.len() == 16
                && stored_user_id.as_ref() == user_id.as_slice()
        });

        let Some((_, user_label, configured_flow, user_uuid)) = matched_user else {
            let expected = self
                .users
                .iter()
                .map(|(user_id, _, _, _)| encode_hex(user_id.as_ref()))
                .collect::<Vec<_>>()
                .join(",");
            let got = encode_hex(&user_id);
            warn!(
                inbound_tag = %self.inbound_tag,
                expected = %expected,
                got = %got,
                "VLESS inbound rejected request with mismatched user id"
            );

            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("invalid VLESS user id: {got}"),
            ));
        };

        validate_request_flow(configured_flow, &request_flow, command)?;

        let access_transport = if command == COMMAND_TCP {
            AccessTransport::Tcp
        } else {
            AccessTransport::Udp
        };
        let traffic_context = Some(
            TrafficContext::new("vless")
                .with_identity(user_label.clone())
                .with_protocol_identity(user_uuid.clone())
                .with_access_target(
                    remote_location.address().to_string(),
                    remote_location.port(),
                    access_transport,
                )
                .with_inbound_tag(self.inbound_tag.clone()),
        );

        match command {
            COMMAND_TCP => Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: server_stream,
                need_initial_flush: true,
                connection_success_response: Some(
                    SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice(),
                ),
                traffic_context,
            }),
            protocol::COMMAND_UDP => Ok(TcpServerSetupResult::BidirectionalUdp {
                remote_location,
                stream: Box::new(VlessUdpStream::new(server_stream)),
                traffic_context,
            }),
            COMMAND_MUX => Ok(TcpServerSetupResult::SessionBasedUdp {
                stream: Box::new(XudpMessageStream::with_write_prefix(
                    server_stream,
                    resolver,
                    SERVER_RESPONSE_HEADER.to_vec(),
                )),
                traffic_context,
            }),
            unknown_protocol_type => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown requested protocol: {unknown_protocol_type}"),
            )),
        }
    }
}

#[async_trait]
impl TcpServerHandler for VlessTcpHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_metadata(
            server_stream,
            "",
            "",
            Arc::new(NativeResolver::new()),
        )
        .await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        let resolver = context
            .resolver
            .clone()
            .unwrap_or_else(|| Arc::new(NativeResolver::new()));
        self.setup_server_stream_with_metadata(
            server_stream,
            context.server_name.as_deref().unwrap_or(""),
            context.alpn_protocol.as_deref().unwrap_or(""),
            resolver,
        )
        .await
    }
}

fn validate_request_flow(
    configured_flow: &str,
    request_flow: &str,
    command: u8,
) -> std::io::Result<()> {
    match request_flow {
        "" => {
            if configured_flow == XTLS_VISION_FLOW {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "client flow is empty but account requires xtls-rprx-vision",
                ));
            }
        }
        XTLS_VISION_FLOW => {
            if configured_flow != XTLS_VISION_FLOW {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("account is not allowed to use flow {XTLS_VISION_FLOW}"),
                ));
            }
            if command != 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xtls-rprx-vision currently supports only TCP requests",
                ));
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "xtls-rprx-vision requires a dedicated Vision handler",
            ));
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown request flow {other}"),
            ));
        }
    }

    Ok(())
}

fn parse_hex(hex_asm: &str) -> Box<[u8]> {
    let mut hex_bytes = hex_asm
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();

    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h << 4 | l)
    }
    bytes.into_boxed_slice()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub(crate) fn looks_like_tls_record(data: &[u8]) -> bool {
    data.len() >= 5
        && matches!(data[0], 0x14..=0x17)
        && data[1] == 0x03
        && matches!(data[2], 0x01..=0x03)
}

pub(crate) fn drain_pending_read(
    pending_read: &mut BytesMut,
    buf: &mut ReadBuf<'_>,
) -> bool {
    if pending_read.is_empty() {
        return false;
    }

    let len = buf.remaining().min(pending_read.len());
    buf.put_slice(&pending_read[..len]);
    pending_read.advance(len);
    true
}

pub(crate) fn append_plaintext_to_read_buf(
    pending_read: &mut BytesMut,
    buf: &mut ReadBuf<'_>,
    plaintext: &[u8],
) {
    let len = buf.remaining().min(plaintext.len());
    buf.put_slice(&plaintext[..len]);
    if len < plaintext.len() {
        pending_read.extend_from_slice(&plaintext[len..]);
    }
}

pub(crate) fn take_vless_response_header(
    vless_response_to_send: &mut bool,
) -> Option<&'static [u8]> {
    if *vless_response_to_send {
        *vless_response_to_send = false;
        Some(SERVER_RESPONSE_HEADER)
    } else {
        None
    }
}

pub(crate) fn bounded_write_chunk(buf: &[u8], max_content_len: usize) -> &[u8] {
    &buf[..buf.len().min(max_content_len)]
}

pub(crate) fn queue_padded_packet(
    pending_write: &mut BytesMut,
    first_write: &mut bool,
    user_uuid: &[u8; 16],
    content: &[u8],
    command: u8,
) -> std::io::Result<()> {
    let is_tls = looks_like_tls_record(content);
    if *first_write {
        append_with_uuid_and_command(
            pending_write,
            content,
            user_uuid,
            command,
            is_tls,
        )?;
        *first_write = false;
    } else {
        append_with_command(pending_write, content, command, is_tls)?;
    }
    Ok(())
}

pub(crate) fn unpad_into_pending_read(
    unpadder: &mut VisionUnpadder,
    pending_read: &mut BytesMut,
    padded: &[u8],
) -> std::io::Result<Option<UnpadCommand>> {
    let result = unpadder.unpad(padded)?;
    if !result.content.is_empty() {
        pending_read.extend_from_slice(&result.content);
    }
    Ok(result.command)
}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        net::{Ipv4Addr, SocketAddr},
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };

    use bytes::{Buf, BufMut, BytesMut};
    use tokio::{
        io::{
            AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream,
            ReadBuf, duplex,
        },
        net::UdpSocket,
        time::timeout,
    };

    use crate::{
        address::{Address, NetLocation},
        async_stream::{AsyncPing, AsyncStream},
        beginning::udp::{run_bidirectional_udp, run_session_based_udp},
        config::server_config::{VlessFallback, VlessUser},
        handler::{
            tcp::tcp_handler::TcpServerSetupResult,
            vless_handler::vision_unpad::{UnpadCommand, VisionUnpadder},
            xudp::frame::{
                FrameMetadata, FrameOption, SessionStatus, TargetNetwork,
            },
        },
        resolver::NativeResolver,
        runtime::RuntimeState,
    };

    use super::*;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
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

    impl AsyncStream for TestStream {}

    fn plain_vless_handler(user_id: &str, user_label: &str) -> VlessTcpHandler {
        VlessTcpHandler::new(
            &[VlessUser {
                user_id: user_id.into(),
                user_label: user_label.into(),
                flow: String::new(),
            }],
            "vless-test",
        )
    }

    fn fallback_vless_handler(user_id: &str, fallback_port: u16) -> VlessTcpHandler {
        VlessTcpHandler::new_with_fallbacks(
            &[VlessUser {
                user_id: user_id.into(),
                user_label: "fallback-user".into(),
                flow: String::new(),
            }],
            &[VlessFallback {
                name: String::new(),
                alpn: String::new(),
                path: String::new(),
                dest: NetLocation::new(
                    Address::Ipv4(Ipv4Addr::LOCALHOST),
                    fallback_port,
                ),
                xver: 0,
            }],
            "vless-fallback-test",
        )
    }

    fn build_plain_vless_request(user_id: &str, command: u8) -> Vec<u8> {
        let mut request = vec![0];
        request.extend_from_slice(&parse_hex(user_id));
        request.push(0);
        request.push(command);
        if command != COMMAND_MUX {
            request.extend_from_slice(&443u16.to_be_bytes());
            request.push(1);
            request.extend_from_slice(&[127, 0, 0, 1]);
        }
        request
    }

    #[tokio::test]
    async fn tcp_request_returns_success_response_and_traffic_context() {
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let handler = plain_vless_handler(user_id, "vless-tcp-user");
        let request = build_plain_vless_request(user_id, COMMAND_TCP);
        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write VLESS TCP request");

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("VLESS TCP handshake must succeed");

        let TcpServerSetupResult::TcpForward {
            remote_location,
            need_initial_flush,
            connection_success_response,
            traffic_context,
            ..
        } = result
        else {
            panic!("VLESS TCP handshake returned a non-TCP result");
        };
        assert_eq!(
            remote_location,
            NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443)
        );
        assert!(need_initial_flush);
        assert_eq!(
            connection_success_response.as_deref(),
            Some(SERVER_RESPONSE_HEADER)
        );
        let context = traffic_context.expect("VLESS TCP context must exist");
        assert_eq!(context.identity.as_deref(), Some("vless-tcp-user"));
        assert_eq!(context.protocol_identity(), Some(user_id));
        assert!(context.user_uuid().is_none());
        let access = context.access_context().expect("access context must exist");
        assert_eq!(access.target_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(access.target_port, Some(443));
        assert_eq!(access.transport, AccessTransport::Tcp);
        assert_eq!(context.inbound_tag.as_deref(), Some("vless-test"));
    }

    #[tokio::test]
    async fn unknown_user_is_rejected_with_permission_denied() {
        let configured_user = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let request_user = "e041e73e-a0a0-49f5-9754-6401aa621fb7";
        let handler = plain_vless_handler(configured_user, "configured-user");
        let request = build_plain_vless_request(request_user, COMMAND_TCP);
        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write unknown-user VLESS request");

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("unknown VLESS user must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("invalid VLESS user id"));
    }

    #[tokio::test]
    async fn unknown_user_falls_back_and_replays_complete_prefix() {
        let configured_user = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let request_user = "e041e73e-a0a0-49f5-9754-6401aa621fb7";
        let handler = fallback_vless_handler(configured_user, 8080);
        let mut request = vec![0];
        request.extend_from_slice(&parse_hex(request_user));
        request.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        let (mut client, server) = duplex(1024);
        client.write_all(&request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("unknown user should select fallback");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            traffic_context,
            ..
        } = result
        else {
            panic!("fallback returned a non-TCP result");
        };
        assert_eq!(remote_location.port(), 8080);
        assert!(traffic_context.is_none());
        let mut replayed = Vec::new();
        stream.read_to_end(&mut replayed).await.unwrap();
        assert_eq!(replayed, request);
    }

    #[tokio::test]
    async fn truncated_unauthenticated_prefix_is_replayed_to_fallback() {
        let handler =
            fallback_vless_handler("3ac9b383-75a1-431c-8184-106c80eb2273", 8081);
        let request = b"GET /";
        let (mut client, server) = duplex(1024);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("truncated unauthenticated prefix should fallback");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("fallback returned a non-TCP result");
        };
        let mut replayed = Vec::new();
        stream.read_to_end(&mut replayed).await.unwrap();
        assert_eq!(replayed, request);
    }

    #[tokio::test]
    async fn authenticated_truncation_does_not_fallback() {
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let handler = fallback_vless_handler(user_id, 8082);
        let mut request = vec![0];
        request.extend_from_slice(&parse_hex(user_id));
        let (mut client, server) = duplex(1024);
        client.write_all(&request).await.unwrap();
        client.shutdown().await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("authenticated truncation must not fallback"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn authenticated_unknown_command_is_rejected() {
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let handler = plain_vless_handler(user_id, "unknown-command-user");
        let request = build_plain_vless_request(user_id, 0xff);
        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write unknown-command VLESS request");

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("unknown VLESS command must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("Unknown requested protocol"));
    }

    #[tokio::test]
    async fn udp_request_returns_framed_bidirectional_stream() {
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let handler = VlessTcpHandler::new(
            &[VlessUser {
                user_id: user_id.into(),
                user_label: "vless-udp-user".into(),
                flow: String::new(),
            }],
            "vless-udp",
        );
        let mut request = vec![0];
        request.extend_from_slice(&parse_hex(user_id));
        request.push(0);
        request.push(protocol::COMMAND_UDP);
        request.extend_from_slice(&53u16.to_be_bytes());
        request.push(1);
        request.extend_from_slice(&[127, 0, 0, 1]);
        request.extend_from_slice(&[0, 4]);
        request.extend_from_slice(b"ping");

        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write VLESS UDP request");
        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("VLESS UDP handshake should succeed");

        let TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            mut stream,
            traffic_context,
        } = result
        else {
            panic!("VLESS UDP handshake returned a non-UDP result");
        };
        assert_eq!(
            remote_location,
            NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 53)
        );
        let context = traffic_context.expect("VLESS traffic context should exist");
        assert_eq!(context.identity.as_deref(), Some("vless-udp-user"));
        assert_eq!(context.inbound_tag.as_deref(), Some("vless-udp"));

        let mut payload = [0u8; 16];
        let payload_length = poll_fn(|cx| {
            let mut read_buffer = ReadBuf::new(&mut payload);
            match Pin::new(&mut *stream).poll_read_message(cx, &mut read_buffer) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buffer.filled().len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
        .expect("read VLESS UDP payload");
        assert_eq!(&payload[..payload_length], b"ping");

        poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, b"pong"))
            .await
            .expect("write VLESS UDP response");
        let mut response = [0u8; 8];
        client
            .read_exact(&mut response)
            .await
            .expect("read VLESS UDP response");
        assert_eq!(&response, &[0, 0, 0, 4, b'p', b'o', b'n', b'g']);
    }

    #[tokio::test]
    async fn udp_request_roundtrips_through_runtime() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP echo socket");
        let echo_address = echo_socket.local_addr().expect("UDP echo address");
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 128];
            let (length, peer) = echo_socket
                .recv_from(&mut buffer)
                .await
                .expect("receive UDP echo request");
            echo_socket
                .send_to(&buffer[..length], peer)
                .await
                .expect("send UDP echo response");
        });

        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let handler = VlessTcpHandler::new(
            &[VlessUser {
                user_id: user_id.into(),
                user_label: "vless-runtime-user".into(),
                flow: String::new(),
            }],
            "vless-runtime-udp",
        );
        let mut request = vec![0];
        request.extend_from_slice(&parse_hex(user_id));
        request.push(0);
        request.push(protocol::COMMAND_UDP);
        request.extend_from_slice(&echo_address.port().to_be_bytes());
        request.push(1);
        request.extend_from_slice(&[127, 0, 0, 1]);
        request.extend_from_slice(&[0, 4]);
        request.extend_from_slice(b"ping");

        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write VLESS UDP request");
        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("VLESS UDP handshake should succeed");
        let TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream,
            traffic_context,
        } = result
        else {
            panic!("VLESS UDP handshake returned a non-UDP result");
        };

        let relay_task = tokio::spawn(run_bidirectional_udp(
            stream,
            remote_location,
            Arc::new(NativeResolver::new()),
            RuntimeState::new(Vec::new(), Vec::new()),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 43123)),
            traffic_context,
        ));

        let mut response = [0u8; 8];
        timeout(Duration::from_secs(5), client.read_exact(&mut response))
            .await
            .expect("VLESS UDP runtime response timeout")
            .expect("read VLESS UDP runtime response");
        assert_eq!(&response, &[0, 0, 0, 4, b'p', b'i', b'n', b'g']);

        echo_task.await.expect("UDP echo task should finish");
        relay_task.abort();
    }

    #[tokio::test]
    async fn fragmented_mux_header_preserves_first_xudp_frame() {
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let handler = VlessTcpHandler::new(
            &[VlessUser {
                user_id: user_id.into(),
                user_label: "fragmented-xudp-user".into(),
                flow: String::new(),
            }],
            "vless-fragmented-xudp",
        );
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 5353));
        let mut request = vec![0];
        request.extend_from_slice(&parse_hex(user_id));
        request.push(0);
        request.push(COMMAND_MUX);
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id: 42,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(NetLocation::from_ip_addr(target.ip(), target.port())),
            network: Some(TargetNetwork::Udp),
            global_id: None,
        }
        .encode(&mut frame)
        .expect("encode fragmented VLESS XUDP frame");
        frame.put_u16(4);
        frame.extend_from_slice(b"ping");
        request.extend_from_slice(&frame);

        let (mut client, server) = duplex(1);
        let writer = tokio::spawn(async move {
            for byte in request {
                client
                    .write_all(&[byte])
                    .await
                    .expect("write fragmented VLESS MUX byte");
                tokio::task::yield_now().await;
            }
        });
        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("fragmented VLESS MUX handshake must succeed");
        let TcpServerSetupResult::SessionBasedUdp {
            mut stream,
            traffic_context,
        } = result
        else {
            panic!("fragmented VLESS MUX returned a non-session result");
        };
        let mut payload = [0u8; 16];
        let (message, length) = poll_fn(|cx| {
            let mut read_buffer = ReadBuf::new(&mut payload);
            match Pin::new(&mut *stream)
                .poll_read_session_message(cx, &mut read_buffer)
            {
                Poll::Ready(Ok(message)) => {
                    Poll::Ready(Ok((message, read_buffer.filled().len())))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
        .expect("read first fragmented VLESS XUDP message");

        let crate::async_stream::SessionMessage::Data {
            session_id,
            target: actual_target,
            global_id,
            is_new,
        } = message
        else {
            panic!("fragmented VLESS XUDP first frame decoded as End");
        };
        assert_eq!(session_id, 42);
        assert_eq!(
            actual_target,
            NetLocation::from_ip_addr(target.ip(), target.port())
        );
        assert_eq!(global_id, None);
        assert!(is_new);
        assert_eq!(&payload[..length], b"ping");
        let context = traffic_context.expect("fragmented VLESS XUDP context");
        assert_eq!(context.identity.as_deref(), Some("fragmented-xudp-user"));
        writer.await.expect("fragmented VLESS MUX writer task");
    }

    #[tokio::test]
    async fn mux_request_roundtrips_xudp_through_runtime() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind VLESS XUDP echo socket");
        let echo_address =
            echo_socket.local_addr().expect("VLESS XUDP echo address");
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 128];
            let (length, peer) = echo_socket
                .recv_from(&mut buffer)
                .await
                .expect("receive VLESS XUDP echo request");
            echo_socket
                .send_to(&buffer[..length], peer)
                .await
                .expect("send VLESS XUDP echo response");
        });

        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let handler = VlessTcpHandler::new(
            &[VlessUser {
                user_id: user_id.into(),
                user_label: "vless-xudp-user".into(),
                flow: String::new(),
            }],
            "vless-xudp",
        );
        let mut request = vec![0];
        request.extend_from_slice(&parse_hex(user_id));
        request.push(0);
        request.push(COMMAND_MUX);
        let mut xudp_frame = BytesMut::new();
        FrameMetadata {
            session_id: 41,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(NetLocation::from_ip_addr(
                echo_address.ip(),
                echo_address.port(),
            )),
            network: Some(TargetNetwork::Udp),
            global_id: None,
        }
        .encode(&mut xudp_frame)
        .expect("encode VLESS XUDP request metadata");
        xudp_frame.put_u16(4);
        xudp_frame.extend_from_slice(b"ping");
        request.extend_from_slice(&xudp_frame);

        let (mut client, server) = duplex(4096);
        client
            .write_all(&request)
            .await
            .expect("write VLESS XUDP request");
        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("VLESS MUX handshake should succeed");
        let TcpServerSetupResult::SessionBasedUdp {
            stream,
            traffic_context,
        } = result
        else {
            panic!("VLESS MUX handshake returned a non-session result");
        };
        let context = traffic_context
            .as_ref()
            .expect("VLESS XUDP traffic context should exist");
        assert_eq!(context.identity.as_deref(), Some("vless-xudp-user"));
        assert_eq!(context.inbound_tag.as_deref(), Some("vless-xudp"));

        let relay_task = tokio::spawn(run_session_based_udp(
            stream,
            Arc::new(NativeResolver::new()),
            RuntimeState::new(Vec::new(), Vec::new()),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 43141)),
            traffic_context,
        ));

        let mut response_header = [0u8; 2];
        timeout(
            Duration::from_secs(5),
            client.read_exact(&mut response_header),
        )
        .await
        .expect("VLESS response header timeout")
        .expect("read VLESS response header");
        assert_eq!(response_header, [0, 0]);

        let mut metadata_length = [0u8; 2];
        client
            .read_exact(&mut metadata_length)
            .await
            .expect("read XUDP response metadata length");
        let metadata_size = u16::from_be_bytes(metadata_length) as usize;
        let mut response = BytesMut::from(&metadata_length[..]);
        response.resize(2 + metadata_size + 2 + 4, 0);
        client
            .read_exact(&mut response[2..])
            .await
            .expect("read XUDP response frame");
        let metadata = FrameMetadata::decode(&mut response)
            .expect("decode VLESS XUDP response")
            .expect("complete VLESS XUDP response");
        assert_eq!(metadata.session_id, 41);
        assert_eq!(metadata.status, SessionStatus::Keep);
        assert_eq!(metadata.network, Some(TargetNetwork::Udp));
        assert_eq!(response.get_u16(), 4);
        assert_eq!(&response[..], b"ping");

        echo_task.await.expect("VLESS XUDP echo task should finish");
        relay_task.abort();
    }

    #[test]
    fn validate_request_flow_allows_plain_vless() {
        validate_request_flow("", "", 1).expect("plain vless should be allowed");
    }

    #[test]
    fn validate_request_flow_rejects_vision_on_plain_account() {
        let err = validate_request_flow("", XTLS_VISION_FLOW, 1)
            .expect_err("plain account should reject vision");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn validate_request_flow_rejects_missing_vision_flow() {
        let err = validate_request_flow(XTLS_VISION_FLOW, "", 1)
            .expect_err("vision account should require client flow");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn validate_request_flow_rejects_unknown_flow() {
        let error = validate_request_flow("", "unknown-flow", COMMAND_TCP)
            .expect_err("unknown VLESS flow must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unknown request flow"));
    }

    #[test]
    fn validate_request_flow_rejects_vision_for_udp_before_handler_selection() {
        let error = validate_request_flow(
            XTLS_VISION_FLOW,
            XTLS_VISION_FLOW,
            protocol::COMMAND_UDP,
        )
        .expect_err("Vision VLESS UDP must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("only TCP"));
    }

    #[test]
    fn validate_request_flow_marks_vision_as_unimplemented() {
        let err = validate_request_flow(XTLS_VISION_FLOW, XTLS_VISION_FLOW, 1)
            .expect_err("vision should require dedicated handler");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn looks_like_tls_record_accepts_tls_header() {
        assert!(looks_like_tls_record(&[0x16, 0x03, 0x03, 0x00, 0x10]));
    }

    #[test]
    fn drain_pending_read_moves_data_into_readbuf() {
        let mut pending = BytesMut::from(&b"hello"[..]);
        let mut storage = [0u8; 3];
        let mut read_buf = ReadBuf::new(&mut storage);

        assert!(drain_pending_read(&mut pending, &mut read_buf));
        assert_eq!(read_buf.filled(), b"hel");
        assert_eq!(&pending[..], b"lo");
    }

    #[test]
    fn append_plaintext_to_read_buf_spills_remainder() {
        let mut pending = BytesMut::new();
        let mut storage = [0u8; 2];
        let mut read_buf = ReadBuf::new(&mut storage);

        append_plaintext_to_read_buf(&mut pending, &mut read_buf, b"abcd");

        assert_eq!(read_buf.filled(), b"ab");
        assert_eq!(&pending[..], b"cd");
    }

    #[test]
    fn unpad_into_pending_read_returns_command_and_content() {
        let uuid = [9u8; 16];
        let mut padded = BytesMut::new();
        let mut first_write = true;
        queue_padded_packet(&mut padded, &mut first_write, &uuid, b"ping", 0)
            .unwrap();

        let mut pending = BytesMut::new();
        let mut unpadder = VisionUnpadder::new(uuid);
        let command = unpad_into_pending_read(&mut unpadder, &mut pending, &padded)
            .expect("unpad should succeed");

        assert_eq!(command, Some(UnpadCommand::Continue));
        assert_eq!(&pending[..], b"ping");
    }

    #[test]
    fn take_vless_response_header_only_returns_once() {
        let mut should_send = true;
        assert_eq!(
            take_vless_response_header(&mut should_send),
            Some(&[0, 0][..])
        );
        assert_eq!(take_vless_response_header(&mut should_send), None);
    }

    #[test]
    fn bounded_write_chunk_limits_to_max_content_len() {
        assert_eq!(bounded_write_chunk(b"abcdef", 4), b"abcd");
        assert_eq!(bounded_write_chunk(b"ab", 4), b"ab");
    }
}
