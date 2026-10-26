use std::sync::Arc;

use async_trait::async_trait;

#[cfg(any(feature = "tls", feature = "reality"))]
use crate::config::server_config::VlessFallback;
#[cfg(any(feature = "tls", feature = "reality"))]
use crate::handler::xudp::message_stream::XudpMessageStream;
#[cfg(feature = "reality")]
use crate::reality::{RealityServerConnection, RealityTlsStream};
use crate::{
    async_stream::AsyncStream,
    config::server_config::VlessUser,
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    traffic::TrafficContext,
};

#[cfg(any(feature = "tls", feature = "reality"))]
use super::SERVER_RESPONSE_HEADER;
#[cfg(any(feature = "tls", feature = "reality"))]
use super::fallback::{
    extend_prefix_for_path, read_vless_auth_prefix, select_vless_fallback,
    vless_fallback_result,
};
#[cfg(any(feature = "tls", feature = "reality"))]
use super::protocol::{COMMAND_MUX, COMMAND_UDP, read_request_header_after_auth};
use super::protocol::{
    COMMAND_RVS, COMMAND_TCP, ParsedVlessHeader, XTLS_VISION_FLOW,
    read_request_header,
};
#[cfg(any(feature = "tls", feature = "reality"))]
use super::reality_vision_stream::RealityVisionServerStream;
#[cfg(feature = "tls")]
use super::tls_vision::{RustlsVisionSession, VisionRecordIo};
#[cfg(any(feature = "tls", feature = "reality"))]
use super::udp_stream::VlessUdpStream;
use super::vision_stream::VisionServerStream;
use super::{
    CompiledVlessUsers, ParsedVlessUser, authorize_reverse_command,
    parse_vless_users, reverse_portal_runtime_unavailable,
};

#[derive(Debug)]
pub struct VisionVlessTcpHandler {
    users: Arc<CompiledVlessUsers>,
    inbound_tag: String,
}

impl VisionVlessTcpHandler {
    pub fn new(users: &[VlessUser], inbound_tag: &str) -> Self {
        Self {
            users: Arc::new(parse_vless_users(users)),
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

#[cfg(feature = "reality")]
pub async fn setup_reality_mixed_vless_server_stream(
    mut tls_stream: RealityTlsStream<Box<dyn AsyncStream>, RealityServerConnection>,
    users: &CompiledVlessUsers,
    fallbacks: &[VlessFallback],
    inbound_tag: &str,
) -> std::io::Result<TcpServerSetupResult> {
    let header = if !fallbacks.is_empty() {
        let (mut prefix, candidate) = read_vless_auth_prefix(&mut tls_stream).await;
        let authenticated = candidate
            .is_some_and(|candidate| users.find(candidate.as_slice()).is_some());
        if !authenticated {
            extend_prefix_for_path(&mut tls_stream, &mut prefix, fallbacks).await;
            let fallback = select_vless_fallback(fallbacks, "", "", &prefix)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no VLESS fallback matched the unauthenticated REALITY request",
                    )
                })?;
            return Ok(vless_fallback_result(
                fallback,
                prefix,
                Box::new(tls_stream),
            ));
        }
        read_request_header_after_auth(
            &mut tls_stream,
            candidate.expect("authenticated candidate must exist"),
        )
        .await?
    } else {
        read_request_header(&mut tls_stream).await?
    };
    let ParsedVlessHeader {
        user_id,
        flow: request_flow,
        command,
        remote_location,
    } = header;

    let user = find_matching_vless_user(users, &user_id, inbound_tag)?;
    authorize_reverse_command(user.reverse_tag.is_some(), command)?;
    let traffic_context = Some(
        TrafficContext::new("vless")
            .with_identity(user.user_label.clone())
            .with_policy_identity(user.user_id.clone())
            .with_inbound_tag(inbound_tag.to_string())
            .with_user_level(user.user_level),
    );
    #[cfg(feature = "vless-reverse")]
    if command == COMMAND_RVS {
        return Ok(TcpServerSetupResult::ReversePortal {
            reverse_tag: user
                .reverse_tag
                .clone()
                .expect("authorized Reverse command requires a reverse tag"),
            stream: Box::new(tls_stream),
            connection_success_response: Some(
                SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice(),
            ),
            traffic_context,
        });
    }

    match request_flow.as_str() {
        "" => {
            if user.flow == XTLS_VISION_FLOW {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "client flow is empty but account requires xtls-rprx-vision",
                ));
            }
            match command {
                COMMAND_TCP => Ok(TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream: Box::new(tls_stream),
                    need_initial_flush: true,
                    connection_success_response: Some(
                        SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice(),
                    ),
                    traffic_context,
                }),
                COMMAND_UDP => Ok(TcpServerSetupResult::BidirectionalUdp {
                    remote_location,
                    stream: Box::new(VlessUdpStream::new(Box::new(tls_stream))),
                    traffic_context,
                }),
                COMMAND_MUX => Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(XudpMessageStream::with_write_prefix(
                        Box::new(tls_stream),
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
        XTLS_VISION_FLOW => {
            if user.flow != XTLS_VISION_FLOW {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("account is not allowed to use flow {XTLS_VISION_FLOW}"),
                ));
            }
            if command != COMMAND_TCP {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xtls-rprx-vision currently supports only TCP requests",
                ));
            }

            // xray's server parses the VLESS header through REALITY first, then
            // installs Vision at the body boundary. Keep already decrypted body
            // bytes so a coalesced request header + first Vision block is not lost.
            let (tcp, mut session) = tls_stream.into_inner();
            let initial_plaintext =
                RealityVisionServerStream::<
                    Box<dyn AsyncStream>,
                    RealityServerConnection,
                >::drain_plaintext_from_session(&mut session)?;

            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(RealityVisionServerStream::new(
                    tcp,
                    session,
                    user_id,
                    &initial_plaintext,
                )?),
                need_initial_flush: false,
                connection_success_response: None,
                traffic_context,
            })
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown request flow {other}"),
        )),
    }
}

#[cfg(feature = "tls")]
pub async fn setup_tls_mixed_vless_server_stream(
    mut tls_stream: tokio_rustls::server::TlsStream<
        VisionRecordIo<Box<dyn AsyncStream>>,
    >,
    users: &CompiledVlessUsers,
    fallbacks: &[VlessFallback],
    inbound_tag: &str,
) -> std::io::Result<TcpServerSetupResult> {
    let (server_name, alpn) = {
        let connection = tls_stream.get_ref().1;
        let server_name = connection.server_name().unwrap_or("").to_string();
        let alpn = connection
            .alpn_protocol()
            .and_then(|value| std::str::from_utf8(value).ok())
            .unwrap_or("")
            .to_string();
        (server_name, alpn)
    };
    let header = if !fallbacks.is_empty() {
        let (mut prefix, candidate) = read_vless_auth_prefix(&mut tls_stream).await;
        let authenticated = candidate
            .is_some_and(|candidate| users.find(candidate.as_slice()).is_some());
        if !authenticated {
            extend_prefix_for_path(&mut tls_stream, &mut prefix, fallbacks).await;
            let fallback = select_vless_fallback(
                fallbacks,
                &server_name,
                &alpn,
                &prefix,
            )
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no VLESS fallback matched the unauthenticated TLS request",
                )
            })?;
            return Ok(vless_fallback_result(
                fallback,
                prefix,
                Box::new(tls_stream),
            ));
        }
        read_request_header_after_auth(
            &mut tls_stream,
            candidate.expect("authenticated candidate must exist"),
        )
        .await?
    } else {
        read_request_header(&mut tls_stream).await?
    };
    let ParsedVlessHeader {
        user_id,
        flow: request_flow,
        command,
        remote_location,
    } = header;

    let user = find_matching_vless_user(users, &user_id, inbound_tag)?;
    authorize_reverse_command(user.reverse_tag.is_some(), command)?;
    let user_label = user.user_label.clone();
    let user_level = user.user_level;
    let traffic_context = Some(
        TrafficContext::new("vless")
            .with_identity(user_label)
            .with_policy_identity(user.user_id.clone())
            .with_inbound_tag(inbound_tag.to_string())
            .with_user_level(user_level),
    );
    #[cfg(feature = "vless-reverse")]
    if command == COMMAND_RVS {
        return Ok(TcpServerSetupResult::ReversePortal {
            reverse_tag: user
                .reverse_tag
                .clone()
                .expect("authorized Reverse command requires a reverse tag"),
            stream: Box::new(tls_stream),
            connection_success_response: Some(
                SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice(),
            ),
            traffic_context,
        });
    }

    match request_flow.as_str() {
        "" => {
            if user.flow == XTLS_VISION_FLOW {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "client flow is empty but account requires xtls-rprx-vision",
                ));
            }
            match command {
                COMMAND_TCP => Ok(TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream: Box::new(tls_stream),
                    need_initial_flush: true,
                    connection_success_response: Some(
                        SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice(),
                    ),
                    traffic_context,
                }),
                COMMAND_UDP => Ok(TcpServerSetupResult::BidirectionalUdp {
                    remote_location,
                    stream: Box::new(VlessUdpStream::new(Box::new(tls_stream))),
                    traffic_context,
                }),
                COMMAND_MUX => Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(XudpMessageStream::with_write_prefix(
                        Box::new(tls_stream),
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
        XTLS_VISION_FLOW => {
            if user.flow != XTLS_VISION_FLOW {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("account is not allowed to use flow {XTLS_VISION_FLOW}"),
                ));
            }
            if command != COMMAND_TCP {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xtls-rprx-vision currently supports only TCP requests",
                ));
            }

            let (io, connection) = tls_stream.into_inner();
            let mut session = io.session(connection);
            let initial_plaintext =
                RealityVisionServerStream::<
                    VisionRecordIo<Box<dyn AsyncStream>>,
                    RustlsVisionSession,
                >::drain_plaintext_from_session(&mut session)?;

            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(RealityVisionServerStream::new(
                    io,
                    session,
                    user_id,
                    &initial_plaintext,
                )?),
                need_initial_flush: false,
                connection_success_response: None,
                traffic_context,
            })
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown request flow {other}"),
        )),
    }
}

#[cfg(feature = "reality")]
#[allow(dead_code)] // Kept as the REALITY Vision entrypoint for the listener integration slice.
pub async fn setup_reality_vision_server_stream(
    mut tls_stream: RealityTlsStream<Box<dyn AsyncStream>, RealityServerConnection>,
    users: &CompiledVlessUsers,
    fallbacks: &[VlessFallback],
    inbound_tag: &str,
) -> std::io::Result<TcpServerSetupResult> {
    let header = if !fallbacks.is_empty() {
        let (mut prefix, candidate) = read_vless_auth_prefix(&mut tls_stream).await;
        let authenticated = candidate
            .is_some_and(|candidate| users.find(candidate.as_slice()).is_some());
        if !authenticated {
            extend_prefix_for_path(&mut tls_stream, &mut prefix, fallbacks).await;
            let fallback = select_vless_fallback(fallbacks, "", "", &prefix)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no VLESS fallback matched the unauthenticated REALITY Vision request",
                    )
                })?;
            return Ok(vless_fallback_result(
                fallback,
                prefix,
                Box::new(tls_stream),
            ));
        }
        read_request_header_after_auth(
            &mut tls_stream,
            candidate.expect("authenticated candidate must exist"),
        )
        .await?
    } else {
        read_request_header(&mut tls_stream).await?
    };
    let ParsedVlessHeader {
        user_id,
        flow: request_flow,
        command,
        remote_location,
    } = header;

    let user = find_matching_user_label(users, &user_id, inbound_tag)?;
    authorize_reverse_command(user.reverse_tag.is_some(), command)?;
    if command == COMMAND_RVS {
        return Err(reverse_portal_runtime_unavailable());
    }
    validate_vision_request_flow(&request_flow, command)?;

    let (tcp, mut session) = tls_stream.into_inner();
    let initial_plaintext = RealityVisionServerStream::<
        Box<dyn AsyncStream>,
        RealityServerConnection,
    >::drain_plaintext_from_session(&mut session)?;

    Ok(TcpServerSetupResult::TcpForward {
        remote_location,
        stream: Box::new(RealityVisionServerStream::new(
            tcp,
            session,
            user_id,
            &initial_plaintext,
        )?),
        need_initial_flush: false,
        connection_success_response: None,
        traffic_context: Some(
            TrafficContext::new("vless")
                .with_identity(user.user_label.clone())
                .with_policy_identity(user.user_id.clone())
                .with_inbound_tag(inbound_tag.to_string())
                .with_user_level(user.user_level),
        ),
    })
}

impl VisionVlessTcpHandler {
    async fn setup_server_stream_with_users(
        &self,
        users: &CompiledVlessUsers,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let ParsedVlessHeader {
            user_id,
            flow: request_flow,
            command,
            remote_location,
        } = read_request_header(&mut server_stream).await?;

        let user = find_matching_user_label(users, &user_id, &self.inbound_tag)?;

        authorize_reverse_command(user.reverse_tag.is_some(), command)?;
        if command == COMMAND_RVS {
            return Err(reverse_portal_runtime_unavailable());
        }
        validate_vision_request_flow(&request_flow, command)?;

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(VisionServerStream::new(server_stream, user_id)),
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context: Some(
                TrafficContext::new("vless")
                    .with_identity(user.user_label.clone())
                    .with_policy_identity(user.user_id.clone())
                    .with_inbound_tag(self.inbound_tag.clone())
                    .with_user_level(user.user_level),
            ),
        })
    }
}

#[async_trait]
impl TcpServerHandler for VisionVlessTcpHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_users(&self.users, server_stream)
            .await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: crate::handler::tcp::tcp_handler::TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        let dynamic_users = context
            .inbound_handshake_runtime()
            .as_ref()
            .and_then(|runtime| runtime.vless_users_snapshot(&self.inbound_tag));
        let users = dynamic_users.as_deref().unwrap_or(self.users.as_ref());
        self.setup_server_stream_with_users(users, server_stream)
            .await
    }
}

#[cfg(any(feature = "tls", feature = "reality"))]
fn find_matching_vless_user<'a>(
    users: &'a CompiledVlessUsers,
    user_id: &[u8; 16],
    inbound_tag: &str,
) -> std::io::Result<&'a ParsedVlessUser> {
    super::find_vless_user(users, user_id, inbound_tag, "vision")
}

fn find_matching_user_label<'a>(
    users: &'a CompiledVlessUsers,
    user_id: &[u8; 16],
    inbound_tag: &str,
) -> std::io::Result<&'a ParsedVlessUser> {
    super::find_vless_user(users, user_id, inbound_tag, "vision")
}

fn validate_vision_request_flow(
    request_flow: &str,
    command: u8,
) -> std::io::Result<()> {
    if request_flow != XTLS_VISION_FLOW {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("vision inbound requires flow {XTLS_VISION_FLOW}"),
        ));
    }

    if command != COMMAND_TCP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "xtls-rprx-vision currently supports only TCP requests",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "tls", feature = "reality"))]
    use super::find_matching_vless_user;
    use super::{find_matching_user_label, validate_vision_request_flow};
    use crate::handler::vless_handler::CompiledVlessUsers;
    use crate::handler::vless_handler::protocol::XTLS_VISION_FLOW;

    #[test]
    fn unmatched_vision_user_errors_do_not_echo_the_user_id() {
        let users = CompiledVlessUsers::default();
        let user_id = [0x42; 16];
        let user_id_hex: String =
            user_id.iter().map(|byte| format!("{byte:02x}")).collect();

        let error = find_matching_user_label(&users, &user_id, "vision-test")
            .expect_err("unknown user must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "invalid VLESS user id");
        assert!(!error.to_string().contains(&user_id_hex));

        #[cfg(any(feature = "tls", feature = "reality"))]
        {
            let error = find_matching_vless_user(&users, &user_id, "vision-test")
                .expect_err("unknown Vision user must be rejected");
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert_eq!(error.to_string(), "invalid VLESS user id");
            assert!(!error.to_string().contains(&user_id_hex));
        }
    }

    #[cfg(feature = "vless-reverse")]
    use tokio::io::{AsyncWriteExt, duplex};

    #[cfg(feature = "vless-reverse")]
    use super::VisionVlessTcpHandler;
    #[cfg(feature = "vless-reverse")]
    use crate::{
        config::server_config::{VlessReverseConfig, VlessUser},
        handler::{
            tcp::tcp_handler::TcpServerHandler,
            vless_handler::{parse_hex, protocol::COMMAND_RVS},
        },
    };

    #[test]
    fn validate_vision_request_flow_requires_vision_marker() {
        let err = validate_vision_request_flow("", 1)
            .expect_err("vision handler should require vision flow");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn validate_vision_request_flow_rejects_non_tcp() {
        let err = validate_vision_request_flow(XTLS_VISION_FLOW, 2)
            .expect_err("vision handler should reject udp");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn validate_vision_request_flow_accepts_tcp() {
        validate_vision_request_flow(XTLS_VISION_FLOW, 1)
            .expect("vision handler should accept tcp header shape");
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test]
    async fn vision_user_snapshot_preserves_reverse_command_boundary() {
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let handler = VisionVlessTcpHandler::new(
            &[VlessUser {
                user_id: user_id.into(),
                user_label: "reverse-user".into(),
                user_level: 0,
                flow: String::new(),
                reverse: Some(VlessReverseConfig {
                    tag: "reverse-out".into(),
                }),
            }],
            "vision-reverse-test",
        );
        let (mut client, server) = duplex(128);
        let mut request = vec![0];
        request.extend_from_slice(&parse_hex(user_id));
        request.push(0);
        request.push(COMMAND_RVS);
        client
            .write_all(&request)
            .await
            .expect("write reverse VLESS request");

        let error = match handler.setup_server_stream(Box::new(server)).await {
            Ok(_) => panic!("Portal runtime remains deferred after Vision auth"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(
            error
                .to_string()
                .contains("Portal runtime is not implemented yet")
        );
    }
}
