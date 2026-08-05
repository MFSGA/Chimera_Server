use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "shadowsocks")]
use std::time::Duration;

#[cfg(any(feature = "trojan", feature = "vless"))]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "shadowsocks")]
use tokio::{net::UdpSocket, time::timeout};

#[cfg(feature = "shadowsocks")]
use crate::handler::shadowsocks::{ShadowsocksCipher, connect_legacy_aead_outbound};
#[cfg(feature = "vmess")]
use crate::handler::vmess::client::{VmessDataSecurity, connect_vmess_tcp};
use crate::http_outbound::{HttpProxyCredentials, connect_http_proxy};
use crate::socks_outbound::{Socks5Credentials, connect_socks5};
#[cfg(feature = "trojan")]
use crate::trojan_outbound::encode_trojan_tcp_request;
#[cfg(feature = "vless")]
use crate::vless_outbound::{VlessTcpOutboundStream, encode_vless_tcp_request};
use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    outbound_registry::OutboundConnectorKind,
    outbound_transport::OutboundTransportConfig,
    resolver::{Resolver, resolve_single_address},
    routing_process::enrich_routing_input,
    routing_state::{OutboundObservation, RoutingInput},
    runtime::RuntimeState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectOutboundAction {
    Freedom {
        tag: Option<String>,
    },
    Blackhole {
        tag: String,
    },
    #[cfg(feature = "shadowsocks")]
    Shadowsocks {
        tag: String,
    },
}

#[cfg(feature = "shadowsocks")]
pub(crate) struct UdpOutboundResponse {
    pub source: NetLocation,
    pub payload: Vec<u8>,
}

pub(crate) struct TcpOutboundConnection {
    pub stream: Box<dyn AsyncStream>,
    pub outbound_tag: Option<String>,
}

enum TcpOutboundHandshake {
    None,
    Http {
        credentials: Option<HttpProxyCredentials>,
        headers: std::collections::HashMap<String, String>,
        target: NetLocation,
    },
    #[cfg(feature = "shadowsocks")]
    Shadowsocks {
        cipher: ShadowsocksCipher,
        master_key: Arc<[u8]>,
        target: NetLocation,
    },
    Socks {
        credentials: Option<Socks5Credentials>,
        target: NetLocation,
    },
    #[cfg(feature = "trojan")]
    Trojan(Vec<u8>),
    #[cfg(feature = "vless")]
    Vless(Vec<u8>),
    #[cfg(feature = "vmess")]
    Vmess {
        user_uuid: [u8; 16],
        security: VmessDataSecurity,
        target: NetLocation,
    },
}

pub(crate) async fn connect_tcp_outbound(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &RuntimeState,
    inbound_tag: &str,
    user: &str,
    source_addr: SocketAddr,
) -> std::io::Result<Option<TcpOutboundConnection>> {
    let target_addr = resolve_single_address(resolver, remote_location).await?;
    let mut route_input = connection_routing_input(
        inbound_tag,
        user,
        2,
        source_addr,
        target_addr,
        remote_location,
    );
    if runtime.routing().requires_process_lookup() {
        enrich_routing_input(&mut route_input).await;
    }

    let selected = select_outbound_connector(runtime, &route_input)?;
    let (outbound_tag, connector) = match selected {
        Some((tag, connector)) => (Some(tag), Some(connector)),
        None => (None, None),
    };

    let (connect_location, transport, handshake) = match connector.as_deref() {
        None | Some(OutboundConnectorKind::Freedom) => (
            remote_location.clone(),
            OutboundTransportConfig::tcp(),
            TcpOutboundHandshake::None,
        ),
        Some(OutboundConnectorKind::Blackhole) => return Ok(None),
        Some(OutboundConnectorKind::HttpTcp(config)) => (
            config.server.clone(),
            config.transport.clone(),
            TcpOutboundHandshake::Http {
                credentials: config.credentials.clone(),
                headers: config.headers.clone(),
                target: remote_location.clone(),
            },
        ),
        #[cfg(feature = "shadowsocks")]
        Some(OutboundConnectorKind::ShadowsocksTcp(config)) => (
            config.server.clone(),
            config.transport.clone(),
            TcpOutboundHandshake::Shadowsocks {
                cipher: config.cipher,
                master_key: config.master_key.clone(),
                target: remote_location.clone(),
            },
        ),
        Some(OutboundConnectorKind::SocksTcp(config)) => (
            config.server.clone(),
            config.transport.clone(),
            TcpOutboundHandshake::Socks {
                credentials: config.credentials.clone(),
                target: remote_location.clone(),
            },
        ),
        #[cfg(feature = "trojan")]
        Some(OutboundConnectorKind::TrojanTcp(config)) => (
            config.server.clone(),
            config.transport.clone(),
            TcpOutboundHandshake::Trojan(encode_trojan_tcp_request(
                &config.password,
                remote_location,
            )?),
        ),
        #[cfg(feature = "vless")]
        Some(OutboundConnectorKind::VlessTcp(config)) => (
            config.server.clone(),
            config.transport.clone(),
            TcpOutboundHandshake::Vless(encode_vless_tcp_request(
                &config.user_uuid,
                remote_location,
            )?),
        ),
        #[cfg(feature = "vmess")]
        Some(OutboundConnectorKind::VmessTcp(config)) => (
            config.server.clone(),
            config.transport.clone(),
            TcpOutboundHandshake::Vmess {
                user_uuid: config.user_uuid,
                security: config.security,
                target: remote_location.clone(),
            },
        ),
        Some(OutboundConnectorKind::Unsupported { protocol }) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "tcp outbound {} uses unsupported protocol {}",
                    outbound_tag.as_deref().unwrap_or("<implicit>"),
                    protocol
                ),
            ));
        }
    };
    let started = Instant::now();
    let attempted_at = unix_time_secs();
    let stream = match transport.connect(resolver, &connect_location).await {
        Ok(stream) => stream,
        Err(error) => {
            record_tcp_outbound_failure(
                runtime,
                outbound_tag.as_deref(),
                started,
                attempted_at,
                &error,
            );
            return Err(error);
        }
    };
    let mut stream = stream;
    let stream: Box<dyn AsyncStream> = match handshake {
        TcpOutboundHandshake::None => stream,
        TcpOutboundHandshake::Http {
            credentials,
            headers,
            target,
        } => {
            if let Err(error) = connect_http_proxy(
                &mut *stream,
                credentials.as_ref(),
                &headers,
                &target,
            )
            .await
            {
                record_tcp_outbound_failure(
                    runtime,
                    outbound_tag.as_deref(),
                    started,
                    attempted_at,
                    &error,
                );
                return Err(error);
            }
            stream
        }
        #[cfg(feature = "shadowsocks")]
        TcpOutboundHandshake::Shadowsocks {
            cipher,
            master_key,
            target,
        } => match connect_legacy_aead_outbound(stream, cipher, master_key, &target)
            .await
        {
            Ok(stream) => stream,
            Err(error) => {
                record_tcp_outbound_failure(
                    runtime,
                    outbound_tag.as_deref(),
                    started,
                    attempted_at,
                    &error,
                );
                return Err(error);
            }
        },
        TcpOutboundHandshake::Socks {
            credentials,
            target,
        } => {
            if let Err(error) =
                connect_socks5(&mut *stream, credentials.as_ref(), &target).await
            {
                record_tcp_outbound_failure(
                    runtime,
                    outbound_tag.as_deref(),
                    started,
                    attempted_at,
                    &error,
                );
                return Err(error);
            }
            stream
        }
        #[cfg(feature = "trojan")]
        TcpOutboundHandshake::Trojan(request) => {
            if let Err(error) = stream.write_all(&request).await {
                record_tcp_outbound_failure(
                    runtime,
                    outbound_tag.as_deref(),
                    started,
                    attempted_at,
                    &error,
                );
                return Err(error);
            }
            stream
        }
        #[cfg(feature = "vless")]
        TcpOutboundHandshake::Vless(request) => {
            if let Err(error) = stream.write_all(&request).await {
                record_tcp_outbound_failure(
                    runtime,
                    outbound_tag.as_deref(),
                    started,
                    attempted_at,
                    &error,
                );
                return Err(error);
            }
            Box::new(VlessTcpOutboundStream::new(stream))
        }
        #[cfg(feature = "vmess")]
        TcpOutboundHandshake::Vmess {
            user_uuid,
            security,
            target,
        } => match connect_vmess_tcp(stream, user_uuid, security, &target) {
            Ok(stream) => stream,
            Err(error) => {
                record_tcp_outbound_failure(
                    runtime,
                    outbound_tag.as_deref(),
                    started,
                    attempted_at,
                    &error,
                );
                return Err(error);
            }
        },
    };

    record_tcp_outbound_success(
        runtime,
        outbound_tag.as_deref(),
        started,
        attempted_at,
    );
    Ok(Some(TcpOutboundConnection {
        stream,
        outbound_tag,
    }))
}

pub(crate) fn connection_routing_input(
    inbound_tag: &str,
    user: &str,
    network: i32,
    source_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: &NetLocation,
) -> RoutingInput {
    RoutingInput {
        inbound_tag: inbound_tag.to_string(),
        network,
        source_ips: vec![encode_ip(source_addr.ip())],
        target_ips: vec![encode_ip(target_addr.ip())],
        source_port: source_addr.port() as u32,
        target_port: target_addr.port() as u32,
        target_domain: match target_location.address() {
            Address::Hostname(hostname) => hostname.clone(),
            _ => String::new(),
        },
        user: user.to_string(),
        ..RoutingInput::default()
    }
}

fn select_outbound_connector(
    runtime: &RuntimeState,
    input: &RoutingInput,
) -> std::io::Result<Option<(String, Arc<OutboundConnectorKind>)>> {
    let Some(outbound) =
        runtime.select_outbound_checked(input).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
        })?
    else {
        return Ok(None);
    };
    let connector = runtime.outbound_connector(&outbound.tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "routed outbound {} is missing from the runtime registry",
                outbound.tag
            ),
        )
    })?;
    Ok(Some((outbound.tag, connector)))
}

#[cfg(feature = "shadowsocks")]
pub(crate) async fn exchange_shadowsocks_udp(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    tag: &str,
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<UdpOutboundResponse> {
    let connector = runtime.outbound_connector(tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Shadowsocks UDP outbound {tag} is missing from the registry"),
        )
    })?;
    let OutboundConnectorKind::ShadowsocksTcp(config) = connector.as_ref() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("outbound {tag} is not a Shadowsocks connector"),
        ));
    };
    if !config.transport.supports_direct_udp() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Shadowsocks UDP outbound {tag} requires network=tcp and security=none"
            ),
        ));
    }
    let server_addr = resolve_single_address(resolver, &config.server).await?;
    let bind_addr = if server_addr.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    let packet = config.udp_codec.encrypt_client_packet(target, payload)?;
    socket.send_to(&packet, server_addr).await?;
    let mut response = vec![0u8; 64 * 1024];
    let response_len = timeout(Duration::from_secs(60), async {
        loop {
            let (length, source) = socket.recv_from(&mut response).await?;
            if source.ip() == server_addr.ip() {
                return Ok::<usize, std::io::Error>(length);
            }
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Shadowsocks UDP response timed out",
        )
    })??;
    response.truncate(response_len);
    let (source, payload) = config.udp_codec.decrypt_client_packet(&response)?;
    Ok(UdpOutboundResponse { source, payload })
}

pub(crate) fn select_direct_outbound(
    runtime: &RuntimeState,
    input: &RoutingInput,
    network_name: &str,
) -> std::io::Result<DirectOutboundAction> {
    let Some((tag, connector)) = select_outbound_connector(runtime, input)? else {
        return Ok(DirectOutboundAction::Freedom { tag: None });
    };

    match connector.as_ref() {
        OutboundConnectorKind::Freedom => {
            Ok(DirectOutboundAction::Freedom { tag: Some(tag) })
        }
        OutboundConnectorKind::Blackhole => {
            Ok(DirectOutboundAction::Blackhole { tag })
        }
        OutboundConnectorKind::HttpTcp(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{network_name} outbound {tag} does not support UDP"),
        )),
        #[cfg(feature = "shadowsocks")]
        OutboundConnectorKind::ShadowsocksTcp(_) if network_name == "udp" => {
            Ok(DirectOutboundAction::Shadowsocks { tag })
        }
        #[cfg(feature = "shadowsocks")]
        OutboundConnectorKind::ShadowsocksTcp(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{network_name} outbound {tag} requires the TCP connector path"),
        )),
        OutboundConnectorKind::SocksTcp(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{network_name} outbound {tag} does not support UDP yet"),
        )),
        #[cfg(feature = "trojan")]
        OutboundConnectorKind::TrojanTcp(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{network_name} outbound {tag} does not support UDP yet"),
        )),
        #[cfg(feature = "vless")]
        OutboundConnectorKind::VlessTcp(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{network_name} outbound {tag} does not support UDP yet"),
        )),
        #[cfg(feature = "vmess")]
        OutboundConnectorKind::VmessTcp(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{network_name} outbound {tag} does not support UDP yet"),
        )),
        OutboundConnectorKind::Unsupported { protocol } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} outbound {} uses unsupported protocol {}",
                network_name, tag, protocol
            ),
        )),
    }
}

fn record_tcp_outbound_success(
    runtime: &RuntimeState,
    outbound_tag: Option<&str>,
    started: Instant,
    attempted_at: i64,
) {
    if let Some(tag) = outbound_tag {
        runtime.record_outbound_observation(
            tag,
            OutboundObservation {
                alive: true,
                delay_ms: started.elapsed().as_millis().min(i64::MAX as u128) as i64,
                last_seen_time: attempted_at,
                last_try_time: attempted_at,
                ..OutboundObservation::default()
            },
        );
    }
}

fn record_tcp_outbound_failure(
    runtime: &RuntimeState,
    outbound_tag: Option<&str>,
    started: Instant,
    attempted_at: i64,
    error: &std::io::Error,
) {
    if let Some(tag) = outbound_tag {
        runtime.record_outbound_observation(
            tag,
            OutboundObservation {
                alive: false,
                delay_ms: started.elapsed().as_millis().min(i64::MAX as u128) as i64,
                last_error_reason: error.to_string(),
                last_try_time: attempted_at,
                ..OutboundObservation::default()
            },
        );
    }
}

fn unix_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn encode_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, io, pin::Pin};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{
        config::{
            def::OutboundStreamSettings,
            rule::{BalancerConfig, RoutingConfig, RuleConfig},
        },
        resolver::NativeResolver,
        routing_state::RoutingState,
        runtime::OutboundSummary,
    };

    struct FixedResolver;

    impl Resolver for FixedResolver {
        fn resolve_location(
            &self,
            location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>
        {
            let result = match location.address() {
                Address::Ipv4(address) => {
                    SocketAddr::new(IpAddr::V4(*address), location.port())
                }
                Address::Ipv6(address) => {
                    SocketAddr::new(IpAddr::V6(*address), location.port())
                }
                Address::Hostname(_) => SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)),
                    location.port(),
                ),
            };
            Box::pin(async move { Ok(vec![result]) })
        }
    }

    fn outbound(tag: &str, protocol: &str) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: protocol.into(),
            settings: None,
            stream_settings: None,
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    #[cfg(feature = "vless")]
    fn vless_outbound(
        tag: &str,
        server: SocketAddr,
        user_id: &str,
    ) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: "vless".into(),
            settings: Some(serde_json::json!({
                "vnext": [{
                    "address": server.ip().to_string(),
                    "port": server.port(),
                    "users": [{
                        "id": user_id,
                        "flow": "",
                        "encryption": "none"
                    }]
                }]
            })),
            stream_settings: Some(OutboundStreamSettings {
                network: "tcp".into(),
                security: Some("none".into()),
                tls_settings: None,
                #[cfg(feature = "reality")]
                reality_settings: None,
                #[cfg(feature = "ws")]
                ws_settings: None,
                #[cfg(feature = "httpupgrade")]
                httpupgrade_settings: None,
                #[cfg(feature = "grpc_transport")]
                grpc_settings: None,
            }),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn vless_plain_tcp_outbound_preserves_target_and_relays_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let expected_uuid = uuid::Uuid::parse_str(user_id).unwrap().into_bytes();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut prefix = [0u8; 19];
            stream.read_exact(&mut prefix).await.unwrap();
            assert_eq!(prefix[0], 0);
            assert_eq!(&prefix[1..17], &expected_uuid);
            assert_eq!(prefix[17], 0);
            assert_eq!(prefix[18], 1);

            let port = stream.read_u16().await.unwrap();
            assert_eq!(port, 443);
            assert_eq!(stream.read_u8().await.unwrap(), 2);
            let domain_length = stream.read_u8().await.unwrap();
            let mut domain = vec![0u8; usize::from(domain_length)];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(&domain, b"target.example");

            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0, 0]).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
        });

        let runtime = RuntimeState::try_new(
            Vec::new(),
            vec![vless_outbound("proxy", server_addr, user_id)],
        )
        .expect("VLESS outbound should compile");
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["test".into()],
                    outbound_tag: Some("proxy".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .unwrap(),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(FixedResolver);
        let target =
            NetLocation::new(Address::Hostname("target.example".into()), 443);
        let mut connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "test",
            "user",
            "198.51.100.7:12345".parse().unwrap(),
        )
        .await
        .expect("VLESS connection should succeed")
        .expect("VLESS outbound must not be blackholed");
        assert_eq!(connection.outbound_tag.as_deref(), Some("proxy"));
        connection.stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        connection.stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[test]
    fn direct_outbound_defaults_to_implicit_freedom() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());

        assert_eq!(
            select_direct_outbound(&runtime, &RoutingInput::default(), "tcp")
                .unwrap(),
            DirectOutboundAction::Freedom { tag: None }
        );
    }

    #[test]
    fn direct_outbound_rejects_unsupported_protocol() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("proxy", "vmess")]);

        let err = select_direct_outbound(&runtime, &RoutingInput::default(), "tcp")
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "tcp outbound proxy uses unsupported protocol vmess"
        );
    }

    #[test]
    fn direct_outbound_rejects_missing_routed_outbound() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["test".into()],
                    outbound_tag: Some("missing".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("missing outbound routing rule should compile"),
        );

        let error = select_direct_outbound(
            &runtime,
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            "tcp",
        )
        .expect_err("missing routed outbound must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("missing outbound missing"));
    }

    #[test]
    fn direct_outbound_rejects_empty_balancer_without_falling_back() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["test".into()],
                    balancer_tag: Some("empty".into()),
                    ..RuleConfig::default()
                }],
                balancers: vec![BalancerConfig {
                    tag: "empty".into(),
                    outbound_selector: vec!["missing-prefix".into()],
                    strategy: Default::default(),
                    fallback_tag: None,
                }],
                ..RoutingConfig::default()
            }))
            .expect("empty balancer routing rule should compile"),
        );

        let error = select_direct_outbound(
            &runtime,
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            "tcp",
        )
        .expect_err("empty routed balancer must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("balancer empty has no available outbound")
        );
    }

    #[test]
    fn direct_outbound_routes_by_authenticated_user() {
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("blocked", "blackhole"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    user: vec!["alice".into()],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .unwrap(),
        );
        let input = connection_routing_input(
            "quic-in",
            "alice",
            2,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            &NetLocation::from_str("example.com:443", None).unwrap(),
        );

        assert_eq!(
            select_direct_outbound(&runtime, &input, "tcp").unwrap(),
            DirectOutboundAction::Blackhole {
                tag: "blocked".into()
            }
        );
        assert_eq!(input.source_port, 12345);
        assert_eq!(input.target_domain, "example.com");
    }

    #[tokio::test]
    async fn tcp_outbound_records_successful_observation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind observed target");
        let target_addr = listener.local_addr().expect("observed target address");
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "observed-in",
            "",
            "127.0.0.1:12345".parse().unwrap(),
        )
        .await
        .expect("observed connection should succeed");
        assert!(connection.is_some());

        let observations = runtime.outbound_observations();
        let status = observations.get("direct").expect("observation missing");
        assert!(status.alive);
        assert!(status.last_seen_time > 0);
        assert_eq!(status.last_error_reason, "");
    }

    #[tokio::test]
    async fn tcp_outbound_records_failed_observation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("reserve failed target port");
        let target_addr = listener.local_addr().expect("failed target address");
        drop(listener);
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

        if connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "observed-in",
            "",
            "127.0.0.1:12345".parse().unwrap(),
        )
        .await
        .is_ok()
        {
            panic!("connection to released port should fail");
        }

        let observations = runtime.outbound_observations();
        let status = observations
            .get("direct")
            .expect("failure observation missing");
        assert!(!status.alive);
        assert!(status.last_try_time > 0);
        assert!(!status.last_error_reason.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tcp_outbound_routes_by_local_process() {
        let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind process routing inbound listener");
        let client = tokio::net::TcpStream::connect(
            inbound_listener.local_addr().expect("inbound address"),
        );
        let (client, accepted) = tokio::join!(client, inbound_listener.accept());
        let _client = client.expect("connect local process client");
        let (_accepted, source_addr) =
            accepted.expect("accept local process client");
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind process routing target");
        let target_addr = target_listener.local_addr().expect("target address");
        let process_name = std::env::current_exe()
            .expect("current executable")
            .file_name()
            .expect("current executable name")
            .to_string_lossy()
            .into_owned();

        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("blocked", "blackhole"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    process: vec![process_name],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("process routing should build"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "process-in",
            "",
            source_addr,
        )
        .await
        .expect("process-routed outbound selection should succeed");

        assert!(
            connection.is_none(),
            "process route should select blackhole"
        );
    }
}
