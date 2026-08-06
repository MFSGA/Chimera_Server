use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(feature = "vmess")]
use std::{future::poll_fn, pin::Pin};

#[cfg(feature = "vless")]
use bytes::BytesMut;
#[cfg(feature = "vless")]
use tokio::io::AsyncReadExt;
#[cfg(any(feature = "trojan", feature = "vless"))]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "vmess")]
use tokio::io::ReadBuf;
use tokio::{net::UdpSocket, time::timeout};

#[cfg(feature = "vmess")]
use crate::async_stream::AsyncMessageStream;
#[cfg(feature = "shadowsocks")]
use crate::handler::shadowsocks::{
    ShadowsocksCipher, ShadowsocksUdpCodec, connect_legacy_aead_outbound,
};
#[cfg(feature = "vmess")]
use crate::handler::vmess::client::{
    VmessDataSecurity, connect_vmess_tcp, connect_vmess_udp,
};
use crate::http_outbound::{HttpProxyCredentials, connect_http_proxy};
use crate::socks_outbound::{
    Socks5Credentials, associate_socks5_udp, connect_socks5,
    decode_socks5_udp_packet, encode_socks5_udp_packet,
};
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
#[cfg(feature = "trojan")]
use crate::{
    handler::trojan_udp::{encode_packet_location, read_packet},
    trojan_outbound::{encode_trojan_tcp_request, encode_trojan_udp_request},
};
#[cfg(feature = "vless")]
use crate::{
    handler::xudp::frame::FrameMetadata,
    outbound_registry::VlessUdpPacketEncoding,
    vless_outbound::{
        VlessTcpOutboundStream, encode_vless_tcp_request, encode_vless_udp_packet,
        encode_vless_udp_request, encode_vless_xudp_packet,
        encode_vless_xudp_request,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    Socks {
        tag: String,
    },
    #[cfg(feature = "trojan")]
    Trojan {
        tag: String,
    },
    #[cfg(feature = "vless")]
    Vless {
        tag: String,
    },
    #[cfg(feature = "vmess")]
    Vmess {
        tag: String,
    },
}

impl DirectOutboundAction {
    pub(crate) fn outbound_tag(&self) -> Option<&str> {
        match self {
            Self::Freedom { tag } => tag.as_deref(),
            Self::Blackhole { tag } | Self::Socks { tag } => Some(tag),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks { tag } => Some(tag),
            #[cfg(feature = "trojan")]
            Self::Trojan { tag } => Some(tag),
            #[cfg(feature = "vless")]
            Self::Vless { tag } => Some(tag),
            #[cfg(feature = "vmess")]
            Self::Vmess { tag } => Some(tag),
        }
    }

    pub(crate) fn required_outbound_tag(&self) -> std::io::Result<&str> {
        self.outbound_tag().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP proxy action is missing its outbound tag",
            )
        })
    }

    fn udp_association_target_key(
        &self,
        _target: &NetLocation,
    ) -> Option<NetLocation> {
        match self {
            #[cfg(feature = "vless")]
            Self::Vless { .. } => Some(_target.clone()),
            #[cfg(feature = "vmess")]
            Self::Vmess { .. } => Some(_target.clone()),
            Self::Freedom { .. } | Self::Blackhole { .. } | Self::Socks { .. } => {
                None
            }
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks { .. } => None,
            #[cfg(feature = "trojan")]
            Self::Trojan { .. } => None,
        }
    }
}

pub(crate) struct UdpOutboundResponse {
    pub source: NetLocation,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpProxyAssociationKey {
    action: DirectOutboundAction,
    target: Option<NetLocation>,
}

struct UdpProxyAssociationEntry {
    association: FixedTargetUdpProxyAssociation,
    last_used: Instant,
}

pub(crate) struct UdpProxyAssociationRegistry {
    associations: HashMap<UdpProxyAssociationKey, UdpProxyAssociationEntry>,
    idle_timeout: Duration,
}

pub(crate) enum FixedTargetUdpProxyAssociation {
    #[cfg(feature = "shadowsocks")]
    Shadowsocks {
        socket: UdpSocket,
        server_addr: SocketAddr,
        codec: Arc<ShadowsocksUdpCodec>,
    },
    Socks {
        _control: Box<dyn AsyncStream>,
        socket: UdpSocket,
        relay_addr: SocketAddr,
    },
    #[cfg(feature = "trojan")]
    Trojan { stream: Box<dyn AsyncStream> },
    #[cfg(feature = "vless")]
    Vless {
        stream: VlessTcpOutboundStream,
        target: NetLocation,
        packet_encoding: VlessUdpPacketEncoding,
        xudp_first: bool,
        xudp_request_prefix: Option<Vec<u8>>,
    },
    #[cfg(feature = "vmess")]
    Vmess {
        stream: Box<dyn AsyncMessageStream>,
        target: NetLocation,
    },
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

#[cfg(feature = "vmess")]
async fn write_vmess_message(
    stream: &mut dyn AsyncMessageStream,
    payload: &[u8],
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, payload)).await?;
    poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx)).await
}

#[cfg(feature = "vmess")]
async fn read_vmess_message(
    stream: &mut dyn AsyncMessageStream,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    let mut read_buffer = ReadBuf::new(buffer);
    poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut read_buffer))
        .await?;
    Ok(read_buffer.filled().len())
}

#[cfg(any(feature = "trojan", feature = "vless", feature = "vmess"))]
fn ensure_fixed_udp_target(
    protocol: &str,
    expected: &NetLocation,
    actual: &NetLocation,
) -> std::io::Result<()> {
    if expected == actual {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("{protocol} UDP association is bound to {expected}, not {actual}"),
    ))
}

#[cfg(feature = "vmess")]
async fn connect_vmess_udp_stream(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    tag: &str,
    target: &NetLocation,
) -> std::io::Result<Box<dyn AsyncMessageStream>> {
    let connector = runtime.outbound_connector(tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VMess UDP outbound {tag} is missing from the registry"),
        )
    })?;
    let OutboundConnectorKind::VmessTcp(config) = connector.as_ref() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("outbound {tag} is not a VMess connector"),
        ));
    };
    let transport = config.transport.connect(resolver, &config.server).await?;
    connect_vmess_udp(transport, config.user_uuid, config.security, target)
}

#[cfg(feature = "vmess")]
async fn exchange_vmess_udp_stream(
    stream: &mut dyn AsyncMessageStream,
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<UdpOutboundResponse> {
    let mut response = vec![0u8; u16::MAX as usize];
    let response_len = timeout(Duration::from_secs(60), async {
        write_vmess_message(stream, payload).await?;
        read_vmess_message(stream, &mut response).await
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "VMess UDP response timed out",
        )
    })??;
    if response_len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "VMess UDP response stream closed before a message arrived",
        ));
    }
    response.truncate(response_len);
    Ok(UdpOutboundResponse {
        source: target.clone(),
        payload: response,
    })
}

#[cfg(feature = "vless")]
async fn connect_vless_udp_stream(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    tag: &str,
    target: &NetLocation,
) -> std::io::Result<(
    VlessTcpOutboundStream,
    VlessUdpPacketEncoding,
    Option<Vec<u8>>,
)> {
    let connector = runtime.outbound_connector(tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS UDP outbound {tag} is missing from the registry"),
        )
    })?;
    let OutboundConnectorKind::VlessTcp(config) = connector.as_ref() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("outbound {tag} is not a VLESS connector"),
        ));
    };
    let mut stream = config.transport.connect(resolver, &config.server).await?;
    let xudp_request_prefix = match config.udp_packet_encoding {
        VlessUdpPacketEncoding::Native => {
            let request = encode_vless_udp_request(&config.user_uuid, target)?;
            stream.write_all(&request).await?;
            None
        }
        VlessUdpPacketEncoding::Xudp => {
            Some(encode_vless_xudp_request(&config.user_uuid)?)
        }
    };
    Ok((
        VlessTcpOutboundStream::new(stream),
        config.udp_packet_encoding,
        xudp_request_prefix,
    ))
}

#[cfg(feature = "shadowsocks")]
async fn connect_shadowsocks_udp_relay(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    tag: &str,
) -> std::io::Result<(UdpSocket, SocketAddr, Arc<ShadowsocksUdpCodec>)> {
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
    Ok((socket, server_addr, config.udp_codec.clone()))
}

#[cfg(feature = "shadowsocks")]
async fn exchange_shadowsocks_udp_relay(
    socket: &UdpSocket,
    server_addr: SocketAddr,
    codec: &ShadowsocksUdpCodec,
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<UdpOutboundResponse> {
    let packet = codec.encrypt_client_packet(target, payload)?;
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
    let (source, payload) = codec.decrypt_client_packet(&response)?;
    Ok(UdpOutboundResponse { source, payload })
}

async fn connect_socks_udp_relay(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    tag: &str,
) -> std::io::Result<(Box<dyn AsyncStream>, UdpSocket, SocketAddr)> {
    let connector = runtime.outbound_connector(tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SOCKS UDP outbound {tag} is missing from the registry"),
        )
    })?;
    let OutboundConnectorKind::SocksTcp(config) = connector.as_ref() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("outbound {tag} is not a SOCKS connector"),
        ));
    };

    let server_addr = resolve_single_address(resolver, &config.server).await?;
    let mut control = config.transport.connect(resolver, &config.server).await?;
    let relay_location =
        associate_socks5_udp(&mut *control, config.credentials.as_ref()).await?;
    if relay_location.port() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS UDP ASSOCIATE returned relay port zero",
        ));
    }
    let mut relay_addr = resolve_single_address(resolver, &relay_location).await?;
    if relay_addr.ip().is_unspecified() {
        relay_addr.set_ip(server_addr.ip());
    }
    let bind_addr = if relay_addr.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    Ok((control, socket, relay_addr))
}

async fn exchange_socks_udp_relay(
    socket: &UdpSocket,
    relay_addr: SocketAddr,
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<UdpOutboundResponse> {
    let packet = encode_socks5_udp_packet(target, payload)?;
    socket.send_to(&packet, relay_addr).await?;

    let mut response = vec![0u8; 64 * 1024];
    let response_len = timeout(Duration::from_secs(60), async {
        loop {
            let (length, source) = socket.recv_from(&mut response).await?;
            if source == relay_addr {
                return Ok::<usize, std::io::Error>(length);
            }
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "SOCKS UDP response timed out",
        )
    })??;
    response.truncate(response_len);
    let decoded = decode_socks5_udp_packet(&response)?;
    Ok(UdpOutboundResponse {
        source: decoded.location,
        payload: decoded.payload,
    })
}

#[cfg(feature = "trojan")]
async fn connect_trojan_udp_stream(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    tag: &str,
    target: &NetLocation,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let connector = runtime.outbound_connector(tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Trojan UDP outbound {tag} is missing from the registry"),
        )
    })?;
    let OutboundConnectorKind::TrojanTcp(config) = connector.as_ref() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("outbound {tag} is not a Trojan connector"),
        ));
    };
    let mut stream = config.transport.connect(resolver, &config.server).await?;
    let request = encode_trojan_udp_request(&config.password, target)?;
    stream.write_all(&request).await?;
    Ok(stream)
}

#[cfg(feature = "trojan")]
async fn exchange_trojan_udp_stream(
    stream: &mut dyn AsyncStream,
    payload_target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<UdpOutboundResponse> {
    let packet = encode_packet_location(payload_target, payload)?;
    stream.write_all(&packet).await?;
    stream.flush().await?;
    let (source, response) = timeout(Duration::from_secs(60), read_packet(stream))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Trojan UDP response timed out",
            )
        })??;
    Ok(UdpOutboundResponse {
        source,
        payload: response,
    })
}

#[cfg(feature = "vless")]
async fn exchange_vless_udp_stream(
    stream: &mut VlessTcpOutboundStream,
    target: &NetLocation,
    payload: &[u8],
    packet_encoding: VlessUdpPacketEncoding,
    xudp_first: &mut bool,
    xudp_request_prefix: &mut Option<Vec<u8>>,
) -> std::io::Result<UdpOutboundResponse> {
    let packet = match packet_encoding {
        VlessUdpPacketEncoding::Native => encode_vless_udp_packet(payload)?,
        VlessUdpPacketEncoding::Xudp => {
            let frame = encode_vless_xudp_packet(target, payload, *xudp_first)?;
            *xudp_first = false;
            if let Some(mut prefix) = xudp_request_prefix.take() {
                prefix.extend_from_slice(&frame);
                prefix
            } else {
                frame
            }
        }
    };
    stream.write_all(&packet).await?;
    stream.flush().await?;

    match packet_encoding {
        VlessUdpPacketEncoding::Native => {
            let response_length = timeout(Duration::from_secs(60), stream.read_u16())
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "VLESS UDP response timed out",
                    )
                })?? as usize;
            if response_length == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "VLESS UDP response payload is empty",
                ));
            }
            let mut response = vec![0u8; response_length];
            timeout(Duration::from_secs(60), stream.read_exact(&mut response))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "VLESS UDP response body timed out",
                    )
                })??;
            Ok(UdpOutboundResponse {
                source: target.clone(),
                payload: response,
            })
        }
        VlessUdpPacketEncoding::Xudp => timeout(
            Duration::from_secs(60),
            read_vless_xudp_packet(stream, target),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "VLESS XUDP response timed out",
            )
        })?,
    }
}

#[cfg(feature = "vless")]
async fn read_vless_xudp_packet(
    stream: &mut VlessTcpOutboundStream,
    fallback_target: &NetLocation,
) -> std::io::Result<UdpOutboundResponse> {
    loop {
        let metadata_length = stream.read_u16().await? as usize;
        if metadata_length < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VLESS XUDP metadata is too short",
            ));
        }
        let mut encoded = BytesMut::with_capacity(metadata_length + 2);
        encoded.extend_from_slice(&(metadata_length as u16).to_be_bytes());
        encoded.resize(metadata_length + 2, 0);
        stream.read_exact(&mut encoded[2..]).await?;
        let metadata = FrameMetadata::decode(&mut encoded)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "VLESS XUDP metadata was incomplete",
            )
        })?;
        if !metadata.option.has_data() {
            continue;
        }
        let payload_length = stream.read_u16().await? as usize;
        if payload_length == 0 {
            continue;
        }
        let mut payload = vec![0u8; payload_length];
        stream.read_exact(&mut payload).await?;
        return Ok(UdpOutboundResponse {
            source: metadata.target.unwrap_or_else(|| fallback_target.clone()),
            payload,
        });
    }
}

impl FixedTargetUdpProxyAssociation {
    pub(crate) async fn exchange(
        &mut self,
        target: &NetLocation,
        payload: &[u8],
    ) -> std::io::Result<UdpOutboundResponse> {
        match self {
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks {
                socket,
                server_addr,
                codec,
            } => {
                exchange_shadowsocks_udp_relay(
                    socket,
                    *server_addr,
                    codec,
                    target,
                    payload,
                )
                .await
            }
            Self::Socks {
                socket, relay_addr, ..
            } => {
                exchange_socks_udp_relay(socket, *relay_addr, target, payload).await
            }
            #[cfg(feature = "trojan")]
            Self::Trojan { stream } => {
                exchange_trojan_udp_stream(&mut **stream, target, payload).await
            }
            #[cfg(feature = "vless")]
            Self::Vless {
                stream,
                target: expected,
                packet_encoding,
                xudp_first,
                xudp_request_prefix,
            } => {
                ensure_fixed_udp_target("VLESS", expected, target)?;
                exchange_vless_udp_stream(
                    stream,
                    target,
                    payload,
                    *packet_encoding,
                    xudp_first,
                    xudp_request_prefix,
                )
                .await
            }
            #[cfg(feature = "vmess")]
            Self::Vmess {
                stream,
                target: expected,
            } => {
                ensure_fixed_udp_target("VMess", expected, target)?;
                exchange_vmess_udp_stream(&mut **stream, target, payload).await
            }
        }
    }
}

impl UdpProxyAssociationRegistry {
    pub(crate) fn new(idle_timeout: Duration) -> Self {
        Self {
            associations: HashMap::new(),
            idle_timeout,
        }
    }

    fn evict_idle(&mut self) {
        let now = Instant::now();
        let idle_timeout = self.idle_timeout;
        self.associations
            .retain(|_, entry| now.duration_since(entry.last_used) < idle_timeout);
    }

    pub(crate) async fn exchange(
        &mut self,
        resolver: &Arc<dyn Resolver>,
        runtime: &RuntimeState,
        action: &DirectOutboundAction,
        target: &NetLocation,
        payload: &[u8],
    ) -> std::io::Result<UdpOutboundResponse> {
        self.evict_idle();
        let key = UdpProxyAssociationKey {
            action: action.clone(),
            target: action.udp_association_target_key(target),
        };
        if !self.associations.contains_key(&key) {
            let association = connect_fixed_target_udp_proxy_association(
                resolver, runtime, action, target,
            )
            .await?;
            self.associations.insert(
                key.clone(),
                UdpProxyAssociationEntry {
                    association,
                    last_used: Instant::now(),
                },
            );
        }

        let result = {
            let entry = self.associations.get_mut(&key).ok_or_else(|| {
                std::io::Error::other(
                    "UDP proxy association disappeared after insertion",
                )
            })?;
            let result = entry.association.exchange(target, payload).await;
            if result.is_ok() {
                entry.last_used = Instant::now();
            }
            result
        };
        if result.is_err() {
            self.associations.remove(&key);
        }
        result
    }
}

pub(crate) async fn connect_fixed_target_udp_proxy_association(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    action: &DirectOutboundAction,
    target: &NetLocation,
) -> std::io::Result<FixedTargetUdpProxyAssociation> {
    let _ = target;
    match action {
        #[cfg(feature = "vless")]
        DirectOutboundAction::Vless { tag } => {
            let (stream, packet_encoding, xudp_request_prefix) =
                connect_vless_udp_stream(resolver, runtime, tag, target).await?;
            Ok(FixedTargetUdpProxyAssociation::Vless {
                stream,
                target: target.clone(),
                packet_encoding,
                xudp_first: true,
                xudp_request_prefix,
            })
        }
        #[cfg(feature = "vmess")]
        DirectOutboundAction::Vmess { tag } => {
            Ok(FixedTargetUdpProxyAssociation::Vmess {
                stream: connect_vmess_udp_stream(resolver, runtime, tag, target)
                    .await?,
                target: target.clone(),
            })
        }
        #[cfg(feature = "shadowsocks")]
        DirectOutboundAction::Shadowsocks { tag } => {
            let (socket, server_addr, codec) =
                connect_shadowsocks_udp_relay(resolver, runtime, tag).await?;
            Ok(FixedTargetUdpProxyAssociation::Shadowsocks {
                socket,
                server_addr,
                codec,
            })
        }
        DirectOutboundAction::Socks { tag } => {
            let (control, socket, relay_addr) =
                connect_socks_udp_relay(resolver, runtime, tag).await?;
            Ok(FixedTargetUdpProxyAssociation::Socks {
                _control: control,
                socket,
                relay_addr,
            })
        }
        #[cfg(feature = "trojan")]
        DirectOutboundAction::Trojan { tag } => {
            Ok(FixedTargetUdpProxyAssociation::Trojan {
                stream: connect_trojan_udp_stream(resolver, runtime, tag, target)
                    .await?,
            })
        }
        DirectOutboundAction::Freedom { .. }
        | DirectOutboundAction::Blackhole { .. } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fixed-target UDP proxy association requires a proxy outbound action",
        )),
    }
}

#[cfg(feature = "vmess")]
pub(crate) async fn exchange_vmess_udp(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    tag: &str,
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<UdpOutboundResponse> {
    let connector = runtime.outbound_connector(tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VMess UDP outbound {tag} is missing from the registry"),
        )
    })?;
    let OutboundConnectorKind::VmessTcp(config) = connector.as_ref() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("outbound {tag} is not a VMess connector"),
        ));
    };

    let transport = config.transport.connect(resolver, &config.server).await?;
    let mut stream =
        connect_vmess_udp(transport, config.user_uuid, config.security, target)?;
    let mut response = vec![0u8; u16::MAX as usize];
    let response_len = timeout(Duration::from_secs(60), async {
        write_vmess_message(&mut *stream, payload).await?;
        read_vmess_message(&mut *stream, &mut response).await
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "VMess UDP response timed out",
        )
    })??;
    if response_len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "VMess UDP response stream closed before a message arrived",
        ));
    }
    response.truncate(response_len);
    Ok(UdpOutboundResponse {
        source: target.clone(),
        payload: response,
    })
}

#[cfg(feature = "vless")]
pub(crate) async fn exchange_vless_udp(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    tag: &str,
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<UdpOutboundResponse> {
    let connector = runtime.outbound_connector(tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS UDP outbound {tag} is missing from the registry"),
        )
    })?;
    let OutboundConnectorKind::VlessTcp(config) = connector.as_ref() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("outbound {tag} is not a VLESS connector"),
        ));
    };

    let mut stream = config.transport.connect(resolver, &config.server).await?;
    let request = encode_vless_udp_request(&config.user_uuid, target)?;
    stream.write_all(&request).await?;
    let packet = encode_vless_udp_packet(payload)?;
    stream.write_all(&packet).await?;
    stream.flush().await?;

    let mut stream = VlessTcpOutboundStream::new(stream);
    let response_length = timeout(Duration::from_secs(60), stream.read_u16())
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "VLESS UDP response timed out",
            )
        })?? as usize;
    if response_length == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "VLESS UDP response payload is empty",
        ));
    }
    let mut response = vec![0u8; response_length];
    timeout(Duration::from_secs(60), stream.read_exact(&mut response))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "VLESS UDP response body timed out",
            )
        })??;
    Ok(UdpOutboundResponse {
        source: target.clone(),
        payload: response,
    })
}

#[cfg(feature = "trojan")]
pub(crate) async fn exchange_trojan_udp(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    tag: &str,
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<UdpOutboundResponse> {
    let connector = runtime.outbound_connector(tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Trojan UDP outbound {tag} is missing from the registry"),
        )
    })?;
    let OutboundConnectorKind::TrojanTcp(config) = connector.as_ref() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("outbound {tag} is not a Trojan connector"),
        ));
    };

    let mut stream = config.transport.connect(resolver, &config.server).await?;
    let request = encode_trojan_udp_request(&config.password, target)?;
    stream.write_all(&request).await?;
    let packet = encode_packet_location(target, payload)?;
    stream.write_all(&packet).await?;
    stream.flush().await?;
    let (source, response) =
        timeout(Duration::from_secs(60), read_packet(&mut stream))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Trojan UDP response timed out",
                )
            })??;
    Ok(UdpOutboundResponse {
        source,
        payload: response,
    })
}

pub(crate) async fn exchange_socks_udp(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    tag: &str,
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<UdpOutboundResponse> {
    let connector = runtime.outbound_connector(tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SOCKS UDP outbound {tag} is missing from the registry"),
        )
    })?;
    let OutboundConnectorKind::SocksTcp(config) = connector.as_ref() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("outbound {tag} is not a SOCKS connector"),
        ));
    };

    let server_addr = resolve_single_address(resolver, &config.server).await?;
    let mut control = config.transport.connect(resolver, &config.server).await?;
    let relay_location =
        associate_socks5_udp(&mut *control, config.credentials.as_ref()).await?;
    if relay_location.port() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS UDP ASSOCIATE returned relay port zero",
        ));
    }
    let mut relay_addr = resolve_single_address(resolver, &relay_location).await?;
    if relay_addr.ip().is_unspecified() {
        relay_addr.set_ip(server_addr.ip());
    }
    let bind_addr = if relay_addr.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    let packet = encode_socks5_udp_packet(target, payload)?;
    socket.send_to(&packet, relay_addr).await?;

    let mut response = vec![0u8; 64 * 1024];
    let response_len = timeout(Duration::from_secs(60), async {
        loop {
            let (length, source) = socket.recv_from(&mut response).await?;
            if source == relay_addr {
                return Ok::<usize, std::io::Error>(length);
            }
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "SOCKS UDP response timed out",
        )
    })??;
    response.truncate(response_len);
    let decoded = decode_socks5_udp_packet(&response)?;
    drop(control);
    Ok(UdpOutboundResponse {
        source: decoded.location,
        payload: decoded.payload,
    })
}

pub(crate) async fn exchange_direct_proxy_udp(
    resolver: &Arc<dyn Resolver>,
    runtime: &RuntimeState,
    action: &DirectOutboundAction,
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<UdpOutboundResponse> {
    match action {
        #[cfg(feature = "shadowsocks")]
        DirectOutboundAction::Shadowsocks { tag } => {
            exchange_shadowsocks_udp(resolver, runtime, tag, target, payload).await
        }
        DirectOutboundAction::Socks { tag } => {
            exchange_socks_udp(resolver, runtime, tag, target, payload).await
        }
        #[cfg(feature = "trojan")]
        DirectOutboundAction::Trojan { tag } => {
            exchange_trojan_udp(resolver, runtime, tag, target, payload).await
        }
        #[cfg(feature = "vless")]
        DirectOutboundAction::Vless { tag } => {
            exchange_vless_udp(resolver, runtime, tag, target, payload).await
        }
        #[cfg(feature = "vmess")]
        DirectOutboundAction::Vmess { tag } => {
            exchange_vmess_udp(resolver, runtime, tag, target, payload).await
        }
        DirectOutboundAction::Freedom { .. }
        | DirectOutboundAction::Blackhole { .. } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "direct UDP proxy exchange requires a proxy outbound action",
        )),
    }
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
        OutboundConnectorKind::SocksTcp(_) if network_name == "udp" => {
            Ok(DirectOutboundAction::Socks { tag })
        }
        OutboundConnectorKind::SocksTcp(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{network_name} outbound {tag} requires the TCP connector path"),
        )),
        #[cfg(feature = "trojan")]
        OutboundConnectorKind::TrojanTcp(_) if network_name == "udp" => {
            Ok(DirectOutboundAction::Trojan { tag })
        }
        #[cfg(feature = "trojan")]
        OutboundConnectorKind::TrojanTcp(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{network_name} outbound {tag} requires the TCP connector path"),
        )),
        #[cfg(feature = "vless")]
        OutboundConnectorKind::VlessTcp(_) if network_name == "udp" => {
            Ok(DirectOutboundAction::Vless { tag })
        }
        #[cfg(feature = "vless")]
        OutboundConnectorKind::VlessTcp(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{network_name} outbound {tag} requires the TCP connector path"),
        )),
        #[cfg(feature = "vmess")]
        OutboundConnectorKind::VmessTcp(_) if network_name == "udp" => {
            Ok(DirectOutboundAction::Vmess { tag })
        }
        #[cfg(feature = "vmess")]
        OutboundConnectorKind::VmessTcp(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{network_name} outbound {tag} requires the TCP connector path"),
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
    #[cfg(feature = "shadowsocks")]
    use crate::config::server_config::ShadowsocksUser;
    #[cfg(feature = "vmess")]
    use crate::{
        config::server_config::VmessUser,
        handler::{
            tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
            vmess::vmess_handler::VmessTcpServerHandler,
        },
    };
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

    #[cfg(feature = "shadowsocks")]
    fn shadowsocks_outbound(
        tag: &str,
        server: SocketAddr,
        password: &str,
    ) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: "shadowsocks".into(),
            settings: Some(serde_json::json!({
                "address": server.ip().to_string(),
                "port": server.port(),
                "method": "aes-128-gcm",
                "password": password
            })),
            stream_settings: Some(OutboundStreamSettings {
                network: "tcp".into(),
                security: Some("none".into()),
                ..OutboundStreamSettings::default()
            }),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    fn socks_outbound(tag: &str, server: SocketAddr) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: "socks".into(),
            settings: Some(serde_json::json!({
                "address": server.ip().to_string(),
                "port": server.port()
            })),
            stream_settings: Some(OutboundStreamSettings {
                network: "tcp".into(),
                security: Some("none".into()),
                ..OutboundStreamSettings::default()
            }),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    #[cfg(feature = "trojan")]
    fn trojan_outbound(
        tag: &str,
        server: SocketAddr,
        password: &str,
    ) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: "trojan".into(),
            settings: Some(serde_json::json!({
                "address": server.ip().to_string(),
                "port": server.port(),
                "password": password
            })),
            stream_settings: Some(OutboundStreamSettings {
                network: "tcp".into(),
                security: Some("none".into()),
                ..OutboundStreamSettings::default()
            }),
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
                xhttp_settings: None,
            }),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    #[cfg(feature = "vmess")]
    fn vmess_outbound(
        tag: &str,
        server: SocketAddr,
        user_id: &str,
        security: &str,
    ) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: "vmess".into(),
            settings: Some(serde_json::json!({
                "vnext": [{
                    "address": server.ip().to_string(),
                    "port": server.port(),
                    "users": [{
                        "id": user_id,
                        "security": security,
                        "alterId": 0
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
                xhttp_settings: None,
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

    #[cfg(feature = "shadowsocks")]
    #[tokio::test]
    async fn shadowsocks_udp_association_reuses_one_socket_for_two_packets() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let password = "shadowsocks-association-password";
        let codec = ShadowsocksUdpCodec::new(
            vec![ShadowsocksUser {
                method: "aes-128-gcm".into(),
                password: password.into(),
                email: "association-test".into(),
            }],
            None,
        )
        .unwrap();
        let targets = [
            NetLocation::new(Address::Hostname("dns.example".into()), 53),
            NetLocation::new(Address::Hostname("ntp.example".into()), 123),
        ];
        let server_targets = targets.clone();
        let server = tokio::spawn(async move {
            let mut buffer = vec![0u8; 64 * 1024];
            let mut client_addr = None;
            for (index, (expected, response)) in [
                (b"query".as_slice(), b"answer".as_slice()),
                (b"query-two".as_slice(), b"answer-two".as_slice()),
            ]
            .into_iter()
            .enumerate()
            {
                let (len, source) = socket.recv_from(&mut buffer).await.unwrap();
                if let Some(client_addr) = client_addr {
                    assert_eq!(source, client_addr);
                } else {
                    client_addr = Some(source);
                }
                let request = codec.decrypt_packet(&buffer[..len]).unwrap();
                assert_eq!(request.target_location, server_targets[index]);
                assert_eq!(request.payload, expected);
                let response_packet = codec
                    .encrypt_packet(&request, &server_targets[index], response)
                    .unwrap();
                socket.send_to(&response_packet, source).await.unwrap();
            }
        });

        let runtime = RuntimeState::try_new(
            Vec::new(),
            vec![shadowsocks_outbound("proxy", server_addr, password)],
        )
        .expect("Shadowsocks outbound should compile");
        let resolver: Arc<dyn Resolver> = Arc::new(FixedResolver);
        let action = DirectOutboundAction::Shadowsocks {
            tag: "proxy".into(),
        };
        let mut associations =
            UdpProxyAssociationRegistry::new(Duration::from_secs(60));
        for (index, (payload, expected)) in [
            (b"query".as_slice(), b"answer".as_slice()),
            (b"query-two".as_slice(), b"answer-two".as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let response = associations
                .exchange(&resolver, &runtime, &action, &targets[index], payload)
                .await
                .expect("Shadowsocks UDP association exchange should succeed");
            assert_eq!(response.source, targets[index]);
            assert_eq!(response.payload, expected);
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks_udp_association_reuses_control_and_relay_for_two_packets() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let targets = [
            NetLocation::new(Address::Hostname("dns.example".into()), 53),
            NetLocation::new(Address::Hostname("ntp.example".into()), 123),
        ];
        let server_targets = targets.clone();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            control.write_all(&[5, 0]).await.unwrap();

            let mut associate = [0u8; 10];
            control.read_exact(&mut associate).await.unwrap();
            assert_eq!(associate, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
            let mut reply = vec![5, 0, 0, 1];
            let std::net::IpAddr::V4(relay_ip) = relay_addr.ip() else {
                panic!("test relay must use IPv4");
            };
            reply.extend_from_slice(&relay_ip.octets());
            reply.extend_from_slice(&relay_addr.port().to_be_bytes());
            control.write_all(&reply).await.unwrap();

            let mut buffer = vec![0u8; 64 * 1024];
            let mut client_addr = None;
            for (index, (expected, response)) in [
                (b"query".as_slice(), b"answer".as_slice()),
                (b"query-two".as_slice(), b"answer-two".as_slice()),
            ]
            .into_iter()
            .enumerate()
            {
                let (len, source) = relay.recv_from(&mut buffer).await.unwrap();
                if let Some(client_addr) = client_addr {
                    assert_eq!(source, client_addr);
                } else {
                    client_addr = Some(source);
                }
                let packet = decode_socks5_udp_packet(&buffer[..len]).unwrap();
                assert_eq!(packet.location, server_targets[index]);
                assert_eq!(packet.payload, expected);
                let response_packet =
                    encode_socks5_udp_packet(&server_targets[index], response)
                        .unwrap();
                relay.send_to(&response_packet, source).await.unwrap();
            }
        });

        let runtime = RuntimeState::try_new(
            Vec::new(),
            vec![socks_outbound("proxy", server_addr)],
        )
        .expect("SOCKS outbound should compile");
        let resolver: Arc<dyn Resolver> = Arc::new(FixedResolver);
        let action = DirectOutboundAction::Socks {
            tag: "proxy".into(),
        };
        let mut associations =
            UdpProxyAssociationRegistry::new(Duration::from_secs(60));
        for (index, (payload, expected)) in [
            (b"query".as_slice(), b"answer".as_slice()),
            (b"query-two".as_slice(), b"answer-two".as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let response = associations
                .exchange(&resolver, &runtime, &action, &targets[index], payload)
                .await
                .expect("SOCKS UDP association exchange should succeed");
            assert_eq!(response.source, targets[index]);
            assert_eq!(response.payload, expected);
        }
        server.await.unwrap();
    }

    #[cfg(feature = "trojan")]
    #[tokio::test]
    async fn trojan_udp_association_reuses_one_connection_for_two_packets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let password = "trojan-association-password";
        let targets = [
            NetLocation::new(Address::Hostname("dns.example".into()), 53),
            NetLocation::new(Address::Hostname("ntp.example".into()), 123),
        ];
        let expected_request =
            encode_trojan_udp_request(password, &targets[0]).unwrap();
        let server_targets = targets.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; expected_request.len()];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected_request);

            for (index, (expected, response)) in [
                (b"query".as_slice(), b"answer".as_slice()),
                (b"query-two".as_slice(), b"answer-two".as_slice()),
            ]
            .into_iter()
            .enumerate()
            {
                let (packet_target, payload) =
                    read_packet(&mut stream).await.unwrap();
                assert_eq!(packet_target, server_targets[index]);
                assert_eq!(payload, expected);
                let packet =
                    encode_packet_location(&server_targets[index], response)
                        .unwrap();
                stream.write_all(&packet).await.unwrap();
                stream.flush().await.unwrap();
            }
        });

        let runtime = RuntimeState::try_new(
            Vec::new(),
            vec![trojan_outbound("proxy", server_addr, password)],
        )
        .expect("Trojan outbound should compile");
        let resolver: Arc<dyn Resolver> = Arc::new(FixedResolver);
        let action = DirectOutboundAction::Trojan {
            tag: "proxy".into(),
        };
        let mut associations =
            UdpProxyAssociationRegistry::new(Duration::from_secs(60));
        for (index, (payload, expected)) in [
            (b"query".as_slice(), b"answer".as_slice()),
            (b"query-two".as_slice(), b"answer-two".as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let response = associations
                .exchange(&resolver, &runtime, &action, &targets[index], payload)
                .await
                .expect("Trojan UDP association exchange should succeed");
            assert_eq!(response.source, targets[index]);
            assert_eq!(response.payload, expected);
        }
        server.await.unwrap();
    }

    #[cfg(feature = "vmess")]
    #[tokio::test]
    async fn vmess_udp_association_reuses_one_connection_for_two_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
        let handler = VmessTcpServerHandler::new(
            vec![VmessUser {
                user_id: user_id.into(),
                user_label: "vmess-udp-outbound-test".into(),
                user_level: 0,
                cipher: "aes-128-gcm".into(),
            }],
            true,
            "vmess-udp-outbound-test",
        );
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let result =
                handler.setup_server_stream(Box::new(stream)).await.unwrap();
            let TcpServerSetupResult::BidirectionalUdp {
                remote_location,
                mut stream,
                ..
            } = result
            else {
                panic!("expected VMess UDP forward");
            };
            assert_eq!(
                remote_location,
                NetLocation::new(Address::Hostname("dns.example".into()), 53)
            );
            let mut request = [0u8; 64];
            for (expected, response) in [
                (b"query".as_slice(), b"answer".as_slice()),
                (b"query-two".as_slice(), b"answer-two".as_slice()),
            ] {
                let request_len = read_vmess_message(&mut *stream, &mut request)
                    .await
                    .unwrap();
                assert_eq!(&request[..request_len], expected);
                write_vmess_message(&mut *stream, response).await.unwrap();
            }
        });

        let runtime = RuntimeState::try_new(
            Vec::new(),
            vec![vmess_outbound("proxy", server_addr, user_id, "aes-128-gcm")],
        )
        .expect("VMess outbound should compile");
        let resolver: Arc<dyn Resolver> = Arc::new(FixedResolver);
        let target = NetLocation::new(Address::Hostname("dns.example".into()), 53);
        let action = DirectOutboundAction::Vmess {
            tag: "proxy".into(),
        };
        let mut associations =
            UdpProxyAssociationRegistry::new(Duration::from_secs(60));
        for (payload, expected) in [
            (b"query".as_slice(), b"answer".as_slice()),
            (b"query-two".as_slice(), b"answer-two".as_slice()),
        ] {
            let response = associations
                .exchange(&resolver, &runtime, &action, &target, payload)
                .await
                .expect("VMess UDP association exchange should succeed");
            assert_eq!(response.source, target);
            assert_eq!(response.payload, expected);
        }
        server.await.unwrap();
    }

    #[cfg(feature = "vmess")]
    #[test]
    fn direct_outbound_selects_vmess_for_udp() {
        let server: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let runtime = RuntimeState::try_new(
            Vec::new(),
            vec![vmess_outbound(
                "proxy",
                server,
                "3ac9b383-75a1-431c-8184-106c80eb2273",
                "none",
            )],
        )
        .expect("VMess outbound should compile");

        assert_eq!(
            select_direct_outbound(&runtime, &RoutingInput::default(), "udp")
                .unwrap(),
            DirectOutboundAction::Vmess {
                tag: "proxy".into()
            }
        );
    }

    #[cfg(feature = "vless")]
    #[tokio::test]
    async fn vless_udp_association_reuses_one_connection_for_two_messages() {
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
            assert_eq!(prefix[18], 2);

            assert_eq!(stream.read_u16().await.unwrap(), 53);
            assert_eq!(stream.read_u8().await.unwrap(), 2);
            let domain_length = stream.read_u8().await.unwrap();
            let mut domain = vec![0u8; usize::from(domain_length)];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(&domain, b"dns.example");

            for (expected, response) in [
                (b"query".as_slice(), b"answer".as_slice()),
                (b"query-two".as_slice(), b"answer-two".as_slice()),
            ] {
                assert_eq!(
                    stream.read_u16().await.unwrap() as usize,
                    expected.len()
                );
                let mut payload = vec![0u8; expected.len()];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(payload, expected);

                if expected == b"query" {
                    stream.write_all(&[0, 0]).await.unwrap();
                }
                stream.write_u16(response.len() as u16).await.unwrap();
                stream.write_all(response).await.unwrap();
            }
        });

        let runtime = RuntimeState::try_new(
            Vec::new(),
            vec![vless_outbound("proxy", server_addr, user_id)],
        )
        .expect("VLESS outbound should compile");
        let resolver: Arc<dyn Resolver> = Arc::new(FixedResolver);
        let target = NetLocation::new(Address::Hostname("dns.example".into()), 53);
        let action = DirectOutboundAction::Vless {
            tag: "proxy".into(),
        };
        let mut associations =
            UdpProxyAssociationRegistry::new(Duration::from_secs(60));
        for (payload, expected) in [
            (b"query".as_slice(), b"answer".as_slice()),
            (b"query-two".as_slice(), b"answer-two".as_slice()),
        ] {
            let response = associations
                .exchange(&resolver, &runtime, &action, &target, payload)
                .await
                .expect("VLESS UDP association exchange should succeed");
            assert_eq!(response.source, target);
            assert_eq!(response.payload, expected);
        }
        server.await.unwrap();
    }

    #[cfg(feature = "vless")]
    #[test]
    fn direct_outbound_selects_vless_for_udp() {
        let server: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let runtime = RuntimeState::try_new(
            Vec::new(),
            vec![vless_outbound(
                "proxy",
                server,
                "3ac9b383-75a1-431c-8184-106c80eb2273",
            )],
        )
        .expect("VLESS outbound should compile");

        assert_eq!(
            select_direct_outbound(&runtime, &RoutingInput::default(), "udp")
                .unwrap(),
            DirectOutboundAction::Vless {
                tag: "proxy".into()
            }
        );
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
