use std::{net::SocketAddr, sync::Arc, time::Duration};

use quic::start_quic_server;
#[cfg(target_os = "linux")]
use socket2::SockRef;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};
use udp::{
    run_bidirectional_udp, run_multi_directional_udp, run_session_based_udp,
    start_udp_server,
};

use crate::{
    address::{BindLocation, NetLocation},
    async_stream::AsyncStream,
    config::{
        Transport,
        server_config::{ServerConfig, ServerProxyConfig},
    },
    handler::{
        http::relay_plain_http_response,
        socks::run_shared_udp_relay,
        tcp::{
            tcp_handler::{
                TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
            },
            tcp_handler_util::create_tcp_server_handler,
        },
    },
    outbound::connect_tcp_outbound,
    resolver::{NativeResolver, Resolver, resolve_single_address},
    runtime::RuntimeState,
    traffic::{
        MeteredStream, TrafficDirection, record_transfer, register_connection,
    },
    util::{prefixed_stream::PrefixedStream, socket::new_tcp_socket},
};

use tracing::{error, info};

#[cfg(feature = "grpc_transport")]
mod grpc_transport;
mod quic;
mod tcp_relay;
pub(crate) mod udp;
mod xhttp;

pub async fn start_servers(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    if is_xhttp_server_protocol(&config.protocol) {
        return xhttp::start_xhttp_server(config, runtime).await;
    }
    #[cfg(feature = "grpc_transport")]
    if is_grpc_server_protocol(&config.protocol) {
        return grpc_transport::start_grpc_server(config, runtime).await;
    }

    let mut join_handles = Vec::with_capacity(3);

    if let ServerProxyConfig::Socks {
        accounts,
        udp_enabled: true,
        ..
    } = &config.protocol
    {
        let bind_addr = match &config.bind_location {
            BindLocation::Address(address) => address.to_socket_addr()?,
        };
        let socket = Arc::new(tokio::net::UdpSocket::bind(bind_addr).await?);
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let runtime = runtime.clone();
        let accounts = accounts.clone();
        let traffic_context = Some(
            crate::traffic::TrafficContext::new("socks")
                .with_inbound_tag(config.tag.clone()),
        );
        join_handles.push(tokio::spawn(async move {
            if let Err(error) = run_shared_udp_relay(
                socket,
                resolver,
                runtime,
                accounts,
                traffic_context,
            )
            .await
            {
                error!("SOCKS5 shared UDP listener stopped with error: {}", error);
            }
        }));
    }

    match config.transport {
        Transport::Tcp => {
            match start_tcp_server_with_runtime(config.clone(), runtime).await {
                Ok(Some(handle)) => {
                    join_handles.push(handle);
                }
                Ok(None) => (),
                Err(e) => {
                    for join_handle in join_handles {
                        join_handle.abort();
                    }
                    return Err(e);
                }
            }
        }
        Transport::TcpAndUdp => {
            match start_tcp_server_with_runtime(config.clone(), runtime.clone())
                .await
            {
                Ok(Some(handle)) => join_handles.push(handle),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
            match start_udp_server(config.clone(), runtime).await {
                Ok(Some(handle)) => join_handles.push(handle),
                Ok(None) => {}
                Err(error) => {
                    for join_handle in join_handles {
                        join_handle.abort();
                    }
                    return Err(error);
                }
            }
        }
        Transport::Quic => match start_quic_server(config.clone(), runtime).await {
            Ok(Some(handle)) => {
                join_handles.push(handle);
            }
            Ok(None) => (),
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        // UDP listeners need runtime state for routing/outbound selection.
        Transport::Udp => match start_udp_server(config.clone(), runtime).await {
            Ok(Some(handle)) => {
                join_handles.push(handle);
            }
            Ok(None) => (),
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            config.bind_location
        )));
    }

    Ok(join_handles)
}

#[cfg(feature = "grpc_transport")]
fn is_grpc_server_protocol(protocol: &ServerProxyConfig) -> bool {
    match protocol {
        ServerProxyConfig::Grpc(_) => true,
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => {
            matches!(tls_config.inner.as_ref(), ServerProxyConfig::Grpc(_))
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality_config) => {
            matches!(reality_config.inner.as_ref(), ServerProxyConfig::Grpc(_))
        }
        _ => false,
    }
}

fn is_xhttp_server_protocol(protocol: &ServerProxyConfig) -> bool {
    match protocol {
        ServerProxyConfig::Xhttp { .. } => true,
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => {
            matches!(tls_config.inner.as_ref(), ServerProxyConfig::Xhttp { .. })
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality_config) => {
            matches!(
                reality_config.inner.as_ref(),
                ServerProxyConfig::Xhttp { .. }
            )
        }
        _ => false,
    }
}

pub async fn start_tcp_server(
    config: ServerConfig,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let runtime = RuntimeState::new(vec![config.clone()], Vec::new());
    start_tcp_server_with_runtime(config, runtime).await
}

async fn start_tcp_server_with_runtime(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,

        protocol,
        ..
    } = config;

    tracing::info!("Starting {} TCP server at {}", &protocol, &bind_location);

    let mut rules_stack = vec![];

    let tcp_handler: Arc<Box<dyn TcpServerHandler>> =
        Arc::new(create_tcp_server_handler(protocol, &tag, &mut rules_stack)?);
    tracing::debug!("TCP handler: {:?}", tcp_handler);

    let listener = match bind_location {
        BindLocation::Address(a) => {
            let socket_addr = a.to_socket_addr()?;
            tokio::net::TcpListener::bind(socket_addr).await?
        }
    };

    Ok(Some(tokio::spawn(async move {
        if let Err(err) = run_tcp_server(listener, tcp_handler, runtime).await {
            error!("TCP server stopped with error: {}", err);
        }
    })))
}

async fn run_tcp_server(
    listener: tokio::net::TcpListener,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let listener_addr = listener.local_addr()?;

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {}", e);
                continue;
            }
        };
        if let Err(e) = stream.set_nodelay(true) {
            error!("Failed to set TCP nodelay: {}", e);
        }
        let cloned_cache = resolver.clone();
        let cloned_handler = server_handler.clone();
        let runtime = runtime.clone();

        tokio::spawn(async move {
            let connection_context = match tcp_server_connection_context(
                &stream,
                cloned_handler.as_ref().as_ref(),
            ) {
                Ok(mut context) => {
                    context.peer_addr = Some(addr);
                    context.listener_addr = Some(listener_addr);
                    context.runtime = Some(runtime.clone());
                    context
                }
                Err(error) => {
                    error!(
                        "{}:{} failed to read original destination: {}",
                        addr.ip(),
                        addr.port(),
                        error
                    );
                    return;
                }
            };
            if let Err(e) = process_stream_with_context(
                stream,
                cloned_handler,
                cloned_cache,
                addr,
                runtime,
                connection_context,
            )
            .await
            {
                error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
            } else {
                tracing::debug!(
                    "{}:{} finished successfully",
                    addr.ip(),
                    addr.port()
                );
            }
        });
    }
}

#[cfg(target_os = "linux")]
fn tcp_server_connection_context(
    stream: &tokio::net::TcpStream,
    server_handler: &dyn TcpServerHandler,
) -> std::io::Result<TcpServerConnectionContext> {
    let local_addr = stream.local_addr()?;
    if !server_handler.requires_original_destination() {
        return Ok(TcpServerConnectionContext {
            original_destination: None,
            local_addr: Some(local_addr),
            ..TcpServerConnectionContext::default()
        });
    }

    let socket = SockRef::from(stream);
    let original_destination = if stream.local_addr()?.is_ipv6() {
        socket.original_dst_v6()?
    } else {
        socket.original_dst_v4()?
    };
    let original_destination =
        original_destination.as_socket().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SO_ORIGINAL_DST returned a non-IP socket address",
            )
        })?;

    Ok(TcpServerConnectionContext {
        original_destination: Some(NetLocation::from_ip_addr(
            original_destination.ip(),
            original_destination.port(),
        )),
        local_addr: Some(local_addr),
        ..TcpServerConnectionContext::default()
    })
}

#[cfg(not(target_os = "linux"))]
fn tcp_server_connection_context(
    stream: &tokio::net::TcpStream,
    server_handler: &dyn TcpServerHandler,
) -> std::io::Result<TcpServerConnectionContext> {
    if server_handler.requires_original_destination() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dokodemo-door followRedirect is supported only on Linux",
        ));
    }

    Ok(TcpServerConnectionContext {
        original_destination: None,
        local_addr: Some(stream.local_addr()?),
        ..TcpServerConnectionContext::default()
    })
}

fn build_proxy_protocol_header(
    version: u8,
    source: SocketAddr,
    destination: Option<SocketAddr>,
) -> std::io::Result<Vec<u8>> {
    match version {
        1 => {
            let Some(destination) = destination else {
                return Ok(b"PROXY UNKNOWN\r\n".to_vec());
            };
            let family = match (source.ip(), destination.ip()) {
                (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => "TCP4",
                (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_)) => "TCP6",
                _ => return Ok(b"PROXY UNKNOWN\r\n".to_vec()),
            };
            Ok(format!(
                "PROXY {family} {} {} {} {}\r\n",
                source.ip(),
                destination.ip(),
                source.port(),
                destination.port()
            )
            .into_bytes())
        }
        2 => {
            let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            let Some(destination) = destination else {
                header.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
                return Ok(header);
            };
            match (source.ip(), destination.ip()) {
                (std::net::IpAddr::V4(source_ip), std::net::IpAddr::V4(dest_ip)) => {
                    header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
                    header.extend_from_slice(&source_ip.octets());
                    header.extend_from_slice(&dest_ip.octets());
                }
                (std::net::IpAddr::V6(source_ip), std::net::IpAddr::V6(dest_ip)) => {
                    header.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
                    header.extend_from_slice(&source_ip.octets());
                    header.extend_from_slice(&dest_ip.octets());
                }
                _ => {
                    header.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
                    return Ok(header);
                }
            }
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
            Ok(header)
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported PROXY protocol version {other}"),
        )),
    }
}

pub(super) async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    runtime: RuntimeState,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let connection_context = TcpServerConnectionContext {
        runtime: Some(runtime.clone()),
        ..TcpServerConnectionContext::default()
    };
    process_stream_with_context(
        stream,
        server_handler,
        resolver,
        peer_addr,
        runtime,
        connection_context,
    )
    .await
}

async fn process_stream_with_context<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    mut peer_addr: SocketAddr,
    runtime: RuntimeState,
    connection_context: TcpServerConnectionContext,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let local_addr = connection_context.local_addr;
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        setup_server_stream(stream, server_handler, connection_context),
    );
    tracing::info!("prepare to setup server stream");
    let mut setup_result = match setup_server_stream_future.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup server stream: {}", e),
            ));
        }
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("server setup timed out: {}", elapsed),
            ));
        }
    };
    let setup_result = loop {
        match setup_result {
            TcpServerSetupResult::PeerAddrOverride {
                peer_addr: overridden,
                inner,
            } => {
                peer_addr = overridden;
                setup_result = *inner;
            }
            other => break other,
        }
    };
    let mut setup_result = match setup_result {
        TcpServerSetupResult::TcpFallback {
            remote_location,
            stream,
            proxy_protocol_version,
            traffic_context,
        } => {
            let prefix = build_proxy_protocol_header(
                proxy_protocol_version,
                peer_addr,
                local_addr,
            )?;
            TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(PrefixedStream::new(prefix, stream)),
                need_initial_flush: false,
                connection_success_response: None,
                traffic_context,
            }
        }
        other => other,
    };

    while matches!(&setup_result, TcpServerSetupResult::HttpPlainForward { .. }) {
        let TcpServerSetupResult::HttpPlainForward {
            remote_location,
            stream: mut server_stream,
            request_head,
            request_method,
            keep_alive,
            next_handler,
            traffic_context,
        } = setup_result
        else {
            unreachable!("HTTP plain-forward loop only accepts HTTP results");
        };
        let mut traffic_context =
            traffic_context.map(|context| context.with_client_ip(peer_addr.ip()));
        let inbound_tag = traffic_context
            .as_ref()
            .and_then(|context| context.inbound_tag.as_deref())
            .unwrap_or_default()
            .to_string();
        let user = traffic_context
            .as_ref()
            .and_then(|context| context.identity.as_deref())
            .unwrap_or_default()
            .to_string();
        let (client_stream, outbound_tag) = match timeout(
            Duration::from_secs(60),
            setup_routed_client_stream(
                resolver.clone(),
                remote_location.clone(),
                &runtime,
                &inbound_tag,
                &user,
                peer_addr,
            ),
        )
        .await
        {
            Ok(Ok(Some(result))) => result,
            Ok(Ok(None)) => {
                let _ = server_stream.shutdown().await;
                return Ok(());
            }
            Ok(Err(error)) => {
                let _ = server_stream.shutdown().await;
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to setup HTTP client stream to {}: {}",
                        remote_location, error
                    ),
                ));
            }
            Err(elapsed) => {
                let _ = server_stream.shutdown().await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "HTTP client setup to {} timed out: {}",
                        remote_location, elapsed
                    ),
                ));
            }
        };
        if let Some(tag) = outbound_tag {
            traffic_context =
                traffic_context.map(|context| context.with_outbound_tag(tag));
        }
        let _connection_guard = register_connection(traffic_context.as_ref());
        let mut client_stream = MeteredStream::new(
            client_stream,
            traffic_context.clone(),
            TrafficDirection::Download,
        );
        client_stream.write_all(&request_head).await?;
        client_stream.flush().await?;
        record_transfer(traffic_context, request_head.len() as u64, 0);

        let response_reusable = relay_plain_http_response(
            &mut client_stream,
            &mut server_stream,
            &request_method,
        )
        .await?;
        let _ = client_stream.shutdown().await;
        if !keep_alive || !response_reusable {
            let _ = server_stream.shutdown().await;
            return Ok(());
        }

        setup_result = match timeout(
            Duration::from_secs(60),
            next_handler.setup_server_stream(server_stream),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok(()),
        };
    }

    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: _need_initial_flush,
            connection_success_response,
            traffic_context,
        } => {
            let mut traffic_context = traffic_context
                .map(|context| context.with_client_ip(peer_addr.ip()));
            let inbound_tag = traffic_context
                .as_ref()
                .and_then(|context| context.inbound_tag.as_deref())
                .unwrap_or_default()
                .to_string();
            let user = traffic_context
                .as_ref()
                .and_then(|context| context.identity.as_deref())
                .unwrap_or_default()
                .to_string();

            let setup_client_stream_future = timeout(
                Duration::from_secs(60),
                setup_routed_client_stream(
                    resolver,
                    remote_location.clone(),
                    &runtime,
                    &inbound_tag,
                    &user,
                    peer_addr,
                ),
            );

            let (client_stream, outbound_tag) =
                match setup_client_stream_future.await {
                    Ok(Ok(Some(result))) => result,
                    Ok(Ok(None)) => {
                        let _ = server_stream.shutdown().await;
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        let _ = server_stream.shutdown().await;
                        return Err(std::io::Error::new(
                            e.kind(),
                            format!(
                                "failed to setup client stream to {}: {}",
                                remote_location, e
                            ),
                        ));
                    }
                    Err(elapsed) => {
                        let _ = server_stream.shutdown().await;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "client setup to {} timed out: {}",
                                remote_location, elapsed
                            ),
                        ));
                    }
                };
            if let Some(tag) = outbound_tag {
                traffic_context =
                    traffic_context.map(|context| context.with_outbound_tag(tag));
            }
            let _connection_guard = register_connection(traffic_context.as_ref());
            let relay_traffic_context = traffic_context.clone();
            let mut server_stream = MeteredStream::new(
                server_stream,
                traffic_context.clone(),
                TrafficDirection::Upload,
            );
            let mut client_stream = MeteredStream::new(
                client_stream,
                traffic_context,
                TrafficDirection::Download,
            );

            if let Some(data) = connection_success_response {
                server_stream.write_all(&data).await?;
            }

            let copy_result = tcp_relay::copy_bidirectional(
                &mut server_stream,
                &mut client_stream,
            )
            .await;

            let (_, _) =
                futures::join!(server_stream.shutdown(), client_stream.shutdown());
            let copy_result = copy_result?;
            record_transfer(
                relay_traffic_context,
                copy_result.bypassed_left_to_right,
                copy_result.bypassed_right_to_left,
            );

            info!(
                relay_backend = copy_result.configured_backend(),
                relay_path = copy_result.effective_path(),
                relay_fallback = copy_result.fallback_reason().unwrap_or("none"),
                bypassed_upload = copy_result.bypassed_left_to_right,
                bypassed_download = copy_result.bypassed_right_to_left,
                "tcp forward to {} completed: client->remote {} bytes, remote->client {} bytes",
                remote_location,
                copy_result.left_to_right,
                copy_result.right_to_left,
            );
            Ok(())
        }
        TcpServerSetupResult::HttpPlainForward { .. } => {
            unreachable!(
                "HTTP plain-forward results must be handled before generic forwarding"
            )
        }
        TcpServerSetupResult::PeerAddrOverride { .. } => {
            unreachable!(
                "peer address override must be normalized before forwarding"
            )
        }
        TcpServerSetupResult::TcpFallback { .. } => {
            unreachable!("fallback result must be normalized before forwarding")
        }
        TcpServerSetupResult::UdpAssociate {
            mut stream,
            traffic_context,
        } => {
            let traffic_context = traffic_context
                .map(|context| context.with_client_ip(peer_addr.ip()));
            let _connection_guard = register_connection(traffic_context.as_ref());
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => return Ok(()),
                    Ok(_) => continue,
                    Err(error) => return Err(error),
                }
            }
        }
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream,
            traffic_context,
        } => {
            run_bidirectional_udp(
                stream,
                remote_location,
                resolver,
                runtime,
                peer_addr,
                traffic_context,
            )
            .await
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream,
            traffic_context,
        } => {
            run_multi_directional_udp(
                stream,
                resolver,
                runtime,
                peer_addr,
                traffic_context,
            )
            .await
        }
        TcpServerSetupResult::SessionBasedUdp {
            stream,
            traffic_context,
        } => {
            run_session_based_udp(stream, runtime, peer_addr, traffic_context).await
        }
        TcpServerSetupResult::AlreadyHandled => Ok(()),
    }
}

async fn setup_server_stream<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    connection_context: TcpServerConnectionContext,
) -> std::io::Result<TcpServerSetupResult>
where
    AS: AsyncStream + 'static,
{
    let server_stream = Box::new(stream);
    server_handler
        .setup_server_stream_with_context(server_stream, connection_context)
        .await
}

async fn setup_routed_client_stream(
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
    runtime: &RuntimeState,
    inbound_tag: &str,
    user: &str,
    peer_addr: SocketAddr,
) -> std::io::Result<Option<(Box<dyn AsyncStream>, Option<String>)>> {
    connect_tcp_outbound(
        &resolver,
        &remote_location,
        runtime,
        inbound_tag,
        user,
        peer_addr,
    )
    .await
    .map(|connection| {
        connection.map(|connection| {
            (
                Box::new(connection.stream) as Box<dyn AsyncStream>,
                connection.outbound_tag,
            )
        })
    })
}

async fn connect_tcp_target(
    target_addr: SocketAddr,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let tcp_socket = new_tcp_socket(None, target_addr.is_ipv6())?;
    let client_stream = tcp_socket.connect(target_addr).await?;

    if let Err(e) = client_stream.set_nodelay(true) {
        error!("Failed to set TCP no-delay on client socket: {}", e);
    }

    Ok(Box::new(client_stream))
}

pub async fn setup_client_stream(
    _server_stream: &mut Box<dyn AsyncStream>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let target_addr = resolve_single_address(&resolver, &remote_location).await?;
    connect_tcp_target(target_addr).await.map(Some)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[cfg(target_os = "linux")]
    use tokio::net::{TcpListener, TcpStream};

    #[cfg(target_os = "linux")]
    use crate::{
        address::{Address, NetLocation},
        config::server_config::DokodemoDoorConfig,
        handler::dokodemo::DokodemoDoorTcpHandler,
    };

    use super::*;

    #[test]
    fn proxy_protocol_v1_encodes_ipv4_addresses_and_ports() {
        let source: SocketAddr = "192.0.2.10:12345".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let header = build_proxy_protocol_header(1, source, Some(destination))
            .expect("build PROXY v1 header");
        assert_eq!(header, b"PROXY TCP4 192.0.2.10 198.51.100.20 12345 443\r\n");
    }

    #[test]
    fn proxy_protocol_v2_encodes_ipv4_addresses_and_ports() {
        let source: SocketAddr = "192.0.2.10:12345".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let header = build_proxy_protocol_header(2, source, Some(destination))
            .expect("build PROXY v2 header");
        let mut expected = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        expected.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
        expected.extend_from_slice(&[192, 0, 2, 10]);
        expected.extend_from_slice(&[198, 51, 100, 20]);
        expected.extend_from_slice(&12345u16.to_be_bytes());
        expected.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(header, expected);
    }

    #[test]
    fn proxy_protocol_uses_unknown_or_local_for_mixed_families() {
        let source = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
        let destination = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);
        assert_eq!(
            build_proxy_protocol_header(1, source, Some(destination)).unwrap(),
            b"PROXY UNKNOWN\r\n"
        );
        let mut expected = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        expected.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        assert_eq!(
            build_proxy_protocol_header(2, source, Some(destination)).unwrap(),
            expected
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn original_destination_matches_tcp_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind original-destination listener");
        let listener_addr = listener.local_addr().expect("listener address");
        let connect_task = tokio::spawn(async move {
            TcpStream::connect(listener_addr)
                .await
                .expect("connect original-destination listener")
        });
        let (server_stream, _) = listener
            .accept()
            .await
            .expect("accept original-destination connection");
        let _client_stream = connect_task.await.expect("connect task finished");
        let handler = DokodemoDoorTcpHandler::new(
            DokodemoDoorConfig {
                target: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 1),
                follow_redirect: true,
            },
            "dokodemo-original-destination",
        );

        let context = tcp_server_connection_context(&server_stream, &handler)
            .expect("read SO_ORIGINAL_DST from accepted TCP connection");
        assert_eq!(
            context.original_destination,
            Some(NetLocation::from_ip_addr(
                listener_addr.ip(),
                listener_addr.port(),
            ))
        );
    }
}
