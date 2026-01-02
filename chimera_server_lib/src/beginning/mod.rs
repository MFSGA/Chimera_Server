use std::{net::SocketAddr, sync::Arc, time::Duration};

use quic::start_quic_server;
use tokio::{io::AsyncWriteExt, task::JoinHandle, time::timeout};

use crate::{
    address::{BindLocation, NetLocation},
    async_stream::AsyncStream,
    config::{
        server_config::{ServerConfig, ServerProxyConfig},
        Transport,
    },
    handler::tcp::{
        tcp_handler::{TcpServerHandler, TcpServerSetupResult},
        tcp_handler_util::create_tcp_server_handler,
    },
    resolver::{resolve_single_address, NativeResolver, Resolver},
    traffic::{record_transfer, register_connection},
    util::socket::new_tcp_socket,
};

use tracing::{error, info};

mod quic;
mod xhttp;

pub async fn start_servers(config: ServerConfig) -> std::io::Result<Vec<JoinHandle<()>>> {
    if matches!(config.protocol, ServerProxyConfig::Xhttp { .. }) {
        return xhttp::start_xhttp_server(config).await;
    }

    let mut join_handles = Vec::with_capacity(3);

    match config.transport {
        Transport::Tcp => match start_tcp_server(config.clone()).await {
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
        Transport::Quic => match start_quic_server(config.clone()).await {
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
        Transport::Udp => {
            panic!("unsupported transport type: udp");
        }
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("failed to start servers at {}", &config.bind_location),
        ));
    }

    Ok(join_handles)
}

pub async fn start_tcp_server(config: ServerConfig) -> std::io::Result<Option<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,

        protocol,
        ..
    } = config;

    tracing::info!("Starting {} TCP server at {}", &protocol, &bind_location);

    let mut rules_stack = vec![];

    let tcp_handler: Arc<Box<dyn TcpServerHandler>> =
        Arc::new(create_tcp_server_handler(protocol, &tag, &mut rules_stack));
    tracing::debug!("TCP handler: {:?}", tcp_handler);

    let listener = match bind_location {
        BindLocation::Address(a) => {
            let socket_addr = a.to_socket_addr()?;
            tokio::net::TcpListener::bind(socket_addr).await?
        }
    };

    Ok(Some(tokio::spawn(async move {
        if let Err(err) = run_tcp_server(listener, tcp_handler).await {
            error!("TCP server stopped with error: {}", err);
        }
    })))
}

async fn run_tcp_server(
    listener: tokio::net::TcpListener,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

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

        tokio::spawn(async move {
            if let Err(e) = process_stream(stream, cloned_handler, cloned_cache, addr).await {
                error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
            } else {
                tracing::debug!("{}:{} finished successfully", addr.ip(), addr.port());
            }
        });
    }
}

async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,

    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        setup_server_stream(stream, server_handler),
    );
    tracing::info!("prepare to setup server stream");
    let setup_result = match setup_server_stream_future.await {
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

    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: _need_initial_flush,
            connection_success_response,
            traffic_context,
        } => {
            let traffic_context =
                traffic_context.map(|context| context.with_client_ip(peer_addr.ip()));
            let _connection_guard = register_connection(traffic_context.as_ref());

            let setup_client_stream_future = timeout(
                Duration::from_secs(60),
                setup_client_stream(&mut server_stream, resolver, remote_location.clone()),
            );

            let mut client_stream = match setup_client_stream_future.await {
                Ok(Ok(Some(s))) => s,
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
                        format!("client setup to {} timed out: {}", remote_location, elapsed),
                    ));
                }
            };

            if let Some(data) = connection_success_response {
                server_stream.write_all(&data).await?;
            }

            let copy_result =
                tokio::io::copy_bidirectional(&mut server_stream, &mut client_stream).await;

            let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());
            let copy_result = copy_result?;

            info!(
                "tcp forward to {} completed: client->remote {} bytes, remote->client {} bytes",
                remote_location, copy_result.0, copy_result.1
            );
            record_transfer(traffic_context, copy_result.0, copy_result.1);
            Ok(())
        }
    }
}

async fn setup_server_stream<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
) -> std::io::Result<TcpServerSetupResult>
where
    AS: AsyncStream + 'static,
{
    let server_stream = Box::new(stream);
    server_handler.setup_server_stream(server_stream).await
}

pub async fn setup_client_stream(
    server_stream: &mut Box<dyn AsyncStream>,

    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let target_addr = resolve_single_address(&resolver, &remote_location).await?;

    let tcp_socket = new_tcp_socket(None, target_addr.is_ipv6())?;
    let client_stream = tcp_socket.connect(target_addr).await?;

    if let Err(e) = client_stream.set_nodelay(true) {
        error!("Failed to set TCP no-delay on client socket: {}", e);
    }

    Ok(Some(Box::new(client_stream)))
}
