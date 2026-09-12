use std::{net::SocketAddr, sync::Arc};

use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    config::server_config::InboundSniffingConfig,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
    outbound::{InboundRoutingMetadata, connect_tcp_outbound_with_routing_metadata},
    resolver::{Resolver, resolve_single_address},
    runtime::DataPlaneRuntime,
    util::socket::new_tcp_socket,
};

use tracing::error;

pub(super) use crate::session::dispatcher::process_stream_with_context;
#[cfg(test)]
pub(super) use crate::session::dispatcher::{
    normalize_setup_result, routing_identity,
};

pub(super) async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    process_stream_with_local_addr(
        stream,
        server_handler,
        resolver,
        peer_addr,
        None,
        runtime,
    )
    .await
}

pub(super) async fn process_stream_with_local_addr<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    process_stream_with_sniffing_and_local_addr(
        stream,
        server_handler,
        resolver,
        peer_addr,
        local_addr,
        runtime,
        None,
    )
    .await
}

pub(super) async fn process_stream_with_sniffing_and_local_addr<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    runtime: DataPlaneRuntime,
    sniffing: Option<InboundSniffingConfig>,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let connection_context = stream_connection_context(&runtime, local_addr);
    process_stream_with_context(
        stream,
        server_handler,
        resolver,
        peer_addr,
        runtime,
        connection_context,
        sniffing,
    )
    .await
}

pub(super) fn stream_connection_context(
    runtime: &DataPlaneRuntime,
    local_addr: Option<SocketAddr>,
) -> TcpServerConnectionContext {
    TcpServerConnectionContext {
        local_addr,
        handshake_runtime: Some(runtime.inbound_handshake_runtime()),
        ..TcpServerConnectionContext::default()
    }
}

pub(crate) async fn setup_server_stream<AS>(
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

pub(crate) async fn setup_routed_client_stream(
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
    runtime: &DataPlaneRuntime,
    inbound_tag: &str,
    user: &str,
    peer_addr: SocketAddr,
    routing_metadata: InboundRoutingMetadata,
) -> std::io::Result<Option<(Box<dyn AsyncStream>, Option<String>)>> {
    connect_tcp_outbound_with_routing_metadata(
        &resolver,
        &remote_location,
        runtime,
        inbound_tag,
        user,
        peer_addr,
        routing_metadata,
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
