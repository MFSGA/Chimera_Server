use std::{net::SocketAddr, sync::Arc};

use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
    outbound::{InboundRoutingMetadata, connect_tcp_outbound_with_routing_metadata},
    resolver::{Resolver, resolve_single_address},
    runtime::DataPlaneRuntime,
    util::socket::new_tcp_socket,
};

use tracing::error;

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
