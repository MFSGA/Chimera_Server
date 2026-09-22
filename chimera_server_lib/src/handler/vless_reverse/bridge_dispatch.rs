use std::net::{Ipv4Addr, SocketAddr};

use async_trait::async_trait;

use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    outbound::{InboundRoutingMetadata, connect_tcp_outbound_with_routing_metadata},
    runtime::DataPlaneRuntime,
};

use super::bridge_worker::BridgeTcpDispatcher;

#[async_trait]
impl BridgeTcpDispatcher for DataPlaneRuntime {
    async fn open_tcp(
        &self,
        reverse_tag: &str,
        target: NetLocation,
        source: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let source =
            source.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let metadata = InboundRoutingMetadata {
            local_addr: local,
            inbound_protocol: Some("vless-reverse".to_string()),
            ..InboundRoutingMetadata::default()
        };
        let resolver = self.resolver();
        let connection = connect_tcp_outbound_with_routing_metadata(
            &resolver,
            &target,
            self,
            reverse_tag,
            "",
            source,
            metadata,
        )
        .await?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("routing rejected VLESS Reverse Bridge target {target}"),
            )
        })?;

        Ok(connection.stream)
    }
}
