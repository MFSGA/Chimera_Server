use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};

// use congestion::BrutalConfig;
use connection::process_hysteria2_connection;
use quinn::congestion::BbrConfig;

use crate::{
    config::server_config::Hysteria2ServerConfig,
    resolver::{NativeResolver, Resolver},
    runtime::RuntimeState,
    util::socket::new_socket2_udp_socket,
};

mod congestion;
pub mod connection;

const MAX_QUIC_ENDPOINTS: usize = 1;
const SHOES_MAX_INCOMING_UNI_STREAMS: u32 = 1024;
const XRAY_MAX_INCOMING_UNI_STREAMS: u32 = 100;

pub async fn run_hysteria2_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    config: Hysteria2ServerConfig,
    inbound_tag: String,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig =
        server_config.try_into().map_err(std::io::Error::other)?;

    let quic_server_config = Arc::new(quic_server_config);

    let endpoints_len = MAX_QUIC_ENDPOINTS;
    let config = Arc::new(config);

    let mut join_handles = Vec::with_capacity(endpoints_len);

    for _ in 0..endpoints_len {
        let quic_server_config = quic_server_config.clone();
        let resolver = resolver.clone();
        let config = config.clone();
        let inbound_tag = inbound_tag.clone();
        let runtime = runtime.clone();

        let base_transport = build_transport_config(config.as_ref())?;
        let mut base_server_config =
            quinn::ServerConfig::with_crypto(quic_server_config);
        // Match Xray's Hysteria2 server behavior: do not migrate an established
        // QUIC connection to a different network path.
        base_server_config.migration(false);
        base_server_config.transport_config(Arc::new(base_transport));

        let socket2_socket = new_socket2_udp_socket(
            bind_address.is_ipv6(),
            None,
            Some(bind_address),
            false,
        )?;

        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(base_server_config.clone()),
            socket2_socket.into(),
            Arc::new(quinn::TokioRuntime),
        )?;

        let join_handle = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let cloned_resolver = resolver.clone();
                let config = config.clone();
                let inbound_tag = inbound_tag.clone();
                let runtime = runtime.clone();
                let tx_bps = Arc::new(AtomicU64::new(0));

                let mut transport = match build_transport_config(config.as_ref()) {
                    Ok(transport) => transport,
                    Err(err) => {
                        tracing::error!(
                            "Failed to configure hysteria2 transport: {}",
                            err
                        );
                        return;
                    }
                };

                // use brutal in the future
                transport
                    .congestion_controller_factory(Arc::new(BbrConfig::default()));

                let mut server_config = base_server_config.clone();
                server_config.transport_config(Arc::new(transport));

                tokio::spawn(async move {
                    let connecting =
                        match incoming.accept_with(Arc::new(server_config)) {
                            Ok(connecting) => connecting,
                            Err(err) => {
                                tracing::error!(
                                    "Failed to accept hysteria2 connection: {}",
                                    err
                                );
                                return;
                            }
                        };

                    let connection = match connecting.await {
                        Ok(connection) => connection,
                        Err(err) => {
                            tracing::error!(
                                "Failed to establish hysteria2 connection: {}",
                                err
                            );
                            return;
                        }
                    };

                    if let Err(e) = process_hysteria2_connection(
                        cloned_resolver,
                        config,
                        tx_bps,
                        connection,
                        Arc::new(inbound_tag),
                        runtime,
                    )
                    .await
                    {
                        tracing::error!("Connection ended with error: {}", e);
                    }
                });
            }
        });
        join_handles.push(join_handle);
    }

    for join_handle in join_handles {
        join_handle.await.map_err(std::io::Error::other)?;
    }
    Ok(())
}

fn build_transport_config(
    config: &Hysteria2ServerConfig,
) -> std::io::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    let idle_timeout =
        Duration::from_secs(config.xray_max_idle_timeout_secs.unwrap_or(120))
            .try_into()
            .map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
            })?;
    let max_bidi_streams =
        quinn::VarInt::from_u64(config.xray_max_incoming_streams.unwrap_or(4096))
            .map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
            })?;
    let max_uni_streams = configured_max_incoming_uni_streams(
        config.xray_max_incoming_streams.is_some(),
    );
    transport
        .max_concurrent_bidi_streams(max_bidi_streams)
        .max_concurrent_uni_streams(max_uni_streams)
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .max_idle_timeout(Some(idle_timeout));
    Ok(transport)
}

fn configured_max_incoming_uni_streams(xray_compat: bool) -> quinn::VarInt {
    if xray_compat {
        XRAY_MAX_INCOMING_UNI_STREAMS.into()
    } else {
        SHOES_MAX_INCOMING_UNI_STREAMS.into()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SHOES_MAX_INCOMING_UNI_STREAMS, XRAY_MAX_INCOMING_UNI_STREAMS,
        configured_max_incoming_uni_streams,
    };

    #[test]
    fn max_incoming_uni_streams_follow_protocol_mode() {
        assert_eq!(
            configured_max_incoming_uni_streams(false).into_inner(),
            u64::from(SHOES_MAX_INCOMING_UNI_STREAMS)
        );
        assert_eq!(
            configured_max_incoming_uni_streams(true).into_inner(),
            u64::from(XRAY_MAX_INCOMING_UNI_STREAMS)
        );
    }
}
