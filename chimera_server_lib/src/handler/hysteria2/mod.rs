use std::{
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

// use congestion::BrutalConfig;
use connection::process_hysteria2_connection;
use quinn::congestion::BbrConfig;

use crate::{
    config::server_config::Hysteria2ServerConfig,
    resolver::{NativeResolver, Resolver},
    util::socket::new_socket2_udp_socket,
};

mod congestion;
pub mod connection;

const MAX_QUIC_ENDPOINTS: usize = 1;

pub async fn run_hysteria2_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    config: Hysteria2ServerConfig,
    inbound_tag: String,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let quic_server_config = Arc::new(quic_server_config);

    let endpoints_len = MAX_QUIC_ENDPOINTS;
    let config = Arc::new(config);

    let mut join_handles = Vec::with_capacity(endpoints_len);

    for _ in 0..endpoints_len {
        let quic_server_config = quic_server_config.clone();
        let resolver = resolver.clone();
        let config = config.clone();
        let inbound_tag = inbound_tag.clone();

        let base_transport = build_transport_config()?;
        let mut base_server_config = quinn::ServerConfig::with_crypto(quic_server_config);
        base_server_config.transport_config(Arc::new(base_transport));

        let socket2_socket =
            new_socket2_udp_socket(bind_address.is_ipv6(), None, Some(bind_address), false)?;

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
                let tx_bps = Arc::new(AtomicU64::new(0));

                let mut transport = match build_transport_config() {
                    Ok(transport) => transport,
                    Err(err) => {
                        tracing::error!("Failed to configure hysteria2 transport: {}", err);
                        return;
                    }
                };

                // use brutal in the future
                transport.congestion_controller_factory(Arc::new(BbrConfig::default()));

                let mut server_config = base_server_config.clone();
                server_config.transport_config(Arc::new(transport));

                tokio::spawn(async move {
                    let connecting = match incoming.accept_with(Arc::new(server_config)) {
                        Ok(connecting) => connecting,
                        Err(err) => {
                            tracing::error!("Failed to accept hysteria2 connection: {}", err);
                            return;
                        }
                    };

                    let connection = match connecting.await {
                        Ok(connection) => connection,
                        Err(err) => {
                            tracing::error!("Failed to establish hysteria2 connection: {}", err);
                            return;
                        }
                    };

                    if let Err(e) = process_hysteria2_connection(
                        cloned_resolver,
                        config,
                        tx_bps,
                        connection,
                        Arc::new(inbound_tag),
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
        join_handle
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    }
    Ok(())
}

fn build_transport_config() -> std::io::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    let idle_timeout = Duration::from_secs(120)
        .try_into()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    transport
        .max_concurrent_bidi_streams(4096_u32.into())
        .max_concurrent_uni_streams(1024_u32.into())
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .max_idle_timeout(Some(idle_timeout));
    Ok(transport)
}
