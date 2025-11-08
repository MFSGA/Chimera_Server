use std::{net::SocketAddr, sync::Arc, time::Duration};

use connection::process_hysteria2_connection;

use crate::{
    config::server_config::Hysteria2Client,
    resolver::{NativeResolver, Resolver},
    util::socket::new_socket2_udp_socket,
};

pub mod connection;


const MAX_QUIC_ENDPOINTS: usize = 1;

pub async fn run_hysteria2_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    clients: Arc<Vec<Hysteria2Client>>,
    
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let quic_server_config = Arc::new(quic_server_config);

    let endpoints_len = MAX_QUIC_ENDPOINTS;

    let mut join_handles = vec![];

    for _ in 0..endpoints_len {
        let quic_server_config = quic_server_config.clone();
        let resolver = resolver.clone();
        let clients = clients.clone();
        let join_handle = tokio::spawn(async move {
            let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config);

            Arc::get_mut(&mut server_config.transport)
                .unwrap()
                .max_concurrent_bidi_streams(4096_u32.into())
                
                .max_concurrent_uni_streams(1024_u32.into())
                .keep_alive_interval(Some(Duration::from_secs(15)))
                .max_idle_timeout(Some(Duration::from_secs(120).try_into().unwrap()));

            let socket2_socket =
                new_socket2_udp_socket(bind_address.is_ipv6(), None, Some(bind_address), false)
                    .unwrap();

            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                socket2_socket.into(),
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap();

            while let Some(conn) = endpoint.accept().await {
                
                let cloned_resolver = resolver.clone();
                let auth_clients = clients.clone();

                tokio::spawn(async move {
                    if let Err(e) = process_hysteria2_connection(
                        
                        cloned_resolver,
                        auth_clients,
                        conn,
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
        join_handle.await?;
    }
    Ok(())
}
