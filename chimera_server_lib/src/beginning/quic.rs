use std::sync::Arc;

use tokio::{io::AsyncReadExt, task::JoinHandle};
use tracing::info;

use crate::{
    address::BindLocation,
    config::server_config::{quic::ServerQuicConfig, ServerConfig, ServerProxyConfig},
    handler::hysteria2::run_hysteria2_server,
    util::rustls_util::create_server_config,
};

pub async fn start_quic_server(config: ServerConfig) -> std::io::Result<Option<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        quic_settings,
        protocol,
        ..
    } = config;

    info!("Starting {} QUIC server at {}", &protocol, &bind_location);
    let bind_address = match bind_location {
        BindLocation::Address(a) => a.to_socket_addr()?,
    };

    let ServerQuicConfig {
        cert,
        key,
        alpn_protocols,
        client_fingerprints,
    } = quic_settings.unwrap();

    let mut cert_file = tokio::fs::File::open(&cert).await?;
    let mut cert_bytes = vec![];
    cert_file.read_to_end(&mut cert_bytes).await?;

    let mut key_file = tokio::fs::File::open(&key).await?;
    let mut key_bytes = vec![];
    key_file.read_to_end(&mut key_bytes).await?;

    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        &alpn_protocols.into_vec(),
        &client_fingerprints.into_vec(),
    ));

    match protocol {
        ServerProxyConfig::Hysteria2 { config } => {
            Ok(Some(tokio::spawn(async move {
                if let Err(err) =
                    run_hysteria2_server(bind_address, server_config, config, tag).await
                {
                    tracing::error!("hysteria2 server stopped with error: {}", err);
                }
            })))
        }
        tcp => {
            let _ = {};
            todo!()
        }
    }
}
