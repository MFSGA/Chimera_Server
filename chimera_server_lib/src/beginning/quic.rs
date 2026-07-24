#[cfg(any(feature = "hysteria", feature = "tuic"))]
use std::sync::Arc;

#[cfg(any(feature = "hysteria", feature = "tuic"))]
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
#[cfg(any(feature = "hysteria", feature = "tuic"))]
use tracing::info;

#[cfg(feature = "hysteria")]
use crate::handler::hysteria2::run_hysteria2_server;
#[cfg(feature = "tuic")]
use crate::handler::tuic::run_tuic_server;
#[cfg(any(feature = "hysteria", feature = "tuic"))]
use crate::{
    address::BindLocation,
    config::server_config::{
        ServerConfig, ServerProxyConfig, quic::ServerQuicConfig,
    },
    runtime::RuntimeState,
    util::rustls_util::create_server_config,
};
#[cfg(not(any(feature = "hysteria", feature = "tuic")))]
use crate::{config::server_config::ServerConfig, runtime::RuntimeState};

pub async fn start_quic_server(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Option<JoinHandle<()>>> {
    #[cfg(any(feature = "hysteria", feature = "tuic"))]
    {
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
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => {
                Ok(Some(tokio::spawn(async move {
                    if let Err(err) = run_hysteria2_server(
                        bind_address,
                        server_config,
                        config,
                        tag,
                        runtime,
                    )
                    .await
                    {
                        tracing::error!(
                            "hysteria2 server stopped with error: {}",
                            err
                        );
                    }
                })))
            }
            #[cfg(feature = "tuic")]
            ServerProxyConfig::TuicV5 { config } => {
                Ok(Some(tokio::spawn(async move {
                    if let Err(err) = run_tuic_server(
                        bind_address,
                        server_config,
                        config,
                        tag,
                        runtime,
                    )
                    .await
                    {
                        tracing::error!("tuic server stopped with error: {}", err);
                    }
                })))
            }

            _other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsupported QUIC server protocol",
            )),
        }
    }

    #[cfg(not(any(feature = "hysteria", feature = "tuic")))]
    {
        let _ = (config, runtime);
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "QUIC server support is disabled in this build",
        ))
    }
}
