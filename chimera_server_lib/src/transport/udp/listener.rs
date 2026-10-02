#[cfg(feature = "shadowsocks")]
use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::{error, info};

#[cfg(feature = "shadowsocks")]
use crate::{
    address::BindLocation, config::server_config::TcpSocketPolicy,
    handler::shadowsocks::ShadowsocksUdpCodec,
};
use crate::{
    config::server_config::{ServerConfig, ServerProxyConfig},
    resolver::resolve_single_address,
    runtime::DataPlaneRuntime,
};

use super::{bind_location_to_socket_addr, create_udp_listener};

use crate::session::udp::dokodemo::run_dokodemo_udp_server;
#[cfg(feature = "shadowsocks")]
use crate::session::udp::shadowsocks::run_shadowsocks_udp_server;

pub(crate) async fn start_udp_server(
    config: ServerConfig,
    runtime: DataPlaneRuntime,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        tcp_socket_policy,
        ..
    } = config;

    let dokodemo_config = match protocol {
        #[cfg(feature = "shadowsocks")]
        ServerProxyConfig::Shadowsocks { users, identity } => {
            return start_shadowsocks_udp_server(
                bind_location,
                tag,
                users,
                identity,
                tcp_socket_policy,
                runtime.clone(),
            )
            .await;
        }
        ServerProxyConfig::DokodemoDoor { config } => config,
        #[cfg(feature = "wireguard")]
        ServerProxyConfig::WireGuard { .. } => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "wireguard inbound protocol engine is not connected to the UDP listener yet",
            ));
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "transport=udp supports dokodemo-door and shadowsocks in this stage (got {other})"
                ),
            ));
        }
    };

    #[cfg(not(target_os = "linux"))]
    if dokodemo_config.follow_redirect {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dokodemo-door UDP followRedirect is supported only on Linux",
        ));
    }

    let bind_addr = bind_location_to_socket_addr(&bind_location)?;
    let target_addr = if dokodemo_config.follow_redirect {
        None
    } else {
        let resolver = runtime.resolver();
        Some(resolve_single_address(&resolver, &dokodemo_config.target).await?)
    };

    if dokodemo_config.follow_redirect {
        info!(
            "Starting DokodemoDoor UDP server at {} with followRedirect",
            bind_location
        );
    } else {
        info!(
            "Starting DokodemoDoor UDP server at {} forwarding to {}",
            bind_location, dokodemo_config.target
        );
    }

    let socket = create_udp_listener(
        bind_addr,
        tcp_socket_policy.as_ref(),
        dokodemo_config.follow_redirect,
    )?;
    Ok(Some(tokio::spawn(async move {
        if let Err(err) = run_dokodemo_udp_server(
            socket,
            dokodemo_config,
            target_addr,
            tag,
            runtime,
        )
        .await
        {
            error!("UDP server stopped with error: {}", err);
        }
    })))
}

#[cfg(feature = "shadowsocks")]
async fn start_shadowsocks_udp_server(
    bind_location: BindLocation,
    inbound_tag: String,
    users: Vec<crate::config::server_config::ShadowsocksUser>,
    identity: Option<crate::config::server_config::ShadowsocksServerIdentity>,
    socket_policy: Option<TcpSocketPolicy>,
    runtime: DataPlaneRuntime,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let bind_addr = bind_location_to_socket_addr(&bind_location)?;
    let socket = create_udp_listener(bind_addr, socket_policy.as_ref(), false)?;
    let codec = Arc::new(ShadowsocksUdpCodec::new(users, identity)?);
    info!("Starting Shadowsocks UDP server at {}", bind_location);

    Ok(Some(tokio::spawn(run_shadowsocks_udp_server(
        socket,
        codec,
        inbound_tag,
        runtime,
    ))))
}
