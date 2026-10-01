use quic::start_quic_server;
use tokio::task::JoinHandle;
use udp::start_udp_server;

use crate::{
    config::{
        Transport,
        server_config::{ServerConfig, ServerProxyConfig},
    },
    runtime::{DataPlaneRuntime, RuntimeState},
    traffic::register_identity,
};

#[allow(dead_code)]
// mKCP's demux/runtime slice is retained for the next transport integration.
mod mkcp;
mod quic;
pub(crate) mod udp;

struct StartingTasks {
    handles: Vec<JoinHandle<()>>,
}

impl StartingTasks {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            handles: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, handle: JoinHandle<()>) {
        self.handles.push(handle);
    }

    fn commit(mut self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut self.handles)
    }

    fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

impl Drop for StartingTasks {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

/// Listener tasks produced only after every required socket bind/listen step
/// for one inbound has succeeded. Dropping the value before adoption aborts
/// the listeners, so lifecycle code cannot accidentally detach a ready-but-
/// unpublished instance.
pub(crate) struct BoundInboundTasks {
    handles: Option<Vec<JoinHandle<()>>>,
}

impl BoundInboundTasks {
    fn new(handles: Vec<JoinHandle<()>>) -> Self {
        Self {
            handles: Some(handles),
        }
    }

    pub(crate) fn into_handles(mut self) -> Vec<JoinHandle<()>> {
        self.handles.take().unwrap_or_default()
    }
}

impl Drop for BoundInboundTasks {
    fn drop(&mut self) {
        if let Some(handles) = self.handles.take() {
            for handle in handles {
                handle.abort();
            }
        }
    }
}

pub(crate) async fn start_bound_servers(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<BoundInboundTasks> {
    start_server_tasks(config, runtime.data_plane())
        .await
        .map(BoundInboundTasks::new)
}

#[cfg(test)]
pub async fn start_servers(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    Ok(start_bound_servers(config, runtime).await?.into_handles())
}

async fn start_server_tasks(
    config: ServerConfig,
    runtime: DataPlaneRuntime,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    register_configured_identities(&config.protocol, &runtime);
    #[cfg(feature = "wireguard")]
    if matches!(config.protocol, ServerProxyConfig::WireGuard { .. }) {
        return crate::wireguard::start_server(config, runtime)
            .await
            .map(|handle| vec![handle]);
    }
    match crate::transport::compile_listener_plan(&config.protocol) {
        crate::transport::InboundListenerPlan::Xhttp(plan) => {
            return crate::transport::xhttp::start_xhttp_server(
                config, runtime, *plan,
            )
            .await;
        }
        #[cfg(feature = "grpc_transport")]
        crate::transport::InboundListenerPlan::Grpc(plan) => {
            return crate::transport::grpc::start_grpc_server(
                config, runtime, *plan,
            )
            .await;
        }
        crate::transport::InboundListenerPlan::Stream => {}
    }

    let mut join_handles = StartingTasks::with_capacity(3);

    match config.transport {
        Transport::Tcp => {
            match crate::transport::tcp::start_tcp_server(config.clone(), runtime)
                .await
            {
                Ok(Some(handle)) => {
                    join_handles.push(handle);
                }
                Ok(None) => (),
                Err(e) => return Err(e),
            }
        }
        Transport::TcpAndUdp => {
            match crate::transport::tcp::start_tcp_server(
                config.clone(),
                runtime.clone(),
            )
            .await
            {
                Ok(Some(handle)) => join_handles.push(handle),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
            match start_udp_server(config.clone(), runtime).await {
                Ok(Some(handle)) => join_handles.push(handle),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
        }
        Transport::Quic => match start_quic_server(config.clone(), runtime).await {
            Ok(Some(handle)) => {
                join_handles.push(handle);
            }
            Ok(None) => (),
            Err(e) => return Err(e),
        },
        Transport::Mkcp(mkcp) => {
            match mkcp::server::start_mkcp_server(config.clone(), runtime, mkcp)
                .await
            {
                Ok(Some(handle)) => join_handles.push(handle),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
        }
        // UDP listeners need runtime state for routing/outbound selection.
        Transport::Udp => match start_udp_server(config.clone(), runtime).await {
            Ok(Some(handle)) => {
                join_handles.push(handle);
            }
            Ok(None) => (),
            Err(e) => return Err(e),
        },
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            config.bind_location
        )));
    }

    Ok(join_handles.commit())
}

fn register_stats_identity(
    runtime: &DataPlaneRuntime,
    level: u32,
    identity: String,
) {
    if identity.is_empty() {
        return;
    }
    let policy = runtime.policy_user_stats(level);
    if policy.uplink || policy.downlink {
        register_identity(identity);
    }
}

fn register_configured_identities(
    protocol: &ServerProxyConfig,
    runtime: &DataPlaneRuntime,
) {
    match protocol {
        #[cfg(feature = "http")]
        ServerProxyConfig::Http {
            accounts,
            user_level,
            ..
        } => {
            for account in accounts {
                register_stats_identity(
                    runtime,
                    *user_level,
                    account.username.clone(),
                );
            }
        }
        #[cfg(feature = "mixed")]
        ServerProxyConfig::Mixed { accounts, .. } => {
            for account in accounts.snapshot() {
                register_stats_identity(runtime, 0, account.username);
            }
        }
        ServerProxyConfig::Socks {
            accounts,
            user_level,
            ..
        } => {
            for account in accounts.snapshot() {
                register_stats_identity(runtime, *user_level, account.username);
            }
        }
        #[cfg(feature = "vless")]
        ServerProxyConfig::Vless { users, .. } => {
            for user in users {
                register_stats_identity(
                    runtime,
                    user.user_level,
                    user.user_label.clone(),
                );
            }
        }
        #[cfg(feature = "vmess")]
        ServerProxyConfig::Vmess { users } => {
            for user in users {
                register_stats_identity(
                    runtime,
                    user.user_level,
                    user.user_label.clone(),
                );
            }
        }
        #[cfg(feature = "trojan")]
        ServerProxyConfig::Trojan { users, .. } => {
            for user in users {
                let identity = user
                    .email
                    .clone()
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| user.password.clone());
                register_stats_identity(runtime, user.user_level, identity);
            }
        }
        #[cfg(feature = "shadowsocks")]
        ServerProxyConfig::Shadowsocks { users, .. } => {
            for user in users {
                register_stats_identity(
                    runtime,
                    user.user_level,
                    user.email.clone(),
                );
            }
        }
        #[cfg(feature = "hysteria")]
        ServerProxyConfig::Hysteria2 { config } => {
            for user in &config.clients {
                let identity = user
                    .email
                    .clone()
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| user.password.clone());
                register_stats_identity(runtime, user.level, identity);
            }
        }
        #[cfg(feature = "tuic")]
        ServerProxyConfig::TuicV5 { config } => {
            register_stats_identity(runtime, 0, config.uuid.clone());
        }
        #[cfg(feature = "wireguard")]
        ServerProxyConfig::WireGuard { config } => {
            for peer in &config.peers {
                if !peer.email.is_empty() {
                    register_stats_identity(runtime, peer.level, peer.email.clone());
                }
            }
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            register_configured_identities(inner, runtime);
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            register_configured_identities(config.inner.as_ref(), runtime);
        }
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            register_configured_identities(config.inner.as_ref(), runtime);
        }
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            register_configured_identities(config.inner.as_ref(), runtime);
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(config) => {
            register_configured_identities(config.inner.as_ref(), runtime);
        }
        _ => {}
    }
}

pub async fn start_tcp_server(
    config: ServerConfig,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let runtime = RuntimeState::new(vec![config.clone()], Vec::new());
    crate::transport::tcp::start_tcp_server(config, runtime.data_plane()).await
}

#[cfg(test)]
mod tests;
