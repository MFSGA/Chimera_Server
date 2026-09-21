//! WireGuard protocol state used by the server inbound.
//!
//! The first runtime slice keeps WireGuard protocol state and the Linux
//! system-TUN shuttle together. Xray routing/outbound dispatch remains a
//! separate follow-up boundary; the current backend relies on host IP routing
//! after decrypted packets are written to the TUN device.

#![cfg(feature = "wireguard")]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use tokio::sync::Mutex;
use tokio::{
    net::UdpSocket,
    task::JoinHandle,
    time::{Duration, interval},
};

use crate::{
    address::BindLocation,
    config::server_config::{
        ServerConfig, ServerProxyConfig, WireGuardAllowedIp, WireGuardServerConfig,
    },
    runtime::DataPlaneRuntime,
};

const PACKET_BUFFER_SIZE: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiveResult {
    Response(Vec<u8>),
    IpPacket { packet: Vec<u8>, source: IpAddr },
    Done,
    Rejected,
}

pub(crate) struct PeerRuntime {
    pub(crate) level: u32,
    pub(crate) email: String,
    allowed_ips: Vec<WireGuardAllowedIp>,
    endpoint: Mutex<Option<SocketAddr>>,
    tunnel: Mutex<Tunn>,
}

impl std::fmt::Debug for PeerRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerRuntime")
            .field("public_key", &"[redacted]")
            .field("level", &self.level)
            .field("email", &self.email)
            .field("allowed_ips", &self.allowed_ips)
            .finish()
    }
}

pub(crate) fn build_peer_runtimes(
    config: &WireGuardServerConfig,
) -> Result<Vec<Arc<PeerRuntime>>, String> {
    let private_key = StaticSecret::from(config.secret_key);
    let server_public_key = PublicKey::from(&private_key);
    config
        .peers
        .iter()
        .map(|peer| {
            if peer.public_key == server_public_key.to_bytes() {
                return Err(
                    "wireguard peer public key must differ from server key".into()
                );
            }
            Ok(Arc::new(PeerRuntime {
                level: peer.level,
                email: peer.email.clone(),
                allowed_ips: peer.allowed_ips.clone(),
                endpoint: Mutex::new(None),
                tunnel: Mutex::new(Tunn::new(
                    private_key.clone(),
                    PublicKey::from(peer.public_key),
                    peer.pre_shared_key,
                    (peer.keep_alive != 0).then_some(peer.keep_alive),
                    0,
                    None,
                )),
            }))
        })
        .collect()
}

impl PeerRuntime {
    pub(crate) async fn receive(
        &self,
        source: IpAddr,
        datagram: &[u8],
    ) -> ReceiveResult {
        let mut output = vec![0u8; PACKET_BUFFER_SIZE];
        let mut tunnel = self.tunnel.lock().await;
        match tunnel.decapsulate(Some(source), datagram, &mut output) {
            TunnResult::WriteToNetwork(packet) => {
                ReceiveResult::Response(packet.to_vec())
            }
            TunnResult::WriteToTunnelV4(packet, packet_source) => {
                if self.is_allowed(IpAddr::V4(packet_source)) {
                    ReceiveResult::IpPacket {
                        packet: packet.to_vec(),
                        source: IpAddr::V4(packet_source),
                    }
                } else {
                    ReceiveResult::Rejected
                }
            }
            TunnResult::WriteToTunnelV6(packet, packet_source) => {
                if self.is_allowed(IpAddr::V6(packet_source)) {
                    ReceiveResult::IpPacket {
                        packet: packet.to_vec(),
                        source: IpAddr::V6(packet_source),
                    }
                } else {
                    ReceiveResult::Rejected
                }
            }
            TunnResult::Done => ReceiveResult::Done,
            TunnResult::Err(_) => ReceiveResult::Rejected,
        }
    }

    pub(crate) async fn set_endpoint(&self, endpoint: SocketAddr) {
        *self.endpoint.lock().await = Some(endpoint);
    }

    pub(crate) async fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.lock().await
    }

    pub(crate) async fn encapsulate(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let mut output = vec![0u8; packet.len() + 148];
        let mut tunnel = self.tunnel.lock().await;
        match tunnel.encapsulate(packet, &mut output) {
            TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
            TunnResult::Done
            | TunnResult::Err(_)
            | TunnResult::WriteToTunnelV4(_, _)
            | TunnResult::WriteToTunnelV6(_, _) => None,
        }
    }

    pub(crate) async fn update_timers(&self) -> Option<Vec<u8>> {
        let mut output = vec![0u8; PACKET_BUFFER_SIZE];
        let mut tunnel = self.tunnel.lock().await;
        match tunnel.update_timers(&mut output) {
            TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
            TunnResult::Done
            | TunnResult::Err(_)
            | TunnResult::WriteToTunnelV4(_, _)
            | TunnResult::WriteToTunnelV6(_, _) => None,
        }
    }

    fn is_allowed(&self, source: IpAddr) -> bool {
        self.allows_ip(source)
    }

    pub(crate) fn allows_ip(&self, address: IpAddr) -> bool {
        self.allowed_ips.is_empty()
            || self
                .allowed_ips
                .iter()
                .any(|allowed| cidr_contains(allowed, address))
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn start_server(
    config: ServerConfig,
    runtime: DataPlaneRuntime,
) -> std::io::Result<JoinHandle<()>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        tcp_socket_policy,
        ..
    } = config;
    let ServerProxyConfig::WireGuard { config } = protocol else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wireguard listener received a non-wireguard protocol",
        ));
    };
    if config.no_kernel_tun {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "wireguard noKernelTun requires the userspace IP stack and is not implemented yet",
        ));
    }
    let address = config
        .addresses
        .iter()
        .find(|address| address.address.is_ipv4())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "wireguard requires at least one IPv4 address for the system TUN backend",
            )
        })?;
    let IpAddr::V4(address) = address.address else {
        unreachable!("selected WireGuard address must be IPv4")
    };
    let tun_name = tun_name_for_tag(&tag);
    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&tun_name)
        .address(address)
        .netmask(netmask(config_address_prefix(&config, address)))
        .mtu(config.mtu)
        .layer(tun::Layer::L3)
        .up();
    tun_config.platform_config(|platform| {
        platform.ensure_root_privileges(true);
    });
    let device = tun::create_as_async(&tun_config).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("failed to create WireGuard TUN device {tun_name}: {error}"),
        )
    })?;
    let bind_addr = match bind_location {
        BindLocation::Address(location) => location.to_socket_addr()?,
    };
    let socket = crate::beginning::udp::create_udp_listener(
        bind_addr,
        tcp_socket_policy.as_ref(),
        false,
    )?;
    let peers = build_peer_runtimes(&config).map_err(std::io::Error::other)?;
    tracing::info!(
        inbound_tag = %tag,
        bind = %bind_addr,
        tun = %tun_name,
        peers = peers.len(),
        "starting WireGuard inbound"
    );
    Ok(tokio::spawn(run_server(socket, device, peers, runtime)))
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn start_server(
    _config: ServerConfig,
    _runtime: DataPlaneRuntime,
) -> std::io::Result<JoinHandle<()>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "WireGuard system TUN inbound is currently implemented only on Linux",
    ))
}

#[cfg(target_os = "linux")]
async fn run_server(
    socket: Arc<UdpSocket>,
    device: tun::AsyncDevice,
    peers: Vec<Arc<PeerRuntime>>,
    _runtime: DataPlaneRuntime,
) {
    let mut udp_buffer = vec![0u8; PACKET_BUFFER_SIZE];
    let mut tun_buffer = vec![0u8; PACKET_BUFFER_SIZE];
    let mut timer = interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            result = socket.recv_from(&mut udp_buffer) => {
                let Ok((length, source)) = result else { break };
                process_udp_datagram(&socket, &device, source, &udp_buffer[..length], &peers).await;
            }
            result = device.recv(&mut tun_buffer) => {
                let Ok(length) = result else { break };
                process_tun_packet(&socket, &tun_buffer[..length], &peers).await;
            }
            _ = timer.tick() => {
                for peer in &peers {
                    if let (Some(endpoint), Some(packet)) =
                        (peer.endpoint().await, peer.update_timers().await)
                    {
                        let _ = socket.send_to(&packet, endpoint).await;
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn process_udp_datagram(
    socket: &UdpSocket,
    device: &tun::AsyncDevice,
    source: SocketAddr,
    datagram: &[u8],
    peers: &[Arc<PeerRuntime>],
) {
    for peer in peers {
        let mut input = Some(datagram);
        while let Some(packet) = input.take() {
            match peer.receive(source.ip(), packet).await {
                ReceiveResult::Response(response) => {
                    peer.set_endpoint(source).await;
                    if socket.send_to(&response, source).await.is_err() {
                        return;
                    }
                    input = Some(&[]);
                }
                ReceiveResult::IpPacket { packet, .. } => {
                    peer.set_endpoint(source).await;
                    let _ = device.send(&packet).await;
                    return;
                }
                ReceiveResult::Done => return,
                ReceiveResult::Rejected => break,
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn process_tun_packet(
    socket: &UdpSocket,
    packet: &[u8],
    peers: &[Arc<PeerRuntime>],
) {
    let Some(destination) = Tunn::dst_address(packet) else {
        return;
    };
    let Some(peer) = peers.iter().find(|peer| peer.allows_ip(destination)) else {
        return;
    };
    let Some(endpoint) = peer.endpoint().await else {
        return;
    };
    if let Some(encrypted) = peer.encapsulate(packet).await {
        let _ = socket.send_to(&encrypted, endpoint).await;
    }
}

#[cfg(target_os = "linux")]
fn config_address_prefix(config: &WireGuardServerConfig, address: Ipv4Addr) -> u8 {
    config
        .addresses
        .iter()
        .find(|candidate| candidate.address == IpAddr::V4(address))
        .map(|candidate| candidate.prefix_len)
        .unwrap_or(32)
}

#[cfg(target_os = "linux")]
fn netmask(prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(mask)
}

#[cfg(target_os = "linux")]
fn tun_name_for_tag(tag: &str) -> String {
    let suffix: String = tag
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
        .take(11)
        .collect();
    if suffix.is_empty() {
        "cwg0".into()
    } else {
        format!("cwg_{suffix}")
    }
}

fn cidr_contains(cidr: &WireGuardAllowedIp, address: IpAddr) -> bool {
    match (cidr.address, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let prefix = cidr.prefix_len;
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(network) & mask) == (u32::from(address) & mask)
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let prefix = cidr.prefix_len;
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(network) & mask) == (u128::from(address) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::server_config::{
        WireGuardAddress, WireGuardDomainStrategy, WireGuardPeerConfig,
    };

    #[tokio::test]
    async fn peer_accepts_handshake_and_allowed_ip() {
        let server_secret = [7u8; 32];
        let client_secret = [9u8; 32];
        let client_public =
            PublicKey::from(&StaticSecret::from(client_secret)).to_bytes();
        let server_public = PublicKey::from(&StaticSecret::from(server_secret));
        let config = WireGuardServerConfig {
            secret_key: server_secret,
            addresses: vec![WireGuardAddress {
                address: "10.0.0.1".parse().unwrap(),
                prefix_len: 32,
            }],
            peers: vec![WireGuardPeerConfig {
                public_key: client_public,
                pre_shared_key: None,
                endpoint: None,
                keep_alive: 0,
                allowed_ips: vec![WireGuardAllowedIp {
                    address: "10.0.0.2".parse().unwrap(),
                    prefix_len: 32,
                }],
                level: 0,
                email: "client".into(),
            }],
            mtu: 1420,
            reserved: [0; 3],
            domain_strategy: WireGuardDomainStrategy::ForceIp,
            dns: Vec::new(),
            no_kernel_tun: true,
        };
        let peers = build_peer_runtimes(&config).unwrap();
        let mut client = Tunn::new(
            StaticSecret::from(client_secret),
            server_public,
            None,
            None,
            1,
            None,
        );
        let mut client_output = vec![0u8; PACKET_BUFFER_SIZE];
        let TunnResult::WriteToNetwork(handshake) =
            client.encapsulate(&[], &mut client_output)
        else {
            panic!("client must start a handshake");
        };
        let response = peers[0]
            .receive("192.0.2.10".parse().unwrap(), handshake)
            .await;
        let ReceiveResult::Response(response) = response else {
            panic!("server must answer the handshake");
        };
        let mut server_output = vec![0u8; PACKET_BUFFER_SIZE];
        let TunnResult::WriteToNetwork(_) =
            client.decapsulate(None, &response, &mut server_output)
        else {
            panic!("client must accept the handshake response");
        };

        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let TunnResult::WriteToNetwork(encrypted) =
            client.encapsulate(&packet, &mut client_output)
        else {
            panic!("client must encrypt the IP packet");
        };
        assert!(matches!(
            peers[0]
                .receive("192.0.2.10".parse().unwrap(), encrypted)
                .await,
            ReceiveResult::IpPacket { .. }
        ));
    }
}
