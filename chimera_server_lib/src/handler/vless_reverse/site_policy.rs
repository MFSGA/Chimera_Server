use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::address::NetLocation;

const MAX_PREFIX_MAPS: usize = 128;
const MAX_ALLOW_RULES: usize = 256;
const MAX_PREFIXES_PER_RULE: usize = 128;
const MAX_PORT_RANGES_PER_RULE: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SiteToSiteConfig {
    #[serde(default)]
    pub(crate) prefix_maps: Vec<SitePrefixMapConfig>,
    #[serde(default)]
    pub(crate) allow: Vec<SiteTargetAllowConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SitePrefixMapConfig {
    pub(crate) from: String,
    pub(crate) to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SiteTargetAllowConfig {
    #[serde(default)]
    pub(crate) network: Vec<String>,
    #[serde(default)]
    pub(crate) ip: Vec<String>,
    #[serde(default)]
    pub(crate) ports: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SiteToSitePolicy {
    prefix_maps: Vec<PrefixMap>,
    allow: Vec<TargetAllowRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrefixMap {
    from: IpPrefix,
    to: IpPrefix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetAllowRule {
    networks: Vec<Network>,
    ip: Vec<IpPrefix>,
    ports: Vec<PortRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    first: u16,
    last: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpPrefix {
    network: IpAddr,
    bits: u8,
}

impl SiteToSitePolicy {
    pub(crate) fn compile(config: &SiteToSiteConfig) -> Result<Self, String> {
        if config.prefix_maps.is_empty() {
            return Err("siteToSite.prefixMaps must not be empty".into());
        }
        if config.prefix_maps.len() > MAX_PREFIX_MAPS {
            return Err(format!(
                "siteToSite.prefixMaps exceeds the limit of {MAX_PREFIX_MAPS}"
            ));
        }
        if config.allow.is_empty() {
            return Err(
                "siteToSite.allow must not be empty; unmatched targets are denied"
                    .into(),
            );
        }
        if config.allow.len() > MAX_ALLOW_RULES {
            return Err(format!(
                "siteToSite.allow exceeds the limit of {MAX_ALLOW_RULES}"
            ));
        }

        let mut prefix_maps = Vec::with_capacity(config.prefix_maps.len());
        for (index, mapping) in config.prefix_maps.iter().enumerate() {
            let from = IpPrefix::parse(&mapping.from).map_err(|error| {
                format!("siteToSite.prefixMaps[{index}].from {error}")
            })?;
            let to = IpPrefix::parse(&mapping.to).map_err(|error| {
                format!("siteToSite.prefixMaps[{index}].to {error}")
            })?;
            if from.width() != to.width() {
                return Err(format!(
                    "siteToSite.prefixMaps[{index}] must use the same address family"
                ));
            }
            if from.bits != to.bits {
                return Err(format!(
                    "siteToSite.prefixMaps[{index}] must use equal prefix lengths"
                ));
            }
            if prefix_maps.iter().any(|existing: &PrefixMap| {
                from.overlaps(existing.from) || to.overlaps(existing.to)
            }) {
                return Err(format!(
                    "siteToSite.prefixMaps[{index}] overlaps another mapping"
                ));
            }
            prefix_maps.push(PrefixMap { from, to });
        }

        let mut allow = Vec::with_capacity(config.allow.len());
        for (index, rule) in config.allow.iter().enumerate() {
            if rule.network.is_empty() {
                return Err(format!(
                    "siteToSite.allow[{index}].network must include tcp and/or udp"
                ));
            }
            if rule.ip.is_empty() || rule.ip.len() > MAX_PREFIXES_PER_RULE {
                return Err(format!(
                    "siteToSite.allow[{index}].ip must contain 1..={MAX_PREFIXES_PER_RULE} prefixes"
                ));
            }
            if rule.ports.is_empty() || rule.ports.len() > MAX_PORT_RANGES_PER_RULE {
                return Err(format!(
                    "siteToSite.allow[{index}].ports must contain 1..={MAX_PORT_RANGES_PER_RULE} port ranges"
                ));
            }

            let mut networks = Vec::with_capacity(rule.network.len());
            for network in &rule.network {
                let network = Network::parse(network).ok_or_else(|| {
                    format!(
                        "siteToSite.allow[{index}].network contains an unsupported protocol"
                    )
                })?;
                if !networks.contains(&network) {
                    networks.push(network);
                }
            }

            let ip = rule
                .ip
                .iter()
                .map(|prefix| {
                    IpPrefix::parse(prefix).map_err(|error| {
                        format!("siteToSite.allow[{index}].ip {error}")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let ports = rule
                .ports
                .iter()
                .map(|port| {
                    PortRange::parse(port).map_err(|error| {
                        format!("siteToSite.allow[{index}].ports {error}")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            allow.push(TargetAllowRule {
                networks,
                ip,
                ports,
            });
        }

        Ok(Self { prefix_maps, allow })
    }

    pub(crate) fn map_tcp_target(
        &self,
        target: &NetLocation,
    ) -> std::io::Result<NetLocation> {
        self.map_target(Network::Tcp, target)
    }

    pub(crate) fn map_udp_target(
        &self,
        target: &NetLocation,
    ) -> std::io::Result<NetLocation> {
        self.map_target(Network::Udp, target)
    }

    pub(crate) fn map_response_source(
        &self,
        source: SocketAddr,
    ) -> std::io::Result<SocketAddr> {
        let mapping = self
            .prefix_maps
            .iter()
            .find(|mapping| mapping.to.contains(source.ip()))
            .ok_or_else(|| {
                denied("response source is outside mapped site prefixes")
            })?;
        Ok(SocketAddr::new(
            mapping.from.map(source.ip()),
            source.port(),
        ))
    }

    fn map_target(
        &self,
        network: Network,
        target: &NetLocation,
    ) -> std::io::Result<NetLocation> {
        let address = target
            .to_socket_addr_nonblocking()
            .map(|address| address.ip())
            .ok_or_else(|| {
                denied("hostname targets are not allowed by siteToSite")
            })?;
        let mapping = self
            .prefix_maps
            .iter()
            .find(|mapping| mapping.from.contains(address))
            .ok_or_else(|| {
                denied("target is outside configured overlay prefixes")
            })?;
        let mapped = mapping.to.map(address);
        let port = target.port();
        if !self.allow.iter().any(|rule| {
            rule.networks.contains(&network)
                && rule.ip.iter().any(|prefix| prefix.contains(mapped))
                && rule.ports.iter().any(|range| range.contains(port))
        }) {
            return Err(denied("mapped target is not allowed by siteToSite"));
        }
        Ok(NetLocation::from_ip_addr(mapped, port))
    }
}

impl Network {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

impl PortRange {
    fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        let (first, last) = match value.split_once('-') {
            Some((first, last)) => (parse_port(first)?, parse_port(last)?),
            None => {
                let port = parse_port(value)?;
                (port, port)
            }
        };
        if first == 0 || last == 0 || first > last {
            return Err("must be a nonzero port or ascending port range".into());
        }
        Ok(Self { first, last })
    }

    fn contains(self, port: u16) -> bool {
        (self.first..=self.last).contains(&port)
    }
}

fn parse_port(value: &str) -> Result<u16, String> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|_| "contains an invalid port".to_string())
}

impl IpPrefix {
    fn parse(value: &str) -> Result<Self, String> {
        let (address, bits) = value
            .trim()
            .split_once('/')
            .ok_or_else(|| "must be a CIDR prefix".to_string())?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| "must contain a valid IP address".to_string())?;
        let width = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let bits = bits
            .parse::<u8>()
            .map_err(|_| "has an invalid prefix length".to_string())?;
        if bits > width {
            return Err("has an invalid prefix length".into());
        }
        Ok(Self {
            network: mask_address(address, bits),
            bits,
        })
    }

    fn width(self) -> u8 {
        match self.network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                mask_v4(u32::from(address), self.bits) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                mask_v6(u128::from(address), self.bits) == u128::from(network)
            }
            _ => false,
        }
    }

    fn overlaps(self, other: Self) -> bool {
        self.width() == other.width()
            && if self.bits <= other.bits {
                self.contains(other.network)
            } else {
                other.contains(self.network)
            }
    }

    fn map(self, address: IpAddr) -> IpAddr {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let network = u32::from(network);
                let address = u32::from(address);
                let mask = v4_mask(self.bits);
                IpAddr::V4(Ipv4Addr::from((network & mask) | (address & !mask)))
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let network = u128::from(network);
                let address = u128::from(address);
                let mask = v6_mask(self.bits);
                IpAddr::V6(Ipv6Addr::from((network & mask) | (address & !mask)))
            }
            _ => address,
        }
    }
}

fn mask_address(address: IpAddr, bits: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & v4_mask(bits)))
        }
        IpAddr::V6(address) => {
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & v6_mask(bits)))
        }
    }
}

fn v4_mask(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    }
}

fn v6_mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    }
}

fn mask_v4(address: u32, bits: u8) -> u32 {
    address & v4_mask(bits)
}

fn mask_v6(address: u128, bits: u8) -> u128 {
    address & v6_mask(bits)
}

fn denied(reason: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(from: &str, to: &str) -> SiteToSitePolicy {
        SiteToSitePolicy::compile(&SiteToSiteConfig {
            prefix_maps: vec![SitePrefixMapConfig {
                from: from.to_string(),
                to: to.to_string(),
            }],
            allow: vec![SiteTargetAllowConfig {
                network: vec!["tcp".to_string(), "udp".to_string()],
                ip: vec![to.to_string()],
                ports: vec![
                    "22".to_string(),
                    "53".to_string(),
                    "80-443".to_string(),
                ],
            }],
        })
        .expect("compile test policy")
    }

    #[test]
    fn prefix_map_preserves_host_bits_and_port_for_ipv4_and_ipv6() {
        let ipv4 = policy("10.200.1.0/24", "192.168.50.0/24");
        assert_eq!(
            ipv4.map_tcp_target(
                &NetLocation::from_str("10.200.1.20:443", None).unwrap()
            )
            .unwrap(),
            NetLocation::from_str("192.168.50.20:443", None).unwrap()
        );

        let ipv6 = policy("fd00:1::/64", "fd00:2::/64");
        assert_eq!(
            ipv6.map_udp_target(
                &NetLocation::from_str("fd00:1::abcd:53", None).unwrap()
            )
            .unwrap(),
            NetLocation::from_str("fd00:2::abcd:53", None).unwrap()
        );
    }

    #[test]
    fn udp_response_source_is_mapped_back_to_overlay_prefix() {
        let policy = policy("10.200.1.0/24", "192.168.50.0/24");
        assert_eq!(
            policy
                .map_response_source("192.168.50.53:5353".parse().unwrap())
                .unwrap(),
            "10.200.1.53:5353".parse().unwrap()
        );
    }

    #[test]
    fn policy_denies_unmapped_targets_and_disallowed_networks_ips_and_ports() {
        let policy = policy("10.200.1.0/24", "192.168.50.0/24");
        assert_eq!(
            policy
                .map_tcp_target(
                    &NetLocation::from_str("10.200.2.20:443", None).unwrap()
                )
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            policy
                .map_tcp_target(
                    &NetLocation::from_str("10.200.1.20:3389", None).unwrap()
                )
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            policy
                .map_response_source("198.51.100.20:443".parse().unwrap())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn site_prefix_config_rejects_ambiguous_and_invalid_policy() {
        let config = |maps| SiteToSiteConfig {
            prefix_maps: maps,
            allow: vec![SiteTargetAllowConfig {
                network: vec!["tcp".to_string()],
                ip: vec!["192.168.0.0/16".to_string()],
                ports: vec!["22".to_string()],
            }],
        };
        assert!(
            SiteToSitePolicy::compile(&config(vec![
                SitePrefixMapConfig {
                    from: "10.0.0.0/24".to_string(),
                    to: "192.168.0.0/24".to_string(),
                },
                SitePrefixMapConfig {
                    from: "10.0.0.128/25".to_string(),
                    to: "192.168.1.0/25".to_string(),
                }
            ]))
            .is_err()
        );
        assert!(
            SiteToSitePolicy::compile(&config(vec![SitePrefixMapConfig {
                from: "10.0.0.0/24".to_string(),
                to: "192.168.0.0/25".to_string(),
            }]))
            .is_err()
        );
        assert!(
            SiteToSitePolicy::compile(&SiteToSiteConfig {
                prefix_maps: vec![SitePrefixMapConfig {
                    from: "10.0.0.0/24".to_string(),
                    to: "192.168.0.0/24".to_string(),
                }],
                allow: vec![SiteTargetAllowConfig {
                    network: vec!["icmp".to_string()],
                    ip: vec!["192.168.0.0/24".to_string()],
                    ports: vec!["0".to_string()],
                }],
            })
            .is_err()
        );
    }
}
