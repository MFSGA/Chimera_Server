use std::{collections::HashMap, net::SocketAddr, time::Duration};

use tokio::{io::AsyncReadExt, time::timeout};

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    config::server_config::InboundSniffingConfig,
    outbound::InboundRoutingMetadata,
    tls_client_hello::{ClientHelloInspection, inspect_client_hello},
    util::prefixed_stream::PrefixedStream,
};

const SNIFFING_MAX_BYTES: usize = 32_767;
const SNIFFING_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SniffedRoutingMetadata {
    pub(crate) protocol: Option<String>,
    pub(crate) domain: Option<String>,
    pub(crate) attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SniffInspection {
    NeedMore,
    Complete(SniffedRoutingMetadata),
    NoClue,
}

const XRAY_HTTP_METHODS: &[&[u8]] = &[
    b"get", b"post", b"head", b"put", b"delete", b"options", b"connect",
];

fn ascii_prefix_eq_ignore_case(input: &[u8], expected: &[u8]) -> bool {
    input
        .iter()
        .zip(expected)
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn inspect_http_routing_metadata(input: &[u8]) -> SniffInspection {
    let method_matches = XRAY_HTTP_METHODS.iter().any(|method| {
        input.len() >= method.len()
            && ascii_prefix_eq_ignore_case(&input[..method.len()], method)
    });
    if !method_matches {
        let method_may_match = XRAY_HTTP_METHODS.iter().any(|method| {
            input.len() < method.len()
                && ascii_prefix_eq_ignore_case(input, &method[..input.len()])
        });
        return if method_may_match {
            SniffInspection::NeedMore
        } else {
            SniffInspection::NoClue
        };
    }

    let Some(header_end) = input.windows(4).position(|window| window == b"\r\n\r\n")
    else {
        return SniffInspection::NeedMore;
    };
    let header_block = &input[..header_end + 2];
    let mut lines = header_block.split(|byte| *byte == b'\n');
    let Some(request_line) = lines.next() else {
        return SniffInspection::NoClue;
    };
    let request_line = request_line.strip_suffix(b"\r").unwrap_or(request_line);
    let request_line = String::from_utf8_lossy(request_line);
    let request_parts = request_line.split(' ').collect::<Vec<_>>();

    let mut attributes = HashMap::new();
    let mut domain = None;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let key = String::from_utf8_lossy(&line[..separator]).to_ascii_lowercase();
        let value = String::from_utf8_lossy(&line[separator + 1..])
            .trim()
            .to_string();
        if key == "host" && !value.is_empty() {
            domain = sniffed_http_domain(&value);
        }
        attributes.insert(key, value);
    }
    if request_parts.len() == 3 {
        attributes.insert(":method".into(), request_parts[0].to_string());
        attributes.insert(":path".into(), request_parts[1].to_string());
    }

    SniffInspection::Complete(SniffedRoutingMetadata {
        protocol: domain.as_ref().map(|_| "http1".to_string()),
        domain,
        attributes,
    })
}

fn sniffed_http_domain(host: &str) -> Option<String> {
    let host = host.trim().to_ascii_lowercase();
    let host = if let Some(host) = host.strip_prefix('[') {
        let (host, remainder) = host.split_once(']')?;
        if !remainder.is_empty()
            && !remainder
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok())
        {
            return None;
        }
        host
    } else if let Some((name, port)) = host.rsplit_once(':') {
        if !name.contains(':') && port.parse::<u16>().is_ok() {
            name
        } else {
            host.as_str()
        }
    } else {
        host.as_str()
    };
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(host.to_string())
    }
}

pub(crate) fn inspect_sniffed_routing_metadata(input: &[u8]) -> SniffInspection {
    let tls_inspection = inspect_client_hello(input);
    match tls_inspection {
        ClientHelloInspection::ServerName(server_name) => {
            return SniffInspection::Complete(SniffedRoutingMetadata {
                protocol: Some("tls".into()),
                domain: Some(server_name.to_ascii_lowercase()),
                attributes: HashMap::new(),
            });
        }
        ClientHelloInspection::EncryptedClientHello
        | ClientHelloInspection::NoServerName => {
            return SniffInspection::Complete(SniffedRoutingMetadata {
                protocol: Some("tls".into()),
                domain: None,
                attributes: HashMap::new(),
            });
        }
        ClientHelloInspection::Incomplete
        | ClientHelloInspection::NotTls
        | ClientHelloInspection::Malformed => {}
    }

    match inspect_http_routing_metadata(input) {
        SniffInspection::NoClue
            if tls_inspection == ClientHelloInspection::Incomplete =>
        {
            SniffInspection::NeedMore
        }
        inspection => inspection,
    }
}

fn sniffed_override_domain(
    sniffing: Option<&InboundSniffingConfig>,
    metadata: &SniffedRoutingMetadata,
    remote_location: &NetLocation,
) -> Option<String> {
    let config = sniffing.filter(|config| config.enabled)?;
    let protocol = metadata.protocol.as_deref()?;
    if !config.overrides_protocol(protocol) {
        return None;
    }
    let domain = metadata.domain.as_deref()?;
    if config.excludes_domain(domain) {
        return None;
    }
    let excluded_ip = match remote_location.address() {
        Address::Ipv4(ip) => config.excludes_ip((*ip).into()),
        Address::Ipv6(ip) => config.excludes_ip((*ip).into()),
        Address::Hostname(_) => false,
    };
    (!excluded_ip).then(|| domain.to_string())
}

pub(crate) fn route_only_sniffed_domain(
    sniffing: Option<&InboundSniffingConfig>,
    metadata: &SniffedRoutingMetadata,
    remote_location: &NetLocation,
) -> Option<String> {
    sniffing
        .filter(|config| config.route_only)
        .and_then(|config| {
            sniffed_override_domain(Some(config), metadata, remote_location)
        })
}

pub(crate) fn sniffed_outbound_target(
    sniffing: Option<&InboundSniffingConfig>,
    metadata: &SniffedRoutingMetadata,
    remote_location: &NetLocation,
) -> NetLocation {
    if sniffing.is_some_and(|config| config.route_only) {
        return remote_location.clone();
    }
    match sniffed_override_domain(sniffing, metadata, remote_location) {
        Some(domain) => {
            NetLocation::new(Address::Hostname(domain), remote_location.port())
        }
        None => remote_location.clone(),
    }
}

pub(crate) struct SniffedRoutePlan {
    pub(crate) outbound_target: NetLocation,
    pub(crate) routing_metadata: InboundRoutingMetadata,
}

pub(crate) fn build_sniffed_route_plan(
    sniffing: Option<&InboundSniffingConfig>,
    sniffed: SniffedRoutingMetadata,
    remote_location: &NetLocation,
    local_addr: Option<SocketAddr>,
) -> SniffedRoutePlan {
    let outbound_target =
        sniffed_outbound_target(sniffing, &sniffed, remote_location);
    let route_target_domain =
        route_only_sniffed_domain(sniffing, &sniffed, remote_location);
    SniffedRoutePlan {
        outbound_target,
        routing_metadata: InboundRoutingMetadata {
            local_addr,
            vless_route: 0,
            inbound_protocol: None,
            sniffed_protocol: sniffed.protocol,
            route_target_domain,
            attributes: sniffed.attributes,
            policy_identities: Vec::new(),
        },
    }
}

pub(crate) async fn sniff_stream_protocol(
    mut stream: Box<dyn AsyncStream>,
    sniffing: Option<&InboundSniffingConfig>,
) -> std::io::Result<(Box<dyn AsyncStream>, SniffedRoutingMetadata)> {
    if !sniffing.is_some_and(|config| config.enabled) {
        return Ok((stream, SniffedRoutingMetadata::default()));
    }

    let mut captured = Vec::new();
    let sniffed = timeout(SNIFFING_TIMEOUT, async {
        loop {
            match inspect_sniffed_routing_metadata(&captured) {
                SniffInspection::Complete(metadata) => {
                    return Ok::<_, std::io::Error>(metadata);
                }
                SniffInspection::NoClue => {
                    return Ok(SniffedRoutingMetadata::default());
                }
                SniffInspection::NeedMore => {}
            }
            if captured.len() >= SNIFFING_MAX_BYTES {
                return Ok(SniffedRoutingMetadata::default());
            }
            let mut buffer = [0u8; 4096];
            let read_limit = buffer
                .len()
                .min(SNIFFING_MAX_BYTES.saturating_sub(captured.len()));
            let read = stream.read(&mut buffer[..read_limit]).await?;
            if read == 0 {
                return Ok(SniffedRoutingMetadata::default());
            }
            captured.extend_from_slice(&buffer[..read]);
        }
    })
    .await
    .unwrap_or(Ok(SniffedRoutingMetadata::default()))?;

    if captured.is_empty() {
        Ok((stream, sniffed))
    } else {
        Ok((Box::new(PrefixedStream::new(captured, stream)), sniffed))
    }
}
