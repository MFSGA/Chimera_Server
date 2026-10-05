use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use serde_json::Value;

use super::wire::{
    FreedomFinalRulePayload, FreedomPortListPayload, FreedomPortRangePayload,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FreedomRuleAction {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cidr {
    address: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IpMatcher {
    cidrs: Vec<Cidr>,
}

impl IpMatcher {
    fn matches(&self, address: IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(address))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FreedomFinalRule {
    action: FreedomRuleAction,
    networks: Vec<i32>,
    ports: Vec<RangeInclusive<u16>>,
    ip: Option<IpMatcher>,
}

impl FreedomFinalRule {
    fn matches(&self, network: i32, address: IpAddr, port: u16) -> bool {
        (self.networks.is_empty() || self.networks.contains(&network))
            && (self.ports.is_empty()
                || self.ports.iter().any(|range| range.contains(&port)))
            && self
                .ip
                .as_ref()
                .is_none_or(|matcher| matcher.matches(address))
    }
}

pub(super) fn compile_static_final_rules(
    raw_rules: &[Value],
    outbound_tag: &str,
) -> Result<Vec<FreedomFinalRulePayload>, String> {
    raw_rules
        .iter()
        .enumerate()
        .map(|(index, raw)| {
            let path =
                format!("freedom outbound {outbound_tag} finalRules[{index}]");
            let object = raw
                .as_object()
                .ok_or_else(|| format!("{path} must be an object"))?;

            if object
                .get("blockDelay")
                .is_some_and(|value| !value.is_null())
            {
                return Err(format!(
                    "{path}.blockDelay is recognized but not implemented"
                ));
            }

            let action = match object
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str()
            {
                "allow" => 0,
                "block" => 1,
                _ => {
                    return Err(format!(
                        "{path}.action must be \"allow\" or \"block\""
                    ));
                }
            };

            let networks = parse_networks(object.get("network"), &path)?;
            let port_list = parse_ports(object.get("port"), &path)?;
            let ip = parse_ip_rules(object.get("ip"), &path)?;

            Ok(FreedomFinalRulePayload {
                action,
                networks,
                port_list,
                ip,
                block_delay: None,
            })
        })
        .collect()
}

pub(super) fn decode_final_rules(
    payload: &[FreedomFinalRulePayload],
    outbound_tag: &str,
) -> io::Result<Vec<FreedomFinalRule>> {
    use crate::geodata::proto::ip_rule;

    payload
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            let path = format!("freedom outbound {outbound_tag} finalRules[{index}]");
            let action = match rule.action {
                0 => FreedomRuleAction::Allow,
                1 => FreedomRuleAction::Block,
                _ => {
                    return Err(invalid_config(format!(
                        "{path} has an unknown action"
                    )));
                }
            };
            if rule.block_delay.is_some() {
                return Err(invalid_config(format!(
                    "{path}.blockDelay is recognized but not implemented"
                )));
            }

            let ports = rule
                .port_list
                .as_ref()
                .map(|list| {
                    list.range
                        .iter()
                        .map(|range| {
                            let from = u16::try_from(range.from).map_err(|_| {
                                invalid_config(format!(
                                    "{path}.port contains a value above 65535"
                                ))
                            })?;
                            let to = u16::try_from(range.to).map_err(|_| {
                                invalid_config(format!(
                                    "{path}.port contains a value above 65535"
                                ))
                            })?;
                            if from > to {
                                return Err(invalid_config(format!(
                                    "{path}.port contains a reversed range"
                                )));
                            }
                            Ok(from..=to)
                        })
                        .collect::<io::Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default();

            let mut cidrs = Vec::with_capacity(rule.ip.len());
            for ip_rule in &rule.ip {
                let Some(ip_rule::Value::Custom(custom)) = ip_rule.value.as_ref()
                else {
                    return Err(invalid_config(format!(
                        "{path}.ip supports literal CIDRs only; GeoIP rules are not implemented"
                    )));
                };
                if custom.reverse_match {
                    return Err(invalid_config(format!(
                        "{path}.ip reverse-match rules are not implemented"
                    )));
                }
                let cidr = custom.cidr.as_ref().ok_or_else(|| {
                    invalid_config(format!("{path}.ip contains an empty CIDR"))
                })?;
                let (address, max_prefix) = match cidr.ip.as_slice() {
                    [a, b, c, d] => (
                        IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
                        32,
                    ),
                    bytes if bytes.len() == 16 => {
                        let octets: [u8; 16] = bytes.try_into().map_err(|_| {
                            invalid_config(format!("{path}.ip contains an invalid IPv6 CIDR"))
                        })?;
                        (IpAddr::V6(Ipv6Addr::from(octets)), 128)
                    }
                    _ => {
                        return Err(invalid_config(format!(
                            "{path}.ip contains an invalid CIDR address"
                        )));
                    }
                };
                if cidr.prefix > max_prefix {
                    return Err(invalid_config(format!(
                        "{path}.ip contains an invalid CIDR prefix"
                    )));
                }
                cidrs.push(Cidr {
                    address,
                    prefix: cidr.prefix as u8,
                });
            }

            let ip = (!cidrs.is_empty()).then_some(IpMatcher { cidrs });
            Ok(FreedomFinalRule {
                action,
                networks: rule.networks.clone(),
                ports,
                ip,
            })
        })
        .collect()
}

pub(super) fn allows(
    final_rules: &[FreedomFinalRule],
    inbound_protocol: Option<&str>,
    network: i32,
    address: IpAddr,
    port: u16,
) -> bool {
    for rule in final_rules {
        if rule.matches(network, address, port) {
            return rule.action == FreedomRuleAction::Allow;
        }
    }

    match inbound_protocol.map(str::to_ascii_lowercase).as_deref() {
        Some("vless-reverse") => false,
        Some(
            "vless" | "vmess" | "trojan" | "hysteria" | "hysteria2" | "wireguard",
        ) => !is_xray_private_ip(address),
        Some(protocol) if protocol.starts_with("shadowsocks") => {
            !is_xray_private_ip(address)
        }
        _ => true,
    }
}

pub(super) fn requires_target_ip_check(
    final_rules: &[FreedomFinalRule],
    inbound_protocol: Option<&str>,
) -> bool {
    !final_rules.is_empty()
        || inbound_protocol.is_some_and(|protocol| {
            let protocol = protocol.to_ascii_lowercase();
            protocol == "vless-reverse"
                || matches!(
                    protocol.as_str(),
                    "vless"
                        | "vmess"
                        | "trojan"
                        | "hysteria"
                        | "hysteria2"
                        | "wireguard"
                )
                || protocol.starts_with("shadowsocks")
        })
}

fn is_xray_private_ip(address: IpAddr) -> bool {
    const V4: &[(Ipv4Addr, u8)] = &[
        (Ipv4Addr::new(0, 0, 0, 0), 8),
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(127, 0, 0, 0), 8),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 0, 0, 0), 24),
        (Ipv4Addr::new(192, 0, 2, 0), 24),
        (Ipv4Addr::new(192, 88, 99, 0), 24),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(198, 18, 0, 0), 15),
        (Ipv4Addr::new(198, 51, 100, 0), 24),
        (Ipv4Addr::new(203, 0, 113, 0), 24),
        (Ipv4Addr::new(224, 0, 0, 0), 3),
    ];
    const V6: &[(Ipv6Addr, u8)] = &[
        (Ipv6Addr::UNSPECIFIED, 127),
        (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
        (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
        (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
    ];

    match address {
        IpAddr::V4(address) => V4.iter().any(|(network, prefix)| {
            Cidr {
                address: IpAddr::V4(*network),
                prefix: *prefix,
            }
            .contains(IpAddr::V4(address))
        }),
        IpAddr::V6(address) => V6.iter().any(|(network, prefix)| {
            Cidr {
                address: IpAddr::V6(*network),
                prefix: *prefix,
            }
            .contains(IpAddr::V6(address))
        }),
    }
}

fn parse_networks(value: Option<&Value>, path: &str) -> Result<Vec<i32>, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        // Xray's NetworkList.Build defaults an omitted network field to TCP.
        return Ok(vec![2]);
    };
    let names = parse_string_list(value, &format!("{path}.network"))?;
    Ok(names
        .into_iter()
        .map(|name| match name.trim().to_ascii_lowercase().as_str() {
            "tcp" => 2,
            "udp" => 3,
            "unix" => 4,
            _ => 0,
        })
        .collect())
}

fn parse_ports(
    value: Option<&Value>,
    path: &str,
) -> Result<Option<FreedomPortListPayload>, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };

    let mut ranges = Vec::new();
    match value {
        Value::Number(number) => {
            let port = number
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .ok_or_else(|| format!("{path}.port must be between 0 and 65535"))?;
            if port != 0 {
                ranges.push(FreedomPortRangePayload {
                    from: u32::from(port),
                    to: u32::from(port),
                });
            }
        }
        Value::String(value) => {
            for text in value
                .split(',')
                .map(str::trim)
                .filter(|text| !text.is_empty())
            {
                if text.starts_with("env:") {
                    return Err(format!(
                        "{path}.port environment-variable ranges are not implemented"
                    ));
                }
                let (from, to) = match text.split_once('-') {
                    Some((from, to)) => {
                        (parse_port(from, path)?, parse_port(to, path)?)
                    }
                    None => {
                        let port = parse_port(text, path)?;
                        (port, port)
                    }
                };
                if from > to {
                    return Err(format!(
                        "{path}.port range lower bound must not exceed upper bound"
                    ));
                }
                ranges.push(FreedomPortRangePayload {
                    from: u32::from(from),
                    to: u32::from(to),
                });
            }
        }
        _ => return Err(format!("{path}.port must be a number or string")),
    }

    Ok(Some(FreedomPortListPayload { range: ranges }))
}

fn parse_port(value: &str, path: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("{path}.port must contain values between 0 and 65535"))
}

fn parse_ip_rules(
    value: Option<&Value>,
    path: &str,
) -> Result<Vec<crate::geodata::proto::IpRule>, String> {
    use crate::geodata::proto::{Cidr, CidrRule, IpRule, ip_rule};

    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    let values = parse_string_list(value, &format!("{path}.ip"))?;
    values
        .into_iter()
        .map(|text| {
            let text = text.trim();
            if text.is_empty() {
                return Err(format!("{path}.ip contains an empty rule"));
            }
            if text.starts_with('!') {
                return Err(format!(
                    "{path}.ip reverse-match rules are not implemented"
                ));
            }
            if text.starts_with("geoip:")
                || text.starts_with("ext:")
                || text.starts_with("ext-ip:")
            {
                return Err(format!(
                    "{path}.ip supports literal CIDRs only; GeoIP rules are not implemented"
                ));
            }

            let (ip_text, prefix_text) = text
                .split_once('/')
                .map_or((text, None), |(ip, prefix)| (ip, Some(prefix)));
            let address = ip_text
                .parse::<IpAddr>()
                .map_err(|_| format!("{path}.ip contains an invalid literal IP or CIDR"))?;
            let max_prefix = if address.is_ipv4() { 32 } else { 128 };
            let prefix = prefix_text
                .map(|prefix| {
                    prefix.parse::<u32>().map_err(|_| {
                        format!("{path}.ip contains an invalid CIDR prefix")
                    })
                })
                .transpose()?
                .unwrap_or(max_prefix);
            if prefix > max_prefix {
                return Err(format!("{path}.ip contains an invalid CIDR prefix"));
            }
            let ip = match address {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            };
            Ok(IpRule {
                value: Some(ip_rule::Value::Custom(CidrRule {
                    cidr: Some(Cidr { ip, prefix }),
                    reverse_match: false,
                })),
            })
        })
        .collect()
}

fn parse_string_list(value: &Value, field: &str) -> Result<Vec<String>, String> {
    match value {
        Value::String(value) => Ok(value
            .split(',')
            .map(|item| item.trim().to_string())
            .collect()),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{field} array values must be strings"))
            })
            .collect(),
        _ => Err(format!("{field} must be a string or string array")),
    }
}

fn invalid_config(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(action: i32, network: i32, port: u32, ip: &str) -> FreedomFinalRule {
        let compiled = compile_static_final_rules(
            &[serde_json::json!({
                "action": if action == 0 { "allow" } else { "block" },
                "network": if network == 2 { "tcp" } else { "udp" },
                "port": port,
                "ip": ip,
            })],
            "test",
        )
        .unwrap();
        decode_final_rules(&compiled, "test").unwrap().remove(0)
    }

    #[test]
    fn first_matching_rule_overrides_xray_inbound_defaults() {
        let rules = vec![rule(0, 2, 8443, "10.0.0.0/8"), rule(1, 2, 0, "0.0.0.0/0")];
        assert!(allows(
            &rules,
            Some("vless-reverse"),
            2,
            "10.1.2.3".parse().unwrap(),
            8443,
        ));
        assert!(!allows(
            &rules,
            Some("vless-reverse"),
            2,
            "10.1.2.3".parse().unwrap(),
            80,
        ));
    }

    #[test]
    fn default_rules_match_xray_vless_and_reverse_behavior() {
        assert!(!allows(
            &[],
            Some("vless-reverse"),
            2,
            "203.0.113.10".parse().unwrap(),
            443,
        ));
        assert!(!allows(
            &[],
            Some("vless"),
            2,
            "192.168.1.5".parse().unwrap(),
            443,
        ));
        assert!(allows(
            &[],
            Some("vless"),
            2,
            "1.1.1.1".parse().unwrap(),
            443,
        ));
    }

    #[test]
    fn omitted_network_defaults_to_tcp_but_explicit_empty_network_is_all() {
        let compile = |rule| {
            let payload = compile_static_final_rules(&[rule], "direct").unwrap();
            decode_final_rules(&payload, "direct").unwrap()
        };
        let omitted = compile(serde_json::json!({
            "action": "allow",
            "ip": "203.0.113.0/24"
        }));
        assert!(allows(
            &omitted,
            Some("vless-reverse"),
            2,
            "203.0.113.7".parse().unwrap(),
            80,
        ));
        assert!(!allows(
            &omitted,
            Some("vless-reverse"),
            3,
            "203.0.113.7".parse().unwrap(),
            80,
        ));

        let explicit_empty = compile(serde_json::json!({
            "action": "allow",
            "network": [],
            "ip": "203.0.113.0/24"
        }));
        assert!(allows(
            &explicit_empty,
            Some("vless-reverse"),
            3,
            "203.0.113.7".parse().unwrap(),
            80,
        ));
    }

    #[test]
    fn unsupported_final_rule_inputs_fail_explicitly() {
        for (rule, expected) in [
            (
                serde_json::json!({"action":"allow", "ip":"geoip:private"}),
                "GeoIP",
            ),
            (
                serde_json::json!({"action":"block", "blockDelay":"30-60"}),
                "blockDelay",
            ),
            (
                serde_json::json!({"action":"allow", "ip":"!10.0.0.0/8"}),
                "reverse-match",
            ),
        ] {
            let error = compile_static_final_rules(&[rule], "direct").unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
    }
}
