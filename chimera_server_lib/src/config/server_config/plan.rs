use crate::{Error, config::Transport};

use super::{ServerConfig, ServerProxyConfig};

/// A compiled inbound that has passed the checks common to every input path.
///
/// File configuration and protobuf management input keep their own decoding
/// and presence rules, then cross this boundary before an inbound is prepared
/// or published by `InboundManager`.
#[derive(Debug)]
pub(crate) struct InboundPlan {
    config: ServerConfig,
}

impl InboundPlan {
    pub(crate) fn from_compiled(config: ServerConfig) -> Result<Self, Error> {
        validate_compiled_inbound(&config)?;
        Ok(Self { config })
    }

    pub(crate) fn into_server_config(self) -> ServerConfig {
        self.config
    }
}

fn validate_compiled_inbound(config: &ServerConfig) -> Result<(), Error> {
    let has_quic_settings = config.quic_settings.is_some();
    let is_quic_transport = matches!(config.transport, Transport::Quic);
    if has_quic_settings != is_quic_transport {
        return Err(Error::InvalidConfig(format!(
            "inbound {} must keep quicSettings aligned with its QUIC transport",
            config.tag
        )));
    }

    if matches!(config.protocol, ServerProxyConfig::Tunnel)
        && !matches!(config.transport, Transport::Tcp)
    {
        return Err(Error::InvalidConfig(format!(
            "api tunnel inbound {} must use TCP transport",
            config.tag
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::{Address, BindLocation, NetLocation},
        config::Transport,
    };

    fn config(transport: Transport, quic_settings: bool) -> ServerConfig {
        ServerConfig {
            tag: "inbound-plan".into(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::from("127.0.0.1").expect("valid address"),
                10001,
            )),
            protocol: ServerProxyConfig::DokodemoDoor {
                config: super::super::DokodemoDoorConfig {
                    target: NetLocation::new(
                        Address::from("127.0.0.1").expect("valid address"),
                        80,
                    ),
                    follow_redirect: false,
                    user_level: 0,
                },
            },
            transport,
            quic_settings: if quic_settings {
                Some(super::super::quic::ServerQuicConfig {
                    cert: String::new(),
                    key: String::new(),
                    alpn_protocols: crate::util::option::NoneOrSome::Unspecified,
                    client_fingerprints:
                        crate::util::option::NoneOrSome::Unspecified,
                })
            } else {
                None
            },
            sniffing: None,
            tcp_socket_policy: None,
        }
    }

    #[test]
    fn accepts_matching_quic_resource_shape() {
        assert!(InboundPlan::from_compiled(config(Transport::Tcp, false)).is_ok());
    }

    #[test]
    fn rejects_quic_settings_on_non_quic_transport() {
        let error = InboundPlan::from_compiled(config(Transport::Tcp, true))
            .expect_err("mismatched QUIC settings must fail");
        assert!(error.to_string().contains("quicSettings"));
    }
}
