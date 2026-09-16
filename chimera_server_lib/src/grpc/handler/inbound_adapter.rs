use super::*;

mod stream_settings;

impl HandlerServiceImpl {
    pub(super) fn parse_typed_message_type(
        typed_message: &proto::xray::common::serial::TypedMessage,
    ) -> &str {
        typed_message.r#type.trim_start_matches('.')
    }

    pub(super) fn decode_typed_message<T: Message + Default>(
        &self,
        typed_message: &proto::xray::common::serial::TypedMessage,
        accepted_types: &[&str],
        label: &str,
    ) -> Result<T, Status> {
        let message_type = Self::parse_typed_message_type(typed_message);
        if !accepted_types.contains(&message_type) {
            return Err(Status::invalid_argument(format!(
                "unsupported {label} type: {message_type}"
            )));
        }
        T::decode(typed_message.value.as_slice()).map_err(|err| {
            Status::invalid_argument(format!("invalid {label} payload: {err}"))
        })
    }

    pub(super) fn parse_address(
        &self,
        value: Option<IpOrDomainPayload>,
    ) -> Result<Address, Status> {
        match value.and_then(|item| item.address) {
            Some(ip_or_domain_payload::Address::Ip(bytes)) => match bytes.as_slice()
            {
                [a, b, c, d] => {
                    Ok(Address::Ipv4(std::net::Ipv4Addr::new(*a, *b, *c, *d)))
                }
                [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] => {
                    Ok(Address::Ipv6(std::net::Ipv6Addr::from([
                        *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n, *o,
                        *p,
                    ])))
                }
                _ => {
                    Err(Status::invalid_argument("listen ip must be 4 or 16 bytes"))
                }
            },
            Some(ip_or_domain_payload::Address::Domain(domain)) => {
                if domain.trim().is_empty() {
                    Err(Status::invalid_argument("listen domain is required"))
                } else {
                    Ok(Address::Hostname(domain))
                }
            }
            None => Ok(Address::UNSPECIFIED),
        }
    }

    pub(super) fn parse_listen_port(
        &self,
        receiver: &ReceiverConfigPayload,
    ) -> Result<u16, Status> {
        let port_list = receiver.port_list.as_ref().ok_or_else(|| {
            Status::invalid_argument("ReceiverConfig.port_list is required")
        })?;
        let range = port_list.range.first().ok_or_else(|| {
            Status::invalid_argument("ReceiverConfig.port_list.range is required")
        })?;
        if range.from == 0 || range.to == 0 {
            return Err(Status::invalid_argument("receiver port must be non-zero"));
        }
        if range.from != range.to {
            return Err(Status::invalid_argument(
                "port ranges are not supported for AddInbound",
            ));
        }
        u16::try_from(range.from)
            .map_err(|_| Status::invalid_argument("receiver port must fit in u16"))
    }

    pub(super) fn parse_add_inbound(
        &self,
        inbound: proto::xray::core::InboundHandlerConfig,
    ) -> Result<ServerConfig, Status> {
        let receiver_settings =
            inbound.receiver_settings.as_ref().ok_or_else(|| {
                Status::invalid_argument("inbound.receiver_settings is required")
            })?;
        let receiver = self.decode_typed_message::<ReceiverConfigPayload>(
            receiver_settings,
            &[TYPE_APP_RECEIVER_CONFIG, TYPE_APP_RECEIVER_CONFIG_V2RAY],
            "receiver settings",
        )?;
        let port = self.parse_listen_port(&receiver)?;
        let address = self.parse_address(receiver.listen)?;

        let proxy_settings = inbound.proxy_settings.as_ref().ok_or_else(|| {
            Status::invalid_argument("inbound.proxy_settings is required")
        })?;
        let mut protocol = self.parse_add_inbound_protocol(proxy_settings)?;
        if let Some(stream_settings) = receiver.stream_settings {
            protocol =
                self.apply_add_inbound_stream_settings(protocol, stream_settings)?;
        }

        let config = ServerConfig {
            tag: inbound.tag,
            bind_location: BindLocation::Address(NetLocation::new(address, port)),
            protocol,
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        };
        crate::config::server_config::InboundPlan::from_compiled(config)
            .map(crate::config::server_config::InboundPlan::into_server_config)
            .map_err(|error| Status::invalid_argument(error.to_string()))
    }

    pub(super) fn parse_add_inbound_protocol(
        &self,
        proxy_settings: &proto::xray::common::serial::TypedMessage,
    ) -> Result<ServerProxyConfig, Status> {
        match Self::parse_typed_message_type(proxy_settings) {
            TYPE_PROXY_SOCKS_SERVER_CONFIG
            | TYPE_PROXY_SOCKS_SERVER_CONFIG_V2RAY => {
                let socks = self.decode_typed_message::<SocksServerConfigPayload>(
                    proxy_settings,
                    &[
                        TYPE_PROXY_SOCKS_SERVER_CONFIG,
                        TYPE_PROXY_SOCKS_SERVER_CONFIG_V2RAY,
                    ],
                    "inbound proxy settings",
                )?;

                let accounts = socks
                    .accounts
                    .into_iter()
                    .map(|(username, password)| SocksUser { username, password })
                    .collect::<Vec<_>>();
                let accounts =
                    crate::config::server_config::SocksUserStore::with_auth_required(
                        accounts,
                        socks.auth_type == 1,
                    );
                let udp_response_ip = match socks.address {
                    Some(address) => {
                        Some(self.parse_address(Some(address))?.to_string())
                    }
                    None => None,
                };

                Ok(ServerProxyConfig::Socks {
                    accounts,
                    udp_enabled: socks.udp_enabled,
                    udp_response_ip,
                    user_level: socks.user_level,
                })
            }
            #[cfg(feature = "vless")]
            TYPE_PROXY_VLESS_INBOUND_CONFIG
            | TYPE_PROXY_VLESS_INBOUND_CONFIG_V2RAY => {
                let config = self
                    .decode_typed_message::<VlessInboundConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_VLESS_INBOUND_CONFIG,
                            TYPE_PROXY_VLESS_INBOUND_CONFIG_V2RAY,
                        ],
                        "inbound proxy settings",
                    )?;
                self.parse_vless_inbound_config(config)
            }
            #[cfg(feature = "vmess")]
            TYPE_PROXY_VMESS_INBOUND_CONFIG
            | TYPE_PROXY_VMESS_INBOUND_CONFIG_V2RAY => {
                let config = self
                    .decode_typed_message::<VmessInboundConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_VMESS_INBOUND_CONFIG,
                            TYPE_PROXY_VMESS_INBOUND_CONFIG_V2RAY,
                        ],
                        "inbound proxy settings",
                    )?;
                self.parse_vmess_inbound_config(config)
            }
            #[cfg(feature = "trojan")]
            TYPE_PROXY_TROJAN_SERVER_CONFIG
            | TYPE_PROXY_TROJAN_SERVER_CONFIG_V2RAY => {
                let config = self
                    .decode_typed_message::<TrojanServerConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_TROJAN_SERVER_CONFIG,
                            TYPE_PROXY_TROJAN_SERVER_CONFIG_V2RAY,
                        ],
                        "inbound proxy settings",
                    )?;
                self.parse_trojan_inbound_config(config)
            }
            other => Err(Status::invalid_argument(format!(
                "unsupported inbound proxy settings type: {other}"
            ))),
        }
    }

    #[cfg(feature = "vless")]
    pub(super) fn parse_vless_inbound_config(
        &self,
        config: VlessInboundConfigPayload,
    ) -> Result<ServerProxyConfig, Status> {
        if config.clients.is_empty() {
            return Err(Status::invalid_argument(
                "vless AddInbound requires at least one client",
            ));
        }
        let users = config
            .clients
            .iter()
            .map(|client| self.parse_vless_user(client))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ServerProxyConfig::Vless {
            users,
            fallbacks: Vec::new(),
        })
    }

    #[cfg(feature = "vless")]
    pub(super) fn parse_vless_user(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<VlessUser, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument("vless client account is required")
        })?;
        let account = self.decode_typed_message::<VlessAccountPayload>(
            account,
            &[TYPE_PROXY_VLESS_ACCOUNT, TYPE_PROXY_VLESS_ACCOUNT_V2RAY],
            "vless account",
        )?;
        let user_id = account.id.trim();
        if user_id.is_empty() {
            return Err(Status::invalid_argument("vless client id is required"));
        }
        validate_vless_flow(&account.flow)?;
        Ok(VlessUser {
            user_id: user_id.to_string(),
            user_label: if user.email.trim().is_empty() {
                user_id.to_string()
            } else {
                user.email.clone()
            },
            user_level: user.level,
            flow: account.flow,
        })
    }

    #[cfg(feature = "vless")]
    pub(super) fn parse_vmess_inbound_config(
        &self,
        config: VmessInboundConfigPayload,
    ) -> Result<ServerProxyConfig, Status> {
        if config.users.is_empty() {
            return Err(Status::invalid_argument(
                "vmess AddInbound requires at least one user",
            ));
        }
        let users = config
            .users
            .iter()
            .map(|user| self.parse_vmess_user(user))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ServerProxyConfig::Vmess { users })
    }

    #[cfg(feature = "vmess")]
    pub(super) fn parse_vmess_user(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<VmessUser, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument("vmess client account is required")
        })?;
        let account = self.decode_typed_message::<VmessAccountPayload>(
            account,
            &[TYPE_PROXY_VMESS_ACCOUNT, TYPE_PROXY_VMESS_ACCOUNT_V2RAY],
            "vmess account",
        )?;
        let user_id = normalize_vmess_user_id(&account.id)
            .map_err(Status::invalid_argument)?;
        let cipher = match account
            .security_settings
            .as_ref()
            .map(|security| security.r#type)
            .unwrap_or(2)
        {
            3 => "aes-128-gcm",
            4 => "chacha20-poly1305",
            _ => "auto",
        }
        .to_string();
        Ok(VmessUser {
            user_label: if user.email.trim().is_empty() {
                user_id.clone()
            } else {
                user.email.clone()
            },
            user_id,
            user_level: user.level,
            cipher,
        })
    }

    #[cfg(feature = "vmess")]
    pub(super) fn parse_shadowsocks_user(
        &self,
        protocol: &ServerProxyConfig,
        user: &proto::xray::common::protocol::User,
    ) -> Result<ShadowsocksUser, Status> {
        let identity_method = match protocol {
            ServerProxyConfig::Shadowsocks { identity, .. } => {
                identity.as_ref().map(|identity| identity.method.as_str())
            }
            _ => {
                return Err(Status::invalid_argument(
                    "shadowsocks account used with a non-shadowsocks inbound",
                ));
            }
        };
        self.parse_shadowsocks_user_with_identity_method(identity_method, user)
    }

    #[cfg(feature = "shadowsocks")]
    pub(super) fn parse_shadowsocks_user_with_identity_method(
        &self,
        identity_method: Option<&str>,
        user: &proto::xray::common::protocol::User,
    ) -> Result<ShadowsocksUser, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument(
                "AddUserOperation.user.account is required for shadowsocks",
            )
        })?;
        let account_type = Self::parse_typed_message_type(account);
        let (method, password) = if let Some(identity_method) = identity_method {
            if account_type != TYPE_PROXY_SHADOWSOCKS_2022_ACCOUNT {
                return Err(Status::invalid_argument(
                    "shadowsocks 2022 inbound requires a shadowsocks_2022 account",
                ));
            }
            let payload =
                Shadowsocks2022AccountPayload::decode(account.value.as_slice())
                    .map_err(|err| {
                        Status::invalid_argument(format!(
                            "invalid shadowsocks 2022 account payload: {err}"
                        ))
                    })?;
            (identity_method.to_string(), payload.key)
        } else {
            if account_type != TYPE_PROXY_SHADOWSOCKS_ACCOUNT
                && account_type != TYPE_PROXY_SHADOWSOCKS_ACCOUNT_V2RAY
            {
                return Err(Status::invalid_argument(
                    "legacy shadowsocks inbound requires a shadowsocks account",
                ));
            }
            let payload =
                ShadowsocksAccountPayload::decode(account.value.as_slice())
                    .map_err(|err| {
                        Status::invalid_argument(format!(
                            "invalid shadowsocks account payload: {err}"
                        ))
                    })?;
            (
                Self::shadowsocks_method_for_cipher_type(payload.cipher_type)?
                    .to_string(),
                payload.password,
            )
        };

        let parsed = ShadowsocksUser {
            method,
            password,
            email: user.email.clone(),
            user_level: user.level,
        };
        crate::handler::shadowsocks::validate_user(&parsed).map_err(|err| {
            Status::invalid_argument(format!("invalid shadowsocks user: {err}"))
        })?;
        Ok(parsed)
    }

    #[cfg(feature = "shadowsocks")]
    pub(super) fn shadowsocks_method_for_cipher_type(
        cipher_type: i32,
    ) -> Result<&'static str, Status> {
        match cipher_type {
            5 => Ok("aes-128-gcm"),
            6 => Ok("aes-256-gcm"),
            7 => Ok("chacha20-ietf-poly1305"),
            8 => Ok("xchacha20-ietf-poly1305"),
            other => Err(Status::invalid_argument(format!(
                "unsupported legacy shadowsocks cipher type {other}"
            ))),
        }
    }

    #[cfg(feature = "shadowsocks")]
    pub(super) fn shadowsocks_cipher_type(method: &str) -> Result<i32, Status> {
        match method {
            "aes-128-gcm" => Ok(5),
            "aes-256-gcm" => Ok(6),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(7),
            "xchacha20-ietf-poly1305" | "xchacha20-poly1305" => Ok(8),
            other => Err(Status::failed_precondition(format!(
                "unsupported legacy shadowsocks cipher {other}"
            ))),
        }
    }

    #[cfg(feature = "shadowsocks")]
    pub(super) fn parse_trojan_user(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<TrojanUser, Status> {
        Ok(TrojanUser {
            password: self.parse_trojan_password(user)?,
            email: (!user.email.is_empty()).then(|| user.email.clone()),
            user_level: user.level,
        })
    }

    #[cfg(feature = "trojan")]
    pub(super) fn parse_trojan_inbound_config(
        &self,
        config: TrojanServerConfigPayload,
    ) -> Result<ServerProxyConfig, Status> {
        let users = config
            .users
            .iter()
            .map(|user| self.parse_trojan_user(user))
            .collect::<Result<Vec<_>, _>>()?;

        let mut fallbacks = Vec::with_capacity(config.fallbacks.len());
        for fallback in config.fallbacks {
            let dest = fallback.dest.trim();
            if dest.is_empty() {
                return Err(Status::invalid_argument(
                    "trojan fallback dest cannot be empty",
                ));
            }
            if !dest.contains(':') {
                return Err(Status::invalid_argument(
                    "trojan fallback dest must be host:port",
                ));
            }
            let dest = NetLocation::from_str(dest, None).map_err(|err| {
                Status::invalid_argument(format!(
                    "invalid trojan fallback dest {dest}: {err}"
                ))
            })?;
            fallbacks.push(crate::config::server_config::TrojanFallback {
                name: String::new(),
                alpn: String::new(),
                path: String::new(),
                dest,
                xver: 0,
            });
        }

        Ok(ServerProxyConfig::Trojan { users, fallbacks })
    }

    pub(super) fn parse_hysteria_client(
        &self,
        user: &proto::xray::common::protocol::User,
    ) -> Result<Hysteria2Client, Status> {
        let account = user.account.as_ref().ok_or_else(|| {
            Status::invalid_argument(
                "AddUserOperation.user.account is required for hysteria",
            )
        })?;
        let account_type = Self::parse_typed_message_type(account);
        if account_type != TYPE_PROXY_HYSTERIA_ACCOUNT {
            return Err(Status::invalid_argument(format!(
                "unsupported hysteria account type: {account_type}"
            )));
        }

        let payload = HysteriaAccountPayload::decode(account.value.as_slice())
            .map_err(|err| {
                Status::invalid_argument(format!(
                    "invalid hysteria account payload: {err}"
                ))
            })?;
        let auth = payload.auth.as_str();

        Ok(Hysteria2Client {
            password: auth.to_string(),
            email: if user.email.is_empty() {
                None
            } else {
                Some(user.email.clone())
            },
            level: user.level,
            xray_uuid_route: true,
            xray_transport_auth_fallback: false,
        })
    }
}
