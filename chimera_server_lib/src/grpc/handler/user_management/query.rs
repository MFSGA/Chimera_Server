use super::*;

impl HandlerServiceImpl {
    pub(in crate::grpc::handler) fn get_user_manager_identities(
        &self,
        protocol: &ServerProxyConfig,
    ) -> Option<Vec<String>> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => {
                Some(users.iter().map(|user| user.user_label.clone()).collect())
            }
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => {
                Some(users.iter().map(|user| user.user_label.clone()).collect())
            }
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => Some(
                users
                    .iter()
                    .filter_map(|user| {
                        user.email
                            .as_ref()
                            .filter(|email| !email.is_empty())
                            .cloned()
                    })
                    .collect(),
            ),
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => Some(
                config
                    .clients
                    .iter()
                    .filter(|client| !client.xray_transport_auth_fallback)
                    .map(|client| client.email.clone().unwrap_or_default())
                    .collect(),
            ),
            #[cfg(feature = "tuic")]
            ServerProxyConfig::TuicV5 { config } => Some(vec![config.uuid.clone()]),
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => {
                let mut identities = Vec::new();
                let mut handled = false;
                match targets.as_ref() {
                    crate::util::option::OneOrSome::One(target) => {
                        if let Some(items) =
                            self.get_user_manager_identities(&target.protocol)
                        {
                            identities.extend(items);
                            handled = true;
                        }
                    }
                    crate::util::option::OneOrSome::Some(list) => {
                        for target in list {
                            if let Some(items) =
                                self.get_user_manager_identities(&target.protocol)
                            {
                                identities.extend(items);
                                handled = true;
                            }
                        }
                    }
                }
                handled.then_some(identities)
            }
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => {
                self.get_user_manager_identities(&tls.inner)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.get_user_manager_identities(&reality.inner)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                self.get_user_manager_identities(inner)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.get_user_manager_identities(&config.inner)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.get_user_manager_identities(&config.inner)
            }
            ServerProxyConfig::Socks { .. } => None,
            #[cfg(feature = "http")]
            ServerProxyConfig::Http { .. } => None,
            #[cfg(feature = "mixed")]
            ServerProxyConfig::Mixed { .. } => None,
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { users, .. } => {
                Some(users.iter().map(|user| user.email.clone()).collect())
            }
            ServerProxyConfig::DokodemoDoor { .. } | ServerProxyConfig::Tunnel => {
                None
            }
            #[cfg(feature = "wireguard")]
            ServerProxyConfig::WireGuard { .. } => None,
        }
    }

    pub(in crate::grpc::handler) fn shadowsocks_user_manager(
        protocol: &ServerProxyConfig,
    ) -> bool {
        match protocol {
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { .. } => true,
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => match targets.as_ref() {
                crate::util::option::OneOrSome::One(target) => {
                    Self::shadowsocks_user_manager(&target.protocol)
                }
                crate::util::option::OneOrSome::Some(targets) => targets
                    .iter()
                    .any(|target| Self::shadowsocks_user_manager(&target.protocol)),
            },
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(config) => {
                Self::shadowsocks_user_manager(&config.inner)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(config) => {
                Self::shadowsocks_user_manager(&config.inner)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                Self::shadowsocks_user_manager(inner)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                Self::shadowsocks_user_manager(&config.inner)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                Self::shadowsocks_user_manager(&config.inner)
            }
            _ => false,
        }
    }

    pub(in crate::grpc::handler) fn select_user_manager_users(
        users: Vec<proto::xray::common::protocol::User>,
        email: &str,
        case_insensitive: bool,
    ) -> Vec<proto::xray::common::protocol::User> {
        if email.is_empty() {
            users
        } else {
            users
                .into_iter()
                .find(|user| {
                    if case_insensitive {
                        user.email.eq_ignore_ascii_case(email)
                    } else {
                        user.email == email
                    }
                })
                .into_iter()
                .collect()
        }
    }

    pub(in crate::grpc::handler) fn get_user_manager_users(
        &self,
        protocol: &ServerProxyConfig,
    ) -> Option<Vec<proto::xray::common::protocol::User>> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => Some(
                users
                    .iter()
                    .map(|user| proto::xray::common::protocol::User {
                        level: user.user_level,
                        email: user.user_label.clone(),
                        account: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                            value: VlessAccountWirePayload {
                                id: user.user_id.clone(),
                                flow: user.flow.clone(),
                                reverse: user.reverse.as_ref().map(|reverse| {
                                    VlessReversePayload {
                                        tag: reverse.tag.clone(),
                                        sniffing: None,
                                    }
                                }),
                            }
                            .encode_to_vec(),
                        }),
                    })
                    .collect(),
            ),
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => Some(
                users
                    .iter()
                    .map(|user| {
                        let security_type = match user.cipher.as_str() {
                            "aes-128-gcm" => 3,
                            "chacha20-poly1305" | "chacha20-ietf-poly1305" => 4,
                            _ => 2,
                        };
                        proto::xray::common::protocol::User {
                            level: 0,
                            email: user.user_label.clone(),
                            account: Some(
                                proto::xray::common::serial::TypedMessage {
                                    r#type: TYPE_PROXY_VMESS_ACCOUNT.to_string(),
                                    value: VmessAccountPayload {
                                        id: user.user_id.clone(),
                                        security_settings: Some(
                                            VmessSecurityConfigPayload {
                                                r#type: security_type,
                                            },
                                        ),
                                        tests_enabled: String::new(),
                                    }
                                    .encode_to_vec(),
                                },
                            ),
                        }
                    })
                    .collect(),
            ),
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, .. } => Some(
                users
                    .iter()
                    .filter(|user| {
                        user.email.as_deref().is_some_and(|email| !email.is_empty())
                    })
                    .map(|user| proto::xray::common::protocol::User {
                        level: user.user_level,
                        email: user.email.clone().unwrap_or_default(),
                        account: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                            value: TrojanAccountPayload {
                                password: user.password.clone(),
                            }
                            .encode_to_vec(),
                        }),
                    })
                    .collect(),
            ),
            #[cfg(feature = "hysteria")]
            ServerProxyConfig::Hysteria2 { config } => Some(
                config
                    .clients
                    .iter()
                    .filter(|client| !client.xray_transport_auth_fallback)
                    .map(|client| proto::xray::common::protocol::User {
                        level: client.level,
                        email: client.email.clone().unwrap_or_default(),
                        account: Some(proto::xray::common::serial::TypedMessage {
                            r#type: TYPE_PROXY_HYSTERIA_ACCOUNT.to_string(),
                            value: HysteriaAccountPayload {
                                auth: client.password.clone(),
                            }
                            .encode_to_vec(),
                        }),
                    })
                    .collect(),
            ),
            #[cfg(feature = "tuic")]
            ServerProxyConfig::TuicV5 { config } => {
                Some(vec![self.build_user(config.uuid.clone())])
            }
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => {
                let mut users = Vec::new();
                let mut handled = false;
                match targets.as_ref() {
                    crate::util::option::OneOrSome::One(target) => {
                        if let Some(items) =
                            self.get_user_manager_users(&target.protocol)
                        {
                            users.extend(items);
                            handled = true;
                        }
                    }
                    crate::util::option::OneOrSome::Some(list) => {
                        for target in list {
                            if let Some(items) =
                                self.get_user_manager_users(&target.protocol)
                            {
                                users.extend(items);
                                handled = true;
                            }
                        }
                    }
                }
                handled.then_some(users)
            }
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => self.get_user_manager_users(&tls.inner),
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                self.get_user_manager_users(&reality.inner)
            }
            ServerProxyConfig::Xhttp { inner, .. } => {
                self.get_user_manager_users(inner)
            }
            #[cfg(feature = "httpupgrade")]
            ServerProxyConfig::HttpUpgrade(config) => {
                self.get_user_manager_users(&config.inner)
            }
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                self.get_user_manager_users(&config.inner)
            }
            ServerProxyConfig::Socks { .. } => None,
            #[cfg(feature = "http")]
            ServerProxyConfig::Http { .. } => None,
            #[cfg(feature = "mixed")]
            ServerProxyConfig::Mixed { .. } => None,
            #[cfg(feature = "shadowsocks")]
            ServerProxyConfig::Shadowsocks { users, identity } => Some(
                users
                    .iter()
                    .map(|user| {
                        let account = if identity.is_some() {
                            Self::typed_message(
                                TYPE_PROXY_SHADOWSOCKS_2022_ACCOUNT,
                                Shadowsocks2022AccountPayload {
                                    key: user.password.clone(),
                                },
                            )
                        } else {
                            Self::typed_message(
                                TYPE_PROXY_SHADOWSOCKS_ACCOUNT,
                                ShadowsocksAccountPayload {
                                    password: user.password.clone(),
                                    cipher_type: Self::shadowsocks_cipher_type(
                                        &user.method,
                                    )
                                    .unwrap_or_default(),
                                    iv_check: false,
                                },
                            )
                        };
                        proto::xray::common::protocol::User {
                            level: user.user_level,
                            email: user.email.clone(),
                            account: Some(account),
                        }
                    })
                    .collect(),
            ),
            ServerProxyConfig::DokodemoDoor { .. } | ServerProxyConfig::Tunnel => {
                None
            }
            #[cfg(feature = "wireguard")]
            ServerProxyConfig::WireGuard { .. } => None,
        }
    }
}
