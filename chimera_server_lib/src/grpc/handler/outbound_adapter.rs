use super::*;

impl HandlerServiceImpl {
    pub(super) fn parse_add_outbound(
        &self,
        outbound: proto::xray::core::OutboundHandlerConfig,
    ) -> Result<OutboundSummary, Status> {
        if outbound.tag.trim().is_empty() {
            return Err(Status::invalid_argument("outbound tag is required"));
        }
        let proxy_settings = outbound.proxy_settings.as_ref().ok_or_else(|| {
            Status::invalid_argument("outbound.proxy_settings is required")
        })?;
        let protocol = match Self::parse_typed_message_type(proxy_settings) {
            TYPE_PROXY_FREEDOM_CONFIG | TYPE_PROXY_FREEDOM_CONFIG_V2RAY => {
                let _ = self.decode_typed_message::<FreedomConfigPayload>(
                    proxy_settings,
                    &[TYPE_PROXY_FREEDOM_CONFIG, TYPE_PROXY_FREEDOM_CONFIG_V2RAY],
                    "outbound proxy settings",
                )?;
                "freedom"
            }
            TYPE_PROXY_SOCKS_CLIENT_CONFIG
            | TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY => {
                let config = self.decode_typed_message::<SocksClientConfigPayload>(
                    proxy_settings,
                    &[
                        TYPE_PROXY_SOCKS_CLIENT_CONFIG,
                        TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY,
                    ],
                    "socks outbound proxy settings",
                )?;
                let server = config.server.ok_or_else(|| {
                    Status::invalid_argument(
                        "socks outbound requires a server endpoint",
                    )
                })?;
                let _ = self.parse_address(server.address)?;
                if !(1..=u32::from(u16::MAX)).contains(&server.port) {
                    return Err(Status::invalid_argument(
                        "socks outbound server port must be between 1 and 65535",
                    ));
                }
                "socks"
            }
            #[cfg(feature = "vless")]
            TYPE_PROXY_VLESS_OUTBOUND_CONFIG
            | TYPE_PROXY_VLESS_OUTBOUND_CONFIG_V2RAY => {
                if outbound.sender_settings.is_some() {
                    return Err(Status::unimplemented(
                        "dynamic VLESS outbound senderSettings/transport are not implemented yet",
                    ));
                }
                let config = self
                    .decode_typed_message::<VlessOutboundConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_VLESS_OUTBOUND_CONFIG,
                            TYPE_PROXY_VLESS_OUTBOUND_CONFIG_V2RAY,
                        ],
                        "vless outbound proxy settings",
                    )?;
                let server = config.vnext.ok_or_else(|| {
                    Status::invalid_argument(
                        "vless outbound requires a vnext endpoint",
                    )
                })?;
                let _ = self.parse_address(server.address)?;
                if !(1..=u32::from(u16::MAX)).contains(&server.port) {
                    return Err(Status::invalid_argument(
                        "vless outbound server port must be between 1 and 65535",
                    ));
                }
                let account =
                    server.user.and_then(|user| user.account).ok_or_else(|| {
                        Status::invalid_argument(
                            "vless outbound requires exactly one user",
                        )
                    })?;
                let account_type = Self::parse_typed_message_type(&account);
                if account_type != TYPE_PROXY_VLESS_ACCOUNT
                    && account_type != TYPE_PROXY_VLESS_ACCOUNT_V2RAY
                {
                    return Err(Status::invalid_argument(format!(
                        "unsupported vless outbound account type: {account_type}"
                    )));
                }
                let account =
                    VlessOutboundAccountPayload::decode(account.value.as_slice())
                        .map_err(|error| {
                            Status::invalid_argument(format!(
                                "invalid vless outbound account payload: {error}"
                            ))
                        })?;
                crate::outbound::parse_xray_uuid(&account.id)
                    .map_err(Status::invalid_argument)?;
                if !account.flow.trim().is_empty() {
                    return Err(Status::unimplemented(format!(
                        "dynamic VLESS outbound flow {} is not implemented yet",
                        account.flow
                    )));
                }
                if !account.encryption.trim().eq_ignore_ascii_case("none") {
                    return Err(Status::unimplemented(format!(
                        "dynamic VLESS outbound encryption {} is not implemented",
                        account.encryption
                    )));
                }
                "vless"
            }
            #[cfg(feature = "trojan")]
            TYPE_PROXY_TROJAN_CLIENT_CONFIG
            | TYPE_PROXY_TROJAN_CLIENT_CONFIG_V2RAY => {
                if let Some(sender_settings) = outbound.sender_settings.as_ref() {
                    crate::outbound::validate_outbound_sender_settings(
                        Some(sender_settings.r#type.as_str()),
                        Some(sender_settings.value.as_slice()),
                    )
                    .map_err(|error| match error.kind() {
                        std::io::ErrorKind::Unsupported => {
                            Status::unimplemented(error.to_string())
                        }
                        _ => Status::invalid_argument(error.to_string()),
                    })?;
                }
                let config = self
                    .decode_typed_message::<TrojanClientConfigPayload>(
                        proxy_settings,
                        &[
                            TYPE_PROXY_TROJAN_CLIENT_CONFIG,
                            TYPE_PROXY_TROJAN_CLIENT_CONFIG_V2RAY,
                        ],
                        "trojan outbound proxy settings",
                    )?;
                let server = config.server.ok_or_else(|| {
                    Status::invalid_argument(
                        "trojan outbound requires a server endpoint",
                    )
                })?;
                let _ = self.parse_address(server.address)?;
                if !(1..=u32::from(u16::MAX)).contains(&server.port) {
                    return Err(Status::invalid_argument(
                        "trojan outbound server port must be between 1 and 65535",
                    ));
                }
                let account =
                    server.user.and_then(|user| user.account).ok_or_else(|| {
                        Status::invalid_argument(
                            "trojan outbound requires exactly one user",
                        )
                    })?;
                let account_type = Self::parse_typed_message_type(&account);
                if account_type != TYPE_PROXY_TROJAN_ACCOUNT
                    && account_type != TYPE_PROXY_TROJAN_ACCOUNT_V2RAY
                {
                    return Err(Status::invalid_argument(format!(
                        "unsupported trojan outbound account type: {account_type}"
                    )));
                }
                let account = TrojanAccountPayload::decode(account.value.as_slice())
                    .map_err(|error| {
                        Status::invalid_argument(format!(
                            "invalid trojan outbound account payload: {error}"
                        ))
                    })?;
                if account.password.is_empty() {
                    return Err(Status::invalid_argument(
                        "trojan outbound password is required",
                    ));
                }
                "trojan"
            }
            TYPE_PROXY_BLACKHOLE_CONFIG => {
                let _ = self.decode_typed_message::<BlackholeConfigPayload>(
                    proxy_settings,
                    &[TYPE_PROXY_BLACKHOLE_CONFIG],
                    "outbound proxy settings",
                )?;
                "blackhole"
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported outbound proxy settings type: {other}"
                )));
            }
        };
        Ok(OutboundSummary {
            tag: outbound.tag,
            protocol: protocol.to_string(),
            proxy_settings_type: Some(proxy_settings.r#type.clone()),
            proxy_settings_value: Some(proxy_settings.value.clone()),
            sender_settings_type: outbound
                .sender_settings
                .as_ref()
                .map(|settings| settings.r#type.clone()),
            sender_settings_value: outbound
                .sender_settings
                .as_ref()
                .map(|settings| settings.value.clone()),
        })
    }

    pub(super) fn typed_message<T: Message>(
        message_type: &str,
        payload: T,
    ) -> proto::xray::common::serial::TypedMessage {
        proto::xray::common::serial::TypedMessage {
            r#type: message_type.to_string(),
            value: payload.encode_to_vec(),
        }
    }

    fn encode_address(address: &Address) -> Option<IpOrDomainPayload> {
        let address = match address {
            Address::Ipv4(addr) => {
                Some(ip_or_domain_payload::Address::Ip(addr.octets().to_vec()))
            }
            Address::Ipv6(addr) => {
                Some(ip_or_domain_payload::Address::Ip(addr.octets().to_vec()))
            }
            Address::Hostname(hostname) if !hostname.is_empty() => {
                Some(ip_or_domain_payload::Address::Domain(hostname.clone()))
            }
            Address::Hostname(_) => None,
        }?;
        Some(IpOrDomainPayload {
            address: Some(address),
        })
    }

    fn encode_receiver_settings(
        &self,
        inbound: &ServerConfig,
        stream_settings: Option<StreamConfigPayload>,
    ) -> proto::xray::common::serial::TypedMessage {
        let (address, port) = match &inbound.bind_location {
            BindLocation::Address(location) => location.components(),
        };
        Self::typed_message(
            TYPE_APP_RECEIVER_CONFIG,
            ReceiverConfigPayload {
                port_list: Some(PortListPayload {
                    range: vec![PortRangePayload {
                        from: u32::from(port),
                        to: u32::from(port),
                    }],
                }),
                listen: Self::encode_address(address),
                stream_settings,
            },
        )
    }

    fn encode_user_manager_protocol(
        &self,
        protocol: &ServerProxyConfig,
    ) -> Option<proto::xray::common::serial::TypedMessage> {
        match protocol {
            #[cfg(feature = "vless")]
            ServerProxyConfig::Vless { users, .. } => {
                let clients = users
                    .iter()
                    .map(|user| proto::xray::common::protocol::User {
                        level: 0,
                        email: user.user_label.clone(),
                        account: Some(Self::typed_message(
                            TYPE_PROXY_VLESS_ACCOUNT,
                            VlessAccountPayload {
                                id: user.user_id.clone(),
                                flow: user.flow.clone(),
                            },
                        )),
                    })
                    .collect();
                Some(Self::typed_message(
                    TYPE_PROXY_VLESS_INBOUND_CONFIG,
                    VlessInboundConfigPayload { clients },
                ))
            }
            #[cfg(feature = "vmess")]
            ServerProxyConfig::Vmess { users } => {
                let users = users
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
                            account: Some(Self::typed_message(
                                TYPE_PROXY_VMESS_ACCOUNT,
                                VmessAccountPayload {
                                    id: user.user_id.clone(),
                                    security_settings: Some(
                                        VmessSecurityConfigPayload {
                                            r#type: security_type,
                                        },
                                    ),
                                    tests_enabled: String::new(),
                                },
                            )),
                        }
                    })
                    .collect();
                Some(Self::typed_message(
                    TYPE_PROXY_VMESS_INBOUND_CONFIG,
                    VmessInboundConfigPayload { users },
                ))
            }
            #[cfg(feature = "trojan")]
            ServerProxyConfig::Trojan { users, fallbacks } => {
                let users = users
                    .iter()
                    .map(|user| proto::xray::common::protocol::User {
                        level: 0,
                        email: user.email.clone().unwrap_or_default(),
                        account: Some(Self::typed_message(
                            TYPE_PROXY_TROJAN_ACCOUNT,
                            TrojanAccountPayload {
                                password: user.password.clone(),
                            },
                        )),
                    })
                    .collect();
                let fallbacks = fallbacks
                    .iter()
                    .map(|fallback| TrojanFallbackPayload {
                        dest: fallback.dest.to_string(),
                    })
                    .collect();
                Some(Self::typed_message(
                    TYPE_PROXY_TROJAN_SERVER_CONFIG,
                    TrojanServerConfigPayload { users, fallbacks },
                ))
            }
            ServerProxyConfig::Socks {
                accounts,
                udp_enabled,
                udp_response_ip,
                user_level,
            } => {
                let auth_type = i32::from(accounts.auth_required());
                let account_map = accounts
                    .snapshot()
                    .iter()
                    .map(|account| {
                        (account.username.clone(), account.password.clone())
                    })
                    .collect();
                Some(Self::typed_message(
                    TYPE_PROXY_SOCKS_SERVER_CONFIG,
                    SocksServerConfigPayload {
                        auth_type,
                        accounts: account_map,
                        address: udp_response_ip.as_deref().and_then(|address| {
                            Address::from(address)
                                .ok()
                                .and_then(|address| Self::encode_address(&address))
                        }),
                        udp_enabled: *udp_enabled,
                        user_level: *user_level,
                    },
                ))
            }
            ServerProxyConfig::DokodemoDoor { config } => {
                let (address, port) = config.target.components();
                Some(Self::typed_message(
                    TYPE_PROXY_DOKODEMO_CONFIG,
                    DokodemoConfigPayload {
                        address: Self::encode_address(address),
                        port: u32::from(port),
                        port_map: std::collections::HashMap::new(),
                        networks: vec![
                            proto::xray::common::net::Network::Tcp as i32,
                        ],
                        follow_redirect: config.follow_redirect,
                        user_level: 0,
                    },
                ))
            }
            _ => None,
        }
    }

    pub(super) fn encode_inbound_config(
        &self,
        inbound: &ServerConfig,
    ) -> proto::xray::core::InboundHandlerConfig {
        let (stream_settings, proxy_settings) =
            self.encode_inbound_protocol_layers(&inbound.protocol);
        proto::xray::core::InboundHandlerConfig {
            tag: inbound.tag.clone(),
            receiver_settings: Some(
                self.encode_receiver_settings(inbound, stream_settings),
            ),
            proxy_settings,
        }
    }

    fn encode_xhttp_config(
        config: &crate::config::server_config::XhttpServerConfig,
    ) -> XhttpConfigPayload {
        fn range(from: usize, to: usize) -> XhttpRangePayload {
            XhttpRangePayload {
                from: from.min(i32::MAX as usize) as i32,
                to: to.min(i32::MAX as usize) as i32,
            }
        }

        let xhttp_mode = match config.mode {
            crate::config::server_config::XhttpMode::Auto => "auto",
            crate::config::server_config::XhttpMode::PacketUp => "packet-up",
            crate::config::server_config::XhttpMode::StreamUp => "stream-up",
            crate::config::server_config::XhttpMode::StreamOne => "stream-one",
        };
        let padding_placement = match config.padding_placement {
            crate::config::server_config::XhttpPaddingPlacement::Cookie => "cookie",
            crate::config::server_config::XhttpPaddingPlacement::Header => "header",
            crate::config::server_config::XhttpPaddingPlacement::Query => "query",
            crate::config::server_config::XhttpPaddingPlacement::QueryInHeader => {
                "queryInHeader"
            }
        };
        let padding_method = match config.padding_method {
            crate::config::server_config::XhttpPaddingMethod::RepeatX => "repeat-x",
            crate::config::server_config::XhttpPaddingMethod::Tokenish => "tokenish",
        };
        let session_placement = match config.session_placement {
            crate::config::server_config::XhttpPlacement::Path => "path",
            crate::config::server_config::XhttpPlacement::Query => "query",
            crate::config::server_config::XhttpPlacement::Header => "header",
            crate::config::server_config::XhttpPlacement::Cookie => "cookie",
        };
        let seq_placement = match config.seq_placement {
            crate::config::server_config::XhttpPlacement::Path => "path",
            crate::config::server_config::XhttpPlacement::Query => "query",
            crate::config::server_config::XhttpPlacement::Header => "header",
            crate::config::server_config::XhttpPlacement::Cookie => "cookie",
        };
        let uplink_data_placement = match config.uplink_data_placement {
            crate::config::server_config::XhttpDataPlacement::Auto => "auto",
            crate::config::server_config::XhttpDataPlacement::Body => "body",
            crate::config::server_config::XhttpDataPlacement::Header => "header",
            crate::config::server_config::XhttpDataPlacement::Cookie => "cookie",
        };

        XhttpConfigPayload {
            host: config.host.clone().unwrap_or_default(),
            path: config.path.clone(),
            mode: xhttp_mode.to_string(),
            headers: std::collections::HashMap::new(),
            x_padding_bytes: Some(range(config.min_padding, config.max_padding)),
            no_grpc_header: config.no_grpc_header,
            no_sse_header: config.no_sse_header,
            sc_max_each_post_bytes: Some(XhttpRangePayload {
                from: config
                    .max_each_post_bytes
                    .clamp(i64::from(i32::MIN), i64::from(i32::MAX))
                    as i32,
                to: config
                    .max_each_post_bytes
                    .clamp(i64::from(i32::MIN), i64::from(i32::MAX))
                    as i32,
            }),
            sc_min_posts_interval_ms: Some(range(
                config.min_posts_interval_ms.0,
                config.min_posts_interval_ms.1,
            )),
            sc_max_buffered_posts: config.max_buffered_posts.min(i64::MAX as usize)
                as i64,
            sc_stream_up_server_secs: Some(range(
                config.stream_up_server_secs.0,
                config.stream_up_server_secs.1,
            )),
            xmux: None,
            download_settings: None,
            x_padding_obfs_mode: config.padding_obfs_mode,
            x_padding_key: config.padding_key.clone(),
            x_padding_header: config.padding_header.clone(),
            x_padding_placement: padding_placement.to_string(),
            x_padding_method: padding_method.to_string(),
            uplink_http_method: config.uplink_http_method.clone(),
            session_id_placement: session_placement.to_string(),
            session_id_key: config.session_key.clone(),
            seq_placement: seq_placement.to_string(),
            seq_key: config.seq_key.clone(),
            uplink_data_placement: uplink_data_placement.to_string(),
            uplink_data_key: config.uplink_data_key.clone(),
            uplink_chunk_size: None,
            server_max_header_bytes: config
                .server_max_header_bytes
                .min(i32::MAX as usize) as i32,
            session_id_table: String::new(),
            session_id_length: None,
        }
    }

    pub(super) fn encode_inbound_protocol_layers(
        &self,
        protocol: &ServerProxyConfig,
    ) -> (
        Option<StreamConfigPayload>,
        Option<proto::xray::common::serial::TypedMessage>,
    ) {
        match protocol {
            #[cfg(feature = "ws")]
            ServerProxyConfig::Websocket { targets } => {
                let target = match targets.as_ref() {
                    crate::util::option::OneOrSome::One(target) => target,
                    crate::util::option::OneOrSome::Some(targets) => {
                        let Some(target) = targets.first() else {
                            return (None, None);
                        };
                        target
                    }
                };
                let mut headers =
                    target.matching_headers.clone().unwrap_or_default();
                let host = headers
                    .remove("Host")
                    .or_else(|| headers.remove("host"))
                    .unwrap_or_default();
                let websocket = Self::typed_message(
                    TYPE_TRANSPORT_WEBSOCKET_CONFIG,
                    WebsocketConfigPayload {
                        host,
                        path: target.matching_path.clone().unwrap_or_default(),
                        header: headers,
                        accept_proxy_protocol: target.accept_proxy_protocol,
                        ed: 0,
                        heartbeat_period: target.heartbeat_period,
                    },
                );
                let (mut stream_settings, proxy_settings) =
                    self.encode_inbound_protocol_layers(&target.protocol);
                let settings =
                    stream_settings.get_or_insert_with(|| StreamConfigPayload {
                        protocol_name: "websocket".to_string(),
                        transport_settings: Vec::new(),
                        security_type: String::new(),
                        security_settings: Vec::new(),
                        quic_params: None,
                    });
                settings.protocol_name = "websocket".to_string();
                settings.transport_settings.push(TransportConfigPayload {
                    settings: Some(websocket),
                    protocol_name: "websocket".to_string(),
                });
                (stream_settings, proxy_settings)
            }
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => {
                let (mut stream_settings, proxy_settings) =
                    self.encode_inbound_protocol_layers(&tls.inner);
                let settings =
                    stream_settings.get_or_insert_with(|| StreamConfigPayload {
                        protocol_name: "tcp".to_string(),
                        transport_settings: Vec::new(),
                        security_type: String::new(),
                        security_settings: Vec::new(),
                        quic_params: None,
                    });
                settings.security_type = "tls".to_string();
                settings.security_settings.push(Self::typed_message(
                    TYPE_TRANSPORT_TLS_CONFIG,
                    TlsConfigPayload {
                        certificate: tls
                            .certificates
                            .iter()
                            .map(|certificate| TlsCertificatePayload {
                                certificate: certificate.certificate_pem.clone(),
                                key: certificate.key_pem.clone().unwrap_or_default(),
                                certificate_path: certificate
                                    .certificate_path
                                    .clone()
                                    .unwrap_or_default(),
                                key_path: certificate
                                    .key_path
                                    .clone()
                                    .unwrap_or_default(),
                            })
                            .collect(),
                        server_name: tls.server_name.clone().unwrap_or_default(),
                        next_protocol: tls.alpn_protocols.clone(),
                        disable_system_root: false,
                    },
                ));
                (stream_settings, proxy_settings)
            }
            #[cfg(feature = "reality")]
            ServerProxyConfig::Reality(reality) => {
                let (mut stream_settings, proxy_settings) =
                    self.encode_inbound_protocol_layers(&reality.inner);
                let settings =
                    stream_settings.get_or_insert_with(|| StreamConfigPayload {
                        protocol_name: "tcp".to_string(),
                        transport_settings: Vec::new(),
                        security_type: String::new(),
                        security_settings: Vec::new(),
                        quic_params: None,
                    });
                settings.security_type = "reality".to_string();
                settings.security_settings.push(Self::typed_message(
                    TYPE_TRANSPORT_REALITY_CONFIG,
                    RealityConfigPayload {
                        dest: reality.dest.to_string(),
                        server_names: reality.server_names.clone(),
                        private_key: reality.private_key.to_vec(),
                        min_client_ver: reality
                            .min_client_version
                            .map(|version| version.to_vec())
                            .unwrap_or_default(),
                        max_client_ver: reality
                            .max_client_version
                            .map(|version| version.to_vec())
                            .unwrap_or_default(),
                        max_time_diff: reality.max_time_diff.unwrap_or_default(),
                        short_ids: reality
                            .short_ids
                            .iter()
                            .map(|short_id| short_id.to_vec())
                            .collect(),
                        ..RealityConfigPayload::default()
                    },
                ));
                (stream_settings, proxy_settings)
            }
            ServerProxyConfig::Xhttp { config, inner } => {
                let (mut stream_settings, proxy_settings) =
                    self.encode_inbound_protocol_layers(inner);
                let settings =
                    stream_settings.get_or_insert_with(|| StreamConfigPayload {
                        protocol_name: "xhttp".to_string(),
                        transport_settings: Vec::new(),
                        security_type: String::new(),
                        security_settings: Vec::new(),
                        quic_params: None,
                    });
                settings.protocol_name = "xhttp".to_string();
                settings.transport_settings.push(TransportConfigPayload {
                    settings: Some(Self::typed_message(
                        TYPE_TRANSPORT_XHTTP_CONFIG,
                        Self::encode_xhttp_config(config),
                    )),
                    protocol_name: "xhttp".to_string(),
                });
                settings.quic_params = match (
                    config.xray_max_idle_timeout_secs,
                    config.xray_max_incoming_streams,
                    config.xray_max_stream_receive_window,
                    config.xray_max_connection_receive_window,
                    config.xray_disable_path_mtu_discovery,
                ) {
                    (None, None, None, None, None) => None,
                    _ => Some(QuicParamsPayload {
                        congestion: String::new(),
                        bbr_profile: String::new(),
                        init_stream_receive_window: config
                            .xray_init_stream_receive_window
                            .unwrap_or_default(),
                        max_stream_receive_window: config
                            .xray_max_stream_receive_window
                            .unwrap_or_default(),
                        init_connection_receive_window: config
                            .xray_init_connection_receive_window
                            .unwrap_or_default(),
                        max_connection_receive_window: config
                            .xray_max_connection_receive_window
                            .unwrap_or_default(),
                        max_idle_timeout: config
                            .xray_max_idle_timeout_secs
                            .unwrap_or_default()
                            as i64,
                        keep_alive_period: 0,
                        disable_path_mtu_discovery: config
                            .xray_disable_path_mtu_discovery
                            .unwrap_or(false),
                        max_incoming_streams: config
                            .xray_max_incoming_streams
                            .unwrap_or_default()
                            as i64,
                    }),
                };
                (stream_settings, proxy_settings)
            }
            protocol => (None, self.encode_user_manager_protocol(protocol)),
        }
    }

    pub(super) fn encode_outbound_config(
        &self,
        outbound: &OutboundSummary,
    ) -> proto::xray::core::OutboundHandlerConfig {
        let proxy_settings = match (
            outbound.proxy_settings_type.as_ref(),
            outbound.proxy_settings_value.as_ref(),
        ) {
            (Some(r#type), Some(value)) => {
                Some(proto::xray::common::serial::TypedMessage {
                    r#type: r#type.clone(),
                    value: value.clone(),
                })
            }
            _ => match outbound.protocol.as_str() {
                "freedom" => Some(Self::typed_message(
                    TYPE_PROXY_FREEDOM_CONFIG,
                    FreedomConfigPayload {},
                )),
                "blackhole" => Some(Self::typed_message(
                    TYPE_PROXY_BLACKHOLE_CONFIG,
                    BlackholeConfigPayload {},
                )),
                _ => None,
            },
        };
        proto::xray::core::OutboundHandlerConfig {
            tag: outbound.tag.clone(),
            sender_settings: None,
            proxy_settings,
            expire: 0,
            comment: String::new(),
        }
    }
}
