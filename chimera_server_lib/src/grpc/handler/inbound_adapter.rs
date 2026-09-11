use super::*;

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

        Ok(ServerConfig {
            tag: inbound.tag,
            bind_location: BindLocation::Address(NetLocation::new(address, port)),
            protocol,
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        })
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

    pub(super) fn xhttp_settings_json(
        config: XhttpConfigPayload,
    ) -> serde_json::Value {
        fn range_value(range: XhttpRangePayload) -> serde_json::Value {
            serde_json::json!({ "from": range.from, "to": range.to })
        }

        let mut settings = serde_json::Map::new();
        if !config.host.is_empty() {
            settings.insert("host".to_string(), config.host.into());
        }
        if !config.path.is_empty() {
            settings.insert("path".to_string(), config.path.into());
        }
        if !config.mode.is_empty() {
            settings.insert("mode".to_string(), config.mode.into());
        }
        if !config.headers.is_empty() {
            settings
                .insert("headers".to_string(), serde_json::json!(config.headers));
        }
        if let Some(range) = config.x_padding_bytes {
            settings.insert("xPaddingBytes".to_string(), range_value(range));
        }
        if config.no_grpc_header {
            settings.insert("noGRPCHeader".to_string(), true.into());
        }
        if config.no_sse_header {
            settings.insert("noSSEHeader".to_string(), true.into());
        }
        if let Some(range) = config.sc_max_each_post_bytes {
            settings.insert("scMaxEachPostBytes".to_string(), range_value(range));
        }
        if let Some(range) = config.sc_min_posts_interval_ms {
            settings.insert("scMinPostsIntervalMs".to_string(), range_value(range));
        }
        if config.sc_max_buffered_posts != 0 {
            settings.insert(
                "scMaxBufferedPosts".to_string(),
                config.sc_max_buffered_posts.into(),
            );
        }
        if let Some(range) = config.sc_stream_up_server_secs {
            settings.insert("scStreamUpServerSecs".to_string(), range_value(range));
        }
        if let Some(xmux) = config.xmux {
            let mut xmux_settings = serde_json::Map::new();
            if let Some(range) = xmux.max_concurrency {
                xmux_settings
                    .insert("maxConcurrency".to_string(), range_value(range));
            }
            if let Some(range) = xmux.max_connections {
                xmux_settings
                    .insert("maxConnections".to_string(), range_value(range));
            }
            if !xmux_settings.is_empty() {
                settings.insert("xmux".to_string(), xmux_settings.into());
            }
        }
        if config.download_settings.is_some() {
            settings.insert("downloadSettings".to_string(), serde_json::json!({}));
        }
        if config.x_padding_obfs_mode {
            settings.insert("xPaddingObfsMode".to_string(), true.into());
        }
        for (key, value) in [
            ("xPaddingKey", config.x_padding_key),
            ("xPaddingHeader", config.x_padding_header),
            ("xPaddingPlacement", config.x_padding_placement),
            ("xPaddingMethod", config.x_padding_method),
            ("uplinkHTTPMethod", config.uplink_http_method),
            ("sessionIDPlacement", config.session_id_placement),
            ("sessionIDKey", config.session_id_key),
            ("seqPlacement", config.seq_placement),
            ("seqKey", config.seq_key),
            ("uplinkDataPlacement", config.uplink_data_placement),
            ("uplinkDataKey", config.uplink_data_key),
            ("sessionIDTable", config.session_id_table),
        ] {
            if !value.is_empty() {
                settings.insert(key.to_string(), value.into());
            }
        }
        if let Some(range) = config.uplink_chunk_size {
            settings.insert("uplinkChunkSize".to_string(), range_value(range));
        }
        if config.server_max_header_bytes != 0 {
            settings.insert(
                "serverMaxHeaderBytes".to_string(),
                config.server_max_header_bytes.into(),
            );
        }
        if let Some(range) = config.session_id_length {
            settings.insert("sessionIDLength".to_string(), range_value(range));
        }
        serde_json::Value::Object(settings)
    }

    pub(super) fn apply_add_inbound_xhttp_quic_params(
        config: &mut crate::config::server_config::XhttpServerConfig,
        params: Option<QuicParamsPayload>,
    ) -> Result<(), Status> {
        let Some(params) = params else {
            return Ok(());
        };

        match params.congestion.to_ascii_lowercase().as_str() {
            "" | "brutal" | "reno" | "bbr" | "force-brutal" => {}
            congestion => {
                return Err(Status::invalid_argument(format!(
                    "streamSettings.quicParams.congestion is unsupported: {congestion}"
                )));
            }
        }
        if params.max_idle_timeout != 0
            && !(4..=120).contains(&params.max_idle_timeout)
        {
            return Err(Status::invalid_argument(
                "streamSettings.quicParams.maxIdleTimeout must be 0 or between 4 and 120 seconds",
            ));
        }
        if params.keep_alive_period != 0
            && !(2..=60).contains(&params.keep_alive_period)
        {
            return Err(Status::invalid_argument(
                "streamSettings.quicParams.keepAlivePeriod must be 0 or between 2 and 60 seconds",
            ));
        }
        if params.max_incoming_streams != 0 && params.max_incoming_streams < 8 {
            return Err(Status::invalid_argument(
                "streamSettings.quicParams.maxIncomingStreams must be 0 or at least 8",
            ));
        }
        for (field, value) in [
            ("initStreamReceiveWindow", params.init_stream_receive_window),
            ("maxStreamReceiveWindow", params.max_stream_receive_window),
            (
                "initConnectionReceiveWindow",
                params.init_connection_receive_window,
            ),
            (
                "maxConnectionReceiveWindow",
                params.max_connection_receive_window,
            ),
        ] {
            if value != 0 && value < 16_384 {
                return Err(Status::invalid_argument(format!(
                    "streamSettings.quicParams.{field} must be 0 or at least 16384"
                )));
            }
        }
        config.xray_max_idle_timeout_secs =
            (params.max_idle_timeout != 0).then_some(params.max_idle_timeout as u64);
        config.xray_max_incoming_streams = (params.max_incoming_streams != 0)
            .then_some((params.max_incoming_streams as u64).min(1_u64 << 60));
        config.xray_init_stream_receive_window =
            Some(params.init_stream_receive_window);
        config.xray_max_stream_receive_window =
            Some(params.max_stream_receive_window);
        config.xray_init_connection_receive_window =
            Some(params.init_connection_receive_window);
        config.xray_max_connection_receive_window =
            Some(params.max_connection_receive_window);
        config.xray_disable_path_mtu_discovery =
            Some(params.disable_path_mtu_discovery);
        Ok(())
    }

    pub(super) fn apply_add_inbound_stream_settings(
        &self,
        mut protocol: ServerProxyConfig,
        stream_settings: StreamConfigPayload,
    ) -> Result<ServerProxyConfig, Status> {
        let network = stream_settings.protocol_name.trim().to_ascii_lowercase();
        match network.as_str() {
            "" | "tcp" => {}
            #[cfg(feature = "ws")]
            "ws" | "websocket" => {
                let transport = stream_settings
                    .transport_settings
                    .iter()
                    .find_map(|item| {
                        let name = item.protocol_name.trim().to_ascii_lowercase();
                        (name == "ws" || name == "websocket")
                            .then_some(item.settings.as_ref())
                            .flatten()
                    })
                    .ok_or_else(|| {
                        Status::invalid_argument(
                            "websocket transport settings are required",
                        )
                    })?;
                let websocket = self
                    .decode_typed_message::<WebsocketConfigPayload>(
                        transport,
                        &[
                            TYPE_TRANSPORT_WEBSOCKET_CONFIG,
                            TYPE_TRANSPORT_WEBSOCKET_CONFIG_V2RAY,
                        ],
                        "websocket transport settings",
                    )?;
                let matching_headers = (!websocket.host.is_empty()).then(|| {
                    std::collections::HashMap::from([(
                        "host".to_string(),
                        websocket.host.clone(),
                    )])
                });
                protocol = ServerProxyConfig::Websocket {
                    targets: Box::new(OneOrSome::One(WebsocketServerConfig {
                        matching_path: Some(if websocket.path.is_empty() {
                            "/".to_string()
                        } else if websocket.path.starts_with('/') {
                            websocket.path
                        } else {
                            format!("/{}", websocket.path)
                        }),
                        matching_headers,
                        xray_mismatch_404: true,
                        trusted_x_forwarded_for: Vec::new(),
                        accept_proxy_protocol: websocket.accept_proxy_protocol,
                        heartbeat_period: websocket.heartbeat_period,
                        protocol,
                    })),
                };
            }
            "xhttp" | "splithttp" => {
                let transport = stream_settings
                    .transport_settings
                    .iter()
                    .find_map(|item| {
                        let name = item.protocol_name.trim().to_ascii_lowercase();
                        (name == "xhttp" || name == "splithttp")
                            .then_some(item.settings.as_ref())
                            .flatten()
                    })
                    .ok_or_else(|| {
                        Status::invalid_argument(
                            "xhttp transport settings are required",
                        )
                    })?;
                let xhttp = self.decode_typed_message::<XhttpConfigPayload>(
                    transport,
                    &[
                        TYPE_TRANSPORT_XHTTP_CONFIG,
                        TYPE_TRANSPORT_XHTTP_CONFIG_V2RAY,
                    ],
                    "xhttp transport settings",
                )?;
                let mut config =
                    crate::config::server_config::collect_xhttp_settings_from_json(
                        Self::xhttp_settings_json(xhttp),
                    )
                    .map_err(|error| Status::invalid_argument(error.to_string()))?;
                Self::apply_add_inbound_xhttp_quic_params(
                    &mut config,
                    stream_settings.quic_params,
                )?;
                protocol = ServerProxyConfig::Xhttp {
                    config,
                    inner: Box::new(protocol),
                };
            }
            unsupported => {
                return Err(Status::invalid_argument(format!(
                    "unsupported inbound network for AddInbound: {unsupported}"
                )));
            }
        }

        let security = stream_settings.security_type.trim().to_ascii_lowercase();
        match security.as_str() {
            "" | "none" => Ok(protocol),
            #[cfg(feature = "tls")]
            "tls" | TYPE_TRANSPORT_TLS_CONFIG | TYPE_TRANSPORT_TLS_CONFIG_V2RAY => {
                let security = stream_settings
                    .security_settings
                    .iter()
                    .find(|item| {
                        matches!(
                            Self::parse_typed_message_type(item),
                            TYPE_TRANSPORT_TLS_CONFIG
                                | TYPE_TRANSPORT_TLS_CONFIG_V2RAY
                        )
                    })
                    .ok_or_else(|| {
                        Status::invalid_argument(
                            "tls security settings are required",
                        )
                    })?;
                let tls = self.decode_typed_message::<TlsConfigPayload>(
                    security,
                    &[TYPE_TRANSPORT_TLS_CONFIG, TYPE_TRANSPORT_TLS_CONFIG_V2RAY],
                    "tls security settings",
                )?;
                let certificate = tls.certificate.first().ok_or_else(|| {
                    Status::invalid_argument(
                        "tls AddInbound requires at least one certificate",
                    )
                })?;
                let certificate_path = certificate.certificate_path.trim();
                let private_key_path = certificate.key_path.trim();
                if certificate_path.is_empty() && certificate.certificate.is_empty()
                {
                    return Err(Status::invalid_argument(
                        "tls AddInbound requires certificate_path or inline certificate PEM",
                    ));
                }
                if private_key_path.is_empty() && certificate.key.is_empty() {
                    return Err(Status::invalid_argument(
                        "tls AddInbound requires key_path or inline private key PEM",
                    ));
                }
                Ok(ServerProxyConfig::Tls(TlsServerConfig {
                    certificates: vec![TlsCertificateConfig {
                        certificate_path: (!certificate_path.is_empty())
                            .then(|| certificate_path.to_string()),
                        certificate_pem: certificate.certificate.clone(),
                        key_path: (!private_key_path.is_empty())
                            .then(|| private_key_path.to_string()),
                        key_pem: (!certificate.key.is_empty())
                            .then(|| certificate.key.clone()),
                        usage: TlsCertificateUsage::Encipherment,
                    }],
                    alpn_protocols: tls.next_protocol,
                    enable_session_resumption: false,
                    reject_unknown_sni: false,
                    min_version: None,
                    max_version: None,
                    server_name: None,
                    inner: Box::new(protocol),
                }))
            }
            #[cfg(feature = "reality")]
            "reality" | TYPE_TRANSPORT_REALITY_CONFIG => {
                let security = stream_settings
                    .security_settings
                    .iter()
                    .find(|item| {
                        Self::parse_typed_message_type(item)
                            == TYPE_TRANSPORT_REALITY_CONFIG
                    })
                    .ok_or_else(|| {
                        Status::invalid_argument(
                            "reality security settings are required",
                        )
                    })?;
                let reality = self.decode_typed_message::<RealityConfigPayload>(
                    security,
                    &[TYPE_TRANSPORT_REALITY_CONFIG],
                    "reality security settings",
                )?;
                let dest = NetLocation::from_str(reality.dest.trim(), Some(443))
                    .map_err(|err| {
                        Status::invalid_argument(format!(
                            "invalid reality.dest value: {} ({err})",
                            reality.dest
                        ))
                    })?;
                if !matches!(dest.address(), Address::Hostname(_)) {
                    return Err(Status::invalid_argument(
                        "reality.dest must be a hostname",
                    ));
                }
                let private_key: [u8; 32] =
                    reality.private_key.as_slice().try_into().map_err(|_| {
                        Status::invalid_argument(
                            "reality private_key must be exactly 32 bytes",
                        )
                    })?;
                let short_ids = reality
                    .short_ids
                    .into_iter()
                    .map(|short_id| {
                        short_id.as_slice().try_into().map_err(|_| {
                            Status::invalid_argument(
                                "reality short_ids entries must be exactly 8 bytes",
                            )
                        })
                    })
                    .collect::<Result<Vec<[u8; 8]>, Status>>()?;
                let min_client_version = self.parse_reality_version(
                    &reality.min_client_ver,
                    "min_client_ver",
                )?;
                let max_client_version = self.parse_reality_version(
                    &reality.max_client_ver,
                    "max_client_ver",
                )?;
                let mut server_names = reality.server_names;
                if server_names.is_empty()
                    && let Some(hostname) = dest.address().hostname()
                {
                    server_names.push(hostname.to_string());
                }
                Ok(ServerProxyConfig::Reality(RealityTransportConfig {
                    dest,
                    private_key,
                    short_ids,
                    cipher_suites: Vec::new(),
                    max_time_diff: (reality.max_time_diff > 0)
                        .then_some(reality.max_time_diff),
                    min_client_version,
                    max_client_version,
                    server_names,
                    inner: Box::new(protocol),
                }))
            }
            unsupported => Err(Status::invalid_argument(format!(
                "unsupported inbound security for AddInbound: {unsupported}"
            ))),
        }
    }

    #[cfg(feature = "reality")]
    pub(super) fn parse_reality_version(
        &self,
        bytes: &[u8],
        field: &str,
    ) -> Result<Option<[u8; 3]>, Status> {
        if bytes.is_empty() {
            return Ok(None);
        }
        let version = bytes.try_into().map_err(|_| {
            Status::invalid_argument(format!(
                "reality {field} must be exactly 3 bytes"
            ))
        })?;
        Ok(Some(version))
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
