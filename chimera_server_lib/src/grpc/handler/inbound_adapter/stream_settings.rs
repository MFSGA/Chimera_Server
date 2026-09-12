use super::*;

impl HandlerServiceImpl {
    pub(in crate::grpc::handler) fn xhttp_settings_json(
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

    pub(in crate::grpc::handler) fn apply_add_inbound_xhttp_quic_params(
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

    pub(in crate::grpc::handler) fn apply_add_inbound_stream_settings(
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
    pub(in crate::grpc::handler) fn parse_reality_version(
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
}
