use super::*;

pub(crate) async fn run_session_based_udp(
    mut server_stream: Box<dyn AsyncSessionMessageStream>,
    runtime: DataPlaneRuntime,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let traffic_context =
        traffic_context.map(|context| context.with_client_ip(peer_addr.ip()));
    let inbound_tag = traffic_context
        .as_ref()
        .and_then(|context| context.inbound_tag.as_deref())
        .unwrap_or_default()
        .to_string();
    let identity = traffic_context
        .as_ref()
        .and_then(|context| context.identity.as_deref())
        .unwrap_or_default()
        .to_string();
    let policy_identities = traffic_context
        .as_ref()
        .map(|context| context.policy_identities.as_slice())
        .unwrap_or_default();
    let _connection_guard = register_connection(traffic_context.as_ref());
    let resolver = runtime.resolver();
    #[cfg(feature = "trojan")]
    let trojan_resolver = resolver.clone();
    let (response_sender, mut response_receiver) =
        mpsc::channel::<SessionUdpEvent>(UDP_SESSION_CHANNEL_CAPACITY);
    let mut sessions = HashMap::<u16, SessionUdpWorker>::new();
    let mut next_generation = 1u64;
    let mut client_buffer = vec![0u8; UDP_BUFFER_SIZE];

    let result = loop {
        tokio::select! {
            request = read_session_message(&mut *server_stream, &mut client_buffer) => {
                let (
                    session_id,
                    target_location,
                    global_id,
                    is_new,
                    payload_length,
                ) = match request {
                    Ok((SessionMessage::Data {
                        session_id,
                        target,
                        global_id,
                        is_new,
                    }, payload_length)) => {
                        (session_id, target, global_id, is_new, payload_length)
                    }
                    Ok((SessionMessage::End { session_id }, _)) => {
                        expire_session_udp_worker(&mut sessions, session_id).await;
                        debug!("session udp {} ended by peer", session_id);
                        continue;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                        break Ok(());
                    }
                    Err(error) => break Err(error),
                };
                if is_new && sessions.contains_key(&session_id) {
                    expire_session_udp_worker(&mut sessions, session_id).await;
                }
                let mut payload = client_buffer[..payload_length].to_vec();
                if !is_new {
                    let existing_worker = sessions
                        .get(&session_id)
                        .filter(|worker| {
                            can_reuse_existing_session_target(
                                worker,
                                global_id,
                                &target_location,
                            )
                        })
                        .map(|worker| {
                            (worker.sender.clone(), worker.key.target_addr)
                        });
                    if let Some((sender, target_addr)) = existing_worker {
                        match sender.send_to(payload, target_addr).await {
                            Ok(()) => continue,
                            Err(retry_payload) => payload = retry_payload,
                        }
                    }
                }
                let (action, routed_target_addr) = match select_direct_outbound_for_location(
                    &resolver,
                    &target_location,
                    &runtime,
                    OutboundRoutingContext::new(
                        &inbound_tag,
                        &identity,
                        peer_addr,
                        3,
                        "udp",
                        InboundRoutingMetadata {
                            local_addr,
                            inbound_protocol: traffic_context
                                .as_ref()
                                .map(|context| context.protocol.to_string()),
                            ..InboundRoutingMetadata::default()
                        },
                    )
                    .with_policy_identities(policy_identities),
                )
                .await
                {
                    Ok(result) => result,
                    Err(error) => break Err(error),
                };

                match action {
                    DirectOutboundAction::Blackhole { tag } => {
                        let packet_context = traffic_context
                            .clone()
                            .map(|context| context.with_outbound_tag(tag.clone()));
                        record_transfer(packet_context, payload_length as u64, 0);
                        debug!(
                            "session udp packet {} to {} dropped by blackhole outbound {}",
                            session_id, target_location, tag
                        );
                    }
                    DirectOutboundAction::Freedom { tag, .. } => {
                        let target_addr = match routed_target_addr {
                            Some(target_addr) => target_addr,
                            None => {
                                break Err(std::io::Error::other(
                                    "session UDP freedom route did not resolve target",
                                ));
                            }
                        };
                        let packet_context = match &tag {
                            Some(tag) => traffic_context
                                .clone()
                                .map(|context| context.with_outbound_tag(tag.clone())),
                            None => traffic_context.clone(),
                        };
                        let key = TargetedUdpSessionKey {
                            target_addr,
                            outbound_tag: tag,
                        };
                        let sender = match plan_session_udp_worker(
                            sessions.get(&session_id),
                            &key,
                            global_id,
                        ) {
                            SessionUdpWorkerPlan::Reuse(sender) => sender,
                            SessionUdpWorkerPlan::Replace => {
                                match replace_session_udp_worker(
                                    &mut sessions,
                                    session_id,
                                    &mut next_generation,
                                    SessionUdpWorkerStart {
                                        key: key.clone(),
                                        route_target: target_location.clone(),
                                        response_sender: response_sender.clone(),
                                        traffic_context: packet_context.clone(),
                                        global_id,
                                        idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                    },
                                )
                                .await
                                {
                                    Ok(sender) => sender,
                                    Err(error) => break Err(error),
                                }
                            }
                        };

                        if let Err(retry_payload) = sender.send_to(payload, target_addr).await {
                            let retry_sender = match replace_session_udp_worker(
                                &mut sessions,
                                session_id,
                                &mut next_generation,
                                SessionUdpWorkerStart {
                                    key,
                                    route_target: target_location.clone(),
                                    response_sender: response_sender.clone(),
                                    traffic_context: packet_context,
                                    global_id,
                                    idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                },
                            )
                            .await
                            {
                                Ok(sender) => sender,
                                Err(error) => break Err(error),
                            };
                            if retry_sender
                                .send_to(retry_payload, target_addr)
                                .await
                                .is_err()
                            {
                                break Err(std::io::Error::new(
                                    std::io::ErrorKind::BrokenPipe,
                                    "session udp socket closed before payload was sent",
                                ));
                            }
                        }
                    }
                    DirectOutboundAction::Trojan { outbound } => {
                        #[cfg(feature = "trojan")]
                        {
                            if global_id.is_some() {
                                break Err(std::io::Error::new(
                                    std::io::ErrorKind::Unsupported,
                                    "Trojan outbound for GlobalID XUDP is not implemented yet",
                                ));
                            }
                            let target_addr = match target_location.to_socket_addr_nonblocking() {
                                Some(target_addr) => target_addr,
                                None => match resolver.resolve_location(&target_location).await {
                                    Ok(addresses) => match addresses.into_iter().next() {
                                        Some(target_addr) => target_addr,
                                        None => {
                                            runtime
                                                .record_user_domain_dns_failure();
                                            break Err(std::io::Error::other(
                                                format!(
                                                    "DNS lookup returned no addresses for {target_location}"
                                                ),
                                            ));
                                        }
                                    },
                                    Err(error) => {
                                        runtime
                                            .record_user_domain_dns_failure();
                                        break Err(error);
                                    }
                                },
                            };
                            let packet_context = traffic_context
                                .clone()
                                .map(|context| context.with_outbound_tag(outbound.tag.clone()));
                            let key = TargetedUdpSessionKey {
                                target_addr,
                                outbound_tag: Some(outbound.tag.clone()),
                            };
                            let sender = match plan_session_udp_worker(
                                sessions.get(&session_id),
                                &key,
                                None,
                            ) {
                                SessionUdpWorkerPlan::Reuse(sender) => sender,
                                SessionUdpWorkerPlan::Replace => {
                                    match replace_trojan_session_udp_worker(
                                        &mut sessions,
                                        session_id,
                                        &mut next_generation,
                                        TrojanSessionUdpWorkerStart {
                                            key: key.clone(),
                                            route_target: target_location.clone(),
                                            response_sender: response_sender.clone(),
                                            traffic_context: packet_context.clone(),
                                            resolver: trojan_resolver.clone(),
                                            runtime: runtime.clone(),
                                            outbound: outbound.clone(),
                                            global_id: None,
                                            idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                        },
                                    )
                                    .await
                                    {
                                        Ok(sender) => sender,
                                        Err(error) => break Err(error),
                                    }
                                }
                            };

                            if let Err(retry_payload) = sender.send_to(payload, target_addr).await {
                                let retry_sender = match replace_trojan_session_udp_worker(
                                    &mut sessions,
                                    session_id,
                                    &mut next_generation,
                                    TrojanSessionUdpWorkerStart {
                                        key,
                                        route_target: target_location.clone(),
                                        response_sender: response_sender.clone(),
                                        traffic_context: packet_context,
                                        resolver: trojan_resolver.clone(),
                                        runtime: runtime.clone(),
                                        outbound,
                                        global_id: None,
                                        idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                    },
                                )
                                .await
                                {
                                    Ok(sender) => sender,
                                    Err(error) => break Err(error),
                                };
                                if retry_sender
                                    .send_to(retry_payload, target_addr)
                                    .await
                                    .is_err()
                                {
                                    break Err(std::io::Error::new(
                                        std::io::ErrorKind::BrokenPipe,
                                        "Trojan session UDP tunnel closed before payload was sent",
                                    ));
                                }
                            }
                        }
                        #[cfg(not(feature = "trojan"))]
                        {
                            break Err(std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                format!(
                                    "Trojan outbound {} requires the trojan feature",
                                    outbound.tag
                                ),
                            ));
                        }
                    }
                    DirectOutboundAction::Vless { outbound } => {
                        if global_id.is_some() {
                            break Err(std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                "VLESS outbound for GlobalID XUDP is not implemented yet",
                            ));
                        }
                        let target_addr = match resolve_session_udp_location(
                            &resolver,
                            &runtime,
                            &target_location,
                        )
                        .await
                        {
                            Ok(target_addr) => target_addr,
                            Err(error) => break Err(error),
                        };
                        let packet_context = traffic_context
                            .clone()
                            .map(|context| context.with_outbound_tag(outbound.tag.clone()));
                        let key = TargetedUdpSessionKey {
                            target_addr,
                            outbound_tag: Some(outbound.tag.clone()),
                        };
                        let sender = match plan_session_udp_worker(
                            sessions.get(&session_id),
                            &key,
                            None,
                        ) {
                            SessionUdpWorkerPlan::Reuse(sender) => sender,
                            SessionUdpWorkerPlan::Replace => {
                                match replace_vless_session_udp_worker(
                                    &mut sessions,
                                    session_id,
                                    &mut next_generation,
                                    VlessSessionUdpWorkerStart {
                                        key: key.clone(),
                                        response_sender: response_sender.clone(),
                                        traffic_context: packet_context.clone(),
                                        resolver: resolver.clone(),
                                        runtime: runtime.clone(),
                                        outbound: outbound.clone(),
                                        target: target_location.clone(),
                                        idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                    },
                                )
                                .await
                                {
                                    Ok(sender) => sender,
                                    Err(error) => break Err(error),
                                }
                            }
                        };

                        if let Err(retry_payload) = sender.send_to(payload, target_addr).await {
                            let retry_sender = match replace_vless_session_udp_worker(
                                &mut sessions,
                                session_id,
                                &mut next_generation,
                                VlessSessionUdpWorkerStart {
                                    key,
                                    response_sender: response_sender.clone(),
                                    traffic_context: packet_context,
                                    resolver: resolver.clone(),
                                    runtime: runtime.clone(),
                                    outbound,
                                    target: target_location,
                                    idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                },
                            )
                            .await
                            {
                                Ok(sender) => sender,
                                Err(error) => break Err(error),
                            };
                            if retry_sender.send_to(retry_payload, target_addr).await.is_err() {
                                break Err(std::io::Error::new(
                                    std::io::ErrorKind::BrokenPipe,
                                    "VLESS session UDP tunnel closed before payload was sent",
                                ));
                            }
                        }
                    }
                    DirectOutboundAction::Socks { outbound } => {
                        break Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "SOCKS outbound {} is not supported for session-based UDP",
                                outbound.tag
                            ),
                        ));
                    }
                    #[cfg(feature = "vless-reverse")]
                    DirectOutboundAction::VlessReverse { tag } => {
                        let target_addr = match resolve_session_udp_location(
                            &resolver,
                            &runtime,
                            &target_location,
                        )
                        .await
                        {
                            Ok(target_addr) => target_addr,
                            Err(error) => break Err(error),
                        };
                        let packet_context = traffic_context
                            .clone()
                            .map(|context| context.with_outbound_tag(tag.clone()));
                        let key = TargetedUdpSessionKey {
                            target_addr,
                            outbound_tag: Some(tag.clone()),
                        };
                        let global_backend_key = global_id.map(|_| {
                            GlobalUdpWorkerKey::Reverse { tag: tag.clone() }
                        });
                        let sender = match sessions
                            .get(&session_id)
                            .filter(|worker| {
                                session_udp_worker_matches_backend(
                                    worker,
                                    &key,
                                    global_id,
                                    global_backend_key.as_ref(),
                                )
                            })
                            .map(|worker| worker.sender.clone())
                        {
                            Some(sender) => sender,
                            None => {
                                match replace_reverse_session_udp_worker(
                                    &mut sessions,
                                    session_id,
                                    &mut next_generation,
                                    ReverseSessionUdpWorkerStart {
                                        key: key.clone(),
                                        response_sender: response_sender.clone(),
                                        traffic_context: packet_context.clone(),
                                        resolver: resolver.clone(),
                                        runtime: runtime.clone(),
                                        tag: tag.clone(),
                                        target: target_location.clone(),
                                        source: peer_addr,
                                        local: local_addr,
                                        global_id,
                                        idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                    },
                                )
                                .await
                                {
                                    Ok(sender) => sender,
                                    Err(error) => break Err(error),
                                }
                            }
                        };

                        if let Err(retry_payload) = sender.send_to(payload, target_addr).await {
                            let retry_sender = match replace_reverse_session_udp_worker(
                                &mut sessions,
                                session_id,
                                &mut next_generation,
                                ReverseSessionUdpWorkerStart {
                                    key,
                                    response_sender: response_sender.clone(),
                                    traffic_context: packet_context,
                                    resolver: resolver.clone(),
                                    runtime: runtime.clone(),
                                    tag,
                                    target: target_location,
                                    source: peer_addr,
                                    local: local_addr,
                                    global_id,
                                    idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                },
                            )
                            .await
                            {
                                Ok(sender) => sender,
                                Err(error) => break Err(error),
                            };
                            if retry_sender.send_to(retry_payload, target_addr).await.is_err() {
                                break Err(std::io::Error::new(
                                    std::io::ErrorKind::BrokenPipe,
                                    "Reverse session UDP tunnel closed before payload was sent",
                                ));
                            }
                        }
                    }
                }
            }
            event = response_receiver.recv() => {
                let Some(event) = event else {
                    break Ok(());
                };
                match event {
                    SessionUdpEvent::Data(response) => {
                        if !is_current_session_udp_response(&sessions, &response) {
                            debug!(
                                "dropping stale session udp response for session {} generation {}",
                                response.session_id, response.generation
                            );
                            continue;
                        }
                        if let Err(error) = write_session_message(
                            &mut *server_stream,
                            response.session_id,
                            &response.payload,
                            &response.source,
                        )
                        .await
                        {
                            break Err(error);
                        }
                        if let Err(error) =
                            flush_session_message(&mut *server_stream).await
                        {
                            break Err(error);
                        }
                        record_transfer(
                            response.traffic_context,
                            0,
                            response.payload.len() as u64,
                        );
                    }
                    SessionUdpEvent::End {
                        session_id,
                        generation,
                        has_error,
                    } => {
                        if !is_current_session_udp_generation(
                            &sessions,
                            session_id,
                            generation,
                        ) {
                            debug!(
                                "dropping stale session udp End for session {} generation {}",
                                session_id, generation
                            );
                            continue;
                        }
                        expire_session_udp_worker(&mut sessions, session_id).await;
                        if let Err(error) = write_session_end(
                            &mut *server_stream,
                            session_id,
                            has_error,
                        )
                        .await
                        {
                            break Err(error);
                        }
                        if let Err(error) =
                            flush_session_message(&mut *server_stream).await
                        {
                            break Err(error);
                        }
                    }
                }
            }
        }
    };

    for (_, worker) in sessions.drain() {
        detach_session_udp_worker(worker).await;
    }
    let _ = shutdown_session_message(&mut *server_stream).await;
    result
}

fn can_reuse_existing_session_target(
    worker: &SessionUdpWorker,
    global_id: Option<[u8; 8]>,
    target: &NetLocation,
) -> bool {
    worker.global_id == global_id
        && !worker.sender.is_closed()
        && same_session_udp_target(&worker.route_target, target)
}

fn same_session_udp_target(left: &NetLocation, right: &NetLocation) -> bool {
    if left.port() != right.port() {
        return false;
    }
    match (left.address(), right.address()) {
        (
            crate::address::Address::Hostname(left),
            crate::address::Address::Hostname(right),
        ) => left.eq_ignore_ascii_case(right),
        _ => left == right,
    }
}

async fn read_session_message(
    stream: &mut dyn AsyncSessionMessageStream,
    buffer: &mut [u8],
) -> std::io::Result<(SessionMessage, usize)> {
    poll_fn(|cx| {
        let mut read_buffer = ReadBuf::new(buffer);
        match Pin::new(&mut *stream).poll_read_session_message(cx, &mut read_buffer)
        {
            std::task::Poll::Ready(Ok(message)) => {
                std::task::Poll::Ready(Ok((message, read_buffer.filled().len())))
            }
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

async fn write_session_message(
    stream: &mut dyn AsyncSessionMessageStream,
    session_id: u16,
    payload: &[u8],
    source: &SocketAddr,
) -> std::io::Result<()> {
    poll_fn(|cx| {
        Pin::new(&mut *stream)
            .poll_write_session_message(cx, session_id, payload, source)
    })
    .await
}

async fn write_session_end(
    stream: &mut dyn AsyncSessionMessageStream,
    session_id: u16,
    has_error: bool,
) -> std::io::Result<()> {
    poll_fn(|cx| {
        Pin::new(&mut *stream).poll_write_session_end(cx, session_id, has_error)
    })
    .await
}

async fn flush_session_message(
    stream: &mut dyn AsyncSessionMessageStream,
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx)).await
}

async fn shutdown_session_message(
    stream: &mut dyn AsyncSessionMessageStream,
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_shutdown_message(cx)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_udp_route_reuse_requires_the_same_logical_domain_target() {
        let (sender, _receiver) = mpsc::channel(1);
        let global_id = Some([4, 3, 2, 1, 8, 7, 6, 5]);
        let route_target = NetLocation::new(
            crate::address::Address::Hostname("allowed.example".to_string()),
            53,
        );
        let worker = SessionUdpWorker {
            key: TargetedUdpSessionKey {
                target_addr: SocketAddr::from(([192, 0, 2, 53], 53)),
                outbound_tag: Some("site-a".to_string()),
            },
            route_target: route_target.clone(),
            global_id,
            global_backend_key: None,
            generation: 1,
            sender: SessionUdpSender::Local(sender),
            task: None,
        };

        assert!(can_reuse_existing_session_target(
            &worker,
            global_id,
            &route_target
        ));
        assert!(can_reuse_existing_session_target(
            &worker,
            global_id,
            &NetLocation::new(
                crate::address::Address::Hostname("ALLOWED.example".to_string()),
                53,
            )
        ));
        assert!(!can_reuse_existing_session_target(
            &worker,
            global_id,
            &NetLocation::new(
                crate::address::Address::Hostname("denied.example".to_string()),
                53,
            )
        ));
        assert!(!can_reuse_existing_session_target(
            &worker,
            global_id,
            &NetLocation::new(
                crate::address::Address::Hostname("allowed.example".to_string()),
                5353,
            )
        ));
    }
}
