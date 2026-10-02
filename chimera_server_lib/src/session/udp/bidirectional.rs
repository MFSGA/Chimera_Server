use super::*;

#[cfg(feature = "trojan")]
use crate::handler::trojan_udp::TrojanUdpStream;

pub(crate) async fn run_bidirectional_udp(
    mut server_stream: Box<dyn AsyncMessageStream>,
    remote_location: NetLocation,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let inbound_tag = traffic_context
        .as_ref()
        .and_then(|context| context.inbound_tag.as_deref())
        .unwrap_or_default();
    let identity = traffic_context
        .as_ref()
        .and_then(|context| context.identity.as_deref())
        .unwrap_or_default();
    let (action, target_addr) = select_direct_outbound_for_location(
        &resolver,
        &remote_location,
        &runtime,
        OutboundRoutingContext::new(
            inbound_tag,
            identity,
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
        .with_policy_identities(
            traffic_context
                .as_ref()
                .map(|context| context.policy_identities.as_slice())
                .unwrap_or_default(),
        ),
    )
    .await?;
    let mut traffic_context =
        traffic_context.map(|context| context.with_client_ip(peer_addr.ip()));

    let result = match action {
        DirectOutboundAction::Blackhole { tag } => {
            traffic_context = traffic_context
                .map(|context| context.with_outbound_tag(tag.clone()));
            let _connection_guard = register_connection(traffic_context.as_ref());
            consume_blackholed_udp_messages(
                &mut *server_stream,
                traffic_context,
                &remote_location,
                &tag,
            )
            .await
        }
        DirectOutboundAction::Freedom { tag, .. } => {
            if let Some(tag) = tag {
                traffic_context =
                    traffic_context.map(|context| context.with_outbound_tag(tag));
            }
            let target_addr = target_addr.ok_or_else(|| {
                std::io::Error::other("UDP freedom route did not resolve target")
            })?;
            let bind_addr = if target_addr.is_ipv6() {
                SocketAddr::from(([0u16; 8], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            };
            let socket = UdpSocket::bind(bind_addr).await?;
            socket.connect(target_addr).await?;
            let _connection_guard = register_connection(traffic_context.as_ref());
            copy_bidirectional_udp_messages(
                &mut *server_stream,
                &socket,
                traffic_context,
            )
            .await
        }
        DirectOutboundAction::Trojan { outbound } => {
            #[cfg(feature = "trojan")]
            {
                traffic_context = traffic_context
                    .map(|context| context.with_outbound_tag(outbound.tag.clone()));
                let _connection_guard =
                    register_connection(traffic_context.as_ref());
                let mut proxy = connect_trojan_udp_via_outbound(
                    &resolver,
                    &remote_location,
                    &runtime,
                    &outbound,
                )
                .await?;
                let result = copy_bidirectional_trojan_udp_messages(
                    &mut *server_stream,
                    &mut proxy,
                    &remote_location,
                    traffic_context,
                )
                .await;
                let _ = shutdown_targeted_message(&mut proxy).await;
                result
            }
            #[cfg(not(feature = "trojan"))]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "Trojan outbound {} requires the trojan feature",
                        outbound.tag
                    ),
                ))
            }
        }
        DirectOutboundAction::Socks { outbound }
        | DirectOutboundAction::Vless { outbound } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("TCP proxy outbound {} cannot be used for UDP", outbound.tag),
        )),
        #[cfg(feature = "vless-reverse")]
        DirectOutboundAction::VlessReverse { tag } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS Reverse outbound {tag} is TCP-only"),
        )),
    };

    let _ = shutdown_message(&mut *server_stream).await;
    result
}

async fn consume_blackholed_udp_messages(
    stream: &mut dyn AsyncMessageStream,
    traffic_context: Option<TrafficContext>,
    remote_location: &NetLocation,
    outbound_tag: &str,
) -> std::io::Result<()> {
    let mut buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];
    loop {
        let len = read_message(stream, &mut buffer).await?;
        if len == 0 {
            return Ok(());
        }
        record_transfer(traffic_context.clone(), len as u64, 0);
        debug!(
            "udp message to {} dropped by blackhole outbound {}",
            remote_location, outbound_tag
        );
    }
}

#[cfg(feature = "trojan")]
async fn copy_bidirectional_trojan_udp_messages(
    stream: &mut dyn AsyncMessageStream,
    proxy: &mut TrojanUdpStream,
    target: &NetLocation,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let mut client_buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];
    let mut target_buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];

    loop {
        tokio::select! {
            result = read_message(stream, &mut client_buffer) => {
                let len = result?;
                if len == 0 {
                    return Ok(());
                }
                proxy.send_to(target, &client_buffer[..len]).await?;
                record_transfer(traffic_context.clone(), len as u64, 0);
            }
            result = proxy.recv_from(&mut target_buffer) => {
                let (_source, len) = result?;
                write_message(stream, &target_buffer[..len]).await?;
                flush_message(stream).await?;
                record_transfer(traffic_context.clone(), 0, len as u64);
            }
        }
    }
}

async fn copy_bidirectional_udp_messages(
    stream: &mut dyn AsyncMessageStream,
    socket: &UdpSocket,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let mut client_buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];
    let mut target_buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];

    loop {
        tokio::select! {
            result = read_message(stream, &mut client_buffer) => {
                let len = result?;
                if len == 0 {
                    return Ok(());
                }
                let written = socket.send(&client_buffer[..len]).await?;
                if written != len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        format!("udp message was truncated: wrote {written} of {len} bytes"),
                    ));
                }
                record_transfer(traffic_context.clone(), len as u64, 0);
            }
            result = socket.recv(&mut target_buffer) => {
                let len = result?;
                write_message(stream, &target_buffer[..len]).await?;
                flush_message(stream).await?;
                record_transfer(traffic_context.clone(), 0, len as u64);
            }
        }
    }
}

async fn read_message(
    stream: &mut dyn AsyncMessageStream,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buffer);
        match Pin::new(&mut *stream).poll_read_message(cx, &mut read_buf) {
            std::task::Poll::Ready(Ok(())) => {
                std::task::Poll::Ready(Ok(read_buf.filled().len()))
            }
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

async fn write_message(
    stream: &mut dyn AsyncMessageStream,
    buffer: &[u8],
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, buffer)).await
}

async fn flush_message(stream: &mut dyn AsyncMessageStream) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx)).await
}

async fn shutdown_message(
    stream: &mut dyn AsyncMessageStream,
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_shutdown_message(cx)).await
}
