use super::*;

pub(super) async fn drive_tcp_streams(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    resolver: Arc<dyn Resolver>,
    auth_ctx: &AuthContext,
    inbound_tag: Arc<String>,
    peer_addr: SocketAddr,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()> {
    let mut stream_tasks = JoinSet::new();
    let result = loop {
        let stream = tokio::select! {
            accepted = next_hysteria_stream(h3_conn) => {
                match accepted {
                    Ok(stream) => stream,
                    Err(err) if err.is_h3_no_error() => break Ok(()),
                    Err(err) => break Err(map_h3_error(err)),
                }
            }
            completed = stream_tasks.join_next(), if !stream_tasks.is_empty() => {
                if let Some(Err(err)) = completed {
                    warn!("hysteria2 tcp stream task ended unexpectedly: {err}");
                }
                continue;
            }
        };
        let resolver = resolver.clone();
        let auth_ctx = auth_ctx.clone();
        let inbound_tag = inbound_tag.clone();
        let runtime = runtime.clone();
        stream_tasks.spawn(async move {
            if let Err(err) = handle_tcp_stream(
                H3RawStream::new(stream),
                resolver,
                auth_ctx,
                inbound_tag,
                peer_addr,
                runtime,
            )
            .await
            {
                debug!("hysteria2 tcp stream ended with error: {}", err);
            }
        });
    };

    abort_and_drain_hysteria_stream_tasks(&mut stream_tasks).await;
    result
}

pub(super) async fn abort_and_drain_hysteria_stream_tasks(
    stream_tasks: &mut JoinSet<()>,
) {
    stream_tasks.abort_all();
    while let Some(result) = stream_tasks.join_next().await {
        if let Err(err) = result
            && !err.is_cancelled()
        {
            warn!("hysteria2 tcp stream task failed during cleanup: {err}");
        }
    }
}

pub(super) async fn next_hysteria_stream(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
) -> Result<BidiStream<Bytes>, h3::error::ConnectionError> {
    poll_fn(|cx| poll_hysteria_stream(h3_conn, cx)).await
}

pub(super) fn poll_hysteria_stream(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    cx: &mut Context<'_>,
) -> Poll<Result<BidiStream<Bytes>, h3::error::ConnectionError>> {
    loop {
        match h3_conn.inner.poll_control(cx) {
            Poll::Ready(Ok(_)) => continue,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => break,
        }
    }
    h3_conn.inner.poll_accept_bi(cx)
}

pub(super) async fn handle_tcp_stream(
    mut stream: H3RawStream,
    resolver: Arc<dyn Resolver>,
    auth_ctx: AuthContext,
    inbound_tag: Arc<String>,
    peer_addr: SocketAddr,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()> {
    let tcp_request_timeout = configured_tcp_request_timeout(
        auth_ctx.xray_compat,
        auth_ctx.client.level,
        &runtime,
    );
    let request = match read_tcp_request(
        &mut stream,
        tcp_request_timeout,
        auth_ctx.xray_compat,
    )
    .await
    {
        Ok(request) => request,
        Err(err) => {
            let _ = stream.shutdown().await;
            return Err(err);
        }
    };
    send_tcp_response(&mut stream, TCP_SUCCESS_STATUS, "", auth_ctx.xray_compat)
        .await?;

    let context_identity = auth_ctx
        .client
        .email
        .clone()
        .unwrap_or(auth_ctx.client.password.clone());
    let connection = match tokio::time::timeout(
        TCP_CONNECT_TIMEOUT,
        connect_tcp_outbound_with_vless_route(
            &resolver,
            &request.target,
            &runtime,
            inbound_tag.as_str(),
            &context_identity,
            peer_addr,
            auth_ctx.vless_route,
        ),
    )
    .await
    {
        Ok(Ok(Some(connection))) => connection,
        Ok(Ok(None)) => {
            let _ = stream.shutdown().await;
            return Ok(());
        }
        Ok(Err(err)) => {
            warn!("failed to connect to {}: {}", request.target, err);
            let _ = stream.shutdown().await;
            return Err(err);
        }
        Err(_) => {
            let _ = stream.shutdown().await;
            return Err(Error::new(
                ErrorKind::TimedOut,
                format!("client setup to {} timed out", request.target),
            ));
        }
    };

    let mut context = hysteria2_traffic_context(
        &auth_ctx.client,
        inbound_tag.as_str(),
        peer_addr,
        &runtime,
    );
    if let Some(tag) = connection.outbound_tag {
        context = context.with_outbound_tag(tag);
    }

    proxy_tcp(stream, connection.stream, context).await
}

pub(super) struct TcpRequest {
    pub(super) target: NetLocation,
}

pub(super) fn configured_tcp_request_timeout(
    xray_compat: bool,
    level: u32,
    runtime: &DataPlaneRuntime,
) -> Option<Duration> {
    xray_compat.then(|| runtime.xray_handshake_timeout_for_level(level))
}

pub(super) async fn read_tcp_request<S>(
    stream: &mut S,
    timeout: Option<Duration>,
    xray_compat: bool,
) -> std::io::Result<TcpRequest>
where
    S: AsyncRead + Unpin,
{
    match timeout {
        Some(timeout) => {
            tokio::time::timeout(timeout, TcpRequest::read(stream, xray_compat))
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::TimedOut,
                        "hysteria2 TCP request header timed out",
                    )
                })?
        }
        None => TcpRequest::read(stream, xray_compat).await,
    }
}

impl TcpRequest {
    pub(super) async fn read<S>(
        stream: &mut S,
        xray_compat: bool,
    ) -> std::io::Result<Self>
    where
        S: AsyncRead + Unpin,
    {
        let request_id = read_varint(stream).await?;
        if request_id != TCP_REQUEST_ID {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unexpected hysteria2 request type: {:#x}", request_id),
            ));
        }

        let address_len = read_varint(stream).await?;
        if address_len > MAX_ADDRESS_LEN as u64 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "request address too long",
            ));
        }
        let address_len = address_len as usize;
        let mut address_bytes = vec![0; address_len];
        stream
            .read_exact(&mut address_bytes)
            .await
            .map_err(Error::other)?;
        let target = if xray_compat {
            None
        } else {
            Some(parse_tcp_request_target(address_bytes.as_slice())?)
        };

        let padding_len =
            validate_tcp_request_padding_len(read_varint(stream).await?)?;
        skip_padding(stream, padding_len).await?;

        let target = match target {
            Some(target) => target,
            None => parse_tcp_request_target(address_bytes.as_slice())?,
        };
        Ok(Self { target })
    }
}

pub(super) async fn proxy_tcp<S>(
    quic_stream: S,
    tcp_stream: Box<dyn crate::async_stream::AsyncStream>,
    context: TrafficContext,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _connection_guard = register_connection(Some(&context));
    let mut quic_stream = MeteredStream::new(
        quic_stream,
        Some(context.clone()),
        TrafficDirection::Upload,
    );
    let mut tcp_stream =
        MeteredStream::new(tcp_stream, Some(context), TrafficDirection::Download);
    match tokio::io::copy_bidirectional_with_sizes(
        &mut quic_stream,
        &mut tcp_stream,
        32 * 1024,
        32 * 1024,
    )
    .await
    {
        Ok((client_to_server, server_to_client)) => {
            debug!(
                "hysteria2 tcp stream forwarded {} bytes client->server and {} bytes server->client",
                client_to_server, server_to_client
            );
            Ok(())
        }
        Err(err) => Err(err),
    }
}

pub(super) struct H3RawStream {
    stream: BidiStream<Bytes>,
    read_buffer: Bytes,
}

impl H3RawStream {
    fn new(stream: BidiStream<Bytes>) -> Self {
        Self {
            stream,
            read_buffer: Bytes::new(),
        }
    }
}

impl AsyncRead for H3RawStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if !this.read_buffer.is_empty() {
                let len = this.read_buffer.len().min(buf.remaining());
                let chunk = this.read_buffer.split_to(len);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }

            match H3RecvStream::poll_data(&mut this.stream, cx) {
                Poll::Ready(Ok(Some(data))) => this.read_buffer = data,
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(Error::other(err)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H3RawStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut data = buf;
        match SendStreamUnframed::poll_send(&mut this.stream, cx, &mut data) {
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match H3SendStream::poll_finish(&mut self.get_mut().stream, cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(super) fn parse_tcp_request_target(
    address_bytes: &[u8],
) -> std::io::Result<NetLocation> {
    let address = std::str::from_utf8(address_bytes)
        .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
    NetLocation::from_str(address, None)
}

pub(super) async fn read_varint<S>(stream: &mut S) -> std::io::Result<u64>
where
    S: AsyncRead + Unpin,
{
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.map_err(Error::other)?;
    let prefix = first[0] >> 6;
    let mut value = (first[0] & 0x3f) as u64;
    if prefix > 3 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("invalid hysteria2 varint prefix: {prefix}"),
        ));
    }
    let remaining: usize = match prefix {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => 7,
        _ => unreachable!(),
    };

    if remaining > 0 {
        let mut buf = [0u8; 8];
        stream
            .read_exact(&mut buf[..remaining])
            .await
            .map_err(Error::other)?;
        for &byte in &buf[..remaining] {
            value = (value << 8) | u64::from(byte);
        }
    }

    Ok(value)
}

pub(super) fn validate_tcp_request_padding_len(
    padding_len: u64,
) -> std::io::Result<usize> {
    if padding_len > MAX_TCP_REQUEST_PADDING_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "padding length too large",
        ));
    }
    usize::try_from(padding_len)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "padding length too large"))
}

pub(super) async fn skip_padding<S>(
    stream: &mut S,
    mut len: usize,
) -> std::io::Result<()>
where
    S: AsyncRead + Unpin,
{
    if len == 0 {
        return Ok(());
    }
    let mut scratch = [0u8; PADDING_SCRATCH_LEN];
    while len > 0 {
        let take = scratch.len().min(len);
        stream
            .read_exact(&mut scratch[..take])
            .await
            .map_err(Error::other)?;
        len -= take;
    }
    Ok(())
}

pub(super) fn build_tcp_response(
    status: u8,
    message: &str,
    xray_compat: bool,
) -> std::io::Result<Vec<u8>> {
    let message_bytes = message.as_bytes();
    let mut rng = rand::rng();
    let padding_len = if xray_compat {
        rng.random_range(128..1024usize)
    } else {
        rng.random_range(0..=63usize)
    };
    let mut buf = Vec::with_capacity(1 + message_bytes.len() + padding_len + 16);
    buf.push(status);
    push_varint(&mut buf, message_bytes.len() as u64)?;
    buf.extend_from_slice(message_bytes);
    push_varint(&mut buf, padding_len as u64)?;
    let padding_start = buf.len();
    if xray_compat {
        buf.extend_from_slice(
            Alphanumeric.sample_string(&mut rng, padding_len).as_bytes(),
        );
    } else if padding_len > 0 {
        buf.resize(padding_start + padding_len, 0);
        rng.fill(&mut buf[padding_start..]);
    }
    Ok(buf)
}

pub(super) async fn send_tcp_response<S>(
    stream: &mut S,
    status: u8,
    message: &str,
    xray_compat: bool,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let buf = build_tcp_response(status, message, xray_compat)?;
    stream.write_all(&buf).await.map_err(Error::other)?;
    stream.flush().await.map_err(Error::other)
}
