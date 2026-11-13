use super::*;

const HYSTERIA2_COPY_BUFFER_SIZE: usize = 32 * 1024;

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
    let policy_identities = vec![auth_ctx.client.password.clone()];
    let connection = match tokio::time::timeout(
        TCP_CONNECT_TIMEOUT,
        connect_tcp_outbound_with_vless_route(
            &resolver,
            &request.target,
            &runtime,
            inbound_tag.as_str(),
            &context_identity,
            peer_addr,
            InboundRoutingMetadata {
                vless_route: auth_ctx.vless_route,
                inbound_protocol: Some("hysteria2".to_string()),
                policy_identities,
                ..InboundRoutingMetadata::default()
            },
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
        HYSTERIA2_COPY_BUFFER_SIZE,
        HYSTERIA2_COPY_BUFFER_SIZE,
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
    eof: bool,
    pending_read_error: Option<Error>,
}

impl H3RawStream {
    fn new(stream: BidiStream<Bytes>) -> Self {
        Self {
            stream,
            read_buffer: Bytes::new(),
            eof: false,
            pending_read_error: None,
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
        let H3RawStream {
            stream,
            read_buffer,
            eof,
            pending_read_error,
        } = this;
        poll_read_quic_chunks(read_buffer, eof, pending_read_error, cx, buf, |cx| {
            match H3RecvStream::poll_data(stream, cx) {
                Poll::Ready(Ok(data)) => Poll::Ready(Ok(data)),
                Poll::Ready(Err(err)) => Poll::Ready(Err(Error::other(err))),
                Poll::Pending => Poll::Pending,
            }
        })
    }
}

fn poll_read_quic_chunks<F>(
    read_buffer: &mut Bytes,
    eof: &mut bool,
    pending_read_error: &mut Option<Error>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
    mut poll_data: F,
) -> Poll<std::io::Result<()>>
where
    F: FnMut(&mut Context<'_>) -> Poll<std::io::Result<Option<Bytes>>>,
{
    if buf.remaining() == 0 {
        return Poll::Ready(Ok(()));
    }
    if let Some(err) = pending_read_error.take() {
        return Poll::Ready(Err(err));
    }
    if *eof {
        return Poll::Ready(Ok(()));
    }

    let filled_before = buf.filled().len();
    loop {
        if !read_buffer.is_empty() {
            let len = read_buffer.len().min(buf.remaining());
            // Copy directly from the current view. `split_to` creates a
            // temporary `Bytes` handle (and may touch its refcount) even
            // though Tokio's ReadBuf always copies these bytes immediately.
            buf.put_slice(&read_buffer[..len]);
            read_buffer.advance(len);
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
        }

        match poll_data(cx) {
            Poll::Ready(Ok(Some(data))) => *read_buffer = data,
            Poll::Ready(Ok(None)) => {
                *eof = true;
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Err(err)) => {
                if buf.filled().len() != filled_before {
                    *pending_read_error = Some(err);
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(err));
            }
            Poll::Pending => {
                return if buf.filled().len() != filled_before {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                };
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

#[cfg(test)]
mod raw_stream_tests {
    use std::{collections::VecDeque, io, task::Poll};

    use bytes::Bytes;
    use tokio::io::ReadBuf;

    use super::poll_read_quic_chunks;

    #[tokio::test]
    async fn raw_stream_read_coalesces_ready_quic_chunks() {
        let mut chunks = VecDeque::from([
            Ok(Some(Bytes::from_static(b"abc"))),
            Ok(Some(Bytes::from_static(b"defgh"))),
        ]);
        let mut read_buffer = Bytes::new();
        let mut eof = false;
        let mut pending_read_error = None;
        let mut destination = [0; 16];
        let mut read_buf = ReadBuf::new(&mut destination);
        let mut poll_count = 0;

        let result = std::future::poll_fn(|cx| {
            poll_read_quic_chunks(
                &mut read_buffer,
                &mut eof,
                &mut pending_read_error,
                cx,
                &mut read_buf,
                |_| {
                    poll_count += 1;
                    chunks.pop_front().map_or(Poll::Pending, Poll::Ready)
                },
            )
        })
        .await;

        result.expect("coalesced raw reads should succeed");
        assert_eq!(read_buf.filled(), b"abcdefgh");
        assert_eq!(poll_count, 3, "read until the QUIC stream is pending");
    }

    #[tokio::test]
    async fn raw_stream_read_preserves_partially_consumed_owned_chunks() {
        let mut chunks = VecDeque::from([
            Ok(Some(Bytes::from(b"abcdefghij".to_vec()))),
            Ok(None),
        ]);
        let mut read_buffer = Bytes::new();
        let mut eof = false;
        let mut pending_read_error = None;
        let mut poll_count = 0;
        let mut received = Vec::new();

        for buffer_size in [3, 4, 5] {
            let mut destination = vec![0; buffer_size];
            let mut read_buf = ReadBuf::new(&mut destination);
            std::future::poll_fn(|cx| {
                poll_read_quic_chunks(
                    &mut read_buffer,
                    &mut eof,
                    &mut pending_read_error,
                    cx,
                    &mut read_buf,
                    |_| {
                        poll_count += 1;
                        chunks.pop_front().map_or(Poll::Pending, Poll::Ready)
                    },
                )
            })
            .await
            .expect("partial reads from an owned Bytes chunk must succeed");
            received.extend_from_slice(read_buf.filled());
        }

        assert_eq!(received, b"abcdefghij");
        assert!(read_buffer.is_empty());
        assert!(eof);
        assert_eq!(poll_count, 2, "one chunk and one EOF, no duplicate reads");
    }

    #[tokio::test]
    async fn raw_stream_read_preserves_randomized_owned_chunk_boundaries() {
        for seed in 0usize..512 {
            let len = (seed * 37) % 157;
            let payload: Vec<u8> = (0..len)
                .map(|i| ((i * 13 + seed * 7) & 255) as u8)
                .collect();
            let mut chunks = VecDeque::new();
            let mut offset = 0usize;
            while offset < len {
                if (offset + seed).is_multiple_of(5) {
                    chunks.push_back(Ok(Some(Bytes::new())));
                }
                let take = ((offset + seed * 3) % 17 + 1).min(len - offset);
                chunks.push_back(Ok(Some(Bytes::from(
                    payload[offset..offset + take].to_vec(),
                ))));
                offset += take;
            }
            chunks.push_back(Ok(None));

            let mut read_buffer = Bytes::new();
            let mut eof = false;
            let mut pending_read_error = None;
            let mut received = Vec::new();
            let mut poll_count = 0usize;
            for iteration in 0usize..512 {
                let buffer_len = (seed + iteration * 11) % 31 + 1;
                let mut destination = vec![0; buffer_len];
                let mut read_buf = ReadBuf::new(&mut destination);
                std::future::poll_fn(|cx| {
                    poll_read_quic_chunks(
                        &mut read_buffer,
                        &mut eof,
                        &mut pending_read_error,
                        cx,
                        &mut read_buf,
                        |_| {
                            poll_count += 1;
                            chunks.pop_front().map_or(Poll::Pending, Poll::Ready)
                        },
                    )
                })
                .await
                .expect("randomized chunk read must succeed");
                received.extend_from_slice(read_buf.filled());
                if eof {
                    break;
                }
                assert!(iteration < 511, "seed={seed}: EOF not reached");
            }
            assert_eq!(received, payload, "seed={seed}");
            assert!(eof, "seed={seed}");
            assert!(pending_read_error.is_none(), "seed={seed}");
            assert!(read_buffer.is_empty(), "seed={seed}");
            assert!(chunks.is_empty(), "seed={seed}");
            assert!(poll_count > 0, "seed={seed}");
        }
    }

    #[tokio::test]
    async fn raw_stream_read_defers_errors_until_buffered_bytes_are_returned() {
        let mut chunks = VecDeque::from([
            Ok(Some(Bytes::from_static(b"payload"))),
            Err(io::Error::other("injected read failure")),
        ]);
        let mut read_buffer = Bytes::new();
        let mut eof = false;
        let mut pending_read_error = None;
        let mut destination = [0; 16];
        let mut read_buf = ReadBuf::new(&mut destination);

        std::future::poll_fn(|cx| {
            poll_read_quic_chunks(
                &mut read_buffer,
                &mut eof,
                &mut pending_read_error,
                cx,
                &mut read_buf,
                |_| chunks.pop_front().map_or(Poll::Pending, Poll::Ready),
            )
        })
        .await
        .expect("buffered bytes must be returned before a read error");
        assert_eq!(read_buf.filled(), b"payload");

        let mut next_buf = ReadBuf::new(&mut destination);
        let err = std::future::poll_fn(|cx| {
            poll_read_quic_chunks(
                &mut read_buffer,
                &mut eof,
                &mut pending_read_error,
                cx,
                &mut next_buf,
                |_| panic!("a deferred read error must not poll QUIC again"),
            )
        })
        .await
        .expect_err("deferred QUIC error must be surfaced on the next read");
        assert_eq!(err.to_string(), "injected read failure");
    }

    #[tokio::test]
    async fn raw_stream_read_preserves_eof_after_returning_buffered_data() {
        let mut chunks =
            VecDeque::from([Ok(Some(Bytes::from_static(b"payload"))), Ok(None)]);
        let mut read_buffer = Bytes::new();
        let mut eof = false;
        let mut pending_read_error = None;
        let mut destination = [0; 16];
        let mut read_buf = ReadBuf::new(&mut destination);

        std::future::poll_fn(|cx| {
            poll_read_quic_chunks(
                &mut read_buffer,
                &mut eof,
                &mut pending_read_error,
                cx,
                &mut read_buf,
                |_| chunks.pop_front().map_or(Poll::Pending, Poll::Ready),
            )
        })
        .await
        .expect("buffered bytes must be returned before EOF");
        assert_eq!(read_buf.filled(), b"payload");

        let mut next_buf = ReadBuf::new(&mut destination);
        let result = std::future::poll_fn(|cx| {
            poll_read_quic_chunks(
                &mut read_buffer,
                &mut eof,
                &mut pending_read_error,
                cx,
                &mut next_buf,
                |_| panic!("known EOF must not poll QUIC again"),
            )
        })
        .await;
        result.expect("EOF is reported as a successful empty read");
        assert!(next_buf.filled().is_empty());
    }
}
