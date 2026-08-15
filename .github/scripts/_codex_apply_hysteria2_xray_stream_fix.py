from pathlib import Path
import re

path = Path("chimera_server_lib/src/handler/hysteria2/connection.rs")
text = path.read_text()

text = text.replace(
    "    future::Future,\n",
    "    future::{Future, poll_fn},\n",
    1,
)
text = text.replace(
    "use h3_quinn::BidiStream;\n",
    "use h3::quic::{RecvStream as H3RecvStream, SendStream as H3SendStream, SendStreamUnframed};\nuse h3_quinn::BidiStream;\n",
    1,
)
text = text.replace(
    "    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},\n",
    "    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},\n",
    1,
)

pattern = re.compile(
    r"    // Keep the H3 driver alive because dropping it closes the underlying QUIC\n"
    r".*?\n}\n\nasync fn await_authentication",
    re.S,
)
replacement = """    // Keep accepting post-authentication Hysteria2 streams through the same
    // h3-quinn connection that handled authentication. Xray 26.3.27+ routes
    // custom 0x401 streams through its HTTP/3 stream dispatcher, and using a
    // second raw Quinn accept loop here can race the H3 driver's accept queue.
    let udp_idle_timeout = config
        .xray_udp_idle_timeout_secs
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs);
    let peer_addr = connection.remote_address();

    if auth_ctx.udp_enabled {
        tokio::try_join!(
            drive_tcp_streams(
                &mut h3_conn,
                resolver.clone(),
                &auth_ctx,
                inbound_tag.clone(),
                peer_addr,
                runtime.clone(),
            ),
            drive_udp_datagrams(
                connection,
                resolver,
                &auth_ctx,
                inbound_tag,
                runtime,
                udp_idle_timeout,
            ),
        )
        .map(|_| ())
    } else {
        drive_tcp_streams(
            &mut h3_conn,
            resolver,
            &auth_ctx,
            inbound_tag,
            peer_addr,
            runtime,
        )
        .await
    }
}

async fn await_authentication"""
text, count = pattern.subn(replacement, text, count=1)
assert count == 1, f"process block replacements: {count}"

pattern = re.compile(
    r"async fn drain_unidirectional_streams\(.*?\nasync fn handle_tcp_stream\(",
    re.S,
)
replacement = """async fn drive_tcp_streams(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    resolver: Arc<dyn Resolver>,
    auth_ctx: &AuthContext,
    inbound_tag: Arc<String>,
    peer_addr: SocketAddr,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    loop {
        let stream = match next_hysteria_stream(h3_conn).await {
            Ok(stream) => stream,
            Err(err) if err.is_h3_no_error() => return Ok(()),
            Err(err) => return Err(map_h3_error(err)),
        };
        let resolver = resolver.clone();
        let client = auth_ctx.client.clone();
        let inbound_tag = inbound_tag.clone();
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_tcp_stream(
                H3RawStream::new(stream),
                resolver,
                client,
                inbound_tag,
                peer_addr,
                runtime,
            )
            .await
            {
                debug!("hysteria2 tcp stream ended with error: {}", err);
            }
        });
    }
}

async fn next_hysteria_stream(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
) -> Result<BidiStream<Bytes>, h3::error::ConnectionError> {
    poll_fn(|cx| poll_hysteria_stream(h3_conn, cx)).await
}

fn poll_hysteria_stream(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    cx: &mut Context<'_>,
) -> Poll<Result<BidiStream<Bytes>, h3::error::ConnectionError>> {
    // Drive the HTTP/3 control and unidirectional streams from the same owner
    // while waiting for custom Hysteria2 bidirectional streams. This replaces
    // the old raw Quinn unidirectional drain and avoids a second accept race.
    loop {
        match h3_conn.inner.poll_control(cx) {
            Poll::Ready(Ok(_)) => continue,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => break,
        }
    }
    h3_conn.inner.poll_accept_bi(cx)
}

async fn handle_tcp_stream("""
text, count = pattern.subn(replacement, text, count=1)
assert count == 1, f"drive block replacements: {count}"

pattern = re.compile(
    r"async fn handle_tcp_stream\(.*?\n}\n\nstruct TcpRequest",
    re.S,
)
replacement = """async fn handle_tcp_stream(
    mut stream: H3RawStream,
    resolver: Arc<dyn Resolver>,
    client: Hysteria2Client,
    inbound_tag: Arc<String>,
    peer_addr: SocketAddr,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let request = match TcpRequest::read(&mut stream).await {
        Ok(request) => request,
        Err(err) => {
            let _ = stream.shutdown().await;
            return Err(err);
        }
    };
    send_tcp_response(&mut stream, TCP_SUCCESS_STATUS, "").await?;

    let context_identity = client.email.clone().unwrap_or(client.password.clone());
    let connection = match tokio::time::timeout(
        TCP_CONNECT_TIMEOUT,
        connect_tcp_outbound(
            &resolver,
            &request.target,
            &runtime,
            inbound_tag.as_str(),
            &context_identity,
            peer_addr,
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

    let mut context = TrafficContext::new("hysteria2")
        .with_identity(context_identity)
        .with_inbound_tag((*inbound_tag).clone())
        .with_client_ip(peer_addr.ip());
    if let Some(tag) = connection.outbound_tag {
        context = context.with_outbound_tag(tag);
    }

    proxy_tcp(stream, connection.stream, context).await
}

struct TcpRequest"""
text, count = pattern.subn(replacement, text, count=1)
assert count == 1, f"handle block replacements: {count}"

text = text.replace(
    "    async fn read(stream: &mut quinn::RecvStream) -> std::io::Result<Self> {\n",
    "    async fn read<S>(stream: &mut S) -> std::io::Result<Self>\n    where\n        S: AsyncRead + Unpin,\n    {\n",
    1,
)

pattern = re.compile(
    r"async fn proxy_tcp\(.*?\n}\n\nenum AuthReject",
    re.S,
)
replacement = """async fn proxy_tcp<S>(
    quic_stream: S,
    tcp_stream: tokio::net::TcpStream,
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

struct H3RawStream {
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

enum AuthReject"""
text, count = pattern.subn(replacement, text, count=1)
assert count == 1, f"proxy block replacements: {count}"

text = text.replace(
    "async fn read_varint(stream: &mut quinn::RecvStream) -> std::io::Result<u64> {\n",
    "async fn read_varint<S>(stream: &mut S) -> std::io::Result<u64>\nwhere\n    S: AsyncRead + Unpin,\n{\n",
    1,
)
text = text.replace(
    "async fn skip_padding(\n    stream: &mut quinn::RecvStream,\n    mut len: usize,\n) -> std::io::Result<()> {\n",
    "async fn skip_padding<S>(stream: &mut S, mut len: usize) -> std::io::Result<()>\nwhere\n    S: AsyncRead + Unpin,\n{\n",
    1,
)
text = text.replace(
    "async fn send_tcp_response(\n    stream: &mut quinn::SendStream,\n    status: u8,\n    message: &str,\n) -> std::io::Result<()> {\n",
    "async fn send_tcp_response<S>(\n    stream: &mut S,\n    status: u8,\n    message: &str,\n) -> std::io::Result<()>\nwhere\n    S: AsyncWrite + Unpin,\n{\n",
    1,
)

test_marker = "    #[test]\n    fn shoes_padding_bounds_apply_to_auth_and_tcp_frames() {"
test = """    #[tokio::test]
    async fn tcp_request_parser_accepts_xray_raw_stream_format() {
        let target = "127.0.0.1:443";
        let mut frame = Vec::new();
        push_varint(&mut frame, TCP_REQUEST_ID).expect("request type varint");
        push_varint(&mut frame, target.len() as u64).expect("address length varint");
        frame.extend_from_slice(target.as_bytes());
        push_varint(&mut frame, 3).expect("padding length varint");
        frame.extend_from_slice(b"pad");

        let (mut writer, mut reader) = tokio::io::duplex(frame.len());
        writer.write_all(&frame).await.expect("write request frame");
        writer.shutdown().await.expect("finish request frame");

        let request = TcpRequest::read(&mut reader)
            .await
            .expect("parse Xray Hysteria2 TCP request");
        assert_eq!(request.target.to_string(), target);
    }

"""
assert test_marker in text
text = text.replace(test_marker, test + test_marker, 1)

path.write_text(text)
