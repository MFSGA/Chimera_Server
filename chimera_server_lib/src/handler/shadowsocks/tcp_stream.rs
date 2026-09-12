use super::*;

pub(super) fn spawn_aead_codec(
    encrypted: Box<dyn AsyncStream>,
    cipher: ShadowsocksCipher,
    master_key: Arc<[u8]>,
    salt_checker: Arc<Mutex<TimedSaltChecker>>,
) -> TaskBackedStream {
    let (encrypted_reader, encrypted_writer) = tokio::io::split(encrypted);
    let (plain_client, plain_codec) = tokio::io::duplex(CODEC_BUFFER_SIZE);
    let (plain_reader, plain_writer) = tokio::io::split(plain_codec);

    let decrypt_key = master_key.clone();
    let decrypt_task = task::spawn(async move {
        if let Err(error) = decrypt_stream(
            encrypted_reader,
            plain_writer,
            cipher,
            decrypt_key,
            salt_checker,
        )
        .await
        {
            debug!("Shadowsocks decrypt task ended with error: {error}");
        }
    });
    let encrypt_task = task::spawn(async move {
        if let Err(error) =
            encrypt_stream(plain_reader, encrypted_writer, cipher, master_key).await
        {
            debug!("Shadowsocks encrypt task ended with error: {error}");
        }
    });

    TaskBackedStream::new(plain_client, decrypt_task, encrypt_task)
}

pub(super) fn spawn_aead2022_codec(
    encrypted: Box<dyn AsyncStream>,
    cipher: ShadowsocksCipher,
    psk: Arc<[u8]>,
    salt_checker: Arc<Mutex<TimedSaltChecker>>,
) -> TaskBackedStream {
    let (encrypted_reader, encrypted_writer) = tokio::io::split(encrypted);
    let (plain_client, plain_codec) = tokio::io::duplex(CODEC_BUFFER_SIZE);
    let (plain_reader, plain_writer) = tokio::io::split(plain_codec);
    let (request_salt_tx, request_salt_rx) = oneshot::channel();

    let decrypt_key = psk.clone();
    let decrypt_task = task::spawn(async move {
        if let Err(error) = decrypt_aead2022_stream(
            encrypted_reader,
            plain_writer,
            cipher,
            decrypt_key,
            salt_checker,
            request_salt_tx,
        )
        .await
        {
            debug!("Shadowsocks 2022 decrypt task ended with error: {error}");
        }
    });
    let encrypt_task = task::spawn(async move {
        if let Err(error) = encrypt_aead2022_stream(
            plain_reader,
            encrypted_writer,
            cipher,
            psk,
            request_salt_rx,
        )
        .await
        {
            debug!("Shadowsocks 2022 encrypt task ended with error: {error}");
        }
    });

    TaskBackedStream::new(plain_client, decrypt_task, encrypt_task)
}

async fn decrypt_aead2022_stream<R, W>(
    mut encrypted: R,
    mut plaintext: W,
    cipher: ShadowsocksCipher,
    psk: Arc<[u8]>,
    salt_checker: Arc<Mutex<TimedSaltChecker>>,
    request_salt_tx: oneshot::Sender<Vec<u8>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut salt = vec![0u8; cipher.salt_len];
    encrypted.read_exact(&mut salt).await?;
    let session_key = derive_aead2022_session_key(&psk, &salt, cipher.key_len())?;
    let unbound_key = UnboundKey::new(cipher.algorithm, &session_key)
        .map_err(|_| io::Error::other("invalid Shadowsocks 2022 opening key"))?;
    let mut opening_key = OpeningKey::new(unbound_key, IncreasingSequence::new());

    let mut fixed_header = vec![0u8; 11 + TAG_LEN];
    encrypted.read_exact(&mut fixed_header).await?;
    let fixed_len = opening_key
        .open_in_place(Aad::empty(), &mut fixed_header)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Shadowsocks 2022 request header",
            )
        })?
        .len();
    fixed_header.truncate(fixed_len);
    if fixed_header.len() != 11 || fixed_header[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Shadowsocks 2022 client stream header type",
        ));
    }
    let timestamp = u64::from_be_bytes(
        fixed_header[1..9]
            .try_into()
            .expect("fixed timestamp length"),
    );
    validate_aead2022_timestamp(timestamp)?;
    let variable_len =
        u16::from_be_bytes([fixed_header[9], fixed_header[10]]) as usize;
    if variable_len == 0 || variable_len > MAX_AEAD2022_VARIABLE_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid Shadowsocks 2022 variable header length: {variable_len}"
            ),
        ));
    }

    let accepted = salt_checker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(&salt);
    if !accepted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "replayed Shadowsocks 2022 salt",
        ));
    }

    let mut variable_header = vec![0u8; variable_len + TAG_LEN];
    encrypted.read_exact(&mut variable_header).await?;
    let opened_len = opening_key
        .open_in_place(Aad::empty(), &mut variable_header)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Shadowsocks 2022 variable request header",
            )
        })?
        .len();
    variable_header.truncate(opened_len);
    if variable_header.len() != variable_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected Shadowsocks 2022 variable header length",
        ));
    }

    let _ = request_salt_tx.send(salt);
    plaintext.write_all(&variable_header).await?;
    plaintext.flush().await?;

    decrypt_chunk_stream(
        &mut encrypted,
        &mut plaintext,
        &mut opening_key,
        MAX_AEAD2022_PAYLOAD_LEN,
    )
    .await
}

async fn encrypt_aead2022_stream<R, W>(
    mut plaintext: R,
    mut encrypted: W,
    cipher: ShadowsocksCipher,
    psk: Arc<[u8]>,
    request_salt_rx: oneshot::Receiver<Vec<u8>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let request_salt = request_salt_rx.await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Shadowsocks 2022 request validation failed",
        )
    })?;

    let mut first_payload = vec![0u8; MAX_AEAD2022_PAYLOAD_LEN];
    let first_len = plaintext.read(&mut first_payload).await?;
    if first_len == 0 {
        return encrypted.shutdown().await;
    }
    first_payload.truncate(first_len);

    let mut salt = vec![0u8; cipher.salt_len];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| io::Error::other("failed to generate Shadowsocks 2022 salt"))?;
    let session_key = derive_aead2022_session_key(&psk, &salt, cipher.key_len())?;
    let unbound_key = UnboundKey::new(cipher.algorithm, &session_key)
        .map_err(|_| io::Error::other("invalid Shadowsocks 2022 sealing key"))?;
    let mut sealing_key = SealingKey::new(unbound_key, IncreasingSequence::new());

    let mut fixed_header = Vec::with_capacity(11 + request_salt.len());
    fixed_header.push(1);
    fixed_header.extend_from_slice(&current_time_secs().to_be_bytes());
    fixed_header.extend_from_slice(&request_salt);
    fixed_header.extend_from_slice(&(first_len as u16).to_be_bytes());
    let fixed_tag = sealing_key
        .seal_in_place_separate_tag(Aad::empty(), &mut fixed_header)
        .map_err(|_| {
            io::Error::other("failed to encrypt Shadowsocks 2022 response header")
        })?;
    let first_tag = sealing_key
        .seal_in_place_separate_tag(Aad::empty(), &mut first_payload)
        .map_err(|_| {
            io::Error::other("failed to encrypt Shadowsocks 2022 first response")
        })?;

    encrypted.write_all(&salt).await?;
    encrypted.write_all(&fixed_header).await?;
    encrypted.write_all(fixed_tag.as_ref()).await?;
    encrypted.write_all(&first_payload).await?;
    encrypted.write_all(first_tag.as_ref()).await?;
    encrypted.flush().await?;

    encrypt_chunk_stream(
        &mut plaintext,
        &mut encrypted,
        &mut sealing_key,
        MAX_AEAD2022_PAYLOAD_LEN,
    )
    .await
}

async fn decrypt_chunk_stream<R, W, N>(
    encrypted: &mut R,
    plaintext: &mut W,
    opening_key: &mut OpeningKey<N>,
    max_payload_len: usize,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    N: NonceSequence,
{
    loop {
        let mut encrypted_length = vec![0u8; 2 + TAG_LEN];
        match encrypted.read_exact(&mut encrypted_length).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error),
        }
        opening_key
            .open_in_place(Aad::empty(), &mut encrypted_length)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Shadowsocks encrypted length",
                )
            })?;
        let payload_len =
            u16::from_be_bytes([encrypted_length[0], encrypted_length[1]]) as usize;
        if payload_len > max_payload_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Shadowsocks payload length exceeds {max_payload_len}"),
            ));
        }

        let mut encrypted_payload = vec![0u8; payload_len + TAG_LEN];
        encrypted.read_exact(&mut encrypted_payload).await?;
        opening_key
            .open_in_place(Aad::empty(), &mut encrypted_payload)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Shadowsocks encrypted payload",
                )
            })?;
        plaintext
            .write_all(&encrypted_payload[..payload_len])
            .await?;
        plaintext.flush().await?;
    }

    plaintext.shutdown().await
}

async fn encrypt_chunk_stream<R, W, N>(
    plaintext: &mut R,
    encrypted: &mut W,
    sealing_key: &mut SealingKey<N>,
    max_payload_len: usize,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    N: NonceSequence,
{
    let mut buffer = vec![0u8; max_payload_len];
    loop {
        let read = plaintext.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let mut length = (read as u16).to_be_bytes();
        let length_tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut length)
            .map_err(|_| io::Error::other("failed to encrypt Shadowsocks length"))?;
        let mut payload = buffer[..read].to_vec();
        let payload_tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut payload)
            .map_err(|_| {
                io::Error::other("failed to encrypt Shadowsocks payload")
            })?;
        encrypted.write_all(&length).await?;
        encrypted.write_all(length_tag.as_ref()).await?;
        encrypted.write_all(&payload).await?;
        encrypted.write_all(payload_tag.as_ref()).await?;
        encrypted.flush().await?;
    }
    encrypted.shutdown().await
}

pub(super) async fn decrypt_stream<R, W>(
    mut encrypted: R,
    mut plaintext: W,
    cipher: ShadowsocksCipher,
    master_key: Arc<[u8]>,
    salt_checker: Arc<Mutex<TimedSaltChecker>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut salt = vec![0u8; cipher.salt_len];
    encrypted.read_exact(&mut salt).await?;
    let accepted = salt_checker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(&salt);
    if !accepted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "replayed Shadowsocks salt",
        ));
    }

    let session_key = derive_session_key(&master_key, &salt, cipher.key_len())?;
    if cipher.is_xchacha() {
        return decrypt_xchacha_stream_body(
            &mut encrypted,
            &mut plaintext,
            &session_key,
        )
        .await;
    }
    let unbound_key = UnboundKey::new(cipher.algorithm, &session_key)
        .map_err(|_| io::Error::other("invalid Shadowsocks opening key"))?;
    let mut opening_key = OpeningKey::new(unbound_key, IncreasingSequence::new());

    decrypt_chunk_stream(
        &mut encrypted,
        &mut plaintext,
        &mut opening_key,
        MAX_PAYLOAD_LEN,
    )
    .await
}

pub(super) async fn encrypt_stream<R, W>(
    mut plaintext: R,
    mut encrypted: W,
    cipher: ShadowsocksCipher,
    master_key: Arc<[u8]>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut salt = vec![0u8; cipher.salt_len];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| io::Error::other("failed to generate Shadowsocks salt"))?;
    let session_key = derive_session_key(&master_key, &salt, cipher.key_len())?;
    if cipher.is_xchacha() {
        return encrypt_xchacha_stream_body(
            &mut plaintext,
            &mut encrypted,
            &salt,
            &session_key,
        )
        .await;
    }
    let unbound_key = UnboundKey::new(cipher.algorithm, &session_key)
        .map_err(|_| io::Error::other("invalid Shadowsocks sealing key"))?;
    let mut sealing_key = SealingKey::new(unbound_key, IncreasingSequence::new());
    let mut sent_salt = false;
    let mut buffer = vec![0u8; MAX_PAYLOAD_LEN];

    loop {
        let read = plaintext.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        if !sent_salt {
            encrypted.write_all(&salt).await?;
            sent_salt = true;
        }

        let mut length = (read as u16).to_be_bytes();
        let length_tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut length)
            .map_err(|_| io::Error::other("failed to encrypt Shadowsocks length"))?;
        encrypted.write_all(&length).await?;
        encrypted.write_all(length_tag.as_ref()).await?;

        let mut payload = buffer[..read].to_vec();
        let payload_tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut payload)
            .map_err(|_| {
                io::Error::other("failed to encrypt Shadowsocks payload")
            })?;
        encrypted.write_all(&payload).await?;
        encrypted.write_all(payload_tag.as_ref()).await?;
        encrypted.flush().await?;
    }

    encrypted.shutdown().await
}

async fn decrypt_xchacha_stream_body<R, W>(
    encrypted: &mut R,
    plaintext: &mut W,
    session_key: &[u8],
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let cipher = XChaCha20Poly1305::new_from_slice(session_key)
        .map_err(|_| io::Error::other("invalid Shadowsocks XChaCha opening key"))?;
    let mut nonce = [0u8; 24];

    loop {
        let mut encrypted_length = vec![0u8; 2 + TAG_LEN];
        match encrypted.read_exact(&mut encrypted_length).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error),
        }
        let current_nonce = take_xchacha_nonce(&mut nonce);
        cipher
            .decrypt_in_place(
                XNonce::from_slice(&current_nonce),
                b"",
                &mut encrypted_length,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Shadowsocks encrypted length",
                )
            })?;
        let payload_len =
            u16::from_be_bytes([encrypted_length[0], encrypted_length[1]]) as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Shadowsocks payload length exceeds {MAX_PAYLOAD_LEN}"),
            ));
        }

        let mut encrypted_payload = vec![0u8; payload_len + TAG_LEN];
        encrypted.read_exact(&mut encrypted_payload).await?;
        let current_nonce = take_xchacha_nonce(&mut nonce);
        cipher
            .decrypt_in_place(
                XNonce::from_slice(&current_nonce),
                b"",
                &mut encrypted_payload,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Shadowsocks encrypted payload",
                )
            })?;
        plaintext.write_all(&encrypted_payload).await?;
        plaintext.flush().await?;
    }

    plaintext.shutdown().await
}

async fn encrypt_xchacha_stream_body<R, W>(
    plaintext: &mut R,
    encrypted: &mut W,
    salt: &[u8],
    session_key: &[u8],
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let cipher = XChaCha20Poly1305::new_from_slice(session_key)
        .map_err(|_| io::Error::other("invalid Shadowsocks XChaCha sealing key"))?;
    let mut nonce = [0u8; 24];
    let mut sent_salt = false;
    let mut buffer = vec![0u8; MAX_PAYLOAD_LEN];

    loop {
        let read = plaintext.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        if !sent_salt {
            encrypted.write_all(salt).await?;
            sent_salt = true;
        }

        let mut length = (read as u16).to_be_bytes().to_vec();
        let current_nonce = take_xchacha_nonce(&mut nonce);
        cipher
            .encrypt_in_place(XNonce::from_slice(&current_nonce), b"", &mut length)
            .map_err(|_| io::Error::other("failed to encrypt Shadowsocks length"))?;
        encrypted.write_all(&length).await?;

        let mut payload = buffer[..read].to_vec();
        let current_nonce = take_xchacha_nonce(&mut nonce);
        cipher
            .encrypt_in_place(XNonce::from_slice(&current_nonce), b"", &mut payload)
            .map_err(|_| {
                io::Error::other("failed to encrypt Shadowsocks payload")
            })?;
        encrypted.write_all(&payload).await?;
        encrypted.flush().await?;
    }

    encrypted.shutdown().await
}

fn take_xchacha_nonce(nonce: &mut [u8; 24]) -> [u8; 24] {
    let current = *nonce;
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    current
}

pub(super) async fn read_socks_location<S>(stream: &mut S) -> io::Result<NetLocation>
where
    S: AsyncRead + Unpin,
{
    match stream.read_u8().await? {
        1 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
            let port = stream.read_u16().await?;
            Ok(NetLocation::new(Address::Ipv4(address.into()), port))
        }
        3 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shadowsocks target domain is empty",
                ));
            }
            let mut domain = vec![0u8; length];
            stream.read_exact(&mut domain).await?;
            let domain = std::str::from_utf8(&domain).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Shadowsocks target domain: {error}"),
                )
            })?;
            let port = stream.read_u16().await?;
            Ok(NetLocation::new(Address::from(domain)?, port))
        }
        4 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;
            let port = stream.read_u16().await?;
            Ok(NetLocation::new(Address::Ipv6(address.into()), port))
        }
        address_type => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown Shadowsocks address type: {address_type}"),
        )),
    }
}

pub(super) struct TaskBackedStream {
    stream: DuplexStream,
    pub(super) decrypt_task: JoinHandle<()>,
    pub(super) encrypt_task: Option<JoinHandle<()>>,
}

impl TaskBackedStream {
    fn new(
        stream: DuplexStream,
        decrypt_task: JoinHandle<()>,
        encrypt_task: JoinHandle<()>,
    ) -> Self {
        Self {
            stream,
            decrypt_task,
            encrypt_task: Some(encrypt_task),
        }
    }

    fn poll_encrypt_shutdown(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(task) = self.encrypt_task.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match std::future::Future::poll(Pin::new(task), cx) {
            Poll::Ready(Ok(())) => {
                self.encrypt_task = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.encrypt_task = None;
                Poll::Ready(Err(io::Error::other(format!(
                    "Shadowsocks encrypt task failed: {error}"
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for TaskBackedStream {
    fn drop(&mut self) {
        self.decrypt_task.abort();
        if let Some(task) = self.encrypt_task.as_ref() {
            task.abort();
        }
    }
}

impl std::fmt::Debug for TaskBackedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksTaskBackedStream")
            .finish_non_exhaustive()
    }
}

impl AsyncRead for TaskBackedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TaskBackedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.stream).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => this.poll_encrypt_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncPing for TaskBackedStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for TaskBackedStream {}
