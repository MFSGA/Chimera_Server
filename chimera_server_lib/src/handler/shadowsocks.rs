use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

use aes::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use async_trait::async_trait;
use aws_lc_rs::{
    aead::{
        AES_128_GCM, AES_256_GCM, Aad, Algorithm, BoundKey, CHACHA20_POLY1305,
        LessSafeKey, NONCE_LEN, Nonce, NonceSequence, OpeningKey, SealingKey,
        UnboundKey,
    },
    error::Unspecified,
    rand::{SecureRandom, SystemRandom},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::AeadInPlace as _};
use md5::{Digest, Md5};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
    },
    sync::oneshot,
    task,
};
use tracing::debug;

use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::{ShadowsocksServerIdentity, ShadowsocksUser},
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    traffic::TrafficContext,
    util::prefixed_stream::PrefixedStream,
};

const TAG_LEN: usize = 16;
const MAX_PAYLOAD_LEN: usize = 0x3fff;
const MAX_AEAD2022_PAYLOAD_LEN: usize = 0xffff;
const MAX_AEAD2022_VARIABLE_HEADER_LEN: usize = 18 * 1024;
const CODEC_BUFFER_SIZE: usize = 64 * 1024;
const SALT_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
pub struct ShadowsocksCipher {
    algorithm: &'static Algorithm,
    salt_len: usize,
    name: &'static str,
}

impl ShadowsocksCipher {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Ok(Self {
                algorithm: &AES_128_GCM,
                salt_len: 16,
                name: "aes-128-gcm",
            }),
            "aes-256-gcm" | "aead_aes_256_gcm" => Ok(Self {
                algorithm: &AES_256_GCM,
                salt_len: 32,
                name: "aes-256-gcm",
            }),
            "chacha20-poly1305"
            | "aead_chacha20_poly1305"
            | "chacha20-ietf-poly1305" => Ok(Self {
                algorithm: &CHACHA20_POLY1305,
                salt_len: 32,
                name: "chacha20-ietf-poly1305",
            }),
            "xchacha20-poly1305"
            | "aead_xchacha20_poly1305"
            | "xchacha20-ietf-poly1305" => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xchacha20-poly1305 Shadowsocks is not supported yet",
            )),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported Shadowsocks cipher method: {other}"),
            )),
        }
    }

    pub(crate) fn key_len(self) -> usize {
        self.algorithm.key_len()
    }

    pub(crate) fn name(self) -> &'static str {
        self.name
    }
}

pub(crate) fn compile_legacy_outbound_key(
    method: &str,
    password: &str,
) -> io::Result<(ShadowsocksCipher, Arc<[u8]>)> {
    if password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shadowsocks password is not specified",
        ));
    }
    if method
        .trim()
        .to_ascii_lowercase()
        .starts_with("2022-blake3-")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shadowsocks 2022 outbound is not supported by the legacy TCP slice",
        ));
    }
    let cipher = ShadowsocksCipher::parse(method)?;
    let master_key = derive_master_key(password, cipher.key_len());
    Ok((cipher, master_key.into()))
}

pub(crate) async fn connect_legacy_aead_outbound(
    encrypted: Box<dyn AsyncStream>,
    cipher: ShadowsocksCipher,
    master_key: Arc<[u8]>,
    target: &NetLocation,
) -> io::Result<Box<dyn AsyncStream>> {
    let mut plaintext = spawn_aead_codec(
        encrypted,
        cipher,
        master_key,
        Arc::new(Mutex::new(TimedSaltChecker::default())),
    );
    plaintext.write_all(&encode_socks_location(target)?).await?;
    plaintext.flush().await?;
    Ok(Box::new(plaintext))
}

#[derive(Debug, Clone)]
enum ShadowsocksKeyMaterial {
    Legacy(Arc<[u8]>),
    Aead2022(Arc<[u8]>),
}

impl ShadowsocksKeyMaterial {
    fn is_aead2022(&self) -> bool {
        matches!(self, Self::Aead2022(_))
    }

    fn bytes(&self) -> Arc<[u8]> {
        match self {
            Self::Legacy(key) | Self::Aead2022(key) => key.clone(),
        }
    }
}

fn parse_user_key(
    user: &ShadowsocksUser,
) -> io::Result<(ShadowsocksCipher, ShadowsocksKeyMaterial)> {
    if user.password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shadowsocks password is not specified",
        ));
    }
    if let Some(method) = user.method.strip_prefix("2022-blake3-") {
        let cipher = ShadowsocksCipher::parse(method)?;
        let key = BASE64.decode(&user.password).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Shadowsocks 2022 base64 key: {error}"),
            )
        })?;
        if key.len() != cipher.key_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Shadowsocks 2022 key length must be {} bytes, got {}",
                    cipher.key_len(),
                    key.len()
                ),
            ));
        }
        Ok((cipher, ShadowsocksKeyMaterial::Aead2022(key.into())))
    } else {
        let cipher = ShadowsocksCipher::parse(&user.method)?;
        Ok((
            cipher,
            ShadowsocksKeyMaterial::Legacy(
                derive_master_key(&user.password, cipher.key_len()).into(),
            ),
        ))
    }
}

pub(crate) fn validate_user(user: &ShadowsocksUser) -> io::Result<()> {
    parse_user_key(user).map(|_| ())
}

#[derive(Debug, Clone)]
struct ShadowsocksIdentityKey {
    cipher: ShadowsocksCipher,
    psk: Arc<[u8]>,
}

fn parse_identity_key(
    identity: ShadowsocksServerIdentity,
) -> io::Result<ShadowsocksIdentityKey> {
    if !matches!(
        identity.method.as_str(),
        "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm"
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shadowsocks 2022 EIH identity must use AES-128-GCM or AES-256-GCM",
        ));
    }
    let user = ShadowsocksUser {
        method: identity.method,
        password: identity.password,
        email: String::new(),
    };
    let (cipher, key) = parse_user_key(&user)?;
    let ShadowsocksKeyMaterial::Aead2022(psk) = key else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shadowsocks EIH identity must be an AEAD 2022 key",
        ));
    };
    Ok(ShadowsocksIdentityKey { cipher, psk })
}

#[derive(Debug)]
struct SaltEntry {
    inserted: Instant,
    salt: Box<[u8]>,
}

#[derive(Debug, Default)]
struct TimedSaltChecker {
    queue: VecDeque<SaltEntry>,
    known: HashSet<Box<[u8]>>,
}

impl TimedSaltChecker {
    fn insert(&mut self, salt: &[u8]) -> bool {
        let now = Instant::now();
        while self
            .queue
            .front()
            .is_some_and(|entry| now.duration_since(entry.inserted) >= SALT_TTL)
        {
            if let Some(entry) = self.queue.pop_front() {
                self.known.remove(&entry.salt);
            }
        }
        if !self.known.insert(salt.into()) {
            return false;
        }
        self.queue.push_back(SaltEntry {
            inserted: now,
            salt: salt.into(),
        });
        true
    }
}

#[derive(Debug)]
enum ShadowsocksUdpMode {
    Legacy {
        master_key: Arc<[u8]>,
        salt_checker: Arc<Mutex<TimedSaltChecker>>,
    },
    Aead2022Aes {
        psk: Arc<[u8]>,
        replay: Mutex<UdpReplayState>,
        server_session_id: [u8; 8],
        next_server_packet_id: AtomicU64,
    },
    Aead2022ChaCha {
        psk: Arc<[u8]>,
        replay: Mutex<UdpReplayState>,
        server_session_id: [u8; 8],
        next_server_packet_id: AtomicU64,
    },
}

#[derive(Debug)]
struct UdpReplaySession {
    last_seen: Instant,
    highest_packet_id: u64,
    packet_ids: HashSet<u64>,
}

#[derive(Debug, Default)]
struct UdpReplayState {
    sessions: HashMap<[u8; 8], UdpReplaySession>,
}

impl UdpReplayState {
    fn check_and_insert(&mut self, session_id: [u8; 8], packet_id: u64) -> bool {
        let now = Instant::now();
        self.sessions
            .retain(|_, session| now.duration_since(session.last_seen) < SALT_TTL);
        let session =
            self.sessions
                .entry(session_id)
                .or_insert_with(|| UdpReplaySession {
                    last_seen: now,
                    highest_packet_id: packet_id,
                    packet_ids: HashSet::new(),
                });
        if packet_id.saturating_add(1024) < session.highest_packet_id
            || !session.packet_ids.insert(packet_id)
        {
            return false;
        }
        session.last_seen = now;
        session.highest_packet_id = session.highest_packet_id.max(packet_id);
        let floor = session.highest_packet_id.saturating_sub(1024);
        session.packet_ids.retain(|id| *id >= floor);
        true
    }
}

#[derive(Debug)]
pub(crate) struct ShadowsocksUdpRequest {
    pub target_location: NetLocation,
    pub payload: Vec<u8>,
    pub identity: String,
    user_index: usize,
    client_session_id: Option<[u8; 8]>,
}

#[derive(Debug)]
struct ShadowsocksUdpUserCodec {
    cipher: ShadowsocksCipher,
    mode: ShadowsocksUdpMode,
    identity: String,
}

impl ShadowsocksUdpUserCodec {
    fn new(user: ShadowsocksUser) -> io::Result<Self> {
        let (cipher, key) = parse_user_key(&user)?;
        let mode = match key {
            ShadowsocksKeyMaterial::Legacy(master_key) => {
                ShadowsocksUdpMode::Legacy {
                    master_key,
                    salt_checker: Arc::new(Mutex::new(TimedSaltChecker::default())),
                }
            }
            ShadowsocksKeyMaterial::Aead2022(psk)
                if cipher.algorithm == &AES_128_GCM
                    || cipher.algorithm == &AES_256_GCM =>
            {
                let mut server_session_id = [0u8; 8];
                SystemRandom::new()
                    .fill(&mut server_session_id)
                    .map_err(|_| {
                        io::Error::other(
                            "failed to generate Shadowsocks 2022 UDP session ID",
                        )
                    })?;
                ShadowsocksUdpMode::Aead2022Aes {
                    psk,
                    replay: Mutex::new(UdpReplayState::default()),
                    server_session_id,
                    next_server_packet_id: AtomicU64::new(0),
                }
            }
            ShadowsocksKeyMaterial::Aead2022(psk) => {
                let mut server_session_id = [0u8; 8];
                SystemRandom::new()
                    .fill(&mut server_session_id)
                    .map_err(|_| {
                        io::Error::other(
                            "failed to generate Shadowsocks 2022 UDP session ID",
                        )
                    })?;
                ShadowsocksUdpMode::Aead2022ChaCha {
                    psk,
                    replay: Mutex::new(UdpReplayState::default()),
                    server_session_id,
                    next_server_packet_id: AtomicU64::new(0),
                }
            }
        };
        Ok(Self {
            cipher,
            mode,
            identity: user.email,
        })
    }

    fn aead2022_psk(&self) -> Option<&[u8]> {
        match &self.mode {
            ShadowsocksUdpMode::Aead2022Aes { psk, .. }
            | ShadowsocksUdpMode::Aead2022ChaCha { psk, .. } => Some(psk),
            ShadowsocksUdpMode::Legacy { .. } => None,
        }
    }

    pub(crate) fn decrypt_packet(
        &self,
        packet: &[u8],
    ) -> io::Result<ShadowsocksUdpRequest> {
        match &self.mode {
            ShadowsocksUdpMode::Legacy {
                master_key,
                salt_checker,
            } => self.decrypt_legacy_packet(packet, master_key, salt_checker),
            ShadowsocksUdpMode::Aead2022Aes { psk, replay, .. } => {
                self.decrypt_aead2022_aes_packet(packet, psk, replay)
            }
            ShadowsocksUdpMode::Aead2022ChaCha { psk, replay, .. } => {
                self.decrypt_aead2022_chacha_packet(packet, psk, replay)
            }
        }
    }

    pub(crate) fn encrypt_packet(
        &self,
        request: &ShadowsocksUdpRequest,
        source: &NetLocation,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        match &self.mode {
            ShadowsocksUdpMode::Legacy { master_key, .. } => {
                self.encrypt_legacy_packet(source, payload, master_key)
            }
            ShadowsocksUdpMode::Aead2022Aes {
                psk,
                server_session_id,
                next_server_packet_id,
                ..
            } => self.encrypt_aead2022_aes_packet(
                request.client_session_id.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "missing Shadowsocks 2022 client session ID",
                    )
                })?,
                source,
                payload,
                psk,
                *server_session_id,
                next_server_packet_id.fetch_add(1, Ordering::Relaxed),
            ),
            ShadowsocksUdpMode::Aead2022ChaCha {
                psk,
                server_session_id,
                next_server_packet_id,
                ..
            } => self.encrypt_aead2022_chacha_packet(
                request.client_session_id.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "missing Shadowsocks 2022 client session ID",
                    )
                })?,
                source,
                payload,
                psk,
                *server_session_id,
                next_server_packet_id.fetch_add(1, Ordering::Relaxed),
            ),
        }
    }

    fn decrypt_legacy_packet(
        &self,
        packet: &[u8],
        master_key: &[u8],
        salt_checker: &Mutex<TimedSaltChecker>,
    ) -> io::Result<ShadowsocksUdpRequest> {
        if packet.len() < self.cipher.salt_len + TAG_LEN + 1 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Shadowsocks UDP packet is too short",
            ));
        }
        let (salt, encrypted) = packet.split_at(self.cipher.salt_len);
        if !salt_checker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(salt)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "replayed Shadowsocks UDP salt",
            ));
        }
        let session_key =
            derive_session_key(master_key, salt, self.cipher.key_len())?;
        let unbound_key = UnboundKey::new(self.cipher.algorithm, &session_key)
            .map_err(|_| io::Error::other("invalid Shadowsocks UDP opening key"))?;
        let mut opening = OpeningKey::new(unbound_key, IncreasingSequence::new());
        let mut plaintext = encrypted.to_vec();
        let opened = opening
            .open_in_place(Aad::empty(), &mut plaintext)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Shadowsocks UDP authentication tag",
                )
            })?
            .len();
        plaintext.truncate(opened);
        let (target_location, offset) = parse_socks_location_slice(&plaintext)?;
        Ok(ShadowsocksUdpRequest {
            target_location,
            payload: plaintext[offset..].to_vec(),
            identity: String::new(),
            user_index: 0,
            client_session_id: None,
        })
    }

    fn encrypt_legacy_packet(
        &self,
        source: &NetLocation,
        payload: &[u8],
        master_key: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut salt = vec![0u8; self.cipher.salt_len];
        SystemRandom::new().fill(&mut salt).map_err(|_| {
            io::Error::other("failed to generate Shadowsocks UDP salt")
        })?;
        let session_key =
            derive_session_key(master_key, &salt, self.cipher.key_len())?;
        let unbound_key = UnboundKey::new(self.cipher.algorithm, &session_key)
            .map_err(|_| io::Error::other("invalid Shadowsocks UDP sealing key"))?;
        let mut sealing = SealingKey::new(unbound_key, IncreasingSequence::new());
        let mut plaintext = encode_socks_location(source)?;
        plaintext.extend_from_slice(payload);
        let tag = sealing
            .seal_in_place_separate_tag(Aad::empty(), &mut plaintext)
            .map_err(|_| {
                io::Error::other("failed to encrypt Shadowsocks UDP packet")
            })?;
        let mut packet = Vec::with_capacity(salt.len() + plaintext.len() + TAG_LEN);
        packet.extend_from_slice(&salt);
        packet.extend_from_slice(&plaintext);
        packet.extend_from_slice(tag.as_ref());
        Ok(packet)
    }

    fn decrypt_aead2022_aes_packet(
        &self,
        packet: &[u8],
        psk: &[u8],
        replay: &Mutex<UdpReplayState>,
    ) -> io::Result<ShadowsocksUdpRequest> {
        if packet.len() < 16 + TAG_LEN + 12 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Shadowsocks 2022 UDP packet is too short",
            ));
        }
        let mut separate_header = [0u8; 16];
        separate_header.copy_from_slice(&packet[..16]);
        aes_decrypt_block(psk, &mut separate_header)?;
        let mut client_session_id = [0u8; 8];
        client_session_id.copy_from_slice(&separate_header[..8]);
        let packet_id = u64::from_be_bytes(
            separate_header[8..16].try_into().expect("packet id length"),
        );

        let session_key = derive_aead2022_session_key(
            psk,
            &client_session_id,
            self.cipher.key_len(),
        )?;
        let unbound_key = UnboundKey::new(self.cipher.algorithm, &session_key)
            .map_err(|_| io::Error::other("invalid Shadowsocks 2022 UDP key"))?;
        let key = LessSafeKey::new(unbound_key);
        let nonce = udp_aead2022_nonce(&separate_header)?;
        let mut body = packet[16..].to_vec();
        let opened = key
            .open_in_place(nonce, Aad::empty(), &mut body)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Shadowsocks 2022 UDP body",
                )
            })?
            .len();
        body.truncate(opened);
        if body.len() < 11 || body[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Shadowsocks 2022 client UDP header",
            ));
        }
        validate_aead2022_timestamp(u64::from_be_bytes(
            body[1..9].try_into().expect("timestamp length"),
        ))?;
        let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
        let address_offset = 11usize.checked_add(padding_len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "UDP padding overflow")
        })?;
        if address_offset >= body.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated Shadowsocks 2022 UDP padding",
            ));
        }
        let (target_location, address_len) =
            parse_socks_location_slice(&body[address_offset..])?;
        let payload_offset = address_offset + address_len;
        if !replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .check_and_insert(client_session_id, packet_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "replayed Shadowsocks 2022 UDP packet",
            ));
        }
        Ok(ShadowsocksUdpRequest {
            target_location,
            payload: body[payload_offset..].to_vec(),
            identity: String::new(),
            user_index: 0,
            client_session_id: Some(client_session_id),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn encrypt_aead2022_aes_packet(
        &self,
        client_session_id: [u8; 8],
        source: &NetLocation,
        payload: &[u8],
        psk: &[u8],
        server_session_id: [u8; 8],
        packet_id: u64,
    ) -> io::Result<Vec<u8>> {
        let mut separate_header = [0u8; 16];
        separate_header[..8].copy_from_slice(&server_session_id);
        separate_header[8..].copy_from_slice(&packet_id.to_be_bytes());

        let session_key = derive_aead2022_session_key(
            psk,
            &server_session_id,
            self.cipher.key_len(),
        )?;
        let unbound_key = UnboundKey::new(self.cipher.algorithm, &session_key)
            .map_err(|_| io::Error::other("invalid Shadowsocks 2022 UDP key"))?;
        let key = LessSafeKey::new(unbound_key);
        let nonce = udp_aead2022_nonce(&separate_header)?;
        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&current_time_secs().to_be_bytes());
        body.extend_from_slice(&client_session_id);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&encode_socks_location(source)?);
        body.extend_from_slice(payload);
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut body)
            .map_err(|_| {
                io::Error::other("failed to seal Shadowsocks 2022 UDP body")
            })?;

        aes_encrypt_block(psk, &mut separate_header)?;
        let mut packet = Vec::with_capacity(16 + body.len());
        packet.extend_from_slice(&separate_header);
        packet.extend_from_slice(&body);
        Ok(packet)
    }

    fn decrypt_aead2022_chacha_packet(
        &self,
        packet: &[u8],
        psk: &[u8],
        replay: &Mutex<UdpReplayState>,
    ) -> io::Result<ShadowsocksUdpRequest> {
        if packet.len() < 24 + TAG_LEN + 28 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Shadowsocks 2022 ChaCha UDP packet is too short",
            ));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(psk).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Shadowsocks 2022 ChaCha UDP key",
            )
        })?;
        let nonce = XNonce::from_slice(&packet[..24]);
        let mut body = packet[24..].to_vec();
        cipher
            .decrypt_in_place(nonce, b"", &mut body)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Shadowsocks 2022 ChaCha UDP body",
                )
            })?;
        if body.len() < 27 || body[16] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Shadowsocks 2022 ChaCha client UDP header",
            ));
        }
        let mut client_session_id = [0u8; 8];
        client_session_id.copy_from_slice(&body[..8]);
        let packet_id =
            u64::from_be_bytes(body[8..16].try_into().expect("packet id length"));
        validate_aead2022_timestamp(u64::from_be_bytes(
            body[17..25].try_into().expect("timestamp length"),
        ))?;
        let padding_len = u16::from_be_bytes([body[25], body[26]]) as usize;
        let address_offset = 27usize.checked_add(padding_len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "UDP padding overflow")
        })?;
        if address_offset >= body.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated Shadowsocks 2022 ChaCha UDP padding",
            ));
        }
        let (target_location, address_len) =
            parse_socks_location_slice(&body[address_offset..])?;
        let payload_offset = address_offset + address_len;
        if !replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .check_and_insert(client_session_id, packet_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "replayed Shadowsocks 2022 ChaCha UDP packet",
            ));
        }
        Ok(ShadowsocksUdpRequest {
            target_location,
            payload: body[payload_offset..].to_vec(),
            identity: String::new(),
            user_index: 0,
            client_session_id: Some(client_session_id),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn encrypt_aead2022_chacha_packet(
        &self,
        client_session_id: [u8; 8],
        source: &NetLocation,
        payload: &[u8],
        psk: &[u8],
        server_session_id: [u8; 8],
        packet_id: u64,
    ) -> io::Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(psk).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Shadowsocks 2022 ChaCha UDP key",
            )
        })?;
        let mut nonce = [0u8; 24];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| io::Error::other("failed to generate XChaCha nonce"))?;
        let mut body = Vec::new();
        body.extend_from_slice(&server_session_id);
        body.extend_from_slice(&packet_id.to_be_bytes());
        body.push(1);
        body.extend_from_slice(&current_time_secs().to_be_bytes());
        body.extend_from_slice(&client_session_id);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&encode_socks_location(source)?);
        body.extend_from_slice(payload);
        cipher
            .encrypt_in_place(XNonce::from_slice(&nonce), b"", &mut body)
            .map_err(|_| {
                io::Error::other("failed to seal Shadowsocks 2022 ChaCha UDP body")
            })?;
        let mut packet = Vec::with_capacity(nonce.len() + body.len());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&body);
        Ok(packet)
    }
}

#[derive(Debug)]
pub(crate) struct ShadowsocksUdpCodec {
    users: Vec<ShadowsocksUdpUserCodec>,
    identity: Option<ShadowsocksIdentityKey>,
}

impl ShadowsocksUdpCodec {
    pub(crate) fn new(
        users: Vec<ShadowsocksUser>,
        identity: Option<ShadowsocksServerIdentity>,
    ) -> io::Result<Self> {
        if users.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks UDP requires at least one user",
            ));
        }
        let users = users
            .into_iter()
            .map(ShadowsocksUdpUserCodec::new)
            .collect::<io::Result<Vec<_>>>()?;
        let identity = identity.map(parse_identity_key).transpose()?;
        if let Some(identity) = &identity
            && users.iter().any(|user| {
                user.cipher.name != identity.cipher.name
                    || user.aead2022_psk().is_none()
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks EIH users must use the identity AES method",
            ));
        }
        Ok(Self { users, identity })
    }

    pub(crate) fn encrypt_client_packet(
        &self,
        target: &NetLocation,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        if self.identity.is_some() || self.users.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks UDP outbound requires exactly one non-EIH user",
            ));
        }
        let user = &self.users[0];
        match &user.mode {
            ShadowsocksUdpMode::Legacy { master_key, .. } => {
                user.encrypt_legacy_packet(target, payload, master_key)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Shadowsocks 2022 UDP outbound is not supported yet",
            )),
        }
    }

    pub(crate) fn decrypt_client_packet(
        &self,
        packet: &[u8],
    ) -> io::Result<(NetLocation, Vec<u8>)> {
        if self.identity.is_some() || self.users.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks UDP outbound requires exactly one non-EIH user",
            ));
        }
        let request = self.users[0].decrypt_packet(packet)?;
        Ok((request.target_location, request.payload))
    }

    pub(crate) fn decrypt_packet(
        &self,
        packet: &[u8],
    ) -> io::Result<ShadowsocksUdpRequest> {
        if let Some(identity) = &self.identity {
            return self.decrypt_eih_packet(packet, identity);
        }
        let mut last_error = None;
        for (user_index, user) in self.users.iter().enumerate() {
            match user.decrypt_packet(packet) {
                Ok(mut request) => {
                    request.user_index = user_index;
                    request.identity = user.identity.clone();
                    return Ok(request);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no Shadowsocks UDP user matched the packet",
            )
        }))
    }

    fn decrypt_eih_packet(
        &self,
        packet: &[u8],
        identity: &ShadowsocksIdentityKey,
    ) -> io::Result<ShadowsocksUdpRequest> {
        if packet.len() < 32 + TAG_LEN + 1 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Shadowsocks EIH UDP packet is too short",
            ));
        }
        let mut separate_header: [u8; 16] = packet[..16]
            .try_into()
            .expect("separate header length checked");
        aes_decrypt_block(&identity.psk, &mut separate_header)?;
        let mut user_hash: [u8; 16] = packet[16..32]
            .try_into()
            .expect("identity header length checked");
        aes_decrypt_block(&identity.psk, &mut user_hash)?;
        for (byte, header) in user_hash.iter_mut().zip(separate_header) {
            *byte ^= header;
        }
        let user_index = self
            .users
            .iter()
            .position(|user| {
                user.aead2022_psk()
                    .is_some_and(|psk| aead2022_user_hash(psk) == user_hash)
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unknown Shadowsocks EIH UDP user",
                )
            })?;
        let user = &self.users[user_index];
        let user_psk = user.aead2022_psk().expect("EIH user key checked");
        let mut rewritten_header = separate_header;
        aes_encrypt_block(user_psk, &mut rewritten_header)?;
        let mut rewritten = Vec::with_capacity(packet.len() - 16);
        rewritten.extend_from_slice(&rewritten_header);
        rewritten.extend_from_slice(&packet[32..]);
        let mut request = user.decrypt_packet(&rewritten)?;
        request.user_index = user_index;
        request.identity = user.identity.clone();
        Ok(request)
    }

    pub(crate) fn encrypt_packet(
        &self,
        request: &ShadowsocksUdpRequest,
        source: &NetLocation,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let user = self.users.get(request.user_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Shadowsocks UDP user index",
            )
        })?;
        user.encrypt_packet(request, source, payload)
    }
}

#[derive(Debug, Clone)]
struct ShadowsocksServerUser {
    cipher: ShadowsocksCipher,
    key: ShadowsocksKeyMaterial,
    salt_checker: Arc<Mutex<TimedSaltChecker>>,
    identity: String,
}

impl ShadowsocksServerUser {
    fn aead2022_psk(&self) -> Option<&[u8]> {
        match &self.key {
            ShadowsocksKeyMaterial::Aead2022(psk) => Some(psk),
            ShadowsocksKeyMaterial::Legacy(_) => None,
        }
    }
}

#[derive(Debug)]
pub struct ShadowsocksTcpServerHandler {
    users: Vec<ShadowsocksServerUser>,
    identity: Option<ShadowsocksIdentityKey>,
    inbound_tag: String,
}

impl ShadowsocksTcpServerHandler {
    pub fn new(
        users: Vec<ShadowsocksUser>,
        identity: Option<ShadowsocksServerIdentity>,
        inbound_tag: &str,
    ) -> io::Result<Self> {
        if users.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks TCP requires at least one user",
            ));
        }
        let users = users
            .into_iter()
            .map(|user| {
                let (cipher, key) = parse_user_key(&user)?;
                Ok(ShadowsocksServerUser {
                    cipher,
                    key,
                    salt_checker: Arc::new(Mutex::new(TimedSaltChecker::default())),
                    identity: user.email,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let identity = identity.map(parse_identity_key).transpose()?;
        if let Some(identity) = &identity {
            if users.iter().any(|user| {
                user.cipher.name != identity.cipher.name
                    || user.aead2022_psk().is_none()
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Shadowsocks EIH users must use the identity AES method",
                ));
            }
        } else if users.len() > 1 && users.iter().any(|user| user.key.is_aead2022())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks 2022 multi-user requires EIH identity",
            ));
        }
        Ok(Self {
            users,
            identity,
            inbound_tag: inbound_tag.to_string(),
        })
    }
}

#[async_trait]
impl TcpServerHandler for ShadowsocksTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let user_index = if let Some(identity) = &self.identity {
            let prefix_len = identity.cipher.salt_len + 16;
            let mut prefix = vec![0u8; prefix_len];
            server_stream.read_exact(&mut prefix).await?;
            let salt = &prefix[..identity.cipher.salt_len];
            let identity_subkey = derive_aead2022_identity_subkey(
                &identity.psk,
                salt,
                identity.cipher.key_len(),
            )?;
            let mut user_hash: [u8; 16] = prefix[identity.cipher.salt_len..]
                .try_into()
                .expect("EIH identity header length checked");
            aes_decrypt_block(&identity_subkey, &mut user_hash)?;
            let user_index = self
                .users
                .iter()
                .position(|user| {
                    user.aead2022_psk()
                        .is_some_and(|psk| aead2022_user_hash(psk) == user_hash)
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "unknown Shadowsocks EIH TCP user",
                    )
                })?;
            server_stream =
                Box::new(PrefixedStream::new(salt.to_vec(), server_stream));
            user_index
        } else if self.users.len() == 1 {
            0
        } else {
            let probe_len = self
                .users
                .iter()
                .map(|user| user.cipher.salt_len + 2 + TAG_LEN)
                .max()
                .unwrap_or(0);
            let mut prefix = vec![0u8; probe_len];
            server_stream.read_exact(&mut prefix).await?;
            let user_index = self
                .users
                .iter()
                .position(|user| legacy_tcp_probe_matches(user, &prefix))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "no Shadowsocks TCP user matched the first AEAD chunk",
                    )
                })?;
            server_stream = Box::new(PrefixedStream::new(prefix, server_stream));
            user_index
        };
        let user = &self.users[user_index];
        let aead2022 = user.key.is_aead2022();
        let mut plaintext = if aead2022 {
            spawn_aead2022_codec(
                server_stream,
                user.cipher,
                user.key.bytes(),
                user.salt_checker.clone(),
            )
        } else {
            spawn_aead_codec(
                server_stream,
                user.cipher,
                user.key.bytes(),
                user.salt_checker.clone(),
            )
        };
        let remote_location = read_socks_location(&mut plaintext).await?;
        if aead2022 {
            let padding_len = plaintext.read_u16().await? as usize;
            if padding_len > 900 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid Shadowsocks 2022 padding length: {padding_len}"
                    ),
                ));
            }
            if padding_len > 0 {
                let mut padding = vec![0u8; padding_len];
                plaintext.read_exact(&mut padding).await?;
            }
        }
        let traffic_context = Some(if user.identity.is_empty() {
            TrafficContext::new("shadowsocks")
                .with_inbound_tag(self.inbound_tag.clone())
        } else {
            TrafficContext::new("shadowsocks")
                .with_identity(user.identity.clone())
                .with_inbound_tag(self.inbound_tag.clone())
        });
        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(plaintext),
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context,
        })
    }
}

fn legacy_tcp_probe_matches(user: &ShadowsocksServerUser, prefix: &[u8]) -> bool {
    let ShadowsocksKeyMaterial::Legacy(master_key) = &user.key else {
        return false;
    };
    let length_end = user.cipher.salt_len + 2 + TAG_LEN;
    if prefix.len() < length_end {
        return false;
    }
    let salt = &prefix[..user.cipher.salt_len];
    let Ok(session_key) =
        derive_session_key(master_key, salt, user.cipher.key_len())
    else {
        return false;
    };
    let Ok(unbound_key) = UnboundKey::new(user.cipher.algorithm, &session_key)
    else {
        return false;
    };
    let mut opening_key = OpeningKey::new(unbound_key, IncreasingSequence::new());
    let mut encrypted_length = prefix[user.cipher.salt_len..length_end].to_vec();
    if opening_key
        .open_in_place(Aad::empty(), &mut encrypted_length)
        .is_err()
    {
        return false;
    }
    let payload_len =
        u16::from_be_bytes([encrypted_length[0], encrypted_length[1]]) as usize;
    payload_len <= MAX_PAYLOAD_LEN
}

fn spawn_aead_codec(
    encrypted: Box<dyn AsyncStream>,
    cipher: ShadowsocksCipher,
    master_key: Arc<[u8]>,
    salt_checker: Arc<Mutex<TimedSaltChecker>>,
) -> TaskBackedStream {
    let (encrypted_reader, encrypted_writer) = tokio::io::split(encrypted);
    let (plain_client, plain_codec) = tokio::io::duplex(CODEC_BUFFER_SIZE);
    let (plain_reader, plain_writer) = tokio::io::split(plain_codec);

    let decrypt_key = master_key.clone();
    task::spawn(async move {
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
    task::spawn(async move {
        if let Err(error) =
            encrypt_stream(plain_reader, encrypted_writer, cipher, master_key).await
        {
            debug!("Shadowsocks encrypt task ended with error: {error}");
        }
    });

    TaskBackedStream(plain_client)
}

fn spawn_aead2022_codec(
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
    task::spawn(async move {
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
    task::spawn(async move {
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

    TaskBackedStream(plain_client)
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

async fn decrypt_stream<R, W>(
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
    let unbound_key = UnboundKey::new(cipher.algorithm, &session_key)
        .map_err(|_| io::Error::other("invalid Shadowsocks opening key"))?;
    let mut opening_key = OpeningKey::new(unbound_key, IncreasingSequence::new());

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
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Shadowsocks payload length exceeds {MAX_PAYLOAD_LEN}"),
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

async fn encrypt_stream<R, W>(
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

fn aes_encrypt_block(key: &[u8], block: &mut [u8; 16]) -> io::Result<()> {
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid AES-128 key")
            })?;
            let mut value = Block::<Aes128>::default();
            value.copy_from_slice(block);
            cipher.encrypt_block(&mut value);
            block.copy_from_slice(&value);
            Ok(())
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid AES-256 key")
            })?;
            let mut value = Block::<Aes256>::default();
            value.copy_from_slice(block);
            cipher.encrypt_block(&mut value);
            block.copy_from_slice(&value);
            Ok(())
        }
        length => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported AES block key length: {length}"),
        )),
    }
}

fn aes_decrypt_block(key: &[u8], block: &mut [u8; 16]) -> io::Result<()> {
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid AES-128 key")
            })?;
            let mut value = Block::<Aes128>::default();
            value.copy_from_slice(block);
            cipher.decrypt_block(&mut value);
            block.copy_from_slice(&value);
            Ok(())
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid AES-256 key")
            })?;
            let mut value = Block::<Aes256>::default();
            value.copy_from_slice(block);
            cipher.decrypt_block(&mut value);
            block.copy_from_slice(&value);
            Ok(())
        }
        length => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported AES block key length: {length}"),
        )),
    }
}

fn udp_aead2022_nonce(separate_header: &[u8; 16]) -> io::Result<Nonce> {
    let nonce: [u8; NONCE_LEN] = separate_header[4..16]
        .try_into()
        .map_err(|_| io::Error::other("invalid Shadowsocks 2022 UDP nonce"))?;
    Ok(Nonce::assume_unique_for_key(nonce))
}

fn current_time_secs() -> u64 {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_secs()
}

fn validate_aead2022_timestamp(timestamp: u64) -> io::Result<()> {
    let now = current_time_secs();
    if now >= timestamp {
        let age = now - timestamp;
        if age > 30 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Shadowsocks 2022 timestamp is {age} seconds old"),
            ));
        }
    } else {
        let future = timestamp - now;
        if future > 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Shadowsocks 2022 timestamp is {future} seconds in the future"
                ),
            ));
        }
    }
    Ok(())
}

fn derive_aead2022_identity_subkey(
    psk: &[u8],
    salt: &[u8],
    key_len: usize,
) -> io::Result<Vec<u8>> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let mut hasher =
        blake3::Hasher::new_derive_key("shadowsocks 2022 identity subkey");
    hasher.update(&material);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; key_len];
    reader.fill(&mut output);
    Ok(output)
}

fn aead2022_user_hash(psk: &[u8]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(psk);
    let mut output = [0u8; 16];
    hasher.finalize_xof().fill(&mut output);
    output
}

fn derive_aead2022_session_key(
    psk: &[u8],
    salt: &[u8],
    key_len: usize,
) -> io::Result<Vec<u8>> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let mut hasher =
        blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
    hasher.update(&material);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; key_len];
    reader.fill(&mut output);
    Ok(output)
}

fn derive_master_key(password: &str, key_len: usize) -> Vec<u8> {
    let password = password.as_bytes();
    let mut output = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while output.len() < key_len {
        let mut digest = Md5::new();
        if !previous.is_empty() {
            digest.update(&previous);
        }
        digest.update(password);
        previous = digest.finalize().to_vec();
        output.extend_from_slice(&previous);
    }
    output.truncate(key_len);
    output
}

struct SessionKeyLen(usize);

impl aws_lc_rs::hkdf::KeyType for SessionKeyLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn derive_session_key(
    master_key: &[u8],
    salt: &[u8],
    key_len: usize,
) -> io::Result<Vec<u8>> {
    let prk = aws_lc_rs::hkdf::Salt::new(
        aws_lc_rs::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
        salt,
    )
    .extract(master_key);
    let okm = prk
        .expand(&[b"ss-subkey"], SessionKeyLen(key_len))
        .map_err(|_| io::Error::other("failed to expand Shadowsocks session key"))?;
    let mut output = vec![0u8; key_len];
    okm.fill(&mut output)
        .map_err(|_| io::Error::other("failed to fill Shadowsocks session key"))?;
    Ok(output)
}

struct IncreasingSequence([u8; NONCE_LEN]);

impl IncreasingSequence {
    fn new() -> Self {
        Self([0u8; NONCE_LEN])
    }
}

impl NonceSequence for IncreasingSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let nonce = Nonce::assume_unique_for_key(self.0);
        for byte in &mut self.0 {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        Ok(nonce)
    }
}

fn parse_socks_location_slice(data: &[u8]) -> io::Result<(NetLocation, usize)> {
    let address_type = *data.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing Shadowsocks address type",
        )
    })?;
    match address_type {
        1 => {
            if data.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated Shadowsocks IPv4 address",
                ));
            }
            let address =
                std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((NetLocation::new(Address::Ipv4(address), port), 7))
        }
        3 => {
            let length = *data.get(1).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing Shadowsocks domain length",
                )
            })? as usize;
            if length == 0 || data.len() < 2 + length + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated Shadowsocks domain address",
                ));
            }
            let domain =
                std::str::from_utf8(&data[2..2 + length]).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid Shadowsocks domain: {error}"),
                    )
                })?;
            let port_offset = 2 + length;
            let port =
                u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
            Ok((
                NetLocation::new(Address::from(domain)?, port),
                port_offset + 2,
            ))
        }
        4 => {
            if data.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated Shadowsocks IPv6 address",
                ));
            }
            let mut address = [0u8; 16];
            address.copy_from_slice(&data[1..17]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((NetLocation::new(Address::Ipv6(address.into()), port), 19))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown Shadowsocks address type: {other}"),
        )),
    }
}

fn encode_socks_location(location: &NetLocation) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    match location.address() {
        Address::Ipv4(address) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Address::Hostname(hostname) => {
            let bytes = hostname.as_bytes();
            let length = u8::try_from(bytes.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Shadowsocks domain exceeds 255 bytes",
                )
            })?;
            output.push(3);
            output.push(length);
            output.extend_from_slice(bytes);
        }
        Address::Ipv6(address) => {
            output.push(4);
            output.extend_from_slice(&address.octets());
        }
    }
    output.extend_from_slice(&location.port().to_be_bytes());
    Ok(output)
}

async fn read_socks_location<S>(stream: &mut S) -> io::Result<NetLocation>
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

struct TaskBackedStream(DuplexStream);

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
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TaskBackedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
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

#[cfg(test)]
mod tests {
    use std::io;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{
        address::{Address, NetLocation},
        config::server_config::ShadowsocksUser,
        handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    };

    use super::{
        ShadowsocksCipher, ShadowsocksTcpServerHandler, ShadowsocksUdpCodec,
        TimedSaltChecker, compile_legacy_outbound_key, connect_legacy_aead_outbound,
        derive_aead2022_session_key, derive_master_key,
    };

    #[test]
    fn derives_xray_compatible_aes_128_master_key() {
        assert_eq!(
            derive_master_key("password", 16),
            vec![
                0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6, 0x1d, 0x83, 0x27,
                0xde, 0xb8, 0x82, 0xcf, 0x99,
            ]
        );
    }

    #[test]
    fn cipher_aliases_match_xray_names() {
        assert_eq!(
            ShadowsocksCipher::parse("aead_aes_128_gcm").unwrap().name,
            "aes-128-gcm"
        );
        assert_eq!(
            ShadowsocksCipher::parse("chacha20-poly1305").unwrap().name,
            "chacha20-ietf-poly1305"
        );
    }

    #[test]
    fn legacy_udp_client_codec_roundtrips_and_rejects_replay() {
        for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            let password = format!("udp-secret-{method}");
            let user = ShadowsocksUser {
                method: method.to_string(),
                password,
                email: "udp-client-test@example.com".into(),
            };
            let client = ShadowsocksUdpCodec::new(vec![user.clone()], None).unwrap();
            let server = ShadowsocksUdpCodec::new(vec![user], None).unwrap();
            let target =
                NetLocation::new(Address::Hostname("dns.example".into()), 5353);
            let request_packet = client
                .encrypt_client_packet(&target, b"udp-request")
                .unwrap();
            let request = server.decrypt_packet(&request_packet).unwrap();
            assert_eq!(request.target_location, target);
            assert_eq!(request.payload, b"udp-request");
            let replay = server
                .decrypt_packet(&request_packet)
                .expect_err("replayed UDP salt must be rejected");
            assert_eq!(replay.kind(), io::ErrorKind::PermissionDenied);

            let source = NetLocation::new(
                Address::Ipv6("2001:db8::1".parse().unwrap()),
                5353,
            );
            let response_packet = server
                .encrypt_packet(&request, &source, b"udp-response")
                .unwrap();
            let (decoded_source, decoded_payload) =
                client.decrypt_client_packet(&response_packet).unwrap();
            assert_eq!(decoded_source, source);
            assert_eq!(decoded_payload, b"udp-response");

            let mut tampered = response_packet;
            *tampered.last_mut().unwrap() ^= 0x80;
            assert!(client.decrypt_client_packet(&tampered).is_err());
        }
    }

    #[tokio::test]
    async fn legacy_aead_outbound_roundtrips_cipher_matrix() {
        for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            let password = format!("secret-{method}");
            let target =
                NetLocation::new(Address::Hostname("echo.example".into()), 443);
            let (client, server) = tokio::io::duplex(256 * 1024);
            let handler = ShadowsocksTcpServerHandler::new(
                vec![ShadowsocksUser {
                    method: method.to_string(),
                    password: password.clone(),
                    email: "cipher-test@example.com".into(),
                }],
                None,
                "shadowsocks-test",
            )
            .unwrap();
            let expected_target = target.clone();
            let server_task = tokio::spawn(async move {
                let result =
                    handler.setup_server_stream(Box::new(server)).await.unwrap();
                let TcpServerSetupResult::TcpForward {
                    remote_location,
                    mut stream,
                    ..
                } = result
                else {
                    panic!("expected Shadowsocks TCP forwarding result");
                };
                assert_eq!(remote_location, expected_target);
                let mut request = vec![0u8; 32 * 1024];
                stream.read_exact(&mut request).await.unwrap();
                assert!(
                    request
                        .iter()
                        .enumerate()
                        .all(|(index, byte)| { *byte == (index % 251) as u8 })
                );
                stream.write_all(b"shadowsocks-response").await.unwrap();
                stream.flush().await.unwrap();
            });

            let (cipher, master_key) =
                compile_legacy_outbound_key(method, &password).unwrap();
            let mut stream = connect_legacy_aead_outbound(
                Box::new(client),
                cipher,
                master_key,
                &target,
            )
            .await
            .unwrap();
            let request = (0..32 * 1024)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            stream.write_all(&request).await.unwrap();
            stream.flush().await.unwrap();
            let mut response = [0u8; 20];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"shadowsocks-response");
            server_task.await.unwrap();
        }
    }

    #[test]
    fn aead2022_udp_derives_key_from_eight_byte_session_id() {
        let key = derive_aead2022_session_key(b"0123456789abcdef", b"session!", 16)
            .expect("derive 2022 UDP session key");
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn salt_replay_is_rejected() {
        let mut checker = TimedSaltChecker::default();
        assert!(checker.insert(b"0123456789abcdef"));
        assert!(!checker.insert(b"0123456789abcdef"));
    }
}
