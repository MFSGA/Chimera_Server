use std::{
    collections::{HashSet, VecDeque},
    io,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

use aes::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use async_trait::async_trait;
use aws_lc_rs::{
    aead::{
        AES_128_GCM, AES_256_GCM, Aad, Algorithm, BoundKey, CHACHA20_POLY1305,
        NONCE_LEN, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
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
    task::{self, JoinHandle},
};
use tracing::debug;

use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::{ShadowsocksServerIdentity, ShadowsocksUser},
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
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
    xchacha: bool,
}

impl ShadowsocksCipher {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Ok(Self {
                algorithm: &AES_128_GCM,
                salt_len: 16,
                name: "aes-128-gcm",
                xchacha: false,
            }),
            "aes-256-gcm" | "aead_aes_256_gcm" => Ok(Self {
                algorithm: &AES_256_GCM,
                salt_len: 32,
                name: "aes-256-gcm",
                xchacha: false,
            }),
            "chacha20-poly1305"
            | "aead_chacha20_poly1305"
            | "chacha20-ietf-poly1305" => Ok(Self {
                algorithm: &CHACHA20_POLY1305,
                salt_len: 32,
                name: "chacha20-ietf-poly1305",
                xchacha: false,
            }),
            "xchacha20-poly1305"
            | "aead_xchacha20_poly1305"
            | "xchacha20-ietf-poly1305" => Ok(Self {
                algorithm: &CHACHA20_POLY1305,
                salt_len: 32,
                name: "xchacha20-ietf-poly1305",
                xchacha: true,
            }),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported Shadowsocks cipher method: {other}"),
            )),
        }
    }

    fn key_len(self) -> usize {
        self.algorithm.key_len()
    }

    fn is_xchacha(self) -> bool {
        self.xchacha
    }
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
        if cipher.is_xchacha() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks 2022 does not support XChaCha20-Poly1305",
            ));
        }
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

#[derive(Debug)]
struct ShadowsocksRuntimeUser {
    config: ShadowsocksUser,
    tcp: Arc<ShadowsocksServerUser>,
    udp: Arc<ShadowsocksUdpUserCodec>,
}

#[derive(Debug)]
pub(crate) struct ShadowsocksUserStore {
    users: RwLock<Vec<Arc<ShadowsocksRuntimeUser>>>,
    identity: Option<ShadowsocksIdentityKey>,
}

#[derive(Debug)]
pub(crate) enum ShadowsocksUserStoreError {
    EmptyEmail,
    DuplicateEmail(String),
    NotFound(String),
    InvalidUser(io::Error),
}

impl ShadowsocksUserStore {
    pub(crate) fn new(
        users: Vec<ShadowsocksUser>,
        identity: Option<ShadowsocksServerIdentity>,
    ) -> io::Result<Self> {
        let identity = identity.map(parse_identity_key).transpose()?;
        let users = users
            .into_iter()
            .map(ShadowsocksRuntimeUser::new)
            .map(|result| result.map(Arc::new))
            .collect::<io::Result<Vec<_>>>()?;
        validate_runtime_users(&users, identity.as_ref())?;
        Ok(Self {
            users: RwLock::new(users),
            identity,
        })
    }

    pub(crate) fn snapshot(&self) -> Vec<ShadowsocksUser> {
        self.users
            .read()
            .expect("Shadowsocks user store lock poisoned")
            .iter()
            .map(|user| user.config.clone())
            .collect()
    }

    fn tcp_users(&self) -> Vec<Arc<ShadowsocksServerUser>> {
        self.users
            .read()
            .expect("Shadowsocks user store lock poisoned")
            .iter()
            .map(|user| user.tcp.clone())
            .collect()
    }

    fn udp_users(&self) -> Vec<Arc<ShadowsocksUdpUserCodec>> {
        self.users
            .read()
            .expect("Shadowsocks user store lock poisoned")
            .iter()
            .map(|user| user.udp.clone())
            .collect()
    }

    pub(crate) fn udp_codec(
        &self,
        base: &ShadowsocksUdpCodec,
    ) -> ShadowsocksUdpCodec {
        base.with_runtime_users(self.udp_users())
    }

    pub(crate) fn identity_method(&self) -> Option<&'static str> {
        self.identity
            .as_ref()
            .map(|identity| match identity.cipher.name {
                "aes-128-gcm" => "2022-blake3-aes-128-gcm",
                "aes-256-gcm" => "2022-blake3-aes-256-gcm",
                "chacha20-ietf-poly1305" => "2022-blake3-chacha20-poly1305",
                _ => unreachable!("validated Shadowsocks 2022 identity cipher"),
            })
    }

    pub(crate) fn add_user(
        &self,
        user: ShadowsocksUser,
    ) -> Result<(), ShadowsocksUserStoreError> {
        let compiled = Arc::new(
            ShadowsocksRuntimeUser::new(user)
                .map_err(ShadowsocksUserStoreError::InvalidUser)?,
        );
        let mut users = self
            .users
            .write()
            .expect("Shadowsocks user store lock poisoned");
        if self.identity.is_some()
            && !compiled.config.email.is_empty()
            && users
                .iter()
                .any(|current| current.config.email == compiled.config.email)
        {
            return Err(ShadowsocksUserStoreError::DuplicateEmail(
                compiled.config.email.clone(),
            ));
        }
        let mut updated = users.clone();
        updated.push(compiled);
        validate_runtime_users(&updated, self.identity.as_ref())
            .map_err(ShadowsocksUserStoreError::InvalidUser)?;
        *users = updated;
        Ok(())
    }

    pub(crate) fn remove_user_by_email(
        &self,
        email: &str,
    ) -> Result<(), ShadowsocksUserStoreError> {
        if email.is_empty() {
            return Err(ShadowsocksUserStoreError::EmptyEmail);
        }
        let mut users = self
            .users
            .write()
            .expect("Shadowsocks user store lock poisoned");
        let Some(index) = users
            .iter()
            .position(|user| user.config.email.eq_ignore_ascii_case(email))
        else {
            return Err(ShadowsocksUserStoreError::NotFound(email.to_string()));
        };
        users.swap_remove(index);
        Ok(())
    }
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
        user_level: 0,
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

mod udp;

pub(crate) use udp::ShadowsocksUdpCodec;
#[cfg(test)]
pub(crate) use udp::ShadowsocksUdpRequest;
use udp::ShadowsocksUdpUserCodec;

#[derive(Debug, Clone)]
struct ShadowsocksServerUser {
    cipher: ShadowsocksCipher,
    key: ShadowsocksKeyMaterial,
    salt_checker: Arc<Mutex<TimedSaltChecker>>,
    identity: String,
    user_level: u32,
}

impl ShadowsocksServerUser {
    fn new(user: &ShadowsocksUser) -> io::Result<Self> {
        let (cipher, key) = parse_user_key(user)?;
        Ok(Self {
            cipher,
            key,
            salt_checker: Arc::new(Mutex::new(TimedSaltChecker::default())),
            identity: user.email.clone(),
            user_level: user.user_level,
        })
    }

    fn aead2022_psk(&self) -> Option<&[u8]> {
        match &self.key {
            ShadowsocksKeyMaterial::Aead2022(psk) => Some(psk),
            ShadowsocksKeyMaterial::Legacy(_) => None,
        }
    }
}

impl ShadowsocksRuntimeUser {
    fn new(config: ShadowsocksUser) -> io::Result<Self> {
        let tcp = Arc::new(ShadowsocksServerUser::new(&config)?);
        let udp = Arc::new(ShadowsocksUdpUserCodec::new(config.clone())?);
        Ok(Self { config, tcp, udp })
    }
}

fn validate_runtime_users(
    users: &[Arc<ShadowsocksRuntimeUser>],
    identity: Option<&ShadowsocksIdentityKey>,
) -> io::Result<()> {
    if let Some(identity) = identity {
        if users.iter().any(|user| {
            user.tcp.cipher.name != identity.cipher.name
                || user.tcp.aead2022_psk().is_none()
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks EIH users must use the identity AES method",
            ));
        }
    } else if users.len() > 1 && users.iter().any(|user| user.tcp.key.is_aead2022())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shadowsocks 2022 multi-user requires EIH identity",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct ShadowsocksTcpServerHandler {
    users: Vec<Arc<ShadowsocksServerUser>>,
    identity: Option<ShadowsocksIdentityKey>,
    inbound_tag: String,
    runtime_users: OnceLock<Arc<ShadowsocksUserStore>>,
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
            .iter()
            .map(ShadowsocksServerUser::new)
            .map(|result| result.map(Arc::new))
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
            runtime_users: OnceLock::new(),
        })
    }
}

#[async_trait]
impl TcpServerHandler for ShadowsocksTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let runtime_users = self.runtime_users.get().map(|store| store.tcp_users());
        let users = runtime_users.as_deref().unwrap_or(&self.users);
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
            let user_index = users
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
        } else if users.len() == 1 {
            0
        } else {
            let probe_len = users
                .iter()
                .map(|user| user.cipher.salt_len + 2 + TAG_LEN)
                .max()
                .unwrap_or(0);
            let mut prefix = vec![0u8; probe_len];
            server_stream.read_exact(&mut prefix).await?;
            let user_index = users
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
        let user = &users[user_index];
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
                .with_user_level(user.user_level)
        } else {
            TrafficContext::new("shadowsocks")
                .with_identity(user.identity.clone())
                .with_inbound_tag(self.inbound_tag.clone())
                .with_user_level(user.user_level)
        });
        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(plaintext),
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context,
        })
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> io::Result<TcpServerSetupResult> {
        if let Some(store) = context
            .inbound_handshake_runtime()
            .and_then(|runtime| runtime.shadowsocks_user_store(&self.inbound_tag))
        {
            let _ = self.runtime_users.set(store);
        }
        self.setup_server_stream(server_stream).await
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
    let mut encrypted_length = prefix[user.cipher.salt_len..length_end].to_vec();
    if user.cipher.is_xchacha() {
        let Ok(cipher) = XChaCha20Poly1305::new_from_slice(&session_key) else {
            return false;
        };
        let nonce = [0u8; 24];
        if cipher
            .decrypt_in_place(XNonce::from_slice(&nonce), b"", &mut encrypted_length)
            .is_err()
        {
            return false;
        }
    } else {
        let Ok(unbound_key) = UnboundKey::new(user.cipher.algorithm, &session_key)
        else {
            return false;
        };
        let mut opening_key =
            OpeningKey::new(unbound_key, IncreasingSequence::new());
        if opening_key
            .open_in_place(Aad::empty(), &mut encrypted_length)
            .is_err()
        {
            return false;
        }
    }
    let payload_len =
        u16::from_be_bytes([encrypted_length[0], encrypted_length[1]]) as usize;
    payload_len <= MAX_PAYLOAD_LEN
}

mod tcp_stream;

#[cfg(test)]
use tcp_stream::{TaskBackedStream, decrypt_stream, encrypt_stream};
use tcp_stream::{read_socks_location, spawn_aead_codec, spawn_aead2022_codec};

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

#[cfg(test)]
mod tests;
