use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use aws_lc_rs::{
    aead::{
        AES_128_GCM, AES_256_GCM, Aad, BoundKey, LessSafeKey, OpeningKey,
        SealingKey, UnboundKey,
    },
    rand::{SecureRandom, SystemRandom},
};
use chacha20poly1305::{
    KeyInit as _, XChaCha20Poly1305, XNonce, aead::AeadInPlace as _,
};

use crate::{
    address::NetLocation,
    config::server_config::{ShadowsocksServerIdentity, ShadowsocksUser},
};

use super::{
    IncreasingSequence, SALT_TTL, ShadowsocksCipher, ShadowsocksIdentityKey,
    ShadowsocksKeyMaterial, TAG_LEN, TimedSaltChecker, aead2022_user_hash,
    aes_decrypt_block, aes_encrypt_block, current_time_secs,
    derive_aead2022_session_key, derive_session_key, encode_socks_location,
    parse_identity_key, parse_socks_location_slice, parse_user_key,
    udp_aead2022_nonce, validate_aead2022_timestamp,
};

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
    pub user_level: u32,
    pub(super) user_index: usize,
    pub(super) client_session_id: Option<[u8; 8]>,
}

#[derive(Debug)]
pub(super) struct ShadowsocksUdpUserCodec {
    cipher: ShadowsocksCipher,
    mode: ShadowsocksUdpMode,
    identity: String,
    user_level: u32,
}

impl ShadowsocksUdpUserCodec {
    pub(super) fn new(user: ShadowsocksUser) -> io::Result<Self> {
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
            user_level: user.user_level,
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
        let mut plaintext = encrypted.to_vec();
        if self.cipher.is_xchacha() {
            let cipher =
                XChaCha20Poly1305::new_from_slice(&session_key).map_err(|_| {
                    io::Error::other("invalid Shadowsocks XChaCha UDP opening key")
                })?;
            let nonce = [0u8; 24];
            cipher
                .decrypt_in_place(XNonce::from_slice(&nonce), b"", &mut plaintext)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Shadowsocks UDP authentication tag",
                    )
                })?;
        } else {
            let unbound_key = UnboundKey::new(self.cipher.algorithm, &session_key)
                .map_err(|_| {
                io::Error::other("invalid Shadowsocks UDP opening key")
            })?;
            let mut opening =
                OpeningKey::new(unbound_key, IncreasingSequence::new());
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
        }
        let (target_location, offset) = parse_socks_location_slice(&plaintext)?;
        Ok(ShadowsocksUdpRequest {
            target_location,
            payload: plaintext[offset..].to_vec(),
            identity: String::new(),
            user_level: 0,
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
        let mut plaintext = encode_socks_location(source)?;
        plaintext.extend_from_slice(payload);
        let mut packet = Vec::with_capacity(salt.len() + plaintext.len() + TAG_LEN);
        packet.extend_from_slice(&salt);
        if self.cipher.is_xchacha() {
            let cipher =
                XChaCha20Poly1305::new_from_slice(&session_key).map_err(|_| {
                    io::Error::other("invalid Shadowsocks XChaCha UDP sealing key")
                })?;
            let nonce = [0u8; 24];
            cipher
                .encrypt_in_place(XNonce::from_slice(&nonce), b"", &mut plaintext)
                .map_err(|_| {
                    io::Error::other("failed to encrypt Shadowsocks UDP packet")
                })?;
            packet.extend_from_slice(&plaintext);
        } else {
            let unbound_key = UnboundKey::new(self.cipher.algorithm, &session_key)
                .map_err(|_| {
                io::Error::other("invalid Shadowsocks UDP sealing key")
            })?;
            let mut sealing =
                SealingKey::new(unbound_key, IncreasingSequence::new());
            let tag = sealing
                .seal_in_place_separate_tag(Aad::empty(), &mut plaintext)
                .map_err(|_| {
                    io::Error::other("failed to encrypt Shadowsocks UDP packet")
                })?;
            packet.extend_from_slice(&plaintext);
            packet.extend_from_slice(tag.as_ref());
        }
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
            user_level: 0,
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
            user_level: 0,
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
    users: Vec<Arc<ShadowsocksUdpUserCodec>>,
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
            .map(|result| result.map(Arc::new))
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

    pub(super) fn with_runtime_users(
        &self,
        users: Vec<Arc<ShadowsocksUdpUserCodec>>,
    ) -> Self {
        Self {
            users,
            identity: self.identity.clone(),
        }
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
                    request.user_level = user.user_level;
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
        request.user_level = user.user_level;
        Ok(request)
    }

    #[cfg(test)]
    pub(crate) fn encrypt_test_request(
        &self,
        target: &NetLocation,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let user = self.users.first().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks UDP test codec has no users",
            )
        })?;
        let request = ShadowsocksUdpRequest {
            target_location: target.clone(),
            payload: Vec::new(),
            identity: String::new(),
            user_level: 0,
            user_index: 0,
            client_session_id: None,
        };
        user.encrypt_packet(&request, target, payload)
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
