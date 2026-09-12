use std::{
    collections::HashSet,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::SystemTime,
};

use async_trait::async_trait;
use aws_lc_rs::aead::{
    AES_128_GCM, Aad, BoundKey, OpeningKey, SealingKey, UnboundKey,
};
use aws_lc_rs::cipher::{
    AES_128, DecryptingKey as CipherDecryptingKey, DecryptionContext,
    UnboundCipherKey,
};
use bytes::BytesMut;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update};
use tokio::io::AsyncReadExt;

use super::md5::{compute_md5, create_chacha_key};
use super::nonce::{SingleUseNonce, VmessNonceSequence};
use super::vmess_stream::VmessStream;
use crate::async_stream::AsyncStream;
use crate::config::server_config::{VmessUser, parse_vmess_user_id};
use crate::handler::{
    tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
    xudp::message_stream::XudpMessageStream,
};
use crate::resolver::NativeResolver;
use crate::traffic::TrafficContext;
use crate::util::allocate_vec;

const TAG_LEN: usize = 16;
const VMESS_AUTH_ID_WINDOW_SECS: u64 = 120;
const VMESS_COMMAND_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

mod request;

use request::{
    COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, DataCipher, parse_request_header,
};

struct VmessServerUser {
    config: VmessUser,
    instruction_key: [u8; 16],
    aead_decrypting_key: CipherDecryptingKey,
}

impl VmessServerUser {
    fn new(user: VmessUser) -> Self {
        let instruction_key = command_key_for_user_id(&user.user_id);

        let derived_key =
            super::sha2::kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
        let unbound_key =
            UnboundCipherKey::new(&AES_128, &derived_key[0..16]).unwrap();
        let aead_decrypting_key = CipherDecryptingKey::ecb(unbound_key).unwrap();

        Self {
            config: user,
            instruction_key,
            aead_decrypting_key,
        }
    }
}

#[derive(Debug, Clone)]
struct AuthenticatedVmessUser {
    instruction_key: [u8; 16],
    user_label: String,
    user_level: u32,
}

pub(crate) struct VmessUserStore {
    users: RwLock<Vec<VmessServerUser>>,
}

impl std::fmt::Debug for VmessUserStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let user_count = self
            .users
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        f.debug_struct("VmessUserStore")
            .field("user_count", &user_count)
            .finish()
    }
}

impl VmessUserStore {
    pub(crate) fn new(users: Vec<VmessUser>) -> Self {
        Self {
            users: RwLock::new(
                users.into_iter().map(VmessServerUser::new).collect(),
            ),
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<VmessUser> {
        self.users
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|user| user.config.clone())
            .collect()
    }

    pub(crate) fn update<R, E, F>(&self, update: F) -> Result<R, E>
    where
        F: FnOnce(&mut Vec<VmessUser>) -> Result<R, E>,
    {
        let mut configs = self.snapshot();
        let result = update(&mut configs)?;
        let compiled = configs.into_iter().map(VmessServerUser::new).collect();
        *self
            .users
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = compiled;
        Ok(result)
    }

    fn authenticate_at(
        &self,
        cert_hash: &[u8; 16],
        current_time_secs: u64,
    ) -> std::io::Result<AuthenticatedVmessUser> {
        let users = self
            .users
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Xray's AuthIDDecoderHolder is keyed by command key, so adding the
        // same UUID again replaces the decoder ticket. Preserve that
        // last-write-wins authentication behavior while retaining all users
        // for management queries.
        for user in users.iter().rev() {
            let mut auth_id = *cert_hash;
            if user
                .aead_decrypting_key
                .decrypt(&mut auth_id, DecryptionContext::None)
                .is_err()
            {
                continue;
            }

            let checksum = super::crc32::crc32c(&auth_id[0..12]);
            let expected_checksum =
                u32::from_be_bytes(auth_id[12..16].try_into().unwrap());
            if checksum != expected_checksum {
                continue;
            }

            let time_secs = u64::from_be_bytes(auth_id[0..8].try_into().unwrap());
            let time_delta = time_secs.abs_diff(current_time_secs);
            if time_delta > VMESS_AUTH_ID_WINDOW_SECS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Hash timestamp is too old ({time_secs} is {time_delta} seconds old)"
                    ),
                ));
            }

            return Ok(AuthenticatedVmessUser {
                instruction_key: user.instruction_key,
                user_label: user.config.user_label.clone(),
                user_level: user.config.user_level,
            });
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "AEAD authentication failed: no matching VMess user",
        ))
    }
}

#[derive(Default)]
struct VmessReplayCache {
    current: HashSet<[u8; 16]>,
    previous: HashSet<[u8; 16]>,
    last_rotation: u64,
}

impl VmessReplayCache {
    fn check_and_insert(&mut self, auth_id: [u8; 16], now: u64) -> bool {
        if now.saturating_sub(self.last_rotation) >= VMESS_AUTH_ID_WINDOW_SECS {
            self.previous = std::mem::take(&mut self.current);
            self.last_rotation = now;
        }
        if self.current.contains(&auth_id) || self.previous.contains(&auth_id) {
            return false;
        }
        self.current.insert(auth_id);
        true
    }
}

pub struct VmessTcpServerHandler {
    users: Arc<VmessUserStore>,
    runtime_users: OnceLock<Arc<VmessUserStore>>,
    udp_enabled: bool,
    inbound_tag: String,
    replay_cache: Mutex<VmessReplayCache>,
}

impl std::fmt::Debug for VmessTcpServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessTcpServerHandler")
            .field("user_count", &self.users.snapshot().len())
            .field("udp_enabled", &self.udp_enabled)
            .finish_non_exhaustive()
    }
}

impl VmessTcpServerHandler {
    pub fn new(users: Vec<VmessUser>, udp_enabled: bool, inbound_tag: &str) -> Self {
        Self {
            users: Arc::new(VmessUserStore::new(users)),
            runtime_users: OnceLock::new(),
            udp_enabled,
            inbound_tag: inbound_tag.to_string(),
            replay_cache: Mutex::new(VmessReplayCache::default()),
        }
    }

    fn selected_users(&self) -> &VmessUserStore {
        self.runtime_users
            .get()
            .map(Arc::as_ref)
            .unwrap_or_else(|| self.users.as_ref())
    }

    fn authenticate_user(
        &self,
        cert_hash: &[u8; 16],
    ) -> std::io::Result<AuthenticatedVmessUser> {
        let current_time_secs = SystemTime::UNIX_EPOCH
            .elapsed()
            .map_err(|error| {
                std::io::Error::other(format!(
                    "system clock is before Unix epoch: {error}"
                ))
            })?
            .as_secs();
        self.authenticate_user_at(cert_hash, current_time_secs)
    }

    fn authenticate_user_at(
        &self,
        cert_hash: &[u8; 16],
        current_time_secs: u64,
    ) -> std::io::Result<AuthenticatedVmessUser> {
        let user = self
            .selected_users()
            .authenticate_at(cert_hash, current_time_secs)?;
        let mut replay_cache = self
            .replay_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !replay_cache.check_and_insert(*cert_hash, current_time_secs) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "replayed VMess AuthID",
            ));
        }
        Ok(user)
    }
}

#[async_trait]
impl TcpServerHandler for VmessTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut cert_hash = [0u8; 16];
        server_stream.read_exact(&mut cert_hash).await?;

        let user = self.authenticate_user(&cert_hash)?;
        let instruction_key = user.instruction_key;
        let user_label = user.user_label.clone();
        let user_level = user.user_level;

        let mut encrypted_payload_length = [0u8; 18];
        server_stream
            .read_exact(&mut encrypted_payload_length)
            .await?;

        let mut nonce = [0u8; 8];
        server_stream.read_exact(&mut nonce).await?;

        let header_length_aead_key = super::sha2::kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
        );
        let header_length_nonce = super::sha2::kdf(
            &instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
        );

        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();
        let mut opening_key = OpeningKey::new(
            unbound_key,
            SingleUseNonce::new(&header_length_nonce[0..12]),
        );

        if opening_key
            .open_in_place(Aad::from(&cert_hash), &mut encrypted_payload_length)
            .is_err()
        {
            return Err(std::io::Error::other(
                "failed to open encrypted header length",
            ));
        }

        let payload_length =
            u16::from_be_bytes(encrypted_payload_length[0..2].try_into().unwrap());

        let header_aead_key = super::sha2::kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key", &cert_hash, &nonce],
        );
        let header_nonce = super::sha2::kdf(
            &instruction_key,
            &[b"VMess Header AEAD Nonce", &cert_hash, &nonce],
        );

        let mut encrypted_header =
            allocate_vec(payload_length as usize + TAG_LEN).into_boxed_slice();
        server_stream.read_exact(&mut encrypted_header).await?;

        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &header_aead_key[0..16]).unwrap();
        let mut opening_key =
            OpeningKey::new(unbound_key, SingleUseNonce::new(&header_nonce[0..12]));

        if opening_key
            .open_in_place(Aad::from(&cert_hash), &mut encrypted_header)
            .is_err()
        {
            return Err(std::io::Error::other("failed to open encrypted header"));
        }

        let request = parse_request_header(
            &encrypted_header[..payload_length as usize],
            self.udp_enabled,
        )?;
        let command = request.command;
        let remote_location = request.remote_location;
        let data_encryption_iv = request.data_encryption_iv;
        let data_encryption_key = request.data_encryption_key;
        let response_authentication_v = request.response_authentication_v;
        let enable_chunk_masking = request.enable_chunk_masking;
        let enable_global_padding = request.enable_global_padding;
        let requested_data_cipher = request.data_cipher;

        let response_header: [u8; 4] = [response_authentication_v, 0, 0, 0];

        let mut truncated_iv = [0u8; 16];
        let mut truncated_key = [0u8; 16];
        truncated_iv.copy_from_slice(
            &super::sha2::compute_sha256(&data_encryption_iv)[0..16],
        );
        truncated_key.copy_from_slice(
            &super::sha2::compute_sha256(&data_encryption_key)[0..16],
        );
        let response_header_iv = truncated_iv;
        let response_header_key = truncated_key;

        let unbound_keys = match requested_data_cipher {
            DataCipher::Aes128Gcm => Some((
                UnboundKey::new(&AES_128_GCM, &data_encryption_key).unwrap(),
                UnboundKey::new(&AES_128_GCM, &response_header_key).unwrap(),
            )),
            DataCipher::ChaCha20Poly1305 => Some((
                UnboundKey::new(
                    &aws_lc_rs::aead::CHACHA20_POLY1305,
                    &create_chacha_key(&data_encryption_key),
                )
                .unwrap(),
                UnboundKey::new(
                    &aws_lc_rs::aead::CHACHA20_POLY1305,
                    &create_chacha_key(&response_header_key),
                )
                .unwrap(),
            )),
            DataCipher::None => None,
        };

        let data_keys =
            if let Some((unbound_opening_key, unbound_sealing_key)) = unbound_keys {
                let opening_key = OpeningKey::new(
                    unbound_opening_key,
                    VmessNonceSequence::new(&data_encryption_iv),
                );
                let sealing_key = SealingKey::new(
                    unbound_sealing_key,
                    VmessNonceSequence::new(&response_header_iv),
                );
                Some((opening_key, sealing_key))
            } else {
                None
            };

        let (read_length_shake_reader, write_length_shake_reader) =
            if enable_chunk_masking {
                let mut request_hasher = Shake128::default();
                request_hasher.update(&data_encryption_iv);
                let request_reader = request_hasher.finalize_xof();

                let mut response_hasher = Shake128::default();
                response_hasher.update(&response_header_iv);
                let response_reader = response_hasher.finalize_xof();

                (Some(request_reader), Some(response_reader))
            } else {
                (None, None)
            };

        let response_header_length_aead_key =
            super::sha2::kdf(&response_header_key, &[b"AEAD Resp Header Len Key"]);
        let response_header_length_nonce =
            super::sha2::kdf(&response_header_iv, &[b"AEAD Resp Header Len IV"]);

        let mut encrypted_response_header = [0u8; 2 + TAG_LEN + 4 + TAG_LEN];
        encrypted_response_header[1] = 4;

        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &response_header_length_aead_key[0..16])
                .unwrap();
        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_length_nonce[0..12]),
        );
        let tag = sealing_key
            .seal_in_place_separate_tag(
                Aad::empty(),
                &mut encrypted_response_header[0..2],
            )
            .unwrap();
        encrypted_response_header[2..2 + TAG_LEN].copy_from_slice(tag.as_ref());

        let response_header_aead_key =
            super::sha2::kdf(&response_header_key, &[b"AEAD Resp Header Key"]);
        let response_header_nonce =
            super::sha2::kdf(&response_header_iv, &[b"AEAD Resp Header IV"]);
        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &response_header_aead_key[0..16]).unwrap();
        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_nonce[0..12]),
        );

        encrypted_response_header[2 + TAG_LEN..2 + TAG_LEN + 4]
            .copy_from_slice(&response_header);

        let tag = sealing_key
            .seal_in_place_separate_tag(
                Aad::empty(),
                &mut encrypted_response_header[2 + TAG_LEN..2 + TAG_LEN + 4],
            )
            .unwrap();
        encrypted_response_header[2 + TAG_LEN + 4..].copy_from_slice(tag.as_ref());

        let prefix_bytes = BytesMut::from(&encrypted_response_header[..]);

        let vmess_stream = VmessStream::new(
            server_stream,
            command == COMMAND_UDP,
            data_keys,
            read_length_shake_reader,
            write_length_shake_reader,
            enable_global_padding,
            Some(prefix_bytes),
            None,
        );
        let traffic_context = Some(
            TrafficContext::new("vmess")
                .with_identity(user_label)
                .with_inbound_tag(self.inbound_tag.clone())
                .with_user_level(user_level),
        );

        match command {
            COMMAND_TCP => Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(vmess_stream),
                need_initial_flush: false,
                connection_success_response: None,
                traffic_context,
            }),
            COMMAND_UDP => Ok(TcpServerSetupResult::BidirectionalUdp {
                remote_location,
                stream: Box::new(vmess_stream),
                traffic_context,
            }),
            COMMAND_MUX => Ok(TcpServerSetupResult::SessionBasedUdp {
                stream: Box::new(XudpMessageStream::new(
                    Box::new(vmess_stream),
                    Arc::new(NativeResolver::new()),
                )),
                traffic_context,
            }),
            _ => unreachable!("VMess command was validated before stream creation"),
        }
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        if let Some(store) = context
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.vmess_user_store(&self.inbound_tag))
        {
            let _ = self.runtime_users.set(store);
        }
        self.setup_server_stream(server_stream).await
    }
}

fn command_key_for_user_id(user_id: &str) -> [u8; 16] {
    let parsed = parse_vmess_user_id(user_id)
        .expect("VMess user ID must be validated before handler construction");
    let mut command_key_input =
        Vec::with_capacity(16 + VMESS_COMMAND_KEY_SALT.len());
    command_key_input.extend_from_slice(&parsed);
    command_key_input.extend_from_slice(VMESS_COMMAND_KEY_SALT);
    compute_md5(&command_key_input)
}

#[cfg(test)]
mod tests;
