use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use aws_lc_rs::aead::{
    AES_128_GCM, Aad, BoundKey, OpeningKey, SealingKey, UnboundKey,
};
use bytes::BytesMut;
use futures::ready;
use rand::Rng;
use sha3::digest::XofReader;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::warn;

use super::nonce::{SingleUseNonce, VmessNonceSequence};
use super::typed::VmessReader;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage,
    AsyncShutdownMessage, AsyncStream, AsyncWriteMessage,
};
use crate::util::allocate_vec;

const HEADER_TAG_LEN: usize = 16;
const ENCRYPTION_TAG_LEN: usize = 16;
const MAX_PADDING_LEN: usize = 64;

const MAX_VMESS_UDP_PAYLOAD_SIZE: usize = 8192;
const MAX_ENCRYPTED_WRITE_DATA_SIZE: usize = 8192 + ENCRYPTION_TAG_LEN;

const MAX_ENCRYPTED_READ_DATA_SIZE: usize = u16::MAX as usize;

struct LengthMask {
    reader: VmessReader,
    mask: [u8; 2],
    enable_padding: bool,
}

impl LengthMask {
    fn new(reader: VmessReader, enable_padding: bool) -> Self {
        Self {
            reader,
            mask: [0u8; 2],
            enable_padding,
        }
    }

    fn next_u16(&mut self) -> u16 {
        self.reader.read(&mut self.mask);
        ((self.mask[0] as u16) << 8) | (self.mask[1] as u16)
    }

    fn next_values(&mut self) -> (usize, u16) {
        let padding = if self.enable_padding {
            (self.next_u16() % (MAX_PADDING_LEN as u16)) as usize
        } else {
            0
        };

        (padding, self.next_u16())
    }
}

enum ShutdownState {
    WriteRemainingData,
    WriteEmptyPacket,
    PollShutdown,
}

pub struct VmessStream {
    stream: Box<dyn AsyncStream>,
    is_udp: bool,

    read_header_state: ReadHeaderState,
    read_header_info: Option<ReadHeaderInfo>,

    opening_key: Option<OpeningKey<VmessNonceSequence>>,
    sealing_key: Option<SealingKey<VmessNonceSequence>>,
    tag_len: usize,
    read_length_mask: Option<LengthMask>,
    write_length_mask: Option<LengthMask>,

    unprocessed_buf: Box<[u8]>,
    unprocessed_start_offset: usize,
    unprocessed_end_offset: usize,
    unprocessed_pending_len: Option<(usize, usize)>,

    processed_buf: Box<[u8]>,
    processed_start_offset: usize,
    processed_end_offset: usize,
    processed_message_lengths: VecDeque<usize>,

    write_cache: Box<[u8]>,
    write_cache_size: usize,

    write_packet: Box<[u8]>,
    write_packet_start_offset: usize,
    write_packet_end_offset: usize,

    pending_prefix_write: Option<BytesMut>,

    shutdown_state: ShutdownState,
    is_eof: bool,
}

enum DecryptState {
    NeedData,
    BufferFull,
    Success,
    ReceivedEof,
}

pub struct ReadHeaderInfo {
    pub response_header_key: [u8; 16],
    pub response_header_iv: [u8; 16],
    pub response_authentication_v: u8,
}

#[derive(PartialEq, Eq, Debug)]
enum ReadHeaderState {
    ReadAeadLength,
    ReadAeadContent(usize),
    Done,
}

fn check_header_response(
    response_header_bytes: &[u8],
    response_authentication_v: u8,
) -> std::io::Result<()> {
    if response_header_bytes.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "VMess response header is too short: {} bytes",
                response_header_bytes.len()
            ),
        ));
    }
    if response_header_bytes[0] != response_authentication_v {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Invalid response auth value, expected {}, got {}",
                response_authentication_v, response_header_bytes[0]
            ),
        ));
    }

    let command_len = response_header_bytes[3] as usize;
    if command_len > response_header_bytes.len() - 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "VMess response command length exceeds header content: {command_len} > {}",
                response_header_bytes.len() - 4
            ),
        ));
    }
    if (response_header_bytes[2] & 0x01) == 0x01 {
        warn!("Ignoring unsupported server dynamic port instructions.");
    }
    Ok(())
}

impl VmessStream {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream: Box<dyn AsyncStream>,
        is_udp: bool,
        encryption_keys: Option<(
            OpeningKey<VmessNonceSequence>,
            SealingKey<VmessNonceSequence>,
        )>,
        read_length_shake_reader: Option<VmessReader>,
        write_length_shake_reader: Option<VmessReader>,
        enable_global_padding: bool,
        prefix_write_bytes: Option<BytesMut>,
        read_header_info: Option<ReadHeaderInfo>,
    ) -> Self {
        let (tag_len, opening_key, sealing_key) = match encryption_keys {
            Some((opening_key, sealing_key)) => {
                (ENCRYPTION_TAG_LEN, Some(opening_key), Some(sealing_key))
            }
            None => (0, None, None),
        };

        let max_unencrypted_read_data_size = MAX_ENCRYPTED_READ_DATA_SIZE - tag_len;
        let max_unencrypted_write_data_size =
            MAX_ENCRYPTED_WRITE_DATA_SIZE - tag_len;

        const MAX_READ_PACKET_SIZE: usize = MAX_ENCRYPTED_READ_DATA_SIZE + 2;
        let unprocessed_buf = allocate_vec(MAX_READ_PACKET_SIZE).into_boxed_slice();
        let processed_buf =
            allocate_vec(max_unencrypted_read_data_size).into_boxed_slice();

        let (write_cache, write_packet) = if !is_udp {
            let write_cache =
                allocate_vec(max_unencrypted_write_data_size).into_boxed_slice();
            const MAX_WRITE_PACKET_SIZE: usize = MAX_ENCRYPTED_WRITE_DATA_SIZE + 2;
            let write_packet =
                allocate_vec(MAX_WRITE_PACKET_SIZE + 40).into_boxed_slice();
            (write_cache, write_packet)
        } else {
            let write_cache = allocate_vec(65535).into_boxed_slice();
            let write_packet_size = 65535
                + (65535usize.div_ceil(max_unencrypted_write_data_size)
                    * (MAX_PADDING_LEN * ENCRYPTION_TAG_LEN));
            let write_packet =
                allocate_vec(write_packet_size + 40).into_boxed_slice();
            (write_cache, write_packet)
        };

        let read_header_state = match read_header_info {
            Some(_) => ReadHeaderState::ReadAeadLength,
            None => ReadHeaderState::Done,
        };

        Self {
            stream,
            is_udp,
            read_header_state,
            read_header_info,
            opening_key,
            sealing_key,
            tag_len,
            read_length_mask: read_length_shake_reader
                .map(|reader| LengthMask::new(reader, enable_global_padding)),
            write_length_mask: write_length_shake_reader
                .map(|reader| LengthMask::new(reader, enable_global_padding)),
            unprocessed_buf,
            unprocessed_start_offset: 0,
            unprocessed_end_offset: 0,
            unprocessed_pending_len: None,
            processed_buf,
            processed_start_offset: 0,
            processed_end_offset: 0,
            processed_message_lengths: VecDeque::new(),
            write_cache,
            write_cache_size: 0,
            write_packet,
            write_packet_start_offset: 0,
            write_packet_end_offset: 0,
            pending_prefix_write: prefix_write_bytes,
            shutdown_state: ShutdownState::WriteRemainingData,
            is_eof: false,
        }
    }

    pub fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        assert!(self.unprocessed_end_offset == 0);

        if data.len() > self.unprocessed_buf.len() {
            return Err(std::io::Error::other(
                "feed_initial_read_data called with too much data",
            ));
        }

        self.unprocessed_buf[0..data.len()].copy_from_slice(data);
        self.unprocessed_end_offset = data.len();

        if self.read_header_state != ReadHeaderState::Done {
            self.process_read_header()?;
            if self.read_header_state != ReadHeaderState::Done {
                return Ok(());
            }
        }

        loop {
            match self.try_decrypt()? {
                DecryptState::NeedData => {
                    break;
                }
                DecryptState::ReceivedEof => {
                    self.is_eof = true;
                    break;
                }
                DecryptState::BufferFull => {
                    break;
                }
                DecryptState::Success => {
                    continue;
                }
            }
        }

        Ok(())
    }

    fn process_read_header(&mut self) -> std::io::Result<()> {
        match self.read_header_state {
            ReadHeaderState::ReadAeadLength => {
                self.process_read_header_aead_length()
            }
            ReadHeaderState::ReadAeadContent(content_len) => {
                self.process_read_header_aead_content(content_len)
            }
            ReadHeaderState::Done => {
                panic!("process_read_header called with Done state");
            }
        }
    }

    fn process_read_header_aead_length(&mut self) -> std::io::Result<()> {
        if self.unprocessed_end_offset - self.unprocessed_start_offset
            < 2 + HEADER_TAG_LEN
        {
            return Ok(());
        }

        let encrypted_response_header_length = &mut self.unprocessed_buf[self
            .unprocessed_start_offset
            ..self.unprocessed_start_offset + 2 + HEADER_TAG_LEN];

        let ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            ..
        } = self.read_header_info.as_ref().unwrap();

        let response_header_length_aead_key = super::sha2::kdf(
            &response_header_key[..],
            &[b"AEAD Resp Header Len Key"],
        );
        let response_header_length_nonce =
            super::sha2::kdf(&response_header_iv[..], &[b"AEAD Resp Header Len IV"]);

        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &response_header_length_aead_key[0..16])
                .unwrap();
        let mut opening_key = OpeningKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_length_nonce[0..12]),
        );

        if opening_key
            .open_in_place(Aad::empty(), encrypted_response_header_length)
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "failed to authenticate encrypted VMess response header length",
            ));
        }

        let response_header_length = u16::from_be_bytes(
            encrypted_response_header_length[0..2].try_into().unwrap(),
        ) as usize;

        self.read_header_state =
            ReadHeaderState::ReadAeadContent(response_header_length);
        self.unprocessed_start_offset += 2 + HEADER_TAG_LEN;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.process_read_header_aead_content(response_header_length)
    }

    fn process_read_header_aead_content(
        &mut self,
        content_len: usize,
    ) -> std::io::Result<()> {
        if content_len < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("VMess response header is too short: {content_len} bytes"),
            ));
        }
        if content_len + HEADER_TAG_LEN > self.unprocessed_buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("VMess response header is too large: {content_len} bytes"),
            ));
        }
        if self.unprocessed_end_offset - self.unprocessed_start_offset
            < content_len + HEADER_TAG_LEN
        {
            return Ok(());
        }

        let encrypted_response_header = &mut self.unprocessed_buf[self
            .unprocessed_start_offset
            ..self.unprocessed_start_offset + content_len + HEADER_TAG_LEN];

        let ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            ..
        } = self.read_header_info.as_ref().unwrap();

        let response_header_aead_key =
            super::sha2::kdf(&response_header_key[..], &[b"AEAD Resp Header Key"]);
        let response_header_nonce =
            super::sha2::kdf(&response_header_iv[..], &[b"AEAD Resp Header IV"]);
        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &response_header_aead_key[0..16]).unwrap();
        let mut opening_key = OpeningKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_nonce[0..12]),
        );

        if opening_key
            .open_in_place(Aad::empty(), encrypted_response_header)
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "failed to authenticate encrypted VMess response header",
            ));
        }

        let _command_len = encrypted_response_header[3];
        if _command_len > 0 {
            warn!("Ignoring unused command bytes from AEAD block");
        }

        self.read_header_state = ReadHeaderState::Done;
        self.unprocessed_start_offset += content_len + HEADER_TAG_LEN;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        let ReadHeaderInfo {
            response_authentication_v,
            ..
        } = self.read_header_info.take().unwrap();

        check_header_response(
            &encrypted_response_header[..content_len],
            response_authentication_v,
        )
    }

    fn try_decrypt(&mut self) -> std::io::Result<DecryptState> {
        let available_len =
            self.unprocessed_end_offset - self.unprocessed_start_offset;

        let (padding_len, data_len) = match self.unprocessed_pending_len {
            None => {
                if available_len < 2 {
                    return Ok(DecryptState::NeedData);
                }

                let length_bytes = &mut self.unprocessed_buf[self
                    .unprocessed_start_offset
                    ..self.unprocessed_start_offset + 2];

                let mut data_len =
                    ((length_bytes[0] as u16) << 8) | (length_bytes[1] as u16);

                let padding_len = match self.read_length_mask {
                    Some(ref mut mask) => {
                        let (padding_len, length_mask) = mask.next_values();
                        data_len ^= length_mask;
                        padding_len
                    }
                    None => 0,
                };

                let data_len = data_len as usize;

                if data_len > MAX_ENCRYPTED_READ_DATA_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "encrypted data length larger than {MAX_ENCRYPTED_READ_DATA_SIZE}"
                        ),
                    ));
                }

                let data_without_padding = data_len.checked_sub(padding_len).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "VMess padding length ({padding_len}) exceeds data length ({data_len})"
                        ),
                    )
                })?;

                if self.tag_len > 0 && data_without_padding < self.tag_len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "data length after padding ({data_without_padding}) is smaller than tag length ({})",
                            self.tag_len
                        ),
                    ));
                }

                self.unprocessed_start_offset += 2;

                if available_len - 2 < data_len {
                    self.unprocessed_pending_len = Some((padding_len, data_len));
                    if self.unprocessed_start_offset == self.unprocessed_end_offset {
                        self.unprocessed_start_offset = 0;
                        self.unprocessed_end_offset = 0;
                    }
                    return Ok(DecryptState::NeedData);
                }

                let processed_data_len = data_len - padding_len - self.tag_len;
                if self.processed_end_offset + processed_data_len
                    > self.processed_buf.len()
                {
                    self.unprocessed_pending_len = Some((padding_len, data_len));
                    if self.unprocessed_start_offset == self.unprocessed_end_offset {
                        self.unprocessed_start_offset = 0;
                        self.unprocessed_end_offset = 0;
                    }
                    return Ok(DecryptState::BufferFull);
                }

                (padding_len, data_len)
            }

            Some((padding_len, data_len)) => {
                if available_len < data_len {
                    return Ok(DecryptState::NeedData);
                }

                let processed_data_len = data_len - padding_len - self.tag_len;
                if self.processed_end_offset + processed_data_len
                    > self.processed_buf.len()
                {
                    return Ok(DecryptState::BufferFull);
                }

                self.unprocessed_pending_len = None;
                (padding_len, data_len)
            }
        };

        if let Some(ref mut opening_key) = self.opening_key
            && opening_key
                .open_in_place(
                    Aad::empty(),
                    &mut self.unprocessed_buf[self.unprocessed_start_offset
                        ..self.unprocessed_start_offset + data_len - padding_len],
                )
                .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "open failed for data",
            ));
        }

        let processed_data_len = data_len - padding_len - self.tag_len;
        if self.is_udp && processed_data_len > MAX_VMESS_UDP_PAYLOAD_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "VMess UDP payload exceeds Xray buffer limit: {processed_data_len} > {MAX_VMESS_UDP_PAYLOAD_SIZE}"
                ),
            ));
        }
        self.processed_buf[self.processed_end_offset
            ..self.processed_end_offset + processed_data_len]
            .copy_from_slice(
                &self.unprocessed_buf[self.unprocessed_start_offset
                    ..self.unprocessed_start_offset + processed_data_len],
            );

        self.processed_end_offset += processed_data_len;
        if self.is_udp && processed_data_len > 0 {
            self.processed_message_lengths.push_back(processed_data_len);
        }
        self.unprocessed_start_offset += data_len;

        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        if processed_data_len == 0 {
            Ok(DecryptState::ReceivedEof)
        } else {
            Ok(DecryptState::Success)
        }
    }

    fn read_processed(&mut self, buf: &mut ReadBuf<'_>) {
        assert!(
            self.processed_end_offset > 0,
            "called without any processed data"
        );

        let available_len = self.processed_end_offset - self.processed_start_offset;

        let unfilled_len = buf.remaining();

        let write_amount = std::cmp::min(unfilled_len, available_len);
        assert!(
            write_amount > 0,
            "no data to write (available_len = {available_len}, unfilled_len = {unfilled_len})",
        );

        buf.put_slice(
            &self.processed_buf[self.processed_start_offset
                ..self.processed_start_offset + write_amount],
        );

        let new_processed_start_offset = self.processed_start_offset + write_amount;
        if new_processed_start_offset == self.processed_end_offset {
            self.processed_start_offset = 0;
            self.processed_end_offset = 0;
        } else {
            self.processed_start_offset = new_processed_start_offset;
        }
    }

    fn read_processed_message(
        &mut self,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        if !self.is_udp {
            self.read_processed(buf);
            return Ok(());
        }

        let message_len =
            *self.processed_message_lengths.front().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "VMess UDP payload is missing its message boundary",
                )
            })?;
        if message_len > buf.remaining() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "VMess UDP payload exceeds receive buffer: {message_len} > {}",
                    buf.remaining()
                ),
            ));
        }

        buf.put_slice(
            &self.processed_buf[self.processed_start_offset
                ..self.processed_start_offset + message_len],
        );
        self.processed_message_lengths.pop_front();
        self.processed_start_offset += message_len;
        if self.processed_start_offset == self.processed_end_offset {
            self.processed_start_offset = 0;
            self.processed_end_offset = 0;
        }
        Ok(())
    }

    fn create_write_packet(&mut self) -> bool {
        if let Some(prefix) = self.pending_prefix_write.take() {
            assert!(self.write_packet_end_offset == 0);
            let prefix_len = prefix.len();
            self.write_packet[0..prefix_len].copy_from_slice(&prefix);
            self.write_packet_end_offset = prefix_len;
        }

        let write_packet_space =
            self.write_packet.len() - self.write_packet_end_offset;
        let max_padding_len = if self.write_length_mask.is_some() {
            MAX_PADDING_LEN
        } else {
            0
        };

        let max_metadata_size = 2 + max_padding_len + self.tag_len;
        if max_metadata_size >= write_packet_space {
            return false;
        }

        let (padding_len, length_mask) = match self.write_length_mask {
            Some(ref mut mask) => mask.next_values(),
            None => (0, 0),
        };

        let metadata_size = 2 + padding_len + self.tag_len;
        let max_data_size = std::cmp::min(
            write_packet_space - metadata_size,
            MAX_ENCRYPTED_WRITE_DATA_SIZE - padding_len - self.tag_len,
        );
        let data_size = std::cmp::min(max_data_size, self.write_cache_size);

        let write_packet_size: usize = data_size + padding_len + self.tag_len;
        assert!(write_packet_size + 2 <= self.write_packet.len());

        let mut next_index = self.write_packet_end_offset;

        let write_packet_size = (write_packet_size as u16) ^ length_mask;
        self.write_packet[next_index] = (write_packet_size >> 8) as u8;
        self.write_packet[next_index + 1] = (write_packet_size & 0xff) as u8;

        next_index += 2;
        self.write_packet[next_index..next_index + data_size]
            .copy_from_slice(&self.write_cache[0..data_size]);

        match self.sealing_key {
            Some(ref mut sealing_key) => {
                let tag = sealing_key
                    .seal_in_place_separate_tag(
                        Aad::empty(),
                        &mut self.write_packet[next_index..next_index + data_size],
                    )
                    .unwrap();
                next_index += data_size;

                self.write_packet[next_index..next_index + self.tag_len]
                    .copy_from_slice(tag.as_ref());
                next_index += self.tag_len;
            }
            None => {
                next_index += data_size;
            }
        }

        if padding_len > 0 {
            rand::rng().fill_bytes(
                &mut self.write_packet[next_index..next_index + padding_len],
            );
            next_index += padding_len;
        }

        self.write_packet_end_offset = next_index;

        if data_size == self.write_cache_size {
            self.write_cache_size = 0;
        } else {
            self.write_cache
                .copy_within(data_size..self.write_cache_size, 0);
            self.write_cache_size -= data_size;
        }

        true
    }

    #[inline]
    fn do_write_packet(&mut self, cx: &mut Context<'_>) -> std::io::Result<bool> {
        loop {
            let remaining_data = &self.write_packet
                [self.write_packet_start_offset..self.write_packet_end_offset];

            match Pin::new(&mut self.stream).poll_write(cx, remaining_data) {
                Poll::Ready(Ok(written)) => {
                    if written == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "write packet eof",
                        ));
                    }
                    self.write_packet_start_offset += written;
                    if self.write_packet_start_offset == self.write_packet_end_offset
                    {
                        self.write_packet_start_offset = 0;
                        self.write_packet_end_offset = 0;
                        return Ok(true);
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
                Poll::Pending => {
                    return Ok(false);
                }
            }
        }
    }

    fn reset_unprocessed_buf_offset(&mut self) {
        assert!(
            self.unprocessed_start_offset > 0
                && self.unprocessed_end_offset > self.unprocessed_start_offset
        );

        self.unprocessed_buf.copy_within(
            self.unprocessed_start_offset..self.unprocessed_end_offset,
            0,
        );
        self.unprocessed_end_offset -= self.unprocessed_start_offset;
        self.unprocessed_start_offset = 0;
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.read_header_state != ReadHeaderState::Done && !this.is_eof {
            loop {
                let mut read_buf = ReadBuf::new(
                    &mut this.unprocessed_buf[this.unprocessed_end_offset..],
                );
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;
                let len = read_buf.filled().len();
                if len == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "VMess stream closed while reading the response header",
                    )));
                }
                this.unprocessed_end_offset += len;
                this.process_read_header()?;
                if this.read_header_state == ReadHeaderState::Done {
                    break;
                }
            }

            loop {
                match this.try_decrypt()? {
                    DecryptState::NeedData => {
                        break;
                    }
                    DecryptState::ReceivedEof => {
                        this.is_eof = true;
                        break;
                    }
                    DecryptState::BufferFull => {
                        assert!(this.processed_end_offset > 0);
                        this.read_processed(buf);
                        return Poll::Ready(Ok(()));
                    }
                    DecryptState::Success => {
                        continue;
                    }
                }
            }
        }

        if this.processed_end_offset > 0 {
            this.read_processed(buf);
            return Poll::Ready(Ok(()));
        } else if this.is_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.unprocessed_end_offset == this.unprocessed_buf.len() {
                this.reset_unprocessed_buf_offset();
                assert!(this.unprocessed_end_offset < this.unprocessed_buf.len());
            }

            let mut read_buf = ReadBuf::new(
                &mut this.unprocessed_buf[this.unprocessed_end_offset..],
            );
            ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;

            let len = read_buf.filled().len();

            if len == 0 {
                let has_partial_frame = this.unprocessed_pending_len.is_some()
                    || this.unprocessed_end_offset > this.unprocessed_start_offset;
                if has_partial_frame {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "VMess stream closed in the middle of a data frame",
                    )));
                }
                this.is_eof = true;
                return Poll::Ready(Ok(()));
            }

            this.unprocessed_end_offset += len;

            loop {
                match this.try_decrypt()? {
                    DecryptState::NeedData => {
                        break;
                    }
                    DecryptState::ReceivedEof => {
                        this.is_eof = true;
                        break;
                    }
                    DecryptState::BufferFull => {
                        assert!(this.processed_end_offset > 0);
                        this.read_processed(buf);
                        return Poll::Ready(Ok(()));
                    }
                    DecryptState::Success => {
                        continue;
                    }
                }
            }

            if this.processed_end_offset > 0 {
                this.read_processed(buf);
                return Poll::Ready(Ok(()));
            }

            if this.is_eof {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        let mut cache_space =
            this.write_cache.len().saturating_sub(this.write_cache_size);

        if cache_space == 0 {
            while this.write_cache_size > 0 && this.create_write_packet() {}
            match this.do_write_packet(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
            while this.write_cache_size > 0 && this.create_write_packet() {}
            cache_space =
                this.write_cache.len().saturating_sub(this.write_cache_size);
            assert!(cache_space > 0);
        }

        let write_count = std::cmp::min(cache_space, buf.len());

        this.write_cache[this.write_cache_size..this.write_cache_size + write_count]
            .copy_from_slice(&buf[0..write_count]);
        this.write_cache_size += write_count;

        Poll::Ready(Ok(write_count))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.write_cache_size == 0 && this.write_packet_end_offset == 0 {
            return Pin::new(&mut this.stream).poll_flush(cx);
        }

        while this.write_cache_size > 0 || this.write_packet_end_offset > 0 {
            while this.write_cache_size > 0 && this.create_write_packet() {}
            match this.do_write_packet(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
            ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut this = self.get_mut();

        loop {
            match this.shutdown_state {
                ShutdownState::WriteRemainingData => {
                    if this.write_cache_size > 0 {
                        while this.write_cache_size > 0 && this.create_write_packet()
                        {
                        }
                    }

                    if this.write_cache_size == 0 && this.create_write_packet() {
                        this.shutdown_state = ShutdownState::WriteEmptyPacket;
                        continue;
                    }
                    ready!(Pin::new(&mut this).poll_flush(cx))?;
                }
                ShutdownState::WriteEmptyPacket => {
                    ready!(Pin::new(&mut this).poll_flush(cx))?;
                    this.shutdown_state = ShutdownState::PollShutdown;
                }
                ShutdownState::PollShutdown => {
                    ready!(Pin::new(&mut this.stream).poll_shutdown(cx))?;
                    break;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for VmessStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl AsyncStream for VmessStream {}

impl AsyncReadMessage for VmessStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.read_header_state != ReadHeaderState::Done && !this.is_eof {
            loop {
                let mut read_buf = ReadBuf::new(
                    &mut this.unprocessed_buf[this.unprocessed_end_offset..],
                );
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;
                let len = read_buf.filled().len();
                if len == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "VMess stream closed while reading the response header",
                    )));
                }
                this.unprocessed_end_offset += len;
                this.process_read_header()?;
                if this.read_header_state == ReadHeaderState::Done {
                    break;
                }
            }

            loop {
                match this.try_decrypt()? {
                    DecryptState::NeedData => break,
                    DecryptState::ReceivedEof => {
                        this.is_eof = true;
                        break;
                    }
                    DecryptState::BufferFull => {
                        assert!(this.processed_end_offset > 0);
                        this.read_processed_message(buf)?;
                        return Poll::Ready(Ok(()));
                    }
                    DecryptState::Success => continue,
                }
            }
        }

        if this.processed_end_offset > 0 {
            this.read_processed_message(buf)?;
            return Poll::Ready(Ok(()));
        }

        match this.try_decrypt()? {
            DecryptState::NeedData => {}
            DecryptState::ReceivedEof => this.is_eof = true,
            DecryptState::BufferFull | DecryptState::Success => {
                assert!(this.processed_end_offset > 0);
                this.read_processed_message(buf)?;
                return Poll::Ready(Ok(()));
            }
        }

        if this.is_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.unprocessed_end_offset == this.unprocessed_buf.len() {
                this.reset_unprocessed_buf_offset();
                assert!(this.unprocessed_end_offset < this.unprocessed_buf.len());
            }

            let mut read_buf = ReadBuf::new(
                &mut this.unprocessed_buf[this.unprocessed_end_offset..],
            );
            ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;
            let len = read_buf.filled().len();

            if len == 0 {
                let has_partial_frame = this.unprocessed_pending_len.is_some()
                    || this.unprocessed_end_offset > this.unprocessed_start_offset;
                if has_partial_frame {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "VMess stream closed in the middle of a data frame",
                    )));
                }
                this.is_eof = true;
                return Poll::Ready(Ok(()));
            }

            this.unprocessed_end_offset += len;
            match this.try_decrypt()? {
                DecryptState::NeedData => {}
                DecryptState::ReceivedEof => {
                    this.is_eof = true;
                    return Poll::Ready(Ok(()));
                }
                DecryptState::BufferFull | DecryptState::Success => {
                    assert!(this.processed_end_offset > 0);
                    this.read_processed_message(buf)?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWriteMessage for VmessStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        assert!(this.write_cache_size == 0);

        if let Some(prefix) = this.pending_prefix_write.take() {
            assert!(this.write_packet_end_offset == 0);
            let prefix_len = prefix.len();
            this.write_packet[0..prefix_len].copy_from_slice(&prefix);
            this.write_packet_end_offset = prefix_len;
        }

        if this.write_packet_end_offset > 0 {
            match this.do_write_packet(cx) {
                Ok(true) => {}
                Ok(false) => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }

        let (padding_len, length_mask) = match this.write_length_mask {
            Some(ref mut mask) => mask.next_values(),
            None => (0, 0),
        };
        let metadata_size = 2 + padding_len + this.tag_len;
        let available_space = std::cmp::min(
            this.write_packet.len() - metadata_size,
            MAX_VMESS_UDP_PAYLOAD_SIZE,
        );
        if available_space < buf.len() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "VMess UDP payload is too large: {} bytes exceeds {available_space}",
                    buf.len()
                ),
            )));
        }

        let packet_size = buf.len() + padding_len + this.tag_len;
        let packet_size = u16::try_from(packet_size).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("VMess UDP frame is too large: {packet_size} bytes"),
            )
        })? ^ length_mask;
        this.write_packet[0..2].copy_from_slice(&packet_size.to_be_bytes());

        let mut end_index = 2 + buf.len();
        this.write_packet[2..end_index].copy_from_slice(buf);
        if let Some(ref mut sealing_key) = this.sealing_key {
            let tag = sealing_key
                .seal_in_place_separate_tag(
                    Aad::empty(),
                    &mut this.write_packet[2..end_index],
                )
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "failed to seal VMess UDP message: {error}"
                    ))
                })?;
            this.write_packet[end_index..end_index + this.tag_len]
                .copy_from_slice(tag.as_ref());
            end_index += this.tag_len;
        }

        if padding_len > 0 {
            rand::rng().fill_bytes(
                &mut this.write_packet[end_index..end_index + padding_len],
            );
            end_index += padding_len;
        }
        this.write_packet_end_offset = end_index;
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for VmessStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        assert!(this.write_cache_size == 0);

        if this.write_packet_end_offset > 0 {
            match this.do_write_packet(cx) {
                Ok(true) => {}
                Ok(false) => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }

        ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for VmessStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_shutdown(cx)
    }
}

impl AsyncMessageStream for VmessStream {}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        pin::Pin,
        task::{Context, Poll},
    };

    use sha3::{
        Shake128,
        digest::{ExtendableOutput, Update},
    };
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    };

    use super::*;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    fn plain_stream(is_udp: bool) -> (DuplexStream, VmessStream) {
        plain_stream_with_capacity(is_udp, MAX_ENCRYPTED_READ_DATA_SIZE + 64)
    }

    fn plain_stream_with_capacity(
        is_udp: bool,
        capacity: usize,
    ) -> (DuplexStream, VmessStream) {
        let (client, server) = duplex(capacity);
        let stream = VmessStream::new(
            Box::new(TestStream(server)),
            is_udp,
            None,
            None,
            None,
            false,
            None,
            None,
        );
        (client, stream)
    }

    fn shake_reader(seed: &[u8]) -> VmessReader {
        let mut hasher = Shake128::default();
        hasher.update(seed);
        hasher.finalize_xof()
    }

    fn encrypted_stream(
        is_udp: bool,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> (DuplexStream, VmessStream) {
        encrypted_stream_with_algorithm(is_udp, &AES_128_GCM, key, iv)
    }

    fn encrypted_stream_with_algorithm(
        is_udp: bool,
        algorithm: &'static aws_lc_rs::aead::Algorithm,
        key: &[u8],
        iv: &[u8; 16],
    ) -> (DuplexStream, VmessStream) {
        let (client, server) = duplex(MAX_ENCRYPTED_READ_DATA_SIZE + 64);
        let opening_key = OpeningKey::new(
            UnboundKey::new(algorithm, key).expect("create VMess opening key"),
            VmessNonceSequence::new(iv),
        );
        let sealing_key = SealingKey::new(
            UnboundKey::new(algorithm, key).expect("create VMess sealing key"),
            VmessNonceSequence::new(iv),
        );
        let stream = VmessStream::new(
            Box::new(TestStream(server)),
            is_udp,
            Some((opening_key, sealing_key)),
            None,
            None,
            false,
            None,
            None,
        );
        (client, stream)
    }

    fn response_header_info() -> ReadHeaderInfo {
        ReadHeaderInfo {
            response_header_key: [0x71; 16],
            response_header_iv: [0x82; 16],
            response_authentication_v: 0x93,
        }
    }

    fn response_header_stream(info: ReadHeaderInfo) -> (DuplexStream, VmessStream) {
        let (client, server) = duplex(4096);
        let stream = VmessStream::new(
            Box::new(TestStream(server)),
            true,
            None,
            None,
            None,
            false,
            None,
            Some(info),
        );
        (client, stream)
    }

    fn encode_response_header(info: &ReadHeaderInfo, content: &[u8]) -> Vec<u8> {
        assert!(content.len() <= u16::MAX as usize);
        let length_key = super::super::sha2::kdf(
            &info.response_header_key,
            &[b"AEAD Resp Header Len Key"],
        );
        let length_nonce = super::super::sha2::kdf(
            &info.response_header_iv,
            &[b"AEAD Resp Header Len IV"],
        );
        let mut encrypted_length = (content.len() as u16).to_be_bytes().to_vec();
        let mut length_sealer = SealingKey::new(
            UnboundKey::new(&AES_128_GCM, &length_key[..16])
                .expect("create VMess response length key"),
            SingleUseNonce::new(&length_nonce[..12]),
        );
        let length_tag = length_sealer
            .seal_in_place_separate_tag(Aad::empty(), &mut encrypted_length)
            .expect("seal VMess response header length");
        encrypted_length.extend_from_slice(length_tag.as_ref());

        let content_key = super::super::sha2::kdf(
            &info.response_header_key,
            &[b"AEAD Resp Header Key"],
        );
        let content_nonce = super::super::sha2::kdf(
            &info.response_header_iv,
            &[b"AEAD Resp Header IV"],
        );
        let mut encrypted_content = content.to_vec();
        let mut content_sealer = SealingKey::new(
            UnboundKey::new(&AES_128_GCM, &content_key[..16])
                .expect("create VMess response content key"),
            SingleUseNonce::new(&content_nonce[..12]),
        );
        let content_tag = content_sealer
            .seal_in_place_separate_tag(Aad::empty(), &mut encrypted_content)
            .expect("seal VMess response header content");
        encrypted_content.extend_from_slice(content_tag.as_ref());

        encrypted_length.extend_from_slice(&encrypted_content);
        encrypted_length
    }

    fn encode_encrypted_frame(
        key: &[u8; 16],
        iv: &[u8; 16],
        payload: &[u8],
    ) -> Vec<u8> {
        encode_encrypted_frame_with_algorithm(&AES_128_GCM, key, iv, payload)
    }

    fn encode_encrypted_frame_with_algorithm(
        algorithm: &'static aws_lc_rs::aead::Algorithm,
        key: &[u8],
        iv: &[u8; 16],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut sealing_key = SealingKey::new(
            UnboundKey::new(algorithm, key)
                .expect("create VMess fixture sealing key"),
            VmessNonceSequence::new(iv),
        );
        let mut encrypted = payload.to_vec();
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut encrypted)
            .expect("seal VMess fixture frame");
        let frame_length = encrypted.len() + tag.as_ref().len();
        let mut frame = Vec::with_capacity(frame_length + 2);
        frame.extend_from_slice(&(frame_length as u16).to_be_bytes());
        frame.extend_from_slice(&encrypted);
        frame.extend_from_slice(tag.as_ref());
        frame
    }

    async fn read_message(
        stream: &mut VmessStream,
        output: &mut [u8],
    ) -> std::io::Result<usize> {
        poll_fn(|cx| {
            let mut buffer = ReadBuf::new(output);
            match Pin::new(&mut *stream).poll_read_message(cx, &mut buffer) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    #[test]
    fn short_response_headers_are_rejected_without_panicking() {
        for length in 0..4 {
            let header = vec![7u8; length];
            let error = check_header_response(&header, 7)
                .expect_err("short VMess response header must fail");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("too short"));
        }
    }

    #[test]
    fn masked_length_smaller_than_padding_is_rejected() {
        let (seed, padding_len, length_mask) = (0u16..=u16::MAX)
            .find_map(|candidate| {
                let seed = candidate.to_be_bytes();
                let mut preview = LengthMask::new(shake_reader(&seed), true);
                let (padding_len, length_mask) = preview.next_values();
                (padding_len > 0).then_some((seed, padding_len, length_mask))
            })
            .expect("find deterministic VMess padding seed");
        let (_, mut stream) = plain_stream(true);
        stream.read_length_mask = Some(LengthMask::new(shake_reader(&seed), true));
        let decoded_length = padding_len - 1;
        let wire_length = (decoded_length as u16) ^ length_mask;

        let error = stream
            .feed_initial_read_data(&wire_length.to_be_bytes())
            .expect_err("VMess padding larger than frame length must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("padding length"));
    }

    #[tokio::test]
    async fn valid_aead_response_header_can_arrive_one_byte_at_a_time() {
        let info = response_header_info();
        let auth_value = info.response_authentication_v;
        let mut wire = encode_response_header(&info, &[auth_value, 0, 0, 0]);
        wire.extend_from_slice(&[0, 4, b'd', b'a', b't', b'a']);
        let (mut client, mut stream) = response_header_stream(info);
        let writer = tokio::spawn(async move {
            for byte in wire {
                client
                    .write_all(&[byte])
                    .await
                    .expect("write fragmented VMess response byte");
                tokio::task::yield_now().await;
            }
        });
        let mut output = [0u8; 16];

        let length = read_message(&mut stream, &mut output)
            .await
            .expect("read data after fragmented VMess response header");

        assert_eq!(&output[..length], b"data");
        assert_eq!(stream.read_header_state, ReadHeaderState::Done);
        writer.await.expect("fragmented response writer task");
    }

    #[test]
    fn corrupted_aead_response_length_tag_is_rejected() {
        let info = response_header_info();
        let auth_value = info.response_authentication_v;
        let mut wire = encode_response_header(&info, &[auth_value, 0, 0, 0]);
        wire[17] ^= 0x01;
        let (_, mut stream) = response_header_stream(info);

        let error = stream
            .feed_initial_read_data(&wire)
            .expect_err("corrupted VMess response length tag must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("header length"));
    }

    #[test]
    fn corrupted_aead_response_content_tag_is_rejected() {
        let info = response_header_info();
        let auth_value = info.response_authentication_v;
        let mut wire = encode_response_header(&info, &[auth_value, 0, 0, 0]);
        *wire.last_mut().expect("VMess response content tag") ^= 0x01;
        let (_, mut stream) = response_header_stream(info);

        let error = stream
            .feed_initial_read_data(&wire)
            .expect_err("corrupted VMess response content tag must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("response header"));
    }

    #[test]
    fn short_and_command_overflow_response_headers_are_rejected() {
        for content in [
            vec![0x93, 0, 0],
            vec![0x93, 0, 0, 1],
            vec![0x93, 0, 0, 2, 0xaa],
        ] {
            let info = response_header_info();
            let wire = encode_response_header(&info, &content);
            let (_, mut stream) = response_header_stream(info);

            let error = stream
                .feed_initial_read_data(&wire)
                .expect_err("invalid VMess response content shape must fail");

            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn response_header_command_bytes_are_consumed_before_data() {
        let info = response_header_info();
        let auth_value = info.response_authentication_v;
        let mut wire =
            encode_response_header(&info, &[auth_value, 0, 0, 2, 0xaa, 0xbb]);
        wire.extend_from_slice(&[0, 4, b'd', b'a', b't', b'a']);
        let (mut client, mut stream) = response_header_stream(info);
        client
            .write_all(&wire)
            .await
            .expect("write VMess response command and data");
        let mut output = [0u8; 16];

        let length = read_message(&mut stream, &mut output)
            .await
            .expect("read data after VMess response command bytes");

        assert_eq!(&output[..length], b"data");
    }

    #[tokio::test]
    async fn encrypted_udp_frame_roundtrips() {
        let key = [0x11; 16];
        let iv = [0x22; 16];
        let (mut client, mut stream) = encrypted_stream(true, &key, &iv);
        let frame = encode_encrypted_frame(&key, &iv, b"secret");
        client
            .write_all(&frame)
            .await
            .expect("write encrypted VMess UDP frame");
        let mut output = [0u8; 16];

        let length = read_message(&mut stream, &mut output)
            .await
            .expect("read encrypted VMess UDP frame");

        assert_eq!(&output[..length], b"secret");
    }

    #[tokio::test]
    async fn chacha20_poly1305_udp_frame_roundtrips() {
        let key = [0x21; 32];
        let iv = [0x32; 16];
        let algorithm = &aws_lc_rs::aead::CHACHA20_POLY1305;
        let (mut client, mut stream) =
            encrypted_stream_with_algorithm(true, algorithm, &key, &iv);
        let frame =
            encode_encrypted_frame_with_algorithm(algorithm, &key, &iv, b"chacha");
        client
            .write_all(&frame)
            .await
            .expect("write ChaCha20-Poly1305 VMess UDP frame");
        let mut output = [0u8; 16];

        let length = read_message(&mut stream, &mut output)
            .await
            .expect("read ChaCha20-Poly1305 VMess UDP frame");

        assert_eq!(&output[..length], b"chacha");
    }

    #[tokio::test]
    async fn corrupted_chacha20_poly1305_frame_is_rejected() {
        let key = [0x41; 32];
        let iv = [0x52; 16];
        let algorithm = &aws_lc_rs::aead::CHACHA20_POLY1305;
        let (mut client, mut stream) =
            encrypted_stream_with_algorithm(true, algorithm, &key, &iv);
        let mut frame =
            encode_encrypted_frame_with_algorithm(algorithm, &key, &iv, b"chacha");
        *frame.last_mut().expect("ChaCha20-Poly1305 VMess tag") ^= 0x01;
        client
            .write_all(&frame)
            .await
            .expect("write corrupted ChaCha20-Poly1305 VMess frame");
        let mut output = [0u8; 16];

        let error = read_message(&mut stream, &mut output)
            .await
            .expect_err("corrupted ChaCha20-Poly1305 VMess frame must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(output, [0; 16]);
    }

    #[tokio::test]
    async fn corrupted_encrypted_udp_frame_is_rejected() {
        let key = [0x31; 16];
        let iv = [0x42; 16];
        let (mut client, mut stream) = encrypted_stream(true, &key, &iv);
        let mut frame = encode_encrypted_frame(&key, &iv, b"secret");
        *frame.last_mut().expect("encrypted VMess frame tag") ^= 0x01;
        client
            .write_all(&frame)
            .await
            .expect("write corrupted encrypted VMess UDP frame");
        let mut output = [0u8; 16];

        let error = read_message(&mut stream, &mut output)
            .await
            .expect_err("corrupted encrypted VMess UDP frame must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("open failed"));
        assert_eq!(output, [0; 16]);
    }

    #[tokio::test]
    async fn encrypted_eof_requires_a_valid_tag() {
        let key = [0x51; 16];
        let iv = [0x62; 16];

        let (mut valid_client, mut valid_stream) = encrypted_stream(true, &key, &iv);
        valid_client
            .write_all(&encode_encrypted_frame(&key, &iv, b""))
            .await
            .expect("write authenticated VMess EOF frame");
        let mut output = [0u8; 1];
        let length = read_message(&mut valid_stream, &mut output)
            .await
            .expect("read authenticated VMess EOF frame");
        assert_eq!(length, 0);
        assert!(valid_stream.is_eof);

        let (mut invalid_client, mut invalid_stream) =
            encrypted_stream(true, &key, &iv);
        let mut invalid_frame = encode_encrypted_frame(&key, &iv, b"");
        *invalid_frame
            .last_mut()
            .expect("VMess EOF authentication tag") ^= 0x01;
        invalid_client
            .write_all(&invalid_frame)
            .await
            .expect("write unauthenticated VMess EOF frame");
        let error = read_message(&mut invalid_stream, &mut output)
            .await
            .expect_err("unauthenticated VMess EOF frame must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!invalid_stream.is_eof);
    }

    #[test]
    fn maximum_plain_frame_fills_processed_buffer() {
        let payload = vec![0x5a; MAX_ENCRYPTED_READ_DATA_SIZE];
        let mut frame = Vec::with_capacity(payload.len() + 2);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&payload);
        let (_, mut stream) = plain_stream(false);

        stream
            .feed_initial_read_data(&frame)
            .expect("maximum plain VMess frame must decode");

        assert_eq!(stream.processed_end_offset, payload.len());
        assert_eq!(&stream.processed_buf[..payload.len()], payload.as_slice());
    }

    #[test]
    fn oversized_direct_udp_frame_is_rejected() {
        let payload = vec![0x5a; MAX_VMESS_UDP_PAYLOAD_SIZE + 1];
        let mut frame = Vec::with_capacity(payload.len() + 2);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&payload);
        let (_, mut stream) = plain_stream(true);

        let error = stream
            .feed_initial_read_data(&frame)
            .expect_err("oversized direct VMess UDP frame must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("Xray buffer limit"));
        assert!(stream.processed_message_lengths.is_empty());
    }

    #[tokio::test]
    async fn truncated_plain_frames_return_unexpected_eof() {
        let frame = [0, 3, b'o', b'n', b'e'];

        for prefix_length in 1..frame.len() {
            let (mut client, mut stream) = plain_stream(true);
            client
                .write_all(&frame[..prefix_length])
                .await
                .expect("write truncated VMess data frame");
            client
                .shutdown()
                .await
                .expect("close truncated VMess data writer");
            let mut output = [0u8; 16];

            let error = read_message(&mut stream, &mut output)
                .await
                .expect_err("truncated VMess data frame must fail");

            assert_eq!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "prefix length {prefix_length}"
            );
        }
    }

    #[tokio::test]
    async fn explicit_empty_frame_marks_protocol_eof() {
        let (mut client, mut stream) = plain_stream(true);
        client
            .write_all(&[0, 0])
            .await
            .expect("write VMess EOF frame");
        let mut output = [0u8; 16];

        let length = read_message(&mut stream, &mut output)
            .await
            .expect("read VMess EOF frame");

        assert_eq!(length, 0);
        assert!(stream.is_eof);
    }

    #[tokio::test]
    async fn small_udp_buffer_preserves_message_for_retry() {
        let (mut client, mut stream) = plain_stream(true);
        client
            .write_all(&[0, 7, b'p', b'a', b'y', b'l', b'o', b'a', b'd'])
            .await
            .expect("write VMess UDP caller-buffer fixture");
        let mut small = [0u8; 4];

        let error = read_message(&mut stream, &mut small)
            .await
            .expect_err("small VMess UDP caller buffer must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds receive buffer"));
        assert_eq!(small, [0; 4]);

        let mut large = [0u8; 16];
        let length = read_message(&mut stream, &mut large)
            .await
            .expect("retry VMess UDP message with a large buffer");
        assert_eq!(&large[..length], b"payload");
    }

    #[tokio::test]
    async fn initial_data_preserves_multiple_udp_message_boundaries() {
        let (_, mut stream) = plain_stream(true);
        stream
            .feed_initial_read_data(&[
                0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o',
            ])
            .expect("feed multiple initial VMess UDP frames");
        assert_eq!(
            stream
                .processed_message_lengths
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [3, 3]
        );
        let mut output = [0u8; 16];

        let first = read_message(&mut stream, &mut output)
            .await
            .expect("read first initial VMess UDP frame");
        assert_eq!(&output[..first], b"one");
        let second = read_message(&mut stream, &mut output)
            .await
            .expect("read second initial VMess UDP frame");
        assert_eq!(&output[..second], b"two");
    }

    #[tokio::test]
    async fn plain_udp_writes_length_prefixed_messages() {
        let (mut client, mut stream) = plain_stream(true);

        for payload in [b"one".as_slice(), b"two".as_slice()] {
            poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, payload))
                .await
                .expect("queue plain VMess UDP message");
            poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
                .await
                .expect("flush plain VMess UDP message");
        }

        let mut encoded = [0u8; 10];
        client
            .read_exact(&mut encoded)
            .await
            .expect("read plain VMess UDP messages");
        assert_eq!(&encoded, &[0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o']);
    }

    #[tokio::test]
    async fn partial_udp_writes_do_not_duplicate_frames_or_eof() {
        let (mut client, mut stream) = plain_stream_with_capacity(true, 1);
        let writer_task = tokio::spawn(async move {
            for payload in [b"one".as_slice(), b"two".as_slice()] {
                poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, payload))
                    .await
                    .expect("queue VMess UDP message through one-byte transport");
                poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
                    .await
                    .expect("flush VMess UDP message through one-byte transport");
            }
            poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
                .await
                .expect("shutdown VMess UDP one-byte transport");
        });

        let mut actual = Vec::new();
        client
            .read_to_end(&mut actual)
            .await
            .expect("read VMess UDP one-byte transport frames");
        writer_task.await.expect("VMess UDP partial writer task");

        assert_eq!(
            actual,
            [0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o', 0, 0,]
        );
    }

    #[tokio::test]
    async fn maximum_plain_udp_write_roundtrips() {
        let (mut client, mut stream) = plain_stream(true);
        let payload = vec![0x5a; MAX_VMESS_UDP_PAYLOAD_SIZE];

        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &payload))
            .await
            .expect("queue maximum plain VMess UDP message");
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .expect("flush maximum plain VMess UDP message");

        let mut length = [0u8; 2];
        client
            .read_exact(&mut length)
            .await
            .expect("read maximum VMess UDP length");
        assert_eq!(
            u16::from_be_bytes(length) as usize,
            MAX_VMESS_UDP_PAYLOAD_SIZE
        );
        let mut decoded = vec![0u8; payload.len()];
        client
            .read_exact(&mut decoded)
            .await
            .expect("read maximum VMess UDP payload");
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn oversized_plain_udp_write_is_rejected() {
        let (_, mut stream) = plain_stream(true);
        let payload = vec![0u8; MAX_VMESS_UDP_PAYLOAD_SIZE + 1];

        let error =
            poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &payload))
                .await
                .expect_err("oversized plain VMess UDP message must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("too large"));
    }

    #[tokio::test]
    async fn large_tcp_write_is_segmented_without_loss() {
        let (mut client, mut stream) = plain_stream(false);
        let payload = (0..20_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        stream
            .write_all(&payload)
            .await
            .expect("write large plain VMess TCP payload");
        stream
            .flush()
            .await
            .expect("flush large plain VMess TCP payload");

        let mut decoded = Vec::with_capacity(payload.len());
        while decoded.len() < payload.len() {
            let length = client
                .read_u16()
                .await
                .expect("read plain VMess TCP frame length")
                as usize;
            assert!(length <= MAX_ENCRYPTED_WRITE_DATA_SIZE);
            let start = decoded.len();
            decoded.resize(start + length, 0);
            client
                .read_exact(&mut decoded[start..])
                .await
                .expect("read plain VMess TCP frame payload");
        }
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn tcp_shutdown_flushes_payload_and_protocol_eof() {
        let (mut client, mut stream) = plain_stream(false);
        stream
            .write_all(b"payload")
            .await
            .expect("write plain VMess TCP payload before shutdown");
        stream
            .shutdown()
            .await
            .expect("shutdown plain VMess TCP stream");

        let mut encoded = Vec::new();
        client
            .read_to_end(&mut encoded)
            .await
            .expect("read VMess TCP shutdown frames");
        assert_eq!(
            encoded,
            [0, 7, b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0, 0]
        );
    }

    #[tokio::test]
    async fn consecutive_plain_udp_frames_preserve_message_boundaries() {
        let (mut client, mut stream) = plain_stream(true);
        client
            .write_all(&[0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o'])
            .await
            .expect("write consecutive plain VMess UDP frames");
        let mut output = [0u8; 16];

        let first = read_message(&mut stream, &mut output)
            .await
            .expect("read first plain VMess UDP frame");
        assert_eq!(&output[..first], b"one");
        let second = read_message(&mut stream, &mut output)
            .await
            .expect("read second plain VMess UDP frame");
        assert_eq!(&output[..second], b"two");
    }
}
