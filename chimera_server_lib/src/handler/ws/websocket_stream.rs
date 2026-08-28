use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use rand::Rng;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Duration, Instant, Interval, MissedTickBehavior, interval_at},
};
use tracing::warn;

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::util::allocate_vec;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum WebsocketPingType {
    Disabled,
    #[default]
    PingFrame,
    EmptyFrame,
}

pub struct WebsocketStream {
    stream: Box<dyn AsyncStream>,
    is_client: bool,
    ping_type: WebsocketPingType,
    heartbeat_interval: Option<Interval>,
    heartbeat_ping_pending: bool,
    pending_initial_data: bool,

    read_state: ReadState,
    read_frame_masked: bool,
    read_frame_opcode: OpCode,
    read_frame_length: u64,
    read_frame_mask: [u8; 4],
    read_frame_mask_offset: usize,
    read_message_fragmented: bool,

    unprocessed_buf: Box<[u8]>,
    unprocessed_start_offset: usize,
    unprocessed_end_offset: usize,

    write_frame: Box<[u8]>,
    write_frame_start_offset: usize,
    write_frame_end_offset: usize,

    ping_data: Box<[u8]>,
    ping_data_size: usize,
    pending_write_pong: bool,

    close_data: [u8; 125],
    close_data_size: usize,
    close_received: bool,
    close_sent: bool,
    protocol_error_pending: bool,
    protocol_error_reason: String,
}

#[derive(Debug, PartialEq)]
enum ReadState {
    Init,
    ReadLength { length_bytes_len: usize },
    ReadMask,
    ReadBinaryContent,
    ReadPingContent,
    ReadCloseContent,
    SkipContent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpCode {
    Continue,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Unknown(u8),
}

impl OpCode {
    pub fn from(code: u8) -> Self {
        match code {
            0 => OpCode::Continue,
            1 => OpCode::Text,
            2 => OpCode::Binary,
            8 => OpCode::Close,
            9 => OpCode::Ping,
            10 => OpCode::Pong,
            _ => OpCode::Unknown(code),
        }
    }
}

impl WebsocketStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        is_client: bool,
        unprocessed_data: &[u8],
    ) -> Self {
        Self::new_with_heartbeat(stream, is_client, unprocessed_data, 0)
    }

    pub fn new_with_heartbeat(
        stream: Box<dyn AsyncStream>,
        is_client: bool,
        unprocessed_data: &[u8],
        heartbeat_period_secs: u32,
    ) -> Self {
        let mut unprocessed_buf = allocate_vec(16384).into_boxed_slice();
        let mut unprocessed_end_offset = 0;
        let write_frame = allocate_vec(32768).into_boxed_slice();
        let ping_data = allocate_vec(125).into_boxed_slice();

        let pending_initial_data = if !unprocessed_data.is_empty() {
            unprocessed_buf[0..unprocessed_data.len()]
                .copy_from_slice(unprocessed_data);
            unprocessed_end_offset = unprocessed_data.len();
            true
        } else {
            false
        };

        let heartbeat_interval = if heartbeat_period_secs == 0 {
            None
        } else {
            let period = Duration::from_secs(heartbeat_period_secs as u64);
            let mut interval = interval_at(Instant::now() + period, period);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            Some(interval)
        };

        Self {
            stream,
            is_client,
            ping_type: WebsocketPingType::PingFrame,
            heartbeat_interval,
            heartbeat_ping_pending: false,
            pending_initial_data,
            read_state: ReadState::Init,
            read_frame_masked: false,
            read_frame_opcode: OpCode::Unknown(99),
            read_frame_length: 0,
            read_frame_mask: [0u8; 4],
            read_frame_mask_offset: 0,
            read_message_fragmented: false,
            unprocessed_buf,
            unprocessed_start_offset: 0,
            unprocessed_end_offset,
            write_frame,
            write_frame_start_offset: 0,
            write_frame_end_offset: 0,
            ping_data,
            ping_data_size: 0,
            pending_write_pong: false,
            close_data: [0; 125],
            close_data_size: 0,
            close_received: false,
            close_sent: false,
            protocol_error_pending: false,
            protocol_error_reason: String::new(),
        }
    }

    fn step_init(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len =
            self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < 2 {
            return Ok(());
        }

        let first = self.unprocessed_buf[self.unprocessed_start_offset];
        let second = self.unprocessed_buf[self.unprocessed_start_offset + 1];
        self.unprocessed_start_offset += 2;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        let read_frame_final = first & 0x80 != 0;

        let reserved_bits = first & 0x70;
        if reserved_bits != 0 {
            let reason = match reserved_bits {
                0x40 => "RSV1 set",
                0x20 => "RSV2 set",
                0x10 => "RSV3 set",
                0x60 => "RSV1 set, RSV2 set",
                0x50 => "RSV1 set, RSV3 set",
                0x30 => "RSV2 set, RSV3 set",
                0x70 => "RSV1 set, RSV2 set, RSV3 set",
                _ => unreachable!(),
            };
            self.queue_protocol_error(reason)?;
            return Err(std::io::Error::other(format!("websocket: {reason}")));
        }

        self.read_frame_masked = second & 0x80 != 0;
        if self.read_frame_masked == self.is_client {
            self.queue_protocol_error("bad MASK")?;
            return Err(std::io::Error::other("websocket: bad MASK"));
        }

        self.read_frame_opcode = OpCode::from(first & 0x0f);
        if let OpCode::Unknown(code) = self.read_frame_opcode {
            let reason = match code {
                3 => "bad opcode 3",
                4 => "bad opcode 4",
                5 => "bad opcode 5",
                6 => "bad opcode 6",
                7 => "bad opcode 7",
                11 => "bad opcode 11",
                12 => "bad opcode 12",
                13 => "bad opcode 13",
                14 => "bad opcode 14",
                15 => "bad opcode 15",
                _ => unreachable!(),
            };
            self.queue_protocol_error(reason)?;
            return Err(std::io::Error::other(format!("websocket: {reason}")));
        }

        let is_control = matches!(
            self.read_frame_opcode,
            OpCode::Close | OpCode::Ping | OpCode::Pong
        );
        if is_control && !read_frame_final {
            self.queue_protocol_error("FIN not set on control")?;
            return Err(std::io::Error::other("websocket: FIN not set on control"));
        }

        let length = second & 0x7f;
        if is_control && length > 125 {
            self.queue_protocol_error("len > 125 for control")?;
            return Err(std::io::Error::other("websocket: len > 125 for control"));
        }

        match self.read_frame_opcode {
            OpCode::Continue => {
                if !self.read_message_fragmented {
                    self.queue_protocol_error("continuation after FIN")?;
                    return Err(std::io::Error::other(
                        "websocket: continuation after FIN",
                    ));
                }
                if read_frame_final {
                    self.read_message_fragmented = false;
                }
            }
            OpCode::Text | OpCode::Binary => {
                if self.read_message_fragmented {
                    self.queue_protocol_error("data before FIN")?;
                    return Err(std::io::Error::other("websocket: data before FIN"));
                }
                self.read_message_fragmented = !read_frame_final;
            }
            _ if !read_frame_final => {
                return Err(std::io::Error::other(format!(
                    "cannot handle non-final frames of type {:?}",
                    self.read_frame_opcode
                )));
            }
            _ => {}
        }

        if length == 126 {
            self.read_state = ReadState::ReadLength {
                length_bytes_len: 2,
            };
            self.step_read_length(cx, buf, 2)
        } else if length == 127 {
            self.read_state = ReadState::ReadLength {
                length_bytes_len: 8,
            };
            self.step_read_length(cx, buf, 8)
        } else {
            self.read_frame_length = length as u64;
            if self.read_frame_masked {
                self.read_state = ReadState::ReadMask;
                self.step_read_mask(cx, buf)
            } else {
                self.step_check_content(cx, buf)
            }
        }
    }

    fn step_read_length(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        length_bytes_len: usize,
    ) -> std::io::Result<()> {
        let unprocessed_len =
            self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < length_bytes_len {
            return Ok(());
        }

        let length_bytes = &self.unprocessed_buf[self.unprocessed_start_offset
            ..self.unprocessed_start_offset + length_bytes_len];
        self.unprocessed_start_offset += length_bytes_len;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        let mut length = 0u64;
        for b in length_bytes {
            length = (length << 8) | (*b as u64);
        }
        self.read_frame_length = length;

        if self.read_frame_length > 0x7fffffffffffffffu64 {
            if !self.is_client {
                self.read_state = ReadState::Init;
                self.close_data[..2].copy_from_slice(&1000u16.to_be_bytes());
                self.close_data_size = 2;
                self.close_received = true;
                return Ok(());
            }
            return Err(std::io::Error::other(format!(
                "Invalid frame length ({})",
                self.read_frame_length
            )));
        }

        if self.read_frame_masked {
            self.read_state = ReadState::ReadMask;
            self.step_read_mask(cx, buf)
        } else {
            self.step_check_content(cx, buf)
        }
    }

    fn step_read_mask(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len =
            self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < 4 {
            return Ok(());
        }

        let mask_bytes = &self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + 4];
        self.read_frame_mask.copy_from_slice(mask_bytes);

        self.unprocessed_start_offset += 4;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.step_check_content(cx, buf)
    }

    fn step_check_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        match self.read_frame_opcode {
            OpCode::Text | OpCode::Binary | OpCode::Continue => {
                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.step_init(cx, buf)
                } else {
                    self.read_state = ReadState::ReadBinaryContent;
                    self.step_read_binary_content(cx, buf)
                }
            }
            OpCode::Ping => {
                self.ping_data_size = 0;

                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.pending_write_pong = true;
                    self.step_init(cx, buf)
                } else {
                    if self.read_frame_length as usize > self.ping_data.len() {
                        return Err(std::io::Error::other(format!(
                            "cannot handle ping data length ({})",
                            self.read_frame_length
                        )));
                    }

                    self.pending_write_pong = false;
                    self.read_state = ReadState::ReadPingContent;
                    self.step_read_ping_content(cx, buf)
                }
            }
            OpCode::Pong => {
                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.step_init(cx, buf)
                } else {
                    self.read_state = ReadState::SkipContent;
                    self.step_skip_content(cx, buf)
                }
            }
            OpCode::Close => {
                if self.read_frame_length > self.close_data.len() as u64 {
                    return Err(std::io::Error::other(format!(
                        "invalid close frame length ({})",
                        self.read_frame_length
                    )));
                }
                self.close_data_size = 0;
                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.close_received = true;
                    Ok(())
                } else {
                    self.read_state = ReadState::ReadCloseContent;
                    self.step_read_close_content()
                }
            }
            _ => {
                warn!("Ignoring unknown frame type: {:?}", self.read_frame_opcode);
                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.step_init(cx, buf)
                } else {
                    self.read_state = ReadState::SkipContent;
                    self.step_skip_content(cx, buf)
                }
            }
        }
    }

    fn step_skip_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        if self.read_frame_length > 0 {
            let unprocessed_len =
                self.unprocessed_end_offset - self.unprocessed_start_offset;
            let skip_amount =
                std::cmp::min(unprocessed_len as u64, self.read_frame_length);
            self.unprocessed_start_offset += skip_amount as usize;
            if self.unprocessed_start_offset == self.unprocessed_end_offset {
                self.unprocessed_start_offset = 0;
                self.unprocessed_end_offset = 0;
            }
            self.read_frame_length -= skip_amount;
            if self.read_frame_length > 0 {
                return Ok(());
            }
        }

        self.read_state = ReadState::Init;
        self.step_init(cx, buf)
    }

    fn step_read_ping_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len =
            self.unprocessed_end_offset - self.unprocessed_start_offset;
        let read_amount =
            std::cmp::min(unprocessed_len, self.read_frame_length as usize);
        if read_amount == 0 {
            return Ok(());
        }

        let content_bytes = &mut self.unprocessed_buf[self.unprocessed_start_offset
            ..self.unprocessed_start_offset + read_amount];
        if self.read_frame_masked {
            let iter = content_bytes.iter_mut().zip(
                self.read_frame_mask
                    .iter()
                    .cycle()
                    .skip(self.read_frame_mask_offset),
            );
            for (byte, &key) in iter {
                *byte ^= key
            }
            self.read_frame_mask_offset =
                (self.read_frame_mask_offset + read_amount) % 4;
        }

        self.ping_data[self.ping_data_size..self.ping_data_size + read_amount]
            .copy_from_slice(content_bytes);
        self.ping_data_size += read_amount;
        self.unprocessed_start_offset += read_amount;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }
        self.read_frame_length -= read_amount as u64;

        if self.read_frame_length == 0 {
            self.read_frame_mask_offset = 0;
            self.read_state = ReadState::Init;
            self.pending_write_pong = true;
            return self.step_init(cx, buf);
        }

        Ok(())
    }

    fn step_read_close_content(&mut self) -> std::io::Result<()> {
        let unprocessed_len =
            self.unprocessed_end_offset - self.unprocessed_start_offset;
        let read_amount =
            std::cmp::min(unprocessed_len, self.read_frame_length as usize);
        if read_amount == 0 {
            return Ok(());
        }

        let content_bytes = &mut self.unprocessed_buf[self.unprocessed_start_offset
            ..self.unprocessed_start_offset + read_amount];
        if self.read_frame_masked {
            let iter = content_bytes.iter_mut().zip(
                self.read_frame_mask
                    .iter()
                    .cycle()
                    .skip(self.read_frame_mask_offset),
            );
            for (byte, &key) in iter {
                *byte ^= key;
            }
            self.read_frame_mask_offset =
                (self.read_frame_mask_offset + read_amount) % 4;
        }

        self.close_data[self.close_data_size..self.close_data_size + read_amount]
            .copy_from_slice(content_bytes);
        self.close_data_size += read_amount;
        self.unprocessed_start_offset += read_amount;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }
        self.read_frame_length -= read_amount as u64;

        if self.read_frame_length == 0 {
            self.read_frame_mask_offset = 0;
            self.read_state = ReadState::Init;
            self.validate_close_payload()?;
            self.close_received = true;
        }

        Ok(())
    }

    fn validate_close_payload(&mut self) -> std::io::Result<()> {
        if self.close_data_size == 1 {
            if self.is_client {
                return Err(std::io::Error::other(
                    "invalid close frame payload length (1)",
                ));
            }
            return Ok(());
        }

        debug_assert!(self.close_data_size >= 2);
        let code = u16::from_be_bytes([self.close_data[0], self.close_data[1]]);
        let valid_code = matches!(code, 1000..=1003 | 1007..=1013)
            || (3000..=4999).contains(&code);
        if !valid_code {
            let reason = format!("bad close code {code}");
            self.queue_protocol_error(reason.clone())?;
            return Err(std::io::Error::other(format!("websocket: {reason}")));
        }

        if std::str::from_utf8(&self.close_data[2..self.close_data_size]).is_err() {
            let reason = "invalid utf8 payload in close frame";
            self.queue_protocol_error(reason)?;
            return Err(std::io::Error::other(format!("websocket: {reason}")));
        }

        Ok(())
    }

    fn step_read_binary_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len =
            self.unprocessed_end_offset - self.unprocessed_start_offset;

        let available_space = buf.remaining();
        if available_space == 0 {
            return Ok(());
        }

        let read_amount = std::cmp::min(
            std::cmp::min(unprocessed_len, self.read_frame_length as usize),
            available_space,
        );

        if read_amount == 0 {
            return Ok(());
        }

        let content_bytes = &mut self.unprocessed_buf[self.unprocessed_start_offset
            ..self.unprocessed_start_offset + read_amount];
        if self.read_frame_masked {
            let iter = content_bytes.iter_mut().zip(
                self.read_frame_mask
                    .iter()
                    .cycle()
                    .skip(self.read_frame_mask_offset),
            );
            for (byte, &key) in iter {
                *byte ^= key
            }
            self.read_frame_mask_offset =
                (self.read_frame_mask_offset + read_amount) % 4;
        }

        buf.put_slice(content_bytes);

        self.unprocessed_start_offset += read_amount;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.read_frame_length -= read_amount as u64;
        if self.read_frame_length == 0 {
            self.read_frame_mask_offset = 0;
            self.read_state = ReadState::Init;
            return self.step_init(cx, buf);
        }

        Ok(())
    }

    fn pack_write_ping_frame(&mut self) -> bool {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;
        if available_space < 6 {
            return false;
        }

        let written = pack_frame(
            0x09,
            self.is_client,
            &[],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        true
    }

    fn pack_write_empty_frame(&mut self) -> bool {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;
        if available_space < 6 {
            return false;
        }

        let written = pack_frame(
            0x02,
            self.is_client,
            &[],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        true
    }

    fn pack_write_pong_frame(&mut self) -> bool {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;

        if available_space < self.ping_data_size + 14 {
            return false;
        }

        let written = pack_frame(
            0x0a,
            self.is_client,
            &self.ping_data[0..self.ping_data_size],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        true
    }

    fn flush_pending_pong(&mut self, cx: &mut Context<'_>) -> std::io::Result<bool> {
        if !self.pending_write_pong {
            return Ok(true);
        }
        if !self.pack_write_pong_frame() {
            self.do_write_frame(cx)?;
            if self.write_frame_end_offset > 0 || !self.pack_write_pong_frame() {
                return Ok(false);
            }
        }
        self.pending_write_pong = false;
        self.do_write_frame(cx)?;
        Ok(self.write_frame_end_offset == 0)
    }

    fn flush_heartbeat(&mut self, cx: &mut Context<'_>) -> std::io::Result<bool> {
        if let Some(interval) = self.heartbeat_interval.as_mut()
            && Pin::new(interval).poll_tick(cx).is_ready()
        {
            self.heartbeat_ping_pending = true;
        }
        if !self.heartbeat_ping_pending {
            return Ok(true);
        }
        if !self.pack_write_ping_frame() {
            self.do_write_frame(cx)?;
            if self.write_frame_end_offset > 0 || !self.pack_write_ping_frame() {
                return Ok(false);
            }
        }
        self.heartbeat_ping_pending = false;
        self.do_write_frame(cx)?;
        Ok(self.write_frame_end_offset == 0)
    }

    fn pack_write_close_frame(&mut self) -> bool {
        let normal_close = 1000u16.to_be_bytes();
        let payload: &[u8] = if self.protocol_error_pending
            || (self.is_client && self.close_received)
        {
            &self.close_data[..self.close_data_size]
        } else if self.close_received {
            // Gorilla's default close handler mirrors the received close code
            // without the reason text. A missing/one-byte status is answered
            // with an empty close payload (CloseNoStatusReceived).
            if self.close_data_size >= 2 {
                &self.close_data[..2]
            } else {
                &[]
            }
        } else {
            &normal_close
        };
        let available_space = self.write_frame.len() - self.write_frame_end_offset;
        if available_space < payload.len() + 14 {
            return false;
        }

        let written = pack_frame(
            0x08,
            self.is_client,
            payload,
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;
        true
    }

    fn pack_write_frame(&mut self, input: &[u8]) -> usize {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;

        if available_space < 40 {
            return 0;
        }

        let pack_amount = std::cmp::min(input.len(), available_space - 14);

        let written = pack_frame(
            0x02,
            self.is_client,
            &input[0..pack_amount],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        pack_amount
    }

    fn do_write_frame(&mut self, cx: &mut Context<'_>) -> std::io::Result<()> {
        loop {
            let remaining_data = &self.write_frame
                [self.write_frame_start_offset..self.write_frame_end_offset];

            match Pin::new(&mut self.stream).poll_write(cx, remaining_data) {
                Poll::Ready(Ok(written)) => {
                    if written == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "write frame eof",
                        ));
                    }
                    self.write_frame_start_offset += written;
                    if self.write_frame_start_offset == self.write_frame_end_offset {
                        self.write_frame_start_offset = 0;
                        self.write_frame_end_offset = 0;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
                Poll::Pending => {
                    break;
                }
            }
        }

        Ok(())
    }

    fn queue_protocol_error(
        &mut self,
        reason: impl Into<String>,
    ) -> std::io::Result<()> {
        let reason = reason.into();
        let reason_bytes = reason.as_bytes();
        debug_assert!(reason_bytes.len() <= self.close_data.len() - 2);
        self.close_data[..2].copy_from_slice(&1002u16.to_be_bytes());
        self.close_data[2..2 + reason_bytes.len()].copy_from_slice(reason_bytes);
        self.close_data_size = 2 + reason_bytes.len();
        self.close_received = true;
        self.protocol_error_pending = true;
        self.protocol_error_reason = reason;
        if !self.pack_write_close_frame() {
            return Err(std::io::Error::other(
                "failed to queue websocket protocol error close frame",
            ));
        }
        self.close_sent = true;
        Ok(())
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

impl AsyncRead for WebsocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.protocol_error_pending {
            this.do_write_frame(cx)?;
            if this.write_frame_end_offset > 0 {
                return Poll::Pending;
            }
            this.protocol_error_pending = false;
            return Poll::Ready(Err(std::io::Error::other(format!(
                "websocket: {}",
                this.protocol_error_reason
            ))));
        }

        if !this.flush_pending_pong(cx)? {
            return Poll::Pending;
        }
        if !this.flush_heartbeat(cx)? {
            return Poll::Pending;
        }

        if this.close_received {
            if !this.close_sent {
                if !this.pack_write_close_frame() {
                    return Poll::Pending;
                }
                this.close_sent = true;
            }
            this.do_write_frame(cx)?;
            if this.write_frame_end_offset > 0 {
                return Poll::Pending;
            }
            return Poll::Ready(Ok(()));
        }

        if this.unprocessed_end_offset > 0
            && this.read_state == ReadState::ReadBinaryContent
        {
            let read_result = this.step_read_binary_content(cx, buf);
            if read_result.is_err() {
                return Poll::Ready(read_result);
            }
            assert!(!buf.filled().is_empty());
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.unprocessed_start_offset * 2 > this.unprocessed_buf.len() {
                this.reset_unprocessed_buf_offset();
            }

            if !this.pending_initial_data {
                assert!(this.unprocessed_start_offset < this.unprocessed_buf.len());

                let mut read_buf = ReadBuf::new(
                    &mut this.unprocessed_buf[this.unprocessed_end_offset..],
                );

                match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                    Poll::Ready(res) => {
                        res?;
                        let len = read_buf.filled().len();
                        if len == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        this.unprocessed_end_offset += len;
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            } else {
                this.pending_initial_data = false;
            }

            let read_result = match this.read_state {
                ReadState::Init => this.step_init(cx, buf),
                ReadState::ReadLength { length_bytes_len } => {
                    this.step_read_length(cx, buf, length_bytes_len)
                }
                ReadState::ReadMask => this.step_read_mask(cx, buf),
                ReadState::SkipContent => this.step_skip_content(cx, buf),
                ReadState::ReadBinaryContent => {
                    this.step_read_binary_content(cx, buf)
                }
                ReadState::ReadPingContent => this.step_read_ping_content(cx, buf),
                ReadState::ReadCloseContent => this.step_read_close_content(),
            };

            if read_result.is_err() {
                if this.protocol_error_pending {
                    this.do_write_frame(cx)?;
                    if this.write_frame_end_offset > 0 {
                        return Poll::Pending;
                    }
                    this.protocol_error_pending = false;
                }
                return Poll::Ready(read_result);
            }

            if !this.flush_pending_pong(cx)? {
                return Poll::Pending;
            }
            if !buf.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            if this.close_received {
                if !this.close_sent {
                    if !this.pack_write_close_frame() {
                        return Poll::Pending;
                    }
                    this.close_sent = true;
                }
                this.do_write_frame(cx)?;
                if this.write_frame_end_offset > 0 {
                    return Poll::Pending;
                }
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for WebsocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if !this.flush_heartbeat(cx)? {
            return Poll::Pending;
        }

        if this.pending_write_pong {
            if this.pack_write_pong_frame() {
                this.pending_write_pong = false;
            } else {
                if let Err(e) = this.do_write_frame(cx) {
                    return Poll::Ready(Err(e));
                }
                if this.pack_write_pong_frame() {
                    this.pending_write_pong = false;
                } else {
                    return Poll::Pending;
                }
            }
        }

        let mut written = 0;
        loop {
            let input = &buf[written..];
            if input.is_empty() {
                break;
            }

            written += this.pack_write_frame(input);

            if let Err(e) = this.do_write_frame(cx) {
                return Poll::Ready(Err(e));
            }

            if this.write_frame_end_offset > 0 {
                break;
            }
        }

        if written > 0 {
            Poll::Ready(Ok(written))
        } else {
            Poll::Pending
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.write_frame_end_offset == 0 {
            return Pin::new(&mut this.stream).poll_flush(cx);
        }

        while this.write_frame_end_offset > 0 {
            match this.do_write_frame(cx) {
                Ok(()) => {
                    if this.write_frame_end_offset > 0 {
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
        let this = self.get_mut();

        while this.write_frame_end_offset > 0 {
            this.do_write_frame(cx)?;
            if this.write_frame_end_offset > 0 {
                return Poll::Pending;
            }
        }

        if !this.close_sent {
            if !this.pack_write_close_frame() {
                return Poll::Pending;
            }
            this.close_sent = true;
            this.do_write_frame(cx)?;
            if this.write_frame_end_offset > 0 {
                return Poll::Pending;
            }
        }

        ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for WebsocketStream {
    fn supports_ping(&self) -> bool {
        self.ping_type != WebsocketPingType::Disabled
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        let this = self.get_mut();

        if this.pending_write_pong {
            if this.pack_write_pong_frame() {
                this.pending_write_pong = false;
                return Poll::Ready(Ok(true));
            } else {
                return Poll::Ready(Ok(false));
            }
        }

        if this.write_frame_end_offset > 0 {
            return Poll::Ready(Ok(false));
        }

        let written = match this.ping_type {
            WebsocketPingType::PingFrame => this.pack_write_ping_frame(),
            WebsocketPingType::EmptyFrame => this.pack_write_empty_frame(),
            _ => {
                panic!("Unexpected ping type: {:?}", this.ping_type);
            }
        };

        assert!(written);

        Poll::Ready(Ok(true))
    }
}

impl AsyncStream for WebsocketStream {}

#[inline]
fn pack_frame(opcode: u8, use_mask: bool, input: &[u8], output: &mut [u8]) -> usize {
    let input_len = input.len();

    output[0] = opcode | 0x80;

    let mut offset = if input_len < 126 {
        output[1] = input_len as u8;
        2
    } else if input_len <= 65535 {
        output[1] = 0x7e;
        let size_bytes = (input_len as u16).to_be_bytes();
        output[2..4].copy_from_slice(&size_bytes);
        4
    } else {
        output[1] = 0x7f;
        let size_bytes = (input_len as u64).to_be_bytes();
        output[2..10].copy_from_slice(&size_bytes);
        10
    };

    let mask = if use_mask {
        output[1] |= 0x80;

        let mut mask_bytes = [0u8; 4];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut mask_bytes);

        output[offset..offset + 4].copy_from_slice(&mask_bytes);
        offset += 4;

        Some(mask_bytes)
    } else {
        None
    };

    if input_len > 0 {
        output[offset..offset + input_len].copy_from_slice(input);
        if let Some(mask_bytes) = mask {
            let iter = output[offset..offset + input_len]
                .iter_mut()
                .zip(mask_bytes.iter().cycle());
            for (byte, &key) in iter {
                *byte ^= key
            }
        }
    }

    offset + input_len
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    struct TestStream(tokio::io::DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
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

    fn websocket_over(transport: tokio::io::DuplexStream) -> WebsocketStream {
        WebsocketStream::new(Box::new(TestStream(transport)), false, &[])
    }

    fn masked_frame(first: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [1u8, 2, 3, 4];
        let mut frame = Vec::with_capacity(6 + payload.len());
        frame.extend_from_slice(&[first, 0x80 | payload.len() as u8]);
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ mask[i % 4]),
        );
        frame
    }

    async fn assert_protocol_close(
        peer: &mut tokio::io::DuplexStream,
        websocket: &mut WebsocketStream,
        reason: &str,
    ) {
        let mut application_data = [0u8; 8];
        let error = websocket.read(&mut application_data).await.unwrap_err();
        assert_eq!(error.to_string(), format!("websocket: {reason}"));

        let mut response = vec![0u8; 4 + reason.len()];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], 0x88);
        assert_eq!(response[1] as usize, reason.len() + 2);
        assert_eq!(&response[2..4], &1002u16.to_be_bytes());
        assert_eq!(&response[4..], reason.as_bytes());
    }

    #[tokio::test]
    async fn server_sends_configured_heartbeat_ping_like_xray() {
        let (mut peer, transport) = tokio::io::duplex(64);
        let mut websocket = WebsocketStream::new_with_heartbeat(
            Box::new(TestStream(transport)),
            false,
            &[],
            1,
        );

        let reader = tokio::spawn(async move {
            let mut application_data = [0u8; 1];
            websocket.read(&mut application_data).await
        });

        let mut ping = [0u8; 2];
        tokio::time::timeout(
            Duration::from_millis(1500),
            peer.read_exact(&mut ping),
        )
        .await
        .expect("heartbeat ping should arrive within Xray's one-second period")
        .unwrap();
        assert_eq!(ping, [0x89, 0x00]);

        reader.abort();
    }

    #[tokio::test]
    async fn server_rejects_unmasked_client_frame_like_xray() {
        let (mut peer, transport) = tokio::io::duplex(64);
        let mut websocket = websocket_over(transport);
        peer.write_all(&[0x82, 0x04, b'p', b'i', b'n', b'g'])
            .await
            .unwrap();

        let mut application_data = [0u8; 4];
        let error = websocket.read(&mut application_data).await.unwrap_err();
        assert_eq!(error.to_string(), "websocket: bad MASK");

        let mut response = [0u8; 12];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(
            response,
            [
                0x88, 0x0a, 0x03, 0xea, b'b', b'a', b'd', b' ', b'M', b'A', b'S',
                b'K'
            ]
        );
    }

    #[tokio::test]
    async fn server_rejects_reserved_bits_like_xray() {
        for (reserved_bits, reason) in [
            (0x40, "RSV1 set"),
            (0x20, "RSV2 set"),
            (0x10, "RSV3 set"),
            (0x60, "RSV1 set, RSV2 set"),
            (0x70, "RSV1 set, RSV2 set, RSV3 set"),
        ] {
            let (mut peer, transport) = tokio::io::duplex(128);
            let mut websocket = websocket_over(transport);
            let mask = [1u8, 2, 3, 4];
            let payload = [
                b'p' ^ mask[0],
                b'i' ^ mask[1],
                b'n' ^ mask[2],
                b'g' ^ mask[3],
            ];
            peer.write_all(&[
                0x82 | reserved_bits,
                0x84,
                mask[0],
                mask[1],
                mask[2],
                mask[3],
                payload[0],
                payload[1],
                payload[2],
                payload[3],
            ])
            .await
            .unwrap();

            let mut application_data = [0u8; 4];
            let error = websocket.read(&mut application_data).await.unwrap_err();
            assert_eq!(error.to_string(), format!("websocket: {reason}"));

            let mut response = vec![0u8; 4 + reason.len()];
            peer.read_exact(&mut response).await.unwrap();
            assert_eq!(response[0], 0x88);
            assert_eq!(response[1] as usize, reason.len() + 2);
            assert_eq!(&response[2..4], &1002u16.to_be_bytes());
            assert_eq!(&response[4..], reason.as_bytes());
        }
    }

    #[tokio::test]
    async fn server_rejects_reserved_opcodes_like_xray() {
        for opcode in [3u8, 4, 5, 6, 7, 11, 12, 13, 14, 15] {
            let (mut peer, transport) = tokio::io::duplex(128);
            let mut websocket = websocket_over(transport);
            peer.write_all(&masked_frame(0x80 | opcode, b"x"))
                .await
                .unwrap();

            let reason = format!("bad opcode {opcode}");
            assert_protocol_close(&mut peer, &mut websocket, &reason).await;
        }
    }

    #[tokio::test]
    async fn server_immediately_pongs_full_control_payload_like_xray() {
        let (mut peer, transport) = tokio::io::duplex(512);
        let mut websocket = websocket_over(transport);
        let payload: Vec<u8> = (0..125).collect();
        peer.write_all(&masked_frame(0x89, &payload)).await.unwrap();

        let mut application_data = [0u8; 1];
        let mut application_read = Box::pin(websocket.read(&mut application_data));
        let mut pong = vec![0u8; 2 + payload.len()];
        tokio::select! {
            result = peer.read_exact(&mut pong) => { result.unwrap(); },
            result = &mut application_read => panic!("ping unexpectedly completed application read: {result:?}"),
        }
        drop(application_read);

        assert_eq!(pong[0], 0x8a);
        assert_eq!(pong[1], 125);
        assert_eq!(&pong[2..], payload.as_slice());
    }

    #[tokio::test]
    async fn server_ignores_pong_payload_like_xray() {
        let (mut peer, transport) = tokio::io::duplex(512);
        let mut websocket = websocket_over(transport);
        let pong_payload: Vec<u8> = (0..125).collect();
        peer.write_all(&masked_frame(0x8a, &pong_payload))
            .await
            .unwrap();
        peer.write_all(&masked_frame(0x82, b"ping")).await.unwrap();

        let mut application_data = [0u8; 4];
        websocket.read_exact(&mut application_data).await.unwrap();
        assert_eq!(&application_data, b"ping");
    }

    #[tokio::test]
    async fn server_normally_closes_on_invalid_63_bit_length_like_xray() {
        let (mut peer, transport) = tokio::io::duplex(64);
        let mut websocket = websocket_over(transport);
        peer.write_all(&[0x82, 0xff]).await.unwrap();
        peer.write_all(&(1u64 << 63).to_be_bytes()).await.unwrap();

        let mut application_data = [0u8; 1];
        assert_eq!(websocket.read(&mut application_data).await.unwrap(), 0);

        let mut response = [0u8; 4];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x88, 0x02, 0x03, 0xe8]);
    }

    #[tokio::test]
    async fn server_rejects_invalid_control_frames_like_xray() {
        for opcode in [0x08u8, 0x09, 0x0a] {
            let (mut peer, transport) = tokio::io::duplex(128);
            let mut websocket = websocket_over(transport);
            peer.write_all(&masked_frame(opcode, b"x")).await.unwrap();
            assert_protocol_close(
                &mut peer,
                &mut websocket,
                "FIN not set on control",
            )
            .await;

            let (mut peer, transport) = tokio::io::duplex(128);
            let mut websocket = websocket_over(transport);
            peer.write_all(&[0x80 | opcode, 0xfe]).await.unwrap();
            assert_protocol_close(
                &mut peer,
                &mut websocket,
                "len > 125 for control",
            )
            .await;
        }
    }

    #[tokio::test]
    async fn server_rejects_invalid_close_codes_like_xray() {
        for code in [999u16, 1004, 1005, 1006, 1014, 1015, 1016, 2999] {
            let (mut peer, transport) = tokio::io::duplex(128);
            let mut websocket = websocket_over(transport);
            peer.write_all(&masked_frame(0x88, &code.to_be_bytes()))
                .await
                .unwrap();

            let reason = format!("bad close code {code}");
            assert_protocol_close(&mut peer, &mut websocket, &reason).await;
        }

        for code in [1000u16, 1003, 1007, 1013, 3000, 4999] {
            let (mut peer, transport) = tokio::io::duplex(128);
            let mut websocket = websocket_over(transport);
            peer.write_all(&masked_frame(0x88, &code.to_be_bytes()))
                .await
                .unwrap();

            let mut application_data = [0u8; 1];
            assert_eq!(websocket.read(&mut application_data).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn server_replies_without_status_to_short_close_like_xray() {
        for payload in [&[][..], &[0x01][..]] {
            let (mut peer, transport) = tokio::io::duplex(64);
            let mut websocket = websocket_over(transport);
            peer.write_all(&masked_frame(0x88, payload)).await.unwrap();

            let mut application_data = [0u8; 1];
            assert_eq!(websocket.read(&mut application_data).await.unwrap(), 0);

            let mut response = [0u8; 2];
            peer.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [0x88, 0x00]);
        }
    }

    #[tokio::test]
    async fn server_rejects_invalid_close_reason_utf8_like_xray() {
        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        let mut payload = 1000u16.to_be_bytes().to_vec();
        payload.push(0xff);
        peer.write_all(&masked_frame(0x88, &payload)).await.unwrap();

        assert_protocol_close(
            &mut peer,
            &mut websocket,
            "invalid utf8 payload in close frame",
        )
        .await;
    }

    #[tokio::test]
    async fn server_rejects_invalid_fragmentation_sequence_like_xray() {
        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        peer.write_all(&masked_frame(0x80, b"x")).await.unwrap();
        assert_protocol_close(&mut peer, &mut websocket, "continuation after FIN")
            .await;

        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        let mut frames = masked_frame(0x02, b"");
        frames.extend_from_slice(&masked_frame(0x82, b"x"));
        peer.write_all(&frames).await.unwrap();
        assert_protocol_close(&mut peer, &mut websocket, "data before FIN").await;
    }

    #[tokio::test]
    async fn server_accepts_binary_fragmentation_sequence() {
        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        let mut frames = masked_frame(0x02, b"pi");
        frames.extend_from_slice(&masked_frame(0x80, b"ng"));
        peer.write_all(&frames).await.unwrap();

        let mut application_data = [0u8; 4];
        websocket.read_exact(&mut application_data).await.unwrap();
        assert_eq!(&application_data, b"ping");
    }

    #[tokio::test]
    async fn server_accepts_text_frames_as_xray_byte_stream() {
        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        let mut frames = masked_frame(0x01, b"pi");
        frames.extend_from_slice(&masked_frame(0x80, b"ng"));
        peer.write_all(&frames).await.unwrap();

        let mut application_data = [0u8; 4];
        websocket.read_exact(&mut application_data).await.unwrap();
        assert_eq!(&application_data, b"ping");
    }

    #[tokio::test]
    async fn shutdown_sends_close_frame_before_transport_eof() {
        let (mut peer, transport) = tokio::io::duplex(64);
        let mut websocket = websocket_over(transport);

        websocket.shutdown().await.unwrap();

        let mut wire = Vec::new();
        peer.read_to_end(&mut wire).await.unwrap();
        assert_eq!(wire, [0x88, 0x02, 0x03, 0xe8]);
    }

    #[tokio::test]
    async fn received_close_echoes_xray_code_without_reason_before_read_eof() {
        let (mut peer, transport) = tokio::io::duplex(64);
        let mut websocket = websocket_over(transport);
        let close_payload = [0x03, 0xe9, b'b', b'y', b'e'];
        let mut frame = [0u8; 32];
        let frame_len = pack_frame(0x08, true, &close_payload, &mut frame);
        peer.write_all(&frame[..frame_len]).await.unwrap();

        let mut application_data = [0u8; 1];
        assert_eq!(websocket.read(&mut application_data).await.unwrap(), 0);

        let mut response = [0u8; 4];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x88, 0x02, 0x03, 0xe9]);

        websocket.shutdown().await.unwrap();
        let mut extra = [0u8; 1];
        assert_eq!(peer.read(&mut extra).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn repeated_shutdown_does_not_send_duplicate_close_frames() {
        let (mut peer, transport) = tokio::io::duplex(64);
        let mut websocket = websocket_over(transport);

        websocket.shutdown().await.unwrap();
        websocket.shutdown().await.unwrap();

        let mut wire = Vec::new();
        peer.read_to_end(&mut wire).await.unwrap();
        assert_eq!(wire, [0x88, 0x02, 0x03, 0xe8]);
    }
}
