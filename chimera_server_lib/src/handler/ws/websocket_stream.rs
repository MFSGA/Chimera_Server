use std::pin::Pin;
use std::task::{Context, Poll};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::util::allocate_vec;
use futures::ready;
use rand::Rng;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Duration, Instant, Interval, MissedTickBehavior, interval_at},
};

mod reader;

use reader::ReadState;

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
mod tests;
