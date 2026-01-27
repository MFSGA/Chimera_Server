use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;
use tracing_subscriber::field::debug;

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::util::allocate_vec;

pub struct WebsocketStream {
    stream: Box<dyn AsyncStream>,

    unprocessed_buf: Box<[u8]>,
    unprocessed_start_offset: usize,
    unprocessed_end_offset: usize,

    read_state: ReadState,
    pending_initial_data: bool,

    read_frame_masked: bool,
    read_frame_opcode: OpCode,
    read_frame_length: u64,
    read_frame_mask: [u8; 4],
    read_frame_mask_offset: usize,

    pending_write_pong: bool,

    write_frame: Box<[u8]>,

    write_frame_end_offset: usize,

    is_client: bool,

    write_frame_start_offset: usize,
}

#[derive(Debug, PartialEq)]
enum ReadState {
    Init,
    ReadBinaryContent,
    ReadLength { length_bytes_len: usize },
    ReadMask,
    SkipContent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpCode {
    Continue,
    Text,
    Binary,
    Unknown(u8),
    Close,
}

impl OpCode {
    pub fn from(code: u8) -> Self {
        match code {
            0 => OpCode::Continue,
            1 => OpCode::Text,
            2 => OpCode::Binary,
            8 => OpCode::Close,

            _ => OpCode::Unknown(code),
        }
    }
}

impl WebsocketStream {
    pub fn new(stream: Box<dyn AsyncStream>, is_client: bool, unprocessed_data: &[u8]) -> Self {
        let mut unprocessed_buf = allocate_vec(16384).into_boxed_slice();
        let mut unprocessed_end_offset = 0;
        let write_frame = allocate_vec(32768).into_boxed_slice();

        let pending_initial_data = if !unprocessed_data.is_empty() {
            todo!()
        } else {
            false
        };

        Self {
            stream,
            read_state: ReadState::Init,

            unprocessed_end_offset,
            unprocessed_start_offset: 0,
            unprocessed_buf,

            pending_initial_data,
            read_frame_masked: false,
            read_frame_opcode: OpCode::Unknown(99),
            read_frame_length: 0,
            read_frame_mask: [0u8; 4],
            read_frame_mask_offset: 0,

            pending_write_pong: false,

            write_frame,
            write_frame_end_offset: 0,

            is_client,

            write_frame_start_offset: 0,
        }
    }

    fn step_init(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> std::io::Result<()> {
        debug!("step_init for poll read");
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < 2 {
            debug!("unprocessed_len < 2");
            return Ok(());
        }

        let first = self.unprocessed_buf[self.unprocessed_start_offset];
        let second = self.unprocessed_buf[self.unprocessed_start_offset + 1];
        self.unprocessed_start_offset += 2;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            todo!()
        }

        let read_frame_final = first & 0x80 != 0;

        self.read_frame_masked = second & 0x80 != 0;

        self.read_frame_opcode = OpCode::from(first & 0x0f);

        if !read_frame_final
            && self.read_frame_opcode != OpCode::Binary
            && self.read_frame_opcode != OpCode::Continue
        {
            todo!()
        }

        let length = second & 0x7f;

        if length == 126 {
            self.read_state = ReadState::ReadLength {
                length_bytes_len: 2,
            };
            self.step_read_length(cx, buf, 2)
        } else if length == 127 {
            todo!()
        } else {
            self.read_frame_length = length as u64;
            if self.read_frame_masked {
                self.read_state = ReadState::ReadMask;
                self.step_read_mask(cx, buf)
            } else {
                todo!()
            }
        }
    }

    fn step_read_length(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        length_bytes_len: usize,
    ) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < length_bytes_len {
            debug!("unprocessed_len < length_bytes_len");
            return Ok(());
        }

        let length_bytes = &self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + length_bytes_len];
        self.unprocessed_start_offset += length_bytes_len;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            todo!()
        }

        let mut length = 0u64;
        for b in length_bytes {
            length = (length << 8) | (*b as u64);
        }
        self.read_frame_length = length;

        if self.read_frame_length > 0x7fffffffffffffffu64 {
            debug!("Invalid frame length ({})", self.read_frame_length);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Invalid frame length ({})", self.read_frame_length),
            ));
        }

        if self.read_frame_masked {
            self.read_state = ReadState::ReadMask;
            self.step_read_mask(cx, buf)
        } else {
            todo!()
        }
    }

    fn step_read_mask(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < 4 {
            return Ok(());
        }

        let mask_bytes =
            &self.unprocessed_buf[self.unprocessed_start_offset..self.unprocessed_start_offset + 4];
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
            OpCode::Binary | OpCode::Continue => {
                if self.read_frame_length == 0 {
                    todo!()
                } else {
                    self.read_state = ReadState::ReadBinaryContent;
                    self.step_read_binary_content(cx, buf)
                }
            }
            OpCode::Text => {
                todo!()
            }
            _ => {
                debug!("Unknown opcode {:?}", self.read_frame_opcode);
                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    todo!()
                } else {
                    self.read_state = ReadState::SkipContent;
                    self.step_skip_content(cx, buf)
                }
            }
        }
    }

    fn step_read_binary_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;

        let available_space = buf.remaining();
        if available_space == 0 {
            debug!("step_read_binary_content No space in buffer");
            return Ok(());
        }

        let read_amount = std::cmp::min(
            std::cmp::min(unprocessed_len, self.read_frame_length as usize),
            available_space,
        );

        if read_amount == 0 {
            return Ok(());
        }

        let content_bytes = &mut self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + read_amount];
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
            self.read_frame_mask_offset = (self.read_frame_mask_offset + read_amount) % 4;
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

    fn pack_write_frame(&mut self, input: &[u8]) -> usize {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;

        if available_space < 40 {
            debug!("poll_write pack_write_frame No space in buffer");
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
            let remaining_data =
                &self.write_frame[self.write_frame_start_offset..self.write_frame_end_offset];

            match Pin::new(&mut self.stream).poll_write(cx, remaining_data) {
                Poll::Ready(Ok(written)) => {
                    debug!("poll_write wrote {} bytes", written);
                    if written == 0 {
                        todo!()
                    }
                    self.write_frame_start_offset += written;
                    if self.write_frame_start_offset == self.write_frame_end_offset {
                        self.write_frame_start_offset = 0;
                        self.write_frame_end_offset = 0;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => {
                    todo!()
                }
                Poll::Pending => {
                    todo!()
                }
            }
        }

        Ok(())
    }

    fn step_skip_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        debug!("step_skip_content for poll read");
        if self.read_frame_length > 0 {
            let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
            let skip_amount = std::cmp::min(unprocessed_len as u64, self.read_frame_length);

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
}

impl AsyncPing for WebsocketStream {
    fn supports_ping(&self) -> bool {
        todo!()
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        todo!()
    }
}

impl AsyncWrite for WebsocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if this.pending_write_pong {
            todo!()
        }

        let mut written = 0;
        loop {
            let input = &buf[written..];
            if input.is_empty() {
                break;
            }

            written += this.pack_write_frame(input);

            if let Err(e) = this.do_write_frame(cx) {
                todo!()
            }

            if this.write_frame_end_offset > 0 {
                break;
            }
        }

        if written > 0 {
            debug!("last poll_write wrote {} bytes", written);
            Poll::Ready(Ok(written))
        } else {
            todo!()
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        debug!("poll_flush started");
        let this = self.get_mut();

        if this.write_frame_end_offset == 0 {
            debug!("poll_flush No data to flush");
            return Pin::new(&mut this.stream).poll_flush(cx);
        }

        while this.write_frame_end_offset > 0 {
            match this.do_write_frame(cx) {
                Ok(()) => {
                    if this.write_frame_end_offset > 0 {
                        todo!("poll_flush write_frame_end_offset > 0");
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
            debug!("poll_flush wrote frame");
            ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        }

        debug!("poll_flush done");
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncRead for WebsocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        debug!("poll_read started");
        let this = self.get_mut();

        if this.unprocessed_end_offset > 0 && this.read_state == ReadState::ReadBinaryContent {
            let read_result = this.step_read_binary_content(cx, buf);
            if read_result.is_err() {
                debug!("poll_read Read error");
                return Poll::Ready(read_result);
            }
            assert!(!buf.filled().is_empty());
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.unprocessed_start_offset * 2 > this.unprocessed_buf.len() {
                todo!()
            }

            if !this.pending_initial_data {
                assert!(this.unprocessed_start_offset < this.unprocessed_buf.len());

                let mut read_buf =
                    ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);

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
                todo!()
            }

            let read_result = match this.read_state {
                ReadState::Init => this.step_init(cx, buf),
                ReadState::ReadBinaryContent => this.step_read_binary_content(cx, buf),
                ReadState::ReadLength { length_bytes_len } => {
                    todo!()
                }
                ReadState::ReadMask => {
                    todo!()
                }
                ReadState::SkipContent => this.step_skip_content(cx, buf),
            };

            if read_result.is_err() {
                todo!()
            }

            if !buf.filled().is_empty() {
                debug!("poll read Read some data");
                return Poll::Ready(Ok(()));
            }
        }
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
        todo!()
    };

    let mask: Option<[u8; 4]> = if use_mask { todo!() } else { None };

    if input_len > 0 {
        output[offset..offset + input_len].copy_from_slice(input);
        if let Some(mask_bytes) = mask {
            todo!()
        }
    }
    offset + input_len
}
