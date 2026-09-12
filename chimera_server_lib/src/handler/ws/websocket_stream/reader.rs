use std::task::Context;

use tokio::io::ReadBuf;
use tracing::warn;

use super::{OpCode, WebsocketStream};

#[derive(Debug, PartialEq)]
pub(super) enum ReadState {
    Init,
    ReadLength { length_bytes_len: usize },
    ReadMask,
    ReadBinaryContent,
    ReadPingContent,
    ReadCloseContent,
    SkipContent,
}

impl WebsocketStream {
    pub(super) fn step_init(
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

        let mut header_errors = Vec::new();
        if first & 0x40 != 0 {
            header_errors.push("RSV1 set".to_string());
        }
        if first & 0x20 != 0 {
            header_errors.push("RSV2 set".to_string());
        }
        if first & 0x10 != 0 {
            header_errors.push("RSV3 set".to_string());
        }

        self.read_frame_opcode = OpCode::from(first & 0x0f);
        let length = second & 0x7f;
        match self.read_frame_opcode {
            OpCode::Close | OpCode::Ping | OpCode::Pong => {
                if length > 125 {
                    header_errors.push("len > 125 for control".to_string());
                }
                if !read_frame_final {
                    header_errors.push("FIN not set on control".to_string());
                }
            }
            OpCode::Text | OpCode::Binary => {
                if self.read_message_fragmented {
                    header_errors.push("data before FIN".to_string());
                }
            }
            OpCode::Continue => {
                if !self.read_message_fragmented {
                    header_errors.push("continuation after FIN".to_string());
                }
            }
            OpCode::Unknown(code) => {
                header_errors.push(format!("bad opcode {code}"));
            }
        }

        self.read_frame_masked = second & 0x80 != 0;
        if self.read_frame_masked == self.is_client {
            header_errors.push("bad MASK".to_string());
        }

        if !header_errors.is_empty() {
            let reason = header_errors.join(", ");
            self.queue_protocol_error(&reason)?;
            return Err(std::io::Error::other(format!("websocket: {reason}")));
        }

        match self.read_frame_opcode {
            OpCode::Continue => {
                if read_frame_final {
                    self.read_message_fragmented = false;
                }
            }
            OpCode::Text | OpCode::Binary => {
                self.read_message_fragmented = !read_frame_final;
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

    pub(super) fn step_read_length(
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

    pub(super) fn step_read_mask(
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

    pub(super) fn step_check_content(
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

    pub(super) fn step_skip_content(
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

    pub(super) fn step_read_ping_content(
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

    pub(super) fn step_read_close_content(&mut self) -> std::io::Result<()> {
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

    pub(super) fn validate_close_payload(&mut self) -> std::io::Result<()> {
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

    pub(super) fn step_read_binary_content(
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
}
