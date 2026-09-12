use super::*;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};

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
