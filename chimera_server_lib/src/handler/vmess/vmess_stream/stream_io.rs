use super::*;
use crate::async_stream::{AsyncPing, AsyncStream};

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

        if let Some(write_len) = this.pending_write_len {
            return match this.drain_accepted_write(cx) {
                Ok(true) => {
                    this.pending_write_len = None;
                    Poll::Ready(Ok(write_len))
                }
                Ok(false) => Poll::Pending,
                Err(error) => {
                    this.pending_write_len = None;
                    Poll::Ready(Err(error))
                }
            };
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let write_count = std::cmp::min(this.write_cache.len(), buf.len());
        this.write_cache[..write_count].copy_from_slice(&buf[..write_count]);
        this.write_cache_size = write_count;
        this.pending_write_len = Some(write_count);

        match this.drain_accepted_write(cx) {
            Ok(true) => {
                this.pending_write_len = None;
                Poll::Ready(Ok(write_count))
            }
            Ok(false) => Poll::Pending,
            Err(error) => {
                this.pending_write_len = None;
                Poll::Ready(Err(error))
            }
        }
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
