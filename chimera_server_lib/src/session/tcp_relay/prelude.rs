use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncStream, RawTcpRelayState};

use super::{MAX_STEPS_PER_POLL, PreludeOutcome};

pub(super) async fn copy_until_raw_ready<A, B>(
    left: &mut A,
    right: &mut B,
    buffer_size: usize,
) -> io::Result<PreludeOutcome>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    if raw_relay_ready(left, right) {
        return Ok(PreludeOutcome::RawReady {
            left_to_right: 0,
            right_to_left: 0,
        });
    }

    let mut left_to_right = CopyDirection::new(buffer_size);
    let mut right_to_left = CopyDirection::new(buffer_size);

    std::future::poll_fn(|cx| {
        for _ in 0..MAX_STEPS_PER_POLL {
            if left_to_right.is_idle()
                && right_to_left.is_idle()
                && raw_relay_ready(left, right)
            {
                return Poll::Ready(Ok(PreludeOutcome::RawReady {
                    left_to_right: left_to_right.transferred,
                    right_to_left: right_to_left.transferred,
                }));
            }

            let left_step =
                poll_copy_direction(cx, left, right, &mut left_to_right)?;
            let right_step =
                poll_copy_direction(cx, right, left, &mut right_to_left)?;

            if left_to_right.is_complete() && right_to_left.is_complete() {
                return Poll::Ready(Ok(PreludeOutcome::Complete {
                    left_to_right: left_to_right.transferred,
                    right_to_left: right_to_left.transferred,
                }));
            }

            if left_to_right.is_idle()
                && right_to_left.is_idle()
                && raw_relay_ready(left, right)
            {
                return Poll::Ready(Ok(PreludeOutcome::RawReady {
                    left_to_right: left_to_right.transferred,
                    right_to_left: right_to_left.transferred,
                }));
            }

            if !left_step.made_progress && !right_step.made_progress {
                return Poll::Pending;
            }
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}

fn raw_relay_ready<A, B>(left: &A, right: &B) -> bool
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    left.raw_tcp_relay_state() == RawTcpRelayState::Ready
        && right.raw_tcp_relay_state() == RawTcpRelayState::Ready
}

#[derive(Debug)]
pub(super) struct CopyDirection {
    buffer: Box<[u8]>,
    position: usize,
    filled: usize,
    read_eof: bool,
    pub(super) flush_pending: bool,
    shutdown_done: bool,
    transferred: u64,
}

impl CopyDirection {
    pub(super) fn new(buffer_size: usize) -> Self {
        Self {
            buffer: vec![0_u8; buffer_size].into_boxed_slice(),
            position: 0,
            filled: 0,
            read_eof: false,
            flush_pending: false,
            shutdown_done: false,
            transferred: 0,
        }
    }

    pub(super) fn is_idle(&self) -> bool {
        self.position == self.filled && !self.flush_pending
    }

    fn is_complete(&self) -> bool {
        self.read_eof && self.shutdown_done && self.is_idle()
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct StepResult {
    pub(super) made_progress: bool,
}

pub(super) fn poll_copy_direction<R, W>(
    cx: &mut Context<'_>,
    reader: &mut R,
    writer: &mut W,
    state: &mut CopyDirection,
) -> io::Result<StepResult>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut made_progress = false;

    while state.position < state.filled {
        match Pin::new(&mut *writer)
            .poll_write(cx, &state.buffer[state.position..state.filled])
        {
            Poll::Ready(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
            Poll::Ready(Ok(written)) => {
                state.position += written;
                state.transferred = state.transferred.saturating_add(written as u64);
                state.flush_pending = true;
                made_progress = true;
            }
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Pending => return Ok(StepResult { made_progress }),
        }
    }

    if state.position == state.filled {
        state.position = 0;
        state.filled = 0;
    }

    if state.flush_pending {
        match Pin::new(&mut *writer).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                state.flush_pending = false;
                made_progress = true;
            }
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Pending => return Ok(StepResult { made_progress }),
        }
    }

    if state.read_eof {
        if !state.shutdown_done {
            match Pin::new(writer).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    state.shutdown_done = true;
                    made_progress = true;
                }
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Pending => return Ok(StepResult { made_progress }),
            }
        }
        return Ok(StepResult { made_progress });
    }

    let mut read_buf = ReadBuf::new(&mut state.buffer);
    match Pin::new(reader).poll_read(cx, &mut read_buf) {
        Poll::Ready(Ok(())) => {
            state.filled = read_buf.filled().len();
            if state.filled == 0 {
                state.read_eof = true;
            }
            Ok(StepResult {
                made_progress: true,
            })
        }
        Poll::Ready(Err(error)) => Err(error),
        Poll::Pending => Ok(StepResult { made_progress }),
    }
}
