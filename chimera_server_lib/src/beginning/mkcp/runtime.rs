use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, mpsc},
};
use tokio_util::sync::PollSender;

use crate::config::MkcpTransportConfig;

use super::{
    MkcpSegment,
    connection::{MkcpConnectionPhase, MkcpConnectionState, MkcpInputOutcome},
};

const DATA_SEGMENT_OVERHEAD: u32 = 18;
const STREAM_CHANNEL_CAPACITY: usize = 32;
const IDLE_UPDATE_INTERVAL: Duration = Duration::from_secs(5);
const TERMINATING_UPDATE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub(crate) struct MkcpConnectionWake {
    notify: Arc<Notify>,
}

impl MkcpConnectionWake {
    pub(crate) async fn notified(&self) {
        self.notify.notified().await;
    }
}

#[derive(Debug)]
pub(crate) struct MkcpByteStream {
    read_receiver: mpsc::Receiver<Vec<u8>>,
    write_sender: PollSender<Vec<u8>>,
    wake: Arc<Notify>,
    read_pending: Vec<u8>,
    read_offset: usize,
    mss: usize,
    write_shutdown: bool,
}

impl AsyncRead for MkcpByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.read_offset < self.read_pending.len() {
                let available = &self.read_pending[self.read_offset..];
                let length = available.len().min(buffer.remaining());
                buffer.put_slice(&available[..length]);
                self.read_offset += length;
                if self.read_offset == self.read_pending.len() {
                    self.read_pending.clear();
                    self.read_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.read_receiver).poll_recv(cx) {
                Poll::Ready(Some(payload)) if payload.is_empty() => continue,
                Poll::Ready(Some(payload)) => {
                    self.read_pending = payload;
                    self.read_offset = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MkcpByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mKCP byte stream write side is closed",
            )));
        }

        match self.write_sender.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let length = buffer.len().min(self.mss);
                self.write_sender
                    .send_item(buffer[..length].to_vec())
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "mKCP connection runtime is closed",
                        )
                    })?;
                self.wake.notify_one();
                Poll::Ready(Ok(length))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mKCP connection runtime is closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if !self.write_shutdown {
            self.write_shutdown = true;
            self.write_sender.close();
            self.wake.notify_one();
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
pub(crate) struct MkcpConnectionRuntime {
    state: MkcpConnectionState,
    stream_read_sender: Option<mpsc::Sender<Vec<u8>>>,
    stream_write_receiver: mpsc::Receiver<Vec<u8>>,
    wake: Arc<Notify>,
    tti: Duration,
    stream_write_closed: bool,
}

impl MkcpConnectionRuntime {
    pub(crate) fn new(
        conversation: u16,
        config: MkcpTransportConfig,
    ) -> (Self, MkcpByteStream) {
        let (stream_read_sender, read_receiver) =
            mpsc::channel(STREAM_CHANNEL_CAPACITY);
        let (write_sender, stream_write_receiver) =
            mpsc::channel(STREAM_CHANNEL_CAPACITY);
        let wake = Arc::new(Notify::new());
        let mss = config.mtu.saturating_sub(DATA_SEGMENT_OVERHEAD).max(1) as usize;
        let stream = MkcpByteStream {
            read_receiver,
            write_sender: PollSender::new(write_sender),
            wake: Arc::clone(&wake),
            read_pending: Vec::new(),
            read_offset: 0,
            mss,
            write_shutdown: false,
        };
        (
            Self {
                state: MkcpConnectionState::new(conversation, config),
                stream_read_sender: Some(stream_read_sender),
                stream_write_receiver,
                wake,
                tti: Duration::from_millis(config.tti as u64),
                stream_write_closed: false,
            },
            stream,
        )
    }

    pub(crate) fn wake_handle(&self) -> MkcpConnectionWake {
        MkcpConnectionWake {
            notify: Arc::clone(&self.wake),
        }
    }

    pub(crate) fn phase(&self) -> MkcpConnectionPhase {
        self.state.phase()
    }

    pub(crate) fn ingest(
        &mut self,
        current: u32,
        segments: Vec<MkcpSegment>,
    ) -> MkcpInputOutcome {
        let outcome = self.state.input(current, segments);
        self.pump_received(current);
        self.sync_read_eof();
        outcome
    }

    pub(crate) fn update(&mut self, current: u32) -> Vec<MkcpSegment> {
        self.pull_stream_writes(current);
        self.pump_received(current);
        let output = self.state.flush(current);
        self.sync_read_eof();
        output
    }

    pub(crate) fn next_update_delay(&self) -> Option<Duration> {
        match self.state.phase() {
            MkcpConnectionPhase::Terminated => None,
            MkcpConnectionPhase::Terminating => Some(TERMINATING_UPDATE_INTERVAL),
            MkcpConnectionPhase::PeerTerminating => {
                Some(if self.state.update_necessary() {
                    self.tti.min(TERMINATING_UPDATE_INTERVAL)
                } else {
                    TERMINATING_UPDATE_INTERVAL
                })
            }
            _ if self.state.update_necessary() => Some(self.tti),
            _ => Some(IDLE_UPDATE_INTERVAL),
        }
    }

    fn pull_stream_writes(&mut self, current: u32) {
        while self.state.can_push_payload() {
            match self.stream_write_receiver.try_recv() {
                Ok(payload) => {
                    debug_assert!(self.state.push_payload(payload));
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    if !self.stream_write_closed {
                        self.stream_write_closed = true;
                        self.state.close(current);
                    }
                    break;
                }
            }
        }
    }

    fn pump_received(&mut self, current: u32) {
        loop {
            let Some(sender) = self.stream_read_sender.as_ref() else {
                return;
            };
            if sender.is_closed() {
                self.stream_read_sender = None;
                self.state.close(current);
                return;
            }
            let Ok(permit) = sender.try_reserve() else {
                return;
            };
            let Some(payload) = self.state.pop_ordered_payload() else {
                return;
            };
            permit.send(payload);
        }
    }

    fn sync_read_eof(&mut self) {
        let close_read = match self.state.phase() {
            MkcpConnectionPhase::ReadyToClose
            | MkcpConnectionPhase::Terminating
            | MkcpConnectionPhase::Terminated => true,
            MkcpConnectionPhase::PeerTerminating => !self.state.data_available(),
            _ => false,
        };
        if close_read {
            self.stream_read_sender = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::timeout,
    };

    use super::*;
    use crate::config::MkcpTransportConfig;

    #[tokio::test]
    async fn byte_stream_chunks_writes_at_xray_mss_and_wakes_runtime() {
        let config = MkcpTransportConfig {
            mtu: 21,
            tti: 50,
            ..MkcpTransportConfig::default()
        };
        let (mut runtime, mut stream) = MkcpConnectionRuntime::new(7, config);
        let wake = runtime.wake_handle();
        let notified = wake.notified();
        tokio::pin!(notified);

        stream
            .write_all(b"abcdefg")
            .await
            .expect("write byte stream");
        notified.await;
        let output = runtime.update(100);
        assert_eq!(output.len(), 3);
        assert!(matches!(
            &output[0],
            MkcpSegment::Data { number: 0, payload, .. } if payload == b"abc"
        ));
        assert!(matches!(
            &output[1],
            MkcpSegment::Data { number: 1, payload, .. } if payload == b"def"
        ));
        assert!(matches!(
            &output[2],
            MkcpSegment::Data { number: 2, payload, .. } if payload == b"g"
        ));
        assert_eq!(runtime.next_update_delay(), Some(Duration::from_millis(50)));
    }

    #[tokio::test]
    async fn runtime_turns_ordered_kcp_payloads_into_one_byte_stream() {
        let (mut runtime, mut stream) =
            MkcpConnectionRuntime::new(11, MkcpTransportConfig::default());
        runtime.ingest(
            10,
            vec![
                MkcpSegment::Data {
                    conversation: 11,
                    option: 0,
                    timestamp: 1,
                    number: 1,
                    sending_next: 0,
                    payload: b"world".to_vec(),
                },
                MkcpSegment::Data {
                    conversation: 11,
                    option: 0,
                    timestamp: 1,
                    number: 0,
                    sending_next: 0,
                    payload: b"hello ".to_vec(),
                },
            ],
        );

        let mut output = [0u8; 11];
        stream
            .read_exact(&mut output)
            .await
            .expect("read ordered byte stream");
        assert_eq!(&output, b"hello world");
        assert_eq!(runtime.next_update_delay(), Some(Duration::from_millis(50)));
    }

    #[tokio::test]
    async fn byte_stream_backpressures_until_owner_updates() {
        let config = MkcpTransportConfig {
            mtu: 21,
            ..MkcpTransportConfig::default()
        };
        let (mut runtime, mut stream) = MkcpConnectionRuntime::new(9, config);
        let fill = vec![0u8; STREAM_CHANNEL_CAPACITY * 3];
        stream.write_all(&fill).await.expect("fill bounded channel");
        assert!(
            timeout(Duration::from_millis(10), stream.write_all(b"x"))
                .await
                .is_err()
        );

        assert_eq!(runtime.update(100).len(), STREAM_CHANNEL_CAPACITY);
        timeout(Duration::from_millis(100), stream.write_all(b"x"))
            .await
            .expect("owner update releases backpressure")
            .expect("write after owner update");
    }

    #[tokio::test]
    async fn stream_shutdown_drives_connection_close_without_hidden_task() {
        let (mut runtime, mut stream) =
            MkcpConnectionRuntime::new(13, MkcpTransportConfig::default());
        assert_eq!(runtime.next_update_delay(), Some(IDLE_UPDATE_INTERVAL));

        stream.shutdown().await.expect("shutdown byte stream");
        let output = runtime.update(25);
        assert_eq!(runtime.phase(), MkcpConnectionPhase::Terminating);
        assert!(matches!(
            output.as_slice(),
            [MkcpSegment::Command {
                command: super::super::COMMAND_TERMINATE,
                ..
            }]
        ));
        assert_eq!(
            runtime.next_update_delay(),
            Some(TERMINATING_UPDATE_INTERVAL)
        );
    }
}
