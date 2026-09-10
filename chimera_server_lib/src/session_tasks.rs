use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// Result of a bounded server-level connection drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectionTaskShutdown {
    /// `true` when every tracked task completed before the grace period ended.
    pub(crate) drained: bool,
    /// Number of tasks still tracked when forced cancellation began.
    pub(crate) cancelled_tasks: usize,
}

#[derive(Debug)]
struct ConnectionTaskOwnerInner {
    tracker: TaskTracker,
    cancellation: CancellationToken,
    accepting: Mutex<bool>,
}

/// Server-level owner for accepted connection tasks that may outlive the
/// listener which accepted them.
///
/// Xray removes a TCP inbound by closing its listening hub while established
/// connections are allowed to finish naturally. Ordinary listener removal
/// therefore only drops an owner handle; it does not cancel tracked tasks.
/// Whole-server shutdown is different: registration is closed first, existing
/// tasks receive a bounded drain window, and only the remaining tasks are then
/// cancelled through the shared token.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionTaskOwner {
    inner: Arc<ConnectionTaskOwnerInner>,
}

impl Default for ConnectionTaskOwner {
    fn default() -> Self {
        Self {
            inner: Arc::new(ConnectionTaskOwnerInner {
                tracker: TaskTracker::new(),
                cancellation: CancellationToken::new(),
                accepting: Mutex::new(true),
            }),
        }
    }
}

impl ConnectionTaskOwner {
    /// Spawn and track a connection task while the server is accepting work.
    ///
    /// Returns `false` once server shutdown has closed registration. The future
    /// is dropped in that case, which also closes any just-accepted socket it
    /// owns.
    pub(crate) fn spawn<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let accepting = self
            .inner
            .accepting
            .lock()
            .expect("connection task owner lock poisoned");
        if !*accepting {
            return false;
        }

        let cancellation = self.inner.cancellation.clone();
        drop(self.inner.tracker.spawn(async move {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {}
                _ = future => {}
            }
        }));
        true
    }

    /// Stop accepting new tracked tasks. Existing tasks keep running.
    pub(crate) fn close(&self) -> bool {
        let mut accepting = self
            .inner
            .accepting
            .lock()
            .expect("connection task owner lock poisoned");
        if !*accepting {
            return false;
        }
        *accepting = false;
        self.inner.tracker.close();
        true
    }

    /// Wait for tracked tasks to finish naturally, then cancel any stragglers.
    pub(crate) async fn drain_or_cancel(
        &self,
        grace_period: Duration,
    ) -> ConnectionTaskShutdown {
        self.close();

        if tokio::time::timeout(grace_period, self.inner.tracker.wait())
            .await
            .is_ok()
        {
            return ConnectionTaskShutdown {
                drained: true,
                cancelled_tasks: 0,
            };
        }

        let cancelled_tasks = self.inner.tracker.len();
        self.inner.cancellation.cancel();
        self.inner.tracker.wait().await;
        ConnectionTaskShutdown {
            drained: false,
            cancelled_tasks,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.tracker.len()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use super::{ConnectionTaskOwner, ConnectionTaskShutdown};

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn owner_tracks_detached_task_until_completion() {
        let owner = ConnectionTaskOwner::default();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();

        assert!(owner.spawn(async move {
            let _ = release_rx.await;
        }));
        tokio::task::yield_now().await;
        assert_eq!(owner.len(), 1);

        release_tx.send(()).expect("release tracked task");
        for _ in 0..50 {
            if owner.len() == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("completed connection task should leave its owner");
    }

    #[tokio::test]
    async fn dropping_owner_handle_does_not_abort_active_connection() {
        let owner = ConnectionTaskOwner::default();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();

        assert!(owner.spawn(async move {
            let _ = release_rx.await;
            let _ = finished_tx.send(());
        }));
        drop(owner);

        release_tx.send(()).expect("release active connection");
        tokio::time::timeout(Duration::from_secs(1), finished_rx)
            .await
            .expect("tracked task should keep running after owner handle drop")
            .expect("tracked task should report completion");
    }

    #[tokio::test]
    async fn shutdown_drains_connections_that_finish_within_grace_period() {
        let owner = ConnectionTaskOwner::default();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();

        assert!(owner.spawn(async move {
            let _ = release_rx.await;
        }));
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = release_tx.send(());
        });

        assert_eq!(
            owner.drain_or_cancel(Duration::from_secs(1)).await,
            ConnectionTaskShutdown {
                drained: true,
                cancelled_tasks: 0,
            }
        );
        assert_eq!(owner.len(), 0);
        assert!(!owner.spawn(async {}));
    }

    #[tokio::test]
    async fn shutdown_cancels_connections_left_after_grace_period() {
        let owner = ConnectionTaskOwner::default();
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);

        assert!(owner.spawn(async move {
            let _drop_flag = DropFlag(task_dropped);
            pending::<()>().await;
        }));
        tokio::task::yield_now().await;

        assert_eq!(
            owner.drain_or_cancel(Duration::from_millis(10)).await,
            ConnectionTaskShutdown {
                drained: false,
                cancelled_tasks: 1,
            }
        );
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(owner.len(), 0);
    }

    #[tokio::test]
    async fn repeated_shutdown_is_idempotent() {
        let owner = ConnectionTaskOwner::default();
        assert_eq!(
            owner.drain_or_cancel(Duration::ZERO).await,
            ConnectionTaskShutdown {
                drained: true,
                cancelled_tasks: 0,
            }
        );
        assert_eq!(
            owner.drain_or_cancel(Duration::ZERO).await,
            ConnectionTaskShutdown {
                drained: true,
                cancelled_tasks: 0,
            }
        );
    }
}
