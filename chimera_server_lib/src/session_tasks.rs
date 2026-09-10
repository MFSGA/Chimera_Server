use std::future::Future;

use tokio_util::task::TaskTracker;

/// Server-level owner for accepted connection tasks that may outlive the
/// listener which accepted them.
///
/// Xray removes a TCP inbound by closing its listening hub while established
/// connections are allowed to finish naturally. `TaskTracker` matches that
/// contract: dropping an owner handle does not abort tracked tasks, while the
/// shared tracker still records their lifetime for later draining/shutdown
/// work.
#[derive(Debug, Clone, Default)]
pub(crate) struct ConnectionTaskOwner {
    tracker: TaskTracker,
}

impl ConnectionTaskOwner {
    pub(crate) fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        drop(self.tracker.spawn(future));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.tracker.len()
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionTaskOwner;

    #[tokio::test]
    async fn owner_tracks_detached_task_until_completion() {
        let owner = ConnectionTaskOwner::default();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();

        owner.spawn(async move {
            let _ = release_rx.await;
        });
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

        owner.spawn(async move {
            let _ = release_rx.await;
            let _ = finished_tx.send(());
        });
        drop(owner);

        release_tx.send(()).expect("release active connection");
        tokio::time::timeout(std::time::Duration::from_secs(1), finished_rx)
            .await
            .expect("tracked task should keep running after owner handle drop")
            .expect("tracked task should report completion");
    }
}
