use std::{sync::Arc, time::Duration};

use tokio::task::JoinHandle;

use crate::{
    beginning::start_bound_servers, config::server_config::ServerConfig,
    runtime::RuntimeState,
};

use super::{
    InboundFailure, InboundLifecycleState, InboundManager, PendingInboundLifecycle,
};

#[derive(Debug)]
pub(super) struct InboundTaskSet {
    pub(super) generation: u64,
    pub(super) handles: Vec<JoinHandle<()>>,
}

pub(super) struct PendingTasks {
    handles: Option<Vec<JoinHandle<()>>>,
}

impl PendingTasks {
    pub(super) fn new(handles: Vec<JoinHandle<()>>) -> Self {
        Self {
            handles: Some(handles),
        }
    }

    pub(super) fn commit(mut self) -> Vec<JoinHandle<()>> {
        self.handles.take().unwrap_or_default()
    }
}

impl Drop for PendingTasks {
    fn drop(&mut self) {
        if let Some(handles) = self.handles.take() {
            abort_tasks(&handles);
        }
    }
}

pub(super) struct ConfiguredStartGuard {
    manager: Arc<InboundManager>,
    started: Vec<(String, u64)>,
}

impl ConfiguredStartGuard {
    pub(super) fn new(manager: Arc<InboundManager>) -> Self {
        Self {
            manager,
            started: Vec::new(),
        }
    }

    pub(super) fn record(&mut self, tag: String, generation: u64) {
        self.started.push((tag, generation));
    }

    pub(super) async fn rollback(&mut self) {
        while let Some((tag, generation)) = self.started.last().cloned() {
            self.manager
                .stop_tasks_for_generation(&tag, generation)
                .await;
            self.started.pop();
        }
    }

    pub(super) fn disarm(&mut self) {
        self.started.clear();
    }
}

impl Drop for ConfiguredStartGuard {
    fn drop(&mut self) {
        if self.started.is_empty() {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let manager = Arc::clone(&self.manager);
        let started = std::mem::take(&mut self.started);
        handle.spawn(async move {
            for (tag, generation) in started.into_iter().rev() {
                manager.stop_tasks_for_generation(&tag, generation).await;
            }
        });
    }
}

pub(super) struct PendingAddGuard {
    manager: Arc<InboundManager>,
    tag: String,
    generation: u64,
    armed: bool,
}

impl PendingAddGuard {
    pub(super) fn new(
        manager: Arc<InboundManager>,
        tag: String,
        generation: u64,
    ) -> Self {
        Self {
            manager,
            tag,
            generation,
            armed: true,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingAddGuard {
    fn drop(&mut self) {
        if self.armed {
            self.manager.clear_pending_lifecycle(
                &self.tag,
                self.generation,
                InboundLifecycleState::Starting,
            );
        }
    }
}

pub(super) struct RemoveCleanupGuard {
    manager: Arc<InboundManager>,
    tag: String,
    generation: u64,
    handles: Vec<JoinHandle<()>>,
    armed: bool,
}

impl RemoveCleanupGuard {
    pub(super) fn new(
        manager: Arc<InboundManager>,
        tag: String,
        generation: u64,
        task_set: Option<InboundTaskSet>,
    ) -> Self {
        let handles = task_set.map(|tasks| tasks.handles).unwrap_or_default();
        abort_tasks(&handles);
        Self {
            manager,
            tag,
            generation,
            handles,
            armed: true,
        }
    }

    pub(super) async fn finish(&mut self) {
        while let Some(handle) = self.handles.last_mut() {
            let _ = handle.await;
            self.handles.pop();
        }
        self.manager.clear_pending_lifecycle(
            &self.tag,
            self.generation,
            InboundLifecycleState::Stopping,
        );
        self.armed = false;
    }
}

impl Drop for RemoveCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let handles = std::mem::take(&mut self.handles);
        let manager = Arc::clone(&self.manager);
        let tag = self.tag.clone();
        let generation = self.generation;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                for handle in handles {
                    let _ = handle.await;
                }
                manager.clear_pending_lifecycle(
                    &tag,
                    generation,
                    InboundLifecycleState::Stopping,
                );
            });
        } else {
            manager.clear_pending_lifecycle(
                &tag,
                generation,
                InboundLifecycleState::Stopping,
            );
        }
    }
}

pub(super) struct ConfiguredStartingGuard {
    manager: Arc<InboundManager>,
    tag: String,
    generation: u64,
    armed: bool,
}

impl ConfiguredStartingGuard {
    pub(super) fn new(
        manager: Arc<InboundManager>,
        tag: String,
        generation: u64,
    ) -> Self {
        Self {
            manager,
            tag,
            generation,
            armed: true,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ConfiguredStartingGuard {
    fn drop(&mut self) {
        if self.armed {
            self.manager
                .restore_prepared_state(&self.tag, self.generation);
        }
    }
}

pub(super) struct AlterRecoveryGuard {
    manager: Arc<InboundManager>,
    runtime: RuntimeState,
    tag: String,
    generation: u64,
    original: Option<ServerConfig>,
}

impl AlterRecoveryGuard {
    pub(super) fn new(
        manager: Arc<InboundManager>,
        runtime: RuntimeState,
        tag: String,
        generation: u64,
        original: ServerConfig,
    ) -> Self {
        Self {
            manager,
            runtime,
            tag,
            generation,
            original: Some(original),
        }
    }

    pub(super) fn disarm(&mut self) {
        self.original = None;
    }
}

impl Drop for AlterRecoveryGuard {
    fn drop(&mut self) {
        let Some(original) = self.original.take() else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let manager = Arc::clone(&self.manager);
        let runtime = self.runtime.clone();
        let tag = self.tag.clone();
        let generation = self.generation;
        handle.spawn(async move {
            manager
                .recover_cancelled_alter(runtime, tag, generation, original)
                .await;
        });
    }
}

impl InboundManager {
    pub(super) fn set_lifecycle_for_generation(
        &self,
        tag: &str,
        generation: u64,
        lifecycle: InboundLifecycleState,
    ) -> bool {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let Some(entry) = state
            .configs
            .iter_mut()
            .find(|entry| entry.config.tag == tag && entry.generation == generation)
        else {
            return false;
        };
        entry.lifecycle = lifecycle;
        true
    }

    fn restore_prepared_state(&self, tag: &str, generation: u64) {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        if let Some(entry) = state.configs.iter_mut().find(|entry| {
            entry.config.tag == tag
                && entry.generation == generation
                && entry.lifecycle == InboundLifecycleState::Starting
        }) {
            entry.lifecycle = InboundLifecycleState::Prepared;
        }
    }

    fn clear_pending_lifecycle(
        &self,
        tag: &str,
        generation: u64,
        lifecycle: InboundLifecycleState,
    ) -> bool {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        if state.pending.get(tag).copied()
            != Some(PendingInboundLifecycle {
                generation,
                lifecycle,
            })
        {
            return false;
        }
        state.pending.remove(tag);
        true
    }

    #[cfg(test)]
    pub(super) fn lifecycle_state(
        &self,
        tag: &str,
    ) -> Option<InboundLifecycleState> {
        let state = self.state.read().expect("inbound manager lock poisoned");
        state
            .configs
            .iter()
            .find(|entry| entry.config.tag == tag)
            .map(|entry| entry.lifecycle)
            .or_else(|| state.pending.get(tag).map(|entry| entry.lifecycle))
    }

    pub(crate) fn unhealthy_inbound(&self) -> Option<InboundFailure> {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .find(|entry| {
                entry.lifecycle == InboundLifecycleState::Failed
                    || (entry.lifecycle == InboundLifecycleState::Running
                        && entry.tasks.as_ref().is_some_and(|handles| {
                            handles.iter().any(JoinHandle::is_finished)
                        }))
            })
            .map(|entry| InboundFailure {
                tag: entry.config.tag.clone(),
                generation: entry.generation,
            })
    }

    pub(crate) fn has_unhealthy_inbound(&self) -> bool {
        self.state
            .read()
            .expect("inbound manager lock poisoned")
            .configs
            .iter()
            .any(|entry| {
                entry.lifecycle == InboundLifecycleState::Failed
                    || (entry.lifecycle == InboundLifecycleState::Running
                        && entry.tasks.as_ref().is_some_and(|handles| {
                            handles.iter().any(JoinHandle::is_finished)
                        }))
            })
    }

    fn detect_running_failure(&self) -> Option<InboundFailure> {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let entry = state.configs.iter_mut().find(|entry| {
            entry.lifecycle == InboundLifecycleState::Running
                && entry.tasks.as_ref().is_some_and(|handles| {
                    handles.iter().any(JoinHandle::is_finished)
                })
        })?;
        entry.lifecycle = InboundLifecycleState::Failed;
        Some(InboundFailure {
            tag: entry.config.tag.clone(),
            generation: entry.generation,
        })
    }

    pub(crate) async fn wait_for_failure(&self) -> InboundFailure {
        const POLL_INTERVAL: Duration = Duration::from_millis(25);

        loop {
            if let Some(failure) = self.detect_running_failure() {
                return failure;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    pub(crate) fn register_tasks(&self, tag: &str, handles: Vec<JoinHandle<()>>) {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let Some(entry) = state
            .configs
            .iter_mut()
            .find(|entry| entry.config.tag == tag)
        else {
            abort_tasks(&handles);
            return;
        };
        entry.lifecycle = InboundLifecycleState::Running;
        if let Some(previous) = entry.tasks.replace(handles) {
            abort_tasks(&previous);
        }
    }

    pub(crate) fn register_tasks_for_generation(
        &self,
        tag: &str,
        generation: u64,
        handles: Vec<JoinHandle<()>>,
    ) -> bool {
        let mut state = self.state.write().expect("inbound manager lock poisoned");
        let Some(entry) = state
            .configs
            .iter_mut()
            .find(|entry| entry.config.tag == tag && entry.generation == generation)
        else {
            abort_tasks(&handles);
            return false;
        };
        entry.lifecycle = InboundLifecycleState::Running;
        if let Some(previous) = entry.tasks.replace(handles) {
            abort_tasks(&previous);
        }
        true
    }

    pub(crate) async fn stop_all_tasks(&self) -> usize {
        let task_sets = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            state
                .configs
                .iter_mut()
                .filter_map(|entry| {
                    let handles = entry.tasks.take()?;
                    let failed = entry.lifecycle == InboundLifecycleState::Failed;
                    if !failed {
                        entry.lifecycle = InboundLifecycleState::Draining;
                    }
                    Some((
                        entry.config.tag.clone(),
                        failed,
                        InboundTaskSet {
                            generation: entry.generation,
                            handles,
                        },
                    ))
                })
                .collect::<Vec<_>>()
        };

        // Abort every listener before awaiting any of them so server shutdown
        // stops accepting new connections across all inbounds promptly.
        for (_, _, task_set) in &task_sets {
            abort_tasks(&task_set.handles);
        }

        let stopped = task_sets.len();
        for (tag, failed, task_set) in task_sets {
            let generation = task_set.generation;
            stop_task_set(task_set).await;
            if !failed {
                self.set_lifecycle_for_generation(
                    &tag,
                    generation,
                    InboundLifecycleState::Prepared,
                );
            }
        }
        stopped
    }

    pub(crate) async fn stop_tasks(&self, tag: &str) -> bool {
        let task_set = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            let Some(entry) = state
                .configs
                .iter_mut()
                .find(|entry| entry.config.tag == tag)
            else {
                return false;
            };
            let Some(handles) = entry.tasks.take() else {
                return false;
            };
            entry.lifecycle = InboundLifecycleState::Stopping;
            Some(InboundTaskSet {
                generation: entry.generation,
                handles,
            })
        };
        let Some(task_set) = task_set else {
            return false;
        };
        let generation = task_set.generation;
        stop_task_set(task_set).await;
        self.set_lifecycle_for_generation(
            tag,
            generation,
            InboundLifecycleState::Prepared,
        );
        true
    }

    pub(crate) async fn stop_tasks_for_generation(
        &self,
        tag: &str,
        generation: u64,
    ) -> bool {
        let task_set = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            let Some(entry) = state.configs.iter_mut().find(|entry| {
                entry.config.tag == tag && entry.generation == generation
            }) else {
                return false;
            };
            let Some(handles) = entry.tasks.take() else {
                return false;
            };
            entry.lifecycle = InboundLifecycleState::Stopping;
            InboundTaskSet {
                generation,
                handles,
            }
        };
        stop_task_set(task_set).await;
        self.set_lifecycle_for_generation(
            tag,
            generation,
            InboundLifecycleState::Prepared,
        );
        true
    }

    async fn recover_cancelled_alter(
        &self,
        runtime: RuntimeState,
        tag: String,
        generation: u64,
        original: ServerConfig,
    ) {
        let _operation_guard = self.operation_lock(&tag).lock().await;
        let should_recover = {
            let mut state =
                self.state.write().expect("inbound manager lock poisoned");
            if let Some(entry) = state.configs.iter_mut().find(|entry| {
                entry.config.tag == tag && entry.generation == generation
            }) {
                if entry.tasks.is_some() {
                    false
                } else {
                    entry.lifecycle = InboundLifecycleState::Recovering;
                    true
                }
            } else {
                false
            }
        };
        if !should_recover {
            return;
        }

        match start_bound_servers(original.clone(), runtime).await {
            Ok(bound) => {
                let handles = bound.into_handles();
                let pending = PendingTasks::new(handles);
                if let Err(error) = self.replace_running_generation(
                    &tag,
                    generation,
                    original,
                    pending.commit(),
                ) {
                    tracing::warn!(
                        inbound_tag = %tag,
                        reason = error,
                        "cancelled inbound alter recovery was superseded"
                    );
                }
            }
            Err(error) => {
                self.set_lifecycle_for_generation(
                    &tag,
                    generation,
                    InboundLifecycleState::Prepared,
                );
                tracing::warn!(
                    inbound_tag = %tag,
                    error = %error,
                    "failed to recover inbound after cancelled alter"
                );
            }
        }
    }
}

pub(super) fn abort_tasks(handles: &[JoinHandle<()>]) {
    for handle in handles {
        handle.abort();
    }
}

pub(super) async fn stop_task_set(task_set: InboundTaskSet) {
    abort_tasks(&task_set.handles);
    for handle in task_set.handles {
        let _ = handle.await;
    }
}
