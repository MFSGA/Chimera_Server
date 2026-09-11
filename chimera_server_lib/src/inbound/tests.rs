use super::{
    AlterRecoveryGuard, ConfiguredStartGuard, ConfiguredStartingGuard,
    InboundLifecycleState, InboundManager, InboundTaskSet, stop_task_set,
};
use crate::{
    address::{BindLocation, NetLocation},
    beginning::start_servers,
    config::{
        Transport,
        server_config::{ServerConfig, ServerProxyConfig, SocksUserStore},
    },
    runtime::RuntimeState,
};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

fn free_localhost_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("read local addr")
        .port()
}

async fn wait_for_tcp_listener(port: u16) -> bool {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

fn inbound(tag: &str, port: u16) -> ServerConfig {
    ServerConfig {
        tag: tag.to_string(),
        bind_location: BindLocation::Address(NetLocation::from_ip_addr(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        )),
        protocol: ServerProxyConfig::Socks {
            accounts: SocksUserStore::new(Vec::new()),
            udp_enabled: false,
            udp_response_ip: None,
            user_level: 0,
        },
        transport: Transport::Tcp,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    }
}

#[test]
fn config_registry_rejects_duplicate_tags() {
    let manager = InboundManager::new(vec![inbound("primary", 10001)]);

    assert!(manager.add_config(inbound("primary", 10002)).is_err());
    assert_eq!(manager.configs().len(), 1);
    assert_eq!(
        manager.config_by_tag("primary").map(|config| config.tag),
        Some("primary".to_string())
    );
}

#[test]
fn config_registry_allows_multiple_untagged_inbounds() {
    let manager = InboundManager::new(Vec::new());

    manager
        .add_config(inbound("", 10001))
        .expect("first untagged inbound");
    manager
        .add_config(inbound("", 10002))
        .expect("second untagged inbound");
    assert_eq!(manager.configs().len(), 2);
}

#[tokio::test]
async fn configured_start_uses_generation_for_untagged_inbounds() {
    let first_port = free_localhost_port();
    let second_port = free_localhost_port();
    let runtime = RuntimeState::new(
        vec![inbound("", first_port), inbound("", second_port)],
        Vec::new(),
    );
    let manager = runtime.inbound_manager();

    assert_eq!(
        manager
            .start_configured_inbounds(runtime.clone(), None)
            .await
            .expect("start untagged inbounds"),
        2
    );
    assert!(wait_for_tcp_listener(first_port).await);
    assert!(wait_for_tcp_listener(second_port).await);
    assert_eq!(manager.stop_all_tasks().await, 2);
}

#[tokio::test]
async fn configured_start_rejects_duplicate_nonempty_tags_before_binding() {
    let first_port = free_localhost_port();
    let second_port = free_localhost_port();
    let runtime = RuntimeState::new(
        vec![
            inbound("duplicate", first_port),
            inbound("duplicate", second_port),
        ],
        Vec::new(),
    );
    let manager = runtime.inbound_manager();

    let error = manager
        .start_configured_inbounds(runtime, None)
        .await
        .expect_err("duplicate nonempty tags must fail startup");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, first_port)).is_ok());
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, second_port)).is_ok());
}

#[tokio::test]
async fn stopping_tasks_does_not_remove_config() {
    let manager = InboundManager::new(vec![inbound("primary", 10001)]);
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Prepared)
    );
    let task = tokio::spawn(std::future::pending());
    manager.register_tasks("primary", vec![task]);
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Running)
    );

    assert!(manager.stop_tasks("primary").await);
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Prepared)
    );
    assert!(manager.config_by_tag("primary").is_some());
    assert!(!manager.stop_tasks("primary").await);
}

#[tokio::test]
async fn stopping_all_tasks_aborts_every_listener_before_reset() {
    let manager =
        InboundManager::new(vec![inbound("first", 10001), inbound("second", 10002)]);
    let first = tokio::spawn(std::future::pending());
    let second = tokio::spawn(std::future::pending());
    let first_abort = first.abort_handle();
    let second_abort = second.abort_handle();
    manager.register_tasks("first", vec![first]);
    manager.register_tasks("second", vec![second]);

    assert_eq!(manager.stop_all_tasks().await, 2);
    assert!(first_abort.is_finished());
    assert!(second_abort.is_finished());
    assert_eq!(
        manager.lifecycle_state("first"),
        Some(InboundLifecycleState::Prepared)
    );
    assert_eq!(
        manager.lifecycle_state("second"),
        Some(InboundLifecycleState::Prepared)
    );
    assert_eq!(manager.configs().len(), 2);
    assert_eq!(manager.stop_all_tasks().await, 0);
}

#[tokio::test]
async fn server_shutdown_exposes_per_inbound_draining_state() {
    let manager = Arc::new(InboundManager::new(vec![inbound("primary", 10001)]));
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::task::spawn_blocking(move || {
        started_tx.send(()).expect("signal blocking task start");
        release_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("wait for test release");
    });
    started_rx.recv().expect("blocking task should start");
    manager.register_tasks("primary", vec![task]);

    let stopping = {
        let manager = Arc::clone(&manager);
        tokio::spawn(async move { manager.stop_all_tasks().await })
    };
    for _ in 0..50 {
        if manager.lifecycle_state("primary")
            == Some(InboundLifecycleState::Draining)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Draining)
    );

    release_tx.send(()).expect("release blocking task");
    assert_eq!(stopping.await.expect("join stop task"), 1);
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Prepared)
    );
}

#[tokio::test]
async fn unexpected_listener_completion_marks_generation_failed() {
    let manager = InboundManager::new(vec![inbound("primary", 10001)]);
    let generation = manager.generation("primary").expect("generation");
    manager.register_tasks("primary", vec![tokio::spawn(async {})]);
    tokio::task::yield_now().await;

    assert!(manager.has_unhealthy_inbound());
    let failure =
        tokio::time::timeout(Duration::from_secs(1), manager.wait_for_failure())
            .await
            .expect("listener failure should be detected");
    assert_eq!(failure.tag, "primary");
    assert_eq!(failure.generation, generation);
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Failed)
    );

    assert_eq!(manager.stop_all_tasks().await, 1);
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Failed)
    );
}

#[tokio::test]
async fn intentional_listener_stop_is_not_reported_as_failure() {
    let manager = InboundManager::new(vec![inbound("primary", 10001)]);
    manager.register_tasks("primary", vec![tokio::spawn(std::future::pending())]);

    assert!(manager.stop_tasks("primary").await);
    assert!(!manager.has_unhealthy_inbound());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), manager.wait_for_failure())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn registering_tasks_for_missing_instance_aborts_them() {
    let manager = InboundManager::new(Vec::new());
    let task = tokio::spawn(std::future::pending());
    let abort_handle = task.abort_handle();

    manager.register_tasks("missing", vec![task]);
    tokio::task::yield_now().await;

    assert!(abort_handle.is_finished());
    assert_eq!(manager.lifecycle_state("missing"), None);
}

#[test]
fn cancelled_configured_start_restores_prepared_state() {
    let manager = Arc::new(InboundManager::new(vec![inbound("primary", 10001)]));
    let generation = manager.generation("primary").unwrap();
    assert!(manager.set_lifecycle_for_generation(
        "primary",
        generation,
        InboundLifecycleState::Starting,
    ));
    let guard = ConfiguredStartingGuard::new(
        Arc::clone(&manager),
        "primary".to_string(),
        generation,
    );

    drop(guard);

    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Prepared)
    );
}

#[tokio::test]
async fn stale_generation_cannot_stop_recreated_inbound_tasks() {
    let manager = InboundManager::new(vec![inbound("primary", 10001)]);
    let old_generation = manager.generation("primary").unwrap();
    assert!(manager.remove_config("primary").is_some());
    manager.add_config(inbound("primary", 10002)).unwrap();
    let new_generation = manager.generation("primary").unwrap();
    assert_ne!(old_generation, new_generation);

    let task = tokio::spawn(std::future::pending());
    assert!(manager.register_tasks_for_generation(
        "primary",
        new_generation,
        vec![task]
    ));
    assert!(
        !manager
            .stop_tasks_for_generation("primary", old_generation)
            .await
    );
    assert!(
        manager
            .stop_tasks_for_generation("primary", new_generation)
            .await
    );
}

#[tokio::test]
async fn stale_generation_registration_aborts_old_task() {
    let manager = InboundManager::new(vec![inbound("primary", 10001)]);
    let old_generation = manager.generation("primary").unwrap();
    assert!(manager.remove_config("primary").is_some());
    manager.add_config(inbound("primary", 10002)).unwrap();

    let task = tokio::spawn(std::future::pending());
    let abort_handle = task.abort_handle();
    assert!(!manager.register_tasks_for_generation(
        "primary",
        old_generation,
        vec![task]
    ));
    tokio::task::yield_now().await;
    assert!(abort_handle.is_finished());
}

#[tokio::test]
async fn cancelled_alter_recovers_original_listener() {
    let port = free_localhost_port();
    let original = inbound("primary", port);
    let runtime = RuntimeState::new(vec![original.clone()], Vec::new());
    let manager = runtime.inbound_manager();
    let generation = manager.generation("primary").unwrap();
    let handles = start_servers(original.clone(), runtime.clone())
        .await
        .expect("start original listener");
    assert!(manager.register_tasks_for_generation("primary", generation, handles));
    assert!(wait_for_tcp_listener(port).await);

    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let transition_manager = Arc::clone(&manager);
    let transition_runtime = runtime.clone();
    let transition_original = original.clone();
    let transition = tokio::spawn(async move {
        let _operation_guard =
            transition_manager.operation_lock("primary").lock().await;
        let task_set = {
            let mut state = transition_manager
                .state
                .write()
                .expect("inbound manager lock poisoned");
            let entry = state
                .configs
                .iter_mut()
                .find(|entry| entry.config.tag == "primary")
                .expect("original inbound registered");
            InboundTaskSet {
                generation: entry.generation,
                handles: entry
                    .tasks
                    .take()
                    .expect("original listener tasks registered"),
            }
        };
        let _recovery = AlterRecoveryGuard::new(
            Arc::clone(&transition_manager),
            transition_runtime,
            "primary".to_string(),
            generation,
            transition_original,
        );
        stop_task_set(task_set).await;
        let _ = armed_tx.send(());
        std::future::pending::<()>().await;
    });

    armed_rx.await.expect("alter recovery guard armed");
    transition.abort();
    let _ = transition.await;

    assert!(
        wait_for_tcp_listener(port).await,
        "cancelling alter must restore the original listener"
    );
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Running)
    );
    assert!(manager.stop_tasks("primary").await);
}

#[tokio::test]
async fn configured_start_rolls_back_prior_listener_on_later_bind_failure() {
    let first_port = free_localhost_port();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind occupied second port");
    let second_port = occupied.local_addr().unwrap().port();
    let runtime = RuntimeState::new(
        vec![inbound("first", first_port), inbound("second", second_port)],
        Vec::new(),
    );
    let manager = runtime.inbound_manager();

    manager
        .start_configured_inbounds(runtime.clone(), None)
        .await
        .expect_err("second inbound bind must fail");

    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, first_port)).is_ok(),
        "failed initial startup must release previously started listeners"
    );
    assert!(manager.config_by_tag("first").is_some());
    assert!(manager.config_by_tag("second").is_some());
    assert_eq!(
        manager.lifecycle_state("first"),
        Some(InboundLifecycleState::Prepared)
    );
    assert_eq!(
        manager.lifecycle_state("second"),
        Some(InboundLifecycleState::Prepared)
    );
    assert!(!manager.stop_tasks("first").await);
}

#[tokio::test]
async fn cancelled_configured_start_guard_cleans_recorded_generation() {
    let manager = Arc::new(InboundManager::new(vec![inbound("primary", 10001)]));
    let generation = manager.generation("primary").unwrap();
    let task = tokio::spawn(std::future::pending());
    let abort_handle = task.abort_handle();
    assert!(manager.register_tasks_for_generation(
        "primary",
        generation,
        vec![task]
    ));

    let mut guard = ConfiguredStartGuard::new(Arc::clone(&manager));
    guard.record("primary".to_string(), generation);
    drop(guard);
    for _ in 0..20 {
        if abort_handle.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(abort_handle.is_finished());
    assert!(!manager.stop_tasks("primary").await);
}

#[tokio::test]
async fn dynamic_add_publishes_running_and_remove_clears_lifecycle() {
    let port = free_localhost_port();
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let manager = runtime.inbound_manager();

    manager
        .add_started(runtime.clone(), inbound("primary", port))
        .await
        .expect("dynamic add");
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Running)
    );
    assert!(wait_for_tcp_listener(port).await);

    manager
        .remove_started("primary")
        .await
        .expect("dynamic remove");
    assert_eq!(manager.lifecycle_state("primary"), None);
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
}

#[tokio::test]
async fn failed_dynamic_add_clears_starting_reservation() {
    let occupied =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind occupied port");
    let port = occupied.local_addr().unwrap().port();
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let manager = runtime.inbound_manager();

    assert!(
        manager
            .add_started(runtime, inbound("primary", port))
            .await
            .is_err()
    );
    assert_eq!(manager.lifecycle_state("primary"), None);
    assert!(manager.config_by_tag("primary").is_none());
}

#[tokio::test]
async fn cancelled_remove_keeps_tombstone_until_task_reaped() {
    let manager = Arc::new(InboundManager::new(vec![inbound("primary", 10001)]));
    let generation = manager.generation("primary").unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::task::spawn_blocking(move || {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
    });
    started_rx.await.expect("blocking task should start");
    assert!(manager.register_tasks_for_generation(
        "primary",
        generation,
        vec![task]
    ));

    let removing_manager = Arc::clone(&manager);
    let removing =
        tokio::spawn(
            async move { removing_manager.remove_started("primary").await },
        );
    for _ in 0..50 {
        if manager.lifecycle_state("primary")
            == Some(InboundLifecycleState::Stopping)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Stopping)
    );
    assert!(manager.config_by_tag("primary").is_none());

    removing.abort();
    let _ = removing.await;
    assert_eq!(
        manager.lifecycle_state("primary"),
        Some(InboundLifecycleState::Stopping)
    );
    assert!(manager.add_config(inbound("primary", 10002)).is_err());

    release_tx.send(()).expect("release blocking task");
    for _ in 0..100 {
        if manager.lifecycle_state("primary").is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(manager.lifecycle_state("primary"), None);
    assert!(manager.add_config(inbound("primary", 10002)).is_ok());
}

#[tokio::test]
async fn cancelled_alter_recovery_does_not_revive_stale_generation() {
    let old_port = free_localhost_port();
    let new_port = free_localhost_port();
    let original = inbound("primary", old_port);
    let runtime = RuntimeState::new(vec![original.clone()], Vec::new());
    let manager = runtime.inbound_manager();
    let old_generation = manager.generation("primary").unwrap();

    assert!(manager.remove_config("primary").is_some());
    manager.add_config(inbound("primary", new_port)).unwrap();
    let new_generation = manager.generation("primary").unwrap();
    let new_task = tokio::spawn(std::future::pending());
    let new_abort = new_task.abort_handle();
    assert!(manager.register_tasks_for_generation(
        "primary",
        new_generation,
        vec![new_task]
    ));

    drop(AlterRecoveryGuard::new(
        Arc::clone(&manager),
        runtime,
        "primary".to_string(),
        old_generation,
        original,
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(manager.generation("primary"), Some(new_generation));
    assert!(!new_abort.is_finished());
    assert!(
        tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, old_port))
            .await
            .is_err(),
        "stale recovery must not revive the removed generation"
    );
    assert!(manager.stop_tasks("primary").await);
}
