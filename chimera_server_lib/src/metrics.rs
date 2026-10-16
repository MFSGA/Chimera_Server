use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::{routing_state::OutboundObservation, runtime::RuntimeState};

#[derive(Clone)]
struct MetricsState {
    runtime: RuntimeState,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct MemStats {
    #[serde(rename = "HeapAlloc")]
    heap_alloc: u64,
    #[serde(rename = "Sys")]
    sys: u64,
    #[serde(rename = "HeapObjects")]
    heap_objects: u64,
    #[serde(rename = "NumGC")]
    num_gc: u32,
    #[serde(rename = "PauseNs")]
    pause_ns: Vec<u64>,
}

#[derive(Serialize)]
struct Stats {
    inbound: HashMap<String, HashMap<String, i64>>,
    outbound: HashMap<String, HashMap<String, i64>>,
    user: HashMap<String, HashMap<String, i64>>,
}

#[derive(Serialize)]
struct ObservatoryEntry {
    alive: bool,
    delay: i64,
    last_seen_time: i64,
    last_try_time: i64,
    outbound_tag: String,
}

impl From<(String, OutboundObservation)> for ObservatoryEntry {
    fn from((outbound_tag, observation): (String, OutboundObservation)) -> Self {
        Self {
            alive: observation.alive,
            delay: observation.delay_ms,
            last_seen_time: observation.last_seen_time,
            last_try_time: observation.last_try_time,
            outbound_tag,
        }
    }
}

#[derive(Serialize)]
struct ChimeraRuntimeInfo {
    memory_source: &'static str,
    memory_values_are_xray_go_runtime_equivalents: bool,
    garbage_collector: &'static str,
    traffic_stats_enabled: bool,
}

#[derive(Serialize)]
struct DebugVars {
    memstats: MemStats,
    stats: Stats,
    observatory: HashMap<String, ObservatoryEntry>,
    chimera: ChimeraRuntimeInfo,
}

pub(crate) async fn start_metrics_server(
    listen: SocketAddr,
    runtime: RuntimeState,
) -> std::io::Result<JoinHandle<()>> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let local_addr = listener.local_addr()?;
    let app = Router::new()
        .route("/debug/vars", get(debug_vars))
        .with_state(MetricsState { runtime });

    info!(%local_addr, "Xray-compatible metrics endpoint listening");
    Ok(tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            error!(%error, "metrics HTTP server stopped unexpectedly");
        }
    }))
}

async fn debug_vars(State(state): State<MetricsState>) -> Response {
    let (resident_bytes, virtual_bytes) = process_memory_bytes().await;
    let observatory = state
        .runtime
        .active_outbound_observations()
        .into_iter()
        .map(ObservatoryEntry::from)
        .map(|entry| (entry.outbound_tag.clone(), entry))
        .collect();

    let body = DebugVars {
        memstats: MemStats {
            // Rust does not expose allocator heap or GC counters through the
            // standard library. These two values are process RSS/virtual size
            // so existing clients get useful memory history without implying
            // that they are Go allocator measurements.
            heap_alloc: resident_bytes,
            sys: virtual_bytes,
            heap_objects: 0,
            num_gc: 0,
            pause_ns: vec![0; 256],
        },
        stats: traffic_stats(),
        observatory,
        chimera: ChimeraRuntimeInfo {
            memory_source: if cfg!(target_os = "linux") {
                "linux_proc_status"
            } else {
                "unavailable"
            },
            memory_values_are_xray_go_runtime_equivalents: false,
            garbage_collector: "none",
            traffic_stats_enabled: cfg!(feature = "traffic"),
        },
    };
    match serde_json::to_vec(&body) {
        Ok(body) => (
            StatusCode::OK,
            [("content-type", "application/json; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to serialize metrics response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn traffic_stats() -> Stats {
    let mut stats = Stats {
        inbound: HashMap::new(),
        outbound: HashMap::new(),
        user: HashMap::new(),
    };
    #[cfg(feature = "traffic")]
    {
        let snapshot = crate::traffic::snapshot();
        for (tag, totals) in snapshot.per_inbound {
            stats.inbound.insert(
                tag,
                HashMap::from([
                    ("uplink".into(), totals.upload_bytes as i64),
                    ("downlink".into(), totals.download_bytes as i64),
                ]),
            );
        }
        for (tag, totals) in snapshot.per_outbound {
            stats.outbound.insert(
                tag,
                HashMap::from([
                    ("uplink".into(), totals.upload_bytes as i64),
                    ("downlink".into(), totals.download_bytes as i64),
                ]),
            );
        }
        let mut user_totals = HashMap::<String, (u64, u64)>::new();
        for ((_, identity), totals) in snapshot.per_inbound_user {
            let entry = user_totals.entry(identity).or_default();
            entry.0 = entry.0.saturating_add(totals.upload_bytes);
            entry.1 = entry.1.saturating_add(totals.download_bytes);
        }
        for identity in snapshot.known_identities {
            user_totals.entry(identity).or_default();
        }
        for (identity, (upload, download)) in user_totals {
            stats.user.insert(
                identity,
                HashMap::from([
                    ("uplink".into(), upload as i64),
                    ("downlink".into(), download as i64),
                ]),
            );
        }
    }
    stats
}

#[cfg(target_os = "linux")]
async fn process_memory_bytes() -> (u64, u64) {
    // Linux-only process memory source. Other OSes need a native process
    // metrics adapter before these values can be widened beyond zero.
    let Ok(status) = tokio::fs::read_to_string("/proc/self/status").await else {
        return (0, 0);
    };
    let mut resident = 0;
    let mut virtual_size = 0;
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let Some(kibibytes) = value
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        match name {
            "VmRSS" => resident = kibibytes.saturating_mul(1024),
            "VmSize" => virtual_size = kibibytes.saturating_mul(1024),
            _ => {}
        }
    }
    (resident, virtual_size)
}

#[cfg(not(target_os = "linux"))]
async fn process_memory_bytes() -> (u64, u64) {
    // Non-Linux process metrics are not implemented or verified yet.
    (0, 0)
}
