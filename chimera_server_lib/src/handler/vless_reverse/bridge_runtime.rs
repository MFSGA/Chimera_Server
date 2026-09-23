use std::{sync::Arc, time::Duration};

use tokio::{task::JoinHandle, time::sleep};

use crate::{
    outbound::{
        VlessReverseBridgeEndpoint, connect_vless_reverse_bridge,
        prepare_vless_reverse_bridge,
    },
    runtime::{DataPlaneRuntime, OutboundSummary},
};

use super::bridge_worker::{
    BridgeDispatchContext, BridgeTcpDispatcher, MuxServerWorker,
};

const XRAY_BRIDGE_MONITOR_INTERVAL: Duration = Duration::from_secs(2);
const XRAY_BRIDGE_MAX_AVERAGE_CONNECTIONS: usize = 16;

#[derive(Debug, Clone)]
pub(crate) struct ReverseBridgePlan {
    pub(crate) outbound_tag: String,
    pub(crate) outbound: OutboundSummary,
    pub(crate) endpoint: VlessReverseBridgeEndpoint,
}

pub(crate) fn prepare_reverse_bridge_plans(
    outbounds: &[OutboundSummary],
) -> std::io::Result<Vec<ReverseBridgePlan>> {
    let mut plans = Vec::new();
    for outbound in outbounds {
        let Some(endpoint) = prepare_vless_reverse_bridge(outbound)? else {
            continue;
        };
        plans.push(ReverseBridgePlan {
            outbound_tag: outbound.tag.clone(),
            outbound: outbound.clone(),
            endpoint,
        });
    }
    Ok(plans)
}

pub(crate) fn start_reverse_bridge_monitors(
    runtime: DataPlaneRuntime,
    plans: Vec<ReverseBridgePlan>,
) -> Vec<JoinHandle<()>> {
    plans
        .into_iter()
        .map(|plan| {
            let runtime = runtime.clone();
            tokio::spawn(async move {
                // Current Xray simplified VLESS Reverse waits two seconds
                // before starting its periodic Bridge monitor.
                sleep(XRAY_BRIDGE_MONITOR_INTERVAL).await;
                run_bridge_monitor(runtime, plan).await;
            })
        })
        .collect()
}

async fn run_bridge_monitor(runtime: DataPlaneRuntime, plan: ReverseBridgePlan) {
    let resolver = runtime.resolver();
    let dispatcher: Arc<dyn BridgeTcpDispatcher> = Arc::new(runtime);
    let mut workers = Vec::<MuxServerWorker>::new();
    let mut previous_state = None;
    let mut successful_dials = 0u64;
    let mut consecutive_failures = 0u64;

    loop {
        let before_retain = workers.len();
        workers.retain(|worker| !worker.closed());
        let removed_workers = before_retain.saturating_sub(workers.len());

        let mut active_workers = 0usize;
        let mut active_connections = 0usize;
        for worker in &workers {
            if worker.is_active() {
                active_workers += 1;
                active_connections += worker.active_connections();
            }
        }

        let state = (workers.len(), active_workers, active_connections);
        if previous_state != Some(state) || removed_workers != 0 {
            tracing::debug!(
                event = "vless_reverse_bridge_state",
                outbound_tag = %plan.outbound_tag,
                reverse_tag = %plan.endpoint.reverse_tag,
                worker_count = state.0,
                active_workers = state.1,
                active_sessions = state.2,
                removed_workers,
                "VLESS Reverse Bridge monitor state changed"
            );
            previous_state = Some(state);
        }

        if should_add_worker(active_workers, active_connections) {
            let dial_reason = if active_workers == 0 {
                if successful_dials == 0 {
                    "initial"
                } else {
                    "reconnect"
                }
            } else {
                "scale"
            };
            match connect_vless_reverse_bridge(
                &resolver,
                &plan.outbound,
                &plan.endpoint,
            )
            .await
            {
                Ok(physical) => {
                    successful_dials = successful_dials.saturating_add(1);
                    let recovered_after_failures = consecutive_failures;
                    consecutive_failures = 0;
                    workers.push(MuxServerWorker::new_with_context(
                        physical,
                        plan.endpoint.reverse_tag.clone(),
                        dispatcher.clone(),
                        BridgeDispatchContext {
                            sniffing: plan.endpoint.sniffing.clone(),
                            routing_user: plan.endpoint.routing_user.clone(),
                            policy_identity: plan.endpoint.policy_identity.clone(),
                            user_level: plan.endpoint.user_level,
                        },
                    ));
                    tracing::info!(
                        event = "vless_reverse_bridge_worker_connected",
                        outbound_tag = %plan.outbound_tag,
                        reverse_tag = %plan.endpoint.reverse_tag,
                        dial_reason,
                        worker_count = workers.len(),
                        recovered_after_failures,
                        "connected VLESS Reverse Bridge worker"
                    );
                }
                Err(error) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    tracing::warn!(
                        event = "vless_reverse_bridge_worker_connect_failed",
                        outbound_tag = %plan.outbound_tag,
                        reverse_tag = %plan.endpoint.reverse_tag,
                        dial_reason,
                        consecutive_failures,
                        %error,
                        "failed to create VLESS Reverse Bridge worker"
                    );
                }
            }
        }

        sleep(XRAY_BRIDGE_MONITOR_INTERVAL).await;
    }
}

fn should_add_worker(active_workers: usize, active_connections: usize) -> bool {
    active_workers == 0
        || active_connections / active_workers > XRAY_BRIDGE_MAX_AVERAGE_CONNECTIONS
}

#[cfg(test)]
mod tests {
    use crate::{
        address::Address, config::def::OutboundItem,
        outbound::compile_static_outbound,
    };

    use super::*;

    #[test]
    fn monitor_scaling_matches_xray_average_connection_threshold() {
        assert!(should_add_worker(0, 0));
        assert!(!should_add_worker(1, 16));
        assert!(should_add_worker(1, 17));
        assert!(!should_add_worker(2, 33));
        assert!(should_add_worker(2, 34));
    }

    fn reverse_outbound_with_stream_settings(
        stream_settings: serde_json::Value,
    ) -> OutboundSummary {
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "tag": "reverse",
            "protocol": "vless",
            "settings": {
                "address": "127.0.0.1",
                "port": 443,
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                "encryption": "none",
                "reverse": {"tag": "bridge-in"}
            },
            "streamSettings": stream_settings
        }))
        .expect("parse Reverse Bridge outbound");
        compile_static_outbound(&item).expect("compile Reverse Bridge outbound")
    }

    #[test]
    fn plan_collection_finds_only_reverse_vless_outbounds() {
        let reverse_item: OutboundItem = serde_json::from_value(serde_json::json!({
            "tag": "reverse",
            "protocol": "vless",
            "settings": {
                "address": "127.0.0.1",
                "port": 443,
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                "encryption": "none",
                "reverse": {"tag": "bridge-in"}
            }
        }))
        .expect("parse Reverse Bridge outbound");
        let direct_item: OutboundItem = serde_json::from_value(serde_json::json!({
            "tag": "direct",
            "protocol": "freedom"
        }))
        .expect("parse freedom outbound");
        let reverse =
            compile_static_outbound(&reverse_item).expect("compile Reverse Bridge");
        let freedom =
            compile_static_outbound(&direct_item).expect("compile freedom");

        let plans = prepare_reverse_bridge_plans(&[freedom, reverse])
            .expect("prepare Reverse Bridge plans");
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].outbound_tag, "reverse");
        assert_eq!(plans[0].endpoint.reverse_tag, "bridge-in");
        assert_eq!(
            plans[0].endpoint.server.address(),
            &Address::Ipv4(std::net::Ipv4Addr::LOCALHOST)
        );
    }

    #[cfg(feature = "ws")]
    #[test]
    fn plan_accepts_websocket_without_early_data() {
        let outbound = reverse_outbound_with_stream_settings(serde_json::json!({
            "network": "ws",
            "wsSettings": {"path": "/reverse"}
        }));
        let plans = prepare_reverse_bridge_plans(&[outbound])
            .expect("WebSocket Reverse Bridge should be supported");
        assert_eq!(plans.len(), 1);
    }

    #[cfg(feature = "ws")]
    #[test]
    fn plan_rejects_websocket_early_data_until_handshake_can_carry_it() {
        let outbound = reverse_outbound_with_stream_settings(serde_json::json!({
            "network": "ws",
            "wsSettings": {"path": "/reverse?ed=64"}
        }));
        let error = prepare_reverse_bridge_plans(&[outbound])
            .expect_err("WebSocket early data must fail closed");
        assert!(error.to_string().contains("early data"));
    }
}
