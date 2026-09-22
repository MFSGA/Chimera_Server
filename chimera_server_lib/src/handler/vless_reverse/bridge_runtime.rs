use std::{sync::Arc, time::Duration};

use tokio::{task::JoinHandle, time::sleep};

use crate::{
    outbound::{
        VlessReverseBridgeEndpoint, connect_vless_reverse_bridge,
        prepare_vless_reverse_bridge,
    },
    runtime::{DataPlaneRuntime, OutboundSummary},
};

use super::bridge_worker::{BridgeTcpDispatcher, MuxServerWorker};

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

    loop {
        workers.retain(|worker| !worker.closed());

        let mut active_workers = 0usize;
        let mut active_connections = 0usize;
        for worker in &workers {
            if worker.is_active() {
                active_workers += 1;
                active_connections += worker.active_connections();
            }
        }

        if should_add_worker(active_workers, active_connections) {
            match connect_vless_reverse_bridge(
                &resolver,
                &plan.outbound,
                &plan.endpoint,
            )
            .await
            {
                Ok(physical) => {
                    workers.push(MuxServerWorker::new(
                        physical,
                        plan.endpoint.reverse_tag.clone(),
                        dispatcher.clone(),
                    ));
                }
                Err(error) => {
                    tracing::warn!(
                        outbound_tag = %plan.outbound_tag,
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
}
