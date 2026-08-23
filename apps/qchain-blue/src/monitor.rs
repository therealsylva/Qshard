#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use actix_web::web::Data;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use qchain_protocol::NodeStatus;
use qchain_registry::{RegistryState, ReplicaRecord, ReplicaStatus, SetStatus};
use tracing::{debug, error, info, warn};

use crate::state::BlueState;

pub async fn run(state: Data<BlueState>) {
    let mut interval = tokio::time::interval(state.audit_interval.max(Duration::from_secs(10)));
    loop {
        interval.tick().await;
        if let Err(error) = cycle(&state).await {
            debug!(%error, "monitor cycle skipped");
        }
    }
}

async fn cycle(state: &BlueState) -> anyhow::Result<()> {
    let _guard = state.mutation.lock().await;
    let mut registry = state.read_registry(true).await?;
    let mut committed_revision = registry.revision;
    let mut changed = false;
    let now = Instant::now();
    let node_ids = registry.nodes.keys().copied().collect::<Vec<_>>();
    for node_id in node_ids {
        let elapsed = state.live_nodes.get(&node_id).map_or_else(
            || now.saturating_duration_since(state.started_at),
            |live| now.saturating_duration_since(live.last_seen),
        );
        let status = registry.nodes[&node_id].status;
        if elapsed >= state.lost_after && status != NodeStatus::Lost {
            let affected = registry.mark_node_lost(node_id)?;
            let repairs = registry.plan_repairs_for_node(node_id, 120)?;
            warn!(%node_id, affected = affected.len(), repairs = repairs.len(), "storage node declared lost");
            changed = true;
        } else if elapsed >= state.suspect_after && status == NodeStatus::Healthy {
            registry.mark_node_suspect(node_id)?;
            changed = true;
        }
    }
    if changed {
        state.commit_registry(&registry).await?;
        committed_revision = registry.revision;
    }

    let leases = registry.repair_leases.values().cloned().collect::<Vec<_>>();
    for lease in leases {
        let Some(set) = registry.sets.get(&lease.set_id) else {
            let _ = registry.fail_repair(lease.lease_id);
            continue;
        };
        let Some(source) = set
            .replicas
            .iter()
            .find(|replica| {
                replica.node_id == lease.source_node_id
                    && replica.share_index == lease.share_index
                    && replica.status == ReplicaStatus::Available
            })
            .cloned()
        else {
            let _ = registry.fail_repair(lease.lease_id);
            continue;
        };
        let Some(source_node) = registry.nodes.get(&lease.source_node_id) else {
            let _ = registry.fail_repair(lease.lease_id);
            continue;
        };
        let Some(destination_node) = registry.nodes.get(&lease.destination_node_id) else {
            let _ = registry.fail_repair(lease.lease_id);
            continue;
        };
        let replacement = ReplicaRecord {
            object_id: lease.replacement_object_id,
            share_id: source.share_id,
            share_index: source.share_index,
            node_id: lease.destination_node_id,
            generation: source.generation,
            sha256: source.sha256,
            encoded_len: source.encoded_len,
            status: ReplicaStatus::Planned,
            verified_at_unix: None,
        };
        let result = async {
            let object = state.read_replica(source_node, &source).await?;
            let payload = STANDARD.decode(&object.payload_base64)?;
            state
                .write_replica(
                    destination_node,
                    &replacement,
                    lease.set_id,
                    set.manifest.manifest.control_public_key,
                    &payload,
                )
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(error) = result {
            warn!(%error, lease_id = %lease.lease_id, "replica repair failed and will be replanned");
            registry.fail_repair(lease.lease_id)?;
        } else {
            registry.complete_repair(lease.lease_id)?;
            info!(set_id = %lease.set_id, share_index = lease.share_index, "replica repair committed");
        }
    }

    audit_sample(state, &mut registry).await?;
    retry_retirements(state, &mut registry).await?;
    if registry.revision != committed_revision {
        state.commit_registry(&registry).await?;
    }
    Ok(())
}

async fn audit_sample(state: &BlueState, registry: &mut RegistryState) -> anyhow::Result<()> {
    let samples = registry
        .sets
        .iter()
        .filter(|(_, set)| {
            matches!(
                set.status,
                SetStatus::Active | SetStatus::Degraded | SetStatus::Critical
            )
        })
        .filter_map(|(set_id, set)| {
            let available = set
                .replicas
                .iter()
                .filter(|replica| replica.status == ReplicaStatus::Available)
                .collect::<Vec<_>>();
            if available.is_empty() {
                None
            } else {
                let index = usize::try_from(registry.revision).unwrap_or(0) % available.len();
                Some((*set_id, available[index].clone()))
            }
        })
        .collect::<Vec<_>>();
    for (set_id, replica) in samples {
        let Some(node) = registry.nodes.get(&replica.node_id) else {
            continue;
        };
        match state.audit_replica(node, &replica).await {
            Ok(response) if response.valid => {}
            Ok(_) => {
                error!(%set_id, object_id = %replica.object_id, "replica failed cryptographic audit");
                registry.mark_node_lost(replica.node_id)?;
                let _ = registry.plan_repairs_for_node(replica.node_id, 120)?;
            }
            Err(error) => {
                debug!(%error, %set_id, object_id = %replica.object_id, "replica audit was inconclusive");
            }
        }
    }
    Ok(())
}

async fn retry_retirements(state: &BlueState, registry: &mut RegistryState) -> anyhow::Result<()> {
    let retiring = registry
        .sets
        .iter()
        .filter(|(_, set)| set.status == SetStatus::Retiring)
        .map(|(set_id, set)| (*set_id, set.replicas.clone()))
        .collect::<Vec<_>>();
    for (set_id, replicas) in retiring {
        for replica in replicas {
            if matches!(replica.status, ReplicaStatus::Deleted | ReplicaStatus::Lost) {
                continue;
            }
            let Some(node) = registry.nodes.get(&replica.node_id) else {
                continue;
            };
            if state.delete_replica(node, &replica).await.is_ok() {
                registry.mark_replica_deleted(set_id, replica.object_id)?;
            }
        }
        if registry.finalize_delete_set(set_id).is_ok() {
            info!(%set_id, "credential tombstone finalized");
        }
    }
    Ok(())
}
