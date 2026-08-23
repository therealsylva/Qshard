#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use qchain_protocol::{NodeRegistration, NodeRole, NodeStatus};
use qshard_core::SignedManifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const REQUIRED_WHITE_NODES: usize = 2;
pub const REQUIRED_GREY_NODES: usize = 8;
pub const TOTAL_REPLICAS: usize = 10;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("node registration is invalid")]
    InvalidNode,
    #[error("node {0} is already registered with conflicting metadata")]
    ConflictingNode(Uuid),
    #[error("insufficient healthy storage nodes: require two White and eight Grey nodes")]
    InsufficientNodes,
    #[error("credential manifest is invalid")]
    InvalidManifest,
    #[error("credential set already exists")]
    SetAlreadyExists,
    #[error("credential set was not found")]
    SetNotFound,
    #[error("control key is not authorized")]
    Unauthorized,
    #[error("replica was not found")]
    ReplicaNotFound,
    #[error("repair cannot be scheduled")]
    RepairUnavailable,
    #[error("request was already processed")]
    Replay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecord {
    pub registration: NodeRegistration,
    pub status: NodeStatus,
    pub used_bytes: u64,
    pub last_seen_unix: i64,
}

impl NodeRecord {
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        self.registration
            .capacity_bytes
            .saturating_sub(self.used_bytes)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetStatus {
    Uploading,
    Active,
    Recovering,
    Reseeding,
    Retiring,
    Deleted,
    Degraded,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaStatus {
    Planned,
    Available,
    Suspect,
    Lost,
    Deleting,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplicaRecord {
    pub object_id: Uuid,
    pub share_id: Uuid,
    pub share_index: u8,
    pub node_id: Uuid,
    pub generation: u64,
    pub sha256: [u8; 32],
    pub encoded_len: u32,
    pub status: ReplicaStatus,
    pub verified_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetRecord {
    pub manifest: SignedManifest,
    pub generation: u64,
    pub status: SetStatus,
    pub replicas: Vec<ReplicaRecord>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepairLease {
    pub lease_id: Uuid,
    pub set_id: Uuid,
    pub share_index: u8,
    pub source_node_id: Uuid,
    pub destination_node_id: Uuid,
    pub replacement_object_id: Uuid,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryState {
    pub revision: u64,
    pub nodes: BTreeMap<Uuid, NodeRecord>,
    pub sets: BTreeMap<Uuid, SetRecord>,
    pub repair_leases: BTreeMap<Uuid, RepairLease>,
    pub tombstones: BTreeMap<Uuid, i64>,
    #[serde(default)]
    pub tombstone_owners: BTreeMap<Uuid, [u8; 32]>,
    #[serde(default)]
    pub tombstone_generations: BTreeMap<Uuid, u64>,
    pub processed_requests: BTreeMap<Uuid, i64>,
}

impl RegistryState {
    pub fn claim_request(
        &mut self,
        request_id: Uuid,
        expires_at_unix: i64,
    ) -> Result<(), RegistryError> {
        let now = Utc::now().timestamp();
        self.processed_requests.retain(|_, expires| *expires >= now);
        if self.processed_requests.contains_key(&request_id) {
            return Err(RegistryError::Replay);
        }
        self.processed_requests.insert(request_id, expires_at_unix);
        self.bump_revision();
        Ok(())
    }

    pub fn register_node(&mut self, registration: NodeRegistration) -> Result<(), RegistryError> {
        registration
            .validate()
            .map_err(|_| RegistryError::InvalidNode)?;
        if registration.role == NodeRole::Blue {
            return Err(RegistryError::InvalidNode);
        }
        if registration.role == NodeRole::White && registration.role_certificate.is_none() {
            return Err(RegistryError::InvalidNode);
        }
        if let Some(existing) = self.nodes.get(&registration.node_id) {
            if existing.registration != registration {
                return Err(RegistryError::ConflictingNode(registration.node_id));
            }
            return Ok(());
        }
        self.nodes.insert(
            registration.node_id,
            NodeRecord {
                registration,
                status: NodeStatus::Healthy,
                used_bytes: 0,
                last_seen_unix: Utc::now().timestamp(),
            },
        );
        self.bump_revision();
        Ok(())
    }

    pub fn heartbeat(&mut self, node_id: Uuid, used_bytes: u64) -> Result<(), RegistryError> {
        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or(RegistryError::InvalidNode)?;
        node.used_bytes = used_bytes.min(node.registration.capacity_bytes);
        node.last_seen_unix = Utc::now().timestamp();
        node.status = NodeStatus::Healthy;
        self.bump_revision();
        Ok(())
    }

    pub fn plan_set(
        &mut self,
        manifest: SignedManifest,
        generation: u64,
    ) -> Result<SetRecord, RegistryError> {
        manifest
            .verify()
            .map_err(|_| RegistryError::InvalidManifest)?;
        if manifest.manifest.shares.len() != 5 || generation == 0 {
            return Err(RegistryError::InvalidManifest);
        }
        if self.sets.contains_key(&manifest.manifest.set_id)
            || self.tombstones.contains_key(&manifest.manifest.set_id)
        {
            return Err(RegistryError::SetAlreadyExists);
        }
        let white = self.select_nodes(
            NodeRole::White,
            REQUIRED_WHITE_NODES,
            manifest.manifest.set_id,
        )?;
        let grey = self.select_nodes(
            NodeRole::Grey,
            REQUIRED_GREY_NODES,
            manifest.manifest.set_id,
        )?;
        let descriptors: BTreeMap<u8, _> = manifest
            .manifest
            .shares
            .iter()
            .map(|share| (share.share_index, share))
            .collect();
        if descriptors.len() != 5 {
            return Err(RegistryError::InvalidManifest);
        }
        let assignments = [
            (1_u8, white[0]),
            (2_u8, white[1]),
            (1_u8, grey[0]),
            (2_u8, grey[1]),
            (3_u8, grey[2]),
            (3_u8, grey[3]),
            (4_u8, grey[4]),
            (4_u8, grey[5]),
            (5_u8, grey[6]),
            (5_u8, grey[7]),
        ];
        let mut replicas = Vec::with_capacity(TOTAL_REPLICAS);
        for (share_index, node_id) in assignments {
            let descriptor = descriptors
                .get(&share_index)
                .ok_or(RegistryError::InvalidManifest)?;
            replicas.push(ReplicaRecord {
                object_id: Uuid::new_v4(),
                share_id: descriptor.share_id,
                share_index,
                node_id,
                generation,
                sha256: descriptor.sha256,
                encoded_len: descriptor.encoded_len,
                status: ReplicaStatus::Planned,
                verified_at_unix: None,
            });
        }
        let distinct_nodes: BTreeSet<_> = replicas.iter().map(|replica| replica.node_id).collect();
        if distinct_nodes.len() != TOTAL_REPLICAS {
            return Err(RegistryError::InsufficientNodes);
        }
        let now = Utc::now().timestamp();
        let record = SetRecord {
            manifest,
            generation,
            status: SetStatus::Uploading,
            replicas,
            created_at_unix: now,
            updated_at_unix: now,
        };
        self.sets
            .insert(record.manifest.manifest.set_id, record.clone());
        self.bump_revision();
        Ok(record)
    }

    pub fn activate_set(&mut self, set_id: Uuid) -> Result<(), RegistryError> {
        let set = self
            .sets
            .get_mut(&set_id)
            .ok_or(RegistryError::SetNotFound)?;
        if set.replicas.len() != TOTAL_REPLICAS {
            return Err(RegistryError::InvalidManifest);
        }
        let now = Utc::now().timestamp();
        for replica in &mut set.replicas {
            replica.status = ReplicaStatus::Available;
            replica.verified_at_unix = Some(now);
        }
        set.status = SetStatus::Active;
        set.updated_at_unix = now;
        self.bump_revision();
        Ok(())
    }

    pub fn abort_set(&mut self, set_id: Uuid) -> Result<(), RegistryError> {
        let set = self.sets.get(&set_id).ok_or(RegistryError::SetNotFound)?;
        if set.status != SetStatus::Uploading {
            return Err(RegistryError::InvalidManifest);
        }
        self.sets.remove(&set_id);
        self.bump_revision();
        Ok(())
    }

    pub fn authorize_set(
        &self,
        set_id: Uuid,
        signer: &[u8; 32],
    ) -> Result<&SetRecord, RegistryError> {
        let set = self.sets.get(&set_id).ok_or(RegistryError::SetNotFound)?;
        if &set.manifest.manifest.control_public_key != signer {
            return Err(RegistryError::Unauthorized);
        }
        Ok(set)
    }

    pub fn authorize_tombstone(
        &self,
        set_id: Uuid,
        signer: &[u8; 32],
    ) -> Result<u64, RegistryError> {
        if !self.tombstones.contains_key(&set_id) {
            return Err(RegistryError::SetNotFound);
        }
        if self.tombstone_owners.get(&set_id) != Some(signer) {
            return Err(RegistryError::Unauthorized);
        }
        Ok(self
            .tombstone_generations
            .get(&set_id)
            .copied()
            .unwrap_or(1))
    }

    pub fn mark_node_lost(&mut self, node_id: Uuid) -> Result<Vec<(Uuid, u8)>, RegistryError> {
        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or(RegistryError::InvalidNode)?;
        node.status = NodeStatus::Lost;
        let mut affected = Vec::new();
        for (set_id, set) in &mut self.sets {
            let mut set_affected = false;
            for replica in &mut set.replicas {
                if replica.node_id == node_id && replica.status == ReplicaStatus::Available {
                    replica.status = ReplicaStatus::Lost;
                    affected.push((*set_id, replica.share_index));
                    set_affected = true;
                }
            }
            if set_affected {
                let available_indices: BTreeSet<_> = set
                    .replicas
                    .iter()
                    .filter(|replica| replica.status == ReplicaStatus::Available)
                    .map(|replica| replica.share_index)
                    .collect();
                set.status = if available_indices.len() < 3 {
                    SetStatus::Critical
                } else {
                    SetStatus::Degraded
                };
                set.updated_at_unix = Utc::now().timestamp();
            }
        }
        self.bump_revision();
        Ok(affected)
    }

    pub fn mark_node_healthy(&mut self, node_id: Uuid) -> Result<(), RegistryError> {
        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or(RegistryError::InvalidNode)?;
        node.status = NodeStatus::Healthy;
        node.last_seen_unix = Utc::now().timestamp();
        self.bump_revision();
        Ok(())
    }

    pub fn mark_node_suspect(&mut self, node_id: Uuid) -> Result<(), RegistryError> {
        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or(RegistryError::InvalidNode)?;
        if node.status == NodeStatus::Healthy {
            node.status = NodeStatus::Suspect;
            self.bump_revision();
        }
        Ok(())
    }

    pub fn mark_replica_lost(
        &mut self,
        set_id: Uuid,
        object_id: Uuid,
    ) -> Result<(), RegistryError> {
        let set = self
            .sets
            .get_mut(&set_id)
            .ok_or(RegistryError::SetNotFound)?;
        let replica = set
            .replicas
            .iter_mut()
            .find(|replica| replica.object_id == object_id)
            .ok_or(RegistryError::ReplicaNotFound)?;
        replica.status = ReplicaStatus::Lost;
        let available_indices = set
            .replicas
            .iter()
            .filter(|replica| replica.status == ReplicaStatus::Available)
            .map(|replica| replica.share_index)
            .collect::<BTreeSet<_>>();
        set.status = if available_indices.len() < 3 {
            SetStatus::Critical
        } else {
            SetStatus::Degraded
        };
        set.updated_at_unix = Utc::now().timestamp();
        self.bump_revision();
        Ok(())
    }

    pub fn plan_repairs_for_node(
        &mut self,
        lost_node_id: Uuid,
        lease_seconds: i64,
    ) -> Result<Vec<RepairLease>, RegistryError> {
        let lost_role = self
            .nodes
            .get(&lost_node_id)
            .ok_or(RegistryError::InvalidNode)?
            .registration
            .role;
        let affected = self
            .sets
            .iter()
            .flat_map(|(set_id, set)| {
                set.replicas
                    .iter()
                    .filter(move |replica| {
                        replica.node_id == lost_node_id && replica.status == ReplicaStatus::Lost
                    })
                    .map(move |replica| (*set_id, replica.share_index))
            })
            .collect::<Vec<_>>();
        let mut leases = Vec::new();
        for (set_id, share_index) in affected {
            if self
                .repair_leases
                .values()
                .any(|lease| lease.set_id == set_id && lease.share_index == share_index)
            {
                continue;
            }
            let set = self.sets.get(&set_id).ok_or(RegistryError::SetNotFound)?;
            let Some(source_node_id) = set
                .replicas
                .iter()
                .find(|replica| {
                    replica.share_index == share_index && replica.status == ReplicaStatus::Available
                })
                .map(|replica| replica.node_id)
            else {
                continue;
            };
            let occupied = set
                .replicas
                .iter()
                .map(|replica| replica.node_id)
                .collect::<BTreeSet<_>>();
            let Some(destination_node_id) = self
                .ranked_nodes(lost_role, set_id)
                .into_iter()
                .find(|node_id| !occupied.contains(node_id))
            else {
                continue;
            };
            let lease = RepairLease {
                lease_id: Uuid::new_v4(),
                set_id,
                share_index,
                source_node_id,
                destination_node_id,
                replacement_object_id: Uuid::new_v4(),
                expires_at_unix: Utc::now().timestamp().saturating_add(lease_seconds.max(30)),
            };
            self.repair_leases.insert(lease.lease_id, lease.clone());
            leases.push(lease);
        }
        if !leases.is_empty() {
            self.bump_revision();
        }
        Ok(leases)
    }

    pub fn complete_repair(&mut self, lease_id: Uuid) -> Result<ReplicaRecord, RegistryError> {
        let lease = self
            .repair_leases
            .remove(&lease_id)
            .ok_or(RegistryError::RepairUnavailable)?;
        if lease.expires_at_unix < Utc::now().timestamp() {
            return Err(RegistryError::RepairUnavailable);
        }
        let set = self
            .sets
            .get_mut(&lease.set_id)
            .ok_or(RegistryError::SetNotFound)?;
        let source = set
            .replicas
            .iter()
            .find(|replica| {
                replica.node_id == lease.source_node_id
                    && replica.share_index == lease.share_index
                    && replica.status == ReplicaStatus::Available
            })
            .cloned()
            .ok_or(RegistryError::RepairUnavailable)?;
        if let Some(lost) = set.replicas.iter_mut().find(|replica| {
            replica.share_index == lease.share_index && replica.status == ReplicaStatus::Lost
        }) {
            lost.status = ReplicaStatus::Deleted;
        }
        let replacement = ReplicaRecord {
            object_id: lease.replacement_object_id,
            share_id: source.share_id,
            share_index: source.share_index,
            node_id: lease.destination_node_id,
            generation: source.generation,
            sha256: source.sha256,
            encoded_len: source.encoded_len,
            status: ReplicaStatus::Available,
            verified_at_unix: Some(Utc::now().timestamp()),
        };
        set.replicas.push(replacement.clone());
        let available = set
            .replicas
            .iter()
            .filter(|replica| replica.status == ReplicaStatus::Available)
            .collect::<Vec<_>>();
        let available_indices = available
            .iter()
            .map(|replica| replica.share_index)
            .collect::<BTreeSet<_>>();
        set.status = if available.len() >= TOTAL_REPLICAS && available_indices.len() == 5 {
            SetStatus::Active
        } else if available_indices.len() < 3 {
            SetStatus::Critical
        } else {
            SetStatus::Degraded
        };
        set.updated_at_unix = Utc::now().timestamp();
        self.bump_revision();
        Ok(replacement)
    }

    pub fn fail_repair(&mut self, lease_id: Uuid) -> Result<(), RegistryError> {
        self.repair_leases
            .remove(&lease_id)
            .ok_or(RegistryError::RepairUnavailable)?;
        self.bump_revision();
        Ok(())
    }

    pub fn begin_delete_set(
        &mut self,
        set_id: Uuid,
        signer: &[u8; 32],
    ) -> Result<Vec<ReplicaRecord>, RegistryError> {
        self.authorize_set(set_id, signer)?;
        let set = self
            .sets
            .get_mut(&set_id)
            .ok_or(RegistryError::SetNotFound)?;
        set.status = SetStatus::Retiring;
        for replica in &mut set.replicas {
            if replica.status != ReplicaStatus::Lost && replica.status != ReplicaStatus::Deleted {
                replica.status = ReplicaStatus::Deleting;
            }
        }
        set.updated_at_unix = Utc::now().timestamp();
        let replicas = set.replicas.clone();
        self.bump_revision();
        Ok(replicas)
    }

    pub fn mark_replica_deleted(
        &mut self,
        set_id: Uuid,
        object_id: Uuid,
    ) -> Result<(), RegistryError> {
        let set = self
            .sets
            .get_mut(&set_id)
            .ok_or(RegistryError::SetNotFound)?;
        let replica = set
            .replicas
            .iter_mut()
            .find(|replica| replica.object_id == object_id)
            .ok_or(RegistryError::ReplicaNotFound)?;
        replica.status = ReplicaStatus::Deleted;
        set.updated_at_unix = Utc::now().timestamp();
        self.bump_revision();
        Ok(())
    }

    pub fn finalize_delete_set(&mut self, set_id: Uuid) -> Result<(), RegistryError> {
        let set = self.sets.get(&set_id).ok_or(RegistryError::SetNotFound)?;
        if set.status != SetStatus::Retiring
            || set.replicas.iter().any(|replica| {
                !matches!(replica.status, ReplicaStatus::Deleted | ReplicaStatus::Lost)
            })
        {
            return Err(RegistryError::ReplicaNotFound);
        }
        let owner = set.manifest.manifest.control_public_key;
        let generation = set.generation;
        self.sets.remove(&set_id);
        self.tombstones.insert(set_id, Utc::now().timestamp());
        self.tombstone_owners.insert(set_id, owner);
        self.tombstone_generations.insert(set_id, generation);
        self.bump_revision();
        Ok(())
    }

    pub fn delete_set(
        &mut self,
        set_id: Uuid,
        signer: &[u8; 32],
    ) -> Result<Vec<ReplicaRecord>, RegistryError> {
        self.begin_delete_set(set_id, signer)
    }

    fn select_nodes(
        &self,
        role: NodeRole,
        count: usize,
        set_id: Uuid,
    ) -> Result<Vec<Uuid>, RegistryError> {
        let selected = self.ranked_nodes(role, set_id);
        if selected.len() < count {
            return Err(RegistryError::InsufficientNodes);
        }
        Ok(selected.into_iter().take(count).collect())
    }

    fn ranked_nodes(&self, role: NodeRole, set_id: Uuid) -> Vec<Uuid> {
        let mut candidates: Vec<_> = self
            .nodes
            .values()
            .filter(|node| {
                node.registration.role == role
                    && node.status == NodeStatus::Healthy
                    && node.available_bytes() >= 128 * 1024
            })
            .map(|node| {
                let mut hasher = Sha256::new();
                hasher.update(set_id.as_bytes());
                hasher.update(node.registration.node_id.as_bytes());
                let score: [u8; 32] = hasher.finalize().into();
                (
                    score,
                    node.registration.node_id,
                    node.registration.failure_domain.clone(),
                )
            })
            .collect();
        candidates.sort_by_key(|candidate| candidate.0);
        let mut selected = Vec::with_capacity(candidates.len());
        let mut domains = BTreeSet::new();
        for (_, node_id, domain) in &candidates {
            if domains.insert(domain.clone()) {
                selected.push(*node_id);
            }
        }
        for (_, node_id, _) in candidates {
            if !selected.contains(&node_id) {
                selected.push(node_id);
            }
        }
        selected
    }

    fn bump_revision(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use qchain_protocol::NodeRegistration;
    use qshard_core::{CredentialBundle, RecoverySeed, create_credential_bundle};

    use super::*;

    fn node(role: NodeRole, index: usize) -> NodeRegistration {
        NodeRegistration {
            node_id: Uuid::new_v4(),
            role,
            endpoint: format!("http://127.0.0.1:{}", 10_000 + index),
            failure_domain: format!("domain-{index}"),
            capacity_bytes: 10 * 1024 * 1024,
            identity_public_key: [u8::try_from(index).unwrap_or(0); 32],
            role_certificate: (role == NodeRole::White)
                .then(|| "curated-test-certificate".to_owned()),
        }
    }

    fn registry_with_spares() -> Result<RegistryState, RegistryError> {
        let mut registry = RegistryState::default();
        for index in 0..3 {
            registry.register_node(node(NodeRole::White, index))?;
        }
        for index in 3..12 {
            registry.register_node(node(NodeRole::Grey, index))?;
        }
        Ok(registry)
    }

    fn bundle() -> Result<CredentialBundle, qshard_core::QshardError> {
        create_credential_bundle(
            b"credential",
            &RecoverySeed::generate(),
            "qchain-test",
            None,
        )
    }

    #[test]
    fn placement_uses_ten_nodes_and_two_different_white_shares()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = RegistryState::default();
        for index in 0..2 {
            registry.register_node(node(NodeRole::White, index))?;
        }
        for index in 2..10 {
            registry.register_node(node(NodeRole::Grey, index))?;
        }
        let seed = RecoverySeed::generate();
        let bundle = create_credential_bundle(b"credential", &seed, "qchain-test", None)?;
        let set = registry.plan_set(bundle.signed_manifest, 1)?;
        let unique_nodes: BTreeSet<_> =
            set.replicas.iter().map(|replica| replica.node_id).collect();
        assert_eq!(unique_nodes.len(), 10);
        let white_indices: BTreeSet<_> = set
            .replicas
            .iter()
            .filter(|replica| registry.nodes[&replica.node_id].registration.role == NodeRole::White)
            .map(|replica| replica.share_index)
            .collect();
        assert_eq!(white_indices, BTreeSet::from([1, 2]));
        Ok(())
    }

    #[test]
    fn replay_claim_is_rejected_and_expired_claims_are_pruned()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = RegistryState::default();
        let request_id = Uuid::new_v4();
        registry.claim_request(request_id, Utc::now().timestamp() + 60)?;
        assert!(matches!(
            registry.claim_request(request_id, Utc::now().timestamp() + 60),
            Err(RegistryError::Replay)
        ));

        let expired = Uuid::new_v4();
        registry.processed_requests.insert(expired, 0);
        registry.claim_request(Uuid::new_v4(), Utc::now().timestamp() + 60)?;
        assert!(!registry.processed_requests.contains_key(&expired));
        Ok(())
    }

    #[test]
    fn lost_replica_is_repaired_to_a_distinct_spare_node() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut registry = registry_with_spares()?;
        let credential = bundle()?;
        let set_id = credential.signed_manifest.manifest.set_id;
        let planned = registry.plan_set(credential.signed_manifest, 1)?;
        registry.activate_set(set_id)?;
        let lost = planned
            .replicas
            .iter()
            .find(|replica| registry.nodes[&replica.node_id].registration.role == NodeRole::Grey)
            .ok_or(RegistryError::ReplicaNotFound)?
            .clone();
        registry.mark_node_lost(lost.node_id)?;
        assert_eq!(registry.sets[&set_id].status, SetStatus::Degraded);

        let leases = registry.plan_repairs_for_node(lost.node_id, 120)?;
        assert_eq!(leases.len(), 1);
        let lease = &leases[0];
        assert_eq!(lease.share_index, lost.share_index);
        assert_ne!(lease.destination_node_id, lost.node_id);
        assert!(
            planned
                .replicas
                .iter()
                .all(|replica| replica.node_id != lease.destination_node_id)
        );
        let replacement = registry.complete_repair(lease.lease_id)?;
        assert_eq!(replacement.share_index, lost.share_index);
        assert_eq!(registry.sets[&set_id].status, SetStatus::Active);
        assert_eq!(
            registry.sets[&set_id]
                .replicas
                .iter()
                .filter(|replica| replica.status == ReplicaStatus::Available)
                .count(),
            TOTAL_REPLICAS
        );
        Ok(())
    }

    #[test]
    fn deletion_is_committed_before_tombstone_finalization()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = registry_with_spares()?;
        let credential = bundle()?;
        let set_id = credential.signed_manifest.manifest.set_id;
        let owner = credential.signed_manifest.manifest.control_public_key;
        registry.plan_set(credential.signed_manifest, 1)?;
        registry.activate_set(set_id)?;

        let replicas = registry.begin_delete_set(set_id, &owner)?;
        assert_eq!(registry.sets[&set_id].status, SetStatus::Retiring);
        assert!(registry.finalize_delete_set(set_id).is_err());
        for replica in replicas {
            registry.mark_replica_deleted(set_id, replica.object_id)?;
        }
        registry.finalize_delete_set(set_id)?;
        assert!(!registry.sets.contains_key(&set_id));
        assert!(registry.tombstones.contains_key(&set_id));
        assert_eq!(registry.authorize_tombstone(set_id, &owner)?, 1);
        assert!(registry.authorize_tombstone(set_id, &[0x55; 32]).is_err());
        Ok(())
    }
}
