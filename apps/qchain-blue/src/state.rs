#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use openraft_sledstore::{ExampleRequest, SledStore};
use qchain_protocol::{
    NodeOperationResponse, SignedEnvelope, StorageAudit, StorageAuditResponse, StorageDelete,
    StorageObject, StorageRead, StorageWrite,
};
use qchain_registry::{NodeRecord, RegistryState, ReplicaRecord};
use reqwest::Client;
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::raft::QchainRaft;

const REGISTRY_KEY: &str = "registry";

#[derive(Debug, Clone)]
pub struct LiveNode {
    pub last_seen: Instant,
    pub available_bytes: u64,
    pub object_count: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RateWindow {
    started: Instant,
    count: u32,
}

pub struct BlueState {
    pub node_id: u64,
    pub raft: QchainRaft,
    pub raft_store: Arc<SledStore>,
    pub identity: Arc<SigningKey>,
    pub client: Client,
    pub live_nodes: DashMap<Uuid, LiveNode>,
    pub started_at: Instant,
    pub trusted_curators: BTreeSet<[u8; 32]>,
    pub cluster_token: String,
    pub admin_token: String,
    pub allow_http: bool,
    pub mutation: Mutex<()>,
    pub(crate) request_rates: DashMap<[u8; 32], RateWindow>,
    pub suspect_after: Duration,
    pub lost_after: Duration,
    pub audit_interval: Duration,
}

impl BlueState {
    pub async fn read_registry(&self, linearizable: bool) -> Result<RegistryState> {
        if linearizable {
            self.raft
                .ensure_linearizable()
                .await
                .context("this Blue node is not the current leader")?;
        }
        let state_machine = self.raft_store.state_machine.read().await;
        let encoded = state_machine
            .get(REGISTRY_KEY)
            .context("failed to read the replicated registry")?;
        encoded.map_or_else(
            || Ok(RegistryState::default()),
            |value| serde_json::from_str(&value).context("the replicated registry is invalid"),
        )
    }

    pub async fn commit_registry(&self, registry: &RegistryState) -> Result<()> {
        let value = serde_json::to_string(registry).context("failed to encode the registry")?;
        self.raft
            .client_write::<tokio::sync::oneshot::error::RecvError>(ExampleRequest::Set {
                key: REGISTRY_KEY.to_owned(),
                value,
            })
            .await
            .context("failed to commit the registry through Raft")?;
        Ok(())
    }

    pub fn rate_limit(&self, signer: [u8; 32], limit_per_minute: u32) -> Result<()> {
        let now = Instant::now();
        if self.request_rates.len() > 100_000 {
            self.request_rates
                .retain(|_, window| now.duration_since(window.started) < Duration::from_secs(120));
        }
        let mut entry = self.request_rates.entry(signer).or_insert(RateWindow {
            started: now,
            count: 0,
        });
        if now.duration_since(entry.started) >= Duration::from_secs(60) {
            *entry = RateWindow {
                started: now,
                count: 0,
            };
        }
        if entry.count >= limit_per_minute {
            bail!("request rate limit exceeded");
        }
        entry.count = entry.count.saturating_add(1);
        Ok(())
    }

    pub async fn write_replica(
        &self,
        node: &NodeRecord,
        replica: &ReplicaRecord,
        set_id: Uuid,
        owner_public_key: [u8; 32],
        payload: &[u8],
    ) -> Result<NodeOperationResponse> {
        let request = StorageWrite {
            object_id: replica.object_id,
            set_id,
            share_index: replica.share_index,
            generation: replica.generation,
            sha256: replica.sha256,
            owner_public_key,
            payload_base64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                payload,
            ),
        };
        match self
            .storage_post(node, "/v1/storage/write", "storage.write", &request)
            .await
        {
            Ok(response) => Ok(response),
            Err(first_error) => self
                .storage_post(node, "/v1/storage/write", "storage.write", &request)
                .await
                .with_context(|| format!("storage write retry failed after: {first_error}")),
        }
    }

    pub async fn read_replica(
        &self,
        node: &NodeRecord,
        replica: &ReplicaRecord,
    ) -> Result<StorageObject> {
        self.storage_post(
            node,
            "/v1/storage/read",
            "storage.read",
            &StorageRead {
                object_id: replica.object_id,
            },
        )
        .await
    }

    pub async fn audit_replica(
        &self,
        node: &NodeRecord,
        replica: &ReplicaRecord,
    ) -> Result<StorageAuditResponse> {
        self.storage_post(
            node,
            "/v1/storage/audit",
            "storage.audit",
            &StorageAudit {
                object_id: replica.object_id,
                expected_sha256: replica.sha256,
            },
        )
        .await
    }

    pub async fn delete_replica(
        &self,
        node: &NodeRecord,
        replica: &ReplicaRecord,
    ) -> Result<NodeOperationResponse> {
        self.storage_post(
            node,
            "/v1/storage/delete",
            "storage.delete",
            &StorageDelete {
                object_id: replica.object_id,
            },
        )
        .await
    }

    async fn storage_post<T: Serialize, R: DeserializeOwned>(
        &self,
        node: &NodeRecord,
        path: &str,
        operation: &str,
        body: &T,
    ) -> Result<R> {
        let envelope = SignedEnvelope::sign(operation, body, &self.identity)?;
        let url = format!(
            "{}/{}",
            node.registration.endpoint.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let response = self
            .client
            .post(url)
            .json(&envelope)
            .send()
            .await
            .context("storage-node request failed")?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .context("failed to read storage-node response")?;
        if !status.is_success() {
            bail!(
                "storage node {} returned {}: {}",
                node.registration.node_id,
                status,
                String::from_utf8_lossy(&bytes)
            );
        }
        serde_json::from_slice(&bytes).context("storage node returned an invalid response")
    }
}
