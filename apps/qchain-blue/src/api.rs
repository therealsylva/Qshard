#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use actix_web::{
    HttpRequest, HttpResponse, ResponseError, get, post,
    web::{Data, Json},
};
use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::future::join_all;
use openraft::{
    BasicNode,
    error::RaftError,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, VoteRequest,
        VoteResponse,
    },
};
use openraft_sledstore::TypeConfig;
use qchain_protocol::{
    CredentialStatusRequest, CredentialStatusResponse, DeleteCredential, HealthResponse, Heartbeat,
    NodeOperationResponse, NodeRegistration, NodeRole, OperationResponse, PlacementReceipt,
    RecoveryAcknowledgement, RetrievalResponse, RetrieveCredential, RetrievedShare, SignedEnvelope,
    SignedRoleCertificate, StorageObject, UploadCredential,
};
use qchain_registry::{RegistryState, ReplicaRecord, ReplicaStatus, SetStatus};
use qshard_core::{SHARE_COUNT, SignedManifest, peek_header};
use serde::{Deserialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tracing::{error, warn};
use uuid::Uuid;

use crate::state::{BlueState, LiveNode};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("request is not authorized")]
    Unauthorized,
    #[error("request is invalid: {0}")]
    BadRequest(String),
    #[error("request conflicts with committed state: {0}")]
    Conflict(String),
    #[error("resource was not found")]
    NotFound,
    #[error("request rate limit exceeded")]
    RateLimited,
    #[error("this Blue node cannot currently serve the request")]
    Unavailable,
    #[error("internal coordinator error")]
    Internal,
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({"error": self.to_string()}))
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        use actix_web::http::StatusCode;
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    error!(error = %error, "Blue node operation failed");
    ApiError::Internal
}

fn unavailable(error: impl std::fmt::Display) -> ApiError {
    warn!(error = %error, "Blue node is unable to provide a linearizable operation");
    ApiError::Unavailable
}

fn verify<T: DeserializeOwned>(
    state: &BlueState,
    envelope: &SignedEnvelope,
    operation: &str,
) -> Result<T, ApiError> {
    state
        .rate_limit(envelope.signer_public_key, 120)
        .map_err(|_| ApiError::RateLimited)?;
    envelope
        .verify(operation)
        .map_err(|error| ApiError::BadRequest(error.to_string()))
}

#[get("/health")]
pub async fn health(state: Data<BlueState>) -> Json<serde_json::Value> {
    let metrics = state.raft.metrics().borrow().clone();
    let initialized = state.raft.is_initialized().await.unwrap_or(false);
    let ready = initialized && metrics.current_leader.is_some();
    let live_storage_nodes = state.live_nodes.len();
    let available_storage_bytes = state.live_nodes.iter().fold(0_u64, |total, node| {
        total.saturating_add(node.available_bytes)
    });
    let stored_objects = state
        .live_nodes
        .iter()
        .fold(0_u64, |total, node| total.saturating_add(node.object_count));
    Json(serde_json::json!({
        "service": "qchain-blue",
        "version": env!("CARGO_PKG_VERSION"),
        "status": if ready { "healthy" } else { "degraded" },
        "ready": ready,
        "initialized": initialized,
        "node_id": state.node_id,
        "current_leader": metrics.current_leader,
        "raft_state": format!("{:?}", metrics.state).to_lowercase(),
        "identity_public_key": hex::encode(state.identity.verifying_key().to_bytes()),
        "live_storage_nodes": live_storage_nodes,
        "available_storage_bytes": available_storage_bytes,
        "stored_objects": stored_objects,
    }))
}

#[post("/v1/nodes/register")]
pub async fn register_node(
    state: Data<BlueState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<NodeOperationResponse>, ApiError> {
    let registration: NodeRegistration = verify(&state, &envelope, "node.register")?;
    if envelope.signer_public_key != registration.identity_public_key
        || registration.role == NodeRole::Blue
    {
        return Err(ApiError::Unauthorized);
    }
    let endpoint = reqwest::Url::parse(&registration.endpoint)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if endpoint.scheme() != "https" && !(state.allow_http && endpoint.scheme() == "http") {
        return Err(ApiError::BadRequest(
            "storage-node endpoint must use HTTPS".to_owned(),
        ));
    }
    if registration.role == NodeRole::White {
        let encoded = registration
            .role_certificate
            .as_deref()
            .ok_or(ApiError::Unauthorized)?;
        SignedRoleCertificate::decode(encoded)
            .and_then(|certificate| certificate.verify(&registration, &state.trusted_curators))
            .map_err(|_| ApiError::Unauthorized)?;
    }
    let _guard = state.mutation.lock().await;
    let mut registry = state.read_registry(true).await.map_err(unavailable)?;
    registry
        .claim_request(
            envelope.payload.request_id,
            envelope.payload.expires_at_unix,
        )
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    registry
        .register_node(registration.clone())
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    state
        .commit_registry(&registry)
        .await
        .map_err(unavailable)?;
    state.live_nodes.insert(
        registration.node_id,
        LiveNode {
            last_seen: std::time::Instant::now(),
            available_bytes: registration.capacity_bytes,
            object_count: 0,
        },
    );
    Ok(Json(NodeOperationResponse {
        node_id: registration.node_id,
        status: "registered".to_owned(),
    }))
}

#[post("/v1/nodes/heartbeat")]
pub async fn node_heartbeat(
    state: Data<BlueState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<NodeOperationResponse>, ApiError> {
    let heartbeat: Heartbeat = envelope
        .verify("node.heartbeat")
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let registry = state.read_registry(false).await.map_err(internal)?;
    let node = registry
        .nodes
        .get(&heartbeat.node_id)
        .ok_or(ApiError::Unauthorized)?;
    if envelope.signer_public_key != node.registration.identity_public_key {
        return Err(ApiError::Unauthorized);
    }
    state.live_nodes.insert(
        heartbeat.node_id,
        LiveNode {
            last_seen: std::time::Instant::now(),
            available_bytes: heartbeat
                .available_bytes
                .min(node.registration.capacity_bytes),
            object_count: heartbeat.object_count,
        },
    );
    if node.status != qchain_protocol::NodeStatus::Healthy {
        let _guard = state.mutation.lock().await;
        let mut current = state.read_registry(true).await.map_err(unavailable)?;
        current
            .mark_node_healthy(heartbeat.node_id)
            .map_err(|error| ApiError::Conflict(error.to_string()))?;
        state.commit_registry(&current).await.map_err(unavailable)?;
    }
    Ok(Json(NodeOperationResponse {
        node_id: heartbeat.node_id,
        status: "healthy".to_owned(),
    }))
}

#[post("/v1/credentials")]
pub async fn upload_credential(
    state: Data<BlueState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<PlacementReceipt>, ApiError> {
    let upload: UploadCredential = verify(&state, &envelope, "credential.upload")?;
    upload
        .manifest
        .verify()
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if envelope.signer_public_key != upload.manifest.manifest.control_public_key {
        return Err(ApiError::Unauthorized);
    }
    let shares = validate_upload(&upload)?;
    let set_id = upload.manifest.manifest.set_id;
    let _guard = state.mutation.lock().await;
    let mut registry = state.read_registry(true).await.map_err(unavailable)?;
    if let Some(existing) = registry.sets.get(&set_id) {
        if existing.manifest.manifest.control_public_key != envelope.signer_public_key {
            return Err(ApiError::Unauthorized);
        }
        if existing.manifest != upload.manifest
            || existing.generation != upload.generation
            || existing.status != SetStatus::Active
        {
            return Err(ApiError::Conflict(
                "credential set already exists with different state".to_owned(),
            ));
        }
        return placement_receipt(&registry, set_id).map(Json);
    }
    registry
        .claim_request(
            envelope.payload.request_id,
            envelope.payload.expires_at_unix,
        )
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    let persisted_usage = registry
        .nodes
        .iter()
        .map(|(node_id, node)| (*node_id, (node.used_bytes, node.status)))
        .collect::<BTreeMap<_, _>>();
    for (node_id, node) in &mut registry.nodes {
        if let Some(live) = state.live_nodes.get(node_id) {
            node.used_bytes = node
                .registration
                .capacity_bytes
                .saturating_sub(live.available_bytes);
        } else {
            node.status = qchain_protocol::NodeStatus::Suspect;
        }
    }
    let planned = registry
        .plan_set(upload.manifest.clone(), upload.generation)
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    for (node_id, (used_bytes, status)) in persisted_usage {
        if let Some(node) = registry.nodes.get_mut(&node_id) {
            node.used_bytes = used_bytes;
            node.status = status;
        }
    }
    state
        .commit_registry(&registry)
        .await
        .map_err(unavailable)?;

    let writes = planned.replicas.iter().map(|replica| {
        let node = &registry.nodes[&replica.node_id];
        let payload = &shares[&replica.share_index];
        state.write_replica(
            node,
            replica,
            set_id,
            upload.manifest.manifest.control_public_key,
            payload,
        )
    });
    let results = join_all(writes).await;
    let successful = planned
        .replicas
        .iter()
        .zip(&results)
        .filter_map(|(replica, result)| result.as_ref().ok().map(|_| replica.object_id))
        .collect::<BTreeSet<_>>();
    if results.iter().any(Result::is_err) {
        retire_failed_upload(
            &state,
            &mut registry,
            &planned.replicas,
            &successful,
            set_id,
            &envelope.signer_public_key,
        )
        .await;
        return Err(ApiError::Unavailable);
    }

    for replica in &planned.replicas {
        if let Some(mut live) = state.live_nodes.get_mut(&replica.node_id) {
            live.available_bytes = live
                .available_bytes
                .saturating_sub(u64::from(replica.encoded_len));
            live.object_count = live.object_count.saturating_add(1);
        }
    }

    registry
        .activate_set(set_id)
        .map_err(|error| internal(error.to_string()))?;
    state
        .commit_registry(&registry)
        .await
        .map_err(unavailable)?;
    placement_receipt(&registry, set_id).map(Json)
}

#[post("/v1/credentials/status")]
pub async fn credential_status(
    state: Data<BlueState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<CredentialStatusResponse>, ApiError> {
    let request: CredentialStatusRequest = verify(&state, &envelope, "credential.status")?;
    let registry = state.read_registry(true).await.map_err(unavailable)?;
    let set = registry
        .authorize_set(request.set_id, &envelope.signer_public_key)
        .map_err(|error| match error {
            qchain_registry::RegistryError::SetNotFound => ApiError::NotFound,
            _ => ApiError::Unauthorized,
        })?;
    let available = set
        .replicas
        .iter()
        .filter(|replica| replica.status == ReplicaStatus::Available)
        .collect::<Vec<_>>();
    let mut indices = available
        .iter()
        .map(|replica| replica.share_index)
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    Ok(Json(CredentialStatusResponse {
        set_id: request.set_id,
        generation: set.generation,
        status: format!("{:?}", set.status).to_lowercase(),
        available_share_indices: indices,
        available_replicas: available.len(),
        registry_revision: registry.revision,
    }))
}

#[post("/v1/credentials/retrieve")]
pub async fn retrieve_credential(
    state: Data<BlueState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<RetrievalResponse>, ApiError> {
    let request: RetrieveCredential = verify(&state, &envelope, "credential.retrieve")?;
    let registry = state.read_registry(true).await.map_err(unavailable)?;
    let set = registry
        .authorize_set(request.set_id, &envelope.signer_public_key)
        .map_err(|_| ApiError::Unauthorized)?;
    if request
        .generation
        .is_some_and(|generation| generation != set.generation)
        || !matches!(set.status, SetStatus::Active | SetStatus::Degraded)
    {
        return Err(ApiError::Conflict(
            "credential generation is unavailable".to_owned(),
        ));
    }
    let candidates = set
        .replicas
        .iter()
        .filter(|replica| replica.status == ReplicaStatus::Available)
        .map(|replica| {
            let node = &registry.nodes[&replica.node_id];
            let state = state.clone();
            async move { (replica, state.read_replica(node, replica).await) }
        });
    let fetched = join_all(candidates).await;
    let mut distinct = BTreeMap::<u8, RetrievedShare>::new();
    for (replica, result) in fetched {
        let Ok(object) = result else {
            continue;
        };
        if let Ok(share) = validate_retrieved(replica, object) {
            distinct.entry(replica.share_index).or_insert(share);
        }
        if distinct.len() >= usize::from(set.manifest.manifest.threshold) {
            break;
        }
    }
    if distinct.len() < usize::from(set.manifest.manifest.threshold) {
        return Err(ApiError::Unavailable);
    }
    Ok(Json(RetrievalResponse {
        manifest: set.manifest.clone(),
        generation: set.generation,
        shares: distinct.into_values().collect(),
    }))
}

#[post("/v1/credentials/recovery-ack")]
pub async fn recovery_ack(
    state: Data<BlueState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<OperationResponse>, ApiError> {
    let request: RecoveryAcknowledgement = verify(&state, &envelope, "credential.recovery_ack")?;
    if request.auto_reseed != request.replacement_set_id.is_some() {
        return Err(ApiError::BadRequest(
            "replacement set does not match auto-reseed mode".to_owned(),
        ));
    }
    let _guard = state.mutation.lock().await;
    let mut registry = state.read_registry(true).await.map_err(unavailable)?;
    match registry.authorize_tombstone(request.set_id, &envelope.signer_public_key) {
        Ok(generation) if generation == request.generation => {
            return Ok(Json(OperationResponse {
                set_id: request.set_id,
                status: "deleted".to_owned(),
                registry_revision: registry.revision,
            }));
        }
        Ok(_) => {
            return Err(ApiError::Conflict(
                "credential generation does not match".to_owned(),
            ));
        }
        Err(qchain_registry::RegistryError::SetNotFound) => {}
        Err(qchain_registry::RegistryError::Unauthorized) => return Err(ApiError::Unauthorized),
        Err(error) => return Err(internal(error)),
    }
    let set = registry
        .authorize_set(request.set_id, &envelope.signer_public_key)
        .map_err(|_| ApiError::Unauthorized)?;
    if set.generation != request.generation {
        return Err(ApiError::Conflict(
            "credential generation does not match".to_owned(),
        ));
    }
    if set.status == SetStatus::Retiring {
        return Ok(Json(OperationResponse {
            set_id: request.set_id,
            status: "retiring".to_owned(),
            registry_revision: registry.revision,
        }));
    }
    if let Some(replacement) = request.replacement_set_id {
        let replacement = registry.sets.get(&replacement).ok_or(ApiError::BadRequest(
            "replacement set was not found".to_owned(),
        ))?;
        if replacement.status != SetStatus::Active {
            return Err(ApiError::Conflict(
                "replacement set is not active".to_owned(),
            ));
        }
    }
    registry
        .claim_request(
            envelope.payload.request_id,
            envelope.payload.expires_at_unix,
        )
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    let status = retire_set(
        &state,
        &mut registry,
        request.set_id,
        &envelope.signer_public_key,
    )
    .await?;
    Ok(Json(OperationResponse {
        set_id: request.set_id,
        status,
        registry_revision: registry.revision,
    }))
}

#[post("/v1/credentials/delete")]
pub async fn delete_credential(
    state: Data<BlueState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<OperationResponse>, ApiError> {
    let request: DeleteCredential = verify(&state, &envelope, "credential.delete")?;
    let _guard = state.mutation.lock().await;
    let mut registry = state.read_registry(true).await.map_err(unavailable)?;
    match registry.authorize_tombstone(request.set_id, &envelope.signer_public_key) {
        Ok(_) => {
            return Ok(Json(OperationResponse {
                set_id: request.set_id,
                status: "deleted".to_owned(),
                registry_revision: registry.revision,
            }));
        }
        Err(qchain_registry::RegistryError::SetNotFound) => {}
        Err(qchain_registry::RegistryError::Unauthorized) => return Err(ApiError::Unauthorized),
        Err(error) => return Err(internal(error)),
    }
    let set = registry
        .authorize_set(request.set_id, &envelope.signer_public_key)
        .map_err(|error| match error {
            qchain_registry::RegistryError::SetNotFound => ApiError::NotFound,
            _ => ApiError::Unauthorized,
        })?;
    if set.status == SetStatus::Retiring {
        return Ok(Json(OperationResponse {
            set_id: request.set_id,
            status: "retiring".to_owned(),
            registry_revision: registry.revision,
        }));
    }
    registry
        .claim_request(
            envelope.payload.request_id,
            envelope.payload.expires_at_unix,
        )
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    let status = retire_set(
        &state,
        &mut registry,
        request.set_id,
        &envelope.signer_public_key,
    )
    .await?;
    Ok(Json(OperationResponse {
        set_id: request.set_id,
        status,
        registry_revision: registry.revision,
    }))
}

#[derive(Debug, Deserialize)]
pub struct InitializeCluster {
    pub members: BTreeMap<u64, String>,
}

#[derive(Debug, Deserialize)]
pub struct AddLearner {
    pub node_id: u64,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangeMembership {
    pub members: BTreeSet<u64>,
}

#[post("/v1/admin/cluster/initialize")]
pub async fn initialize_cluster(
    request: HttpRequest,
    state: Data<BlueState>,
    body: Json<InitializeCluster>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&request, &state)?;
    if body.members.is_empty() {
        return Err(ApiError::BadRequest(
            "cluster membership cannot be empty".to_owned(),
        ));
    }
    for (id, url) in &body.members {
        validate_raft_member(*id, url, state.allow_http)?;
    }
    let members = body
        .members
        .iter()
        .map(|(id, url)| (*id, BasicNode::new(url)))
        .collect::<BTreeMap<_, _>>();
    if let Ok(result) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.raft.initialize(members),
    )
    .await
    {
        result.map_err(unavailable)?;
    } else {
        if !state.raft.is_initialized().await.map_err(unavailable)? {
            return Err(ApiError::Unavailable);
        }
        warn!("cluster initialization committed after its acknowledgement timed out");
    }
    Ok(Json(serde_json::json!({"status": "initialized"})))
}

#[post("/v1/admin/cluster/add-learner")]
pub async fn add_learner(
    request: HttpRequest,
    state: Data<BlueState>,
    body: Json<AddLearner>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&request, &state)?;
    validate_raft_member(body.node_id, &body.url, state.allow_http)?;
    state
        .raft
        .add_learner(body.node_id, BasicNode::new(&body.url), true)
        .await
        .map_err(unavailable)?;
    Ok(Json(
        serde_json::json!({"status": "learner_added", "node_id": body.node_id}),
    ))
}

#[post("/v1/admin/cluster/change-membership")]
pub async fn change_membership(
    request: HttpRequest,
    state: Data<BlueState>,
    body: Json<ChangeMembership>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&request, &state)?;
    if body.members.is_empty() || body.members.contains(&0) {
        return Err(ApiError::BadRequest(
            "voting membership must contain non-zero node IDs".to_owned(),
        ));
    }
    state
        .raft
        .change_membership(body.members.clone(), true)
        .await
        .map_err(unavailable)?;
    Ok(Json(
        serde_json::json!({"status": "membership_changed", "members": body.members}),
    ))
}

#[post("/v1/raft/append")]
pub async fn raft_append(
    request: HttpRequest,
    state: Data<BlueState>,
    body: Json<AppendEntriesRequest<TypeConfig>>,
) -> HttpResponse {
    if !token_matches(&request, "x-qchain-cluster-token", &state.cluster_token) {
        return HttpResponse::Unauthorized().finish();
    }
    let result: Result<AppendEntriesResponse<u64>, RaftError<u64>> =
        state.raft.append_entries(body.into_inner()).await;
    HttpResponse::Ok().json(result)
}

#[post("/v1/raft/vote")]
pub async fn raft_vote(
    request: HttpRequest,
    state: Data<BlueState>,
    body: Json<VoteRequest<u64>>,
) -> HttpResponse {
    if !token_matches(&request, "x-qchain-cluster-token", &state.cluster_token) {
        return HttpResponse::Unauthorized().finish();
    }
    let result: Result<VoteResponse<u64>, RaftError<u64>> =
        state.raft.vote(body.into_inner()).await;
    HttpResponse::Ok().json(result)
}

#[post("/v1/raft/snapshot")]
pub async fn raft_snapshot(
    request: HttpRequest,
    state: Data<BlueState>,
    body: Json<InstallSnapshotRequest<TypeConfig>>,
) -> HttpResponse {
    if !token_matches(&request, "x-qchain-cluster-token", &state.cluster_token) {
        return HttpResponse::Unauthorized().finish();
    }
    let result = state.raft.install_snapshot(body.into_inner()).await;
    HttpResponse::Ok().json(result)
}

fn validate_upload(upload: &UploadCredential) -> Result<BTreeMap<u8, Vec<u8>>, ApiError> {
    if upload.generation == 0 || upload.shares.len() != usize::from(SHARE_COUNT) {
        return Err(ApiError::BadRequest(
            "exactly five unique shares are required".to_owned(),
        ));
    }
    let mut decoded = BTreeMap::new();
    for share in &upload.shares {
        let bytes = share
            .decode()
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        let header =
            peek_header(&bytes).map_err(|error| ApiError::BadRequest(error.to_string()))?;
        let descriptor = upload
            .manifest
            .descriptor(share.share_index)
            .ok_or_else(|| ApiError::BadRequest("share is absent from the manifest".to_owned()))?;
        if header.set_id != upload.manifest.manifest.set_id
            || header.share_id != share.share_id
            || header.share_index != share.share_index
            || header.control_public_key != upload.manifest.manifest.control_public_key
            || descriptor.share_id != share.share_id
            || descriptor.sha256 != share.sha256
        {
            return Err(ApiError::BadRequest(
                "share metadata does not match the signed manifest".to_owned(),
            ));
        }
        if decoded.insert(share.share_index, bytes).is_some() {
            return Err(ApiError::BadRequest("duplicate share index".to_owned()));
        }
    }
    if decoded.keys().copied().collect::<BTreeSet<_>>() != BTreeSet::from([1, 2, 3, 4, 5]) {
        return Err(ApiError::BadRequest(
            "share indices must be one through five".to_owned(),
        ));
    }
    Ok(decoded)
}

fn placement_receipt(registry: &RegistryState, set_id: Uuid) -> Result<PlacementReceipt, ApiError> {
    let set = registry.sets.get(&set_id).ok_or(ApiError::NotFound)?;
    let mut placements = BTreeMap::<u8, Vec<Uuid>>::new();
    for replica in &set.replicas {
        if replica.status == ReplicaStatus::Available {
            placements
                .entry(replica.share_index)
                .or_default()
                .push(replica.node_id);
        }
    }
    Ok(PlacementReceipt {
        set_id,
        generation: set.generation,
        registry_revision: registry.revision,
        placements,
        committed_at_unix: set.updated_at_unix,
    })
}

fn validate_retrieved(replica: &ReplicaRecord, object: StorageObject) -> Result<RetrievedShare> {
    if object.object_id != replica.object_id || object.sha256 != replica.sha256 {
        bail!("storage object metadata mismatch");
    }
    let bytes = STANDARD.decode(&object.payload_base64)?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let header = peek_header(&bytes)?;
    if digest != replica.sha256
        || header.share_id != replica.share_id
        || header.share_index != replica.share_index
    {
        bail!("storage object integrity mismatch");
    }
    Ok(RetrievedShare {
        share_id: replica.share_id,
        share_index: replica.share_index,
        payload_base64: object.payload_base64,
    })
}

async fn retire_failed_upload(
    state: &BlueState,
    registry: &mut RegistryState,
    replicas: &[ReplicaRecord],
    successful: &BTreeSet<Uuid>,
    set_id: Uuid,
    signer: &[u8; 32],
) {
    if registry.begin_delete_set(set_id, signer).is_err() {
        return;
    }
    for replica in replicas {
        if !successful.contains(&replica.object_id) {
            let _ = registry.mark_replica_deleted(set_id, replica.object_id);
            continue;
        }
        if let Some(node) = registry.nodes.get(&replica.node_id) {
            if state.delete_replica(node, replica).await.is_ok() {
                let _ = registry.mark_replica_deleted(set_id, replica.object_id);
            }
        }
    }
    let _ = registry.finalize_delete_set(set_id);
    if let Err(error) = state.commit_registry(registry).await {
        error!(%error, %set_id, "failed to commit failed-upload cleanup state");
    }
}

async fn retire_set(
    state: &BlueState,
    registry: &mut RegistryState,
    set_id: Uuid,
    signer: &[u8; 32],
) -> Result<String, ApiError> {
    let replicas = registry
        .begin_delete_set(set_id, signer)
        .map_err(|error| match error {
            qchain_registry::RegistryError::SetNotFound => ApiError::NotFound,
            qchain_registry::RegistryError::Unauthorized => ApiError::Unauthorized,
            _ => ApiError::Conflict(error.to_string()),
        })?;
    state.commit_registry(registry).await.map_err(unavailable)?;
    for replica in &replicas {
        if matches!(replica.status, ReplicaStatus::Deleted | ReplicaStatus::Lost) {
            continue;
        }
        let Some(node) = registry.nodes.get(&replica.node_id) else {
            continue;
        };
        if state.delete_replica(node, replica).await.is_ok() {
            registry
                .mark_replica_deleted(set_id, replica.object_id)
                .map_err(internal)?;
        }
    }
    let status = if registry.finalize_delete_set(set_id).is_ok() {
        "deleted"
    } else {
        "retiring"
    };
    state.commit_registry(registry).await.map_err(unavailable)?;
    Ok(status.to_owned())
}

fn require_admin(request: &HttpRequest, state: &BlueState) -> Result<(), ApiError> {
    if token_matches(
        request,
        "authorization",
        &format!("Bearer {}", state.admin_token),
    ) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

fn validate_raft_member(node_id: u64, endpoint: &str, allow_http: bool) -> Result<(), ApiError> {
    if node_id == 0 {
        return Err(ApiError::BadRequest(
            "Raft member ID must be non-zero".to_owned(),
        ));
    }
    let url =
        reqwest::Url::parse(endpoint).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if url.scheme() != "https" && !(allow_http && url.scheme() == "http") {
        return Err(ApiError::BadRequest(
            "Raft member URL must use HTTPS".to_owned(),
        ));
    }
    Ok(())
}

fn token_matches(request: &HttpRequest, header: &str, expected: &str) -> bool {
    let Some(value) = request
        .headers()
        .get(header)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    value.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[allow(dead_code)]
fn _typed_health() -> HealthResponse {
    HealthResponse {
        service: String::new(),
        version: String::new(),
        status: String::new(),
    }
}

#[allow(dead_code)]
fn _signed_manifest(_: &SignedManifest) {}
