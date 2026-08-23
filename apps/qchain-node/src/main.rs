#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufReader, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use actix_web::{
    App, HttpResponse, HttpServer, ResponseError, get, post,
    web::{self, Data, Json},
};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, ValueEnum};
use ed25519_dalek::SigningKey;
use qchain_protocol::{
    HealthResponse, Heartbeat, NodeOperationResponse, NodeRegistration, NodeRole, SignedEnvelope,
    StorageAudit, StorageAuditResponse, StorageDelete, StorageObject, StorageRead, StorageWrite,
};
use qshard_core::{MAX_SECRET_BYTES, peek_header};
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tracing::{error, info, warn};
use uuid::Uuid;

const MAX_STORED_SHARE_BYTES: usize = MAX_SECRET_BYTES + 16 * 1024;
const REPLAY_PREFIX: &[u8] = b"request/";

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RoleArg {
    Grey,
    White,
}

impl From<RoleArg> for NodeRole {
    fn from(value: RoleArg) -> Self {
        match value {
            RoleArg::Grey => Self::Grey,
            RoleArg::White => Self::White,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "qchain-node",
    version,
    about = "Run a Qchain Grey or White storage node"
)]
struct Args {
    #[arg(long, value_enum, default_value = "grey")]
    role: RoleArg,
    #[arg(long, default_value = "127.0.0.1:9443")]
    listen: SocketAddr,
    #[arg(long, help = "HTTPS URL advertised to Blue nodes")]
    advertise_url: String,
    #[arg(long)]
    failure_domain: String,
    #[arg(long, default_value_t = 1024)]
    capacity_mib: u64,
    #[arg(long, default_value_t = 1_000_000)]
    max_objects: u64,
    #[arg(long, default_value = "./qchain-node-data")]
    data_dir: PathBuf,
    #[arg(
        long,
        required = true,
        action = clap::ArgAction::Append,
        help = "Blue node URL used for registration and heartbeats; repeat for failover"
    )]
    blue: Vec<String>,
    #[arg(long, required = true, num_args = 1.., help = "Trusted Blue Ed25519 public key in hexadecimal")]
    blue_public_key: Vec<String>,
    #[arg(long, help = "Curator-issued certificate required for White nodes")]
    role_certificate: Option<String>,
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    #[arg(long)]
    tls_key: Option<PathBuf>,
    #[arg(long, help = "Permit plain HTTP only for isolated local testing")]
    insecure_dev: bool,
    #[arg(long, default_value_t = 15)]
    heartbeat_seconds: u64,
    #[arg(long)]
    log_json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ObjectMetadata {
    object_id: Uuid,
    set_id: Uuid,
    share_index: u8,
    generation: u64,
    sha256: [u8; 32],
    owner_public_key: [u8; 32],
    encoded_len: u32,
}

struct StorageStore {
    node_id: Uuid,
    objects_dir: PathBuf,
    metadata: sled::Tree,
    replay: sled::Tree,
    used_bytes: AtomicU64,
    capacity_bytes: u64,
    max_objects: u64,
    mutation_lock: Mutex<()>,
}

impl StorageStore {
    fn open(data_dir: &Path, capacity_bytes: u64, max_objects: u64) -> Result<Self> {
        fs::create_dir_all(data_dir)
            .with_context(|| format!("failed to create {}", data_dir.display()))?;
        let node_id = load_or_create_node_id(&data_dir.join("node-id"))?;
        let objects_dir = data_dir.join("objects");
        fs::create_dir_all(&objects_dir)?;
        let database = sled::open(data_dir.join("metadata.db"))?;
        let metadata = database.open_tree("objects")?;
        let replay = database.open_tree("replay")?;
        let mut used_bytes = 0_u64;
        for entry in &metadata {
            let (_, value) = entry?;
            let object: ObjectMetadata = serde_json::from_slice(&value)?;
            used_bytes = used_bytes.saturating_add(u64::from(object.encoded_len));
        }
        if used_bytes > capacity_bytes {
            bail!("existing shard data exceeds the configured capacity");
        }
        Ok(Self {
            node_id,
            objects_dir,
            metadata,
            replay,
            used_bytes: AtomicU64::new(used_bytes),
            capacity_bytes,
            max_objects,
            mutation_lock: Mutex::new(()),
        })
    }

    fn write(&self, request: &StorageWrite) -> Result<NodeOperationResponse, ApiError> {
        let payload = STANDARD
            .decode(&request.payload_base64)
            .map_err(|_| ApiError::BadRequest("invalid payload encoding"))?;
        if payload.len() > MAX_STORED_SHARE_BYTES {
            return Err(ApiError::BadRequest("encoded share exceeds the node limit"));
        }
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        if digest != request.sha256 {
            return Err(ApiError::BadRequest("share hash does not match"));
        }
        let header = peek_header(&payload)
            .map_err(|_| ApiError::BadRequest("payload is not a valid Qshard share"))?;
        if header.set_id != request.set_id
            || header.share_index != request.share_index
            || header.control_public_key != request.owner_public_key
        {
            return Err(ApiError::BadRequest(
                "authenticated share metadata does not match the request",
            ));
        }
        let encoded_len = u32::try_from(payload.len())
            .map_err(|_| ApiError::BadRequest("share length overflow"))?;
        let metadata = ObjectMetadata {
            object_id: request.object_id,
            set_id: request.set_id,
            share_index: request.share_index,
            generation: request.generation,
            sha256: request.sha256,
            owner_public_key: request.owner_public_key,
            encoded_len,
        };
        let _guard = self.mutation_lock.lock().map_err(|_| ApiError::Internal)?;
        if let Some(existing) = self
            .metadata
            .get(request.object_id.as_bytes())
            .map_err(|_| ApiError::Internal)?
        {
            let existing: ObjectMetadata =
                serde_json::from_slice(&existing).map_err(|_| ApiError::Internal)?;
            if existing == metadata {
                let path = self.object_path(request.object_id)?;
                if path.exists() {
                    let stored = fs::read(&path).map_err(|_| ApiError::Internal)?;
                    let stored_digest: [u8; 32] = Sha256::digest(&stored).into();
                    if stored_digest != request.sha256 {
                        return Err(ApiError::Corrupt);
                    }
                } else {
                    atomic_write_new(&path, &payload).map_err(|_| ApiError::Internal)?;
                }
                return Ok(NodeOperationResponse {
                    node_id: self.node_id,
                    status: "available".to_owned(),
                });
            }
            return Err(ApiError::Conflict("object identifier already exists"));
        }
        if u64::try_from(self.metadata.len()).unwrap_or(u64::MAX) >= self.max_objects
            || self
                .used_bytes
                .load(Ordering::Acquire)
                .saturating_add(u64::from(encoded_len))
                > self.capacity_bytes
        {
            return Err(ApiError::Capacity);
        }
        let path = self.object_path(request.object_id)?;
        if path.exists() {
            let orphan = fs::read(&path).map_err(|_| ApiError::Internal)?;
            let orphan_digest: [u8; 32] = Sha256::digest(&orphan).into();
            if orphan_digest != request.sha256 {
                return Err(ApiError::Conflict(
                    "orphaned object has conflicting contents",
                ));
            }
        } else {
            atomic_write_new(&path, &payload).map_err(|_| ApiError::Internal)?;
        }
        let encoded_metadata = serde_json::to_vec(&metadata).map_err(|_| ApiError::Internal)?;
        if self
            .metadata
            .insert(request.object_id.as_bytes(), encoded_metadata)
            .is_err()
            || self.metadata.flush().is_err()
        {
            let _ = fs::remove_file(&path);
            return Err(ApiError::Internal);
        }
        self.used_bytes
            .fetch_add(u64::from(encoded_len), Ordering::AcqRel);
        Ok(NodeOperationResponse {
            node_id: self.node_id,
            status: "available".to_owned(),
        })
    }

    fn read(&self, object_id: Uuid) -> Result<StorageObject, ApiError> {
        let metadata = self.get_metadata(object_id)?;
        let payload = fs::read(self.object_path(object_id)?).map_err(|_| ApiError::NotFound)?;
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        if digest != metadata.sha256 {
            return Err(ApiError::Corrupt);
        }
        Ok(StorageObject {
            object_id,
            sha256: digest,
            payload_base64: STANDARD.encode(payload),
        })
    }

    fn audit(&self, request: &StorageAudit) -> Result<StorageAuditResponse, ApiError> {
        let metadata = self.get_metadata(request.object_id)?;
        let payload =
            fs::read(self.object_path(request.object_id)?).map_err(|_| ApiError::NotFound)?;
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        Ok(StorageAuditResponse {
            object_id: request.object_id,
            sha256: digest,
            encoded_len: metadata.encoded_len,
            valid: digest == request.expected_sha256 && digest == metadata.sha256,
        })
    }

    fn delete(&self, object_id: Uuid) -> Result<NodeOperationResponse, ApiError> {
        let _guard = self.mutation_lock.lock().map_err(|_| ApiError::Internal)?;
        let path = self.object_path(object_id)?;
        let Some(encoded) = self
            .metadata
            .get(object_id.as_bytes())
            .map_err(|_| ApiError::Internal)?
        else {
            if path.exists() {
                fs::remove_file(&path).map_err(|_| ApiError::Internal)?;
            }
            return Ok(NodeOperationResponse {
                node_id: self.node_id,
                status: "deleted".to_owned(),
            });
        };
        let metadata: ObjectMetadata =
            serde_json::from_slice(&encoded).map_err(|_| ApiError::Internal)?;
        if path.exists() {
            fs::remove_file(&path).map_err(|_| ApiError::Internal)?;
        }
        self.metadata
            .remove(object_id.as_bytes())
            .map_err(|_| ApiError::Internal)?;
        self.metadata.flush().map_err(|_| ApiError::Internal)?;
        self.used_bytes
            .fetch_sub(u64::from(metadata.encoded_len), Ordering::AcqRel);
        Ok(NodeOperationResponse {
            node_id: self.node_id,
            status: "deleted".to_owned(),
        })
    }

    fn claim_request(&self, request_id: Uuid, expires_at_unix: i64) -> Result<(), ApiError> {
        let mut key = Vec::with_capacity(REPLAY_PREFIX.len() + 16);
        key.extend_from_slice(REPLAY_PREFIX);
        key.extend_from_slice(request_id.as_bytes());
        let replaced = self
            .replay
            .compare_and_swap(
                key,
                None as Option<&[u8]>,
                Some(expires_at_unix.to_be_bytes().as_slice()),
            )
            .map_err(|_| ApiError::Internal)?;
        match replaced {
            Ok(()) => Ok(()),
            Err(_) => Err(ApiError::Replay),
        }
    }

    fn prune_replay(&self, now: i64) {
        for entry in self.replay.scan_prefix(REPLAY_PREFIX).flatten() {
            let (key, value) = entry;
            if value.len() == 8 {
                let mut encoded = [0_u8; 8];
                encoded.copy_from_slice(&value);
                if i64::from_be_bytes(encoded) < now {
                    let _ = self.replay.remove(key);
                }
            }
        }
    }

    fn get_metadata(&self, object_id: Uuid) -> Result<ObjectMetadata, ApiError> {
        let encoded = self
            .metadata
            .get(object_id.as_bytes())
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::NotFound)?;
        serde_json::from_slice(&encoded).map_err(|_| ApiError::Internal)
    }

    fn object_path(&self, object_id: Uuid) -> Result<PathBuf, ApiError> {
        let encoded = object_id.simple().to_string();
        let directory = self.objects_dir.join(&encoded[..2]);
        fs::create_dir_all(&directory).map_err(|_| ApiError::Internal)?;
        Ok(directory.join(format!("{object_id}.qshare")))
    }

    fn available_bytes(&self) -> u64 {
        self.capacity_bytes
            .saturating_sub(self.used_bytes.load(Ordering::Acquire))
    }
}

struct AppState {
    store: Arc<StorageStore>,
    trusted_blue_keys: BTreeSet<[u8; 32]>,
}

impl AppState {
    fn authorize<T: DeserializeOwned>(
        &self,
        envelope: &SignedEnvelope,
        operation: &str,
    ) -> Result<T, ApiError> {
        if !self.trusted_blue_keys.contains(&envelope.signer_public_key) {
            return Err(ApiError::Unauthorized);
        }
        let body = envelope
            .verify(operation)
            .map_err(|_| ApiError::Unauthorized)?;
        self.store.claim_request(
            envelope.payload.request_id,
            envelope.payload.expires_at_unix,
        )?;
        Ok(body)
    }
}

#[derive(Debug, Error)]
enum ApiError {
    #[error("request is not authorized")]
    Unauthorized,
    #[error("request was already processed")]
    Replay,
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("{0}")]
    Conflict(&'static str),
    #[error("object was not found")]
    NotFound,
    #[error("node storage capacity has been reached")]
    Capacity,
    #[error("stored object failed its integrity check")]
    Corrupt,
    #[error("internal storage error")]
    Internal,
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        HttpResponse::build(status).json(serde_json::json!({"error": self.to_string()}))
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        use actix_web::http::StatusCode;
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Replay | Self::Conflict(_) => StatusCode::CONFLICT,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Capacity => StatusCode::INSUFFICIENT_STORAGE,
            Self::Corrupt | Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[get("/health")]
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "qchain-node".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        status: "healthy".to_owned(),
    })
}

#[post("/v1/storage/write")]
async fn write_object(
    state: Data<AppState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<NodeOperationResponse>, ApiError> {
    let request: StorageWrite = state.authorize(&envelope, "storage.write")?;
    state.store.write(&request).map(Json)
}

#[post("/v1/storage/read")]
async fn read_object(
    state: Data<AppState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<StorageObject>, ApiError> {
    let request: StorageRead = state.authorize(&envelope, "storage.read")?;
    state.store.read(request.object_id).map(Json)
}

#[post("/v1/storage/audit")]
async fn audit_object(
    state: Data<AppState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<StorageAuditResponse>, ApiError> {
    let request: StorageAudit = state.authorize(&envelope, "storage.audit")?;
    state.store.audit(&request).map(Json)
}

#[post("/v1/storage/delete")]
async fn delete_object(
    state: Data<AppState>,
    envelope: Json<SignedEnvelope>,
) -> Result<Json<NodeOperationResponse>, ApiError> {
    let request: StorageDelete = state.authorize(&envelope, "storage.delete")?;
    state.store.delete(request.object_id).map(Json)
}

#[actix_web::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    initialize_logging(args.log_json)?;
    validate_args(&args)?;
    let capacity_bytes = args
        .capacity_mib
        .checked_mul(1024 * 1024)
        .context("capacity is too large")?;
    let store = Arc::new(StorageStore::open(
        &args.data_dir,
        capacity_bytes,
        args.max_objects,
    )?);
    let identity = Arc::new(load_or_create_signing_key(
        &args.data_dir.join("identity.key"),
    )?);
    let trusted_blue_keys = args
        .blue_public_key
        .iter()
        .map(|value| decode_public_key(value))
        .collect::<Result<BTreeSet<_>>>()?;
    let registration = NodeRegistration {
        node_id: store.node_id,
        role: args.role.into(),
        endpoint: args.advertise_url.clone(),
        failure_domain: args.failure_domain.clone(),
        capacity_bytes,
        identity_public_key: identity.verifying_key().to_bytes(),
        role_certificate: args.role_certificate.clone(),
    };
    let heartbeat_store = Arc::clone(&store);
    let heartbeat_identity = Arc::clone(&identity);
    let heartbeat_blue = args.blue.clone();
    let heartbeat_interval = args.heartbeat_seconds;
    tokio::spawn(async move {
        registration_loop(
            heartbeat_blue,
            registration,
            heartbeat_store,
            heartbeat_identity,
            heartbeat_interval,
        )
        .await;
    });

    let state = Data::new(AppState {
        store,
        trusted_blue_keys,
    });
    let state_factory = state.clone();
    let server = HttpServer::new(move || {
        App::new()
            .app_data(state_factory.clone())
            .app_data(web::JsonConfig::default().limit(MAX_STORED_SHARE_BYTES + 32 * 1024))
            .service(health)
            .service(write_object)
            .service(read_object)
            .service(audit_object)
            .service(delete_object)
    });
    info!(node_id = %state.store.node_id, role = ?args.role, listen = %args.listen, "storage node starting");
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            server
                .bind_rustls_0_23(args.listen, load_tls(cert, key)?)?
                .run()
                .await?;
        }
        (None, None) if args.insecure_dev => {
            server.bind(args.listen)?.run().await?;
        }
        _ => bail!("both --tls-cert and --tls-key are required unless --insecure-dev is set"),
    }
    Ok(())
}

async fn registration_loop(
    blue: Vec<String>,
    registration: NodeRegistration,
    store: Arc<StorageStore>,
    identity: Arc<SigningKey>,
    heartbeat_seconds: u64,
) {
    let client = match Client::builder().timeout(Duration::from_secs(10)).build() {
        Ok(client) => client,
        Err(error) => {
            error!(%error, "failed to build Blue node client");
            return;
        }
    };
    let mut registered_blue = None;
    let mut interval = tokio::time::interval(Duration::from_secs(heartbeat_seconds.max(5)));
    loop {
        interval.tick().await;
        store.prune_replay(chrono::Utc::now().timestamp());
        if registered_blue.is_none() {
            registered_blue = first_accepting_blue(
                &client,
                &blue,
                "/v1/nodes/register",
                "node.register",
                &registration,
                &identity,
            )
            .await;
            if registered_blue.is_none() {
                continue;
            }
            info!(blue = %registered_blue.as_deref().unwrap_or_default(), "node registration accepted");
        }
        let heartbeat = Heartbeat {
            node_id: store.node_id,
            available_bytes: store.available_bytes(),
            object_count: u64::try_from(store.metadata.len()).unwrap_or(u64::MAX),
        };
        let Some(active_blue) = registered_blue.as_deref() else {
            continue;
        };
        if !send_signed(
            &client,
            active_blue,
            "/v1/nodes/heartbeat",
            "node.heartbeat",
            &heartbeat,
            &identity,
        )
        .await
        {
            warn!(blue = %active_blue, "heartbeat failed; registration will be retried");
            registered_blue = None;
        }
    }
}

async fn first_accepting_blue<T: Serialize>(
    client: &Client,
    blue_nodes: &[String],
    path: &str,
    operation: &str,
    body: &T,
    key: &SigningKey,
) -> Option<String> {
    for blue in blue_nodes {
        if send_signed(client, blue, path, operation, body, key).await {
            return Some(blue.clone());
        }
    }
    None
}

async fn send_signed<T: Serialize>(
    client: &Client,
    base: &str,
    path: &str,
    operation: &str,
    body: &T,
    key: &SigningKey,
) -> bool {
    let envelope = match SignedEnvelope::sign(operation, body, key) {
        Ok(value) => value,
        Err(error) => {
            warn!(%error, "failed to sign node request");
            return false;
        }
    };
    let url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    match client.post(url).json(&envelope).send().await {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            warn!(status = %response.status(), "Blue node rejected node request");
            false
        }
        Err(error) => {
            warn!(%error, "Blue node request failed");
            false
        }
    }
}

fn validate_args(args: &Args) -> Result<()> {
    let advertise = reqwest::Url::parse(&args.advertise_url).context("invalid --advertise-url")?;
    if advertise.scheme() != "https" && !(args.insecure_dev && advertise.scheme() == "http") {
        bail!("advertise URL must use HTTPS unless --insecure-dev is set");
    }
    for value in &args.blue {
        let url = reqwest::Url::parse(value).context("invalid --blue URL")?;
        let name = "Blue";
        if url.scheme() != "https" && !(args.insecure_dev && url.scheme() == "http") {
            bail!("{name} URL must use HTTPS unless --insecure-dev is set");
        }
    }
    if args.failure_domain.trim().is_empty() {
        bail!("--failure-domain cannot be empty");
    }
    if matches!(args.role, RoleArg::White)
        && args.role_certificate.as_deref().is_none_or(str::is_empty)
    {
        bail!("White nodes require --role-certificate");
    }
    if args.heartbeat_seconds == 0 || args.capacity_mib == 0 || args.max_objects == 0 {
        bail!("capacity, object limit, and heartbeat interval must be non-zero");
    }
    Ok(())
}

fn initialize_logging(json: bool) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("qchain_node=info,actix_web=info"));
    if json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow!(error.to_string()))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init()
            .map_err(|error| anyhow!(error.to_string()))?;
    }
    Ok(())
}

fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value).context("Blue public key is not valid hexadecimal")?;
    decoded
        .try_into()
        .map_err(|_| anyhow!("Blue public key must contain exactly 32 bytes"))
}

fn load_or_create_node_id(path: &Path) -> Result<Uuid> {
    if path.exists() {
        let value = fs::read_to_string(path)?;
        return Uuid::parse_str(value.trim()).context("stored node identifier is invalid");
    }
    let value = Uuid::new_v4();
    atomic_write_new(path, value.to_string().as_bytes())?;
    Ok(value)
}

fn load_or_create_signing_key(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let bytes = fs::read(path)?;
        let encoded: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("stored node identity key is invalid"))?;
        return Ok(SigningKey::from_bytes(&encoded));
    }
    let key = SigningKey::generate(&mut OsRng);
    atomic_write_new(path, &key.to_bytes())?;
    Ok(key)
}

fn atomic_write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".qchain-{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    set_private_permissions(&file)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if path.exists() {
        let _ = fs::remove_file(&temporary);
        bail!("{} already exists", path.display());
    }
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_file: &File) -> Result<()> {
    Ok(())
}

fn load_tls(cert_path: &Path, key_path: &Path) -> Result<rustls::ServerConfig> {
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certificates = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        bail!("TLS certificate file does not contain a certificate");
    }
    let mut key_reader = BufReader::new(File::open(key_path)?);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .context("TLS key file does not contain a private key")?;
    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)?)
}

#[cfg(test)]
mod tests {
    use qshard_core::{RecoverySeed, create_credential_bundle};

    use super::*;

    #[test]
    fn storage_lifecycle_is_integrity_checked_and_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = StorageStore::open(directory.path(), 1024 * 1024, 10)?;
        let bundle = create_credential_bundle(
            b"node storage test credential",
            &RecoverySeed::generate(),
            "qchain-test",
            None,
        )?;
        let share = &bundle.shares[0];
        let object_id = Uuid::new_v4();
        let request = StorageWrite {
            object_id,
            set_id: share.header.set_id,
            share_index: share.header.share_index,
            generation: 1,
            sha256: share.sha256,
            owner_public_key: share.header.control_public_key,
            payload_base64: STANDARD.encode(&share.bytes),
        };

        assert_eq!(store.write(&request)?.status, "available");
        assert_eq!(store.write(&request)?.status, "available");
        let stored = store.read(object_id)?;
        assert_eq!(stored.sha256, share.sha256);
        assert_eq!(STANDARD.decode(stored.payload_base64)?, share.bytes);
        assert!(
            store
                .audit(&StorageAudit {
                    object_id,
                    expected_sha256: share.sha256,
                })?
                .valid
        );

        let mut conflict = request.clone();
        conflict.generation = 2;
        assert!(matches!(store.write(&conflict), Err(ApiError::Conflict(_))));
        assert_eq!(store.delete(object_id)?.status, "deleted");
        assert_eq!(store.delete(object_id)?.status, "deleted");
        assert_eq!(store.available_bytes(), 1024 * 1024);
        Ok(())
    }

    #[test]
    fn storage_rejects_replayed_signed_requests() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = StorageStore::open(directory.path(), 1024 * 1024, 10)?;
        let request_id = Uuid::new_v4();
        store.claim_request(request_id, chrono::Utc::now().timestamp() + 60)?;
        assert!(matches!(
            store.claim_request(request_id, chrono::Utc::now().timestamp() + 60),
            Err(ApiError::Replay)
        ));
        Ok(())
    }
}
