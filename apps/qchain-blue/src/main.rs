#![forbid(unsafe_code)]

mod api;
mod monitor;
mod raft;
mod state;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufReader, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use actix_web::{App, HttpServer, web};
use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use ed25519_dalek::SigningKey;
use openraft::{BasicNode, Config, SnapshotPolicy, storage::Adaptor};
use openraft_sledstore::SledStore;
use rand::rngs::OsRng;
use reqwest::Client;
use tracing::info;
use uuid::Uuid;

use crate::{raft::NetworkFactory, state::BlueState};

#[derive(Debug, Parser)]
#[command(
    name = "qchain-blue",
    version,
    about = "Run a Qchain Blue coordinator and replicated registry node"
)]
struct Args {
    #[arg(long)]
    node_id: u64,
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    #[arg(long, help = "HTTPS URL other Blue nodes use for this node")]
    advertise_url: String,
    #[arg(long, default_value = "./qchain-blue-data")]
    data_dir: PathBuf,
    #[arg(long)]
    cluster_token_file: PathBuf,
    #[arg(long)]
    admin_token_file: PathBuf,
    #[arg(long, required = true, num_args = 1.., help = "Trusted White-node curator public keys in hexadecimal")]
    curator_public_key: Vec<String>,
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    #[arg(long)]
    tls_key: Option<PathBuf>,
    #[arg(long, help = "Permit plain HTTP only for isolated local testing")]
    insecure_dev: bool,
    #[arg(
        long,
        help = "Initialize a new cluster; use once with identical initial members"
    )]
    bootstrap: bool,
    #[arg(
        long,
        value_name = "ID=URL",
        help = "Initial voting member; repeat for a three-node cluster"
    )]
    initial_member: Vec<String>,
    #[arg(long, default_value_t = 30)]
    suspect_seconds: u64,
    #[arg(long, default_value_t = 90)]
    lost_seconds: u64,
    #[arg(long, default_value_t = 60)]
    audit_seconds: u64,
    #[arg(long)]
    log_json: bool,
}

#[actix_web::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    initialize_logging(args.log_json)?;
    validate_args(&args)?;
    fs::create_dir_all(&args.data_dir)?;
    let cluster_token = read_token(&args.cluster_token_file, "cluster")?;
    let admin_token = read_token(&args.admin_token_file, "admin")?;
    let identity = Arc::new(load_or_create_signing_key(
        &args.data_dir.join("blue-identity.key"),
    )?);
    let database = Arc::new(sled::open(args.data_dir.join("raft.db"))?);
    let raft_store = SledStore::new(Arc::clone(&database)).await;
    let (log_store, state_machine) = Adaptor::new(Arc::clone(&raft_store));
    let client = Client::builder()
        .https_only(!args.insecure_dev)
        .timeout(Duration::from_secs(15))
        .build()?;
    let network = NetworkFactory::new(client.clone(), cluster_token.clone());
    let config = Arc::new(
        Config {
            cluster_name: "qchain-blue-v1".to_owned(),
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            snapshot_policy: SnapshotPolicy::LogsSinceLast(500),
            max_in_snapshot_log_to_keep: 100,
            ..Config::default()
        }
        .validate()?,
    );
    let raft = openraft::Raft::new(args.node_id, config, network, log_store, state_machine).await?;
    if args.bootstrap && !raft.is_initialized().await? {
        let members = initial_members(&args)?;
        if let Ok(result) =
            tokio::time::timeout(Duration::from_secs(10), raft.initialize(members)).await
        {
            result?;
        } else {
            if !raft.is_initialized().await? {
                bail!("cluster initialization timed out before consensus was established");
            }
            tracing::warn!("cluster initialization committed after its acknowledgement timed out");
        }
    }
    let trusted_curators = args
        .curator_public_key
        .iter()
        .map(|value| decode_public_key(value))
        .collect::<Result<BTreeSet<_>>>()?;
    let state = web::Data::new(BlueState {
        node_id: args.node_id,
        raft,
        raft_store,
        identity,
        client,
        live_nodes: dashmap::DashMap::new(),
        started_at: std::time::Instant::now(),
        trusted_curators,
        cluster_token,
        admin_token,
        allow_http: args.insecure_dev,
        mutation: tokio::sync::Mutex::new(()),
        request_rates: dashmap::DashMap::new(),
        suspect_after: Duration::from_secs(args.suspect_seconds),
        lost_after: Duration::from_secs(args.lost_seconds),
        audit_interval: Duration::from_secs(args.audit_seconds),
    });
    let monitor_state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        monitor::run(monitor_state).await;
    });
    info!(
        node_id = args.node_id,
        listen = %args.listen,
        identity_public_key = %hex::encode(state.identity.verifying_key().to_bytes()),
        "Blue node starting"
    );
    let app_state = state.clone();
    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(web::JsonConfig::default().limit(16 * 1024 * 1024))
            .service(api::health)
            .service(api::register_node)
            .service(api::node_heartbeat)
            .service(api::upload_credential)
            .service(api::credential_status)
            .service(api::retrieve_credential)
            .service(api::recovery_ack)
            .service(api::delete_credential)
            .service(api::initialize_cluster)
            .service(api::add_learner)
            .service(api::change_membership)
            .service(api::raft_append)
            .service(api::raft_vote)
            .service(api::raft_snapshot)
    });
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

fn validate_args(args: &Args) -> Result<()> {
    let url = reqwest::Url::parse(&args.advertise_url).context("invalid --advertise-url")?;
    if url.scheme() != "https" && !(args.insecure_dev && url.scheme() == "http") {
        bail!("--advertise-url must use HTTPS unless --insecure-dev is set");
    }
    if args.node_id == 0 {
        bail!("--node-id must be non-zero");
    }
    if args.suspect_seconds == 0
        || args.lost_seconds <= args.suspect_seconds
        || args.audit_seconds == 0
    {
        bail!("health intervals must be non-zero and lost-seconds must exceed suspect-seconds");
    }
    if !args.bootstrap && !args.initial_member.is_empty() {
        bail!("--initial-member requires --bootstrap");
    }
    Ok(())
}

fn initial_members(args: &Args) -> Result<BTreeMap<u64, BasicNode>> {
    if args.initial_member.is_empty() {
        return Ok(BTreeMap::from([(
            args.node_id,
            BasicNode::new(&args.advertise_url),
        )]));
    }
    let mut members = BTreeMap::new();
    for value in &args.initial_member {
        let (id, url) = value
            .split_once('=')
            .context("initial member must use ID=URL")?;
        let id = id.parse::<u64>().context("initial member ID is invalid")?;
        if id == 0 {
            bail!("initial member IDs must be non-zero");
        }
        let parsed = reqwest::Url::parse(url).context("initial member URL is invalid")?;
        if parsed.scheme() != "https" && !(args.insecure_dev && parsed.scheme() == "http") {
            bail!("initial member URLs must use HTTPS unless --insecure-dev is set");
        }
        if members.insert(id, BasicNode::new(url)).is_some() {
            bail!("initial member ID {id} is duplicated");
        }
    }
    if !members.contains_key(&args.node_id) {
        bail!("initial member list must contain this node's ID");
    }
    Ok(members)
}

fn read_token(path: &Path, name: &str) -> Result<String> {
    let value =
        fs::read_to_string(path).with_context(|| format!("failed to read {name} token file"))?;
    let value = value.trim().to_owned();
    if value.len() < 32 {
        bail!("{name} token must contain at least 32 characters");
    }
    Ok(value)
}

fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value).context("curator public key is not valid hexadecimal")?;
    decoded
        .try_into()
        .map_err(|_| anyhow!("curator public key must contain exactly 32 bytes"))
}

fn load_or_create_signing_key(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let bytes = fs::read(path)?;
        let encoded: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("stored Blue identity key is invalid"))?;
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

fn initialize_logging(json: bool) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("qchain_blue=info,openraft=info,actix_web=info")
    });
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
