#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use qchain_protocol::{
    BlueDirectory, BlueDirectoryNode, NodeRole, RoleCertificateClaims, SignedBlueDirectory,
    SignedRoleCertificate,
};
use rand::{RngCore as _, rngs::OsRng};
use reqwest::Client;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "qchain-admin",
    version,
    about = "Administer Qchain Blue membership and White-node certificates"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate an Ed25519 curator key with restricted file permissions.
    GenerateKey(GenerateKey),
    /// Generate the persistent ID and Ed25519 identity for a storage node.
    GenerateNodeIdentity(GenerateNodeIdentity),
    /// Generate a random cluster or admin token file.
    GenerateToken(GenerateKey),
    /// Print the public key corresponding to a protected private key file.
    PublicKey(KeyFile),
    /// Issue a curator-signed certificate for one White node identity.
    IssueWhite(IssueWhite),
    /// Issue a signed directory of curated Blue nodes for Black clients.
    IssueDirectory(IssueDirectory),
    /// Perform authenticated Blue-cluster membership operations.
    Cluster(ClusterArgs),
}

#[derive(Debug, Args)]
struct GenerateKey {
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct KeyFile {
    #[arg(long)]
    key: PathBuf,
}

#[derive(Debug, Args)]
struct GenerateNodeIdentity {
    #[arg(long)]
    data_dir: PathBuf,
}

#[derive(Debug, Args)]
struct IssueWhite {
    #[arg(long)]
    curator_key: PathBuf,
    #[arg(long)]
    node_id: Uuid,
    #[arg(long)]
    identity_public_key: String,
    #[arg(long, default_value_t = 365)]
    valid_days: i64,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct IssueDirectory {
    #[arg(long)]
    curator_key: PathBuf,
    #[arg(long)]
    network: String,
    #[arg(long, required = true, num_args = 1.., value_name = "ID,URL,PUBLIC_KEY")]
    node: Vec<String>,
    #[arg(long, default_value_t = 30)]
    valid_days: i64,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ClusterArgs {
    #[arg(long)]
    blue: String,
    #[arg(long)]
    admin_token_file: PathBuf,
    #[arg(long)]
    allow_http: bool,
    #[command(subcommand)]
    operation: ClusterOperation,
}

#[derive(Debug, Subcommand)]
enum ClusterOperation {
    /// Initialize a pristine cluster from ID=URL member definitions.
    Initialize {
        #[arg(long, required = true, num_args = 1.., value_name = "ID=URL")]
        member: Vec<String>,
    },
    /// Add and fully synchronize a learner.
    AddLearner {
        #[arg(long)]
        node_id: u64,
        #[arg(long)]
        url: String,
    },
    /// Promote the specified learner IDs to the voting membership.
    ChangeMembership {
        #[arg(long, required = true, num_args = 1..)]
        member: Vec<u64>,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::GenerateKey(args) => {
            let key = SigningKey::generate(&mut OsRng);
            atomic_write_new(&args.output, &key.to_bytes())?;
            println!("Private key: {}", args.output.display());
            println!(
                "Public key: {}",
                hex::encode(key.verifying_key().to_bytes())
            );
        }
        Command::GenerateNodeIdentity(args) => {
            fs::create_dir_all(&args.data_dir)?;
            let key = SigningKey::generate(&mut OsRng);
            let node_id = Uuid::new_v4();
            atomic_write_new(&args.data_dir.join("identity.key"), &key.to_bytes())?;
            atomic_write_new(
                &args.data_dir.join("node-id"),
                node_id.to_string().as_bytes(),
            )?;
            println!("Node identifier: {node_id}");
            println!(
                "Identity public key: {}",
                hex::encode(key.verifying_key().to_bytes())
            );
        }
        Command::GenerateToken(args) => {
            let mut bytes = [0_u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let token = URL_SAFE_NO_PAD.encode(bytes);
            atomic_write_new(&args.output, token.as_bytes())?;
            println!("Token file: {}", args.output.display());
        }
        Command::PublicKey(args) => {
            let key = load_key(&args.key)?;
            println!("{}", hex::encode(key.verifying_key().to_bytes()));
        }
        Command::IssueWhite(args) => issue_white(args)?,
        Command::IssueDirectory(args) => issue_directory(args)?,
        Command::Cluster(args) => cluster(args).await?,
    }
    Ok(())
}

fn issue_directory(args: IssueDirectory) -> Result<()> {
    if args.valid_days <= 0 || args.valid_days > 365 {
        bail!("--valid-days must be between 1 and 365");
    }
    let curator = load_key(&args.curator_key)?;
    let mut nodes = Vec::new();
    for value in args.node {
        let parts = value.splitn(3, ',').collect::<Vec<_>>();
        if parts.len() != 3 {
            bail!("Blue directory nodes must use ID,URL,PUBLIC_KEY");
        }
        let url = reqwest::Url::parse(parts[1]).context("Blue directory URL is invalid")?;
        if url.scheme() != "https" {
            bail!("Blue directory URLs must use HTTPS");
        }
        nodes.push(BlueDirectoryNode {
            node_id: parts[0].parse()?,
            url: parts[1].to_owned(),
            identity_public_key: decode_public_key(parts[2])?,
        });
    }
    nodes.sort_by_key(|node| node.node_id);
    let now = Utc::now().timestamp();
    let signed = SignedBlueDirectory::issue(
        BlueDirectory {
            version: 1,
            network_id: args.network,
            issued_at_unix: now,
            expires_at_unix: now.saturating_add(args.valid_days.saturating_mul(86_400)),
            nodes,
        },
        &curator,
    )?;
    atomic_write_new(&args.output, &serde_json::to_vec_pretty(&signed)?)?;
    println!("Signed Blue directory: {}", args.output.display());
    Ok(())
}

fn issue_white(args: IssueWhite) -> Result<()> {
    if args.valid_days <= 0 || args.valid_days > 3650 {
        bail!("--valid-days must be between 1 and 3650");
    }
    let curator = load_key(&args.curator_key)?;
    let identity_public_key = decode_public_key(&args.identity_public_key)?;
    let now = Utc::now().timestamp();
    let claims = RoleCertificateClaims {
        version: 1,
        node_id: args.node_id,
        role: NodeRole::White,
        identity_public_key,
        not_before_unix: now.saturating_sub(60),
        expires_at_unix: now.saturating_add(args.valid_days.saturating_mul(86_400)),
    };
    let encoded = SignedRoleCertificate::issue(claims, &curator)?.encode()?;
    if let Some(path) = args.output {
        atomic_write_new(&path, encoded.as_bytes())?;
        println!("White-node certificate: {}", path.display());
    } else {
        println!("{encoded}");
    }
    Ok(())
}

async fn cluster(args: ClusterArgs) -> Result<()> {
    let url = reqwest::Url::parse(&args.blue).context("invalid Blue URL")?;
    if url.scheme() != "https" && !(args.allow_http && url.scheme() == "http") {
        bail!("Blue URL must use HTTPS unless --allow-http is set");
    }
    let token = fs::read_to_string(&args.admin_token_file).context("failed to read admin token")?;
    let token = token.trim();
    if token.len() < 32 {
        bail!("admin token must contain at least 32 characters");
    }
    let client = Client::builder().https_only(!args.allow_http).build()?;
    match args.operation {
        ClusterOperation::Initialize { member } => {
            let mut members = BTreeMap::new();
            for value in member {
                let (id, endpoint) = value.split_once('=').context("member must use ID=URL")?;
                let id = id.parse::<u64>()?;
                validate_member(id, endpoint, args.allow_http)?;
                if members.insert(id, endpoint.to_owned()).is_some() {
                    bail!("member ID {id} is duplicated");
                }
            }
            post_admin(
                &client,
                &args.blue,
                "/v1/admin/cluster/initialize",
                token,
                &serde_json::json!({"members": members}),
            )
            .await?;
        }
        ClusterOperation::AddLearner { node_id, url } => {
            validate_member(node_id, &url, args.allow_http)?;
            post_admin(
                &client,
                &args.blue,
                "/v1/admin/cluster/add-learner",
                token,
                &serde_json::json!({"node_id": node_id, "url": url}),
            )
            .await?;
        }
        ClusterOperation::ChangeMembership { member } => {
            let members = member.into_iter().collect::<BTreeSet<_>>();
            if members.is_empty() || members.contains(&0) {
                bail!("voting membership must contain non-zero node IDs");
            }
            post_admin(
                &client,
                &args.blue,
                "/v1/admin/cluster/change-membership",
                token,
                &serde_json::json!({"members": members}),
            )
            .await?;
        }
    }
    println!("Cluster operation accepted.");
    Ok(())
}

fn validate_member(node_id: u64, endpoint: &str, allow_http: bool) -> Result<()> {
    if node_id == 0 {
        bail!("member node ID must be non-zero");
    }
    let url = reqwest::Url::parse(endpoint).context("member URL is invalid")?;
    if url.scheme() != "https" && !(allow_http && url.scheme() == "http") {
        bail!("member URL must use HTTPS unless --allow-http is set");
    }
    Ok(())
}

async fn post_admin<T: Serialize>(
    client: &Client,
    base: &str,
    path: &str,
    token: &str,
    body: &T,
) -> Result<()> {
    let url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let response = client
        .post(url)
        .bearer_auth(token)
        .json(body)
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        bail!(
            "Blue node returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    Ok(())
}

fn load_key(path: &Path) -> Result<SigningKey> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let encoded: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("private key must contain exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&encoded))
}

fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).context("identity public key is not valid hexadecimal")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("identity public key must contain exactly 32 bytes"))
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
