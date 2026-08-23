#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fs, io::Write as _, path::PathBuf};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use qchain_cli::{
    ClientRecord, atomic_write, default_state_dir, endpoint, ensure_https, initialize_logging,
    load_capsule, load_record, print_value, read_secret, save_capsule, save_record,
    validate_capsule_context,
};
use qchain_protocol::{
    CredentialStatusRequest, CredentialStatusResponse, DeleteCredential, OperationResponse,
    PlacementReceipt, RecoveryAcknowledgement, RetrievalResponse, RetrieveCredential,
    SignedBlueDirectory, SignedEnvelope, UploadCredential, UploadShare,
};
use qshard_core::{
    RecoveryCapsule, RecoveryMode, RecoverySeed, create_credential_bundle, recover_credential,
};
use reqwest::Client;
use rustyline::{DefaultEditor, error::ReadlineError};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "qchain",
    version,
    about = "Store and recover encrypted credentials on Qchain"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        env = "QCHAIN_BLUE_URL",
        default_value = "https://127.0.0.1:8443"
    )]
    blue: String,
    #[arg(
        long,
        global = true,
        env = "QCHAIN_BLUE_DIRECTORY",
        help = "Curator-signed Blue directory JSON"
    )]
    directory: Option<PathBuf>,
    #[arg(long, global = true, num_args = 0.., help = "Trusted directory curator public key in hexadecimal")]
    curator_public_key: Vec<String>,
    #[arg(
        long,
        global = true,
        help = "Bypass signed Blue-directory verification for local development"
    )]
    allow_unsigned_blue: bool,
    #[arg(long, global = true, env = "QCHAIN_STATE_DIR", default_value_os_t = default_state_dir())]
    state_dir: PathBuf,
    #[arg(
        long,
        global = true,
        help = "Permit plain HTTP for isolated local development"
    )]
    allow_http: bool,
    #[arg(long, global = true)]
    json: bool,
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Encrypt, split, and place a credential across ten storage nodes.
    Store(StoreArgs),
    /// Retrieve and reconstruct a credential, then acknowledge successful recovery.
    Recover(RecoverArgs),
    /// Query the committed availability of a credential set.
    Status(SetArgs),
    /// Permanently remove every registered replica of a credential set.
    Delete(SetArgs),
    /// List local credential records without exposing secret material.
    List,
    /// Start an interactive shell. Command history is kept in memory only.
    Repl,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RecoveryModeArg {
    PerCredential,
    Master,
}

impl From<RecoveryModeArg> for RecoveryMode {
    fn from(value: RecoveryModeArg) -> Self {
        match value {
            RecoveryModeArg::PerCredential => Self::PerCredential,
            RecoveryModeArg::Master => Self::Master,
        }
    }
}

#[derive(Debug, Args)]
struct StoreArgs {
    #[arg(
        long,
        help = "Read the credential from this file; otherwise use a hidden prompt or standard input"
    )]
    input: Option<PathBuf>,
    #[arg(long, default_value = "credential")]
    label: String,
    #[arg(long, default_value = "qchain-mainnet")]
    network: String,
    #[arg(long, value_enum, default_value = "per-credential")]
    recovery_mode: RecoveryModeArg,
    #[arg(
        long,
        help = "Recovery capsule path; defaults to the protected Qchain state directory"
    )]
    capsule: Option<PathBuf>,
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    set_id: Uuid,
    #[arg(long, conflicts_with = "stdout")]
    output: Option<PathBuf>,
    #[arg(long)]
    stdout: bool,
    #[arg(
        long,
        help = "Upload a fresh credential set before deleting the recovered set"
    )]
    auto_reseed: bool,
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct SetArgs {
    set_id: Uuid,
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
}

#[derive(Clone)]
struct RuntimeOptions {
    blue: String,
    blue_urls: Vec<String>,
    directory_network: Option<String>,
    state_dir: PathBuf,
    allow_http: bool,
    json: bool,
    client: Client,
}

#[derive(Debug, Serialize)]
struct LocalListEntry {
    set_id: Uuid,
    label: String,
    active: bool,
    generation: u64,
    blue_url: String,
    replacement_set_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct RecoveryReport {
    set_id: Uuid,
    status: String,
    registry_revision: u64,
    replacement_set_id: Option<Uuid>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    initialize_logging(cli.verbose);
    if let Err(error) = dispatch(cli).await {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    let (blue_urls, directory_network) = resolve_blue(&cli)?;
    for url in &blue_urls {
        ensure_https(url, cli.allow_http)?;
    }
    let blue = blue_urls
        .first()
        .cloned()
        .context("no Blue endpoints are configured")?;
    let options = RuntimeOptions {
        blue,
        blue_urls,
        directory_network,
        state_dir: cli.state_dir,
        allow_http: cli.allow_http,
        json: cli.json,
        client: Client::builder().https_only(!cli.allow_http).build()?,
    };
    match cli.command.unwrap_or(Command::Repl) {
        Command::Repl => repl(options).await,
        command => execute(command, &options).await,
    }
}

async fn execute(command: Command, options: &RuntimeOptions) -> Result<()> {
    match command {
        Command::Store(args) => store(args, options).await,
        Command::Recover(args) => recover(args, options).await,
        Command::Status(args) => status(args, options).await,
        Command::Delete(args) => delete(args, options).await,
        Command::List => list(options),
        Command::Repl => bail!("nested interactive shells are not supported"),
    }
}

async fn store(args: StoreArgs, options: &RuntimeOptions) -> Result<()> {
    if options
        .directory_network
        .as_deref()
        .is_some_and(|network| network != args.network)
    {
        bail!(
            "credential network {} does not match the signed Blue directory",
            args.network
        );
    }
    let secret = read_secret(args.input.as_deref())?;
    let (seed, existing_capsule) = match args.recovery_mode {
        RecoveryModeArg::Master => {
            let path = args
                .capsule
                .clone()
                .unwrap_or_else(|| options.state_dir.join("master.recovery.qrc"));
            if path.exists() {
                let capsule = load_capsule(&path, args.passphrase_file.as_deref())?;
                if capsule.mode != RecoveryMode::Master || capsule.network_id != args.network {
                    bail!("the master recovery capsule belongs to a different mode or network");
                }
                (capsule.seed(), Some(path))
            } else {
                (RecoverySeed::generate(), None)
            }
        }
        RecoveryModeArg::PerCredential => (RecoverySeed::generate(), None),
    };
    let bundle = create_credential_bundle(&secret, &seed, &args.network, None)?;
    let set_id = bundle.signed_manifest.manifest.set_id;
    let capsule_path = args
        .capsule
        .clone()
        .or(existing_capsule)
        .unwrap_or_else(|| match args.recovery_mode {
            RecoveryModeArg::Master => options.state_dir.join("master.recovery.qrc"),
            RecoveryModeArg::PerCredential => options
                .state_dir
                .join("recovery")
                .join(format!("{set_id}.qrc")),
        });
    if !capsule_path.exists() {
        let capsule_set_id =
            matches!(args.recovery_mode, RecoveryModeArg::PerCredential).then_some(set_id);
        let capsule = RecoveryCapsule::new(
            args.recovery_mode.into(),
            args.network,
            capsule_set_id,
            &seed,
        );
        save_capsule(
            &capsule_path,
            &capsule,
            args.passphrase_file.as_deref(),
            false,
        )?;
    }
    let mut record = ClientRecord {
        label: args.label,
        blue_url: options.blue.clone(),
        blue_urls: options.blue_urls.clone(),
        capsule_path,
        manifest: bundle.signed_manifest.clone(),
        generation: 1,
        active: false,
        replacement_set_id: None,
    };
    save_record(&options.state_dir, &record)?;
    let receipt = upload_bundle(&options.client, &options.blue_urls, &bundle, &seed).await?;
    record.generation = receipt.generation;
    record.active = true;
    save_record(&options.state_dir, &record)?;
    if options.json {
        print_value(&receipt, true)?;
    } else {
        println!("Credential set committed: {}", receipt.set_id);
        println!("Generation: {}", receipt.generation);
        println!("Storage replicas: 10 on 10 distinct nodes");
        println!("Registry revision: {}", receipt.registry_revision);
        println!("Recovery capsule: {}", record.capsule_path.display());
    }
    Ok(())
}

async fn recover(args: RecoverArgs, options: &RuntimeOptions) -> Result<()> {
    if args.output.is_none() && !args.stdout {
        bail!("choose --output <path> or --stdout");
    }
    if args.stdout && options.json {
        bail!("--stdout cannot be combined with --json");
    }
    let mut record = load_record(&options.state_dir, args.set_id)?;
    let endpoints = operation_blue_urls(&record, options)?;
    for url in &endpoints {
        ensure_https(url, options.allow_http)?;
    }
    let capsule = load_capsule(&record.capsule_path, args.passphrase_file.as_deref())?;
    validate_capsule_context(&capsule, args.set_id, &record.manifest.manifest.network_id)?;
    let seed = capsule.seed();
    let key = seed.control_signing_key(args.set_id)?;
    let request = RetrieveCredential {
        set_id: args.set_id,
        generation: Some(record.generation),
    };
    let envelope = SignedEnvelope::sign("credential.retrieve", &request, &key)?;
    let response: RetrievalResponse = post(
        &options.client,
        &endpoints,
        "/v1/credentials/retrieve",
        &envelope,
    )
    .await?;
    let encoded = response
        .shares
        .iter()
        .map(|share| {
            STANDARD
                .decode(&share.payload_base64)
                .context("Blue node returned invalid share encoding")
        })
        .collect::<Result<Vec<_>>>()?;
    let secret = Zeroizing::new(recover_credential(
        &encoded,
        &seed,
        Some(&response.manifest),
    )?);

    if let Some(path) = &args.output {
        atomic_write(path, &secret, args.force, true)?;
    } else {
        std::io::stdout().write_all(&secret)?;
        std::io::stdout().flush()?;
    }

    let replacement_set_id = if args.auto_reseed {
        let replacement =
            create_credential_bundle(&secret, &seed, &response.manifest.manifest.network_id, None)?;
        let replacement_id = replacement.signed_manifest.manifest.set_id;
        let replacement_capsule_path = if capsule.mode == RecoveryMode::PerCredential {
            let path = options
                .state_dir
                .join("recovery")
                .join(format!("{replacement_id}.qrc"));
            let next_capsule = RecoveryCapsule::new(
                RecoveryMode::PerCredential,
                capsule.network_id.clone(),
                Some(replacement_id),
                &seed,
            );
            save_capsule(&path, &next_capsule, args.passphrase_file.as_deref(), false)?;
            path
        } else {
            record.capsule_path.clone()
        };
        let mut replacement_record = ClientRecord {
            label: record.label.clone(),
            blue_url: record.blue_url.clone(),
            blue_urls: endpoints.clone(),
            capsule_path: replacement_capsule_path,
            manifest: replacement.signed_manifest.clone(),
            generation: 1,
            active: false,
            replacement_set_id: None,
        };
        save_record(&options.state_dir, &replacement_record)?;
        let replacement_receipt =
            upload_bundle(&options.client, &endpoints, &replacement, &seed).await?;
        replacement_record.generation = replacement_receipt.generation;
        replacement_record.active = true;
        save_record(&options.state_dir, &replacement_record)?;
        Some(replacement_id)
    } else {
        None
    };

    let acknowledgement = RecoveryAcknowledgement {
        set_id: args.set_id,
        generation: response.generation,
        auto_reseed: args.auto_reseed,
        replacement_set_id,
    };
    let signed = SignedEnvelope::sign("credential.recovery_ack", &acknowledgement, &key)?;
    let operation: OperationResponse = post(
        &options.client,
        &endpoints,
        "/v1/credentials/recovery-ack",
        &signed,
    )
    .await?;
    record.active = false;
    record.replacement_set_id = replacement_set_id;
    save_record(&options.state_dir, &record)?;
    if !args.stdout {
        if options.json {
            print_value(
                &RecoveryReport {
                    set_id: operation.set_id,
                    status: operation.status,
                    registry_revision: operation.registry_revision,
                    replacement_set_id,
                },
                true,
            )?;
        } else {
            if let Some(path) = args.output {
                println!("Recovered credential written to {}", path.display());
            }
            println!("Original set retired: {}", args.set_id);
            if let Some(replacement) = replacement_set_id {
                println!("Replacement set committed: {replacement}");
            }
        }
    }
    Ok(())
}

async fn status(args: SetArgs, options: &RuntimeOptions) -> Result<()> {
    let record = load_record(&options.state_dir, args.set_id)?;
    let endpoints = operation_blue_urls(&record, options)?;
    let capsule = load_capsule(&record.capsule_path, args.passphrase_file.as_deref())?;
    validate_capsule_context(&capsule, args.set_id, &record.manifest.manifest.network_id)?;
    let key = capsule.seed().control_signing_key(args.set_id)?;
    let envelope = SignedEnvelope::sign(
        "credential.status",
        &CredentialStatusRequest {
            set_id: args.set_id,
        },
        &key,
    )?;
    let response: CredentialStatusResponse = post(
        &options.client,
        &endpoints,
        "/v1/credentials/status",
        &envelope,
    )
    .await?;
    if options.json {
        print_value(&response, true)?;
    } else {
        println!("Credential set: {}", response.set_id);
        println!("Status: {}", response.status);
        println!("Generation: {}", response.generation);
        println!("Available replicas: {}", response.available_replicas);
        println!(
            "Available share indices: {:?}",
            response.available_share_indices
        );
        println!("Registry revision: {}", response.registry_revision);
    }
    Ok(())
}

async fn delete(args: SetArgs, options: &RuntimeOptions) -> Result<()> {
    let mut record = load_record(&options.state_dir, args.set_id)?;
    let endpoints = operation_blue_urls(&record, options)?;
    let capsule = load_capsule(&record.capsule_path, args.passphrase_file.as_deref())?;
    validate_capsule_context(&capsule, args.set_id, &record.manifest.manifest.network_id)?;
    let key = capsule.seed().control_signing_key(args.set_id)?;
    let envelope = SignedEnvelope::sign(
        "credential.delete",
        &DeleteCredential {
            set_id: args.set_id,
        },
        &key,
    )?;
    let response: OperationResponse = post(
        &options.client,
        &endpoints,
        "/v1/credentials/delete",
        &envelope,
    )
    .await?;
    record.active = false;
    save_record(&options.state_dir, &record)?;
    if options.json {
        print_value(&response, true)?;
    } else {
        println!("Credential set deleted: {}", response.set_id);
        println!("Registry revision: {}", response.registry_revision);
    }
    Ok(())
}

fn list(options: &RuntimeOptions) -> Result<()> {
    let directory = options.state_dir.join("credentials");
    let mut entries = Vec::new();
    if directory.exists() {
        for item in fs::read_dir(&directory)
            .with_context(|| format!("failed to read {}", directory.display()))?
        {
            let path = item?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record: ClientRecord = serde_json::from_slice(&fs::read(&path)?)
                .with_context(|| format!("invalid local state in {}", path.display()))?;
            entries.push(LocalListEntry {
                set_id: record.manifest.manifest.set_id,
                label: record.label,
                active: record.active,
                generation: record.generation,
                blue_url: record.blue_url,
                replacement_set_id: record.replacement_set_id,
            });
        }
    }
    entries.sort_by_key(|entry| entry.set_id);
    if options.json {
        print_value(&entries, true)?;
    } else if entries.is_empty() {
        println!("No local credential records were found.");
    } else {
        for entry in entries {
            println!(
                "{}  {}  generation={}  active={}",
                entry.set_id, entry.label, entry.generation, entry.active
            );
        }
    }
    Ok(())
}

async fn upload_bundle(
    client: &Client,
    blue_urls: &[String],
    bundle: &qshard_core::CredentialBundle,
    seed: &RecoverySeed,
) -> Result<PlacementReceipt> {
    let set_id = bundle.signed_manifest.manifest.set_id;
    let shares = bundle
        .shares
        .iter()
        .map(|share| {
            UploadShare::from_bytes(
                share.header.share_id,
                share.header.share_index,
                &share.bytes,
            )
        })
        .collect();
    let upload = UploadCredential {
        manifest: bundle.signed_manifest.clone(),
        generation: 1,
        shares,
    };
    let key = seed.control_signing_key(set_id)?;
    let envelope = SignedEnvelope::sign("credential.upload", &upload, &key)?;
    post(client, blue_urls, "/v1/credentials", &envelope).await
}

async fn post<T: Serialize, R: DeserializeOwned>(
    client: &Client,
    bases: &[String],
    path: &str,
    body: &T,
) -> Result<R> {
    let mut failures = Vec::new();
    for _attempt in 0..2 {
        for base in bases {
            let response = match client.post(endpoint(base, path)).json(body).send().await {
                Ok(response) => response,
                Err(error) => {
                    failures.push(format!("{base}: {error}"));
                    continue;
                }
            };
            let status = response.status();
            let bytes = response
                .bytes()
                .await
                .context("failed to read the Blue node response")?;
            if status.is_success() {
                return serde_json::from_slice(&bytes)
                    .context("Blue node returned an invalid response");
            }
            let message = String::from_utf8_lossy(&bytes);
            if status.is_server_error() {
                failures.push(format!("{base}: {status} {message}"));
                continue;
            }
            bail!("Blue node returned {status}: {message}");
        }
    }
    bail!("all Blue endpoints failed: {}", failures.join("; "))
}

async fn repl(options: RuntimeOptions) -> Result<()> {
    println!("Qchain interactive shell. Type 'help' for commands or 'exit' to leave.");
    let mut editor = DefaultEditor::new()?;
    loop {
        match editor.readline("qchain> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if matches!(line, "exit" | "quit") {
                    break;
                }
                if line == "help" {
                    println!("Commands: store, recover, status, delete, list, exit");
                    println!("Use '<command> --help' for command-specific options.");
                    continue;
                }
                let Some(words) = shell_words::split(line).ok() else {
                    eprintln!("Error: unmatched quote in command");
                    continue;
                };
                let argv = std::iter::once("qchain".to_owned())
                    .chain(words)
                    .collect::<Vec<_>>();
                match Cli::try_parse_from(argv) {
                    Ok(parsed) => {
                        let parsed_options = RuntimeOptions {
                            blue: options.blue.clone(),
                            blue_urls: options.blue_urls.clone(),
                            directory_network: options.directory_network.clone(),
                            state_dir: options.state_dir.clone(),
                            allow_http: options.allow_http,
                            json: parsed.json || options.json,
                            client: options.client.clone(),
                        };
                        if let Some(command) = parsed.command {
                            if let Err(error) = execute(command, &parsed_options).await {
                                eprintln!("Error: {error:#}");
                            }
                        }
                    }
                    Err(error) => eprint!("{error}"),
                }
            }
            Err(ReadlineError::Interrupted) => {}
            Err(ReadlineError::Eof) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn resolve_blue(cli: &Cli) -> Result<(Vec<String>, Option<String>)> {
    if let Some(path) = &cli.directory {
        if cli.curator_public_key.is_empty() {
            bail!("at least one --curator-public-key is required with --directory");
        }
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let directory: SignedBlueDirectory =
            serde_json::from_slice(&bytes).context("signed Blue directory is invalid")?;
        let trusted = cli
            .curator_public_key
            .iter()
            .map(|value| {
                let bytes =
                    hex::decode(value).context("curator public key is not valid hexadecimal")?;
                bytes.try_into().map_err(|_| {
                    anyhow::anyhow!("curator public key must contain exactly 32 bytes")
                })
            })
            .collect::<Result<BTreeSet<[u8; 32]>>>()?;
        directory
            .verify(&trusted)
            .context("signed Blue directory verification failed")?;
        let network = directory.directory.network_id.clone();
        return Ok((
            directory
                .directory
                .nodes
                .into_iter()
                .map(|node| node.url)
                .collect(),
            Some(network),
        ));
    }
    if !cli.allow_unsigned_blue && !cli.allow_http {
        bail!(
            "production use requires --directory and --curator-public-key; use --allow-unsigned-blue only for development"
        );
    }
    Ok((vec![cli.blue.clone()], None))
}

fn record_blue_urls(record: &ClientRecord) -> Vec<String> {
    if record.blue_urls.is_empty() {
        vec![record.blue_url.clone()]
    } else {
        record.blue_urls.clone()
    }
}

fn operation_blue_urls(record: &ClientRecord, options: &RuntimeOptions) -> Result<Vec<String>> {
    if let Some(network) = options.directory_network.as_deref() {
        if record.manifest.manifest.network_id != network {
            bail!(
                "credential network {} does not match the signed Blue directory",
                record.manifest.manifest.network_id
            );
        }
        Ok(options.blue_urls.clone())
    } else {
        Ok(record_blue_urls(record))
    }
}
