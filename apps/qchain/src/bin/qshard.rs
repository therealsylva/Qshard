#![forbid(unsafe_code)]

use std::{fs, io::Write as _, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use qchain_cli::{
    atomic_write, initialize_logging, load_capsule, print_value, read_secret, save_capsule,
    validate_capsule_context,
};
use qshard_core::{
    RecoveryCapsule, RecoveryMode, RecoverySeed, SignedManifest, create_credential_bundle,
    peek_header, recover_credential,
};
use rustyline::{DefaultEditor, error::ReadlineError};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[derive(Debug, Parser)]
#[command(
    name = "qshard",
    version,
    about = "Create and recover encrypted Qshard credential shares"
)]
struct Cli {
    #[arg(long, global = true, help = "Print machine-readable JSON")]
    json: bool,
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Split and encrypt one credential into five shares.
    Split(SplitArgs),
    /// Recover a credential from any three valid shares.
    Recover(RecoverArgs),
    /// Authenticate a share set and test reconstruction without emitting the secret.
    Verify(VerifyArgs),
    /// Display non-secret authenticated share or manifest metadata.
    Inspect(InspectArgs),
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
struct SplitArgs {
    #[arg(
        long,
        help = "Read the credential from this file; otherwise use a hidden prompt or standard input"
    )]
    input: Option<PathBuf>,
    #[arg(long, default_value = "qshard-output")]
    output_dir: PathBuf,
    #[arg(long, default_value = "qchain-mainnet")]
    network: String,
    #[arg(long, value_enum, default_value = "per-credential")]
    recovery_mode: RecoveryModeArg,
    #[arg(
        long,
        help = "Recovery capsule path; master mode reuses an existing capsule"
    )]
    capsule: Option<PathBuf>,
    #[arg(long, help = "Read the recovery passphrase from a protected file")]
    passphrase_file: Option<PathBuf>,
    #[arg(long, help = "Replace existing output files")]
    force: bool,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    #[arg(required = true, num_args = 3..=5)]
    shares: Vec<PathBuf>,
    #[arg(long)]
    capsule: PathBuf,
    #[arg(long)]
    manifest: Option<PathBuf>,
    #[arg(long, conflicts_with = "stdout")]
    output: Option<PathBuf>,
    #[arg(long, help = "Write the recovered credential to standard output")]
    stdout: bool,
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    #[arg(required = true, num_args = 3..=5)]
    shares: Vec<PathBuf>,
    #[arg(long)]
    capsule: PathBuf,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct InspectArgs {
    path: PathBuf,
}

#[derive(Debug, Serialize)]
struct SplitReport {
    set_id: uuid::Uuid,
    threshold: u8,
    share_count: u8,
    manifest: PathBuf,
    recovery_capsule: PathBuf,
    shares: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
struct VerifyReport {
    set_id: uuid::Uuid,
    valid: bool,
    supplied_shares: usize,
    unique_share_indices: Vec<u8>,
}

fn main() {
    let cli = Cli::parse();
    initialize_logging(cli.verbose);
    if let Err(error) = dispatch(cli) {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command.unwrap_or(Command::Repl) {
        Command::Split(args) => split(args, cli.json),
        Command::Recover(args) => recover(args, cli.json),
        Command::Verify(args) => verify(&args, cli.json),
        Command::Inspect(args) => inspect(&args, cli.json),
        Command::Repl => repl(cli.json),
    }
}

fn split(args: SplitArgs, json: bool) -> Result<()> {
    let secret = read_secret(args.input.as_deref())?;
    let master_capsule_path = args
        .capsule
        .clone()
        .unwrap_or_else(|| args.output_dir.join("master.recovery.qrc"));
    let (seed, existing_master) =
        if matches!(args.recovery_mode, RecoveryModeArg::Master) && master_capsule_path.exists() {
            let capsule = load_capsule(&master_capsule_path, args.passphrase_file.as_deref())?;
            if capsule.mode != RecoveryMode::Master
                || capsule.set_id.is_some()
                || capsule.network_id != args.network
            {
                bail!("the master recovery capsule belongs to a different mode or network");
            }
            (capsule.seed(), true)
        } else {
            (RecoverySeed::generate(), false)
        };
    let bundle = create_credential_bundle(&secret, &seed, &args.network, None)?;
    let set_id = bundle.signed_manifest.manifest.set_id;
    let manifest_path = args.output_dir.join(format!("{set_id}.manifest.json"));
    let capsule_path = match args.recovery_mode {
        RecoveryModeArg::Master => master_capsule_path,
        RecoveryModeArg::PerCredential => args
            .capsule
            .clone()
            .unwrap_or_else(|| args.output_dir.join(format!("{set_id}.recovery.qrc"))),
    };
    let capsule_set_id = match args.recovery_mode {
        RecoveryModeArg::PerCredential => Some(set_id),
        RecoveryModeArg::Master => None,
    };
    let capsule = RecoveryCapsule::new(
        args.recovery_mode.into(),
        args.network,
        capsule_set_id,
        &seed,
    );
    let manifest_bytes = serde_json::to_vec_pretty(&bundle.signed_manifest)?;
    atomic_write(&manifest_path, &manifest_bytes, args.force, false)?;
    if !existing_master {
        save_capsule(
            &capsule_path,
            &capsule,
            args.passphrase_file.as_deref(),
            args.force,
        )?;
    }
    let mut share_paths = Vec::with_capacity(bundle.shares.len());
    for share in bundle.shares {
        let path = args.output_dir.join(format!(
            "{set_id}.share-{}.qshare",
            share.header.share_index
        ));
        atomic_write(&path, &share.bytes, args.force, true)?;
        share_paths.push(path);
    }
    let report = SplitReport {
        set_id,
        threshold: bundle.signed_manifest.manifest.threshold,
        share_count: bundle.signed_manifest.manifest.share_count,
        manifest: manifest_path,
        recovery_capsule: capsule_path,
        shares: share_paths,
    };
    if json {
        print_value(&report, true)?;
    } else {
        println!("Credential set: {}", report.set_id);
        println!(
            "Recovery threshold: {} of {}",
            report.threshold, report.share_count
        );
        println!("Manifest: {}", report.manifest.display());
        println!("Recovery capsule: {}", report.recovery_capsule.display());
        println!("Encrypted shares:");
        for path in report.shares {
            println!("  {}", path.display());
        }
    }
    Ok(())
}

fn recover(args: RecoverArgs, json: bool) -> Result<()> {
    if args.output.is_none() && !args.stdout {
        bail!("choose --output <path> or --stdout");
    }
    let capsule = load_capsule(&args.capsule, args.passphrase_file.as_deref())?;
    let manifest = args.manifest.as_ref().map(load_manifest).transpose()?;
    let encoded = read_shares(&args.shares)?;
    let first_header = peek_header(
        encoded
            .first()
            .context("at least one encrypted share is required")?,
    )?;
    validate_capsule_context(&capsule, first_header.set_id, &first_header.network_id)?;
    let secret = zeroize::Zeroizing::new(recover_credential(
        &encoded,
        &capsule.seed(),
        manifest.as_ref(),
    )?);
    if let Some(path) = args.output {
        atomic_write(&path, &secret, args.force, true)?;
        if !json {
            println!("Recovered credential written to {}", path.display());
        }
    } else {
        std::io::stdout().write_all(&secret)?;
        std::io::stdout().flush()?;
    }
    if json {
        print_value(
            &serde_json::json!({"set_id": first_header.set_id, "recovered": true}),
            true,
        )?;
    }
    Ok(())
}

fn verify(args: &VerifyArgs, json: bool) -> Result<()> {
    let capsule = load_capsule(&args.capsule, args.passphrase_file.as_deref())?;
    let manifest = load_manifest(&args.manifest)?;
    validate_capsule_context(
        &capsule,
        manifest.manifest.set_id,
        &manifest.manifest.network_id,
    )?;
    let encoded = read_shares(&args.shares)?;
    let recovered = zeroize::Zeroizing::new(recover_credential(
        &encoded,
        &capsule.seed(),
        Some(&manifest),
    )?);
    let mut indices = encoded
        .iter()
        .map(|bytes| peek_header(bytes).map(|header| header.share_index))
        .collect::<Result<Vec<_>, _>>()?;
    indices.sort_unstable();
    indices.dedup();
    let report = VerifyReport {
        set_id: manifest.manifest.set_id,
        valid: !recovered.is_empty(),
        supplied_shares: encoded.len(),
        unique_share_indices: indices,
    };
    if json {
        print_value(&report, true)?;
    } else {
        println!("Set {} is valid.", report.set_id);
        println!(
            "Authenticated distinct shares: {}",
            report.unique_share_indices.len()
        );
        println!("Reconstruction test: passed");
    }
    Ok(())
}

fn inspect(args: &InspectArgs, json: bool) -> Result<()> {
    let bytes =
        fs::read(&args.path).with_context(|| format!("failed to read {}", args.path.display()))?;
    if let Ok(manifest) = serde_json::from_slice::<SignedManifest>(&bytes) {
        manifest.verify()?;
        if json {
            print_value(&manifest, true)?;
        } else {
            println!("Type: signed manifest");
            println!("Set: {}", manifest.manifest.set_id);
            println!("Network: {}", manifest.manifest.network_id);
            println!(
                "Threshold: {} of {}",
                manifest.manifest.threshold, manifest.manifest.share_count
            );
            println!("Shares: {}", manifest.manifest.shares.len());
            println!("Signature: valid");
        }
        return Ok(());
    }
    let header = peek_header(&bytes)?;
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    if json {
        print_value(
            &serde_json::json!({"header": header, "sha256": hex::encode(sha256)}),
            true,
        )?;
    } else {
        println!("Type: encrypted share");
        println!("Set: {}", header.set_id);
        println!("Share index: {}", header.share_index);
        println!("Share identifier: {}", header.share_id);
        println!("Network: {}", header.network_id);
        println!("SHA-256: {}", hex::encode(sha256));
    }
    Ok(())
}

fn repl(json: bool) -> Result<()> {
    println!("Qshard interactive shell. Type 'help' for commands or 'exit' to leave.");
    let mut editor = DefaultEditor::new()?;
    loop {
        match editor.readline("qshard> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if matches!(line, "exit" | "quit") {
                    break;
                }
                if line == "help" {
                    println!("Commands: split, recover, verify, inspect, exit");
                    println!("Use '<command> --help' for command-specific options.");
                    continue;
                }
                let Some(words) = shell_words::split(line).ok() else {
                    eprintln!("Error: unmatched quote in command");
                    continue;
                };
                let argv = std::iter::once("qshard".to_owned())
                    .chain(words)
                    .collect::<Vec<_>>();
                match Cli::try_parse_from(argv) {
                    Ok(parsed) => {
                        if matches!(parsed.command, Some(Command::Repl) | None) {
                            eprintln!("Error: nested interactive shells are not supported");
                        } else if let Err(error) = dispatch(Cli {
                            json: parsed.json || json,
                            ..parsed
                        }) {
                            eprintln!("Error: {error:#}");
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

fn read_shares(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    paths
        .iter()
        .map(|path| fs::read(path).with_context(|| format!("failed to read {}", path.display())))
        .collect()
}

fn load_manifest(path: &PathBuf) -> Result<SignedManifest> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let manifest: SignedManifest =
        serde_json::from_slice(&bytes).context("manifest JSON is invalid")?;
    manifest.verify()?;
    Ok(manifest)
}
