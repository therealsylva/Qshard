#![forbid(unsafe_code)]

use std::{
    fs::{self, File},
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use directories::ProjectDirs;
use qshard_core::{RecoveryCapsule, RecoveryMode, SignedManifest};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRecord {
    pub label: String,
    pub blue_url: String,
    #[serde(default)]
    pub blue_urls: Vec<String>,
    pub capsule_path: PathBuf,
    pub manifest: SignedManifest,
    pub generation: u64,
    pub active: bool,
    pub replacement_set_id: Option<Uuid>,
}

#[must_use]
pub fn default_state_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("QCHAIN_STATE_DIR") {
        return PathBuf::from(path);
    }
    ProjectDirs::from("network", "Qchain", "Qchain").map_or_else(
        || PathBuf::from(".qchain"),
        |dirs| dirs.data_local_dir().to_path_buf(),
    )
}

pub fn initialize_logging(verbose: bool) {
    let default_filter = if verbose {
        "qchain=debug"
    } else {
        "qchain=warn"
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

pub fn ensure_https(url: &str, allow_http: bool) -> Result<()> {
    let parsed = reqwest::Url::parse(url).context("the Blue node URL is invalid")?;
    if parsed.scheme() != "https" && !(allow_http && parsed.scheme() == "http") {
        bail!("the Blue node URL must use HTTPS; use --allow-http only for local development");
    }
    Ok(())
}

#[must_use]
pub fn endpoint(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

pub fn read_secret(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(path) = path {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read secret from {}", path.display()))?;
        return Ok(Zeroizing::new(bytes));
    }
    if !io::stdin().is_terminal() {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .context("failed to read the secret from standard input")?;
        trim_one_line_ending(&mut bytes);
        return Ok(Zeroizing::new(bytes));
    }
    let value =
        rpassword::prompt_password("Credential: ").context("failed to read the credential")?;
    Ok(Zeroizing::new(value.into_bytes()))
}

pub fn read_passphrase(path: Option<&Path>, confirm: bool) -> Result<Zeroizing<String>> {
    if let Some(path) = path {
        let mut value = fs::read_to_string(path)
            .with_context(|| format!("failed to read passphrase from {}", path.display()))?;
        while value.ends_with(['\n', '\r']) {
            value.pop();
        }
        if value.is_empty() {
            bail!("the passphrase file is empty");
        }
        return Ok(Zeroizing::new(value));
    }
    if !io::stdin().is_terminal() {
        bail!("a passphrase file is required when standard input is not a terminal");
    }
    let first = Zeroizing::new(rpassword::prompt_password("Recovery passphrase: ")?);
    if first.is_empty() {
        bail!("the recovery passphrase cannot be empty");
    }
    if confirm {
        let second = Zeroizing::new(rpassword::prompt_password("Confirm recovery passphrase: ")?);
        if *first != *second {
            bail!("the recovery passphrases do not match");
        }
    }
    Ok(first)
}

pub fn load_capsule(path: &Path, passphrase_file: Option<&Path>) -> Result<RecoveryCapsule> {
    let encoded = fs::read_to_string(path)
        .with_context(|| format!("failed to read recovery capsule {}", path.display()))?;
    let passphrase = read_passphrase(passphrase_file, false)?;
    RecoveryCapsule::open(encoded.trim(), &passphrase)
        .context("failed to open the recovery capsule")
}

pub fn save_capsule(
    path: &Path,
    capsule: &RecoveryCapsule,
    passphrase_file: Option<&Path>,
    overwrite: bool,
) -> Result<()> {
    let passphrase = read_passphrase(passphrase_file, true)?;
    let encoded = capsule
        .seal(&passphrase)
        .context("failed to seal the recovery capsule")?;
    atomic_write(path, encoded.as_bytes(), overwrite, true)
}

pub fn atomic_write(path: &Path, bytes: &[u8], overwrite: bool, private: bool) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    if path.exists() && !overwrite {
        bail!(
            "{} already exists; use --force to replace it",
            path.display()
        );
    }
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create a temporary file in {}", parent.display()))?;
    temporary
        .write_all(bytes)
        .context("failed to write the temporary file")?;
    temporary
        .as_file()
        .sync_all()
        .context("failed to synchronize the temporary file")?;
    if private {
        set_private_permissions(temporary.as_file())?;
    }
    temporary
        .persist(path)
        .map_err(|error| anyhow!("failed to persist {}: {}", path.display(), error.error))?;
    sync_directory(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("failed to synchronize {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("failed to restrict file permissions")
}

#[cfg(not(unix))]
fn set_private_permissions(_file: &File) -> Result<()> {
    Ok(())
}

#[must_use]
pub fn record_path(state_dir: &Path, set_id: Uuid) -> PathBuf {
    state_dir.join("credentials").join(format!("{set_id}.json"))
}

pub fn save_record(state_dir: &Path, record: &ClientRecord) -> Result<()> {
    let path = record_path(state_dir, record.manifest.manifest.set_id);
    let bytes =
        serde_json::to_vec_pretty(record).context("failed to encode local credential state")?;
    atomic_write(&path, &bytes, true, true)
}

pub fn load_record(state_dir: &Path, set_id: Uuid) -> Result<ClientRecord> {
    let path = record_path(state_dir, set_id);
    let bytes =
        fs::read(&path).with_context(|| format!("failed to read local state for {set_id}"))?;
    let record: ClientRecord =
        serde_json::from_slice(&bytes).context("local credential state is invalid")?;
    record
        .manifest
        .verify()
        .context("local credential manifest verification failed")?;
    if record.manifest.manifest.set_id != set_id {
        bail!("local credential record does not match the requested set");
    }
    Ok(record)
}

pub fn validate_capsule_context(
    capsule: &RecoveryCapsule,
    set_id: Uuid,
    network_id: &str,
) -> Result<()> {
    if capsule.network_id != network_id
        || match capsule.mode {
            RecoveryMode::PerCredential => capsule.set_id != Some(set_id),
            RecoveryMode::Master => capsule.set_id.is_some(),
        }
    {
        bail!("recovery capsule does not match the credential context");
    }
    Ok(())
}

pub fn print_value<T: Serialize>(value: &T, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn trim_one_line_ending(bytes: &mut Vec<u8>) {
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
}

#[cfg(test)]
mod tests {
    use qshard_core::RecoverySeed;

    use super::*;

    #[test]
    fn recovery_capsule_is_bound_to_mode_network_and_set() -> Result<()> {
        let seed = RecoverySeed::generate();
        let set_id = Uuid::new_v4();
        let capsule = RecoveryCapsule::new(
            RecoveryMode::PerCredential,
            "qchain-test".to_owned(),
            Some(set_id),
            &seed,
        );
        validate_capsule_context(&capsule, set_id, "qchain-test")?;
        assert!(validate_capsule_context(&capsule, Uuid::new_v4(), "qchain-test").is_err());
        assert!(validate_capsule_context(&capsule, set_id, "other-network").is_err());

        let master =
            RecoveryCapsule::new(RecoveryMode::Master, "qchain-test".to_owned(), None, &seed);
        validate_capsule_context(&master, Uuid::new_v4(), "qchain-test")?;
        Ok(())
    }
}
