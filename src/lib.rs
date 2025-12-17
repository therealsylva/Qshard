pub mod cli;
pub mod crypto;
pub mod error;
pub mod file;
pub mod shamir;

use crate::crypto::{generate_key, AesKey};
use crate::error::QshardError;
use crate::file::{load_shard, save_shard};
use crate::shamir::{combine_secret, split_secret};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use hex;
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::read_password;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;
use rand::RngCore;
use std::path::PathBuf;

const NUM_SHARES: u8 = 5;
const THRESHOLD: u8 = 3;
const MIN_SECRET_LEN: usize = 64;

// --- NEW HELPER FUNCTION ---
/// Collects shard file paths from a source, which can be a file or a directory.
fn collect_shard_paths(source: &Path) -> Result<Vec<PathBuf>> {
    let mut shard_paths = Vec::new();

    if source.is_file() {
        shard_paths.push(source.to_path_buf());
    } else if source.is_dir() {
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "qshard") {
                shard_paths.push(path);
            }
        }
        if shard_paths.is_empty() {
            return Err(anyhow::anyhow!("No .qshard files found in directory: {}", source.display()));
        }
    } else {
        return Err(anyhow::anyhow!("Source is not a valid file or directory: {}", source.display()));
    }

    Ok(shard_paths)
}

fn read_secret() -> Result<String> {
    let secret = read_password()?;
    if secret.is_empty() {
        Err(anyhow::anyhow!("Secret cannot be empty."))
    } else {
        Ok(secret)
    }
}

// `run_create_command` remains the same
pub fn run_create_command(output_dir: &Path, id: Option<String>) -> Result<()> {
    // ... (no changes to this function) ...
    eprint!("Enter secret to shard: ");
    let secret = read_secret()?;
    let key = generate_key();
    let token = format!("QS-TKN-{}", STANDARD.encode(key.as_slice()));

    let mut secret_bytes = secret.into_bytes();
    let original_len = secret_bytes.len();
    
    if secret_bytes.len() < MIN_SECRET_LEN {
        let padding_len = MIN_SECRET_LEN - secret_bytes.len();
        let mut padding = vec![0u8; padding_len];
        rand::thread_rng().fill_bytes(&mut padding);
        secret_bytes.extend_from_slice(&padding);
    }

    let final_id = if let Some(user_id) = id {
        user_id
    } else {
        let mut bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };

    let shares = split_secret(&secret_bytes, THRESHOLD, NUM_SHARES)?;
    secret_bytes.zeroize();

    let pb = ProgressBar::new(NUM_SHARES as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    fs::create_dir_all(output_dir)?;
    for (i, share) in shares.into_iter().enumerate() {
        save_shard(
            share,
            (i + 1) as u8,
            THRESHOLD,
            &final_id,
            original_len as u16,
            &key,
            output_dir,
        )?;
        pb.inc(1);
    }
    pb.finish_with_message("Done.");

    println!("\n🔑 Recovery Token: {}", token);
    println!("⚠️  Save this token! It is required for recovery.");
    Ok(())
}


// --- UPDATED COMMAND FUNCTIONS ---
// These now use the `collect_shard_paths` helper.

pub fn run_recover_command(source: &Path) -> Result<()> {
    let shard_paths = collect_shard_paths(source)?;
    eprint!("Enter Recovery Token: ");
    let token = read_secret()?;
    let key_str = token.strip_prefix("QS-TKN-").unwrap_or(&token);
    let key_bytes = STANDARD.decode(key_str)?;
    let key = AesKey::from_slice(&key_bytes);

    let mut shares = Vec::new();
    let mut common_id: Option<String> = None;
    let mut original_len: Option<u16> = None;

    for path in &shard_paths {
        let (share, _, cid, len) = load_shard(path, key)?;
        if let Some(expected_cid) = &common_id {
            if &cid != expected_cid {
                return Err(QshardError::InvalidShardFile(
                    "Shard from a different set".into(),
                )
                .into());
            }
        } else {
            common_id = Some(cid);
            original_len = Some(len);
        }
        shares.push(share);
    }

    if shares.len() < THRESHOLD as usize {
        return Err(QshardError::NotEnoughShares.into());
    }

    let mut secret_bytes = combine_secret(&shares)?;
    let final_len = original_len.unwrap() as usize;
    secret_bytes.truncate(final_len);
    
    let secret = String::from_utf8(secret_bytes)?;
    println!("{}", secret);
    Ok(())
}

pub fn run_status_command(source: &Path) -> Result<()> {
    let shard_paths = collect_shard_paths(source)?;
    println!("Checking shard availability...");
    let mut found_ids = Vec::new();
    let mut common_id: Option<String> = None;

    for path in &shard_paths {
        let dummy_key = generate_key();
        match load_shard(path, &dummy_key) {
            Ok((_, share_id, cid, _)) => {
                if let Some(expected_cid) = &common_id {
                    if &cid != expected_cid {
                        println!("❓ {}: Shard from a different set.", path.display());
                        continue;
                    }
                } else {
                    common_id = Some(cid);
                }
                found_ids.push(share_id);
                println!("✅ {}: Shard {} is valid.", path.display(), share_id);
            }
            Err(QshardError::Crypto(_)) => {
                println!("❌ {}: Invalid or encrypted with a different token.", path.display());
            }
            Err(e) => {
                println!("❌ {}: {}", path.display(), e);
            }
        }
    }

    found_ids.sort_unstable();
    if found_ids.len() >= THRESHOLD as usize {
        println!(
            "\n✅ Recovery is possible with shards: {:?}",
            found_ids
        );
    } else {
        println!(
            "\n❌ Recovery not possible. Found {}/{} required shards.",
            found_ids.len(),
            THRESHOLD
        );
    }
    Ok(())
}

pub fn run_verify_command(source: &Path) -> Result<()> {
    let shard_paths = collect_shard_paths(source)?;
    eprint!("Enter Recovery Token: ");
    let token = read_secret()?;
    let key_str = token.strip_prefix("QS-TKN-").unwrap_or(&token);
    let key_bytes = STANDARD.decode(key_str)?;
    let key = AesKey::from_slice(&key_bytes);

    let mut shares = Vec::new();
    let mut common_id: Option<String> = None;
    let mut original_len: Option<u16> = None;

    for path in &shard_paths {
        let (share, _, cid, len) = load_shard(path, key)?;
        if let Some(expected_cid) = &common_id {
            if &cid != expected_cid {
                return Err(QshardError::InvalidShardFile(
                    "Shard from a different set".into(),
                )
                .into());
            }
        } else {
            common_id = Some(cid);
            original_len = Some(len);
        }
        shares.push(share);
    }

    if shares.len() < THRESHOLD as usize {
        return Err(QshardError::NotEnoughShares.into());
    }

    let mut secret_bytes = combine_secret(&shares)?;
    let final_len = original_len.unwrap() as usize;
    secret_bytes.truncate(final_len);
    secret_bytes.zeroize();

    println!("✅ Recovery is possible with these shards.");
    Ok(())
}

pub fn run_purge_command(source: &Path) -> Result<()> {
    let shard_paths = collect_shard_paths(source)?;
    let pb = ProgressBar::new(shard_paths.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.red} [{elapsed_precise}] [{bar:40.red/white}] {pos}/{len} ({msg})")
            .unwrap()
            .progress_chars("#>-"),
    );

    for path in shard_paths {
        if path.exists() {
            let file = fs::OpenOptions::new().write(true).open(&path)?;
            let metadata = file.metadata()?;
            file.set_len(metadata.len())?;
            drop(file);
            fs::remove_file(&path)?;
            pb.set_message(format!("Purged {}", path.display()));
        }
        pb.inc(1);
    }
    pb.finish_with_message("Done.");
    Ok(())
}