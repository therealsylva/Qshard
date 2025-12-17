use crate::{crypto, error::QshardError};
use aes_gcm::Aes256Gcm;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"QSHARD01";
const VERSION: u8 = 1;

#[derive(Serialize, Deserialize, Debug, Zeroize)]
pub struct ShardHeader {
    magic: [u8; 8],
    version: u8,
    threshold: u8,
    share_id: u8,
    common_id: String,
    secret_len: u16,
}

impl ShardHeader {
    pub fn new(threshold: u8, share_id: u8, common_id: String, secret_len: u16) -> Self {
        Self {
            magic: *MAGIC,
            version: VERSION,
            threshold,
            share_id,
            common_id,
            secret_len,
        }
    }

    pub fn validate(&self) -> Result<(), QshardError> {
        if self.magic != *MAGIC {
            return Err(QshardError::InvalidShardFile(
                "Invalid magic number".into(),
            ));
        }
        if self.version != VERSION {
            return Err(QshardError::InvalidShardFile(
                "Unsupported file version".into(),
            ));
        }
        Ok(())
    }
}

pub fn save_shard(
    share: Vec<u8>,
    share_id: u8,
    threshold: u8,
    common_id: &str,
    secret_len: u16,
    key: &aes_gcm::Key<Aes256Gcm>,
    output_dir: &std::path::Path,
) -> Result<(), QshardError> {
    let header = ShardHeader::new(threshold, share_id, common_id.to_string(), secret_len);
    let header_bytes = bincode::serialize(&header)?;

    let encrypted_share = crypto::encrypt(&share, key)?;
    
    let mut file_data = header_bytes;
    file_data.extend_from_slice(&encrypted_share);

    let safe_id = common_id.replace(' ', "_");
    let filename = format!("qs-{}-{}.qshard", safe_id, share_id);
    let path = output_dir.join(filename);

    std::fs::write(path, &file_data)?;
    Ok(())
}

pub fn load_shard(
    path: &std::path::Path,
    key: &aes_gcm::Key<Aes256Gcm>,
) -> Result<(Vec<u8>, u8, String, u16), QshardError> {
    let file_data = std::fs::read(path)?;

    // This is the corrected, more robust way to deserialize
    let mut cursor = std::io::Cursor::new(&file_data);
    let header: ShardHeader = bincode::deserialize_from(&mut cursor)?;
    header.validate()?;

    // Get the position of the cursor, which is the start of the encrypted data
    let header_size = cursor.position() as usize;
    let encrypted_share_bytes = &file_data[header_size..];

    let share = crypto::decrypt(encrypted_share_bytes, key)?;

    Ok((share, header.share_id, header.common_id, header.secret_len))
}

