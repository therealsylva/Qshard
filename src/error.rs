use thiserror::Error;

#[derive(Error, Debug)]
pub enum QshardError {
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptography Error: {0}")]
    Crypto(String),

    #[error("Shamir Secret Sharing Error: {0}")]
    Shamir(String),

    #[error("Invalid shard file: {0}")]
    InvalidShardFile(String),

    #[error("Not enough shares provided to meet the threshold.")]
    NotEnoughShares,

    #[error("Provided shares do not combine to a valid secret.")]
    ShareCombinationFailed,

    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Bincode serialization/deserialization error: {0}")]
    Bincode(#[from] bincode::Error),
}