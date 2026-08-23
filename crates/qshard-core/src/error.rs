use thiserror::Error;

#[derive(Debug, Error)]
pub enum QshardError {
    #[error("credential is empty")]
    EmptySecret,
    #[error("credential exceeds the {max} byte limit")]
    SecretTooLarge { max: usize },
    #[error("not enough distinct shares: found {found}, require {required}")]
    NotEnoughShares { found: usize, required: usize },
    #[error("shares belong to different credential sets")]
    MixedShareSets,
    #[error("duplicate share index {0}")]
    DuplicateShare(u8),
    #[error("invalid shard file: {0}")]
    InvalidShard(String),
    #[error("shard authentication failed")]
    AuthenticationFailed,
    #[error("recovery capsule authentication failed")]
    CapsuleAuthenticationFailed,
    #[error("recovery capsule is malformed")]
    MalformedCapsule,
    #[error("recovery passphrase cannot be empty")]
    EmptyPassphrase,
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("secret sharing failed: {0}")]
    SecretSharing(String),
    #[error("signature validation failed")]
    InvalidSignature,
}
