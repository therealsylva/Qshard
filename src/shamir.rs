use crate::error::QshardError;
use shamirsecretsharing::{create_shares, combine_shares};

pub fn split_secret(secret: &[u8], threshold: u8, num_shares: u8) -> Result<Vec<Vec<u8>>, QshardError> {
    // The crate expects (secret, num_shares, threshold)
    create_shares(secret, num_shares, threshold)
        .map_err(|e| QshardError::Shamir(e.to_string()))
}

pub fn combine_secret(shares: &[Vec<u8>]) -> Result<Vec<u8>, QshardError> {
    combine_shares(shares)
        .map_err(|e| QshardError::Shamir(e.to_string()))?
        .ok_or(QshardError::ShareCombinationFailed)
}