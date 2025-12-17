use crate::error::QshardError;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

pub type AesKey = Key<Aes256Gcm>;

pub fn generate_key() -> AesKey {
    Aes256Gcm::generate_key(&mut OsRng)
}

pub fn encrypt(plaintext: &[u8], key: &AesKey) -> Result<Vec<u8>, QshardError> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| QshardError::Crypto(e.to_string()))?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt(ciphertext_with_nonce: &[u8], key: &AesKey) -> Result<Vec<u8>, QshardError> {
    if ciphertext_with_nonce.len() < 12 {
        return Err(QshardError::Crypto("Ciphertext is too short".into()));
    }

    let cipher = Aes256Gcm::new(key);
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| QshardError::Crypto(e.to_string()))
}