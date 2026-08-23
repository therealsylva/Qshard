#![forbid(unsafe_code)]

mod error;

use std::collections::{BTreeMap, BTreeSet};

use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
pub use error::QshardError;
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const THRESHOLD: u8 = 3;
pub const SHARE_COUNT: u8 = 5;
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
pub const SHARD_MAGIC: &[u8; 8] = b"QSHARD02";
pub const SHARD_VERSION: u16 = 2;
const NONCE_LEN: usize = 24;
const MAX_HEADER_BYTES: usize = 4096;
const CAPSULE_PREFIX: &str = "QC-RCV1-";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryMode {
    PerCredential,
    Master,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoverySeed([u8; 32]);

impl RecoverySeed {
    #[must_use]
    pub fn generate() -> Self {
        let mut value = [0_u8; 32];
        OsRng.fill_bytes(&mut value);
        Self(value)
    }

    #[must_use]
    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn control_signing_key(&self, set_id: Uuid) -> Result<SigningKey, QshardError> {
        let keys = derive_keys(self, set_id)?;
        Ok(SigningKey::from_bytes(&keys.control))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardHeader {
    pub version: u16,
    pub network_id: String,
    pub set_id: Uuid,
    pub share_id: Uuid,
    pub share_index: u8,
    pub threshold: u8,
    pub share_count: u8,
    pub original_len: u32,
    pub control_public_key: [u8; 32],
    pub created_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareDescriptor {
    pub share_id: Uuid,
    pub share_index: u8,
    pub sha256: [u8; 32],
    pub encoded_len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: u16,
    pub network_id: String,
    pub set_id: Uuid,
    pub threshold: u8,
    pub share_count: u8,
    pub control_public_key: [u8; 32],
    pub created_at_unix: i64,
    pub shares: Vec<ShareDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedManifest {
    pub manifest: Manifest,
    pub signature: Vec<u8>,
}

impl SignedManifest {
    pub fn verify(&self) -> Result<(), QshardError> {
        let indices = self
            .manifest
            .shares
            .iter()
            .map(|share| share.share_index)
            .collect::<BTreeSet<_>>();
        let share_ids = self
            .manifest
            .shares
            .iter()
            .map(|share| share.share_id)
            .collect::<BTreeSet<_>>();
        if self.manifest.version != SHARD_VERSION
            || self.manifest.threshold != THRESHOLD
            || self.manifest.share_count != SHARE_COUNT
            || self.manifest.network_id.is_empty()
            || self.manifest.network_id.len() > 128
            || self.manifest.shares.len() != usize::from(SHARE_COUNT)
            || indices != BTreeSet::from([1, 2, 3, 4, 5])
            || share_ids.len() != usize::from(SHARE_COUNT)
            || self
                .manifest
                .shares
                .iter()
                .any(|share| share.encoded_len == 0)
        {
            return Err(QshardError::InvalidShard(
                "manifest invariants failed".to_owned(),
            ));
        }
        let key = VerifyingKey::from_bytes(&self.manifest.control_public_key)
            .map_err(|_| QshardError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| QshardError::InvalidSignature)?;
        let encoded = serde_json::to_vec(&self.manifest)?;
        key.verify(&encoded, &signature)
            .map_err(|_| QshardError::InvalidSignature)
    }

    #[must_use]
    pub fn descriptor(&self, index: u8) -> Option<&ShareDescriptor> {
        self.manifest
            .shares
            .iter()
            .find(|share| share.share_index == index)
    }
}

#[derive(Debug, Clone)]
pub struct EncodedShare {
    pub header: ShardHeader,
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct CredentialBundle {
    pub signed_manifest: SignedManifest,
    pub shares: Vec<EncodedShare>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryCapsule {
    pub version: u16,
    pub mode: RecoveryMode,
    pub network_id: String,
    pub set_id: Option<Uuid>,
    pub root_seed: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct CapsuleEnvelope {
    version: u16,
    salt: [u8; 16],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKeys {
    encryption: [u8; 32],
    control: [u8; 32],
}

fn derive_keys(seed: &RecoverySeed, set_id: Uuid) -> Result<DerivedKeys, QshardError> {
    let hkdf = Hkdf::<Sha256>::new(Some(set_id.as_bytes()), seed.expose());
    let mut encryption = [0_u8; 32];
    let mut control = [0_u8; 32];
    hkdf.expand(b"qchain/v1/shard-encryption", &mut encryption)
        .map_err(|_| QshardError::KeyDerivation)?;
    hkdf.expand(b"qchain/v1/control-signing", &mut control)
        .map_err(|_| QshardError::KeyDerivation)?;
    Ok(DerivedKeys {
        encryption,
        control,
    })
}

fn header_bytes(header: &ShardHeader) -> Result<Vec<u8>, QshardError> {
    let encoded = serde_json::to_vec(header)?;
    if encoded.len() > MAX_HEADER_BYTES {
        return Err(QshardError::InvalidShard("header is too large".to_owned()));
    }
    Ok(encoded)
}

fn encode_share(
    header: ShardHeader,
    plaintext: &[u8],
    encryption_key: &[u8; 32],
) -> Result<EncodedShare, QshardError> {
    let aad = header_bytes(&header)?;
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(encryption_key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| QshardError::AuthenticationFailed)?;
    let header_len = u32::try_from(aad.len())
        .map_err(|_| QshardError::InvalidShard("header length overflow".to_owned()))?;
    let mut bytes = Vec::with_capacity(8 + 2 + 4 + aad.len() + NONCE_LEN + ciphertext.len());
    bytes.extend_from_slice(SHARD_MAGIC);
    bytes.extend_from_slice(&SHARD_VERSION.to_be_bytes());
    bytes.extend_from_slice(&header_len.to_be_bytes());
    bytes.extend_from_slice(&aad);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    let sha256 = Sha256::digest(&bytes).into();
    Ok(EncodedShare {
        header,
        bytes,
        sha256,
    })
}

fn validate_header(header: &ShardHeader) -> Result<(), QshardError> {
    if header.version != SHARD_VERSION
        || header.threshold != THRESHOLD
        || header.share_count != SHARE_COUNT
        || !(1..=SHARE_COUNT).contains(&header.share_index)
        || header.original_len as usize > MAX_SECRET_BYTES
    {
        return Err(QshardError::InvalidShard(
            "header invariants failed".to_owned(),
        ));
    }
    Ok(())
}

fn decode_share(
    bytes: &[u8],
    encryption_key: &[u8; 32],
) -> Result<(ShardHeader, Vec<u8>), QshardError> {
    const PREFIX_LEN: usize = 14;
    if bytes.len() < PREFIX_LEN + NONCE_LEN + 16 {
        return Err(QshardError::InvalidShard("file is truncated".to_owned()));
    }
    if bytes.get(..8) != Some(SHARD_MAGIC.as_slice()) {
        return Err(QshardError::InvalidShard(
            "magic value does not match".to_owned(),
        ));
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != SHARD_VERSION {
        return Err(QshardError::InvalidShard(format!(
            "unsupported version {version}"
        )));
    }
    let header_len = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    if header_len == 0 || header_len > MAX_HEADER_BYTES {
        return Err(QshardError::InvalidShard(
            "invalid header length".to_owned(),
        ));
    }
    let header_end = PREFIX_LEN
        .checked_add(header_len)
        .ok_or_else(|| QshardError::InvalidShard("header length overflow".to_owned()))?;
    let nonce_end = header_end
        .checked_add(NONCE_LEN)
        .ok_or_else(|| QshardError::InvalidShard("nonce length overflow".to_owned()))?;
    if nonce_end + 16 > bytes.len() {
        return Err(QshardError::InvalidShard("file is truncated".to_owned()));
    }
    let aad = &bytes[PREFIX_LEN..header_end];
    let header: ShardHeader = serde_json::from_slice(aad)?;
    validate_header(&header)?;
    let nonce = XNonce::from_slice(&bytes[header_end..nonce_end]);
    let cipher = XChaCha20Poly1305::new(encryption_key.into());
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &bytes[nonce_end..],
                aad,
            },
        )
        .map_err(|_| QshardError::AuthenticationFailed)?;
    Ok((header, plaintext))
}

pub fn create_credential_bundle(
    secret: &[u8],
    seed: &RecoverySeed,
    network_id: &str,
    set_id: Option<Uuid>,
) -> Result<CredentialBundle, QshardError> {
    if secret.is_empty() {
        return Err(QshardError::EmptySecret);
    }
    if secret.len() > MAX_SECRET_BYTES {
        return Err(QshardError::SecretTooLarge {
            max: MAX_SECRET_BYTES,
        });
    }
    if network_id.is_empty() || network_id.len() > 128 {
        return Err(QshardError::InvalidShard(
            "invalid network identifier".to_owned(),
        ));
    }
    let set_id = set_id.unwrap_or_else(Uuid::new_v4);
    let keys = derive_keys(seed, set_id)?;
    let signing_key = SigningKey::from_bytes(&keys.control);
    let control_public_key = signing_key.verifying_key().to_bytes();
    let created_at_unix = Utc::now().timestamp();
    let sharks = Sharks(THRESHOLD);
    let raw_shares: Vec<Share> = sharks.dealer(secret).take(SHARE_COUNT.into()).collect();
    let original_len = u32::try_from(secret.len()).map_err(|_| QshardError::SecretTooLarge {
        max: MAX_SECRET_BYTES,
    })?;
    let mut shares = Vec::with_capacity(SHARE_COUNT.into());
    for (offset, share) in raw_shares.iter().enumerate() {
        let share_index = u8::try_from(offset + 1)
            .map_err(|_| QshardError::InvalidShard("share index overflow".to_owned()))?;
        let header = ShardHeader {
            version: SHARD_VERSION,
            network_id: network_id.to_owned(),
            set_id,
            share_id: Uuid::new_v4(),
            share_index,
            threshold: THRESHOLD,
            share_count: SHARE_COUNT,
            original_len,
            control_public_key,
            created_at_unix,
        };
        shares.push(encode_share(
            header,
            &Vec::<u8>::from(share),
            &keys.encryption,
        )?);
    }
    let descriptors = shares
        .iter()
        .map(|share| {
            let encoded_len = u32::try_from(share.bytes.len())
                .map_err(|_| QshardError::InvalidShard("encoded share is too large".to_owned()))?;
            Ok(ShareDescriptor {
                share_id: share.header.share_id,
                share_index: share.header.share_index,
                sha256: share.sha256,
                encoded_len,
            })
        })
        .collect::<Result<Vec<_>, QshardError>>()?;
    let manifest = Manifest {
        version: SHARD_VERSION,
        network_id: network_id.to_owned(),
        set_id,
        threshold: THRESHOLD,
        share_count: SHARE_COUNT,
        control_public_key,
        created_at_unix,
        shares: descriptors,
    };
    let signature = signing_key
        .sign(&serde_json::to_vec(&manifest)?)
        .to_bytes()
        .to_vec();
    let signed_manifest = SignedManifest {
        manifest,
        signature,
    };
    signed_manifest.verify()?;
    Ok(CredentialBundle {
        signed_manifest,
        shares,
    })
}

pub fn recover_credential(
    encoded_shares: &[Vec<u8>],
    seed: &RecoverySeed,
    expected_manifest: Option<&SignedManifest>,
) -> Result<Vec<u8>, QshardError> {
    if encoded_shares.len() < THRESHOLD.into() {
        return Err(QshardError::NotEnoughShares {
            found: encoded_shares.len(),
            required: THRESHOLD.into(),
        });
    }
    if let Some(manifest) = expected_manifest {
        manifest.verify()?;
    }
    let first = peek_header(&encoded_shares[0])?;
    let keys = derive_keys(seed, first.set_id)?;
    let derived_control_public_key = SigningKey::from_bytes(&keys.control)
        .verifying_key()
        .to_bytes();
    if first
        .control_public_key
        .ct_eq(&derived_control_public_key)
        .unwrap_u8()
        != 1
        || expected_manifest.is_some_and(|manifest| {
            manifest.manifest.control_public_key != derived_control_public_key
        })
    {
        return Err(QshardError::InvalidSignature);
    }
    let mut decoded = BTreeMap::<u8, Share>::new();
    for bytes in encoded_shares {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let (header, plaintext) = decode_share(bytes, &keys.encryption)?;
        let plaintext = Zeroizing::new(plaintext);
        if header.set_id != first.set_id
            || header
                .control_public_key
                .ct_eq(&first.control_public_key)
                .unwrap_u8()
                != 1
        {
            return Err(QshardError::MixedShareSets);
        }
        if let Some(manifest) = expected_manifest {
            if manifest.manifest.set_id != header.set_id {
                return Err(QshardError::MixedShareSets);
            }
            let descriptor = manifest.descriptor(header.share_index).ok_or_else(|| {
                QshardError::InvalidShard("share absent from manifest".to_owned())
            })?;
            if descriptor.share_id != header.share_id
                || descriptor.sha256.ct_eq(&digest).unwrap_u8() != 1
            {
                return Err(QshardError::InvalidShard(
                    "share hash does not match manifest".to_owned(),
                ));
            }
        }
        let share = Share::try_from(plaintext.as_slice())
            .map_err(|error| QshardError::SecretSharing(error.to_owned()))?;
        if decoded.insert(header.share_index, share).is_some() {
            return Err(QshardError::DuplicateShare(header.share_index));
        }
    }
    if decoded.len() < THRESHOLD.into() {
        return Err(QshardError::NotEnoughShares {
            found: decoded.len(),
            required: THRESHOLD.into(),
        });
    }
    let secret = Sharks(THRESHOLD)
        .recover(decoded.values())
        .map_err(|error| QshardError::SecretSharing(error.to_owned()))?;
    if secret.len() != first.original_len as usize {
        return Err(QshardError::InvalidShard(
            "recovered length does not match authenticated metadata".to_owned(),
        ));
    }
    Ok(secret)
}

pub fn peek_header(bytes: &[u8]) -> Result<ShardHeader, QshardError> {
    const PREFIX_LEN: usize = 14;
    if bytes.len() < PREFIX_LEN || bytes.get(..8) != Some(SHARD_MAGIC.as_slice()) {
        return Err(QshardError::InvalidShard(
            "invalid or truncated prefix".to_owned(),
        ));
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != SHARD_VERSION {
        return Err(QshardError::InvalidShard(format!(
            "unsupported version {version}"
        )));
    }
    let header_len = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    if header_len == 0 || header_len > MAX_HEADER_BYTES || PREFIX_LEN + header_len > bytes.len() {
        return Err(QshardError::InvalidShard(
            "invalid header length".to_owned(),
        ));
    }
    let header = serde_json::from_slice(&bytes[PREFIX_LEN..PREFIX_LEN + header_len])?;
    validate_header(&header)?;
    Ok(header)
}

impl RecoveryCapsule {
    #[must_use]
    pub fn new(
        mode: RecoveryMode,
        network_id: String,
        set_id: Option<Uuid>,
        seed: &RecoverySeed,
    ) -> Self {
        Self {
            version: 1,
            mode,
            network_id,
            set_id,
            root_seed: *seed.expose(),
        }
    }

    pub fn seal(&self, passphrase: &str) -> Result<String, QshardError> {
        if passphrase.is_empty() {
            return Err(QshardError::EmptyPassphrase);
        }
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let mut key = Zeroizing::new([0_u8; 32]);
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt, &mut *key)
            .map_err(|_| QshardError::KeyDerivation)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(self)?);
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|_| QshardError::CapsuleAuthenticationFailed)?;
        let envelope = CapsuleEnvelope {
            version: 1,
            salt,
            nonce,
            ciphertext,
        };
        Ok(format!(
            "{CAPSULE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope)?)
        ))
    }

    pub fn open(encoded: &str, passphrase: &str) -> Result<Self, QshardError> {
        if passphrase.is_empty() {
            return Err(QshardError::EmptyPassphrase);
        }
        let payload = encoded
            .strip_prefix(CAPSULE_PREFIX)
            .ok_or(QshardError::MalformedCapsule)?;
        let envelope: CapsuleEnvelope = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
        if envelope.version != 1 {
            return Err(QshardError::MalformedCapsule);
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &envelope.salt, &mut *key)
            .map_err(|_| QshardError::KeyDerivation)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&envelope.nonce),
                    envelope.ciphertext.as_slice(),
                )
                .map_err(|_| QshardError::CapsuleAuthenticationFailed)?,
        );
        let capsule: Self = serde_json::from_slice(&plaintext)?;
        if capsule.version != 1 {
            return Err(QshardError::MalformedCapsule);
        }
        Ok(capsule)
    }

    #[must_use]
    pub fn seed(&self) -> RecoverySeed {
        RecoverySeed::from_bytes(self.root_seed)
    }
}

impl Drop for RecoveryCapsule {
    fn drop(&mut self) {
        self.root_seed.zeroize();
    }
}

#[must_use]
pub fn unique_share_indices(shares: &[EncodedShare]) -> BTreeSet<u8> {
    shares
        .iter()
        .map(|share| share.header.share_index)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_three_share_combination_recovers() -> Result<(), QshardError> {
        let seed = RecoverySeed::generate();
        let secret = b"a production credential longer than the legacy sixty-four-byte boundary and still recoverable";
        let bundle = create_credential_bundle(secret, &seed, "qchain-test", None)?;
        for a in 0..3 {
            for b in (a + 1)..4 {
                for c in (b + 1)..5 {
                    let selected = vec![
                        bundle.shares[a].bytes.clone(),
                        bundle.shares[b].bytes.clone(),
                        bundle.shares[c].bytes.clone(),
                    ];
                    assert_eq!(
                        recover_credential(&selected, &seed, Some(&bundle.signed_manifest))?,
                        secret
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn two_shares_cannot_recover() -> Result<(), QshardError> {
        let seed = RecoverySeed::generate();
        let bundle = create_credential_bundle(b"credential", &seed, "qchain-test", None)?;
        assert!(matches!(
            recover_credential(
                &[
                    bundle.shares[0].bytes.clone(),
                    bundle.shares[1].bytes.clone()
                ],
                &seed,
                Some(&bundle.signed_manifest)
            ),
            Err(QshardError::NotEnoughShares { .. })
        ));
        Ok(())
    }

    #[test]
    fn tampering_is_rejected() -> Result<(), QshardError> {
        let seed = RecoverySeed::generate();
        let bundle = create_credential_bundle(b"credential", &seed, "qchain-test", None)?;
        let mut bytes = bundle.shares[0].bytes.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(
            recover_credential(
                &[
                    bytes,
                    bundle.shares[1].bytes.clone(),
                    bundle.shares[2].bytes.clone()
                ],
                &seed,
                None
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn wrong_seed_mixed_sets_and_duplicate_indices_are_rejected() -> Result<(), QshardError> {
        let seed = RecoverySeed::generate();
        let first = create_credential_bundle(b"credential one", &seed, "qchain-test", None)?;
        let second = create_credential_bundle(b"credential two", &seed, "qchain-test", None)?;
        assert!(
            recover_credential(
                &first.shares[..3]
                    .iter()
                    .map(|share| share.bytes.clone())
                    .collect::<Vec<_>>(),
                &RecoverySeed::generate(),
                Some(&first.signed_manifest),
            )
            .is_err()
        );
        assert!(matches!(
            recover_credential(
                &[
                    first.shares[0].bytes.clone(),
                    first.shares[1].bytes.clone(),
                    second.shares[2].bytes.clone(),
                ],
                &seed,
                None,
            ),
            Err(QshardError::AuthenticationFailed | QshardError::MixedShareSets)
        ));
        assert!(matches!(
            recover_credential(
                &[
                    first.shares[0].bytes.clone(),
                    first.shares[0].bytes.clone(),
                    first.shares[1].bytes.clone(),
                ],
                &seed,
                Some(&first.signed_manifest),
            ),
            Err(QshardError::DuplicateShare(1))
        ));
        Ok(())
    }

    #[test]
    fn capsule_round_trip_and_wrong_password_failure() -> Result<(), QshardError> {
        let seed = RecoverySeed::generate();
        let capsule = RecoveryCapsule::new(
            RecoveryMode::PerCredential,
            "qchain-test".to_owned(),
            Some(Uuid::new_v4()),
            &seed,
        );
        let sealed = capsule.seal("correct horse battery staple")?;
        let opened = RecoveryCapsule::open(&sealed, "correct horse battery staple")?;
        assert_eq!(opened.root_seed, capsule.root_seed);
        assert!(RecoveryCapsule::open(&sealed, "wrong password").is_err());
        Ok(())
    }
}
