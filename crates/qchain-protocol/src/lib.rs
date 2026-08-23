#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use qshard_core::SignedManifest;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_REQUEST_TTL_SECONDS: i64 = 120;
const WHITE_CERTIFICATE_PREFIX: &str = "QC-WHITE1-";

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("request has expired or is not yet valid")]
    ExpiredRequest,
    #[error("request signature is invalid")]
    InvalidSignature,
    #[error("request body is invalid: {0}")]
    InvalidBody(#[from] serde_json::Error),
    #[error("invalid URL")]
    InvalidUrl,
    #[error("payload hash does not match")]
    HashMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Grey,
    White,
    Blue,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Healthy,
    Suspect,
    Degraded,
    Lost,
    Draining,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningPayload {
    pub version: u16,
    pub operation: String,
    pub request_id: Uuid,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub payload: SigningPayload,
    pub signer_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

impl SignedEnvelope {
    pub fn sign<T: Serialize>(
        operation: &str,
        body: &T,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let now = Utc::now().timestamp();
        let payload = SigningPayload {
            version: PROTOCOL_VERSION,
            operation: operation.to_owned(),
            request_id: Uuid::new_v4(),
            issued_at_unix: now,
            expires_at_unix: now + DEFAULT_REQUEST_TTL_SECONDS,
            body: serde_json::to_value(body)?,
        };
        let encoded = serde_json::to_vec(&payload)?;
        Ok(Self {
            payload,
            signer_public_key: key.verifying_key().to_bytes(),
            signature: key.sign(&encoded).to_bytes().to_vec(),
        })
    }

    pub fn verify<T: DeserializeOwned>(
        &self,
        expected_operation: &str,
    ) -> Result<T, ProtocolError> {
        if self.payload.version != PROTOCOL_VERSION || self.payload.operation != expected_operation
        {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let now = Utc::now().timestamp();
        if self.payload.issued_at_unix > now + 30
            || self.payload.expires_at_unix < now
            || self.payload.expires_at_unix <= self.payload.issued_at_unix
            || self
                .payload
                .expires_at_unix
                .saturating_sub(self.payload.issued_at_unix)
                > 300
        {
            return Err(ProtocolError::ExpiredRequest);
        }
        let key = VerifyingKey::from_bytes(&self.signer_public_key)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| ProtocolError::InvalidSignature)?;
        key.verify(&serde_json::to_vec(&self.payload)?, &signature)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        Ok(serde_json::from_value(self.payload.body.clone())?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRegistration {
    pub node_id: Uuid,
    pub role: NodeRole,
    pub endpoint: String,
    pub failure_domain: String,
    pub capacity_bytes: u64,
    pub identity_public_key: [u8; 32],
    pub role_certificate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleCertificateClaims {
    pub version: u16,
    pub node_id: Uuid,
    pub role: NodeRole,
    pub identity_public_key: [u8; 32],
    pub not_before_unix: i64,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRoleCertificate {
    pub claims: RoleCertificateClaims,
    pub curator_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlueDirectoryNode {
    pub node_id: u64,
    pub url: String,
    pub identity_public_key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlueDirectory {
    pub version: u16,
    pub network_id: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub nodes: Vec<BlueDirectoryNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBlueDirectory {
    pub directory: BlueDirectory,
    pub curator_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

impl SignedBlueDirectory {
    pub fn issue(directory: BlueDirectory, curator: &SigningKey) -> Result<Self, ProtocolError> {
        let signature = curator
            .sign(&serde_json::to_vec(&directory)?)
            .to_bytes()
            .to_vec();
        Ok(Self {
            directory,
            curator_public_key: curator.verifying_key().to_bytes(),
            signature,
        })
    }

    pub fn verify(
        &self,
        trusted_curators: &std::collections::BTreeSet<[u8; 32]>,
    ) -> Result<(), ProtocolError> {
        let now = Utc::now().timestamp();
        if self.directory.version != 1
            || self.directory.issued_at_unix > now + 60
            || self.directory.expires_at_unix < now
            || self.directory.network_id.is_empty()
            || self.directory.network_id.len() > 128
            || self.directory.nodes.is_empty()
            || !trusted_curators.contains(&self.curator_public_key)
        {
            return Err(ProtocolError::InvalidSignature);
        }
        let mut node_ids = BTreeSet::new();
        let mut urls = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for node in &self.directory.nodes {
            let url = Url::parse(&node.url).map_err(|_| ProtocolError::InvalidUrl)?;
            if url.scheme() != "https"
                || node.node_id == 0
                || !node_ids.insert(node.node_id)
                || !urls.insert(node.url.clone())
                || !identities.insert(node.identity_public_key)
            {
                return Err(ProtocolError::InvalidUrl);
            }
        }
        let key = VerifyingKey::from_bytes(&self.curator_public_key)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| ProtocolError::InvalidSignature)?;
        key.verify(&serde_json::to_vec(&self.directory)?, &signature)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

impl SignedRoleCertificate {
    pub fn issue(
        claims: RoleCertificateClaims,
        curator: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let signature = curator
            .sign(&serde_json::to_vec(&claims)?)
            .to_bytes()
            .to_vec();
        Ok(Self {
            claims,
            curator_public_key: curator.verifying_key().to_bytes(),
            signature,
        })
    }

    pub fn encode(&self) -> Result<String, ProtocolError> {
        Ok(format!(
            "{WHITE_CERTIFICATE_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?)
        ))
    }

    pub fn decode(value: &str) -> Result<Self, ProtocolError> {
        let payload = value
            .strip_prefix(WHITE_CERTIFICATE_PREFIX)
            .ok_or(ProtocolError::InvalidSignature)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        serde_json::from_slice(&bytes).map_err(ProtocolError::from)
    }

    pub fn verify(
        &self,
        registration: &NodeRegistration,
        trusted_curators: &std::collections::BTreeSet<[u8; 32]>,
    ) -> Result<(), ProtocolError> {
        let now = Utc::now().timestamp();
        if self.claims.version != 1
            || self.claims.role != NodeRole::White
            || registration.role != NodeRole::White
            || self.claims.node_id != registration.node_id
            || self.claims.identity_public_key != registration.identity_public_key
            || self.claims.not_before_unix > now
            || self.claims.expires_at_unix < now
            || !trusted_curators.contains(&self.curator_public_key)
        {
            return Err(ProtocolError::InvalidSignature);
        }
        let key = VerifyingKey::from_bytes(&self.curator_public_key)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| ProtocolError::InvalidSignature)?;
        key.verify(&serde_json::to_vec(&self.claims)?, &signature)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

impl NodeRegistration {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let parsed = Url::parse(&self.endpoint).map_err(|_| ProtocolError::InvalidUrl)?;
        if !matches!(parsed.scheme(), "https" | "http")
            || self.failure_domain.is_empty()
            || self.capacity_bytes == 0
        {
            return Err(ProtocolError::InvalidUrl);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Heartbeat {
    pub node_id: Uuid,
    pub available_bytes: u64,
    pub object_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UploadShare {
    pub share_id: Uuid,
    pub share_index: u8,
    pub sha256: [u8; 32],
    pub payload_base64: String,
}

impl UploadShare {
    #[must_use]
    pub fn from_bytes(share_id: Uuid, share_index: u8, bytes: &[u8]) -> Self {
        Self {
            share_id,
            share_index,
            sha256: Sha256::digest(bytes).into(),
            payload_base64: STANDARD.encode(bytes),
        }
    }

    pub fn decode(&self) -> Result<Vec<u8>, ProtocolError> {
        let bytes = STANDARD
            .decode(&self.payload_base64)
            .map_err(|_| ProtocolError::HashMismatch)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if digest != self.sha256 {
            return Err(ProtocolError::HashMismatch);
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UploadCredential {
    pub manifest: SignedManifest,
    pub generation: u64,
    pub shares: Vec<UploadShare>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlacementReceipt {
    pub set_id: Uuid,
    pub generation: u64,
    pub registry_revision: u64,
    pub placements: BTreeMap<u8, Vec<Uuid>>,
    pub committed_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetrieveCredential {
    pub set_id: Uuid,
    pub generation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetrievedShare {
    pub share_id: Uuid,
    pub share_index: u8,
    pub payload_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetrievalResponse {
    pub manifest: SignedManifest,
    pub generation: u64,
    pub shares: Vec<RetrievedShare>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryAcknowledgement {
    pub set_id: Uuid,
    pub generation: u64,
    pub auto_reseed: bool,
    pub replacement_set_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatusRequest {
    pub set_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatusResponse {
    pub set_id: Uuid,
    pub generation: u64,
    pub status: String,
    pub available_share_indices: Vec<u8>,
    pub available_replicas: usize,
    pub registry_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteCredential {
    pub set_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationResponse {
    pub set_id: Uuid,
    pub status: String,
    pub registry_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageWrite {
    pub object_id: Uuid,
    pub set_id: Uuid,
    pub share_index: u8,
    pub generation: u64,
    pub sha256: [u8; 32],
    pub owner_public_key: [u8; 32],
    pub payload_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageRead {
    pub object_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageDelete {
    pub object_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageAudit {
    pub object_id: Uuid,
    pub expected_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageAuditResponse {
    pub object_id: Uuid,
    pub sha256: [u8; 32],
    pub encoded_len: u32,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageObject {
    pub object_id: Uuid,
    pub sha256: [u8; 32],
    pub payload_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub service: String,
    pub version: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeOperationResponse {
    pub node_id: Uuid,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn signed_envelope_round_trip() -> Result<(), ProtocolError> {
        let key = SigningKey::generate(&mut OsRng);
        let body = StorageRead {
            object_id: Uuid::new_v4(),
        };
        let signed = SignedEnvelope::sign("storage.read", &body, &key)?;
        let decoded: StorageRead = signed.verify("storage.read")?;
        assert_eq!(decoded, body);
        Ok(())
    }

    #[test]
    fn signed_envelope_rejects_tampering_and_wrong_operation() -> Result<(), ProtocolError> {
        let key = SigningKey::generate(&mut OsRng);
        let body = StorageRead {
            object_id: Uuid::new_v4(),
        };
        let signed = SignedEnvelope::sign("storage.read", &body, &key)?;
        assert!(signed.verify::<StorageRead>("storage.delete").is_err());

        let mut tampered = signed;
        tampered.payload.body["object_id"] = serde_json::json!(Uuid::new_v4());
        assert!(tampered.verify::<StorageRead>("storage.read").is_err());
        Ok(())
    }

    #[test]
    fn white_certificate_is_bound_to_node_identity() -> Result<(), ProtocolError> {
        let curator = SigningKey::generate(&mut OsRng);
        let identity = SigningKey::generate(&mut OsRng);
        let node_id = Uuid::new_v4();
        let now = Utc::now();
        let certificate = SignedRoleCertificate::issue(
            RoleCertificateClaims {
                version: 1,
                node_id,
                role: NodeRole::White,
                identity_public_key: identity.verifying_key().to_bytes(),
                not_before_unix: (now - Duration::minutes(1)).timestamp(),
                expires_at_unix: (now + Duration::days(1)).timestamp(),
            },
            &curator,
        )?;
        let registration = NodeRegistration {
            node_id,
            role: NodeRole::White,
            endpoint: "https://white.example.test".to_owned(),
            failure_domain: "region-a".to_owned(),
            capacity_bytes: 1024,
            identity_public_key: identity.verifying_key().to_bytes(),
            role_certificate: Some(certificate.encode()?),
        };
        let trusted = BTreeSet::from([curator.verifying_key().to_bytes()]);
        certificate.verify(&registration, &trusted)?;

        let mut impersonation = registration;
        impersonation.identity_public_key =
            SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert!(certificate.verify(&impersonation, &trusted).is_err());
        Ok(())
    }

    #[test]
    fn blue_directory_requires_trusted_curator_and_https() -> Result<(), ProtocolError> {
        let curator = SigningKey::generate(&mut OsRng);
        let identity = SigningKey::generate(&mut OsRng);
        let now = Utc::now();
        let directory = BlueDirectory {
            version: 1,
            network_id: "qchain-test".to_owned(),
            issued_at_unix: (now - Duration::minutes(1)).timestamp(),
            expires_at_unix: (now + Duration::days(1)).timestamp(),
            nodes: vec![BlueDirectoryNode {
                node_id: 1,
                url: "https://blue.example.test".to_owned(),
                identity_public_key: identity.verifying_key().to_bytes(),
            }],
        };
        let signed = SignedBlueDirectory::issue(directory.clone(), &curator)?;
        signed.verify(&BTreeSet::from([curator.verifying_key().to_bytes()]))?;
        assert!(signed.verify(&BTreeSet::new()).is_err());

        let mut insecure = directory;
        insecure.nodes[0].url = "http://blue.example.test".to_owned();
        let insecure = SignedBlueDirectory::issue(insecure, &curator)?;
        assert!(
            insecure
                .verify(&BTreeSet::from([curator.verifying_key().to_bytes()]))
                .is_err()
        );
        Ok(())
    }
}
