# Qchain protocol v1

## Transport and encoding

All APIs use JSON over HTTPS. Plain HTTP is accepted only when the relevant explicit development flag is enabled. Service request bodies are size-limited.

Client and coordinator operations use an Ed25519 `SignedEnvelope`:

```json
{
  "payload": {
    "version": 1,
    "operation": "credential.status",
    "request_id": "uuid",
    "issued_at_unix": 0,
    "expires_at_unix": 0,
    "body": {}
  },
  "signer_public_key": [0],
  "signature": [0]
}
```

The signature covers the canonical JSON serialization produced by the Rust protocol types. Requests expire after 120 seconds by default, may not request more than a 300-second validity window, and allow at most 30 seconds of future clock skew. Mutations record request identifiers in the replicated registry; storage commands record them in the receiving node's local replay tree. Credential operations return the existing committed result when a response is lost and the identical signed request is retried.

Implementations in other languages must match the exact versioned serialization before they can interoperate. No compatibility is promised for unversioned ad hoc JSON.

## Client-to-Blue endpoints

| Method | Path | Signed operation | Result |
|---|---|---|---|
| `POST` | `/v1/credentials` | `credential.upload` | Committed placement receipt |
| `POST` | `/v1/credentials/status` | `credential.status` | Linearizable availability status |
| `POST` | `/v1/credentials/retrieve` | `credential.retrieve` | Three distinct encrypted shares and manifest |
| `POST` | `/v1/credentials/recovery-ack` | `credential.recovery_ack` | Retirement/deletion status |
| `POST` | `/v1/credentials/delete` | `credential.delete` | Retirement/deletion status |

The signer public key must equal the set's control public key. Uploads contain exactly five unique shares numbered one through five. Blue validates each encoded header, hash, share identifier, and signed manifest before placement.

Retrieval returns only sets in `active` or `degraded` state and only after three distinct share indices pass storage and cryptographic metadata validation.

## Storage-node endpoints

| Method | Path | Signed operation | Behavior |
|---|---|---|---|
| `POST` | `/v1/storage/write` | `storage.write` | Idempotently persist one validated encrypted share |
| `POST` | `/v1/storage/read` | `storage.read` | Return an integrity-checked encrypted share |
| `POST` | `/v1/storage/audit` | `storage.audit` | Compare stored and expected SHA-256 identities |
| `POST` | `/v1/storage/delete` | `storage.delete` | Idempotently delete one object |

Storage nodes accept commands only from configured Blue identity public keys. Object paths are derived from UUIDs rather than user input. Writes use a same-filesystem temporary file, file synchronization, atomic rename, and persistent sled metadata.

## Node membership

Storage nodes sign `node.register` and `node.heartbeat` envelopes with their persistent identity key. Registration binds the UUID, role, advertised endpoint, failure domain, capacity, and identity public key.

White registration additionally requires a curator-signed certificate bound to the White role, node UUID, identity public key, validity interval, and curator key. Grey registration is permissionless but remains subject to placement health and capacity requirements.

## Blue discovery

Black clients use a curator-signed `BlueDirectory`. It contains a network identifier, issue and expiry times, and one or more HTTPS Blue endpoints with their identity public keys. The client rejects an empty, expired, untrusted, non-HTTPS, or incorrectly signed directory.

## Blue consensus and administration

Raft peer endpoints are `/v1/raft/append`, `/v1/raft/vote`, and `/v1/raft/snapshot`. They require the shared cluster token in `x-qchain-cluster-token` and should also be isolated at the network layer.

Cluster administration endpoints initialize membership, add a synchronized learner, and change voting membership. They require `Authorization: Bearer <admin-token>`. Operators should use `qchain-admin cluster`; these endpoints are not public client APIs.

## Health

`GET /health` is unsigned. Blue health includes initialization, readiness, current leader, Raft state, identity public key, connected storage-node count, available bytes, and object count. It exposes no credential or share identifiers.

## Compatibility

The current wire, certificate, directory, and capsule versions are version 1. The Qshard binary container and manifest use version 2. A future incompatible change must introduce a new version and an explicit migration path.
