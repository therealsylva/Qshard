# Security policy

## Project status

Qchain handles high-value secret material. The code applies conservative cryptographic and operational controls, but it has not yet received an independent security audit. A passing test suite is not a substitute for cryptographic review, protocol analysis, infrastructure hardening, or an incident-response exercise.

Before storing live credentials, operators should commission an external audit, run a staged multi-node deployment, establish encrypted backups for Blue registry state, protect curator and service keys with an appropriate secrets system, and document a recovery procedure.

## Supported versions

Security fixes are applied to the latest commit on the default branch. Until the first signed release, no older revision is supported.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not open a public issue containing exploit details, credentials, private keys, recovery capsules, tokens, node databases, or unredacted logs.

Include the affected revision, impact, reproduction steps, and any proposed mitigation. Maintainers should acknowledge a report within seven days, coordinate validation and remediation privately, and publish an advisory after a fix is available.

## Trust boundaries

- The recovery seed is the root secret. It derives distinct encryption and control-signing keys for each credential set.
- The recovery capsule encrypts that seed under a user passphrase. It must be backed up separately from the share network.
- Grey and White nodes see only authenticated ciphertext shares and placement metadata.
- Blue nodes see encrypted shares in transit and store registry metadata, never persistent share payloads.
- Curators authorize White identities and the Blue directory. Curator keys do not decrypt credentials.
- TLS authenticates service endpoints and protects metadata in transit. Ed25519 signatures authorize protocol operations independently of TLS.

## Threats addressed

- Compromise of fewer than three distinct encrypted share indices does not reveal a credential.
- Stored-share modification is detected by AEAD authentication, signed manifests, and SHA-256 identity checks.
- A storage node cannot fabricate authorized Blue commands without a trusted Blue identity key.
- Signed operations expire quickly; replayed mutations are rejected or resolved through their idempotent committed result.
- A lost storage node triggers a consensus-committed degraded state and repair onto a distinct eligible node.
- Deletion is a persistent lifecycle: the registry records retirement before remote deletion and retries incomplete work.

## Residual risks

- Compromise of a recovery capsule and its passphrase permits recovery and control operations.
- A compromised client can expose plaintext before sharding or after recovery.
- Three or more distinct shares plus the recovery seed are sufficient to reconstruct the credential.
- A malicious or unavailable Blue quorum can deny service, expose metadata, or prevent repair and deletion; it still cannot decrypt shares without the recovery seed.
- Host compromise, swap, crash dumps, terminal capture, filesystem snapshots, and backups can retain sensitive material beyond process-level zeroization.
- TLS private keys, cluster tokens, admin tokens, curator keys, and node identities require external lifecycle management.
- The design has not been formally verified and the implementation has not been independently audited.

## Operator requirements

- Never enable `--insecure-dev`, `--allow-http`, or `--allow-unsigned-blue` outside an isolated development environment.
- Run at least three Blue voting members in separate failure domains.
- Maintain spare Grey and White capacity. Exact placement uses two White and eight Grey nodes; automatic repair requires an additional eligible node of the lost node's role.
- Restrict service data directories and key files to the service account.
- Keep admin and cluster endpoints on a private network and apply network-level rate limits.
- Monitor Blue readiness, Raft quorum, storage-node heartbeats, degraded sets, repair failures, capacity, and certificate expiry.
- Test restore procedures and key rotation in a non-production environment.
