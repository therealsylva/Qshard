# Qchain and Qshard

Qchain is a lightweight credential-storage network. Qshard is its offline cryptographic core and command-line client. A credential is encrypted, split into five Shamir shares, and recoverable from any three. Qchain places two replicas of each share on ten distinct storage nodes.

This repository is a Rust workspace containing the complete client, storage-node, Blue-coordinator, registry, protocol, and administration source.

> Security status: this implementation is production-oriented, but it has not received an independent cryptographic or application-security audit. Do not use it for irreplaceable live credentials until an external audit and deployment review are complete.

## Network roles

| Role | Responsibility | Curated |
|---|---|---|
| Black | Uses the client but stores no shares for other users | No |
| Grey | Runs a casual storage node | No |
| White | Runs a high-uptime storage node with a curator-issued role certificate | Yes |
| Blue | Routes ephemeral share traffic, maintains the replicated registry, monitors availability, and coordinates repair | Yes |

Every credential set has exactly ten replicas on ten different nodes:

- Share 1: one White and one Grey replica
- Share 2: one White and one Grey replica
- Shares 3, 4, and 5: two Grey replicas each
- The two White nodes always hold different share indices

Blue nodes never persist credential shares. Registry mutations are replicated with Raft; the network does not use peer-to-peer gossip, a blockchain, or an incentive token.

## Binaries

| Binary | Purpose |
|---|---|
| `qshard` | Offline split, recover, verify, inspect, and REPL operations |
| `qchain` | Network store, recover, status, delete, list, and REPL operations |
| `qchain-node` | Grey or White persistent storage service |
| `qchain-blue` | Blue coordinator, replicated registry, monitoring, and repair service |
| `qchain-admin` | Key generation, certificates, signed directories, and Raft membership |

All interactive output is plain, professional terminal text. Both client binaries support `--json` for automation and retain REPL history in memory only.

## Build

Install the stable Rust toolchain, then run:

```bash
cargo build --release --locked
cargo test --workspace --locked
```

Release binaries are written to `target/release/`.

## Offline Qshard example

Split a credential into five encrypted shares and a passphrase-protected recovery capsule:

```bash
qshard split \
  --input ./credential.txt \
  --output-dir ./credential-shares \
  --network qchain-mainnet \
  --recovery-mode per-credential
```

Recover from any three shares:

```bash
qshard recover \
  --capsule ./credential-shares/<set-id>.recovery.qrc \
  --manifest ./credential-shares/<set-id>.manifest.json \
  --output ./recovered.txt \
  ./credential-shares/<share-1>.qshare \
  ./credential-shares/<share-2>.qshare \
  ./credential-shares/<share-3>.qshare
```

Run `qshard` or `qshard repl` for the interactive shell. Secrets are read from a hidden prompt when standard input is a terminal.

For master recovery mode, pass the same protected capsule path on later splits; Qshard opens and reuses its seed instead of replacing it:

```bash
qshard split --recovery-mode master --capsule ./master.recovery.qrc --input ./credential.txt
```

## Qchain client example

Production clients require a curator-signed Blue directory and at least one trusted curator public key:

```bash
qchain \
  --directory ./qchain-blue-directory.json \
  --curator-public-key <hex-public-key> \
  store \
  --input ./credential.txt \
  --label primary-login \
  --recovery-mode per-credential
```

The client saves its protected recovery capsule and local credential record before upload. Recovery writes the credential successfully before sending the deletion acknowledgement. With `--auto-reseed`, a replacement set is fully committed before the original set is retired.

Plain HTTP and unsigned Blue endpoints are rejected unless the explicit local-development flags are supplied.

## Security properties

- 3-of-5 Shamir secret sharing for arbitrary credentials up to 64 KiB
- XChaCha20-Poly1305 encryption for every share, with authenticated metadata
- Independent HKDF domains for share encryption and Ed25519 control signing
- Argon2-protected recovery capsules, available per credential or as one master capsule
- Signed, expiring operations with replay detection and idempotent retry handling
- Curator-signed White certificates and Blue directories
- TLS required by services and clients outside explicit development mode
- Persistent retirement state, retryable deletion, integrity audits, and lost-replica repair
- Quotas, capacity checks, request-size limits, and request rate limits

The recovery capsule remains the critical secret. Losing it and its passphrase makes recovery impossible; compromising both permits recovery and control operations. See [SECURITY.md](SECURITY.md) and [the architecture](docs/ARCHITECTURE.md) for the complete trust model.

## Documentation

- [Architecture and invariants](docs/ARCHITECTURE.md)
- [Protocol reference](docs/PROTOCOL.md)
- [Deployment and operations](docs/OPERATIONS.md)
- [Security policy and threat model](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

MIT. See [LICENSE](LICENSE).
