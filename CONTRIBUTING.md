# Contributing

## Development setup

Install stable Rust with `rustfmt` and `clippy`, then run:

```bash
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

Do not commit credentials, recovery capsules, private keys, token files, TLS keys, node data, or test output containing secrets.

## Change requirements

- Preserve the fixed 3-of-5 and ten-distinct-node placement invariants unless an explicit protocol version is introduced.
- Keep control-signing and encryption derivation domains separate.
- Keep Blue share handling ephemeral.
- Commit lifecycle transitions through Raft before performing dependent external actions.
- Add negative tests for authentication, replay, tampering, partial failure, or lifecycle changes.
- Maintain professional, emoji-free terminal output and machine-readable `--json` responses.
- Do not weaken TLS or signed-directory defaults to simplify deployment.

Protocol or cryptographic changes must explain compatibility, migration, threat-model impact, and failure behavior in the pull request.

## Commit and review scope

Prefer focused commits. A pull request should state what changed, why the invariant still holds, which tests were run, and whether the change affects persisted data or wire compatibility.
