# Qshard

<div align="center">

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/qshard.svg)](https://crates.io/crates/qshard)

**A CLI tool for decentralized credential sharding.**

Split a secret into 5 encrypted shards. Any 3 shards, combined with a recovery token, are sufficient to restore the original secret.

</div>

---

## About

`qshard` is a command-line utility that implements [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) to provide a robust method for securing sensitive credentials like passwords, API keys, or recovery phrases.

Instead of storing your entire secret in one place, you can distribute encrypted `.qshard` files across multiple locations (different computers, cloud storage, USB drives). An attacker would need to compromise multiple locations and the recovery token to reconstruct your secret.

### Key Features

-   **Threshold Recovery**: Uses a (3, 5) Shamir scheme. Any 3 out of the 5 generated shards are enough to recover the secret.
-   **Token-Based Encryption**: All shards are encrypted with AES-256-GCM. A unique **Recovery Token** is required to decrypt and use them, preventing recovery if the files are acquired without the token.
-   **Custom Identifiers**: Name your shard sets for easy organization (e.g., `qs-gmail_backup-1.qshard`).
-   **Directory-Aware**: The `recover`, `status`, `verify`, and `purge` commands can operate on an entire directory of shards, not just individual files.
-   **Secure Memory**: Sensitive data is securely wiped from memory after use.
-   **Cross-Platform**: Built in Rust, it runs on Linux, macOS, and Windows.

## Installation

### From Source

Ensure you have [Rust](https://rustup.rs/) installed (version 1.70 or newer).

```bash
git clone https://github.com/therealsylva/qshard.git
cd qshard
cargo build --release
```

The compiled binary will be located at `target/release/qshard`.

### From Crates.io (Once Published)

```bash
cargo install qshard
```

## Usage

### Create Shards

Splits a secret into 5 `.qshard` files in the specified output directory. You can provide a custom identifier for the shard set.

```bash
$ qshard create --output-dir ./secrets --id "gmail_account"
Enter secret to shard: [hidden]
  [00:00:00] [########################################] 5/5 (0s)

🔑 Recovery Token: QS-TNK-qL9bX4wP...[truncated]
⚠️  Save this token! It is required for recovery.
```

This will create files like:
- `qs-gmail_account-1.qshard`
- `qs-gmail_account-2.qshard`
- `...`

### Recover Secret

Restores the original secret using any 3 of the 5 shard files. You can point it to a directory containing the shards.

```bash
$ qshard recover ./secrets/
Enter Recovery Token: [hidden]
MySuperSecretPassword123!
```

### Check Shard Status

Checks the validity and availability of a set of shards.

```bash
$ qshard status ./secrets/
Checking shard availability...
✅ ./secrets/qs-gmail_account-1.qshard: Shard 1 is valid.
✅ ./secrets/qs-gmail_account-3.qshard: Shard 3 is valid.
✅ ./secrets/qs-gmail_account-5.qshard: Shard 5 is valid.

✅ Recovery is possible with shards: [1, 3, 5]
```

### Verify Recovery

Tests if recovery is possible without exposing the secret in your terminal.

```bash
$ qshard verify ./secrets/
Enter Recovery Token: [hidden]
✅ Recovery is possible with these shards.
```

### Purge Shards

Securely overwrites and deletes shard files.

```bash
$ qshard purge ./secrets/qs-gmail_account-1.qshard ./secrets/qs-gmail_account-2.qshard
Purging...
✅ Done.
```

## Security Considerations

-   **The Recovery Token is Critical**: The recovery token is the master key to your secrets. Store it in a separate, secure location from your shard files. Losing the token means losing access to your secret forever.
-   **Minimum Secret Length**: For security, secrets shorter than 64 bytes are automatically padded with random data before sharding. This padding is removed during recovery.

## How It Works

1.  **Input**: You provide a secret (e.g., a password).
2.  **Padding**: The secret is padded to a minimum length of 64 bytes to ensure cryptographic security.
3.  **Sharding**: The padded secret is split into 5 shares using Shamir's Secret Sharing. Any 3 of these shares can reconstruct the original padded secret.
4.  **Encryption**: A 32-byte recovery token is generated. This token is used as an AES-256-GCM key to encrypt each of the 5 shares individually.
5.  **Storage**: The encrypted shares are saved to `.qshard` files, which contain metadata like the share ID and original secret length.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Author

Created by [therealsylva](https://github.com/therealsylva).
