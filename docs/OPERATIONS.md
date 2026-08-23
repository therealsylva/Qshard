# Qchain operations

This runbook describes a production-shaped deployment. Replace example paths, hosts, public keys, and certificates with values managed by your infrastructure. Commands intentionally omit `--insecure-dev`.

## Recommended topology

- Three or five Blue voting members in separate failure domains
- At least three curated White storage nodes so one can be a repair destination
- At least nine Grey storage nodes, preferably more, across distinct failure domains
- Private connectivity between Blue members and storage nodes
- Public client access only to the Blue API through a TLS reverse proxy or directly configured TLS listener
- Independent monitoring and encrypted backups for every Blue data directory

All service accounts should use a restrictive umask and dedicated data directory. Protect TLS keys, identity keys, curator keys, cluster tokens, admin tokens, and recovery capsules outside the repository.

## Build and install

```bash
cargo build --release --locked
install -m 0755 target/release/qchain /usr/local/bin/qchain
install -m 0755 target/release/qshard /usr/local/bin/qshard
install -m 0755 target/release/qchain-node /usr/local/bin/qchain-node
install -m 0755 target/release/qchain-blue /usr/local/bin/qchain-blue
install -m 0755 target/release/qchain-admin /usr/local/bin/qchain-admin
```

Create separate Unix users for Blue and storage services. Never run them as root when a dedicated unprivileged account is sufficient.

## Generate administrative material

Run these steps on a protected administration host:

```bash
qchain-admin generate-key --output ./curator.key
qchain-admin public-key --key ./curator.key
qchain-admin generate-token --output ./cluster.token
qchain-admin generate-token --output ./admin.token
```

Every Blue member in one cluster uses the same cluster and admin token, but its own data directory and generated `blue-identity.key`. Distribute only the curator public key to Blue services. Keep the curator private key offline when not issuing certificates or directories.

## Start Blue members

Start each pristine member without `--bootstrap` so all Raft endpoints are listening before initialization:

```bash
qchain-blue \
  --node-id 1 \
  --listen 0.0.0.0:8443 \
  --advertise-url https://blue-1.example.net:8443 \
  --data-dir /var/lib/qchain/blue \
  --cluster-token-file /etc/qchain/cluster.token \
  --admin-token-file /etc/qchain/admin.token \
  --curator-public-key <curator-public-key> \
  --tls-cert /etc/qchain/tls/fullchain.pem \
  --tls-key /etc/qchain/tls/private-key.pem \
  --log-json
```

Use different node IDs, URLs, data directories, and TLS identities for the other members. Initialize the pristine cluster once after all members are reachable:

```bash
qchain-admin cluster \
  --blue https://blue-1.example.net:8443 \
  --admin-token-file ./admin.token \
  initialize \
  --member 1=https://blue-1.example.net:8443 \
  --member 2=https://blue-2.example.net:8443 \
  --member 3=https://blue-3.example.net:8443
```

For later expansion, start the new empty member, add it as a learner, wait until it is synchronized according to health and logs, then change voting membership:

```bash
qchain-admin cluster \
  --blue https://blue-1.example.net:8443 \
  --admin-token-file ./admin.token \
  add-learner --node-id 4 --url https://blue-4.example.net:8443

qchain-admin cluster \
  --blue https://blue-1.example.net:8443 \
  --admin-token-file ./admin.token \
  change-membership --member 1 2 3 4
```

Do not initialize an existing data directory or create two independent clusters with overlapping service URLs.

## Start Grey nodes

Generate persistent node identity material before enrollment:

```bash
qchain-admin generate-node-identity --data-dir /var/lib/qchain/node
```

Record the printed UUID and identity public key. Start a Grey node with repeated Blue endpoints and trusted Blue identity keys:

```bash
qchain-node \
  --role grey \
  --listen 0.0.0.0:9443 \
  --advertise-url https://grey-1.example.net:9443 \
  --failure-domain region-a/rack-3 \
  --capacity-mib 1024 \
  --max-objects 1000000 \
  --data-dir /var/lib/qchain/node \
  --blue https://blue-1.example.net:8443 \
  --blue https://blue-2.example.net:8443 \
  --blue-public-key <blue-1-public-key> <blue-2-public-key> <blue-3-public-key> \
  --tls-cert /etc/qchain/tls/fullchain.pem \
  --tls-key /etc/qchain/tls/private-key.pem \
  --log-json
```

The node tries Blue endpoints until a serving member accepts registration and re-enters discovery after a failed heartbeat.

## Curate and start White nodes

After verifying the operator, endpoint, failure domain, and identity out of band, issue a certificate:

```bash
qchain-admin issue-white \
  --curator-key ./curator.key \
  --node-id <white-node-uuid> \
  --identity-public-key <white-identity-public-key> \
  --valid-days 365 \
  --output ./white-node.certificate
```

Start `qchain-node --role white` with the same production options as a Grey node plus:

```bash
--role-certificate "$(<./white-node.certificate)"
```

Plan certificate renewal before expiry. A certificate is bound to the node UUID and identity key and cannot be transferred to another node.

## Issue the Black-client directory

Obtain each Blue member's identity public key from protected provisioning output or its health endpoint, verify it out of band, then issue the directory:

```bash
qchain-admin issue-directory \
  --curator-key ./curator.key \
  --network qchain-mainnet \
  --valid-days 30 \
  --node 1,https://blue-1.example.net:8443,<blue-1-public-key> \
  --node 2,https://blue-2.example.net:8443,<blue-2-public-key> \
  --node 3,https://blue-3.example.net:8443,<blue-3-public-key> \
  --output ./qchain-blue-directory.json
```

Distribute the signed JSON, curator public key, and expected network identifier through an authenticated channel. Renew it before expiry.

## Client lifecycle

Store:

```bash
qchain --directory ./qchain-blue-directory.json \
  --curator-public-key <curator-public-key> \
  store --input ./credential.txt --label primary-login
```

Check committed availability:

```bash
qchain --directory ./qchain-blue-directory.json \
  --curator-public-key <curator-public-key> \
  status <set-id>
```

Recover and retire the stored set:

```bash
qchain --directory ./qchain-blue-directory.json \
  --curator-public-key <curator-public-key> \
  recover <set-id> --output ./recovered.txt
```

Recover while committing a replacement first:

```bash
qchain --directory ./qchain-blue-directory.json \
  --curator-public-key <curator-public-key> \
  recover <set-id> --output ./recovered.txt --auto-reseed
```

Use a protected `--passphrase-file` for non-interactive automation. Never pass a passphrase directly on the command line.

## Monitoring

Alert on:

- Blue `ready: false`, no current leader, or loss of voting quorum;
- fewer than the planned number of live White or Grey nodes;
- node capacity approaching its configured byte or object limit;
- sets in `degraded`, `critical`, or long-lived `retiring` state;
- repeated audit or repair failures;
- heartbeat gaps, TLS expiry, White certificate expiry, and Blue-directory expiry;
- unexpected growth in rate-limit, unauthorized, replay, or invalid-share responses.

Health endpoints intentionally contain aggregate operational data only. Retain structured logs according to your security policy and ensure that proxies do not log full request bodies.

## Backup and recovery

Back up Blue data directories using a method consistent with sled and Raft. Prefer stopping one follower, snapshotting its filesystem, restarting it, and confirming it catches up before touching another member. Never restore multiple members from divergent snapshots as if they were one current quorum.

Storage-node shares are already redundant and can be repaired from online replicas. Backing them up can undermine deletion guarantees; if infrastructure snapshots storage volumes, their retention must be documented in the threat model.

Client recovery capsules require a separate encrypted backup. Blue registry backup cannot replace a lost recovery capsule.

## Rotation and decommissioning

- Add and synchronize replacement Blue identities before removing old voting members.
- Update storage-node Blue key allow-lists and issue a new signed directory during Blue identity rotation.
- Issue a new White certificate after rotating a White identity.
- Drain or declare a storage node lost, wait for repairs to commit, then securely decommission its volume according to operator policy.
- Rotate cluster and admin tokens during a controlled maintenance window across all affected members.

Deletion removes active files and metadata but cannot guarantee erasure from external snapshots, filesystem journals, SSD remapping, or operator backups.
