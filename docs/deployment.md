# Settled — Deployment Guide

## Components

There are two deployable binaries and one CLI tool. The libraries (settled-core, settled-storage) are compile-time dependencies — they are not deployed separately.

| Component | Binary | Role | Required |
|-----------|--------|------|----------|
| Audit log server | `settled-server` | Accepts writes, stores records, signs tree heads, exposes gRPC and admin HTTP | Yes |
| Witness node | `settled-node` | Independent counter-signing witness; verifies and archives STHs pushed by the server | Optional |
| Verification CLI | `settled-check` | Operator tool for verifying STH signatures and inclusion proofs against a live server | Optional |

A minimal production deployment is just `settled-server`. `settled-node` is only needed if you want independent counter-signatures (the threshold protocol). `settled-check` is a diagnostic tool run on demand, not a persistent service.

---

## Building the Binaries

Requires Rust stable (1.75+) and `protoc` (Protocol Buffers compiler).

```sh
# Install protoc on macOS
brew install protobuf

# Install protoc on Debian/Ubuntu
apt-get install -y protobuf-compiler

# Build release binaries
cargo build --release -p settled-server
cargo build --release -p settled-node
cargo build --release -p settled-check

# Binaries are placed at:
# target/release/settled-server
# target/release/settled-node
# target/release/settled-check
```

Copy the binaries to the target host — they have no runtime dependencies beyond libc.

---

## `settled-server`

### What it runs

Three concurrent tasks inside a single process:

- **gRPC server** (default `:50051`) — the write and query API used by application SDKs
- **Admin HTTP server** (default `:8080`) — settled-node registry, health check, Prometheus metrics
- **STH task** — background loop that periodically signs the Merkle root and pushes it to registered settled nodes

### Storage

`settled-server` uses RocksDB for all persistent state. RocksDB is embedded — there is no external database to configure.

The data directory contains:

| Path | Contents |
|------|----------|
| `<data-dir>/` | RocksDB files (column families: log, tree, heads, index, settledes, final_heads) |
| `<data-dir>/signing.key` | 32-byte raw Ed25519 signing key (generated on first start if absent) |

**The signing key is the most critical file in the deployment.** Back it up immediately after first start. If lost, historical proofs remain verifiable (they contain the embedded public key) but new STHs cannot be signed with the same identity.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--data-dir` | `/var/lib/settled` | Directory for RocksDB data and signing key |
| `--key-path` | `<data-dir>/signing.key` | Override path to the signing key |
| `--listen` | `0.0.0.0:50051` | gRPC listen address |
| `--admin-listen` | `0.0.0.0:8080` | Admin HTTP listen address |
| `--sth-interval-secs` | `60` | How often to sign a new STH (seconds) |
| `--api-key` | *(unset)* | Shared secret clients must present as `authorization: Bearer <key>`. Also read from `$SETTLED_API_KEY`. If unset, auth is disabled (dev mode only). |
| `--max-push-failures` | `6` | Consecutive push failures before a settled node is flagged dead |
| `--push-timeout-ms` | `5000` | Per-attempt timeout when pushing STHs to settled nodes |
| `--threshold` | `0` | Minimum counter-signatures required for a FinalSTH (0 = threshold disabled) |
| `--max-appends-per-sec` | *(unset)* | Server-wide append rate limit (token bucket, requests/sec). Omit to allow unlimited writes. |
| `--max-get-latest` | `1000` | Maximum entries `GetLatest` may return per call. |
| `--max-message-bytes` | `4194304` | Maximum gRPC request size in bytes. Larger requests are rejected with `RESOURCE_EXHAUSTED`. |

### Ad-hoc debugging with grpcurl

The server exposes the standard [gRPC server reflection](https://grpc.io/docs/guides/reflection/) service, so `grpcurl` works without a proto file:

```sh
# Install grpcurl (macOS)
brew install grpcurl

# List all available RPC methods
grpcurl -plaintext localhost:50051 list settled.v1.SettledLog

# Describe a method's request/response shape
grpcurl -plaintext localhost:50051 describe settled.v1.SettledLog.GetSth

# Call GetSth (latest)
grpcurl -plaintext -d '{"tree_size": 0}' localhost:50051 settled.v1.SettledLog/GetSth

# Append an entry
grpcurl -plaintext \
  -d '{"key": "dXNlcjoxMjM=", "data": "bG9naW4="}' \
  localhost:50051 settled.v1.SettledLog/Append

# With an API key
grpcurl -plaintext \
  -H "authorization: Bearer $SETTLED_API_KEY" \
  -d '{"tree_size": 0}' \
  localhost:50051 settled.v1.SettledLog/GetSth
```

> **Note:** when `--api-key` is set, the reflection service also requires the key. This is intentional — schema information is protected by the same credentials as data access.

### Authentication

The server enforces a shared API key when `--api-key` (or `$SETTLED_API_KEY`) is set. Every gRPC client must include the header:

```
authorization: Bearer <key>
```

If neither the flag nor the environment variable is set the server starts in **dev mode** and logs a warning — all requests are accepted without credentials. Always set an API key in production.

```sh
# Generate a random key
export SETTLED_API_KEY=$(openssl rand -hex 32)

# Or pass it as a flag
settled-server --data-dir /var/lib/settled --api-key "$SETTLED_API_KEY"
```

### Starting the server

```sh
# Development — no auth
settled-server --data-dir /var/lib/settled

# Production — with API key
SETTLED_API_KEY=<your-key> settled-server \
  --data-dir /var/lib/settled \
  --listen 0.0.0.0:50051 \
  --admin-listen 127.0.0.1:8080 \
  --sth-interval-secs 30
```

Log output is written to stdout in structured JSON when `RUST_LOG` is set, or human-readable by default.

```sh
RUST_LOG=info settled-server --data-dir /var/lib/settled
```

### Verifying the server is running

```sh
# Health check (returns 200 OK)
curl http://localhost:8080/health

# Prometheus metrics
curl http://localhost:8080/metrics

# Verify the STH signature using settled-check
settled-check verify --server http://localhost:50051
```

### systemd unit (Linux)

```ini
[Unit]
Description=Settled audit log server
After=network.target

[Service]
Type=simple
User=settled
Group=settled
ExecStart=/usr/local/bin/settled-server \
  --data-dir /var/lib/settled \
  --listen 0.0.0.0:50051 \
  --admin-listen 127.0.0.1:8080 \
  --sth-interval-secs 60
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

# Protect the signing key
ReadWritePaths=/var/lib/settled
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
# Install
useradd -r -s /sbin/nologin settled
mkdir -p /var/lib/settled
chown settled:settled /var/lib/settled
cp target/release/settled-server /usr/local/bin/
cp settled-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now settled-server
```

---

## `settled-node`

`settled-node` is an independent witness service. The main server pushes each new STH to it over HTTP. The node verifies the Ed25519 signature, archives the STH, and returns a counter-signature. It has no persistent storage — its archive is in memory and is rebuilt from pushes after a restart.

### When to deploy it

Deploy one or more settled nodes when you want independent cryptographic witnesses to the log's history. This is the threshold protocol: the main server can be configured to require a minimum number of counter-signatures (`--threshold N`) before a FinalSTH is considered valid. Settled nodes should run on infrastructure independent from the main server — different host, different operator if possible.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `0.0.0.0:8181` | HTTP listen address |
| `--key-path` | `./settled-node.key` | Path to this node's Ed25519 signing key (generated if absent) |

### Starting the node

```sh
settled-node \
  --listen 0.0.0.0:8181 \
  --key-path /etc/settled-node/signing.key
```

On first start, the node logs its public key:

```
INFO settled_node: Settled node identity public_key="a3f2..."
```

Record this public key — it identifies this witness in any FinalSTH counter-signatures.

### Registering the node with the server

After starting the node, register its URL with the server's admin API so the server knows to push STHs to it:

```sh
curl -X POST http://localhost:8080/v1/admin/settledes \
  -H 'content-type: application/json' \
  -d '{"url":"http://my-witness-host:8181"}'
```

The server will begin pushing new STHs to the node on the next STH interval. To see registered nodes:

```sh
curl http://localhost:8080/v1/admin/settledes
```

To remove a node:

```sh
# URL-encode the node URL
curl -X DELETE 'http://localhost:8080/v1/admin/settledes/http%3A%2F%2Fmy-witness-host%3A8181'
```

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /push` | Receive an STH push from the main server; returns a counter-signature |
| `GET /archive/:tree_size` | Retrieve a previously witnessed STH by tree size |

### systemd unit (Linux)

```ini
[Unit]
Description=Settled witness node
After=network.target

[Service]
Type=simple
User=settled-node
Group=settled-node
ExecStart=/usr/local/bin/settled-node \
  --listen 0.0.0.0:8181 \
  --key-path /etc/settled-node/signing.key
Restart=on-failure
RestartSec=5s

ReadOnlyPaths=/etc/settled-node
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

---

## `settled-check`

`settled-check` is a command-line verification tool. It is not a service — run it on demand to verify the server is healthy and proofs are valid.

```sh
# Verify the latest STH signature
settled-check verify --server http://localhost:50051

# Also verify an inclusion proof for entry seq=42
settled-check verify --server http://localhost:50051 --seq 42
```

Exit code 0 means all verifications passed. Exit code 1 means verification failed or the server was unreachable.

---

## Networking

| Port | Component | Protocol | Exposure |
|------|-----------|----------|----------|
| 50051 | settled-server | gRPC (HTTP/2) | Application network (SDK clients connect here) |
| 8080 | settled-server admin | HTTP | Internal only — do not expose publicly |
| 8181 | settled-node | HTTP | Reachable from the main server |

The admin port (`8080`) exposes the settled-node registry (add/remove witnesses) and Prometheus metrics. It should be firewalled to the local host or internal network. It does not require authentication.

The gRPC port (`50051`) is the endpoint application SDKs connect to. Expose it to your application network. Use a TLS-terminating proxy (nginx, Envoy) in front of it if clients are on untrusted networks.

---

## Monitoring

`settled-server` exposes Prometheus metrics at `GET http://localhost:8080/metrics`.

Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `settled_entries_appended_total` | Counter | Total entries written to the log |
| `settled_append_duration_seconds` | Histogram | Write path latency (p50 target < 100µs, p99 < 1ms) |
| `settled_sth_signed_total` | Counter | Total Signed Tree Heads produced |
| `settled_sth_sign_duration_seconds` | Histogram | Ed25519 signing duration |
| `settled_tree_size` | Gauge | Entries covered by the latest STH |
| `settled_sth_last_timestamp_ns` | Gauge | Unix timestamp (ns) of the latest STH |

To compute STH lag (time since last signed tree head) in Grafana:

```
time() * 1e9 - settled_sth_last_timestamp_ns
```

---

## Backup and Recovery

### What to back up

| File | Priority | Notes |
|------|----------|-------|
| `<data-dir>/signing.key` | Critical | Loss means new STHs cannot be signed with the original key identity |
| `<data-dir>/` (RocksDB) | Important | Loss of the RocksDB directory means loss of all log data |
| settled-node `signing.key` | Important | Loss means this node's counter-signatures cannot be produced |

### Recovery after data directory loss

If the RocksDB directory is lost but the signing key is intact and log backups exist, the server can be restarted with a restored data directory. The Merkle tree is fully reconstructible from the log column family — the server rebuilds it on startup automatically.

If the signing key is lost, a new key can be generated. Historical STHs remain verifiable (they embed the public key that signed them). New STHs will carry a different public key identity. Inform any relying parties of the key change.

---

## Key Rotation

The server maintains an append-only **key chain** — every signing key ever used is recorded in storage with its version number and the tree size at which it was activated. This lets verifiers authenticate STHs signed by any historical key without the server ever deleting old keys.

### When to rotate

- Scheduled key hygiene (e.g., annually)
- Suspected key compromise
- Personnel change

### How to rotate

Call the admin API:

```sh
curl -X POST http://localhost:8080/api/rotate-key
```

The server responds with the new key record:

```json
{
  "version": 2,
  "public_key": "a3f2...",
  "activated_at_tree_size": 104857
}
```

The hot-swap is instant — the server immediately begins signing new STHs with the new key. In-flight and historical STHs continue to verify against their respective key versions.

### Viewing the full key chain

```sh
curl http://localhost:8080/api/keys
```

Returns all key records in version-ascending order:

```json
[
  { "version": 1, "public_key": "...", "activated_at_tree_size": 0 },
  { "version": 2, "public_key": "...", "activated_at_tree_size": 104857 }
]
```

### SDK verification after rotation

SDK verifiers expose a `verify_tree_head_with_chain` function. Pass the key chain fetched from `/api/keys` and the function will automatically select the correct public key for each STH's `key_version` field.

```typescript
// TypeScript example
import { verifyTreeHeadWithChain } from '@daltonr/settled-sdk';

const chain = await fetch('http://localhost:8080/api/keys').then(r => r.json());
const keyChain = chain.map(r => ({
  version: r.version,
  publicKey: Buffer.from(r.public_key, 'hex'),
  activatedAtTreeSize: BigInt(r.activated_at_tree_size),
}));

const ok = verifyTreeHeadWithChain(sth, keyChain);
```

```python
# Python example
from settled.verifier import KeyRecord, verify_tree_head_with_chain
import requests

data = requests.get('http://localhost:8080/api/keys').json()
chain = [KeyRecord(r['version'], bytes.fromhex(r['public_key']), r['activated_at_tree_size']) for r in data]

ok = verify_tree_head_with_chain(tree_size, root_hash, timestamp_ns, signature, key_version, chain)
```

### Post-rotation checklist

1. Confirm the new version is returned by `GET /api/keys`.
2. Verify a new STH has been produced with the new key version (wait up to `--sth-interval-secs`).
3. Update any SDK clients that pin a specific public key to use `verify_tree_head_with_chain` instead.
4. Back up the new `signing.key` file.

---

## SDK Deployment

The SDKs are client libraries — they are not deployed as services. They are included as dependencies in application code.

| SDK | Install |
|-----|---------|
| TypeScript | `npm install @daltonr/settled-sdk` |
| Python | `pip install settled-sdk` |
| Go | `go get github.com/richardadalton/settled/sdks/go` |
| Java | `implementation 'io.github.richardadalton:settled-sdk:0.1.0'` (Gradle) |
| .NET | `dotnet add package Settled.Sdk` |
| Rust | `cargo add settled-sdk` (crates.io) or `{ path = "sdks/rust" }` for local use |

For SDK publishing instructions see [`docs/publishing/`](publishing/).

Each SDK connects to `settled-server` on the gRPC port (default `50051`). The server address is the only configuration an SDK client needs.

```typescript
// TypeScript example
import { SettledClient } from '@daltonr/settled-sdk';
const client = new SettledClient('localhost:50051');
```

```python
# Python example
from settled import SettledClient
client = SettledClient('localhost:50051')
```
