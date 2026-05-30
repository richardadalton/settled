# Settled

A self-hostable, tamper-evident audit log with cryptographically verifiable proofs.

Settled does one thing: accept an entry, return a cryptographic proof that the entry was committed, and allow anyone to verify that proof independently — forever, without trusting the server.

## What it is

Settled is an append-only log backed by a binary Merkle tree (RFC 6962 — the same construction used by Google's Certificate Transparency). Every write produces an **inclusion proof** (this entry is in the log) and supports **consistency proofs** (the log was never rewritten between two observed states). Both proofs are verifiable client-side with no server interaction.

It is not a database. There are no updates or deletes.

## Why it exists

Regulated applications need tamper-evident audit trails. The current options are:

| Option | Problem |
|--------|---------|
| Database audit table | A compromised admin can rewrite history silently |
| Managed SaaS (Splunk, CloudTrail) | Vendor lock-in, cloud-only, expensive at scale |
| Immudb / Trillian | Correct guarantees, but limited SDK ecosystem |

Settled fills the gap: self-hostable, genuine cryptographic tamper-evidence, with first-class SDKs for TypeScript, Python, Go, Java, Rust, and .NET.

## How it works

Each entry is hashed (`SHA-256(0x00 || data)`) and inserted as a leaf in an append-only Merkle tree. Interior nodes use `SHA-256(0x01 || left || right)` — the RFC 6962 domain separation that prevents second-preimage attacks. The server periodically signs the tree root with Ed25519, producing a **Signed Tree Head (STH)**. Clients hold STHs and use them to verify proofs independently.

Write throughput is decoupled from proof generation: clients receive a durable acknowledgment immediately, and proofs are produced asynchronously. This mirrors how CT logs handle billions of entries.

## Getting started

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) — to run the server
- [Node.js](https://nodejs.org/) 18+ and npm — to run the web demo

### 1. Pull and run the server

```sh
docker pull richardadalton/settled-server:latest

docker run -d \
  --name settled \
  -p 50051:50051 \
  -p 8080:8080 \
  -v settled-data:/data \
  richardadalton/settled-server:latest
```

On first start, the server generates an Ed25519 signing key at `/data/signing.key` inside the volume. **Back this up** — it is the root of trust for all proofs. If it is lost, existing proofs can no longer be verified against it.

```sh
# Back up the signing key
docker cp settled:/data/signing.key ./signing.key.backup
```

Verify the server is healthy:

```sh
curl http://localhost:8080/health
```

The server exposes gRPC reflection, so you can explore the API with `grpcurl` without a proto file:

```sh
# List all methods
grpcurl -plaintext localhost:50051 list settled.v1.SettledLog

# Fetch the latest Signed Tree Head
grpcurl -plaintext -d '{"tree_size": 0}' localhost:50051 settled.v1.SettledLog/GetSth
```

See the [deployment guide](docs/deployment.md#ad-hoc-debugging-with-grpcurl) for more examples including authenticated requests.

#### STH interval

Writes and signing are decoupled. Every append is acknowledged and durably stored immediately — the Ed25519 signing step happens in the background on a separate timer, so write throughput is never blocked by cryptographic operations.

By default the server signs a new Signed Tree Head (STH) every **60 seconds**. Entries appended since the last signing are safely stored but not yet visible to readers until the next cycle. The 60-second default is a deliberate trade-off: it keeps signing overhead negligible even under high write load. For development or low-latency read requirements you can reduce it:

```sh
docker run -d \
  --name settled \
  -p 50051:50051 \
  -p 8080:8080 \
  -v settled-data:/data \
  richardadalton/settled-server:latest \
  --data-dir /data --sth-interval-secs 5
```

Set `--sth-interval-secs` to any positive integer. Lower values mean fresher reads; higher values mean fewer signatures and lower CPU overhead at scale.

### 2. Run the web demo

The `demos/typescript` directory contains a small TypeScript app that appends entries to the log and displays the audit trail.

```sh
cd demos/typescript
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). Enter a key and some data, click **Append**, then click **Reload Audit** to see the full log.

The **Key** is a correlation identifier, not a unique constraint. Use it to group related records — a user ID, order ID, or product ID that will have many entries over time. The server indexes by key so you can efficiently retrieve the most recent entry for any given entity.

## Architecture overview

Settled is built in three layers. The core cryptographic library (`settled-core`) implements the RFC 6962 Merkle tree, proof generation and verification, and Ed25519 signing — with no I/O dependencies. The storage layer (`settled-storage`) wraps RocksDB with five column families: an append-only entry log, a materialised tree node cache, a signed tree head history, a key-to-sequence index, and a key rotation record. The server (`settled-server`) exposes this over gRPC using Tokio and Tonic, decoupling write acknowledgement (WAL commit) from proof availability (background STH signing task). Six first-party SDKs — TypeScript, Python, Go, Java, Rust, and .NET — each ship their own gRPC client and a standalone verifier that can check proofs locally with no server connection.

## SDK quick-start

All examples assume the server is running on `localhost:50051`. Each SDK appends an entry and verifies the resulting inclusion proof client-side.

**TypeScript**
```typescript
import { SettledClient, verifyInclusion } from '@daltonr/settled-sdk';

const client = new SettledClient('http://localhost:50051');
const { seq, leafHash } = await client.append(key, data);
const { proof, treeSize, sth } = await client.inclusionProof(seq);
const ok = verifyInclusion(leafHash, seq, treeSize, proof, sth.rootHash);
```

**Python**
```python
from settled import SettledClient
from settled.verifier import verify_inclusion

client = SettledClient('localhost:50051')
result = client.append(b'user:42', b'{"action":"login"}')
proof = client.inclusion_proof(result.seq)
ok = verify_inclusion(result.leaf_hash, result.seq, proof.tree_size, proof.proof, proof.sth.root_hash)
```

**Go**
```go
c, _ := client.New("localhost:50051")
res, _ := c.Append(ctx, []byte("user:42"), []byte(`{"action":"login"}`))
p, _ := c.InclusionProof(ctx, res.Seq, 0)
ok := verifier.VerifyInclusion(res.LeafHash, res.Seq, p.TreeSize, p.Proof, p.Sth.RootHash)
```

**Java**
```java
try (var client = new SettledClient("localhost:50051")) {
    var res    = client.append("user:42".getBytes(), data);
    var proof  = client.inclusionProof(res.seq(), 0);
    boolean ok = Verifier.verifyInclusion(res.leafHash(), res.seq(), proof.treeSize(), proof.proof(), proof.sth().rootHash());
}
```

**Rust**
```rust
let mut client = SettledClient::connect("http://localhost:50051").await?;
let res   = client.append(b"user:42".to_vec(), data).await?;
let proof = client.inclusion_proof(res.seq, 0).await?;
let ok    = verify_inclusion(&res.leaf_hash, res.seq, proof.tree_size, &proof.proof, &proof.sth.root_hash);
```

**.NET**
```csharp
using var client = new SettledClient("http://localhost:50051");
var res   = await client.AppendAsync(key, data);
var proof = await client.InclusionProofAsync(res.Seq);
bool ok   = Verifier.VerifyInclusion(res.LeafHash, res.Seq, proof.TreeSize, proof.Proof, proof.Sth.RootHash);
```

## Project status

| Phase | What | Status |
|-------|------|--------|
| 1 | Spec and wire format | Done |
| 2 | `settled-core` — cryptographic library | Done |
| 3 | `settled-storage` — RocksDB storage layer | Done |
| 4 | `settled-server` — gRPC/HTTP server | Done |
| 5 | TypeScript SDK | Done |
| 6 | Additional SDKs (Python, Go, Java, Rust, .NET) | Done |
| 7 | External verifier protocol | Done |
| 8 | Performance validation | Done |

## Project structure

```
crates/
  settled-core/       # Merkle tree, inclusion/consistency proofs, Ed25519 STH signing
  settled-storage/    # RocksDB storage layer (log, tree, heads, index, keys column families)
  settled-server/     # gRPC/HTTP server (Tokio + Tonic)
  settled-check/      # External verifier CLI (verify STH signatures and inclusion proofs)
sdks/
  typescript/         # npm: @daltonr/settled-sdk
  python/             # PyPI: settled-sdk
  go/                 # pkg.go.dev: github.com/richardadalton/settled/sdks/go
  java/               # Maven Central: io.github.richardadalton:settled-sdk
  rust/               # crates.io: settled-sdk
  dotnet/             # NuGet: Settled.Sdk
tools/
  gen-sth-vectors/    # Binary for generating Ed25519 signed tree head test vectors
fuzz/                 # cargo-fuzz targets for all verifier functions
scripts/              # Python cross-language test vector generator
test-vectors/         # Canonical JSON test vectors (generated, committed)
docs/                 # Specs and deployment guide (see below)
```

## Running the tests

```sh
cargo test
```

Requires Rust stable. The fuzz targets require nightly:

```sh
cargo +nightly fuzz run fuzz_verify_inclusion
```

## Regenerating test vectors

```sh
python3 scripts/gen-test-vectors.py        # Merkle vectors
cargo run --bin gen-sth-vectors            # Ed25519 signed tree head vectors
```

## Docs

- [`docs/wire-format.md`](docs/wire-format.md) — hash constructions, proof algorithms, STH signing payload, duplicate key semantics
- [`docs/storage-schema.md`](docs/storage-schema.md) — RocksDB column family layout, key encodings, protobuf schemas
- [`docs/deployment.md`](docs/deployment.md) — running the server, Docker, systemd, networking
- [`docs/settled-node-spec.md`](docs/settled-node-spec.md) — external verifier node protocol specification
- [`docs/publishing/`](docs/publishing/) — how to publish each SDK to its registry (npm, PyPI, Maven Central, NuGet, pkg.go.dev)

## Licence

Copyright © 2026 Devjoy Ltd. All rights reserved.

Source code is published under the [Elastic License 2.0](./LICENSE). In summary:

- You may view, inspect, and run the software.
- You may not offer the software to third parties as a hosted or managed service.
- You may not remove or obscure licence or copyright notices.
- No warranty is provided.

This is not an open source project. The source is published for transparency and auditability — pull requests are not accepted. If you'd like to discuss integration or licensing, [get in touch](https://www.devjoy.com/settled/#contact).
