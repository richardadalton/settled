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

The `examples/web-demo` directory contains a small TypeScript app that appends entries to the log and displays the audit trail.

```sh
cd examples/web-demo
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). Enter a key and some data, click **Append**, then click **Reload Audit** to see the full log.

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

## Crate structure

```
crates/
  settled-core/       # Merkle tree, inclusion/consistency proofs, Ed25519 STH signing
  settled-storage/    # RocksDB storage layer (log, tree, heads, index, keys CFs)
  gen-sth-vectors/    # Binary for generating signed tree head test vectors
fuzz/                 # cargo-fuzz targets for all verifier functions
scripts/              # Python cross-language test vector generator
test-vectors/         # Canonical JSON test vectors (generated, committed)
docs/                 # Specs: wire-format.md, storage-schema.md, implementation-plan.md
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
- [`docs/implementation-plan.md`](docs/implementation-plan.md) — full build plan with completion gates for each phase

## Licence

Copyright © 2026 Devjoy Ltd. All rights reserved.

Source code is published under the [Elastic License 2.0](./LICENSE). In summary:

- You may view, inspect, and run the software.
- You may not offer the software to third parties as a hosted or managed service.
- You may not remove or obscure licence or copyright notices.
- No warranty is provided.

This is not an open source project. The source is published for transparency and auditability — pull requests are not accepted. If you'd like to discuss integration or licensing, [get in touch](https://www.devjoy.com/settled/#contact).
