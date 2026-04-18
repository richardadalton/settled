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

Settled fills the gap: self-hostable, open source, genuine cryptographic tamper-evidence, with first-class SDKs for TypeScript, Python, Go, Java, Rust, and .NET.

## How it works

Each entry is hashed (`SHA-256(0x00 || data)`) and inserted as a leaf in an append-only Merkle tree. Interior nodes use `SHA-256(0x01 || left || right)` — the RFC 6962 domain separation that prevents second-preimage attacks. The server periodically signs the tree root with Ed25519, producing a **Signed Tree Head (STH)**. Clients hold STHs and use them to verify proofs independently.

Write throughput is decoupled from proof generation: clients receive a durable acknowledgment immediately, and proofs are produced asynchronously. This mirrors how CT logs handle billions of entries.

## Project status

Under active development. Phases completed:

| Phase | What | Status |
|-------|------|--------|
| 1 | Spec and wire format | Done |
| 2 | `settled-core` — cryptographic library | Done |
| 3 | `settled-storage` — RocksDB storage layer | Done |
| 4 | `settled-server` — gRPC/HTTP server | Upcoming |
| 5 | TypeScript SDK | Upcoming |
| 6 | Additional SDKs | Upcoming |
| 7 | External verifier protocol | Upcoming |
| 8 | Performance validation | Upcoming |

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
