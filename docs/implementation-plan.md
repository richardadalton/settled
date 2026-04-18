# Settled — Implementation Plan

**Status:** Draft  
**Based on:** [settled.md](./settled.md)

---

## 1. Spec Review and Concerns

### 1.1 What the Spec Gets Right

- The RFC 6962 Merkle design is battle-tested (Google's Certificate Transparency logs). Using it as-is is the right call.
- Decoupling WAL acknowledgment from proof availability is the key architectural insight. The throughput math checks out.
- Ed25519 is the right signing algorithm. The 0x00/0x01 domain separation prefix is correctly specified and prevents second-preimage attacks.
- The external verifier protocol is well-designed and completes the security story — without it, a server operator with storage access can reconstruct a fraudulent history.
- RocksDB column family layout is appropriate for the access patterns.

### 1.2 Gaps That Must Be Resolved Before Coding

**Gap 1 — Signature wire format is underspecified.**

The spec says `Ed25519(private_key, tree_size || root_hash || timestamp)` but does not specify the byte encoding of `tree_size` (u64) and `timestamp` (i64). Every SDK must encode identically or cross-SDK verification fails silently. The canonical encoding must be:

```
tree_size:  u64, big-endian (8 bytes)
root_hash:  bytes[32]       (verbatim)
timestamp:  i64, big-endian (8 bytes)
total:      48 bytes signed
```

This must be documented in `docs/wire-format.md` and referenced by every SDK implementation.

**Gap 2 — No test vectors defined.**

RFC 6962 does not ship test vectors. The spec mentions "RFC 6962 test vectors" but does not define them. Before any code is written, known-good vectors must be committed to `test-vectors/`. These are the ground truth every implementation is validated against. Candidate sources: Trillian (Google's Go reference implementation), or hand-computed from the spec's own hash definitions.

Minimum required vectors:
- Leaf hashes for a set of known inputs
- Tree roots for sizes 1, 2, 3, 4, 5, 6, 7, 8
- Inclusion proofs for each leaf in a tree of size 7 and 8
- Consistency proofs: (1→2), (1→4), (3→7), (4→8), (7→8)
- A signed tree head with known key, payload, and expected signature bytes

**Gap 3 — Duplicate key behavior in the `index` column family is unspecified.**

The spec defines `index CF: user key (bytes) → seq (u64)`. What happens when the same key is appended twice? Options:
- Last-write-wins: `GET /v1/entries/:key` returns the most recent entry
- Multi-valued: returns all entries with that key (requires key → [seq] structure)

This decision affects the `GetRequest` API and index CF schema. Must be specified before the storage layer is built.

Recommendation: last-write-wins for the index (simple, O(1) lookup), with `GetRequest` by sequence number as the primary retrieval path. The key index is a convenience, not the canonical identifier.

**Gap 4 — Tree node addressing scheme is underspecified.**

The spec says `tree CF: level:index (u64:u64) → SHA-256 hash`. The exact algorithm mapping the binary Merkle tree to (level, index) pairs must be precisely defined. A mistake here produces subtly wrong consistency proofs that may pass some tests and fail others. The rebuild-from-log path must produce bit-for-bit identical nodes.

Recommendation: adopt the Trillian node addressing convention (level 0 = leaves, index = left-to-right position at that level) and document it explicitly in `docs/storage-schema.md`.

**Gap 5 — Key rotation is deferred but may be a v1 blocker for compliance.**

Open Question 1 in the spec defers key rotation. For regulated industries (the primary target market), a key management story is expected before production deployment. Without it, a compromised signing key with no rotation path is a liability.

Minimum viable v1 approach: store the signing key with a version number; historical STHs record which key version signed them; a key rotation produces a new key version and a rotation event in the log. Full certificate-chain-style rotation can be a v2 feature.

**Gap 6 — M1 milestone mixes two incompatible build targets.**

M1 lists "WASM build target" alongside the core Rust library. WASM (`wasm32-unknown-unknown`) and native builds use different Cargo targets and toolchains; mixing them in a single milestone creates unnecessary friction. Split into:
- M1: core library correctness with full test coverage, native only
- M1b: WASM and native binding export (napi-rs, PyO3) after core is validated

**Gap 7 — Timeline is optimistic for the stated accuracy requirements.**

The 10-day estimate produces a working prototype. A verifiably correct system with exhaustive test coverage and 5 cross-validated SDK implementations is closer to 4–6 weeks. The milestones below reflect the more conservative estimate.

---

## 2. Pre-Implementation Artifacts

These must exist before Phase 2 begins. They are not code — they are specifications that code will be verified against.

### 2.1 `docs/wire-format.md`

Canonical byte encoding for:
- SignedTreeHead signing payload
- Leaf hash construction
- Node hash construction
- Protobuf field encoding choices that affect hash inputs

### 2.2 `docs/storage-schema.md`

Exact binary format for every key and value in every RocksDB column family:
- `log` CF: key encoding, LogEntry protobuf schema
- `tree` CF: (level, index) key encoding, hash value format
- `heads` CF: tree_size key encoding, SignedTreeHead protobuf schema
- `index` CF: raw key bytes, u64 seq encoding, duplicate key semantics

### 2.3 `test-vectors/`

JSON files containing:
- `leaf-hashes.json`: `{ "input_hex": "...", "hash_hex": "..." }[]`
- `tree-roots.json`: `{ "size": N, "leaves": [...], "root_hex": "..." }[]`
- `inclusion-proofs.json`: `{ "tree_size": N, "leaf_index": i, "leaves": [...], "path": [...], "root_hex": "..." }[]`
- `consistency-proofs.json`: `{ "old_size": a, "new_size": b, "leaves": [...], "proof": [...], "old_root": "...", "new_root": "..." }[]`
- `signed-tree-heads.json`: `{ "private_key_hex": "...", "tree_size": N, "root_hash_hex": "...", "timestamp_ns": T, "expected_signature_hex": "..." }[]`

---

## 3. Step-by-Step Implementation Plan

The guiding principle: **correctness flows downward**. Each phase is verified before the next phase builds on it. No milestone is complete without passing its tests.

---

### Phase 1 — Pre-implementation Spec Work (2 days)

**Step 1.1** — Write `docs/wire-format.md` with exact byte encodings (see Gap 1).

**Step 1.2** — Write `docs/storage-schema.md` with column family schemas (see Gap 4).

**Step 1.3** — Decide duplicate key semantics and document in `docs/wire-format.md` (see Gap 3).

**Step 1.4** — Generate and commit all test vectors to `test-vectors/` (see Gap 2). Derive from Trillian or compute by hand from the spec's hash definitions. Cross-check at least the small cases (size 1–4) manually.

**Step 1.5** — Sketch a minimal key rotation scheme and append it to `docs/wire-format.md` (see Gap 5).

**Completion gate:** A reviewer can read these documents and implement a correct Merkle verifier in any language without referring to any code.

---

### Phase 2 — `settled-core`: Cryptographic Library (4 days)

This crate has no dependencies on storage or network. It is the foundation everything else stands on.

**Step 2.1 — Workspace and crate setup.**

```
settled/
  Cargo.toml          (workspace)
  crates/
    settled-core/     (this phase)
    settled-server/   (Phase 4)
  test-vectors/
  docs/
```

**Step 2.2 — Leaf and node hashing.**

```rust
pub fn leaf_hash(data: &[u8]) -> [u8; 32]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32]
```

Tests:
- Every entry in `leaf-hashes.json` produces the expected output. Exact byte match — no tolerance.
- `leaf_hash(b"")` matches the vector for empty input.
- `node_hash` is not commutative: `node_hash(a, b) != node_hash(b, a)` for distinct a, b.

**Step 2.3 — Append-only Merkle tree.**

Implement RFC 6962 incremental append. Store only the "frontier" — the rightmost complete subtree at each level — not the full tree (full materialisation lives in the storage layer).

```rust
pub struct MerkleTree { ... }
impl MerkleTree {
    pub fn new() -> Self
    pub fn append(&mut self, leaf_hash: [u8; 32]) -> u64   // returns new leaf index
    pub fn size(&self) -> u64
    pub fn root(&self) -> Option<[u8; 32]>                 // None if empty
    pub fn root_at_size(&self, size: u64) -> Result<[u8; 32], Error>
}
```

Tests:
- `root()` for trees of each size in `tree-roots.json` matches exactly.
- `root_at_size(k)` for k ≤ current size is consistent with having stopped appending at k.
- Appending to a tree of size N then querying `root_at_size(N)` returns the same root as before.

**Step 2.4 — Inclusion proof generation and verification.**

```rust
pub fn inclusion_proof(
    tree: &MerkleTree,
    leaf_index: u64,
    tree_size: u64,
) -> Result<Vec<[u8; 32]>, Error>

pub fn verify_inclusion(
    leaf_hash: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool
```

Tests:
- Every entry in `inclusion-proofs.json`: `inclusion_proof` produces the expected path; `verify_inclusion` returns true.
- Property test (proptest/quickcheck): for any randomly generated tree of size 1–1000, every leaf's inclusion proof verifies against the root.
- Negative: tampered leaf hash → `verify_inclusion` returns false.
- Negative: tampered proof element → `verify_inclusion` returns false.
- Negative: wrong tree size → `verify_inclusion` returns false.
- Negative: wrong root → `verify_inclusion` returns false.
- Edge cases: leaf at index 0, leaf at index N-1, single-leaf tree.

**Step 2.5 — Consistency proof generation and verification.**

```rust
pub fn consistency_proof(
    old_size: u64,
    new_size: u64,
    tree: &MerkleTree,
) -> Result<Vec<[u8; 32]>, Error>

pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    proof: &[[u8; 32]],
    old_root: &[u8; 32],
    new_root: &[u8; 32],
) -> bool
```

Tests:
- Every entry in `consistency-proofs.json` verifies correctly.
- Property test: any two size snapshots of a growing tree are consistent.
- Negative: tree with a tampered historical entry fails consistency check (this is the core tamper-evidence guarantee — test it explicitly by building two trees that diverge at a known point and confirming the proof fails).
- Negative: proof from a completely different tree fails.
- Edge: `old_size == new_size` → trivial proof (empty or single-element).
- Edge: `old_size == 1`.
- Edge: consistency across a power-of-two boundary.

**Step 2.6 — Ed25519 signing.**

```rust
pub struct SigningKey(/* ed25519_dalek::SigningKey */);
pub struct VerifyingKey(/* ed25519_dalek::VerifyingKey */);

impl SigningKey {
    pub fn generate() -> Self
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error>
    pub fn verifying_key(&self) -> VerifyingKey
    pub fn sign_tree_head(&self, sth: &UnsignedTreeHead) -> [u8; 64]
}

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error>
    pub fn verify_tree_head(&self, sth: &SignedTreeHead) -> bool
}
```

The `sign_tree_head` function encodes the STH fields in exactly the canonical order defined in `docs/wire-format.md`.

Tests:
- Sign a known STH with a known key, verify signature matches the vector in `signed-tree-heads.json`.
- `verify_tree_head` returns true for a freshly signed STH.
- `verify_tree_head` returns false if any field of the STH is modified after signing.
- `verify_tree_head` returns false with the wrong public key.

**Step 2.7 — Fuzz testing.**

Use `cargo-fuzz` on:
- `verify_inclusion`: arbitrary (leaf_hash, index, size, proof, root) must never panic.
- `verify_consistency`: arbitrary inputs must never panic.
- `verify_tree_head`: arbitrary STH bytes must never panic.

A verifier that panics on malformed input is a denial-of-service vulnerability.

**Step 2.8 — WASM build.**

Add `wasm-pack` target. Export `verify_inclusion`, `verify_consistency`, `verify_tree_head` to JavaScript. Run the same test vector suite via Node.js against the WASM build.

**Completion gate:** All test vectors pass. Fuzz runs 1M iterations without a crash. WASM exports are verified. Zero `unsafe` blocks unless clearly justified and reviewed.

---

### Phase 3 — Storage Layer (3 days)

**Step 3.1 — RocksDB column family setup.**

Four CFs as specified: `log`, `tree`, `heads`, `index`. Key and value encodings exactly as documented in `docs/storage-schema.md`. No schema variation.

**Step 3.2 — `LogStore`: write and read log entries.**

```rust
pub struct LogStore { /* ... */ }
impl LogStore {
    pub fn append(&self, key: &[u8], data: &[u8]) -> Result<(u64, i64)>  // (seq, timestamp_ns)
    pub fn get_by_seq(&self, seq: u64) -> Result<Option<LogEntry>>
    pub fn get_seq_by_key(&self, key: &[u8]) -> Result<Option<u64>>
    pub fn seq_range(&self, start: u64, end: u64) -> Result<Vec<LogEntry>>
}
```

Tests:
- Written entry is retrievable by seq immediately after write.
- Written entry is retrievable by seq after DB close and reopen (crash-safe).
- Key index returns correct seq after reopen.
- Concurrent appends produce gap-free, monotonically increasing sequence numbers.
- `seq_range` returns entries in order.

**Step 3.3 — `TreeStore`: materialise and retrieve Merkle nodes.**

```rust
pub struct TreeStore { /* ... */ }
impl TreeStore {
    pub fn write_batch(&self, nodes: &[(u64, u64, [u8; 32])]) -> Result<()>  // (level, index, hash)
    pub fn get_node(&self, level: u64, index: u64) -> Result<Option<[u8; 32]>>
    pub fn rebuild_from_log(&self, log: &LogStore) -> Result<()>
}
```

Tests:
- After writing N entries and their tree nodes, `settled-core` inclusion proofs based on retrieved nodes all verify.
- `rebuild_from_log` with a cleared tree CF produces bit-for-bit identical node hashes to the original write path. This is the critical rebuild correctness test.
- Rebuild is idempotent: running it twice produces the same result.

**Step 3.4 — `HeadStore`: signed tree head history.**

```rust
pub struct HeadStore { /* ... */ }
impl HeadStore {
    pub fn write(&self, sth: &SignedTreeHead) -> Result<()>
    pub fn latest(&self) -> Result<Option<SignedTreeHead>>
    pub fn at_size(&self, tree_size: u64) -> Result<Option<SignedTreeHead>>
    pub fn range(&self, from_size: u64, to_size: u64) -> Result<Vec<SignedTreeHead>>
}
```

Tests:
- Write 10 STHs of increasing sizes, `latest()` returns the largest.
- `at_size` returns the STH with exactly that tree_size.
- `at_size` on a size that was never written returns None (not the nearest neighbour).

**Step 3.5 — Crash recovery integration test.**

This is one of the most important tests in the suite.

Scenario:
1. Start DB, write 1000 entries (seq 0–999).
2. Background tree builder runs and produces STH at size 1000.
3. Write entries 1000–1099 (WAL-durable but not yet in tree).
4. Simulate crash (drop the DB handle without flushing the tree CF).
5. Reopen DB.
6. Trigger rebuild / tree builder catches up.
7. Verify: all 1100 entries are retrievable, all inclusion proofs verify, consistency proof from the pre-crash STH to the new STH verifies.

**Completion gate:** All tests pass including the crash recovery test. `rebuild_from_log` produces identical nodes to the live write path.

---

### Phase 4 — Server (4 days)

**Step 4.1 — Write path (critical path).**

`AppendRequest → validate → assign seq (atomic u64) → RocksDB WAL write → AppendResponse`.

No tree operations on this path. The leaf_hash in `AppendResponse` is computed as `SHA256(0x00 || data)` using `settled-core`.

Tests:
- Response `seq` matches the seq stored in the DB.
- Response `leaf_hash` matches the `settled-core` leaf hash for the submitted data.
- 1000 concurrent appends: all succeed, all seqs are unique and gap-free.
- Write latency benchmark: p99 < 1ms at 10K concurrent requests (CI perf test with explicit threshold).

**Step 4.2 — Background tree builder.**

```
MMD loop (configurable interval, default 100ms):
  1. Drain accumulated seqs since last batch
  2. Fetch entries from LogStore
  3. Compute leaf hashes
  4. Extend MerkleTree
  5. Compute inclusion proof nodes (batch write to TreeStore)
  6. Sign new STH with Ed25519
  7. Persist STH to HeadStore
  8. Broadcast STH to SSE subscribers
```

Tests:
- After one full MMD cycle, every previously acknowledged entry has a valid inclusion proof.
- Builder handles zero new entries without producing a duplicate STH.
- Builder handles exactly 1 new entry.
- Builder handles the `batch_size` threshold trigger (fires before MMD if N entries accumulated).
- After a simulated crash between step 1 and step 7, recovery completes correctly.

**Step 4.3 — gRPC handlers (tonic).**

Implement all RPCs. Each is thin — validate inputs, delegate to storage + `settled-core`, return response.

For each RPC, tests use a **real server and real DB** (no mocks):
- `Append` returns correct seq and leaf_hash.
- `Get` returns the entry and its inclusion proof; proof verifies with `settled-core`.
- `GetInclusionProof` for seq not yet in a tree returns `NOT_FOUND` or waits (define the behaviour).
- `GetConsistencyProof` from STH₁ to STH₂ verifies locally.
- `GetSignedTreeHead` signature verifies with the embedded public key.
- `AppendStream` pipelining: send 10,000 requests, receive 10,000 responses in order, all seqs unique.
- `StreamTreeHeads` SSE: receive at least 3 STH events during sustained write load.

**Step 4.4 — REST layer (Axum).**

Every gRPC test has an HTTP counterpart at the REST endpoints. Shared business logic — only the serialisation layer differs.

**Step 4.5 — End-to-end correctness test.**

This test must pass before Phase 4 is considered complete:

1. Start a real server (in-process or subprocess).
2. Append 10,000 entries via gRPC.
3. Wait for 2 MMD cycles.
4. For every single entry (all 10,000):
   - Fetch its inclusion proof.
   - Verify the proof using `settled-core::verify_inclusion`.
5. Fetch a consistency proof between the STH after entry 5,000 and the final STH.
6. Verify the consistency proof using `settled-core::verify_consistency`.
7. Assert all 10,000 verifications passed. Any single failure is a hard failure.

**Completion gate:** End-to-end correctness test passes. All gRPC and REST integration tests pass against a real server.

---

### Phase 5 — TypeScript SDK (2 days)

**Step 5.1 — Generate gRPC stubs** from the proto file using `ts-proto`.

**Step 5.2 — `SettledClient`** with connection management and reconnect logic.

**Step 5.3 — Client-side proof verification.**

Two options:
- (a) Call the WASM build of `settled-core` — shares the exact same implementation.
- (b) Reimplement in TypeScript using `crypto.subtle`.

If (b), the implementation **must** pass all test vectors from `test-vectors/` before shipping. No exceptions.

```typescript
// Pure functions — no network calls
function verifyInclusion(
  leafHash: Uint8Array,
  leafIndex: bigint,
  treeSize: bigint,
  proof: Uint8Array[],
  root: Uint8Array,
): boolean

function verifyConsistency(
  oldSize: bigint,
  newSize: bigint,
  proof: Uint8Array[],
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
): boolean

function verifyTreeHead(sth: SignedTreeHead): boolean
```

Tests:
- Run every entry in all `test-vectors/*.json` files through the TypeScript verifier.
- Integration test: append via TypeScript SDK, wait for MMD, fetch proof, `verifyInclusion` returns true.
- Negative: tampered proof element → `verifyInclusion` returns false.

**Step 5.4 — `appendStream`** with configurable `batchSize` and `flushIntervalMs`, back-pressure on buffer full.

**Step 5.5 — Cross-language verification test.**

A test that:
1. Appends entries via the Rust integration test harness.
2. Retrieves proofs from the server.
3. Verifies those proofs using the TypeScript SDK's verifier.

And vice versa: append via TypeScript SDK, verify via Rust `settled-core`. Any encoding mismatch will surface here.

**Completion gate:** All test vectors pass in TypeScript. Cross-language verification test passes. Integration tests pass against a live server.

---

### Phase 6 — Additional SDKs (per SDK, ~1 day each)

Each SDK follows an identical gate structure:

1. Generate gRPC stubs.
2. Implement proof verification (native bindings or clean reimplementation).
3. Run all test vectors — this is the hard gate.
4. Integration test against a live server: append → proof → verify.
5. Cross-language verification: proofs generated by Rust verified in this SDK, and vice versa.

**Python** — PyO3 bindings to `settled-core` for verification. `grpcio-tools` for stubs. Publish to PyPI.

**Go** — Clean reimplementation of verify functions (idiomatic Go, no CGo). `protoc-gen-go` for stubs. Test vectors run via Go test suite. This is the most valuable cross-check: two independent implementations must agree on every vector.

**Java/Kotlin** — `protoc-gen-grpc-java`. Verify layer reimplemented in Java. Maven Central release.

**Rust client** — shares `settled-core` directly. `tonic-build` for stubs. This is the simplest SDK.

**.NET** — `Grpc.Tools`. Verify layer in C#. NuGet release.

**Completion gate per SDK:** All test vectors pass. Cross-language verification test passes. Published to the respective package registry.

---

### Phase 7 — External Settled Protocol (2 days)

**Step 7.1 — Settled registry.**

Admin API: `POST/GET/DELETE /v1/admin/settledes`. Stored in a `settledes` CF in RocksDB.

**Step 7.2 — STH push loop.**

On each MMD cycle after signing, push the new STH to every registered settled URL. Push failures must not block the log. Retry with backoff. Dead settledes flagged after N failures.

Tests:
- Mock settled HTTP server receives pushes at the configured interval.
- Push failures do not block the main write path.
- Server retries failed pushes with exponential backoff.
- Signature on the push payload verifies with the server's public key.

**Step 7.3 — `settled-node` archive service.**

A lightweight server that:
- Receives STH pushes from the main server.
- Verifies the push signature.
- Stores the STH in its local archive.
- Exposes `GET /archive/:tree_size` for retrieval.

**Step 7.4 — `settled-check` CLI.**

```bash
settled-check verify \
  --server grpc://settled.example.com:9000 \
  --sth ./archived-sth.json
```

Tests:
- Consistent case: real server, real archived STH, prints success and entry count delta.
- Tampered STH: manually change the root_hash in the archived STH JSON, verify detection and clear error message.
- Server cannot produce proof (server was reconstructed): verify detection.
- Server is unreachable: clear error, exit code 1.

**Step 7.5 — Threshold counter-signature protocol.**

Tests:
- M-of-N happy path: all N settledes online, M signatures collected, `FinalSTH` is valid.
- Degraded: only M settledes online, still reaches threshold, `FinalSTH` is valid.
- Below threshold: only M-1 settledes online, STH is not finalised, clients configured for threshold mode reject it.
- Fraudulent counter-signature (wrong key): rejected.
- Client with threshold=0 (default) accepts an STH without counter-signatures (backwards compatibility).

**Completion gate:** All push, archive, CLI, and threshold tests pass. Docker image for `settled-node` published.

---

### Phase 8 — Performance Validation (1 day)

Run only after Phase 4 correctness tests pass. Performance on incorrect code is irrelevant.

**Benchmark suite (all run against a real server, not mocks):**

| Benchmark | Target | Failure threshold |
|-----------|--------|-------------------|
| Sustained write throughput | 500K entries/sec | < 400K |
| Write latency p50 | < 100µs | > 500µs |
| Write latency p99 | < 1ms | > 5ms |
| Tree update time at 50K leaves | < 5ms | > 10ms |
| Inclusion proof verification (client-side) | > 1M/sec | < 500K |
| Consistency proof verification | > 500K/sec | < 200K |

These benchmarks run in CI on a dedicated performance runner. A regression in throughput or latency beyond the failure threshold blocks the build.

**Grafana dashboard:** Expose Prometheus metrics from the server. Dashboard shows: entries/sec, WAL write latency histogram, tree update duration, STH publication lag, active connections.

**Completion gate:** All benchmarks pass their targets on the designated hardware. Dashboard displays correct metrics under sustained load.

---

## 4. Testing Philosophy

**No mocks in correctness tests.** The server's storage and crypto paths must be tested against real RocksDB instances and real Ed25519 keys. Mocking either defeats the purpose of the tests.

**Test vectors are immutable.** Once committed, test vectors never change. If an implementation disagrees with a vector, the implementation is wrong. Changing a vector to match broken code is not acceptable.

**Cross-language verification tests are mandatory.** A proof generated by one SDK must be verifiable by every other SDK. This is the strongest possible correctness signal.

**Negative tests matter as much as positive tests.** A verification function that always returns `true` passes all positive tests. Negative tests (tampered data, wrong keys, mismatched sizes) are where bugs hide.

**Property tests complement vector tests.** Vectors cover known cases. Property tests (proptest, hypothesis, quickcheck) cover the space of cases no one thought of.

**Fuzz all verifiers.** A malformed proof that causes a panic is a denial-of-service vulnerability. Every public verification function must be fuzz-tested.

---

## 5. Open Questions from the Spec

These are carried forward from `settled.md` Section 13 with disposition notes:

| # | Question | Disposition |
|---|----------|-------------|
| 1 | Key rotation | Sketch a minimal key versioning scheme for v1 (see Gap 5 above). Full chain-of-trust rotation is v2. |
| 2 | Large payload storage | Accept up to 64KB inline for v1. Add a hash-reference mode (store hash, payload elsewhere) as a v2 feature. Document the limit clearly in the SDK. |
| 3 | Retention and cold archival | Out of scope for v1. Document that the log grows indefinitely. Add a `settled-archive` export command to v2 roadmap. |
| 4 | Multi-tenancy | Out of scope for v1. Named log instances is the right approach; design it as isolated RocksDB prefixes or separate DB files. |
| 5 | Strict causal ordering | Out of scope for v1. Sequences are assigned by a single atomic counter so entries are totally ordered within one node; that is sufficient for most compliance use cases. |
