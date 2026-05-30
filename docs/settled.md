# Settled — Tamper-Evident Audit Log

**Status:** Current implementation reference

---

## 1. What It Is

Settled is a standalone, self-hostable tamper-evident audit log with cryptographically verifiable inclusion and consistency proofs. It is designed to be the missing piece in the Node.js compliance ecosystem — and to be fast enough that throughput is never the reason you reach for something else.

It is not a database. It does not support updates or deletes. It does one thing: accept an entry, return a proof that the entry was committed, and allow anyone to verify that proof independently — forever, without trusting the server.

---

## 2. The Problem It Solves

Every application in a regulated industry needs an audit trail. Most implement one of:

- **Database audit table** — fast, queryable, but a compromised admin can rewrite history silently
- **Managed SaaS** (Splunk, Pangea, CloudTrail) — vendor lock-in, cloud-only, expensive at scale
- **Immudb / Trillian** — correct cryptographic guarantees but no maintained Node.js SDK, Go-only ecosystem, limited throughput on older versions

Settled fills the gap: self-hostable, open source, genuine cryptographic tamper-evidence, and a first-class TypeScript SDK with SDKs for all major languages.

---

## 3. Design Goals

| Goal | Target |
|------|--------|
| Write throughput | 500K entries/sec per node |
| Write latency (p99) | < 1ms acknowledgment |
| Proof availability | Configurable MMD: 100ms default |
| Horizontal scale | Linear via partitioning |
| Proof verification | Client-side, no server trust required |
| Deployment | Single Docker container, no external dependencies |
| SDK languages | TypeScript, Python, Go, Java, Rust, .NET |

The key insight that makes these numbers achievable: **decouple the write path from the proof path**. Clients get a durable acknowledgment immediately. Proofs are generated asynchronously in batches. This is how Google's Certificate Transparency logs handle billions of entries.

---

## 4. Cryptographic Foundation

### 4.1 The Merkle Tree

Settled uses a **binary append-only Merkle tree** as defined in RFC 6962 (Certificate Transparency). Each leaf is the SHA-256 hash of the submitted data. Interior nodes are SHA-256 of the concatenation of their children.

```
              root
             /    \
           h01    h23
          /   \  /   \
         h0  h1 h2  h3
         |   |  |   |
        e0  e1 e2  e3
```

This structure supports two proof types:

**Inclusion proof** — proves entry `e` at index `i` is in the tree of size `n`. Returns the sibling hash at each level from leaf to root. O(log n) hashes. Anyone can recompute the root and compare against the signed tree head.

**Consistency proof** — proves tree of size `n` is a prefix of tree of size `m`. Returns the minimal set of node hashes that allows a verifier holding the old root to compute the new root. O(log m) hashes. This is what prevents retroactive history rewriting — you cannot produce a valid consistency proof for a tree where earlier entries were altered.

### 4.2 Signed Tree Heads

Periodically (every MMD interval), the server computes the current Merkle root and signs it with **Ed25519**:

```
SignedTreeHead {
  tree_size:  uint64
  root_hash:  bytes[32]
  timestamp:  int64 (Unix nanoseconds)
  signature:  bytes[64]   // Ed25519(private_key, tree_size || root_hash || timestamp)
  public_key: bytes[32]
}
```

Ed25519 was chosen over ECDSA for signing speed (~70K signatures/sec), small key/signature size, and resistance to weak random number generators. The public key is embedded in every signed tree head so verification requires no external key lookup.

Signed tree heads can be published to an external transparency monitor (a simple HTTP endpoint, S3 bucket, or public log) to create an independent settled that the server cannot tamper with after the fact.

### 4.3 Leaf Hash Construction

```
leaf_hash = SHA256(0x00 || data)
```

Interior node:
```
node_hash = SHA256(0x01 || left_hash || right_hash)
```

The `0x00` / `0x01` domain separation prefix prevents second-preimage attacks (a leaf cannot be mistaken for an interior node). This follows RFC 6962 exactly.

---

## 5. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Clients                                  │
│     TypeScript  Python  Go  Java  Rust  .NET  REST              │
└────────────────────────┬────────────────────────────────────────┘
                         │ gRPC (primary) / HTTP+JSON (secondary)
┌────────────────────────▼────────────────────────────────────────┐
│                      Settled Server (Rust)                       │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  gRPC/HTTP  │  │  Write path  │  │    Tree builder       │  │
│  │  handler    │→→│  WAL append  │  │    (background)       │  │
│  │             │  │  → ack       │  │    batch → Merkle     │  │
│  └─────────────┘  └──────┬───────┘  │    → sign head       │  │
│                           │          └───────────────────────┘  │
│                    ┌──────▼──────────────────────┐              │
│                    │         RocksDB              │              │
│                    │  log CF    tree CF   idx CF  │              │
│                    └─────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

### 5.1 Why Rust

The server is written in Rust for three reasons that are not negotiable at these performance targets:

1. **No garbage collector.** GC pauses are incompatible with sub-millisecond p99 write latency at high throughput. Java and Node.js both have GC. Go has a low-latency GC but still pauses. Rust has no runtime.

2. **Memory safety without cost.** Crypto code and network servers written in C/C++ have a long history of memory safety vulnerabilities (buffer overflows, use-after-free). Rust eliminates this class of bugs at compile time.

3. **Tokio async runtime.** Rust's async I/O via Tokio handles hundreds of thousands of concurrent connections with minimal overhead. Combined with `tonic` (gRPC) and `rocksdb-rs`, the server has near-zero overhead between the wire and the storage layer.

### 5.2 Why RocksDB

RocksDB is an LSM-tree (Log-Structured Merge-tree) key-value store developed by Facebook. LSM-trees are explicitly designed for write-heavy append-heavy workloads — exactly this use case.

Key properties:
- Sequential disk writes even for random key inserts — maximises SSD throughput
- Write path: in-memory MemTable → immutable MemTable → SST file (background compaction)
- ~500K-1M simple puts/sec on modern NVMe hardware
- Used in production at Facebook, LinkedIn, Slack, Netflix

Settled uses three RocksDB **column families** (independent key spaces in the same file):

| Column Family | Key | Value | Purpose |
|---------------|-----|-------|---------|
| `log` | seq (u64, big-endian) | LogEntry (protobuf) | The actual entries |
| `tree` | level:index (u64:u64) | SHA-256 hash (32 bytes) | Materialised Merkle tree nodes |
| `heads` | tree_size (u64) | SignedTreeHead (protobuf) | History of signed tree heads |
| `index` | user key (bytes) | seq (u64) | Key → sequence lookup |

The `log` and `index` column families use a **WAL (Write-Ahead Log)** for crash safety. The `tree` column family can be rebuilt from the `log` if necessary — it is a derived data structure.

### 5.3 Write Path (Critical Path)

Every nanosecond here matters:

```
1. Client sends AppendRequest via gRPC
2. Server validates request (key non-empty, data size limit)
3. Atomic:
   a. Assign sequence number (atomic u64 counter)
   b. Write LogEntry to RocksDB WAL (log CF + index CF)
   c. fsync (configurable — default on, can disable for max throughput)
4. Return AppendResponse { seq, timestamp } to client
   → This is the acknowledgment. Entry is durable.

Background (async, does not block the client):
5. Leaf accumulator collects entries since last tree update
6. At MMD interval (default 100ms) OR batch_size threshold (default 10,000):
   a. Compute leaf hashes for all new entries
   b. Extend the Merkle tree (O(N log N) for N new leaves)
   c. Compute new root hash
   d. Sign new SignedTreeHead with Ed25519
   e. Persist tree nodes and head to RocksDB
7. Broadcast new SignedTreeHead to connected clients (optional SSE stream)
```

The client receives its acknowledgment at step 4. The proof becomes available after step 6. The time between 4 and 6 is the **Maximum Merge Delay (MMD)** — configurable, default 100ms.

This is the same pattern used by Google's CT logs. The trade-off is deliberate: you get a durability guarantee immediately, and a proof shortly after. If the server crashes between steps 4 and 6, the entry is recoverable from the WAL and will be included in the tree on restart.

### 5.4 Batch Tree Update Performance

At 100ms MMD with 500K entries/sec sustained:
- 50,000 new leaves per batch
- log₂(50,000) ≈ 16 levels of new nodes to compute
- 50,000 × 16 = 800,000 SHA-256 operations per batch
- SHA-256 throughput on modern CPU with AVX2: ~2 billion calls/sec
- Tree update time: 800,000 / 2,000,000,000 = **0.4 milliseconds**

The tree update consumes less than 0.5% of the MMD window. Proof generation is never the bottleneck.

---

## 6. The Wire Protocol

### 6.1 gRPC API

The server exposes a single gRPC service defined in `proto/settled.v1.proto`. The full proto is the canonical reference; a summary of every RPC follows.

```protobuf
syntax = "proto3";
package settled.v1;

service SettledLog {
  rpc Append(AppendRequest)           returns (AppendResponse);
  rpc BatchAppend(BatchAppendRequest) returns (BatchAppendResponse);
  rpc Get(GetRequest)                 returns (GetResponse);
  rpc GetLatest(GetLatestRequest)     returns (GetLatestResponse);
  rpc GetByKey(GetByKeyRequest)       returns (GetByKeyResponse);
  rpc ListEntries(ListEntriesRequest) returns (ListEntriesResponse);
  rpc Watch(WatchRequest)             returns (stream Entry);
  rpc GetSth(GetSthRequest)           returns (GetSthResponse);
  rpc InclusionProof(InclusionProofRequest)     returns (InclusionProofResponse);
  rpc ConsistencyProof(ConsistencyProofRequest) returns (ConsistencyProofResponse);
}
```

**Default ports:** gRPC on `:50051`, admin HTTP on `:8080`.

---

### 6.2 Write RPCs

#### `Append`

Append a single entry. Returns immediately once the entry is durably written to the WAL.

```protobuf
message AppendRequest  { bytes key = 1; bytes data = 2; }
message AppendResponse {
  uint64 seq          = 1;   // assigned sequence number (0-based)
  int64  timestamp_ns = 2;   // nanoseconds since Unix epoch
  bytes  leaf_hash    = 3;   // SHA-256(0x00 || data)
  bytes  key          = 4;   // echo of the request key, for async correlation
}
```

#### `BatchAppend`

Append up to 1 000 entries atomically. All seqs are assigned contiguously and all entries land in a single RocksDB `WriteBatch` (one WAL sync). Returns one `AppendResponse` per entry in input order.

```protobuf
message BatchAppendRequest  { repeated AppendRequest  entries = 1; }
message BatchAppendResponse { repeated AppendResponse entries = 1; }
```

---

### 6.3 Read RPCs

#### `Get`

Retrieve a single entry by sequence number.

```protobuf
message GetRequest  { uint64 seq = 1; }
message GetResponse { Entry entry = 1; }

message Entry {
  uint64 seq          = 1;
  int64  timestamp_ns = 2;
  bytes  key          = 3;
  bytes  data         = 4;
  bytes  leaf_hash    = 5;
}
```

#### `GetLatest`

Return the N most-recent entries, newest first. `n = 0` is treated as 1. Values above the server cap (`--max-get-latest`, default 1 000) are silently clamped. `total_available` tells callers whether the result was truncated.

```protobuf
message GetLatestRequest  { uint32 n = 1; }
message GetLatestResponse {
  repeated Entry entries       = 1;
  uint64         total_available = 2;
}
```

#### `GetByKey`

Return all entries for an exact key match, oldest first, with cursor-based pagination. `cursor = 0` starts from the beginning of the log; `next_cursor = 0` in the response means no further pages. `limit = 0` uses the server default (50), capped at 1 000.

```protobuf
message GetByKeyRequest {
  bytes  key    = 1;
  uint64 cursor = 2;
  uint32 limit  = 3;
}
message GetByKeyResponse {
  repeated Entry entries     = 1;
  uint64         next_cursor = 2;
}
```

Backed by an O(1) index CF (`key → latest seq`) for the first lookup; subsequent pages scan forward from the cursor.

#### `ListEntries`

Return a seq-ordered page of entries within `[from_seq, to_seq)`. `to_seq = 0` means no upper bound. `cursor` overrides `from_seq` for subsequent pages. `limit = 0` uses the server default (50), capped at 1 000.

```protobuf
message ListEntriesRequest {
  uint64 from_seq = 1;
  uint64 to_seq   = 2;
  uint64 cursor   = 3;
  uint32 limit    = 4;
}
message ListEntriesResponse {
  repeated Entry entries     = 1;
  uint64         next_cursor = 2;
}
```

---

### 6.4 Streaming RPC

#### `Watch`

Server-streaming RPC that pushes entries as they are appended. The stream stays open until the client cancels it.

- `from_seq = 0` — stream only entries appended after the watch is established (live-only).
- `from_seq > 0` — replay all entries with seq ≥ from_seq, then continue live with no gap.

```protobuf
message WatchRequest { uint64 from_seq = 1; }
// Response type: stream Entry (defined above)
```

If the subscriber falls more than 1 024 entries behind the broadcast buffer, the server closes the stream with `RESOURCE_EXHAUSTED` and the client should reconnect with the last received seq.

---

### 6.5 Proof and STH RPCs

#### `GetSth`

Retrieve a Signed Tree Head. `tree_size = 0` returns the latest.

```protobuf
message GetSthRequest  { uint64 tree_size = 1; }
message GetSthResponse { SignedTreeHead sth = 1; }

message SignedTreeHead {
  uint64 tree_size    = 1;
  bytes  root_hash    = 2;
  int64  timestamp_ns = 3;
  bytes  signature    = 4;   // Ed25519 over the signing payload
  bytes  public_key   = 5;
  uint32 key_version  = 6;
}
```

#### `InclusionProof`

Return an RFC 6962 inclusion proof for `seq` against `tree_size` (0 = latest STH).

```protobuf
message InclusionProofRequest  { uint64 seq = 1; uint64 tree_size = 2; }
message InclusionProofResponse {
  uint64 leaf_index    = 1;
  uint64 tree_size     = 2;
  repeated bytes proof = 3;   // O(log n) sibling hashes
  SignedTreeHead sth   = 4;
}
```

#### `ConsistencyProof`

Prove that `old_size` is a prefix of `new_size` (0 = latest STH). `old_size` must be > 0.

```protobuf
message ConsistencyProofRequest  { uint64 old_size = 1; uint64 new_size = 2; }
message ConsistencyProofResponse {
  uint64 old_size      = 1;
  uint64 new_size      = 2;
  repeated bytes proof = 3;
  SignedTreeHead old_sth = 4;
  SignedTreeHead new_sth = 5;
}
```

---

### 6.6 Pagination conventions

All paginated RPCs (`GetByKey`, `ListEntries`) use the same cursor pattern:

- First request: omit `cursor` (or set to 0) — starts from the beginning of the range.
- Subsequent requests: pass `next_cursor` from the previous response as `cursor`.
- End of results: `next_cursor = 0` in the response.

Since seqs are 0-based and monotonically increasing, `next_cursor = 0` is unambiguous — 0 is a valid seq, but the cursor always points to the *next* seq to read (i.e. last returned + 1), so 0 can only appear when the log is exhausted.

---

### 6.7 gRPC Reflection

The server registers the standard [gRPC server reflection](https://grpc.io/docs/guides/reflection/) service. `grpcurl` works without a local proto file:

```sh
grpcurl -plaintext localhost:50051 list settled.v1.SettledLog
grpcurl -plaintext -d '{"tree_size":0}' localhost:50051 settled.v1.SettledLog/GetSth
```

---

## 7. SDK Overview

Six first-party SDKs are published and kept in sync with the proto. Each ships a gRPC client and a standalone verifier that runs locally with no server contact.

| Language | Registry | Package |
|----------|----------|---------|
| TypeScript | npm | `@daltonr/settled-sdk` |
| Python | PyPI | `settled-sdk` |
| Go | pkg.go.dev | `github.com/richardadalton/settled/sdks/go` |
| Java | Maven Central | `io.github.richardadalton:settled-sdk` |
| Rust | crates.io | `settled-sdk` |
| .NET | NuGet | `Settled.Sdk` |

All six implement the full RPC surface: Append, BatchAppend, Get, GetLatest, GetByKey, ListEntries, Watch (streaming), GetSth, InclusionProof, ConsistencyProof.

See the `sdks/` directory and `docs/publishing/` for per-language publishing and usage details.

---

## 8. Security Model

### 8.1 What the Cryptography Guarantees

- **Inclusion** — an entry returned with a valid inclusion proof was committed to the log. A server cannot fabricate a valid proof for an entry it did not receive.
- **Append-only** — a valid consistency proof from STH₁ to STH₂ proves no entries before STH₁ were altered or removed. History cannot be silently rewritten.
- **Non-equivocation** — a server cannot show different trees to different clients without detection, provided at least one client publishes the signed tree heads it receives.

### 8.2 What the Cryptography Does Not Guarantee

- **Availability** — a server can refuse to serve entries or proofs.
- **Liveness** — a server can stop accepting new entries.
- **Complete independence from the server operator** — if the signing key is compromised, a server operator can sign fraudulent tree heads. Mitigated by publishing signed tree heads to an independent external verifier (settled-node).

### 8.3 Key Management

The Ed25519 signing key is generated at first startup and stored at `--key-path` (default `<data-dir>/signing.key`). Hot key rotation is supported via `POST /api/rotate-key` on the admin HTTP port; the old public key remains in the key store so old STHs remain verifiable. All signed tree heads embed `key_version` so verifiers select the correct public key automatically.

### 8.4 Authentication

The server enforces a shared API key when `--api-key` (or `$SETTLED_API_KEY`) is set. Clients must include `authorization: Bearer <key>` on every gRPC request. The gRPC reflection service is also protected by the same key when auth is enabled.

---

## 9. Deployment

See [`docs/deployment.md`](deployment.md) for the full deployment guide, including Docker, systemd, configuration flags, and admin HTTP endpoints.

The admin HTTP server (default `:8080`) exposes:

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness check |
| `GET /metrics` | Prometheus metrics |
| `GET /api/sth` | Current signed tree head |
| `GET /api/stats` | Entry count, tree size, last STH timestamp |
| `POST /api/sth/force` | Trigger immediate STH signing |
| `GET /api/keys` | All signing key records |
| `POST /api/rotate-key` | Rotate the active signing key |
