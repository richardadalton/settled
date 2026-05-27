# Settled — Tamper-Evident Audit Log

**Status:** Proposed  
**Author:** POP Project

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

### 6.1 gRPC (Primary)

Protocol Buffers definition (simplified):

```protobuf
syntax = "proto3";
package settled.v1;

service SettledLog {
  // Single-entry append
  rpc Append(AppendRequest) returns (AppendResponse);

  // High-throughput streaming append — client streams requests,
  // server streams acknowledgments. Pipelining without round-trips.
  rpc AppendStream(stream AppendRequest) returns (stream AppendResponse);

  // Retrieve an entry with its inclusion proof
  rpc Get(GetRequest) returns (GetResponse);

  // Get an inclusion proof for a known sequence number
  rpc GetInclusionProof(InclusionProofRequest) returns (InclusionProof);

  // Prove tree(first) is a prefix of tree(second)
  rpc GetConsistencyProof(ConsistencyProofRequest) returns (ConsistencyProof);

  // Latest signed tree head
  rpc GetSignedTreeHead(GetSTHRequest) returns (SignedTreeHead);

  // Stream of signed tree heads as they are produced
  rpc StreamTreeHeads(StreamSTHRequest) returns (stream SignedTreeHead);
}

message AppendRequest {
  string key   = 1;   // application-defined key (max 512 bytes)
  bytes  data  = 2;   // payload to commit (max 64KB)
}

message AppendResponse {
  uint64 seq            = 1;   // assigned sequence number
  int64  timestamp_ns   = 2;   // server-assigned nanosecond timestamp
  bytes  leaf_hash      = 3;   // SHA-256(0x00 || data)
  // proof available after next tree update (within MMD)
}

message InclusionProof {
  uint64         leaf_index = 1;
  uint64         tree_size  = 2;
  bytes          leaf_hash  = 3;
  repeated bytes path       = 4;   // sibling hashes, leaf → root
  SignedTreeHead head        = 5;
}

message ConsistencyProof {
  uint64         first_size  = 1;
  uint64         second_size = 2;
  repeated bytes proof       = 3;
  SignedTreeHead head         = 4;
}

message SignedTreeHead {
  uint64 tree_size  = 1;
  bytes  root_hash  = 2;
  int64  timestamp  = 3;
  bytes  signature  = 4;
  bytes  public_key = 5;
}
```

gRPC is the primary protocol. Generated stubs provide type-safe clients in every supported language with no hand-written serialisation code.

### 6.2 REST + JSON (Secondary)

A thin REST layer (served on a separate port, default 8080) for environments where gRPC is awkward (browser, serverless, simple scripts):

```
POST   /v1/append                  → AppendResponse
GET    /v1/entries/:seq            → GetResponse
GET    /v1/proof/inclusion/:seq    → InclusionProof
GET    /v1/proof/consistency/:a/:b → ConsistencyProof
GET    /v1/sth                     → SignedTreeHead (latest)
GET    /v1/sth/:tree_size          → SignedTreeHead (historical)
GET    /v1/sth/stream              → SSE stream of SignedTreeHeads
```

The REST layer is implemented via `grpc-gateway` or a thin Axum handler — it adds minimal overhead and shares all business logic with the gRPC path.

---

## 7. SDK Design

### 7.1 Generated vs Handwritten

The gRPC stub layer is fully generated from the proto file. The SDK wraps the generated stub with:
- Connection management and reconnection
- Streaming append with configurable batch size and flush interval
- Client-side proof verification (critical — this must run locally, never on the server)
- Signed tree head caching and staleness detection

### 7.2 TypeScript SDK

```typescript
import { SettledClient } from '@daltonr/settled-sdk';

const client = new SettledClient({
  url: 'grpc://localhost:9000',
  // For mutual TLS in production:
  // tls: { cert, key, ca }
});

// Single append — returns proof handle
const receipt = await client.append('trade-001', sha256(record));
// receipt.seq, receipt.timestamp, receipt.leafHash

// Wait for proof to be available (within MMD)
const proof = await receipt.awaitProof();

// Verify locally — no server contact, pure crypto
const valid = client.verify(sha256(record), proof);

// High-throughput streaming append
const stream = client.appendStream({ 
  batchSize: 1000, 
  flushIntervalMs: 50 
});
stream.write('trade-002', sha256(record2));
stream.write('trade-003', sha256(record3));
const receipts = await stream.flush();

// Consistency check — prove nothing was rewritten since last audit
const consistent = await client.verifyConsistency(
  savedTreeHead,       // what you had last time
  await client.getSignedTreeHead()   // current
);
```

The `verify` and `verifyConsistency` methods are pure functions over `crypto.subtle` — they make no network calls and cannot be subverted by a compromised server.

### 7.3 SDK Languages and Delivery

| Language | Delivery | Generator |
|----------|----------|-----------|
| TypeScript/Node.js | `@settled/client` on npm | `ts-proto` + handwritten verify layer |
| Python | `settled-client` on PyPI | `grpcio-tools` + handwritten verify layer |
| Go | `github.com/settled/settled-go` | `protoc-gen-go` + handwritten verify layer |
| Java/Kotlin | Maven Central | `protoc-gen-grpc-java` + verify layer |
| Rust | `settled-client` on crates.io | `tonic-build` — shares core lib directly |
| .NET | NuGet | `Grpc.Tools` + verify layer |

The proof verification logic — the Merkle path computation — is implemented once in Rust as a `settled-core` crate, then exposed to other languages via:
- Native bindings (Node.js via `napi-rs`, Python via `PyO3`)
- Or re-implemented in idiomatic language code following the same test vectors

Test vectors are published in the repo. Any SDK implementation must pass all vectors before release.

### 7.4 WASM Build

`settled-core` (the Merkle verification library) compiles to WebAssembly. This enables:
- **Browser-side proof verification** — a web app can verify a proof against a stored signed tree head without any server call
- **Edge function verification** (Cloudflare Workers, Deno Deploy)
- **Embedded use cases** where native binaries are unavailable

No existing tamper-evident log product supports browser-native proof verification. This is a meaningful differentiator.

---

## 8. Throughput Design

### 8.1 Why Previous Approaches Failed

Immudb 1.1.0 with the Node.js SDK gave us ~6K records/sec. The bottlenecks were:

1. **`setAll` transaction latency ~250ms** — each call is a full Immudb transaction, synchronously committed before returning
2. **drain-before-commit constraint** — Kafka offsets would not advance until all writes flushed, so evaluation throughput was capped by write throughput
3. **No pipelining** — one outstanding write at a time per batch

Settled eliminates all three:

1. Write acknowledgment comes after WAL write (~50 microseconds), not after tree update
2. The Kafka consumer can commit offsets after WAL acknowledgment; tree proof availability follows within the MMD
3. The streaming gRPC endpoint pipelines thousands of writes concurrently

### 8.2 Throughput Model

Single Settled node, NVMe SSD, 8-core server:

| Component | Throughput | Notes |
|-----------|-----------|-------|
| gRPC receive | ~2M req/sec | Tonic benchmark |
| WAL write | ~800K/sec | Sequential RocksDB writes |
| Tree update | ~10M leaves/sec | SHA-256 AVX2, batched |
| Ed25519 sign | ~70K/sec | Once per MMD, not per entry |
| gRPC respond | ~2M/sec | |
| **Net sustained** | **~500K entries/sec** | WAL is the bottleneck |

For the full\_system example (35K/sec generator): a single Settled node at less than 10% capacity.

### 8.3 Horizontal Scaling

For throughputs beyond a single node, Settled partitions by key prefix. A consistent-hash ring of N nodes each handles 1/N of the key space. Clients use a thin routing layer (or the SDK handles it transparently). Each partition maintains its own Merkle tree; cross-partition consistency proofs use a root-of-roots structure.

This is a v2 feature. At 500K/sec per node, most use cases never need it.

### 8.4 Durability vs Throughput Knob

For applications where throughput matters more than strict per-entry durability:

```typescript
const client = new SettledClient({
  url: 'grpc://localhost:9000',
  durability: 'wal',        // default: durable after WAL write
  // durability: 'memory',  // fastest: ack after memory write, periodic WAL flush
  // durability: 'proof',   // strictest: ack only after proof available
});
```

The `wal` default gives the right balance for compliance use cases: entries survive crashes, proofs follow within the MMD. The `proof` mode is equivalent to Immudb's drain-before-commit and has the same throughput characteristics — it exists for applications that need it but is not the default.

---

## 9. Security Model

### 9.1 What the Cryptography Guarantees

- **Inclusion** — an entry returned with a valid inclusion proof was committed to the log. A server cannot fabricate a valid proof for an entry it did not receive.
- **Append-only** — a valid consistency proof from STH₁ to STH₂ proves no entries before STH₁ were altered or removed. History cannot be silently rewritten.
- **Non-equivocation** — a server cannot show different trees to different clients without detection, as long as at least one client publishes the signed tree heads it receives.

### 9.2 What the Cryptography Does Not Guarantee

- **Availability** — a server can refuse to serve entries or proofs. Settled does not prevent denial of service.
- **Liveness** — a server can stop accepting new entries.
- **Complete independence from the server operator** — if the signing key is compromised, a server operator can sign fraudulent tree heads. Mitigated by publishing signed tree heads to an independent verifier service.

### 9.3 Key Management

The Ed25519 signing key is generated at first startup and stored in RocksDB. For production deployments it should be stored in a hardware security module (HSM) or cloud KMS (AWS KMS, GCP Cloud HSM). The server supports a `--kms-provider` flag for pluggable key backends.

The public key is included in every signed tree head. Clients that cache old signed tree heads can verify new ones without contacting a key server.

### 9.4 TLS

All gRPC connections are TLS by default. Mutual TLS is supported for environments that require client certificate authentication. The Docker image ships with a self-signed cert for development; production deployments should provide their own.

### 9.5 Authentication and Authorisation

Settled does not implement application-level auth. It delegates to:
- **mTLS** for transport-level identity
- **A sidecar proxy** (Envoy, Nginx) for API key or JWT validation

This keeps the server simple and correct. Auth is a solved problem; tamper-evident logs are not.

---

## 10. Deployment

### 10.1 Single Container (Default)

```yaml
services:
  settled:
    image: settled/settled:latest
    ports:
      - "9000:9000"   # gRPC
      - "8080:8080"   # REST + SSE
    volumes:
      - settled_data:/data
    environment:
      SETTLED_DATA_DIR: /data
      SETTLED_MMD_MS: 100
      SETTLED_MAX_ENTRY_BYTES: 65536
      SETTLED_LOG_LEVEL: info
    healthcheck:
      test: ["CMD", "settled-ctl", "status"]
      interval: 10s

volumes:
  settled_data:
```

No external dependencies. One container, one volume. The RocksDB data directory is the entire state of the system.

### 10.2 External Verifiers — Making Recreation Impossible

This is the feature that completes the security model. Without it, an attacker with full server access can delete the database, reconstruct it with falsified records, and produce new signed tree heads. With external verifiers, they cannot — because the root hash is a deterministic function of the data, not of the signing key.

**The mechanism:**

When the server produces `STH(N)` with `root_hash=X` and pushes it to registered external verifiers, those settledes hold cryptographic proof of what the log contained at that point. If the database is ever deleted and reconstructed with different data, the new `STH(N)` will have `root_hash=Y ≠ X`. Any registered settled can detect this immediately by comparing what they received against what the server now claims.

The signing key does not help the attacker. They can sign the fraudulent tree head with the original key, but `root_hash` is determined by the data. The signature proves authorship; the root hash proves content. Only the content check matters for detecting reconstruction.

**Registered settledes:**

Each external verifier is registered with the server via the admin API:

```
POST /v1/admin/settledes
{
  "name":        "Compliance Officer",
  "url":         "https://compliance.example.com/settled-inbox",
  "public_key":  "ed25519:<base64>",   // settled's own Ed25519 public key
  "push_interval_ms": 5000
}
```

The server maintains a verifier registry in RocksDB. On each STH publication cycle, it pushes the signed tree head to every registered settled URL. The push is authenticated — the server signs the push payload with its own key; the verifier verifies before archiving.

The `public_key` in the registration is the verifier's own key, used for the optional **counter-signature** feature described below.

**What a verifier receives:**

```json
{
  "sth": {
    "tree_size":  1000000,
    "root_hash":  "sha256:<base64>",
    "timestamp":  1713362400000000000,
    "signature":  "ed25519:<base64>",
    "public_key": "ed25519:<base64>"
  },
  "server_id":   "settled-prod-01.example.com",
  "push_seq":    4721
}
```

The settled archives this. That is the entire settled responsibility — receive and store.

**Verification by a verifier:**

At any point in the future, a verifier can check whether the log is consistent with what they received:

```
GET /v1/proof/consistency/{their_tree_size}/{current_tree_size}
```

This returns a consistency proof. The settled verifies it locally against their archived root hash. If it fails — or if the server cannot produce a proof at all — the log has been tampered with or reconstructed.

This check requires no trust in the server. It is pure Merkle verification against the verifier's own archived data.

**The settled CLI:**

The TypeScript SDK ships a `settled-check` CLI:

```bash
# Check consistency between archived STH and current server state
settled-check verify \
  --server grpc://settled.example.com:9000 \
  --sth ./archived-sth-2026-04-17.json

# Output:
# ✓ Consistent. Log grew from 1,000,000 to 4,721,088 entries.
#   No entries have been removed or altered.

# Or on failure:
# ✗ INCONSISTENT. Server cannot prove consistency from tree_size=1,000,000.
#   The log may have been reconstructed after 2026-04-17T14:00:00Z.
```

**Threshold counter-signatures (optional, maximum security):**

For the highest security tier, configure N registered verifiers to counter-sign each tree head. The server collects M-of-N counter-signatures before publishing the STH as final:

```yaml
environment:
  SETTLED_THRESHOLD_M: 2
  SETTLED_THRESHOLD_N: 3
```

With threshold signing:
- A tree head is only considered final when M settledes have independently signed it
- An attacker who controls the server but not the verifier keys cannot produce a valid final STH for falsified data
- The signing key compromise is no longer sufficient — the attacker must also compromise M independent settled key holders

The counter-signature protocol:

```
1. Server produces candidate STH
2. Server pushes candidate to all N settledes
3. Each settled verifies the candidate is consistent with their archived STHs
4. Each settled that accepts returns a counter-signature (Ed25519 over the STH bytes)
5. Server collects M signatures, bundles them into the FinalSTH
6. FinalSTH is published and accepted by clients

FinalSTH {
  sth:                  SignedTreeHead
  counter_signatures:   [{ settled_id, signature, public_key }, ...]   // M of them
}
```

Clients configured with threshold verification reject any STH that does not carry M valid counter-signatures from registered verifiers. A server operator acting alone cannot forge a FinalSTH — they need M colluding settledes.

**Deployment example with three settledes:**

```yaml
services:
  settled-server:
    image: settled/settled:latest
    environment:
      SETTLED_THRESHOLD_M: 2
      SETTLED_THRESHOLD_N: 3
      SETTLED_PUSH_INTERVAL_MS: 5000

  # Each runs in an independent trust domain — different org, different cloud, different team
  settled-a:
    image: settled/settled-node:latest
    environment:
      SETTLED_ROLE: external
      SETTLED_ARCHIVE_DIR: /archive-a
    volumes:
      - settled_archive_a:/archive-a

  settled-b:
    image: settled/settled-node:latest
    environment:
      SETTLED_ROLE: external
      SETTLED_ARCHIVE_DIR: /archive-b
    volumes:
      - settled_archive_b:/archive-b

  settled-c:
    image: settled/settled-node:latest
    environment:
      SETTLED_ROLE: external
      SETTLED_ARCHIVE_DIR: /archive-c
    volumes:
      - settled_archive_c:/archive-c
```

In a real deployment, settledes A, B, and C would run in completely separate environments — different cloud accounts, different organisations, different geographies. The security guarantee scales with the independence of the verifieres.

### 10.3 Backup and Recovery

The entire log is in the RocksDB data directory. Backup is a filesystem snapshot or `rocksdb::BackupEngine` call. Recovery from backup restores all entries and the full Merkle tree history. The tree can also be fully recomputed from just the `log` column family if the `tree` column family is corrupted.

---

## 11. Relation to POP

Settled is a standalone product with no dependency on POP. Any application can use it.

Within the POP ecosystem, it replaces `ImmudbWriter` as the tamper-proof audit backend. The `AuditEntry` produced by every POP program maps cleanly to a Settled entry:

```typescript
const receipt = await settled.append(
  entry.entryId,
  sha256(JSON.stringify(entry))
);
```

The `PROGRAM_HASH` and `pluginHash` from POP's provenance model can be stored as entry metadata, enabling queries like "show me all decisions made by policy version X" via the `index` column family.

`verify.ts` becomes: fetch entry from Postgres, fetch proof from Settled, verify locally. The verification is pure crypto — no server trust.

---

## 12. Build Milestones

### M1 — Core Rust library (2 days)
- Binary Merkle tree: append, inclusion proof, consistency proof
- Ed25519 sign and verify
- SHA-256 leaf and node hashing per RFC 6962
- Full test suite with RFC 6962 test vectors
- WASM build target

### M2 — Server (2 days)
- RocksDB storage: log, tree, heads, index column families
- WAL append with fsync
- Background tree builder with configurable MMD
- gRPC server (tonic): Append, Get, GetInclusionProof, GetConsistencyProof, GetSignedTreeHead
- AppendStream for high-throughput pipelined clients

### M3 — REST layer and Docker (1 day)
- Axum HTTP handler for all gRPC endpoints
- SSE stream for tree heads
- Docker image with health check and graceful shutdown
- docker-compose example

### M4 — TypeScript SDK (1 day)
- Generated gRPC stubs via ts-proto
- SettledClient with connection management
- Client-side proof verification (calls WASM core or reimplements in TS)
- appendStream with batching and back-pressure
- Full test suite against live server

### M5 — Additional SDKs (2 days)
- Python: grpcio-tools generated + PyO3 bindings to Rust verify
- Go: protoc-gen-go + native Go verify implementation
- Java: protoc-gen-grpc-java + verify
- Test vectors shared across all SDKs

### M6 — External settled protocol (1 day)
- Settled registry: register/list/remove endpoints via admin API
- STH push loop: push to all registered verifiers on each MMD cycle
- Settled-side archive service: receive and store STHs
- `settled-check` CLI: verify consistency against archived STH
- Threshold counter-signature protocol (M-of-N)
- `settled-node` Docker image for running an independent settled

### M7 — Replace ImmudbWriter in full_system (half day)
- SettledWriter implementing the same enqueue/drain interface
- verify.ts updated to use SettledClient
- Immudb container removed from docker-compose

### M8 — Performance validation (1 day)
- Benchmark: sustained throughput (target 500K/sec)
- Benchmark: write latency p50/p99 under load
- Benchmark: proof generation throughput
- Grafana dashboard for Settled metrics

**Total: ~10 days for a genuinely production-grade v1 with multi-language SDKs.**

---

## 13. Open Questions

1. **Key rotation** — how does a client verify proofs against historical signed tree heads when the signing key has been rotated? Needs a key history log or certificate chain approach.

2. **Entry size limit** — 64KB default. Should large payloads be stored by hash reference only (store the hash in Settled, store the payload elsewhere)?

3. **Retention** — the log is append-only and grows forever. Settled does not support deletion. Archival to cold storage (S3 Glacier) with proof-of-archive needs specifying.

4. **Multi-tenancy** — should a single Settled instance serve multiple isolated logs (different signing keys, different trees)? Useful for SaaS deployments. Implemented as named log instances.

5. **Sequencing guarantees** — currently best-effort ordering within the MMD window. Applications that require strict causal ordering need a sequencing protocol (Raft/Paxos). Out of scope for v1.
