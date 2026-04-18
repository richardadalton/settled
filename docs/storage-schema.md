# Settled — Storage Schema

**Status:** Authoritative  
**All storage layer implementations must conform exactly to this document.**

---

## 1. Overview

Settled uses RocksDB with five column families. Each CF has an independent key space and compaction policy.

| Column Family | Key | Value | Purpose |
|---------------|-----|-------|---------|
| `log`         | seq (u64 BE) | LogEntry (protobuf) | Immutable entry log |
| `tree`        | level\|\|index (u64 BE \|\| u64 BE) | hash (32 bytes) | Materialised Merkle nodes |
| `heads`       | tree_size (u64 BE) | SignedTreeHead (protobuf) | History of signed tree heads |
| `index`       | key (raw bytes) | seq (u64 BE) | User key → sequence lookup |
| `keys`        | version (u32 BE) | KeyRecord (protobuf) | Signing key history |

**Endianness:** All multi-byte integers in keys are **big-endian**. This ensures RocksDB's default byte-order comparator produces correct numeric ordering (range scans work correctly).

---

## 2. `log` Column Family

Stores the authoritative append-only entry log. Never modified after write.

### 2.1 Key

```
key = seq as u64, big-endian (8 bytes)
```

Sequence numbers start at 0 and increment by 1 for each entry. They are assigned atomically. There are no gaps in the sequence.

### 2.2 Value: `LogEntry` Protobuf

```protobuf
message LogEntry {
  uint64 seq          = 1;   // sequence number (redundant with key, included for self-description)
  int64  timestamp_ns = 2;   // Unix timestamp in nanoseconds, server clock at write time
  bytes  key          = 3;   // user-provided key, max 512 bytes
  bytes  data         = 4;   // user-provided payload, max 65536 bytes
  bytes  leaf_hash    = 5;   // SHA-256(0x00 || data), 32 bytes
}
```

`leaf_hash` is stored redundantly to avoid recomputing it during tree builds.

### 2.3 Write Behaviour

- Written once on `Append`. Never updated or deleted.
- Written to the WAL before the response is sent to the client (crash-safe).
- `fsync` is called after each write by default (`SETTLED_FSYNC=true`). Can be disabled for maximum throughput at the cost of losing the last few milliseconds of writes on a crash.

### 2.4 Scan Behaviour

The tree builder reads new entries by scanning from the last processed sequence number. Because keys are big-endian u64, `DB::iterator` with `seek(last_seq + 1)` iterates entries in order.

---

## 3. `tree` Column Family

Stores materialised Merkle tree nodes. Can be rebuilt entirely from the `log` CF.

### 3.1 Node Addressing

A node is identified by (level, index):

- **Level 0**: leaf nodes. `index` = sequence number of the leaf.
- **Level h** (h > 0): internal nodes. `index = i` covers the range of leaves `[i * 2^h, (i+1) * 2^h - 1]`.

Equivalently: node `(h, i)` is the Merkle hash of the subtree rooted at height `h` over leaves starting at position `i * 2^h`.

**A node `(h, i)` is "complete"** when all leaves in its range `[i * 2^h, (i+1) * 2^h - 1]` have been appended. Only complete nodes are written to the `tree` CF.

### 3.2 Key

```
key = level as u64, big-endian (8 bytes)
   || index as u64, big-endian (8 bytes)
total: 16 bytes
```

### 3.3 Value

```
value = SHA-256 hash, 32 bytes (raw, no length prefix)
```

### 3.4 Which Nodes to Write on Batch Update

When a batch of new leaves with indices `[N, N+1, ..., N+k-1]` is added to a tree that previously had `N` entries:

For each new leaf at index `j`:
1. Write `(0, j)` = `leaf_hash(entry_j.data)`.
2. For each level `h` from 1 upward: if `(j + 1)` is divisible by `2^h`, then `(h, j >> h)` is now complete. Compute it as `node_hash((h-1, 2*(j >> h)), (h-1, 2*(j >> h) + 1))` and write it.
3. Stop when `(j + 1)` is not divisible by `2^h`.

After processing all leaves in the batch, compute and store the "incomplete" frontier nodes needed to answer inclusion proof queries. These are the rightmost nodes that cannot be completed from the batch alone but are needed as sibling hashes in proofs.

### 3.5 Rebuild Procedure

To rebuild the `tree` CF from the `log` CF:

1. Delete all keys in the `tree` CF.
2. Read all `LogEntry` records from the `log` CF in sequence order.
3. Process them as a single batch using the procedure in §3.4.
4. The result must be bit-for-bit identical to the nodes that would have been written by the live write path.

This must be verified by a test (see implementation-plan.md Phase 3, Step 3.3).

---

## 4. `heads` Column Family

Stores the history of signed tree heads. One entry per tree update cycle (MMD interval or batch threshold).

### 4.1 Key

```
key = tree_size as u64, big-endian (8 bytes)
```

`tree_size` is the number of entries in the tree at the time the STH was signed. Keys are unique — one STH per tree size.

### 4.2 Value: `SignedTreeHead` Protobuf

```protobuf
message SignedTreeHead {
  uint64 tree_size  = 1;   // number of entries
  bytes  root_hash  = 2;   // 32-byte SHA-256 Merkle root
  int64  timestamp  = 3;   // Unix nanoseconds
  bytes  signature  = 4;   // 64-byte Ed25519 signature
  bytes  public_key = 5;   // 32-byte Ed25519 public key (raw)
  uint32 key_version = 6;  // version of the signing key (see keys CF)
}
```

### 4.3 Lookup Patterns

- **Latest STH**: `DB::iterator` seek to the maximum possible key (`0xFFFFFFFFFFFFFFFF`), then iterate backward by one step.
- **STH at exact size**: `DB::get(tree_size_as_u64_be)`.
- **STH at or before size**: seek to `tree_size_as_u64_be`, then step backward if exact match not found.

---

## 5. `index` Column Family

A secondary index from user-provided key bytes to the most recent sequence number for that key.

### 5.1 Key

```
key = raw bytes of the AppendRequest.key field
```

No length prefix, no encoding transformation. Maximum 512 bytes (enforced at the application layer before write).

### 5.2 Value

```
value = seq as u64, big-endian (8 bytes)
```

### 5.3 Write Behaviour

- Written atomically with the corresponding `log` CF write in the same RocksDB `WriteBatch`.
- On duplicate key: the new seq **overwrites** the old one (last-write-wins, per wire-format.md §7).
- The old entry at the previous seq remains in the `log` CF and is permanently retrievable by seq.

### 5.4 Atomicity Guarantee

The `log` CF write and the `index` CF write for the same entry are always in the same `WriteBatch`. They are either both committed or both absent. This ensures the index never points to a seq that doesn't exist in the log, and the log never has an entry without an index entry (for its key).

---

## 6. `keys` Column Family

Stores the history of Ed25519 signing keys.

### 6.1 Key

```
key = version as u32, big-endian (4 bytes)
```

Version starts at 1.

### 6.2 Value: `KeyRecord` Protobuf

```protobuf
message KeyRecord {
  uint32 version                   = 1;
  bytes  public_key                = 2;   // 32-byte Ed25519 public key (raw)
  bytes  private_key_encrypted     = 3;   // encrypted private key seed (32 bytes + auth tag)
  uint64 activated_at_tree_size    = 4;   // first STH signed with this key
  uint64 retired_at_tree_size      = 5;   // 0 = still active
  bytes  rotation_signature        = 6;   // Ed25519 sig by previous key over this KeyRecord's bytes (empty for key version 1)
}
```

The private key seed is encrypted at rest using AES-256-GCM with a key derived from the server's master secret (or KMS-managed key). The plaintext seed is never written to disk.

---

## 7. Column Family Configuration

### 7.1 Compaction

| CF | Compaction style | Notes |
|----|-----------------|-------|
| `log` | Level compaction | Sequential keys → minimal write amplification |
| `tree` | Level compaction | Mostly write-once, occasional rebuilds |
| `heads` | Level compaction | Small, sparse, rarely written |
| `index` | Level compaction | Random key space, frequent overwrites |
| `keys` | Level compaction | Tiny, almost never written |

### 7.2 Bloom Filters

Enable bloom filters on the `index` and `heads` CFs. Point lookups on these CFs benefit most from bloom filters. The `log` CF is accessed primarily by range scan (seq iteration) so bloom filters add overhead without benefit.

### 7.3 WAL

The WAL is shared across all CFs in the same RocksDB instance. Crash recovery replays the WAL and re-applies all writes since the last memtable flush. No explicit WAL management code is needed — RocksDB handles this automatically.

The `tree` CF is the only CF that can safely be rebuilt from scratch. If the `tree` CF is marked as "not WAL-synced" for performance, recovery must trigger a `rebuild_from_log` before the server accepts queries. In the default configuration, all CFs use the same WAL and no special recovery logic is needed.

---

## 8. Schema Version

A special key in the default column family (not a named CF):

```
key   = b"schema_version"
value = version as u32, big-endian (4 bytes)
```

Current schema version: **1**.

On open, the server checks this key. If absent, it writes `1` (fresh database). If present and greater than the server's supported version, the server refuses to start and logs an error. Future migrations increment this version.

---

## 9. Protobuf Encoding Notes

All protobuf values use the standard proto3 binary encoding. Field numbers are stable and must never be reused. No optional fields in the v1 schema — every field is present in every record.

The `leaf_hash` field in `LogEntry` (field 5) is always 32 bytes. The `root_hash` field in `SignedTreeHead` (field 2) is always 32 bytes. The `signature` field (field 4) is always 64 bytes. These sizes are invariants; any record violating them indicates data corruption.
