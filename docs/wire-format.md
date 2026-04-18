# Settled — Wire Format Specification

**Status:** Authoritative  
**All implementations must conform exactly to this document.**

---

## 1. Hash Constructions

All hash functions use SHA-256 (32-byte output). Domain separation prefixes follow RFC 6962 Section 2.1 exactly.

### 1.1 Leaf Hash

```
leaf_hash(data) = SHA-256(0x00 || data)
```

- `0x00` is a single byte domain separation prefix.
- `data` is the raw bytes of the submitted entry payload (not the key).
- An empty payload (`data = b""`) is valid and produces a defined hash.

### 1.2 Interior Node Hash

```
node_hash(left, right) = SHA-256(0x01 || left || right)
```

- `0x01` is a single byte domain separation prefix.
- `left` and `right` are each 32-byte SHA-256 hashes.
- The operation is **not commutative**: `node_hash(a, b) ≠ node_hash(b, a)`.

### 1.3 Why Domain Separation Matters

Without the 0x00/0x01 prefix, an interior node hash (64 bytes of input) could be confused with a leaf hash of a 64-byte payload. This is the second-preimage attack described in RFC 6962 Section 2.1. The prefixes eliminate it.

---

## 2. Merkle Tree Structure

The tree is a binary append-only Merkle tree as defined in RFC 6962. For a tree with `n` leaves:

```
MTH([]) = undefined (empty tree has no root)

MTH([d(0)]) = leaf_hash(d(0))

MTH(D[n]) where n > 1:
  k = largest power of 2 strictly less than n
  MTH(D[n]) = node_hash(MTH(D[0:k]), MTH(D[k:n]))
```

Where `D[a:b]` denotes the slice of leaf data from index `a` (inclusive) to `b` (exclusive).

`k` values for common tree sizes:

| n | k |
|---|---|
| 2 | 1 |
| 3 | 2 |
| 4 | 2 |
| 5 | 4 |
| 6 | 4 |
| 7 | 4 |
| 8 | 4 |
| 9 | 8 |

For sizes that are powers of 2, `k = n/2`.  
For other sizes, `k` is the largest power of 2 strictly less than `n`.

### 2.1 Tree Shape for Sizes 1–8

```
size=1:  h0

size=2:  node(h0, h1)

size=3:  node(node(h0, h1), h2)

size=4:  node(node(h0, h1), node(h2, h3))

size=5:  node(node(node(h0,h1),node(h2,h3)), h4)

size=6:  node(node(node(h0,h1),node(h2,h3)), node(h4,h5))

size=7:  node(node(node(h0,h1),node(h2,h3)), node(node(h4,h5),h6))

size=8:  node(node(node(h0,h1),node(h2,h3)), node(node(h4,h5),node(h6,h7)))
```

Where `hi = leaf_hash(entry_i_data)`.

---

## 3. Inclusion Proof

An inclusion proof for leaf at index `m` in a tree of size `n` is a list of sibling hashes from leaf to root. The verifier can recompute the root from the leaf hash and this path, then compare against the signed tree head.

### 3.1 Generation (RFC 6962 Section 2.1.1)

```
PATH(m, D[n]):
  if n == 1: return []
  k = largest power of 2 strictly less than n
  if m < k:
    return PATH(m, D[0:k]) + [MTH(D[k:n])]
  else:
    return PATH(m - k, D[k:n]) + [MTH(D[0:k])]
```

### 3.2 Verification

```
verify_inclusion(leaf_hash, m, n, path, root):
  fn = m
  sn = n - 1
  r  = leaf_hash

  for each step in path:
    if sn == 0: return false          // proof too long
    if fn is odd OR fn == sn:
      r  = node_hash(step, r)
      while fn != 0 AND fn is even:
        fn = fn >> 1
        sn = sn >> 1
    else:
      r  = node_hash(r, step)
    fn = fn >> 1
    sn = sn >> 1

  return sn == 0 AND r == root
```

---

## 4. Consistency Proof

A consistency proof from tree size `m` to tree size `n` proves that the first `m` entries of the size-`n` tree are identical to the size-`m` tree. A client holding `STH(m)` can verify a new `STH(n)` without having seen any intermediate entries.

### 4.1 Generation (RFC 6962 Section 2.1.2)

```
PROOF(m, D[n]):
  if m == n: return []
  return SUBPROOF(m, D[n], true)

SUBPROOF(m, D[n], b):
  n = len(D)
  if m == n:
    if b:    return []
    else:    return [MTH(D)]
  k = largest power of 2 strictly less than n
  if m <= k:
    return SUBPROOF(m, D[0:k], b) + [MTH(D[k:n])]
  else:
    return SUBPROOF(m - k, D[k:n], false) + [MTH(D[0:k])]
```

### 4.2 Verification

```
verify_consistency(m, n, proof, old_root, new_root):
  if m == n AND proof is empty:
    return old_root == new_root

  fn = m - 1
  sn = n - 1
  if fn has a set bit:               // m is not a power of 2
    while fn is even:
      fn = fn >> 1
      sn = sn >> 1
    fr = proof[0]
    sr = proof[0]
    proof = proof[1:]
  else:
    fr = old_root
    sr = old_root

  for each step in proof:
    if sn == 0: return false
    if fn is odd OR fn == sn:
      fr = node_hash(step, fr)
      sr = node_hash(step, sr)
      while fn != 0 AND fn is even:
        fn = fn >> 1
        sn = sn >> 1
    else if fn is even:
      sr = node_hash(sr, step)
    else:
      return false
    fn = fn >> 1
    sn = sn >> 1

  return sn == 0 AND fr == old_root AND sr == new_root
```

---

## 5. Signed Tree Head

### 5.1 Structure

```
SignedTreeHead {
  tree_size:  uint64        // number of entries in the tree
  root_hash:  bytes[32]     // SHA-256 Merkle root
  timestamp:  int64         // Unix nanoseconds, server clock
  signature:  bytes[64]     // Ed25519 signature over the canonical payload
  public_key: bytes[32]     // Ed25519 public key (raw, 32 bytes)
}
```

### 5.2 Canonical Signing Payload

The bytes signed by Ed25519 are the concatenation of:

```
signing_payload =
  tree_size  as u64, big-endian (8 bytes)  ||
  root_hash  as bytes[32]                  ||
  timestamp  as i64, big-endian (8 bytes)
```

Total: **48 bytes**.

No padding, no length prefixes, no version byte. The fields are concatenated in this exact order.

**All implementations must produce identical signing_payload bytes for the same inputs.** Any deviation means cross-SDK signature verification will fail.

### 5.3 Signing Algorithm

Ed25519 as defined in RFC 8032. Library: `ed25519-dalek` (Rust), `cryptography.hazmat.primitives.asymmetric.ed25519` (Python), `golang.org/x/crypto/ed25519` (Go), `java.security.Signature` with `Ed25519` (Java).

Ed25519 signs the message directly (no pre-hashing). The `signing_payload` above is the message.

### 5.4 Key Encoding

- **Private key**: 32 raw bytes (the seed, not the expanded key).
- **Public key**: 32 raw bytes (compressed Edwards curve point).

Keys are stored in RocksDB and transmitted in the `public_key` field of `SignedTreeHead` as raw bytes. No ASN.1, no PEM, no JWK in the hot path.

For human-readable contexts (configuration files, admin API responses), keys are encoded as `base64url` without padding.

---

## 6. Key Versioning (Minimal v1 Scheme)

Each signing key has an associated version number (u32, starting at 1). When verifying a historical `SignedTreeHead`, the verifier must use the key version that was active when that STH was produced.

### 6.1 Key Record

```
KeyRecord {
  version:    uint32
  public_key: bytes[32]
  activated_at_tree_size: uint64    // first STH signed with this key
  retired_at_tree_size:   uint64    // 0 = still active
}
```

### 6.2 Key Rotation Procedure

1. Generate a new Ed25519 key pair.
2. Write a `KeyRecord` to the `keys` column family with the current `tree_size` as `activated_at_tree_size`.
3. Update the old key's `retired_at_tree_size`.
4. Include the new `public_key` in all subsequent `SignedTreeHead` messages.
5. Publish a signed rotation announcement (signed with the **old** key) containing the new public key. This creates an auditable chain.

### 6.3 Verifying Across a Key Rotation

A verifier with a cached old STH and key version V:
- Fetches the key history from the server (or a trusted external archive).
- Identifies which key signed the STH being verified (by checking `activated_at` and `retired_at` ranges against the STH's `tree_size`).
- Verifies the signature with that key.

This is a v1 minimum. A full certificate-chain approach with cross-signatures is a v2 feature.

---

## 7. Duplicate Key Semantics

The `index` column family maps a user-provided key to a sequence number. When the same key is appended more than once:

- **Semantics: last-write-wins.** The index stores the sequence number of the most recent append for that key.
- The earlier entry is not deleted or modified — it remains in the `log` CF at its original sequence number and is fully provable.
- The index is a **convenience lookup**, not the canonical identifier. The sequence number is the canonical identifier.

Rationale: O(1) lookup, simple schema, consistent with the use case of "find the latest state of this entity." Clients that need all versions of a key must scan the log CF directly (or maintain their own secondary index).

---

## 8. AppendResponse Leaf Hash

The `leaf_hash` returned in `AppendResponse` is:

```
leaf_hash = SHA-256(0x00 || data)
```

Where `data` is the raw bytes of the `AppendRequest.data` field. The `key` field is **not** included in the leaf hash. The key is stored in the `LogEntry` for index lookups but does not affect the Merkle commitment.

This means two entries with the same `data` but different `key` values produce the same `leaf_hash`. This is intentional and correct — the Merkle tree commits to the data content, not the key. The sequence number disambiguates entries with identical content.
