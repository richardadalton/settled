#!/usr/bin/env python3
"""
Generate canonical test vectors for settled-core.

This script is an independent implementation of the Merkle primitives in Python.
Its purpose is to provide a cross-language ground truth: the Rust settled-core
implementation must produce identical outputs for every vector in these files.

Uses only the Python standard library (hashlib, struct, json).

Ed25519 signed tree head vectors are generated separately by the Rust
`gen-sth-vectors` binary (cargo run --bin gen-sth-vectors), which writes
to test-vectors/signed-tree-heads.json.

Run from the repo root:
  python3 scripts/gen-test-vectors.py
"""

import hashlib
import json
import os
import struct
import sys


# ---------------------------------------------------------------------------
# Core hash primitives (wire-format.md §1)
# ---------------------------------------------------------------------------

def leaf_hash(data: bytes) -> bytes:
    """SHA-256(0x00 || data)"""
    h = hashlib.sha256()
    h.update(b'\x00')
    h.update(data)
    return h.digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left || right)"""
    assert len(left) == 32 and len(right) == 32
    h = hashlib.sha256()
    h.update(b'\x01')
    h.update(left)
    h.update(right)
    return h.digest()


# ---------------------------------------------------------------------------
# Merkle Tree Hash (wire-format.md §2)
# ---------------------------------------------------------------------------

def _k(n: int) -> int:
    """Largest power of 2 strictly less than n."""
    assert n > 1
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def mth(leaf_hashes: list) -> bytes:
    """RFC 6962 Merkle Tree Hash over pre-computed leaf hashes."""
    n = len(leaf_hashes)
    if n == 0:
        raise ValueError("MTH undefined for empty tree")
    if n == 1:
        return leaf_hashes[0]
    k = _k(n)
    return node_hash(mth(leaf_hashes[:k]), mth(leaf_hashes[k:]))


# ---------------------------------------------------------------------------
# Inclusion proof (wire-format.md §3)
# ---------------------------------------------------------------------------

def inclusion_proof_path(m: int, leaf_hashes: list) -> list:
    """RFC 6962 PATH(m, D[n]) — sibling hashes from leaf to root."""
    n = len(leaf_hashes)
    assert 0 <= m < n
    if n == 1:
        return []
    k = _k(n)
    if m < k:
        return inclusion_proof_path(m, leaf_hashes[:k]) + [mth(leaf_hashes[k:])]
    else:
        return inclusion_proof_path(m - k, leaf_hashes[k:]) + [mth(leaf_hashes[:k])]


def verify_inclusion(leaf_h: bytes, m: int, n: int, path: list, root: bytes) -> bool:
    """Verify an inclusion proof (wire-format.md §3.2)."""
    if n == 0 or m >= n:
        return False
    fn, sn, r = m, n - 1, leaf_h
    for step in path:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = node_hash(step, r)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, step)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ---------------------------------------------------------------------------
# Consistency proof (wire-format.md §4)
# ---------------------------------------------------------------------------

def _subproof(m: int, leaf_hashes: list, b: bool) -> list:
    n = len(leaf_hashes)
    if m == n:
        return [] if b else [mth(leaf_hashes)]
    k = _k(n)
    if m <= k:
        return _subproof(m, leaf_hashes[:k], b) + [mth(leaf_hashes[k:])]
    else:
        return _subproof(m - k, leaf_hashes[k:], False) + [mth(leaf_hashes[:k])]


def consistency_proof(old_size: int, leaf_hashes: list) -> list:
    """RFC 6962 PROOF(old_size, D[new_size])."""
    new_size = len(leaf_hashes)
    assert 0 < old_size <= new_size
    if old_size == new_size:
        return []
    return _subproof(old_size, leaf_hashes, True)


def verify_consistency(old_size: int, new_size: int, proof: list,
                       old_root: bytes, new_root: bytes) -> bool:
    """
    Verify a consistency proof (wire-format.md §4.2).

    Uses a recursive approach that mirrors SUBPROOF generation exactly,
    which makes correctness straightforward to reason about.
    """
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0 or old_size > new_size:
        return False

    proof_iter = iter(proof)

    def subproof(m, n, b):
        """
        Mirror of SUBPROOF(m, D[n], b).
        Returns (reconstructed_old_hash, reconstructed_new_hash).
        When b=True and m==n, returns (None, None) — the shared subtree
        hash equals old_root, substituted by the caller.
        Raises StopIteration if the proof is exhausted prematurely.
        """
        if m == n:
            if b:
                return None, None  # shared prefix; caller substitutes old_root
            else:
                h = next(proof_iter)
                return h, h
        k = _k(n)
        if m <= k:
            lo, ln = subproof(m, k, b)
            rh = next(proof_iter)
            if lo is None:
                # subproof(m, k, True) with m==k: subtree hash IS old_root
                return old_root, node_hash(old_root, rh)
            return lo, node_hash(ln, rh)
        else:
            ro, rn = subproof(m - k, n - k, False)
            lh = next(proof_iter)
            return node_hash(lh, ro), node_hash(lh, rn)

    try:
        computed_old, computed_new = subproof(old_size, new_size, True)
    except StopIteration:
        return False  # proof too short

    # Proof must be fully consumed
    if next(proof_iter, None) is not None:
        return False

    if computed_old is None:
        computed_old = old_root

    return computed_old == old_root and computed_new == new_root


# ---------------------------------------------------------------------------
# Standard leaf data used across all vector files
#
# 8 entries using human-readable UTF-8 strings so the vectors are legible.
# These same entries must be used by all SDK test suites.
# ---------------------------------------------------------------------------

ENTRY_DATA = [f"entry-{i}".encode() for i in range(8)]
LEAF_HASHES = [leaf_hash(d) for d in ENTRY_DATA]


# ---------------------------------------------------------------------------
# Vector generation
# ---------------------------------------------------------------------------

def gen_leaf_hash_vectors():
    cases = [
        (b"",          "empty input"),
        (b"\x00",      "single null byte"),
        (b"\xff",      "single 0xFF byte"),
        (b"hello",     "ASCII string"),
        (b"\x00" * 32, "32 null bytes"),
    ]
    vectors = [{"description": desc, "input_hex": data.hex(), "hash_hex": leaf_hash(data).hex()}
               for data, desc in cases]
    for i, (data, lh) in enumerate(zip(ENTRY_DATA, LEAF_HASHES)):
        vectors.append({"description": f"standard entry {i}",
                        "input_hex": data.hex(), "hash_hex": lh.hex()})
    return vectors


def gen_node_hash_vectors():
    vectors = []
    for i in range(4):
        left, right = LEAF_HASHES[i], LEAF_HASHES[i + 1]
        vectors.append({"description": f"node_hash(leaf[{i}], leaf[{i+1}])",
                        "left_hex": left.hex(), "right_hex": right.hex(),
                        "hash_hex": node_hash(left, right).hex()})
    a, b = LEAF_HASHES[0], LEAF_HASHES[1]
    vectors.append({
        "description": "non-commutativity: node_hash(a,b) != node_hash(b,a)",
        "left_hex": a.hex(), "right_hex": b.hex(),
        "hash_hex": node_hash(a, b).hex(),
        "swapped_hash_hex": node_hash(b, a).hex(),
        "note": "hash_hex and swapped_hash_hex MUST differ",
    })
    return vectors


def gen_tree_root_vectors():
    vectors = []
    for size in range(1, 9):
        lh = LEAF_HASHES[:size]
        vectors.append({"size": size,
                        "leaf_hashes_hex": [h.hex() for h in lh],
                        "root_hex": mth(lh).hex()})
    return vectors


def gen_inclusion_proof_vectors():
    vectors = []
    for size in range(1, 9):
        lh = LEAF_HASHES[:size]
        root = mth(lh)
        for idx in range(size):
            path = inclusion_proof_path(idx, lh)
            assert verify_inclusion(lh[idx], idx, size, path, root), \
                f"self-check failed: size={size} idx={idx}"
            vectors.append({
                "tree_size": size,
                "leaf_index": idx,
                "leaf_hash_hex": lh[idx].hex(),
                "proof_hex": [h.hex() for h in path],
                "root_hex": root.hex(),
            })
    return vectors


def gen_consistency_proof_vectors():
    pairs = [
        (1,1),(1,2),(1,3),(1,4),(1,8),
        (2,3),(2,4),(2,8),
        (3,4),(3,7),(3,8),
        (4,5),(4,7),(4,8),
        (6,7),(6,8),(7,8),(8,8),
    ]
    vectors = []
    for old_size, new_size in pairs:
        lh_old = LEAF_HASHES[:old_size]
        lh_new = LEAF_HASHES[:new_size]
        old_root = mth(lh_old)
        new_root = mth(lh_new)
        proof = consistency_proof(old_size, lh_new)
        assert verify_consistency(old_size, new_size, proof, old_root, new_root), \
            f"self-check failed: old={old_size} new={new_size}"
        vectors.append({
            "old_size": old_size,
            "new_size": new_size,
            "old_root_hex": old_root.hex(),
            "new_root_hex": new_root.hex(),
            "proof_hex": [h.hex() for h in proof],
        })
    return vectors


def gen_negative_vectors():
    """Vectors that MUST cause verification to return false."""
    size, idx = 4, 2
    lh = LEAF_HASHES[:size]
    root = mth(lh)
    path = inclusion_proof_path(idx, lh)

    def flip(b: bytes) -> bytes:
        return bytes([b[0] ^ 0xFF]) + b[1:]

    old_size = 2
    lh_old = LEAF_HASHES[:old_size]
    old_root = mth(lh_old)
    cons_proof = consistency_proof(old_size, lh)

    return {
        "inclusion_tampered_leaf": {
            "description": "Tampered leaf hash — verify_inclusion must return false",
            "leaf_hash_hex": flip(lh[idx]).hex(),
            "leaf_index": idx, "tree_size": size,
            "proof_hex": [h.hex() for h in path], "root_hex": root.hex(),
            "expected_result": False,
        },
        "inclusion_tampered_proof_element": {
            "description": "Tampered proof element — verify_inclusion must return false",
            "leaf_hash_hex": lh[idx].hex(),
            "leaf_index": idx, "tree_size": size,
            "proof_hex": [flip(path[0]).hex()] + [h.hex() for h in path[1:]],
            "root_hex": root.hex(),
            "expected_result": False,
        },
        "inclusion_tampered_root": {
            "description": "Tampered root — verify_inclusion must return false",
            "leaf_hash_hex": lh[idx].hex(),
            "leaf_index": idx, "tree_size": size,
            "proof_hex": [h.hex() for h in path], "root_hex": flip(root).hex(),
            "expected_result": False,
        },
        "inclusion_wrong_leaf_index": {
            "description": "Wrong leaf index — verify_inclusion must return false",
            "leaf_hash_hex": lh[idx].hex(),
            "leaf_index": idx + 1, "tree_size": size,
            "proof_hex": [h.hex() for h in path], "root_hex": root.hex(),
            "expected_result": False,
        },
        "consistency_tampered_proof_element": {
            "description": "Tampered consistency proof element — must return false",
            "old_size": old_size, "new_size": size,
            "old_root_hex": old_root.hex(), "new_root_hex": root.hex(),
            "proof_hex": [flip(cons_proof[0]).hex()] + [h.hex() for h in cons_proof[1:]],
            "expected_result": False,
        },
        "consistency_wrong_old_root": {
            "description": "Wrong old root — verify_consistency must return false",
            "old_size": old_size, "new_size": size,
            "old_root_hex": flip(old_root).hex(), "new_root_hex": root.hex(),
            "proof_hex": [h.hex() for h in cons_proof],
            "expected_result": False,
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(repo_root, "test-vectors")
    os.makedirs(out_dir, exist_ok=True)

    files = {
        "leaf-hashes.json":         gen_leaf_hash_vectors(),
        "node-hashes.json":         gen_node_hash_vectors(),
        "tree-roots.json":          gen_tree_root_vectors(),
        "inclusion-proofs.json":    gen_inclusion_proof_vectors(),
        "consistency-proofs.json":  gen_consistency_proof_vectors(),
        "negative-cases.json":      gen_negative_vectors(),
    }

    for filename, data in files.items():
        path = os.path.join(out_dir, filename)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        count = len(data) if isinstance(data, list) else len(data)
        print(f"  wrote {path} ({count} entries)")

    print("\n  note: test-vectors/signed-tree-heads.json is generated by the Rust")
    print("        `gen-sth-vectors` binary once the workspace is set up:")
    print("        cargo run --bin gen-sth-vectors")

    # Self-verify all positive and negative vectors
    print("\nSelf-verification:")
    errors = 0

    inclusion_data = files["inclusion-proofs.json"]
    for v in inclusion_data:
        lh = bytes.fromhex(v["leaf_hash_hex"])
        p = [bytes.fromhex(h) for h in v["proof_hex"]]
        r = bytes.fromhex(v["root_hex"])
        if not verify_inclusion(lh, v["leaf_index"], v["tree_size"], p, r):
            print(f"  FAIL inclusion size={v['tree_size']} idx={v['leaf_index']}")
            errors += 1
    print(f"  inclusion proofs:   {len(inclusion_data)} vectors, {errors} failures")

    cons_data = files["consistency-proofs.json"]
    cons_errors = 0
    for v in cons_data:
        p = [bytes.fromhex(h) for h in v["proof_hex"]]
        if not verify_consistency(v["old_size"], v["new_size"], p,
                                   bytes.fromhex(v["old_root_hex"]),
                                   bytes.fromhex(v["new_root_hex"])):
            print(f"  FAIL consistency old={v['old_size']} new={v['new_size']}")
            cons_errors += 1
    print(f"  consistency proofs: {len(cons_data)} vectors, {cons_errors} failures")

    neg_data = files["negative-cases.json"]
    neg_errors = 0
    for name, v in neg_data.items():
        p = [bytes.fromhex(h) for h in v["proof_hex"]]
        if "leaf_index" in v:
            result = verify_inclusion(bytes.fromhex(v["leaf_hash_hex"]),
                                      v["leaf_index"], v["tree_size"], p,
                                      bytes.fromhex(v["root_hex"]))
        else:
            result = verify_consistency(v["old_size"], v["new_size"], p,
                                        bytes.fromhex(v["old_root_hex"]),
                                        bytes.fromhex(v["new_root_hex"]))
        if result != v["expected_result"]:
            print(f"  FAIL negative '{name}': got {result}, expected {v['expected_result']}")
            neg_errors += 1
    print(f"  negative cases:     {len(neg_data)} vectors, {neg_errors} failures")

    total = errors + cons_errors + neg_errors
    if total:
        print(f"\n{total} failure(s) — vectors are incorrect.")
        sys.exit(1)
    else:
        print("\nAll self-checks passed.")


if __name__ == "__main__":
    main()
