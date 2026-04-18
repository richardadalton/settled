"""
Pure-Python proof verifier for the Settled tamper-evident audit log.
Implements RFC 6962 Merkle tree verification and Ed25519 STH verification.
See docs/wire-format.md for the canonical spec.
"""
import hashlib
import struct
from typing import Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def leaf_hash(data: bytes) -> bytes:
    """SHA-256(0x00 || data)"""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left || right)"""
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion(
    leaf: bytes,
    leaf_index: int,
    tree_size: int,
    proof: list[bytes],
    root: bytes,
) -> bool:
    """Verify an RFC 6962 inclusion proof."""
    if tree_size == 0 or leaf_index >= tree_size:
        return False

    fn_ = leaf_index
    sn = tree_size - 1
    r = leaf

    for step in proof:
        if sn == 0:
            return False
        if (fn_ & 1) != 0 or fn_ == sn:
            r = node_hash(step, r)
            while fn_ != 0 and (fn_ & 1) == 0:
                fn_ >>= 1
                sn >>= 1
        else:
            r = node_hash(r, step)
        fn_ >>= 1
        sn >>= 1

    return sn == 0 and r == root


def _k(n: int) -> int:
    """Largest power of 2 strictly less than n. Requires n > 1."""
    p = 1
    while p * 2 < n:
        p <<= 1
    return p


def verify_consistency(
    old_size: int,
    new_size: int,
    proof: list[bytes],
    old_root: bytes,
    new_root: bytes,
) -> bool:
    """Verify an RFC 6962 consistency proof."""
    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root
    if old_size == 0 or old_size > new_size:
        return False

    it: Iterator[bytes] = iter(proof)
    consumed = [0]

    def _next() -> bytes | None:
        consumed[0] += 1
        return next(it, None)

    def _subproof(m: int, n: int, b: bool) -> tuple[bytes, bytes] | None:
        if m == n:
            if b:
                return (old_root, old_root)
            h = _next()
            if h is None:
                return None
            return (h, h)
        split = _k(n)
        if m <= split:
            sub = _subproof(m, split, b)
            if sub is None:
                return None
            lo, ln = sub
            rh = _next()
            if rh is None:
                return None
            return (lo, node_hash(ln, rh))
        else:
            sub = _subproof(m - split, n - split, False)
            if sub is None:
                return None
            ro, rn = sub
            lh = _next()
            if lh is None:
                return None
            return (node_hash(lh, ro), node_hash(lh, rn))

    result = _subproof(old_size, new_size, True)
    if result is None:
        return False
    computed_old, computed_new = result

    if next(it, None) is not None:
        return False

    return computed_old == old_root and computed_new == new_root


def signing_payload(tree_size: int, root_hash: bytes, timestamp_ns: int) -> bytes:
    """Canonical 48-byte signing payload. See wire-format.md §5.2."""
    return struct.pack(">Q", tree_size) + root_hash + struct.pack(">q", timestamp_ns)


def verify_tree_head(
    tree_size: int,
    root_hash: bytes,
    timestamp_ns: int,
    signature: bytes,
    public_key: bytes,
) -> bool:
    """Verify the Ed25519 signature on a Signed Tree Head."""
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        payload = signing_payload(tree_size, root_hash, timestamp_ns)
        key.verify(signature, payload)
        return True
    except (InvalidSignature, Exception):
        return False
