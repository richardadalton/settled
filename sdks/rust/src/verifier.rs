use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Returns SHA-256(0x00 || data). See docs/wire-format.md §3.
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update([0x00u8])
        .chain_update(data)
        .finalize()
        .into()
}

/// Returns SHA-256(0x01 || left || right). See docs/wire-format.md §3.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update([0x01u8])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// Largest power of 2 strictly less than n. Requires n > 1.
fn split(n: u64) -> u64 {
    let mut p = 1u64;
    while p * 2 < n {
        p <<= 1;
    }
    p
}

/// Verifies an RFC 6962 inclusion proof.
/// Returns true iff `leaf` at `leaf_index` in a tree of `tree_size` with
/// the given proof hashes produces `root`.
pub fn verify_inclusion(
    leaf: [u8; 32],
    leaf_index: u64,
    tree_size: u64,
    proof: &[[u8; 32]],
    root: [u8; 32],
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }

    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = leaf;

    for step in proof {
        if sn == 0 {
            return false;
        }
        if (fn_ & 1) != 0 || fn_ == sn {
            r = node_hash(step, &r);
            while fn_ != 0 && (fn_ & 1) == 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, step);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    sn == 0 && r == root
}

/// Verifies an RFC 6962 consistency proof.
/// Returns true iff the tree of `old_size` with root `old_root` is a prefix
/// of the tree of `new_size` with root `new_root`.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    proof: &[[u8; 32]],
    old_root: [u8; 32],
    new_root: [u8; 32],
) -> bool {
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if old_size == 0 || old_size > new_size {
        return false;
    }

    let mut idx = 0usize;
    let result = {
        let mut next = || -> Option<[u8; 32]> {
            if idx >= proof.len() {
                return None;
            }
            let h = proof[idx];
            idx += 1;
            Some(h)
        };
        verify_subproof(old_size, new_size, old_root, &mut next, true)
    };

    match result {
        Some((computed_old, computed_new)) => {
            idx == proof.len() && computed_old == old_root && computed_new == new_root
        }
        None => false,
    }
}

fn verify_subproof(
    m: u64,
    n: u64,
    old_root: [u8; 32],
    next: &mut dyn FnMut() -> Option<[u8; 32]>,
    b: bool,
) -> Option<([u8; 32], [u8; 32])> {
    if m == n {
        if b {
            return Some((old_root, old_root));
        }
        let h = next()?;
        return Some((h, h));
    }
    let sp = split(n);
    if m <= sp {
        let (lo, ln) = verify_subproof(m, sp, old_root, next, b)?;
        let rh = next()?;
        Some((lo, node_hash(&ln, &rh)))
    } else {
        let (ro, rn) = verify_subproof(m - sp, n - sp, old_root, next, false)?;
        let lh = next()?;
        Some((node_hash(&lh, &ro), node_hash(&lh, &rn)))
    }
}

/// Returns the canonical 48-byte signing payload for a Signed Tree Head.
/// Layout: tree_size (u64 BE, 8 bytes) || root_hash (32 bytes) || timestamp_ns (i64 BE, 8 bytes).
/// See docs/wire-format.md §5.2.
pub fn signing_payload(tree_size: u64, root_hash: [u8; 32], timestamp_ns: i64) -> [u8; 48] {
    let mut buf = [0u8; 48];
    buf[0..8].copy_from_slice(&tree_size.to_be_bytes());
    buf[8..40].copy_from_slice(&root_hash);
    buf[40..48].copy_from_slice(&timestamp_ns.to_be_bytes());
    buf
}

/// A key chain record returned by `GET /api/keys`.
pub struct KeyRecord {
    pub version: u32,
    pub public_key: [u8; 32],
    pub activated_at_tree_size: u64,
}

/// Verifies an STH against a key chain. Finds the record whose `version` matches
/// `key_version` and verifies the signature with that record's public key.
pub fn verify_tree_head_with_chain(
    tree_size: u64,
    root_hash: [u8; 32],
    timestamp_ns: i64,
    signature: &[u8],
    key_version: u32,
    chain: &[KeyRecord],
) -> bool {
    let Some(record) = chain.iter().find(|r| r.version == key_version) else {
        return false;
    };
    verify_tree_head(tree_size, root_hash, timestamp_ns, signature, &record.public_key)
}

/// Verifies an STH and enforces that its timestamp is strictly later than
/// `previous_timestamp_ns`. Returns false if `timestamp_ns <= previous_timestamp_ns`
/// or if the signature is invalid. Use this when processing a sequence of STHs to
/// guard against replayed or out-of-order tree heads.
pub fn verify_tree_head_sequential(
    tree_size: u64,
    root_hash: [u8; 32],
    timestamp_ns: i64,
    signature: &[u8],
    public_key: &[u8],
    previous_timestamp_ns: i64,
) -> bool {
    if timestamp_ns <= previous_timestamp_ns {
        return false;
    }
    verify_tree_head(tree_size, root_hash, timestamp_ns, signature, public_key)
}

/// Verifies the Ed25519 signature on a Signed Tree Head.
/// `public_key` must be 32 raw bytes; `signature` must be 64 raw bytes.
pub fn verify_tree_head(
    tree_size: u64,
    root_hash: [u8; 32],
    timestamp_ns: i64,
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    let Ok(key_arr) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&key_arr) else {
        return false;
    };
    let sig = Signature::from(sig_arr);
    let payload = signing_payload(tree_size, root_hash, timestamp_ns);
    vk.verify(&payload, &sig).is_ok()
}
