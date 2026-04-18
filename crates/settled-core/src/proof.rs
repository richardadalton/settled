use crate::hash::node_hash;
use crate::merkle::mth;

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("leaf index {0} out of range for tree size {1}")]
    LeafIndexOutOfRange(u64, u64),
    #[error("invalid tree sizes: old={0} new={1}")]
    InvalidSizes(u64, u64),
    #[error("proof too short")]
    TooShort,
    #[error("proof too long")]
    TooLong,
}

/// Largest power of 2 strictly less than n. Requires n > 1.
fn k(n: usize) -> usize {
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros()) as usize
}

// ---------------------------------------------------------------------------
// Inclusion proof
// ---------------------------------------------------------------------------

/// RFC 6962 PATH(m, D[n]).
/// Returns the sibling hashes from leaf to root for leaf at index `m`.
pub fn inclusion_proof(leaf_hashes: &[[u8; 32]], leaf_index: usize) -> Result<Vec<[u8; 32]>, ProofError> {
    let n = leaf_hashes.len();
    if leaf_index >= n {
        return Err(ProofError::LeafIndexOutOfRange(leaf_index as u64, n as u64));
    }
    Ok(path(leaf_hashes, leaf_index))
}

fn path(leaf_hashes: &[[u8; 32]], m: usize) -> Vec<[u8; 32]> {
    let n = leaf_hashes.len();
    if n == 1 {
        return vec![];
    }
    let split = k(n);
    if m < split {
        let mut p = path(&leaf_hashes[..split], m);
        p.push(mth(&leaf_hashes[split..]).unwrap());
        p
    } else {
        let mut p = path(&leaf_hashes[split..], m - split);
        p.push(mth(&leaf_hashes[..split]).unwrap());
        p
    }
}

/// Verify an inclusion proof.
/// Returns true iff `leaf_hash` at index `leaf_index` in a tree of size
/// `tree_size` with the given `proof` produces `root`.
pub fn verify_inclusion(
    leaf_hash: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }

    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = *leaf_hash;

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

    sn == 0 && &r == root
}

// ---------------------------------------------------------------------------
// Consistency proof
// ---------------------------------------------------------------------------

/// RFC 6962 PROOF(old_size, D[new_size]).
/// `leaf_hashes` must contain all `new_size` leaves.
pub fn consistency_proof(
    leaf_hashes: &[[u8; 32]],
    old_size: usize,
) -> Result<Vec<[u8; 32]>, ProofError> {
    let new_size = leaf_hashes.len();
    if old_size == 0 || old_size > new_size {
        return Err(ProofError::InvalidSizes(old_size as u64, new_size as u64));
    }
    if old_size == new_size {
        return Ok(vec![]);
    }
    Ok(subproof(leaf_hashes, old_size, true))
}

fn subproof(leaf_hashes: &[[u8; 32]], m: usize, b: bool) -> Vec<[u8; 32]> {
    let n = leaf_hashes.len();
    if m == n {
        if b {
            return vec![];
        } else {
            return vec![mth(leaf_hashes).unwrap()];
        }
    }
    let split = k(n);
    if m <= split {
        let mut p = subproof(&leaf_hashes[..split], m, b);
        p.push(mth(&leaf_hashes[split..]).unwrap());
        p
    } else {
        let mut p = subproof(&leaf_hashes[split..], m - split, false);
        p.push(mth(&leaf_hashes[..split]).unwrap());
        p
    }
}

/// Verify a consistency proof.
/// Uses the same recursive structure as proof generation so correctness
/// is straightforward to reason about.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    proof: &[[u8; 32]],
    old_root: &[u8; 32],
    new_root: &[u8; 32],
) -> bool {
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if old_size == 0 || old_size > new_size {
        return false;
    }

    let mut iter = proof.iter();

    match verify_subproof(old_size as usize, new_size as usize, old_root, &mut iter, true) {
        Some((computed_old, computed_new)) => {
            iter.next().is_none()  // proof fully consumed
                && &computed_old == old_root
                && &computed_new == new_root
        }
        None => false,
    }
}

/// Returns (reconstructed_old_root, reconstructed_new_root), or None on error.
/// `None` from the recursive call (when b=true and m==n) means "use old_root".
fn verify_subproof<'a>(
    m: usize,
    n: usize,
    old_root: &[u8; 32],
    iter: &mut impl Iterator<Item = &'a [u8; 32]>,
    b: bool,
) -> Option<([u8; 32], [u8; 32])> {
    if m == n {
        if b {
            return Some((*old_root, *old_root)); // sentinel: shared subtree = old_root
        } else {
            let h = iter.next()?;
            return Some((*h, *h));
        }
    }
    let split = k(n);
    if m <= split {
        let (lo, ln) = verify_subproof(m, split, old_root, iter, b)?;
        let rh = iter.next()?;
        // lo == old_root when the recursion hit m==n with b=true (shared prefix)
        let actual_old = lo;
        let actual_new = node_hash(&ln, rh);
        Some((actual_old, actual_new))
    } else {
        let (ro, rn) = verify_subproof(m - split, n - split, old_root, iter, false)?;
        let lh = iter.next()?;
        Some((node_hash(lh, &ro), node_hash(lh, &rn)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::leaf_hash;
    use std::fs;

    fn load_vectors(name: &str) -> serde_json::Value {
        let path = format!(
            "{}/../../test-vectors/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {path}"));
        serde_json::from_str(&data).expect("invalid JSON")
    }

    fn decode32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn standard_leaf_hashes() -> Vec<[u8; 32]> {
        (0..8).map(|i| leaf_hash(format!("entry-{i}").as_bytes())).collect()
    }

    // -----------------------------------------------------------------------
    // Inclusion proof tests
    // -----------------------------------------------------------------------

    #[test]
    fn inclusion_proof_vectors() {
        let vectors = load_vectors("inclusion-proofs.json");
        let lh = standard_leaf_hashes();

        for v in vectors.as_array().unwrap() {
            let tree_size = v["tree_size"].as_u64().unwrap() as usize;
            let leaf_index = v["leaf_index"].as_u64().unwrap() as usize;
            let expected_root = decode32(v["root_hex"].as_str().unwrap());
            let expected_proof: Vec<[u8; 32]> = v["proof_hex"]
                .as_array().unwrap()
                .iter()
                .map(|h| decode32(h.as_str().unwrap()))
                .collect();

            let got = inclusion_proof(&lh[..tree_size], leaf_index).unwrap();
            assert_eq!(
                got, expected_proof,
                "inclusion_proof mismatch: size={tree_size} idx={leaf_index}"
            );

            let valid = verify_inclusion(&lh[leaf_index], leaf_index as u64,
                                        tree_size as u64, &got, &expected_root);
            assert!(valid, "verify_inclusion failed: size={tree_size} idx={leaf_index}");
        }
    }

    #[test]
    fn inclusion_negative_cases() {
        let vectors = load_vectors("negative-cases.json");
        let cases = vectors.as_object().unwrap();

        for (name, v) in cases {
            if !name.starts_with("inclusion_") {
                continue;
            }
            let lh = decode32(v["leaf_hash_hex"].as_str().unwrap());
            let leaf_index = v["leaf_index"].as_u64().unwrap();
            let tree_size = v["tree_size"].as_u64().unwrap();
            let proof: Vec<[u8; 32]> = v["proof_hex"]
                .as_array().unwrap()
                .iter()
                .map(|h| decode32(h.as_str().unwrap()))
                .collect();
            let root = decode32(v["root_hex"].as_str().unwrap());

            let result = verify_inclusion(&lh, leaf_index, tree_size, &proof, &root);
            assert!(!result, "negative case '{name}' should have failed");
        }
    }

    // -----------------------------------------------------------------------
    // Consistency proof tests
    // -----------------------------------------------------------------------

    #[test]
    fn consistency_proof_vectors() {
        let vectors = load_vectors("consistency-proofs.json");
        let lh = standard_leaf_hashes();

        for v in vectors.as_array().unwrap() {
            let old_size = v["old_size"].as_u64().unwrap() as usize;
            let new_size = v["new_size"].as_u64().unwrap() as usize;
            let old_root = decode32(v["old_root_hex"].as_str().unwrap());
            let new_root = decode32(v["new_root_hex"].as_str().unwrap());
            let expected_proof: Vec<[u8; 32]> = v["proof_hex"]
                .as_array().unwrap()
                .iter()
                .map(|h| decode32(h.as_str().unwrap()))
                .collect();

            let got = consistency_proof(&lh[..new_size], old_size).unwrap();
            assert_eq!(
                got, expected_proof,
                "consistency_proof mismatch: old={old_size} new={new_size}"
            );

            let valid = verify_consistency(
                old_size as u64, new_size as u64, &got, &old_root, &new_root,
            );
            assert!(valid, "verify_consistency failed: old={old_size} new={new_size}");
        }
    }

    #[test]
    fn consistency_negative_cases() {
        let vectors = load_vectors("negative-cases.json");
        let cases = vectors.as_object().unwrap();

        for (name, v) in cases {
            if !name.starts_with("consistency_") {
                continue;
            }
            let old_size = v["old_size"].as_u64().unwrap();
            let new_size = v["new_size"].as_u64().unwrap();
            let proof: Vec<[u8; 32]> = v["proof_hex"]
                .as_array().unwrap()
                .iter()
                .map(|h| decode32(h.as_str().unwrap()))
                .collect();
            let old_root = decode32(v["old_root_hex"].as_str().unwrap());
            let new_root = decode32(v["new_root_hex"].as_str().unwrap());

            let result = verify_consistency(old_size, new_size, &proof, &old_root, &new_root);
            assert!(!result, "negative case '{name}' should have failed");
        }
    }

    // -----------------------------------------------------------------------
    // Cross-check: proofs generated here must verify against Python-generated roots
    // -----------------------------------------------------------------------

    #[test]
    fn cross_check_roots_match_python_vectors() {
        let vectors = load_vectors("tree-roots.json");
        let lh = standard_leaf_hashes();

        for v in vectors.as_array().unwrap() {
            let size = v["size"].as_u64().unwrap() as usize;
            let expected = decode32(v["root_hex"].as_str().unwrap());
            let got = mth(&lh[..size]).unwrap();
            assert_eq!(got, expected, "root mismatch at size {size}");
        }
    }

    // -----------------------------------------------------------------------
    // Tamper-evidence: the core security guarantee
    // -----------------------------------------------------------------------

    /// A server that alters a historical entry cannot produce a valid consistency
    /// proof against a client holding the original signed tree head.
    ///
    /// This is the central guarantee of the append-only log. If this test fails,
    /// the cryptography provides no tamper-evidence.
    #[test]
    fn tampered_history_fails_consistency_check() {
        let real_hashes = standard_leaf_hashes();
        let old_root = mth(&real_hashes[..4]).unwrap(); // STH at size 4

        // Attacker rewrites entry 0 and builds a new tree from tampered data.
        let mut tampered = real_hashes.clone();
        tampered[0] = leaf_hash(b"TAMPERED-ENTRY");
        let tampered_new_root = mth(&tampered).unwrap();

        // The attacker cannot produce a consistency proof from their tampered tree
        // that verifies against the client's archived old_root.
        let tampered_proof = consistency_proof(&tampered, 4).unwrap();
        assert!(
            !verify_consistency(4, 8, &tampered_proof, &old_root, &tampered_new_root),
            "tampered history must fail consistency check"
        );

        // Also confirm: the correct proof from the real tree does verify.
        let real_proof = consistency_proof(&real_hashes, 4).unwrap();
        let real_new_root = mth(&real_hashes).unwrap();
        assert!(
            verify_consistency(4, 8, &real_proof, &old_root, &real_new_root),
            "real proof must verify"
        );
    }

    /// A proof produced by a completely different tree cannot be used to convince
    /// a verifier holding a root from a different tree.
    #[test]
    fn proof_from_different_tree_fails() {
        let tree_a: Vec<[u8; 32]> = (0u8..8).map(|i| leaf_hash(&[i])).collect();
        let tree_b: Vec<[u8; 32]> = (10u8..18).map(|i| leaf_hash(&[i])).collect();

        let old_root_a = mth(&tree_a[..4]).unwrap();
        let new_root_b = mth(&tree_b).unwrap();
        let proof_b = consistency_proof(&tree_b, 4).unwrap();

        // Proof from tree B cannot verify against roots from tree A.
        assert!(
            !verify_consistency(4, 8, &proof_b, &old_root_a, &new_root_b),
            "proof from different tree must fail"
        );
    }

    /// verify_consistency must reject malformed inputs without panicking.
    #[test]
    fn consistency_edge_cases() {
        let lh = standard_leaf_hashes();
        let old_root = mth(&lh[..4]).unwrap();
        let new_root = mth(&lh).unwrap();
        let proof = consistency_proof(&lh, 4).unwrap();

        // old_size > new_size
        assert!(!verify_consistency(8, 4, &proof, &old_root, &new_root));
        // old_size == 0
        assert!(!verify_consistency(0, 8, &proof, &old_root, &new_root));
        // proof too long (extra element)
        let mut long_proof = proof.clone();
        long_proof.push([0u8; 32]);
        assert!(!verify_consistency(4, 8, &long_proof, &old_root, &new_root));
        // proof too short (missing element)
        assert!(!verify_consistency(4, 8, &proof[..proof.len()-1], &old_root, &new_root));
        // empty proof for non-equal sizes
        assert!(!verify_consistency(4, 8, &[], &old_root, &new_root));
    }

    /// verify_inclusion must reject malformed inputs without panicking.
    #[test]
    fn inclusion_edge_cases() {
        let lh = standard_leaf_hashes();
        let root = mth(&lh).unwrap();
        let proof = inclusion_proof(&lh, 3).unwrap();

        // leaf_index >= tree_size
        assert!(!verify_inclusion(&lh[3], 8, 8, &proof, &root));
        // tree_size == 0
        assert!(!verify_inclusion(&lh[0], 0, 0, &[], &root));
        // proof too long
        let mut long_proof = proof.clone();
        long_proof.push([0u8; 32]);
        assert!(!verify_inclusion(&lh[3], 3, 8, &long_proof, &root));
    }

    // -----------------------------------------------------------------------
    // Property tests
    // -----------------------------------------------------------------------

    proptest::proptest! {
        /// For any tree, every leaf's inclusion proof verifies against the root.
        #[test]
        fn prop_every_leaf_verifies(
            entries in proptest::collection::vec(
                proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=64usize),
                1..=64usize,
            )
        ) {
            let lh: Vec<[u8; 32]> = entries.iter().map(|e| leaf_hash(e)).collect();
            let root = mth(&lh).unwrap();
            let n = lh.len();
            for i in 0..n {
                let proof = inclusion_proof(&lh, i).unwrap();
                proptest::prop_assert!(
                    verify_inclusion(&lh[i], i as u64, n as u64, &proof, &root),
                    "inclusion failed: size={n} idx={i}"
                );
            }
        }

        /// Any two size snapshots of a growing tree are consistent with each other.
        #[test]
        fn prop_any_two_snapshots_consistent(
            entries in proptest::collection::vec(
                proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=64usize),
                2..=32usize,
            )
        ) {
            let lh: Vec<[u8; 32]> = entries.iter().map(|e| leaf_hash(e)).collect();
            let n = lh.len();
            for old in 1..=n {
                let old_root = mth(&lh[..old]).unwrap();
                let new_root = mth(&lh).unwrap();
                let proof = consistency_proof(&lh, old).unwrap();
                proptest::prop_assert!(
                    verify_consistency(old as u64, n as u64, &proof, &old_root, &new_root),
                    "consistency failed: old={old} new={n}"
                );
            }
        }

        /// A proof for leaf i must not verify for leaf j (i != j) in the same tree.
        #[test]
        fn prop_wrong_index_fails(
            entries in proptest::collection::vec(
                proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32usize),
                2..=16usize,
            )
        ) {
            let lh: Vec<[u8; 32]> = entries.iter().map(|e| leaf_hash(e)).collect();
            let root = mth(&lh).unwrap();
            let n = lh.len();
            // Check a sample: proof for index 0 must not verify for index 1.
            let proof = inclusion_proof(&lh, 0).unwrap();
            proptest::prop_assert!(
                !verify_inclusion(&lh[0], 1, n as u64, &proof, &root),
                "proof for idx=0 must not verify at idx=1"
            );
        }
    }
}
