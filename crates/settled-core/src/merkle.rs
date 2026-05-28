use crate::hash::node_hash;

/// Largest power of 2 strictly less than n. Panics if n <= 1.
fn k(n: u64) -> u64 {
    assert!(n > 1);
    1u64 << (63 - (n - 1).leading_zeros())
}

/// Compute the Merkle root over a slice of pre-computed leaf hashes (RFC 6962).
/// Returns None for an empty slice.
pub fn mth(leaf_hashes: &[[u8; 32]]) -> Option<[u8; 32]> {
    match leaf_hashes.len() {
        0 => None,
        1 => Some(leaf_hashes[0]),
        n => {
            let split = k(n as u64) as usize;
            let left = mth(&leaf_hashes[..split]).unwrap();
            let right = mth(&leaf_hashes[split..]).unwrap();
            Some(node_hash(&left, &right))
        }
    }
}

/// Append-only Merkle tree. Stores the frontier (rightmost complete subtrees
/// at each level) so the root can be computed incrementally.
///
/// This is the in-memory structure used during batch tree updates.
/// Materialised nodes are written to RocksDB separately.
pub struct MerkleTree {
    /// frontier[i] holds the hash of the complete subtree at level i,
    /// if one exists at the current tree size.
    frontier: Vec<[u8; 32]>,
    size: u64,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            frontier: Vec::new(),
            size: 0,
        }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Append a pre-computed leaf hash. Returns the leaf index (0-based).
    pub fn append(&mut self, lh: [u8; 32]) -> u64 {
        let index = self.size;
        let mut hash = lh;
        let mut level = 0usize;
        // Combine with existing frontier nodes while the bit at `level` is set.
        while self.size & (1 << level) != 0 {
            hash = node_hash(&self.frontier[level], &hash);
            level += 1;
        }
        if level < self.frontier.len() {
            self.frontier[level] = hash;
        } else {
            self.frontier.push(hash);
        }
        // Zero out lower levels (they're now incorporated into `hash`).
        for l in 0..level {
            self.frontier[l] = [0u8; 32];
        }
        self.size += 1;
        index
    }

    /// Current Merkle root. Returns None if the tree is empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.size == 0 {
            return None;
        }
        let mut hash: Option<[u8; 32]> = None;
        for (level, &node) in self.frontier.iter().enumerate() {
            if self.size & (1 << level) == 0 {
                continue; // this level not occupied
            }
            hash = Some(match hash {
                None => node,
                Some(h) => node_hash(&node, &h),
            });
        }
        hash
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::leaf_hash;
    use std::fs;

    fn load_vectors(name: &str) -> serde_json::Value {
        let path = format!("{}/../../test-vectors/{name}", env!("CARGO_MANIFEST_DIR"));
        let data = fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {path}"));
        serde_json::from_str(&data).expect("invalid JSON")
    }

    fn decode32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn mth_vectors() {
        let vectors = load_vectors("tree-roots.json");
        for v in vectors.as_array().unwrap() {
            let leaf_hashes: Vec<[u8; 32]> = v["leaf_hashes_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| decode32(h.as_str().unwrap()))
                .collect();
            let expected = decode32(v["root_hex"].as_str().unwrap());
            let got = mth(&leaf_hashes).expect("mth returned None for non-empty tree");
            assert_eq!(got, expected, "mth failed for tree size {}", v["size"]);
        }
    }

    #[test]
    fn incremental_tree_matches_mth() {
        // Build a tree incrementally and verify the root matches mth() at each step.
        let entries: Vec<Vec<u8>> = (0..8).map(|i| format!("entry-{i}").into_bytes()).collect();
        let leaf_hashes: Vec<[u8; 32]> = entries.iter().map(|e| leaf_hash(e)).collect();

        let mut tree = MerkleTree::new();
        for (i, &lh) in leaf_hashes.iter().enumerate() {
            tree.append(lh);
            let expected = mth(&leaf_hashes[..=i]).unwrap();
            assert_eq!(
                tree.root().unwrap(),
                expected,
                "incremental root mismatch at size {}",
                i + 1
            );
        }
    }

    #[test]
    fn tree_root_vectors() {
        let vectors = load_vectors("tree-roots.json");
        let entries: Vec<Vec<u8>> = (0..8).map(|i| format!("entry-{i}").into_bytes()).collect();
        let leaf_hashes: Vec<[u8; 32]> = entries.iter().map(|e| leaf_hash(e)).collect();

        let mut tree = MerkleTree::new();
        for (i, &lh) in leaf_hashes.iter().enumerate() {
            tree.append(lh);
            let v = &vectors.as_array().unwrap()[i];
            let expected = decode32(v["root_hex"].as_str().unwrap());
            assert_eq!(
                tree.root().unwrap(),
                expected,
                "tree root mismatch at size {}",
                i + 1
            );
        }
    }
}
