use std::collections::HashMap;
use std::sync::Arc;

use rocksdb::{IteratorMode, WriteBatch};
use settled_core::hash::node_hash;

use crate::db::{DbInner, CF_TREE};
use crate::error::{Error, Result};
use crate::log_store::LogStore;

#[derive(Clone)]
pub struct TreeStore(pub(crate) Arc<DbInner>);

impl TreeStore {
    /// Persist a batch of pre-computed Merkle nodes.
    /// Each node is `(level, index, hash)`.
    pub fn write_batch(&self, nodes: &[(u64, u64, [u8; 32])]) -> Result<()> {
        let cf = self.0.db.cf_handle(CF_TREE).expect("tree CF must exist");
        let mut batch = WriteBatch::default();
        for (level, index, hash) in nodes {
            let key = tree_key(*level, *index);
            batch.put_cf(cf, key, hash);
        }
        self.0.db.write(batch)?;
        Ok(())
    }

    pub fn get_node(&self, level: u64, index: u64) -> Result<Option<[u8; 32]>> {
        let cf = self.0.db.cf_handle(CF_TREE).expect("tree CF must exist");
        match self.0.db.get_cf(cf, tree_key(level, index))? {
            Some(v) => {
                let hash: [u8; 32] = (*v)
                    .try_into()
                    .map_err(|_| Error::Corruption("tree node value must be 32 bytes".into()))?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Rebuild the tree CF from scratch using the log CF.
    /// All existing tree nodes are deleted, then recomputed from log entries.
    pub fn rebuild_from_log(&self, log: &LogStore) -> Result<()> {
        // Clear the tree CF.
        {
            let cf = self.0.db.cf_handle(CF_TREE).expect("tree CF must exist");
            let keys: Vec<_> = self
                .0
                .db
                .iterator_cf(cf, IteratorMode::Start)
                .filter_map(|r| r.ok().map(|(k, _)| k.to_vec()))
                .collect();
            if !keys.is_empty() {
                let mut batch = WriteBatch::default();
                for k in &keys {
                    batch.delete_cf(cf, k);
                }
                self.0.db.write(batch)?;
            }
        }

        // Load all log entries and compute nodes.
        // For large trees this loads all entries into memory. Acceptable for Phase 3.
        let entries = log.seq_range(0, u64::MAX)?;
        let nodes =
            compute_nodes_from_leaves(entries.iter().map(|e| (e.seq, e.leaf_hash)).collect());
        self.write_batch(&nodes)
    }
}

/// Compute all Merkle tree nodes that should be written for the given leaf sequence.
///
/// Leaves must be provided in ascending seq order starting from 0 (i.e. a full tree scan).
/// Returns `(level, index, hash)` tuples for every complete node.
pub fn compute_nodes_from_leaves(leaves: Vec<(u64, [u8; 32])>) -> Vec<(u64, u64, [u8; 32])> {
    let mut cache: HashMap<(u64, u64), [u8; 32]> = HashMap::new();
    let mut nodes = Vec::new();

    for (j, hash) in leaves {
        cache.insert((0, j), hash);
        nodes.push((0, j, hash));

        let mut h = 1u64;
        // h < 63 guards against shift overflow for pathologically large trees.
        while h < 63 && (j + 1) % (1u64 << h) == 0 {
            let idx = j >> h;
            let left = cache[&(h - 1, 2 * idx)];
            let right = cache[&(h - 1, 2 * idx + 1)];
            let parent = node_hash(&left, &right);
            cache.insert((h, idx), parent);
            nodes.push((h, idx, parent));
            h += 1;
        }
    }

    nodes
}

fn tree_key(level: u64, index: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&level.to_be_bytes());
    key[8..].copy_from_slice(&index.to_be_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use settled_core::hash::leaf_hash;
    use settled_core::proof::{inclusion_proof, verify_inclusion};
    use tempfile::TempDir;

    fn open_fresh() -> (TempDir, Db) {
        let dir = TempDir::new().unwrap();
        let db = Db::open(dir.path()).unwrap();
        (dir, db)
    }

    fn append_n(log: &LogStore, n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let data = format!("entry-{i}").into_bytes();
                let (_, _) = log.append(format!("k{i}").as_bytes(), &data).unwrap();
                leaf_hash(&data)
            })
            .collect()
    }

    #[test]
    fn written_nodes_are_retrievable() {
        let (_dir, db) = open_fresh();
        let tree = db.tree_store();
        let hash = [0xABu8; 32];
        tree.write_batch(&[(0, 5, hash)]).unwrap();
        assert_eq!(tree.get_node(0, 5).unwrap(), Some(hash));
        assert_eq!(tree.get_node(0, 6).unwrap(), None);
    }

    #[test]
    fn inclusion_proofs_verify_after_tree_write() {
        let (_dir, db) = open_fresh();
        let log = db.log_store();
        let tree = db.tree_store();

        let n = 8usize;
        let leaf_hashes = append_n(&log, n);

        let nodes = compute_nodes_from_leaves(
            leaf_hashes
                .iter()
                .copied()
                .enumerate()
                .map(|(i, h)| (i as u64, h))
                .collect(),
        );
        tree.write_batch(&nodes).unwrap();

        let root = settled_core::merkle::mth(&leaf_hashes).unwrap();

        for idx in 0..n {
            let path = inclusion_proof(&leaf_hashes, idx).unwrap();
            assert!(
                verify_inclusion(&leaf_hashes[idx], idx as u64, n as u64, &path, &root),
                "inclusion proof failed for idx={idx}"
            );
        }
    }

    #[test]
    fn rebuild_produces_identical_nodes() {
        let (_dir, db) = open_fresh();
        let log = db.log_store();
        let tree = db.tree_store();

        let n = 7usize;
        let leaf_hashes = append_n(&log, n);

        // Write via live path.
        let live_nodes = compute_nodes_from_leaves(
            leaf_hashes
                .iter()
                .copied()
                .enumerate()
                .map(|(i, h)| (i as u64, h))
                .collect(),
        );
        tree.write_batch(&live_nodes).unwrap();

        // Snapshot all nodes before rebuild.
        let before: HashMap<(u64, u64), [u8; 32]> =
            live_nodes.iter().map(|&(l, i, h)| ((l, i), h)).collect();

        // Rebuild from log.
        tree.rebuild_from_log(&log).unwrap();

        // Every node must match the live-path result.
        for ((level, index), expected) in &before {
            let got = tree.get_node(*level, *index).unwrap().unwrap();
            assert_eq!(
                got, *expected,
                "mismatch at ({level},{index}) after rebuild"
            );
        }
    }

    #[test]
    fn rebuild_is_idempotent() {
        let (_dir, db) = open_fresh();
        let log = db.log_store();
        let tree = db.tree_store();

        let n = 5usize;
        let leaf_hashes = append_n(&log, n);
        let nodes = compute_nodes_from_leaves(
            leaf_hashes
                .iter()
                .copied()
                .enumerate()
                .map(|(i, h)| (i as u64, h))
                .collect(),
        );
        tree.write_batch(&nodes).unwrap();

        tree.rebuild_from_log(&log).unwrap();
        tree.rebuild_from_log(&log).unwrap();

        // Spot-check a few nodes.
        for (level, index, expected) in &nodes {
            assert_eq!(tree.get_node(*level, *index).unwrap().unwrap(), *expected);
        }
    }
}
