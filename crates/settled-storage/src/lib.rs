pub mod db;
pub mod error;
pub mod head_store;
pub mod log_store;
pub mod tree_store;
pub mod types;
pub mod verify;

mod proto;

pub use db::Db;
pub use error::{Error, Result};
pub use head_store::HeadStore;
pub use log_store::LogStore;
pub use tree_store::TreeStore;
pub use types::{LogEntry, SignedTreeHead};
pub use verify::verify_sth;

#[cfg(test)]
mod crash_recovery_tests {
    use settled_core::hash::leaf_hash;
    use settled_core::merkle::mth;
    use settled_core::proof::{
        consistency_proof, inclusion_proof, verify_consistency, verify_inclusion,
    };
    use tempfile::TempDir;

    use crate::db::Db;
    use crate::tree_store::compute_nodes_from_leaves;

    /// Phase 3 crash-recovery integration test.
    ///
    /// Scenario:
    /// 1. Write 1000 entries; build tree nodes for all 1000; record the root.
    /// 2. Write 100 more entries (log CF only — tree CF stays at size 1000).
    /// 3. Drop the DB (simulate crash where tree CF was not flushed for the last 100).
    /// 4. Reopen. Call rebuild_from_log.
    /// 5. Verify all 1100 entries are retrievable, all inclusion proofs verify,
    ///    consistency proof from the pre-crash root to the new root verifies.
    #[test]
    fn crash_recovery_rebuild() {
        let dir = TempDir::new().unwrap();

        // ── Phase A: write 1000 entries, build tree to size 1000 ─────────────
        let old_root;
        {
            let db = Db::open(dir.path()).unwrap();
            let log = db.log_store();
            let tree = db.tree_store();

            let mut leaf_hashes = Vec::with_capacity(1000);
            for i in 0usize..1000 {
                let data = format!("entry-{i}").into_bytes();
                log.append(format!("k{i}").as_bytes(), &data).unwrap();
                leaf_hashes.push(leaf_hash(&data));
            }

            let nodes = compute_nodes_from_leaves(
                leaf_hashes
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(i, h)| (i as u64, h))
                    .collect(),
            );
            tree.write_batch(&nodes).unwrap();

            old_root = mth(&leaf_hashes).unwrap();
            // DB drops here (simulated crash after tree is at size 1000).
        }

        // ── Phase B: write 100 more entries to log CF only ───────────────────
        {
            let db = Db::open(dir.path()).unwrap();
            let log = db.log_store();

            for i in 1000usize..1100 {
                let data = format!("entry-{i}").into_bytes();
                log.append(format!("k{i}").as_bytes(), &data).unwrap();
            }
            // Drop without updating tree CF — simulates crash / unflused tree.
        }

        // ── Phase C: reopen, rebuild, verify ─────────────────────────────────
        let db = Db::open(dir.path()).unwrap();
        let log = db.log_store();
        let tree = db.tree_store();

        // Rebuild tree CF from log.
        tree.rebuild_from_log(&log).unwrap();

        // Reload all 1100 leaf hashes from the log.
        let entries = log.seq_range(0, 1100).unwrap();
        assert_eq!(entries.len(), 1100, "all 1100 entries must be in log CF");

        let leaf_hashes: Vec<[u8; 32]> = entries.iter().map(|e| e.leaf_hash).collect();
        let new_root = mth(&leaf_hashes).unwrap();

        // All entries retrievable by seq.
        for e in &entries {
            let found = log.get_by_seq(e.seq).unwrap().unwrap();
            assert_eq!(found.seq, e.seq);
            assert_eq!(found.data, e.data);
        }

        // All inclusion proofs verify against new root.
        for idx in 0..1100usize {
            let path = inclusion_proof(&leaf_hashes, idx).unwrap();
            assert!(
                verify_inclusion(&leaf_hashes[idx], idx as u64, 1100, &path, &new_root),
                "inclusion proof failed for idx={idx}"
            );
        }

        // Consistency proof from old root (size 1000) to new root (size 1100) verifies.
        let cons = consistency_proof(&leaf_hashes, 1000).unwrap();
        assert!(
            verify_consistency(1000, 1100, &cons, &old_root, &new_root),
            "consistency proof from 1000 to 1100 must verify"
        );
    }
}
