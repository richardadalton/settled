use std::sync::{Arc, Mutex};

use settled_core::merkle::MerkleTree;
use settled_storage::{Db, HeadStore, LogStore, TreeStore};

use crate::config::Config;
use crate::signer::{LocalSigner, Signer};

pub struct AppendState {
    pub merkle: MerkleTree,
}

#[derive(Clone)]
pub struct AppState {
    pub log: LogStore,
    pub tree: TreeStore,
    pub heads: HeadStore,
    /// Serialises appends and keeps the in-memory MerkleTree consistent with the log.
    pub append_mu: Arc<Mutex<AppendState>>,
    pub signer: Arc<dyn Signer>,
    pub config: Config,
}

impl AppState {
    pub async fn build(config: Config) -> anyhow::Result<Self> {
        let data_dir = config.data_dir.clone();
        let key_path = config.key_path.clone();

        let (db, merkle) = tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&data_dir)?;
            let db = Db::open(&data_dir)?;

            // Reconstruct in-memory Merkle tree from the full log on startup.
            let entries = db.log_store().seq_range(0, u64::MAX)?;
            let mut merkle = MerkleTree::new();
            for entry in &entries {
                merkle.append(entry.leaf_hash);
            }
            tracing::info!("Rebuilt Merkle tree from {} log entries", entries.len());

            Ok::<_, anyhow::Error>((db, merkle))
        })
        .await??;

        let signer = LocalSigner::load_or_generate(&key_path)?;
        tracing::info!("Public key: {}", hex::encode(signer.public_key()));

        Ok(AppState {
            log: db.log_store(),
            tree: db.tree_store(),
            heads: db.head_store(),
            append_mu: Arc::new(Mutex::new(AppendState { merkle })),
            signer: Arc::new(signer),
            config,
        })
    }
}
