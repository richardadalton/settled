use std::sync::{Arc, Mutex};

use settled_core::merkle::MerkleTree;
use settled_storage::{Db, HeadStore, KeyRecord, KeyStore, LogStore, TreeStore};

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
    pub keys: KeyStore,
    /// Serialises appends and keeps the in-memory MerkleTree consistent with the log.
    pub append_mu: Arc<Mutex<AppendState>>,
    pub signer: Arc<LocalSigner>,
    pub config: Config,
}

impl AppState {
    pub async fn build(config: Config) -> anyhow::Result<Self> {
        let data_dir = config.data_dir.clone();
        let key_path = config.key_path.clone();

        let (db, merkle, initial_version, needs_seed) = tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&data_dir)?;
            let db = Db::open(&data_dir)?;

            // Reconstruct in-memory Merkle tree from the full log on startup.
            let entries = db.log_store().seq_range(0, u64::MAX)?;
            let mut merkle = MerkleTree::new();
            for entry in &entries {
                merkle.append(entry.leaf_hash);
            }
            tracing::info!("Rebuilt Merkle tree from {} log entries", entries.len());

            // Determine key version from CF_KEYS; seed if empty.
            let key_store = db.key_store();
            let latest = key_store.latest()?;
            let version = latest.as_ref().map_or(1, |r| r.version);
            let needs_seed = latest.is_none();

            Ok::<_, anyhow::Error>((db, merkle, version, needs_seed))
        })
        .await??;

        let signer = Arc::new(LocalSigner::load_or_generate(&key_path, initial_version)?);
        tracing::info!(
            version = initial_version,
            public_key = hex::encode(signer.public_key()),
            "Active signing key"
        );

        let key_store = db.key_store();
        if needs_seed {
            key_store.put(&KeyRecord {
                version: 1,
                public_key: signer.public_key(),
                activated_at_tree_size: 0,
            })?;
            tracing::info!("Seeded CF_KEYS with version-1 public key");
        }

        Ok(AppState {
            log: db.log_store(),
            tree: db.tree_store(),
            heads: db.head_store(),
            keys: key_store,
            append_mu: Arc::new(Mutex::new(AppendState { merkle })),
            signer,
            config,
        })
    }
}
