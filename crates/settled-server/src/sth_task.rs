use std::time::{Duration, SystemTime, UNIX_EPOCH};

use settled_storage::SignedTreeHead;

use crate::state::AppState;

pub async fn run(state: AppState) {
    let interval = Duration::from_secs(state.config.sth_interval_secs);
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = sign_and_store(&state) {
            tracing::error!("STH signing failed: {e}");
        }
    }
}

fn sign_and_store(state: &AppState) -> anyhow::Result<()> {
    // Snapshot tree state without holding the lock during signing.
    let (tree_size, root_hash) = {
        let mu = state.append_mu.lock().unwrap();
        (mu.merkle.size(), mu.merkle.root())
    };

    if tree_size == 0 {
        return Ok(());
    }

    // Skip if we already have an STH at this tree size.
    if let Some(latest) = state.heads.latest()? {
        if latest.tree_size == tree_size {
            return Ok(());
        }
    }

    let root_hash = root_hash.unwrap(); // safe: tree_size > 0 implies a root exists
    let timestamp_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;

    let payload = settled_core::sth::signing_payload(tree_size, &root_hash, timestamp_ns);
    let signature = state.signer.sign(&payload);

    let sth = SignedTreeHead {
        tree_size,
        root_hash,
        timestamp_ns,
        signature,
        public_key: state.signer.public_key(),
        key_version: state.signer.key_version(),
    };

    state.heads.write(&sth)?;
    tracing::info!(
        tree_size,
        root = hex::encode(root_hash),
        "Signed new STH"
    );

    Ok(())
}
