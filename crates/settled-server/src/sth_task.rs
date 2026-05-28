use std::time::{Duration, SystemTime, UNIX_EPOCH};

use settled_storage::SignedTreeHead;

use crate::signer::Signer;
use crate::state::AppState;

/// Run the STH signing loop.
///
/// Wakes every `sth_interval_secs` to sign the current tree root. When
/// `shutdown` resolves (value changes or sender is dropped) the task performs
/// one final signing cycle — capturing any entries appended since the last
/// interval — then returns so callers can await a clean exit.
pub async fn run(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let interval = Duration::from_secs(state.config.sth_interval_secs);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                if let Err(e) = sign_and_store(&state) {
                    tracing::error!("STH signing failed: {e}");
                }
            }
            _ = shutdown.changed() => {
                // Final sign before exit to capture any entries appended
                // since the last interval.
                if let Err(e) = sign_and_store(&state) {
                    tracing::error!("STH signing failed on shutdown: {e}");
                }
                tracing::info!("STH task shut down");
                return;
            }
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

    let sign_timer = crate::metrics::STH_SIGN_DURATION.start_timer();
    let payload = settled_core::sth::signing_payload(tree_size, &root_hash, timestamp_ns);
    let signature = state.signer.sign(&payload);
    sign_timer.observe_duration();

    let sth = SignedTreeHead {
        tree_size,
        root_hash,
        timestamp_ns,
        signature,
        public_key: state.signer.public_key(),
        key_version: state.signer.key_version(),
    };

    state.heads.write(&sth)?;
    crate::metrics::STH_SIGNED.inc();
    crate::metrics::TREE_SIZE.set(tree_size as i64);
    crate::metrics::STH_LAST_TIMESTAMP_NS.set(timestamp_ns);
    tracing::info!(tree_size, root = hex::encode(root_hash), "Signed new STH");

    Ok(())
}
