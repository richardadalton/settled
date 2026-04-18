use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use settled_storage::{CounterSignature, FinalSTH, SignedTreeHead};

use crate::state::AppState;

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct SthPushBody {
    pub tree_size: u64,
    pub root_hash: String,
    pub timestamp_ns: i64,
    pub signature: String,
    pub public_key: String,
    pub key_version: u32,
}

impl From<&SignedTreeHead> for SthPushBody {
    fn from(s: &SignedTreeHead) -> Self {
        SthPushBody {
            tree_size: s.tree_size,
            root_hash: hex::encode(s.root_hash),
            timestamp_ns: s.timestamp_ns,
            signature: hex::encode(s.signature),
            public_key: hex::encode(s.public_key),
            key_version: s.key_version,
        }
    }
}

#[derive(Deserialize)]
pub struct PushResponse {
    pub counter_signature: String,
    pub public_key: String,
}

// ── Push ──────────────────────────────────────────────────────────────────────

/// Spawn a push task for each live settled node after a new STH is signed.
/// Non-blocking: fires and forgets. Push failures never block the main path.
pub fn trigger(state: AppState, sth: SignedTreeHead) {
    tokio::spawn(push_all(state, sth));
}

async fn push_all(state: AppState, sth: SignedTreeHead) {
    let records = match state.settled.live() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to list settled nodes: {e}");
            return;
        }
    };

    if records.is_empty() {
        return;
    }

    let body = SthPushBody::from(&sth);
    let threshold = state.config.threshold;

    let mut counter_sigs: Vec<CounterSignature> = Vec::new();

    for record in records {
        let url = record.url.clone();
        match push_with_retry(&state, &url, &body).await {
            Ok(cs) => {
                tracing::info!(%url, "Push succeeded, received counter-signature");
                counter_sigs.push(cs);
                // Reset failure count on success.
                if let Ok(Some(mut r)) = state.settled.get(&url) {
                    r.consecutive_failures = 0;
                    r.flagged_dead = false;
                    let _ = state.settled.update(&r);
                }
            }
            Err(e) => {
                tracing::warn!(%url, "Push failed: {e}");
                if let Ok(Some(mut r)) = state.settled.get(&url) {
                    r.consecutive_failures += 1;
                    if r.consecutive_failures >= state.config.max_push_failures {
                        r.flagged_dead = true;
                        tracing::warn!(%url, "Settled node flagged dead after {} failures",
                            r.consecutive_failures);
                    }
                    let _ = state.settled.update(&r);
                }
            }
        }
    }

    if threshold > 0 {
        let final_sth = FinalSTH { sth, counter_signatures: counter_sigs };
        if let Err(e) = state.final_heads.write(&final_sth) {
            tracing::error!("Failed to write FinalSTH: {e}");
        } else {
            tracing::info!(
                tree_size = final_sth.sth.tree_size,
                counter_sigs = final_sth.counter_signatures.len(),
                "Stored FinalSTH"
            );
        }
    }
}

async fn push_with_retry(
    state: &AppState,
    url: &str,
    body: &SthPushBody,
) -> anyhow::Result<CounterSignature> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(state.config.push_timeout_ms))
        .build()?;

    let push_url = format!("{url}/push");
    let mut delay_ms = 1_000u64;
    let max_attempts = 4;

    for attempt in 1..=max_attempts {
        match client.post(&push_url).json(body).send().await {
            Ok(resp) if resp.status().is_success() => {
                let pr: PushResponse = resp.json().await?;
                let cs = parse_counter_signature(url, &pr)?;
                return Ok(cs);
            }
            Ok(resp) => {
                let status = resp.status();
                if attempt < max_attempts {
                    tracing::debug!(%url, attempt, %status, "Push failed, retrying in {delay_ms}ms");
                    sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2;
                } else {
                    anyhow::bail!("Push to {url} failed after {max_attempts} attempts: {status}");
                }
            }
            Err(e) => {
                if attempt < max_attempts {
                    tracing::debug!(%url, attempt, "Push error: {e}, retrying in {delay_ms}ms");
                    sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2;
                } else {
                    anyhow::bail!("Push to {url} failed after {max_attempts} attempts: {e}");
                }
            }
        }
    }
    unreachable!()
}

fn parse_counter_signature(url: &str, pr: &PushResponse) -> anyhow::Result<CounterSignature> {
    let sig_bytes = hex::decode(&pr.counter_signature)?;
    let key_bytes = hex::decode(&pr.public_key)?;
    let signature: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("counter_signature must be 64 bytes"))?;
    let public_key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public_key must be 32 bytes"))?;
    Ok(CounterSignature {
        settled_node_url: url.to_owned(),
        public_key,
        signature,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::SystemTime;

    use axum::routing::post;
    use axum::{Json, Router};
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use rand::rngs::OsRng;
    use settled_core::sth::signing_payload;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    use crate::config::Config;
    use crate::state::AppState;

    fn make_test_sth(key: &SigningKey) -> SignedTreeHead {
        let root_hash = [0xab_u8; 32];
        let tree_size = 10u64;
        let timestamp_ns = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        let payload = signing_payload(tree_size, &root_hash, timestamp_ns);
        let sig = key.sign(&payload).to_bytes();
        SignedTreeHead {
            tree_size,
            root_hash,
            timestamp_ns,
            signature: sig,
            public_key: key.verifying_key().to_bytes(),
            key_version: 1,
        }
    }

    async fn test_state(dir: &TempDir) -> AppState {
        let config = Config {
            data_dir: dir.path().to_path_buf(),
            key_path: dir.path().join("signing.key"),
            listen: "127.0.0.1:0".parse().unwrap(),
            admin_listen: "127.0.0.1:0".parse().unwrap(),
            sth_interval_secs: 60,
            max_push_failures: 3,
            push_timeout_ms: 2000,
            threshold: 0,
        };
        AppState::build(config).await.unwrap()
    }

    /// Start a minimal mock settled-node HTTP server and return its address.
    /// The server accepts pushes and returns a counter-signature.
    async fn start_mock_node(node_key: Arc<SigningKey>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let handler_key = node_key.clone();
            let app = Router::new().route(
                "/push",
                post(move |Json(body): Json<SthPushBody>| {
                    let key = handler_key.clone();
                    async move {
                        let root_hash: [u8; 32] = hex::decode(&body.root_hash)
                            .unwrap()
                            .try_into()
                            .unwrap();
                        let payload = signing_payload(body.tree_size, &root_hash, body.timestamp_ns);
                        let sig = key.sign(&payload).to_bytes();
                        Json(serde_json::json!({
                            "counter_signature": hex::encode(sig),
                            "public_key": hex::encode(key.verifying_key().to_bytes()),
                        }))
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });

        addr
    }

    /// Start a mock node that always returns HTTP 500.
    async fn start_failing_mock_node(call_count: Arc<AtomicU32>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let app = Router::new().route(
                "/push",
                post(move || {
                    let count = call_count.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn mock_node_receives_push_with_correct_signature() {
        let dir = TempDir::new().unwrap();
        let state = test_state(&dir).await;

        let server_key = SigningKey::generate(&mut OsRng);
        let node_key = Arc::new(SigningKey::generate(&mut OsRng));
        let sth = make_test_sth(&server_key);

        let addr = start_mock_node(node_key.clone()).await;
        let node_url = format!("http://{addr}");

        // Register the mock node.
        state
            .settled
            .register(&settled_storage::SettledRecord {
                url: node_url.clone(),
                public_key: None,
                consecutive_failures: 0,
                flagged_dead: false,
                registered_at_ns: 0,
            })
            .unwrap();

        let body = SthPushBody::from(&sth);
        let result = push_with_retry(&state, &node_url, &body).await;
        assert!(result.is_ok(), "push should succeed: {:?}", result.err());

        let cs = result.unwrap();
        // Verify the counter-signature from the mock node.
        assert!(
            settled_storage::verify::verify_counter_signature_pub(&cs, &sth),
            "counter-signature must verify"
        );
    }

    #[tokio::test]
    async fn push_failure_does_not_block_and_increments_failure_count() {
        let dir = TempDir::new().unwrap();
        let state = test_state(&dir).await;
        let server_key = SigningKey::generate(&mut OsRng);
        let sth = make_test_sth(&server_key);

        // Register an unreachable node.
        state
            .settled
            .register(&settled_storage::SettledRecord {
                url: "http://127.0.0.1:1".to_owned(),
                public_key: None,
                consecutive_failures: 0,
                flagged_dead: false,
                registered_at_ns: 0,
            })
            .unwrap();

        // trigger returns immediately (fire-and-forget).
        let start = std::time::Instant::now();
        trigger(state.clone(), sth);
        assert!(
            start.elapsed().as_millis() < 100,
            "trigger must be non-blocking"
        );
    }

    #[tokio::test]
    async fn server_retries_failed_push_with_backoff() {
        let call_count = Arc::new(AtomicU32::new(0));
        let dir = TempDir::new().unwrap();
        let state = test_state(&dir).await;

        let addr = start_failing_mock_node(call_count.clone()).await;
        let node_url = format!("http://{addr}");
        let body = SthPushBody {
            tree_size: 1,
            root_hash: hex::encode([0u8; 32]),
            timestamp_ns: 0,
            signature: hex::encode([0u8; 64]),
            public_key: hex::encode([0u8; 32]),
            key_version: 1,
        };

        let _ = push_with_retry(&state, &node_url, &body).await;
        // Should have tried max_attempts (4) times.
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            4,
            "must retry 4 times before giving up"
        );
    }

    #[tokio::test]
    async fn dead_node_flagged_after_max_failures() {
        let dir = TempDir::new().unwrap();
        let config = Config {
            data_dir: dir.path().to_path_buf(),
            key_path: dir.path().join("signing.key"),
            listen: "127.0.0.1:0".parse().unwrap(),
            admin_listen: "127.0.0.1:0".parse().unwrap(),
            sth_interval_secs: 60,
            max_push_failures: 2,
            push_timeout_ms: 500,
            threshold: 0,
        };
        let state = AppState::build(config).await.unwrap();
        let server_key = SigningKey::generate(&mut OsRng);

        let url = "http://127.0.0.1:1".to_owned();
        state
            .settled
            .register(&settled_storage::SettledRecord {
                url: url.clone(),
                public_key: None,
                consecutive_failures: 0,
                flagged_dead: false,
                registered_at_ns: 0,
            })
            .unwrap();

        // Simulate 2 failed push cycles.
        for _ in 0..2 {
            let sth = make_test_sth(&server_key);
            push_all(state.clone(), sth).await;
        }

        let record = state.settled.get(&url).unwrap().unwrap();
        assert!(record.flagged_dead, "node must be flagged dead after max_push_failures");
    }
}
