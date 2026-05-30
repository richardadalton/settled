use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use settled_storage::KeyRecord;

use crate::signer::Signer;
use crate::state::AppState;

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct KeyRecordJson {
    version: u32,
    public_key: String,
    activated_at_tree_size: u64,
}

impl From<KeyRecord> for KeyRecordJson {
    fn from(r: KeyRecord) -> Self {
        Self {
            version: r.version,
            public_key: hex::encode(r.public_key),
            activated_at_tree_size: r.activated_at_tree_size,
        }
    }
}

#[derive(Serialize)]
struct SthJson {
    tree_size: u64,
    root_hash: String,
    timestamp_ns: i64,
    signature: String,
    public_key: String,
    key_version: u32,
}

#[derive(Serialize)]
struct StatsJson {
    /// Total entries durably written to the log.
    entry_count: u64,
    /// Current Merkle tree size (may be ahead of the latest signed STH).
    tree_size: u64,
    /// Timestamp of the last signed STH (nanoseconds since Unix epoch), or
    /// null if no STH has been produced yet.
    last_sth_timestamp_ns: Option<i64>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn metrics() -> Result<String, StatusCode> {
    crate::metrics::gather_text().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// GET /api/keys — returns all key records in version-ascending order.
async fn list_keys(State(state): State<AppState>) -> Result<Json<Vec<KeyRecordJson>>, StatusCode> {
    let records = state
        .keys
        .all()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(records.into_iter().map(KeyRecordJson::from).collect()))
}

/// POST /api/rotate-key — generates a new signing key, stores the public key in
/// CF_KEYS with `activated_at_tree_size` set to the current log size, and hot-swaps
/// the in-memory signer. Returns the new key record.
async fn rotate_key(State(state): State<AppState>) -> Result<Json<KeyRecordJson>, StatusCode> {
    let activated_at = {
        let guard = state.append_mu.lock().unwrap();
        guard.merkle.size()
    };
    let new_version = state.signer.key_version() + 1;
    let new_pubkey = state
        .signer
        .rotate(new_version)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let record = KeyRecord {
        version: new_version,
        public_key: new_pubkey,
        activated_at_tree_size: activated_at,
    };
    state
        .keys
        .put(&record)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(KeyRecordJson::from(record)))
}

/// GET /api/sth — latest signed tree head as JSON.
/// Returns 204 No Content if no STH has been produced yet.
async fn get_sth(State(state): State<AppState>) -> Result<Json<SthJson>, StatusCode> {
    let sth = state
        .heads
        .latest()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NO_CONTENT)?;
    Ok(Json(SthJson {
        tree_size: sth.tree_size,
        root_hash: hex::encode(sth.root_hash),
        timestamp_ns: sth.timestamp_ns,
        signature: hex::encode(sth.signature),
        public_key: hex::encode(sth.public_key),
        key_version: sth.key_version,
    }))
}

/// GET /api/stats — entry count, Merkle tree size, and last STH timestamp.
async fn stats(State(state): State<AppState>) -> Result<Json<StatsJson>, StatusCode> {
    let entry_count = state.log.count();
    let tree_size = {
        let mu = state.append_mu.lock().unwrap();
        mu.merkle.size()
    };
    let last_sth_timestamp_ns = state
        .heads
        .latest()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(|s| s.timestamp_ns);
    Ok(Json(StatsJson {
        entry_count,
        tree_size,
        last_sth_timestamp_ns,
    }))
}

/// POST /api/sth/force — trigger an immediate STH signing cycle.
/// Returns the new STH if a new one was produced, or 204 if the tree is empty
/// or already up to date.
async fn force_sth(State(state): State<AppState>) -> Result<Json<SthJson>, StatusCode> {
    crate::sth_task::sign_and_store(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Return whatever the latest STH now is (may be unchanged if tree was empty).
    let sth = state
        .heads
        .latest()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NO_CONTENT)?;
    Ok(Json(SthJson {
        tree_size: sth.tree_size,
        root_hash: hex::encode(sth.root_hash),
        timestamp_ns: sth.timestamp_ns,
        signature: hex::encode(sth.signature),
        public_key: hex::encode(sth.public_key),
        key_version: sth.key_version,
    }))
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/api/keys", get(list_keys))
        .route("/api/rotate-key", post(rotate_key))
        .route("/api/sth", get(get_sth))
        .route("/api/stats", get(stats))
        .route("/api/sth/force", post(force_sth))
        .with_state(state)
}
