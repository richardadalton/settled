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

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/api/keys", get(list_keys))
        .route("/api/rotate-key", post(rotate_key))
        .with_state(state)
}
