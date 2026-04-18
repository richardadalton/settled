use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use settled_core::sth::signing_payload;
use settled_storage::verify::verify_sth;
use settled_storage::SignedTreeHead;

// ── State ─────────────────────────────────────────────────────────────────────

pub struct NodeState {
    pub signing_key: SigningKey,
    pub archive: RwLock<BTreeMap<u64, SignedTreeHead>>,
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PushBody {
    pub tree_size: u64,
    pub root_hash: String,
    pub timestamp_ns: i64,
    pub signature: String,
    pub public_key: String,
    pub key_version: u32,
}

#[derive(Serialize, Deserialize)]
pub struct PushResponse {
    pub counter_signature: String,
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct ArchivedSth {
    pub tree_size: u64,
    pub root_hash: String,
    pub timestamp_ns: i64,
    pub signature: String,
    pub public_key: String,
    pub key_version: u32,
}

impl From<&SignedTreeHead> for ArchivedSth {
    fn from(s: &SignedTreeHead) -> Self {
        ArchivedSth {
            tree_size: s.tree_size,
            root_hash: hex::encode(s.root_hash),
            timestamp_ns: s.timestamp_ns,
            signature: hex::encode(s.signature),
            public_key: hex::encode(s.public_key),
            key_version: s.key_version,
        }
    }
}

// ── Key management ────────────────────────────────────────────────────────────

pub fn load_or_generate_key(path: &Path) -> anyhow::Result<SigningKey> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Key file must be exactly 32 bytes"))?;
        Ok(SigningKey::from_bytes(&arr))
    } else {
        use rand::rngs::OsRng;
        let key = SigningKey::generate(&mut OsRng);
        std::fs::write(path, key.to_bytes())?;
        tracing::info!(?path, "Generated new signing key");
        Ok(key)
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn push(
    State(state): State<Arc<NodeState>>,
    Json(body): Json<PushBody>,
) -> Result<Json<PushResponse>, StatusCode> {
    let root_hash_bytes = hex::decode(&body.root_hash).map_err(|_| StatusCode::BAD_REQUEST)?;
    let signature_bytes = hex::decode(&body.signature).map_err(|_| StatusCode::BAD_REQUEST)?;
    let public_key_bytes = hex::decode(&body.public_key).map_err(|_| StatusCode::BAD_REQUEST)?;

    let root_hash: [u8; 32] = root_hash_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let public_key: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let sth = SignedTreeHead {
        tree_size: body.tree_size,
        root_hash,
        timestamp_ns: body.timestamp_ns,
        signature,
        public_key,
        key_version: body.key_version,
    };

    if !verify_sth(&sth) {
        tracing::warn!(tree_size = sth.tree_size, "Rejected STH with invalid signature");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Sign with this node's key and archive.
    let payload = signing_payload(sth.tree_size, &sth.root_hash, sth.timestamp_ns);
    let counter_sig = state.signing_key.sign(&payload).to_bytes();
    let node_public_key = state.signing_key.verifying_key().to_bytes();

    {
        let mut archive = state.archive.write().await;
        archive.entry(sth.tree_size).or_insert(sth);
    }

    tracing::info!(tree_size = body.tree_size, "Counter-signed STH");

    Ok(Json(PushResponse {
        counter_signature: hex::encode(counter_sig),
        public_key: hex::encode(node_public_key),
    }))
}

async fn archive_get(
    State(state): State<Arc<NodeState>>,
    AxumPath(tree_size): AxumPath<u64>,
) -> Result<Json<ArchivedSth>, StatusCode> {
    let archive = state.archive.read().await;
    match archive.get(&tree_size) {
        Some(sth) => Ok(Json(ArchivedSth::from(sth))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: Arc<NodeState>) -> Router {
    Router::new()
        .route("/push", post(push))
        .route("/archive/:tree_size", get(archive_get))
        .with_state(state)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use ed25519_dalek::SigningKey as DalekKey;
    use rand::rngs::OsRng;
    use settled_core::sth::signing_payload;
    use tower::ServiceExt;

    fn make_state() -> Arc<NodeState> {
        Arc::new(NodeState {
            signing_key: DalekKey::generate(&mut OsRng),
            archive: RwLock::new(BTreeMap::new()),
        })
    }

    fn valid_push_body(server_key: &DalekKey) -> serde_json::Value {
        let root_hash = [0xde_u8; 32];
        let tree_size = 42u64;
        let timestamp_ns = 1_700_000_000_000_000_000i64;
        let payload = signing_payload(tree_size, &root_hash, timestamp_ns);
        let sig = server_key.sign(&payload).to_bytes();
        serde_json::json!({
            "tree_size": tree_size,
            "root_hash": hex::encode(root_hash),
            "timestamp_ns": timestamp_ns,
            "signature": hex::encode(sig),
            "public_key": hex::encode(server_key.verifying_key().to_bytes()),
            "key_version": 1,
        })
    }

    #[tokio::test]
    async fn valid_push_returns_counter_signature() {
        let state = make_state();
        let node_pub = state.signing_key.verifying_key().to_bytes();
        let app = router(state);

        let server_key = DalekKey::generate(&mut OsRng);
        let body = valid_push_body(&server_key);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/push")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let pr: PushResponse = serde_json::from_slice(&bytes).unwrap();

        // Counter-signature public key must match the node's key.
        assert_eq!(pr.public_key, hex::encode(node_pub));

        // Verify the counter-signature over the original STH payload.
        let root_hash = hex::decode(&body["root_hash"].as_str().unwrap()).unwrap();
        let root_arr: [u8; 32] = root_hash.try_into().unwrap();
        let payload = signing_payload(
            body["tree_size"].as_u64().unwrap(),
            &root_arr,
            body["timestamp_ns"].as_i64().unwrap(),
        );
        let sig_bytes = hex::decode(&pr.counter_signature).unwrap();
        let sig: [u8; 64] = sig_bytes.try_into().unwrap();
        let key_bytes = hex::decode(&pr.public_key).unwrap();
        let key_arr: [u8; 32] = key_bytes.try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_arr).unwrap();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(verifying_key.verify_strict(&payload, &dalek_sig).is_ok());
    }

    #[tokio::test]
    async fn invalid_signature_returns_400() {
        let state = make_state();
        let app = router(state);

        let body = serde_json::json!({
            "tree_size": 1u64,
            "root_hash": hex::encode([0u8; 32]),
            "timestamp_ns": 0i64,
            "signature": hex::encode([0u8; 64]),
            "public_key": hex::encode([0u8; 32]),
            "key_version": 1,
        });

        let req = Request::builder()
            .method(Method::POST)
            .uri("/push")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn archive_retrieval() {
        let state = make_state();
        let app = router(state);

        let server_key = DalekKey::generate(&mut OsRng);
        let body = valid_push_body(&server_key);

        // Push first.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/push")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        app.clone().oneshot(req).await.unwrap();

        // Retrieve from archive.
        let tree_size = body["tree_size"].as_u64().unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/archive/{tree_size}"))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let archived: ArchivedSth = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(archived.tree_size, tree_size);
    }

    #[tokio::test]
    async fn archive_not_found_returns_404() {
        let state = make_state();
        let app = router(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/archive/999")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
