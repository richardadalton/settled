use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use settled_storage::SettledRecord;

use crate::state::AppState;

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterBody {
    pub url: String,
}

#[derive(Serialize, Deserialize)]
pub struct SettledRecordView {
    pub url: String,
    pub public_key: Option<String>,
    pub consecutive_failures: u32,
    pub flagged_dead: bool,
    pub registered_at_ns: i64,
}

impl From<SettledRecord> for SettledRecordView {
    fn from(r: SettledRecord) -> Self {
        SettledRecordView {
            url: r.url,
            public_key: r.public_key.map(hex::encode),
            consecutive_failures: r.consecutive_failures,
            flagged_dead: r.flagged_dead,
            registered_at_ns: r.registered_at_ns,
        }
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterBody>,
) -> Result<Json<SettledRecordView>, StatusCode> {
    let url = body.url.trim().to_owned();
    if url.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let registered_at_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;

    let record = SettledRecord {
        url: url.clone(),
        public_key: None,
        consecutive_failures: 0,
        flagged_dead: false,
        registered_at_ns,
    };

    state
        .settled
        .register(&record)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!(%url, "Registered settled node");
    Ok(Json(record.into()))
}

async fn list(
    State(state): State<AppState>,
) -> Result<Json<Vec<SettledRecordView>>, StatusCode> {
    let records = state
        .settled
        .list()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(records.into_iter().map(Into::into).collect()))
}

async fn remove(
    State(state): State<AppState>,
    Path(url): Path<String>,
) -> StatusCode {
    match state.settled.delete(&url) {
        Ok(_) => {
            tracing::info!(%url, "Removed settled node");
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn metrics() -> Result<String, StatusCode> {
    crate::metrics::gather_text().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/settledes", post(register))
        .route("/v1/admin/settledes", get(list))
        .route("/v1/admin/settledes/:url", delete(remove))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .with_state(state)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tempfile::TempDir;
    use tower::ServiceExt;

    use crate::config::Config;
    use crate::state::AppState;

    async fn test_state(dir: &TempDir) -> AppState {
        let config = Config {
            data_dir: dir.path().to_path_buf(),
            key_path: dir.path().join("signing.key"),
            listen: "127.0.0.1:0".parse().unwrap(),
            admin_listen: "127.0.0.1:0".parse().unwrap(),
            sth_interval_secs: 60,
            max_push_failures: 3,
            push_timeout_ms: 1000,
            threshold: 0,
        };
        AppState::build(config).await.unwrap()
    }

    #[tokio::test]
    async fn register_and_list() {
        let dir = TempDir::new().unwrap();
        let state = test_state(&dir).await;
        let app = router(state);

        // Register a settled node.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/admin/settledes")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"url":"http://node1.example.com"}"#))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // List — should return 1 entry.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/admin/settledes")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let records: Vec<SettledRecordView> = serde_json::from_slice(&body).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].url, "http://node1.example.com");
    }

    #[tokio::test]
    async fn delete_settled_node() {
        let dir = TempDir::new().unwrap();
        let state = test_state(&dir).await;
        let app = router(state);

        // Register.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/admin/settledes")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"url":"http://to-delete.example.com"}"#))
            .unwrap();
        app.clone().oneshot(req).await.unwrap();

        // Delete.
        let url_encoded = urlencoding::encode("http://to-delete.example.com");
        let req = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/v1/admin/settledes/{url_encoded}"))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }
}
