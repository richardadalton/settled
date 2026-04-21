use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;

use crate::state::AppState;

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn metrics() -> Result<String, StatusCode> {
    crate::metrics::gather_text().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .with_state(state)
}
