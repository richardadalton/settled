use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub key_path: PathBuf,
    pub listen: SocketAddr,
    /// HTTP admin API listen address (health, metrics).
    pub admin_listen: SocketAddr,
    pub sth_interval_secs: u64,
    /// If set, every gRPC request must carry `authorization: Bearer <key>`.
    /// If unset, auth is disabled (development mode).
    pub api_key: Option<String>,
    /// Server-wide append rate limit (token bucket). `None` = unlimited.
    pub max_appends_per_sec: Option<u32>,
    /// Maximum entries `GetLatest` may return per call (silently clamped).
    pub max_get_latest: u32,
    /// Maximum gRPC decoding message size in bytes.
    pub max_message_bytes: usize,
}
