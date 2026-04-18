use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub key_path: PathBuf,
    pub listen: SocketAddr,
    /// HTTP admin API listen address (settled registry + health).
    pub admin_listen: SocketAddr,
    pub sth_interval_secs: u64,
    /// Mark a settled node dead after this many consecutive push failures.
    pub max_push_failures: u32,
    /// Timeout in ms for each push attempt.
    pub push_timeout_ms: u64,
    /// Minimum number of valid counter-signatures for a FinalSTH to be valid.
    /// 0 = threshold disabled (backwards compatible).
    pub threshold: usize,
}
