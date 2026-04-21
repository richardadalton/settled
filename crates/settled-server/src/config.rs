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
}
