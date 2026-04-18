use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub key_path: PathBuf,
    pub listen: SocketAddr,
    pub sth_interval_secs: u64,
}
