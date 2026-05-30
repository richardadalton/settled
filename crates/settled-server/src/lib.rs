pub mod proto {
    tonic::include_proto!("settled.v1");
}

/// Compiled file descriptor set for gRPC reflection.
pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("settled.v1.descriptor");

pub mod admin;
pub mod config;
pub mod error;
pub mod metrics;
pub mod rate_limit;
pub mod service;
pub mod signer;
pub mod state;
pub mod sth_task;

pub use config::Config;
pub use service::SettledService;
pub use state::AppState;
