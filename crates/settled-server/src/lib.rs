pub mod proto {
    tonic::include_proto!("settled.v1");
}

pub mod admin;
pub mod config;
pub mod error;
pub mod metrics;
pub mod service;
pub mod signer;
pub mod state;
pub mod sth_task;

pub use config::Config;
pub use service::SettledService;
pub use state::AppState;
