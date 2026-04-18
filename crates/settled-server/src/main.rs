use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use settled_server::proto::settled_log_server::SettledLogServer;
use settled_server::{AppState, Config, SettledService};
use tonic::transport::Server;

#[derive(Parser)]
#[command(about = "Settled — tamper-evident audit log server")]
struct Args {
    /// Directory for the RocksDB database and default key location
    #[arg(long, default_value = "/var/lib/settled")]
    data_dir: PathBuf,

    /// Path to the Ed25519 signing key (32-byte raw seed).
    /// Defaults to <data_dir>/signing.key; generated on first run if absent.
    #[arg(long)]
    key_path: Option<PathBuf>,

    /// gRPC listen address
    #[arg(long, default_value = "0.0.0.0:50051")]
    listen: SocketAddr,

    /// Seconds between signed tree heads
    #[arg(long, default_value_t = 60)]
    sth_interval_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let key_path = args
        .key_path
        .unwrap_or_else(|| args.data_dir.join("signing.key"));

    let config = Config {
        data_dir: args.data_dir,
        key_path,
        listen: args.listen,
        sth_interval_secs: args.sth_interval_secs,
    };

    let state = AppState::build(config.clone()).await?;

    tokio::spawn(settled_server::sth_task::run(state.clone()));

    tracing::info!("Listening on {}", config.listen);

    Server::builder()
        .add_service(SettledLogServer::new(SettledService::new(state)))
        .serve(config.listen)
        .await?;

    Ok(())
}
