use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

mod server;

#[derive(Parser)]
#[command(about = "Settled node — counter-signing witness for Settled audit logs")]
struct Args {
    /// HTTP listen address
    #[arg(long, default_value = "0.0.0.0:8181")]
    listen: SocketAddr,

    /// Path to this node's Ed25519 signing key (generated if absent)
    #[arg(long)]
    key_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let key_path = args
        .key_path
        .unwrap_or_else(|| PathBuf::from("settled-node.key"));

    let signing_key = server::load_or_generate_key(&key_path)?;
    tracing::info!(
        public_key = hex::encode(signing_key.verifying_key().to_bytes()),
        "Settled node identity"
    );

    let state = Arc::new(server::NodeState {
        signing_key,
        archive: RwLock::new(std::collections::BTreeMap::new()),
    });

    let app = server::router(state);
    let listener = TcpListener::bind(args.listen).await?;
    tracing::info!("Settled node listening on {}", args.listen);
    axum::serve(listener, app).await?;

    Ok(())
}
