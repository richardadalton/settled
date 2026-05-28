use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use settled_server::proto::settled_log_server::SettledLogServer;
use settled_server::{AppState, Config, SettledService};
use tokio::net::TcpListener;
use tonic::transport::Server;

#[derive(Parser)]
#[command(about = "Settled — tamper-evident audit log server")]
struct Args {
    #[arg(long, default_value = "/var/lib/settled")]
    data_dir: PathBuf,

    #[arg(long)]
    key_path: Option<PathBuf>,

    /// gRPC listen address
    #[arg(long, default_value = "0.0.0.0:50051")]
    listen: SocketAddr,

    /// HTTP admin API listen address
    #[arg(long, default_value = "0.0.0.0:8080")]
    admin_listen: SocketAddr,

    #[arg(long, default_value_t = 60)]
    sth_interval_secs: u64,

    /// API key clients must present as `authorization: Bearer <key>`.
    /// Falls back to $SETTLED_API_KEY. If neither is set, auth is disabled (dev mode).
    #[arg(long, env = "SETTLED_API_KEY")]
    api_key: Option<String>,
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
        admin_listen: args.admin_listen,
        sth_interval_secs: args.sth_interval_secs,
        api_key: args.api_key,
    };

    let state = AppState::build(config.clone()).await?;

    tokio::spawn(settled_server::sth_task::run(state.clone()));

    // Launch HTTP admin server.
    let admin_listener = TcpListener::bind(config.admin_listen).await?;
    tracing::info!("Admin API listening on {}", config.admin_listen);
    let admin_state = state.clone();
    tokio::spawn(async move {
        axum::serve(admin_listener, settled_server::admin::router(admin_state))
            .await
            .ok();
    });

    if config.api_key.is_none() {
        tracing::warn!("SETTLED_API_KEY is not set — server accepts unauthenticated requests");
    }
    let api_key = config.api_key.clone();
    tracing::info!("gRPC listening on {}", config.listen);
    Server::builder()
        .add_service(SettledLogServer::with_interceptor(
            SettledService::new(state),
            move |req: tonic::Request<()>| {
                if let Some(ref expected) = api_key {
                    let ok = req
                        .metadata()
                        .get("authorization")
                        .is_some_and(|v| v.as_bytes() == format!("Bearer {expected}").as_bytes());
                    if ok {
                        Ok(req)
                    } else {
                        Err(tonic::Status::unauthenticated("missing or invalid api key"))
                    }
                } else {
                    Ok(req)
                }
            },
        ))
        .serve(config.listen)
        .await?;

    Ok(())
}
