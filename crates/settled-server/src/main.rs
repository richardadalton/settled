use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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

/// Resolves on SIGTERM (Unix) or Ctrl-C, whichever arrives first.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl-C"),
        _ = terminate => tracing::info!("Received SIGTERM"),
    }
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

    // Shutdown coordination: one watch channel, multiple receivers.
    let (shutdown_tx, sth_rx) = tokio::sync::watch::channel(false);
    let admin_rx = shutdown_tx.subscribe();

    // STH signing task — runs until shutdown_tx signals it.
    let sth_handle = tokio::spawn(settled_server::sth_task::run(state.clone(), sth_rx));

    // Admin HTTP server with graceful shutdown.
    let admin_listener = TcpListener::bind(config.admin_listen).await?;
    tracing::info!("Admin API listening on {}", config.admin_listen);
    let admin_state = state.clone();
    tokio::spawn(async move {
        axum::serve(admin_listener, settled_server::admin::router(admin_state))
            .with_graceful_shutdown(async move {
                let mut rx = admin_rx;
                let _ = rx.changed().await;
            })
            .await
            .ok();
    });

    if config.api_key.is_none() {
        tracing::warn!("SETTLED_API_KEY is not set — server accepts unauthenticated requests");
    }
    let api_key = config.api_key.clone();
    tracing::info!("gRPC listening on {}", config.listen);

    // gRPC server: blocks until the shutdown signal fires, then drains in-flight RPCs.
    Server::builder()
        .add_service(SettledLogServer::with_interceptor(
            SettledService::new(state),
            #[allow(clippy::result_large_err)]
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
        .serve_with_shutdown(config.listen, shutdown_signal())
        .await?;

    tracing::info!("gRPC drained; shutting down remaining tasks");

    // Notify the STH task and admin server.
    let _ = shutdown_tx.send(true);

    // Wait up to 10 s for the STH task to finish its final signing cycle.
    if tokio::time::timeout(Duration::from_secs(10), sth_handle)
        .await
        .is_err()
    {
        tracing::warn!("STH task did not finish within 10 s");
    }

    tracing::info!("Shutdown complete");
    Ok(())
}
