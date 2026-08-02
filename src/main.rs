use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use tracing_subscriber::EnvFilter;
use veloxvpn::config;
use veloxvpn::tls;
use veloxvpn::web;
use veloxvpn::web::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,veloxvpn=debug")),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| std::env::var("VELOXVPN_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(config::default_config_path);

    let cfg = match config::Config::load_or_create(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to load config {}: {e}", config_path.display());
            std::process::exit(1);
        }
    };
    let identity = match tls::load_identity(&config_path) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("failed to load TLS identity next to {}: {e}", config_path.display());
            std::process::exit(1);
        }
    };

    let state = Arc::new(AppState {
        config: Arc::new(RwLock::new(cfg)),
        config_path,
        identity,
        handles: Arc::new(Mutex::new(Default::default())),
        addrs: Arc::new(Mutex::new(Default::default())),
        tunnels: Arc::new(Mutex::new(Default::default())),
    });

    web::spawn_all(&state).await;

    let (listen, sub_path, sub_token, admin_token, user) = {
        let cfg = state.config.read().await;
        (
            cfg.web.listen.clone(),
            cfg.subscription.path.clone(),
            cfg.subscription.token.clone(),
            cfg.web.admin_token.clone(),
            cfg.web.user.clone(),
        )
    };

    tracing::info!("web UI:       http://{listen}");
    tracing::info!("login:        {user} / <configured password>");
    tracing::info!("admin token:  {admin_token}");
    tracing::info!("subscription: http://{listen}{sub_path}?token={sub_token}");

    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("failed to bind web UI on {listen}: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, web::router(state.clone()))
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!("web server error: {e}");
        std::process::exit(1);
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
