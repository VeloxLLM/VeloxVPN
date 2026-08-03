use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    if std::env::args().nth(1).as_deref() == Some("health") {
        std::process::exit(run_health_command(std::env::args().skip(2)).await);
    }

    let config_path = config_path_from_args();

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
            tracing::error!(
                "failed to load TLS identity next to {}: {e}",
                config_path.display()
            );
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
        runtime: Arc::new(RwLock::new(Default::default())),
        events: Arc::new(Mutex::new(Default::default())),
        sessions: Arc::new(Mutex::new(Default::default())),
        login_attempts: Arc::new(Mutex::new(web::RateLimiter::new(
            10,
            Duration::from_secs(60),
        ))),
        subscription_attempts: Arc::new(Mutex::new(web::RateLimiter::new(
            120,
            Duration::from_secs(60),
        ))),
    });

    let _ = web::spawn_all(&state).await;

    let (listen, user) = {
        let cfg = state.config.read().await;
        (cfg.web.listen.clone(), cfg.web.user.clone())
    };

    tracing::info!("web UI:       http://{listen}");
    tracing::info!("login:        {user} / <configured password>");
    let bootstrap = state
        .config_path
        .with_file_name("initial-admin-password.txt");
    if bootstrap.exists() {
        tracing::warn!(
            "initial admin credentials: {} (change the password, then remove this file)",
            bootstrap.display()
        );
    }
    tracing::info!("subscription: configured (URL hidden; view it after login)");

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
    web::stop_all(&state).await;
}

async fn run_health_command(args: impl Iterator<Item = String>) -> i32 {
    let mut args = args;
    let mut url = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--url" | "-u" => url = args.next(),
            _ => {
                eprintln!("usage: veloxvpn health --url http://127.0.0.1:18080/api/status");
                return 2;
            }
        }
    }
    let Some(url) = url else {
        eprintln!("usage: veloxvpn health --url http://127.0.0.1:18080/api/status");
        return 2;
    };
    match health_check(&url).await {
        Ok(nodes) => {
            println!("healthy nodes={nodes}");
            0
        }
        Err(error) => {
            eprintln!("unhealthy: {error}");
            1
        }
    }
}

async fn health_check(url: &str) -> Result<usize, String> {
    let (authority, path) = parse_health_url(url)?;
    let mut stream = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(&authority),
    )
    .await
    .map_err(|_| "connection timed out".to_string())?
    .map_err(|error| format!("connection failed: {error}"))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    tokio::time::timeout(Duration::from_secs(3), stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| "request timed out".to_string())?
        .map_err(|error| format!("request failed: {error}"))?;

    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(3),
        stream.take(64 * 1024).read_to_end(&mut response),
    )
    .await
    .map_err(|_| "response timed out".to_string())?
    .map_err(|error| format!("response failed: {error}"))?;
    let response =
        std::str::from_utf8(&response).map_err(|_| "response was not valid UTF-8".to_string())?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response".to_string())?;
    let status = headers.lines().next().unwrap_or_default();
    if !status.contains(" 200 ") {
        return Err(format!("health endpoint returned {status}"));
    }
    let body: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "invalid health JSON".to_string())?;
    if body.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err("service reported an unhealthy node".to_string());
    }
    Ok(body
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len))
}

fn parse_health_url(url: &str) -> Result<(String, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "health URL must use http://".to_string())?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || authority.contains('@') {
        return Err("invalid health URL authority".to_string());
    }
    let authority = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let path = if path.is_empty() {
        "/api/status".to_string()
    } else {
        format!("/{path}")
    };
    Ok((authority, path))
}

fn config_path_from_args() -> PathBuf {
    let mut args = std::env::args().skip(1);
    let mut positional = None;
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            if let Some(value) = args.next() {
                return PathBuf::from(value);
            }
        } else if !arg.starts_with('-') && positional.is_none() {
            positional = Some(PathBuf::from(arg));
        }
    }
    positional
        .or_else(|| std::env::var("VELOXVPN_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(config::default_config_path)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                tracing::error!("failed to install SIGTERM handler: {error}");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn serve_health_once(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{address}/api/status")
    }

    #[test]
    fn health_url_defaults_to_status_path_and_port_80() {
        assert_eq!(
            parse_health_url("http://127.0.0.1").unwrap(),
            ("127.0.0.1:80".to_string(), "/api/status".to_string())
        );
        assert_eq!(
            parse_health_url("http://127.0.0.1:18080/custom").unwrap(),
            ("127.0.0.1:18080".to_string(), "/custom".to_string())
        );
    }

    #[test]
    fn health_url_rejects_tls_and_userinfo() {
        assert!(parse_health_url("https://127.0.0.1/status").is_err());
        assert!(parse_health_url("http://user@127.0.0.1/status").is_err());
    }

    #[tokio::test]
    async fn health_check_uses_public_status_result() {
        let healthy = serve_health_once(r#"{"ok":true,"nodes":[{},{},{}]}"#).await;
        assert_eq!(health_check(&healthy).await.unwrap(), 3);

        let unhealthy = serve_health_once(r#"{"ok":false,"nodes":[{}]}"#).await;
        assert!(health_check(&unhealthy).await.is_err());
    }
}
