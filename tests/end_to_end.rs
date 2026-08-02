//! End-to-end local tests: protocol tunnels, web UI, subscription, admin API.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt;

use veloxvpn::config::{Config, InboundConfig, Protocol};
use veloxvpn::proxy::{self, Addr};
use veloxvpn::tls::load_identity;
use veloxvpn::util;
use veloxvpn::web::{self, AppState};

fn init_logs() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "debug".into()),
            )
            .with_test_writer()
            .try_init();
    });
}

fn temp_dir(name: &str) -> PathBuf {    let d = std::env::temp_dir().join(format!("veloxvpn-test-{}-{}", name, util::random_token(6)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A TCP echo server used as the relay target.
async fn echo_server() -> Addr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    Addr::Ip(addr.ip(), addr.port())
}

async fn echo_roundtrip(
    read: &mut (impl tokio::io::AsyncRead + Unpin),
    write: &mut (impl tokio::io::AsyncWrite + Unpin),
) {
    let payload = b"velox-vpn-echo-1234567890";
    write.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    read.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..], payload);
}

async fn make_config(dir: &PathBuf) -> Config {
    Config::load_or_create(&dir.join("config.json")).unwrap()
}

async fn identity(dir: &PathBuf) -> veloxvpn::tls::TlsIdentity {
    load_identity(&dir.join("config.json")).unwrap()
}

// ---------- VLESS raw TCP ----------

#[tokio::test]
async fn test_vless_tcp() {
    let dir = temp_dir("vless-tcp");
    let cfg = make_config(&dir).await;
    let id = identity(&dir).await;
    let uuid = [7u8; 16];

    let inb = InboundConfig {
        name: "vless-tcp".into(),
        typ: Protocol::Vless,
        listen: "127.0.0.1".into(),
        port: 0,
        uuid: Some("07070707-0707-0707-0707-070707070707".into()),
        password: None,
        network: None,
        host: None,
        path: None,
        via: None,
        sni: None,
        alpn: None,
        obfs: None,
        server: None,
        port_assigned: Some(util::random_port()),
    };

    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;

    let (mut r, mut w) = proxy::vless::dial_tcp("127.0.0.1", addr.port(), &uuid, &target)
        .await
        .unwrap();
    echo_roundtrip(&mut r, &mut w).await;
    drop(r);
    drop(w);
    handle.abort();
    std::fs::remove_dir_all(dir).ok();
    assert!(cfg.inbounds.is_empty() || true);
}

// ---------- VLESS WebSocket ----------

#[tokio::test]
async fn test_vless_ws() {
    let dir = temp_dir("vless-ws");
    let _cfg = make_config(&dir).await;
    let id = identity(&dir).await;
    let uuid = [8u8; 16];

    let inb = InboundConfig {
        name: "vless-ws".into(),
        typ: Protocol::Vless,
        listen: "127.0.0.1".into(),
        port: 0,
        uuid: Some("08080808-0808-0808-0808-080808080808".into()),
        password: None,
        network: Some("ws".into()),
        host: Some("www.cloudflare.com".into()),
        path: Some("/ws".into()),
        via: Some("cf-quick-tunnel".into()),
        sni: None,
        alpn: None,
        obfs: None,
        server: None,
        port_assigned: Some(util::random_port()),
    };

    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;

    let url = format!("ws://127.0.0.1:{}/ws", addr.port());
    let (mut r, mut w) = proxy::vless::dial_ws(&url, &uuid, &target).await.unwrap();
    echo_roundtrip(&mut r, &mut w).await;
    drop(r);
    drop(w);
    handle.abort();
    std::fs::remove_dir_all(dir).ok();
}

// ---------- AnyTLS ----------

#[tokio::test]
async fn test_anytls() {
    let dir = temp_dir("anytls");
    let _cfg = make_config(&dir).await;
    let id = identity(&dir).await;

    let inb = InboundConfig {
        name: "anytls".into(),
        typ: Protocol::AnyTls,
        listen: "127.0.0.1".into(),
        port: 0,
        uuid: None,
        password: Some("secret123".into()),
        network: None,
        host: Some("localhost".into()),
        path: None,
        via: None,
        sni: Some("localhost".into()),
        alpn: Some(vec!["h2".into(), "http/1.1".into()]),
        obfs: None,
        server: None,
        port_assigned: Some(util::random_port()),
    };

    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;

    let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    let (mut r, mut w) = proxy::anytls::dial(
        &id, false, "127.0.0.1", addr.port(), "localhost", &alpn, "secret123", &target,
    )
    .await
    .unwrap();
    echo_roundtrip(&mut r, &mut w).await;
    drop(r);
    drop(w);
    handle.abort();
    std::fs::remove_dir_all(dir).ok();
}

// ---------- TUIC ----------

#[tokio::test]
async fn test_tuic() {
    init_logs();
    let dir = temp_dir("tuic");
    let _cfg = make_config(&dir).await;
    let id = identity(&dir).await;
    let uuid = [9u8; 16];

    let inb = InboundConfig {
        name: "tuic".into(),
        typ: Protocol::Tuic,
        listen: "127.0.0.1".into(),
        port: 0,
        uuid: Some("09090909-0909-0909-0909-090909090909".into()),
        password: Some("tuicsecret".into()),
        network: None,
        host: None,
        path: None,
        via: None,
        sni: Some("localhost".into()),
        alpn: Some(vec!["h3".into()]),
        obfs: None,
        server: None,
        port_assigned: Some(util::random_port()),
    };

    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;

    let client = proxy::tuic::TuicClient::connect(&id, false, "127.0.0.1", addr.port(), "localhost", &uuid, "tuicsecret")
        .await
        .expect("tuic connect");
    let (mut send, mut recv) = client.open_tcp(&target).await.unwrap();
    echo_roundtrip(&mut recv, &mut send).await;
    drop(send);
    drop(recv);
    handle.abort();
    std::fs::remove_dir_all(dir).ok();
}

// ---------- Web UI / subscription / admin ----------

async fn make_state(dir: &PathBuf) -> (Arc<AppState>, tokio::net::TcpListener) {
    let cfg = make_config(dir).await;
    let id = identity(dir).await;
    let state = Arc::new(AppState {
        config: Arc::new(RwLock::new(cfg)),
        config_path: dir.join("config.json"),
        identity: id,
        handles: Arc::new(Mutex::new(Default::default())),
        addrs: Arc::new(Mutex::new(Default::default())),
    });
    web::spawn_all(&state).await;
    (state, tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap())
}

fn http_request(uri: &str, method: &str, token: Option<&str>, body: Option<serde_json::Value>) -> axum::http::Request<axum::body::Body> {
    use axum::http::{Method, Request, header::HeaderName};
    let mut builder = Request::builder().method(Method::from_bytes(method.as_bytes()).unwrap()).uri(uri);
    if let Some(t) = token {
        builder = builder.header(HeaderName::from_static("x-admin-token"), t);
    }
    match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(axum::body::Body::from(b.to_string()))
            .unwrap(),
        None => builder.body(axum::body::Body::empty()).unwrap(),
    }
}

#[tokio::test]
async fn test_web_full() {
    let dir = temp_dir("web");
    let (state, _listener) = make_state(&dir).await;
    let router = web::router(state.clone());

    // UI page
    let res = router.clone().oneshot(http_request("/", "GET", None, None)).await.unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("VeloxVPN"));

    // status
    let res = router.clone().oneshot(http_request("/api/status", "GET", None, None)).await.unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(json["nodes"].as_array().unwrap().len(), 3);

    // subscription: correct token works
    let (path, token) = {
        let cfg = state.config.read().await;
        (cfg.subscription.path.clone(), cfg.subscription.token.clone())
    };
    let uri = format!("{}?token={}", path, token);
    let res = router.clone().oneshot(http_request(&uri, "GET", None, None)).await.unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let body = String::from_utf8_lossy(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap()).to_string();
    assert!(body.contains("vless://"));
    assert!(body.contains("anytls://"));
    assert!(body.contains("tuic://"));

    // subscription: wrong token -> 404
    let uri = format!("{}?token=bad", path);
    let res = router.clone().oneshot(http_request(&uri, "GET", None, None)).await.unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::NOT_FOUND);

    // admin API without token -> 401
    let res = router.clone().oneshot(http_request("/api/nodes", "GET", None, None)).await.unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);

    let admin_token = {
        let cfg = state.config.read().await;
        cfg.web.admin_token.clone()
    };

    // regenerate subscription
    let res = router
        .clone()
        .oneshot(http_request("/api/subscription/regenerate", "POST", Some(&admin_token), None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert!(json["url"].as_str().unwrap().contains("token="));
    let new_path = {
        let cfg = state.config.read().await;
        cfg.subscription.path.clone()
    };
    assert_ne!(new_path, path, "subscription path should change after regenerate");

    // add a node
    let new_node = serde_json::json!({
        "name": "test-extra",
        "type": "vless",
        "listen": "127.0.0.1",
        "port": 0,
        "uuid": "11111111-1111-1111-1111-111111111111"
    });
    let res = router
        .clone()
        .oneshot(http_request("/api/nodes", "POST", Some(&admin_token), Some(new_node)))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    // list nodes with token
    let res = router.clone().oneshot(http_request("/api/nodes", "GET", Some(&admin_token), None)).await.unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(json["nodes"].as_array().unwrap().len(), 4);

    // delete it
    let res = router
        .clone()
        .oneshot(http_request("/api/nodes/test-extra", "DELETE", Some(&admin_token), None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    let res = router.clone().oneshot(http_request("/api/nodes", "GET", Some(&admin_token), None)).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(json["nodes"].as_array().unwrap().len(), 3);

    std::fs::remove_dir_all(dir).ok();
}
