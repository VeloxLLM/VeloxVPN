//! End-to-end local tests: protocol tunnels, web UI, subscription, admin API.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt;

use veloxvpn::config::{Config, InboundConfig, Protocol};
use veloxvpn::proxy::{self, Addr};
use veloxvpn::tls::load_identity;
use veloxvpn::util;
use veloxvpn::web::{self, AppState};

async fn network_timeout<T>(label: &str, future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .unwrap_or_else(|_| panic!("{label} timed out"))
}

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

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("veloxvpn-test-{}-{}", name, util::random_token(6)));
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

/// A server that only replies after the client half-closes its upload side.
/// This catches relays that incorrectly cancel the download half on FIN.
async fn reply_after_eof_server() -> Addr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"complete-upload");
        stream.write_all(b"response-after-eof").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    Addr::Ip(addr.ip(), addr.port())
}

async fn echo_roundtrip(
    read: &mut (impl tokio::io::AsyncRead + Unpin),
    write: &mut (impl tokio::io::AsyncWrite + Unpin),
) {
    let payload = b"velox-vpn-echo-1234567890";
    let mut buf = vec![0u8; payload.len()];
    network_timeout("echo roundtrip", async {
        write.write_all(payload).await.unwrap();
        read.read_exact(&mut buf).await.unwrap();
    })
    .await;
    assert_eq!(&buf[..], payload);
}

async fn make_config(dir: &Path) -> Config {
    Config::load_or_create(&dir.join("config.json")).unwrap()
}

async fn identity(dir: &Path) -> veloxvpn::tls::TlsIdentity {
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
        port_assigned: None,
    };

    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;

    let (mut r, mut w) = network_timeout(
        "VLESS TCP dial",
        proxy::vless::dial_tcp("127.0.0.1", addr.port(), &uuid, &target),
    )
    .await
    .unwrap();
    echo_roundtrip(&mut r, &mut w).await;
    drop(r);
    drop(w);
    handle.abort();
    let _ = handle.await;
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
        port_assigned: None,
    };

    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;

    let url = format!("ws://127.0.0.1:{}/ws", addr.port());
    let (mut r, mut w) = network_timeout(
        "VLESS WebSocket dial",
        proxy::vless::dial_ws(&url, &uuid, &target),
    )
    .await
    .unwrap();
    echo_roundtrip(&mut r, &mut w).await;
    drop(r);
    drop(w);
    handle.abort();
    let _ = handle.await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn test_vless_ws_handles_128_concurrent_connections() {
    let dir = temp_dir("vless-ws-concurrency");
    let cfg = make_config(&dir).await;
    let id = identity(&dir).await;
    let inb = cfg.inbounds[0].clone();
    let uuid = proxy::parse_uuid(inb.uuid.as_deref().unwrap()).unwrap();
    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;
    let url = format!("ws://127.0.0.1:{}{}", addr.port(), inb.path.unwrap());

    tokio::time::timeout(Duration::from_secs(20), async {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..128 {
            let url = url.clone();
            let target = target.clone();
            tasks.spawn(async move {
                let (mut read, mut write) =
                    proxy::vless::dial_ws(&url, &uuid, &target).await.unwrap();
                echo_roundtrip(&mut read, &mut write).await;
                write.shutdown().await.unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("128 concurrent VLESS WebSocket connections timed out");

    handle.abort();
    let _ = handle.await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn test_vless_rejects_wrong_uuid_and_ws_path() {
    let dir = temp_dir("vless-negative");
    let cfg = make_config(&dir).await;
    let id = identity(&dir).await;
    let target = echo_server().await;

    let mut tcp = cfg.inbounds[0].clone();
    tcp.network = None;
    tcp.path = None;
    let (addr, handle) = proxy::start_inbound(&tcp, &id).await.unwrap();
    let wrong_uuid = [0x55_u8; 16];
    let rejected = tokio::time::timeout(
        Duration::from_secs(3),
        proxy::vless::dial_tcp("127.0.0.1", addr.port(), &wrong_uuid, &target),
    )
    .await
    .expect("VLESS rejection timed out");
    assert!(rejected.is_err());
    handle.abort();
    let _ = handle.await;

    let ws = cfg.inbounds[0].clone();
    let (addr, handle) = proxy::start_inbound(&ws, &id).await.unwrap();
    let wrong_path = format!("ws://127.0.0.1:{}/not-the-configured-path", addr.port());
    let rejected = network_timeout(
        "wrong VLESS WebSocket path rejection",
        tokio_tungstenite::connect_async(wrong_path),
    )
    .await;
    assert!(rejected.is_err());
    handle.abort();
    let _ = handle.await;
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
        port_assigned: None,
    };

    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;

    let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    let (mut r, mut w) = network_timeout(
        "AnyTLS dial",
        proxy::anytls::dial(
            &id,
            false,
            "127.0.0.1",
            addr.port(),
            "localhost",
            &alpn,
            "secret123",
            &target,
        ),
    )
    .await
    .unwrap();
    echo_roundtrip(&mut r, &mut w).await;
    drop(r);
    drop(w);
    handle.abort();
    let _ = handle.await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn test_anytls_preserves_response_after_client_fin() {
    let dir = temp_dir("anytls-half-close");
    let cfg = make_config(&dir).await;
    let id = identity(&dir).await;
    let inb = cfg.inbounds[1].clone();
    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = reply_after_eof_server().await;
    let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    let (mut read, mut write) = network_timeout(
        "AnyTLS half-close dial",
        proxy::anytls::dial(
            &id,
            false,
            "127.0.0.1",
            addr.port(),
            "localhost",
            &alpn,
            inb.password.as_deref().unwrap(),
            &target,
        ),
    )
    .await
    .unwrap();

    write.write_all(b"complete-upload").await.unwrap();
    write.shutdown().await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), read.read_to_end(&mut response))
        .await
        .expect("AnyTLS response timed out")
        .unwrap();
    assert_eq!(response, b"response-after-eof");

    handle.abort();
    let _ = handle.await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn test_anytls_rejects_wrong_password() {
    let dir = temp_dir("anytls-negative");
    let cfg = make_config(&dir).await;
    let id = identity(&dir).await;
    let inb = cfg.inbounds[1].clone();
    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;
    let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    let (mut read, mut write) = network_timeout(
        "wrong AnyTLS password dial",
        proxy::anytls::dial(
            &id,
            false,
            "127.0.0.1",
            addr.port(),
            "localhost",
            &alpn,
            "wrong-password",
            &target,
        ),
    )
    .await
    .unwrap();
    write.write_all(b"must-not-relay").await.unwrap();
    let mut byte = [0_u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(3), read.read(&mut byte)).await;
    assert!(!matches!(result, Ok(Ok(1))));
    handle.abort();
    let _ = handle.await;
    std::fs::remove_dir_all(dir).ok();
}

/// A UDP echo server used to verify TUIC UDP relay.
async fn udp_echo_server() -> Addr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], src).await;
        }
    });
    Addr::Ip(addr.ip(), addr.port())
}

#[tokio::test]
async fn test_tuic_udp() {
    init_logs();
    let dir = temp_dir("tuic-udp");
    let _cfg = make_config(&dir).await;
    let id = identity(&dir).await;
    let uuid = [10u8; 16];

    let inb = InboundConfig {
        name: "tuic".into(),
        typ: Protocol::Tuic,
        listen: "127.0.0.1".into(),
        port: 0,
        uuid: Some("0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a".into()),
        password: Some("tuicsecret".into()),
        network: None,
        host: None,
        path: None,
        via: None,
        sni: Some("localhost".into()),
        alpn: Some(vec!["h3".into()]),
        obfs: None,
        server: None,
        port_assigned: None,
    };

    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let echo_addr = udp_echo_server().await;

    let client = network_timeout(
        "TUIC UDP connect",
        proxy::tuic::TuicClient::connect(
            &id,
            false,
            "127.0.0.1",
            addr.port(),
            "localhost",
            &uuid,
            "tuicsecret",
        ),
    )
    .await
    .expect("tuic connect");
    let mut udp = client.open_udp().await;

    let payload = b"velox-udp-ping-1234";
    network_timeout("TUIC UDP send", udp.send_to(&echo_addr, payload))
        .await
        .expect("send_to");
    let (src, reply) = tokio::time::timeout(std::time::Duration::from_secs(10), udp.recv())
        .await
        .expect("recv timeout")
        .expect("recv closed");
    assert_eq!(&reply[..], payload);
    assert_eq!(src.port(), echo_addr.port());

    drop(udp);
    handle.abort();
    let _ = handle.await;
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
        port_assigned: None,
    };

    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;

    let client = network_timeout(
        "TUIC TCP connect",
        proxy::tuic::TuicClient::connect(
            &id,
            false,
            "127.0.0.1",
            addr.port(),
            "localhost",
            &uuid,
            "tuicsecret",
        ),
    )
    .await
    .expect("tuic connect");
    let (mut send, mut recv) = network_timeout("TUIC TCP stream", client.open_tcp(&target))
        .await
        .unwrap();
    echo_roundtrip(&mut recv, &mut send).await;
    drop(send);
    drop(recv);
    handle.abort();
    let _ = handle.await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn test_tuic_allows_more_than_default_stream_limit() {
    init_logs();
    let dir = temp_dir("tuic-stream-limit");
    let cfg = make_config(&dir).await;
    let id = identity(&dir).await;
    let inb = cfg.inbounds[2].clone();
    let uuid = proxy::parse_uuid(inb.uuid.as_deref().unwrap()).unwrap();
    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;
    let client = network_timeout(
        "TUIC stream-limit connect",
        proxy::tuic::TuicClient::connect(
            &id,
            false,
            "127.0.0.1",
            addr.port(),
            "localhost",
            &uuid,
            inb.password.as_deref().unwrap(),
        ),
    )
    .await
    .unwrap();

    let mut streams = tokio::time::timeout(Duration::from_secs(10), async {
        let mut streams = Vec::with_capacity(128);
        for _ in 0..128 {
            streams.push(client.open_tcp(&target).await.unwrap());
        }
        streams
    })
    .await
    .expect("opening 128 concurrent TUIC streams timed out");

    for (send, recv) in &mut streams {
        echo_roundtrip(recv, send).await;
    }
    drop(streams);
    handle.abort();
    let _ = handle.await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn test_tuic_rejects_wrong_password() {
    init_logs();
    let dir = temp_dir("tuic-negative");
    let cfg = make_config(&dir).await;
    let id = identity(&dir).await;
    let inb = cfg.inbounds[2].clone();
    let uuid = proxy::parse_uuid(inb.uuid.as_deref().unwrap()).unwrap();
    let (addr, handle) = proxy::start_inbound(&inb, &id).await.unwrap();
    let target = echo_server().await;
    let client = network_timeout(
        "wrong TUIC password connect",
        proxy::tuic::TuicClient::connect(
            &id,
            false,
            "127.0.0.1",
            addr.port(),
            "localhost",
            &uuid,
            "wrong-password",
        ),
    )
    .await
    .unwrap();
    let (mut send, mut recv) =
        network_timeout("wrong TUIC password stream", client.open_tcp(&target))
            .await
            .unwrap();
    send.write_all(b"must-not-relay").await.unwrap();
    let mut byte = [0_u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut byte)).await;
    assert!(!matches!(result, Ok(Ok(Some(1)))));
    handle.abort();
    let _ = handle.await;
    std::fs::remove_dir_all(dir).ok();
}

// ---------- Web UI / subscription / admin ----------

async fn make_state(dir: &Path) -> (Arc<AppState>, tokio::net::TcpListener) {
    let mut cfg = make_config(dir).await;
    cfg.inbounds[0].via = None;
    cfg.web.password_hash = util::hash_password("test-admin-password").unwrap();
    cfg.web.password.clear();
    cfg.save(&dir.join("config.json")).unwrap();
    let id = identity(dir).await;
    let state = Arc::new(AppState {
        config: Arc::new(RwLock::new(cfg)),
        config_path: dir.join("config.json"),
        identity: id,
        handles: Arc::new(Mutex::new(Default::default())),
        addrs: Arc::new(Mutex::new(Default::default())),
        tunnels: Arc::new(Mutex::new(Default::default())),
        runtime: Arc::new(RwLock::new(Default::default())),
        events: Arc::new(Mutex::new(Default::default())),
        sessions: Arc::new(Mutex::new(Default::default())),
        login_attempts: Arc::new(Mutex::new(web::RateLimiter::new(
            100,
            Duration::from_secs(60),
        ))),
        subscription_attempts: Arc::new(Mutex::new(web::RateLimiter::new(
            1_000,
            Duration::from_secs(60),
        ))),
    });
    let _ = web::spawn_all(&state).await;
    (
        state,
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
    )
}

#[tokio::test]
async fn test_spawn_retries_auto_port_lost_to_real_bind_race() {
    let dir = temp_dir("auto-port-bind-retry");
    let mut cfg = make_config(&dir).await;
    cfg.inbounds.truncate(1);
    cfg.inbounds[0].listen = "127.0.0.1".into();
    cfg.inbounds[0].via = None;
    let original_port = cfg.inbounds[0].effective_port();
    cfg.save(&dir.join("config.json")).unwrap();
    let conflict = tokio::net::TcpListener::bind(("127.0.0.1", original_port))
        .await
        .unwrap();
    let state = Arc::new(AppState {
        config: Arc::new(RwLock::new(cfg)),
        config_path: dir.join("config.json"),
        identity: identity(&dir).await,
        handles: Arc::new(Mutex::new(Default::default())),
        addrs: Arc::new(Mutex::new(Default::default())),
        tunnels: Arc::new(Mutex::new(Default::default())),
        runtime: Arc::new(RwLock::new(Default::default())),
        events: Arc::new(Mutex::new(Default::default())),
        sessions: Arc::new(Mutex::new(Default::default())),
        login_attempts: Arc::new(Mutex::new(web::RateLimiter::new(
            100,
            Duration::from_secs(60),
        ))),
        subscription_attempts: Arc::new(Mutex::new(web::RateLimiter::new(
            1_000,
            Duration::from_secs(60),
        ))),
    });

    assert!(web::spawn_all(&state).await);
    let rebound_port = state.config.read().await.inbounds[0].effective_port();
    assert_ne!(rebound_port, original_port);
    assert_eq!(
        state.addrs.lock().await.values().next().unwrap().port(),
        rebound_port
    );
    let persisted: Config =
        serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(persisted.inbounds[0].effective_port(), rebound_port);

    drop(conflict);
    stop_web_test(&state, &dir).await;
}

fn http_request(
    uri: &str,
    method: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> axum::http::Request<axum::body::Body> {
    use axum::http::{header::HeaderName, Method, Request};
    let mut builder = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).unwrap())
        .uri(uri);
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

async fn login(router: &axum::Router, username: &str, password: &str) -> String {
    let res = router
        .clone()
        .oneshot(http_request(
            "/api/login",
            "POST",
            None,
            Some(serde_json::json!({ "username": username, "password": password })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    json["token"].as_str().unwrap().to_string()
}

async fn stop_web_test(state: &Arc<AppState>, dir: &Path) {
    web::stop_all(state).await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn test_web_login_and_public_status() {
    let dir = temp_dir("web");
    let (state, _listener) = make_state(&dir).await;
    let router = web::router(state.clone());

    // UI page
    let res = router
        .clone()
        .oneshot(http_request("/", "GET", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let page = String::from_utf8_lossy(&body);
    assert!(page.contains("VeloxVPN"));
    assert!(page.contains("id=\"statusFilter\""));
    assert!(page.contains("id=\"subUrl\" type=\"password\""));
    assert!(page.contains("class=\"sub masked\" id=\"subText\""));

    let res = router
        .clone()
        .oneshot(http_request("/api/admin/status", "GET", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);

    // Public status is deliberately redacted.
    let res = router
        .clone()
        .oneshot(http_request("/api/status", "GET", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(json["nodes"].as_array().unwrap().len(), 3);
    assert!(json["subscription"]["token"].is_null());
    assert!(json["subscription"]["path"].is_null());

    // admin API without token -> 401
    let res = router
        .clone()
        .oneshot(http_request("/api/nodes", "GET", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);

    let res = router
        .clone()
        .oneshot(http_request(
            "/api/login",
            "POST",
            None,
            Some(serde_json::json!({
                "username": "admin",
                "password": "x".repeat(70 * 1024)
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);

    // login with test credentials
    let res = router
        .clone()
        .oneshot(http_request(
            "/api/login",
            "POST",
            None,
            Some(serde_json::json!({ "username": "admin", "password": "test-admin-password" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let login_token = json["token"].as_str().unwrap().to_string();
    assert_eq!(login_token.len(), 48);

    let res = router
        .clone()
        .oneshot(http_request(
            "/api/admin/status",
            "GET",
            Some(&login_token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let events = json["events"].as_array().unwrap();
    assert!(!events.is_empty());
    assert!(events.iter().all(|event| {
        let event = event.as_str().unwrap();
        !event.contains(&login_token) && !event.contains("test-admin-password")
    }));

    // wrong credentials -> 401
    let res = router
        .clone()
        .oneshot(http_request(
            "/api/login",
            "POST",
            None,
            Some(serde_json::json!({ "username": "admin", "password": "wrong" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);

    stop_web_test(&state, &dir).await;
}

#[tokio::test]
async fn test_web_account_change() {
    let dir = temp_dir("web-account");
    let (state, _listener) = make_state(&dir).await;
    let router = web::router(state.clone());
    let login_token = login(&router, "admin", "test-admin-password").await;

    // change account credentials (requires current password)
    let res = router
        .clone()
        .oneshot(http_request(
            "/api/account",
            "POST",
            Some(&login_token),
            Some(serde_json::json!({ "old_password": "test-admin-password", "username": "boss", "password": "new-password-99" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    assert_eq!(state.config.read().await.web.user, "boss");
    assert!(util::verify_password(
        &state.config.read().await.web.password_hash,
        "new-password-99"
    ));

    let res = router
        .clone()
        .oneshot(http_request("/api/nodes", "GET", Some(&login_token), None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);

    // new credentials work
    let res = router
        .clone()
        .oneshot(http_request(
            "/api/login",
            "POST",
            None,
            Some(serde_json::json!({ "username": "boss", "password": "new-password-99" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    stop_web_test(&state, &dir).await;
}

#[tokio::test]
async fn test_web_subscription() {
    let dir = temp_dir("web-subscription");
    let (state, _listener) = make_state(&dir).await;
    let router = web::router(state.clone());
    let admin_token = login(&router, "admin", "test-admin-password").await;
    let (path, token) = {
        let cfg = state.config.read().await;
        (
            cfg.subscription.path.clone(),
            cfg.subscription.token.clone(),
        )
    };

    let uri = format!("{}?token={}", path, token);
    let res = router
        .clone()
        .oneshot(http_request(&uri, "GET", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let body = String::from_utf8_lossy(
        &axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .to_string();
    assert!(body.contains("vless://"));
    assert!(body.contains("anytls://"));
    assert!(body.contains("tuic://"));

    let uri = format!("{}?token=bad", path);
    let res = router
        .clone()
        .oneshot(http_request(&uri, "GET", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::NOT_FOUND);

    let uri = format!("{}?token={}&format=clash", path, token);
    let res = router
        .clone()
        .oneshot(http_request(&uri, "GET", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let clash = String::from_utf8_lossy(
        &axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .to_string();
    assert!(clash.contains("proxies:"));
    assert!(clash.contains("type: vless"));
    assert!(clash.contains("type: anytls"));
    assert!(clash.contains("type: tuic"));
    assert!(clash.contains("proxy-groups:"));
    assert!(clash.contains("rules:"));

    // regenerate subscription
    let res = router
        .clone()
        .oneshot(http_request(
            "/api/subscription/regenerate",
            "POST",
            Some(&admin_token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(json["url"].as_str().unwrap().contains("token="));
    let new_path = {
        let cfg = state.config.read().await;
        cfg.subscription.path.clone()
    };
    assert_ne!(
        new_path, path,
        "subscription path should change after regenerate"
    );
    let old_uri = format!("{}?token={}", path, token);
    let res = router
        .clone()
        .oneshot(http_request(&old_uri, "GET", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::NOT_FOUND);

    stop_web_test(&state, &dir).await;
}

#[tokio::test]
async fn test_web_node_lifecycle() {
    let dir = temp_dir("web-node-lifecycle");
    let (state, _listener) = make_state(&dir).await;
    let router = web::router(state.clone());
    let admin_token = login(&router, "admin", "test-admin-password").await;

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
        .oneshot(http_request(
            "/api/nodes",
            "POST",
            Some(&admin_token),
            Some(new_node),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    // list nodes with token
    let res = router
        .clone()
        .oneshot(http_request("/api/nodes", "GET", Some(&admin_token), None))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(json["nodes"].as_array().unwrap().len(), 4);

    // delete it
    let res = router
        .clone()
        .oneshot(http_request(
            "/api/nodes/test-extra",
            "DELETE",
            Some(&admin_token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    let res = router
        .clone()
        .oneshot(http_request("/api/nodes", "GET", Some(&admin_token), None))
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(json["nodes"].as_array().unwrap().len(), 3);

    let persisted: Config =
        serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(persisted.inbounds.len(), 3);

    web::stop_all(&state).await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn test_web_failed_node_change_preserves_config_and_listeners() {
    let dir = temp_dir("web-node-rollback");
    let (state, _listener) = make_state(&dir).await;
    let router = web::router(state.clone());
    let admin_token = login(&router, "admin", "test-admin-password").await;
    let config_path = dir.join("config.json");
    let before: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    let before_tasks: std::collections::HashMap<String, tokio::task::Id> = state
        .handles
        .lock()
        .await
        .iter()
        .map(|(name, handle)| (name.clone(), handle.id()))
        .collect();
    let conflict = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let conflict_port = conflict.local_addr().unwrap().port();

    let res = router
        .clone()
        .oneshot(http_request(
            "/api/nodes",
            "POST",
            Some(&admin_token),
            Some(serde_json::json!({
                "name": "must-rollback",
                "type": "vless",
                "listen": "127.0.0.1",
                "port": conflict_port,
                "uuid": "33333333-3333-3333-3333-333333333333"
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::CONFLICT);

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(after, before);
    assert_eq!(state.config.read().await.inbounds.len(), 3);
    assert_eq!(state.handles.lock().await.len(), 3);
    let after_tasks: std::collections::HashMap<String, tokio::task::Id> = state
        .handles
        .lock()
        .await
        .iter()
        .map(|(name, handle)| (name.clone(), handle.id()))
        .collect();
    assert_eq!(
        after_tasks, before_tasks,
        "preflight failure restarted old listeners"
    );
    assert!(state.runtime.read().await.values().all(|status| {
        status.get("state").and_then(serde_json::Value::as_str) == Some("listening")
    }));

    drop(conflict);
    stop_web_test(&state, &dir).await;
}

#[tokio::test]
async fn test_web_failed_save_preserves_account_and_subscription() {
    let dir = temp_dir("web-save-rollback");
    let (state, _listener) = make_state(&dir).await;
    let router = web::router(state.clone());
    let admin_token = login(&router, "admin", "test-admin-password").await;
    let before = state.config.read().await.clone();

    // Replacing the target file with a directory forces atomic persist to fail
    // on both Windows and Unix without relying on root permission semantics.
    let config_path = dir.join("config.json");
    std::fs::remove_file(&config_path).unwrap();
    std::fs::create_dir(&config_path).unwrap();

    let res = router
        .clone()
        .oneshot(http_request(
            "/api/account",
            "POST",
            Some(&admin_token),
            Some(serde_json::json!({
                "old_password": "test-admin-password",
                "username": "must-not-apply",
                "password": "must-not-apply-99"
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    {
        let current = state.config.read().await;
        assert_eq!(current.web.user, before.web.user);
        assert_eq!(current.web.password_hash, before.web.password_hash);
    }

    let res = router
        .clone()
        .oneshot(http_request(
            "/api/subscription/regenerate",
            "POST",
            Some(&admin_token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    {
        let current = state.config.read().await;
        assert_eq!(current.subscription.path, before.subscription.path);
        assert_eq!(current.subscription.token, before.subscription.token);
    }

    stop_web_test(&state, &dir).await;
}

#[tokio::test]
async fn test_web_changes_persist_after_reload() {
    let dir = temp_dir("web-persistence");
    let (state, _listener) = make_state(&dir).await;
    let router = web::router(state.clone());
    let original_path = state.config.read().await.subscription.path.clone();
    let login_token = login(&router, "admin", "test-admin-password").await;

    let res = router
        .clone()
        .oneshot(http_request(
            "/api/account",
            "POST",
            Some(&login_token),
            Some(serde_json::json!({
                "old_password": "test-admin-password",
                "username": "persisted-admin",
                "password": "persisted-password-99"
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    let admin_token = login(&router, "persisted-admin", "persisted-password-99").await;
    let res = router
        .clone()
        .oneshot(http_request(
            "/api/subscription/regenerate",
            "POST",
            Some(&admin_token),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    let res = router
        .clone()
        .oneshot(http_request(
            "/api/nodes",
            "POST",
            Some(&admin_token),
            Some(serde_json::json!({
                "name": "persisted-extra",
                "type": "vless",
                "listen": "127.0.0.1",
                "port": 0,
                "uuid": "22222222-2222-2222-2222-222222222222"
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    web::stop_all(&state).await;
    drop(router);
    drop(state);

    let persisted = Config::load_or_create(&dir.join("config.json")).unwrap();
    assert_eq!(persisted.web.user, "persisted-admin");
    assert!(util::verify_password(
        &persisted.web.password_hash,
        "persisted-password-99"
    ));
    assert_ne!(persisted.subscription.path, original_path);
    assert!(persisted.inbound_index("persisted-extra").is_some());

    std::fs::remove_dir_all(dir).ok();
}
