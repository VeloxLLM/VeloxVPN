//! Local web UI: subscription URL + Cloud9-style admin panel.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::config::{Config, InboundConfig};
use crate::proxy;
use crate::tls::TlsIdentity;
use crate::util;

pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub config_path: PathBuf,
    pub identity: TlsIdentity,
    pub handles: Arc<Mutex<HashMap<String, InboundHandle>>>,
    pub addrs: Arc<Mutex<HashMap<String, SocketAddr>>>,
    pub tunnels: Arc<Mutex<HashMap<String, tokio::process::Child>>>,
    pub runtime: Arc<RwLock<HashMap<String, Value>>>,
    pub events: Arc<Mutex<VecDeque<String>>>,
    pub sessions: Arc<Mutex<HashMap<String, Instant>>>,
    pub login_attempts: Arc<Mutex<RateLimiter>>,
    pub subscription_attempts: Arc<Mutex<RateLimiter>>,
}

type InboundHandle = JoinHandle<Result<(), String>>;

pub struct RateLimiter {
    attempts: VecDeque<Instant>,
    limit: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            attempts: VecDeque::new(),
            limit,
            window,
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        while self
            .attempts
            .front()
            .is_some_and(|at| now.duration_since(*at) >= self.window)
        {
            self.attempts.pop_front();
        }
        if self.attempts.len() >= self.limit {
            return false;
        }
        self.attempts.push_back(now);
        true
    }
}

pub type SharedState = Arc<AppState>;

const MAX_ADMIN_EVENTS: usize = 200;
const PORT_BIND_RETRIES: usize = 16;
const TASK_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(30);

async fn record_event(state: &SharedState, message: impl Into<String>) {
    let mut events = state.events.lock().await;
    push_bounded_event(&mut events, message.into());
}

fn push_bounded_event(events: &mut VecDeque<String>, message: String) {
    events.push_back(message);
    while events.len() > MAX_ADMIN_EVENTS {
        events.pop_front();
    }
}

/// Start all inbounds from the current config.
pub async fn spawn_all(state: &SharedState) -> bool {
    let config = state.config.read().await;
    let mut working = config.clone();
    drop(config);
    let mut all_started = true;
    let mut ports_changed = false;
    for index in 0..working.inbounds.len() {
        let initial = working.inbounds[index].clone();
        record_event(
            state,
            format!("starting {} [{}]", initial.name, initial.typ.as_str()),
        )
        .await;
        state.runtime.write().await.insert(
            initial.name.clone(),
            json!({ "state": "starting", "error": null, "tunnel": "not-required" }),
        );
        let initial_port = working.inbounds[index].effective_port();
        let mut attempts = 0;
        let (inb, started) = loop {
            let candidate = working.inbounds[index].clone();
            match proxy::start_inbound(&candidate, &state.identity).await {
                Ok(started) => break (candidate, Ok(started)),
                Err(error)
                    if candidate.port == 0
                        && attempts < PORT_BIND_RETRIES
                        && is_address_in_use(&error) =>
                {
                    attempts += 1;
                    if let Err(reassign_error) = working.reassign_auto_port(&candidate.name) {
                        break (candidate, Err(reassign_error));
                    }
                }
                Err(error) => break (candidate, Err(error)),
            }
        };
        ports_changed |= inb.effective_port() != initial_port;
        match started {
            Ok((addr, handle)) => {
                state.addrs.lock().await.insert(inb.name.clone(), addr);
                state.handles.lock().await.insert(inb.name.clone(), handle);
                state.runtime.write().await.insert(
                    inb.name.clone(),
                    json!({
                        "state": "listening",
                        "addr": addr.to_string(),
                        "error": null,
                        "tunnel": if inb.via.as_deref() == Some("cf-quick-tunnel") { "starting" } else { "not-required" },
                    }),
                );
                tracing::info!(
                    "inbound {} [{}] listening on {} (via {})",
                    inb.name,
                    inb.typ.as_str(),
                    addr,
                    inb.via.as_deref().unwrap_or("-")
                );
                record_event(
                    state,
                    format!(
                        "listening {} [{}] on port {}",
                        inb.name,
                        inb.typ.as_str(),
                        addr.port()
                    ),
                )
                .await;
                if inb.typ == crate::config::Protocol::Vless
                    && inb.via.as_deref() == Some("cf-quick-tunnel")
                {
                    start_cloudflared(state, &inb).await;
                }
            }
            Err(e) => {
                all_started = false;
                state.runtime.write().await.insert(
                    inb.name.clone(),
                    json!({ "state": "failed", "addr": null, "error": e.clone(), "tunnel": "unavailable" }),
                );
                tracing::error!("failed to start inbound {}: {e}", inb.name);
                record_event(state, format!("failed {}: {e}", inb.name)).await;
            }
        }
    }
    if ports_changed {
        if all_started {
            let mut config = state.config.write().await;
            let mut next = config.clone();
            for inbound in &working.inbounds {
                if let Some(index) = next.inbound_index(&inbound.name) {
                    next.inbounds[index].port_assigned = inbound.port_assigned;
                }
            }
            if next.save(&state.config_path).is_ok() {
                *config = next;
            } else {
                drop(config);
                stop_all(state).await;
                record_event(state, "failed to persist reassigned inbound ports").await;
                all_started = false;
            }
        } else {
            // Do not leave listeners on retry ports that were never persisted.
            stop_all(state).await;
        }
    }
    all_started
}

fn is_address_in_use(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("address already in use")
        || error.contains("os error 98")
        || error.contains("os error 10048")
}

/// Spawn a `cloudflared` quick tunnel for a local inbound and, once ready,
/// persist the random `*.trycloudflare.com` hostname as the public server.
async fn start_cloudflared(state: &SharedState, inb: &InboundConfig) {
    use std::process::Stdio;
    use tokio::io::AsyncBufReadExt;
    use tokio::process::Command;

    let port = inb.effective_port();
    let url = format!("http://127.0.0.1:{port}");
    let mut child = match Command::new("cloudflared")
        .args(["tunnel", "--url", &url])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            if let Some(status) = state.runtime.write().await.get_mut(&inb.name) {
                status["tunnel"] = json!("failed");
                status["error"] = json!(format!("cloudflared unavailable: {e}"));
            }
            tracing::error!("cloudflared not available for {}: {e}", inb.name);
            record_event(
                state,
                format!("tunnel failed {}: cloudflared unavailable", inb.name),
            )
            .await;
            return;
        }
    };
    let stderr = child.stderr.take();
    {
        let state = Arc::clone(state);
        let name = inb.name.clone();
        if let Some(err) = stderr {
            tokio::spawn(async move {
                let mut lines = tokio::io::BufReader::new(err).lines();
                let mut tunnel_ready = false;
                while let Ok(Some(line)) = lines.next_line().await {
                    if tunnel_ready {
                        continue;
                    }
                    if let Some(host) = extract_tunnel_host(&line) {
                        let persisted = {
                            let mut cfg = state.config.write().await;
                            if let Some(idx) = cfg.inbound_index(&name) {
                                if cfg.inbounds[idx].server.as_deref() == Some(host.as_str()) {
                                    true
                                } else {
                                    let mut next = cfg.clone();
                                    next.inbounds[idx].server = Some(host.clone());
                                    if next.save(&state.config_path).is_ok() {
                                        *cfg = next;
                                        true
                                    } else {
                                        false
                                    }
                                }
                            } else {
                                false
                            }
                        };
                        if persisted {
                            tracing::info!("{} public tunnel ready: https://{host}", name);
                            if let Some(status) = state.runtime.write().await.get_mut(&name) {
                                status["tunnel"] = json!("ready");
                            }
                            record_event(&state, format!("tunnel ready {name}")).await;
                        } else {
                            tracing::error!("failed to persist public tunnel address for {name}");
                            if let Some(status) = state.runtime.write().await.get_mut(&name) {
                                status["tunnel"] = json!("failed");
                                status["error"] = json!("failed to persist tunnel address");
                            }
                            record_event(
                                &state,
                                format!("tunnel failed {name}: configuration save failed"),
                            )
                            .await;
                        }
                        tunnel_ready = true;
                    }
                }
                if let Some(status) = state.runtime.write().await.get_mut(&name) {
                    status["tunnel"] = json!("stopped");
                    status["error"] = json!("cloudflared output stream closed");
                }
                record_event(&state, format!("tunnel stopped {name}")).await;
            });
        }
    }
    state.tunnels.lock().await.insert(inb.name.clone(), child);
    {
        let state = Arc::clone(state);
        let name = inb.name.clone();
        tokio::spawn(async move {
            tokio::time::sleep(TUNNEL_READY_TIMEOUT).await;
            let timed_out = {
                let mut runtime = state.runtime.write().await;
                mark_tunnel_readiness_timeout(&mut runtime, &name)
            };
            if timed_out {
                tracing::error!("cloudflared readiness timed out for {name}");
                record_event(&state, format!("tunnel failed {name}: readiness timeout")).await;
            }
        });
    }
}

fn mark_tunnel_readiness_timeout(runtime: &mut HashMap<String, Value>, name: &str) -> bool {
    let Some(status) = runtime.get_mut(name) else {
        return false;
    };
    if status.get("tunnel").and_then(Value::as_str) != Some("starting") {
        return false;
    }
    status["tunnel"] = json!("failed");
    status["error"] = json!("cloudflared readiness timeout");
    true
}

fn extract_tunnel_host(line: &str) -> Option<String> {
    let start = line.find("https://")? + "https://".len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '.' || c == '-'))
        .unwrap_or(rest.len());
    let host = rest[..end].trim_end_matches('.').to_string();
    // Quick-tunnel hostnames look like `<random-words>.trycloudflare.com`.
    // Skip the Cloudflare API endpoint and anything that isn't a random name.
    if host.contains(".trycloudflare.com")
        && host != "api.trycloudflare.com"
        && host != "cftunnel.com"
        && host.split('.').next().is_some_and(|n| n.contains('-'))
    {
        Some(host)
    } else {
        None
    }
}

/// Abort all running inbounds and start them again from config.
pub async fn restart_inbounds(state: &SharedState) -> bool {
    stop_all(state).await;
    spawn_all(state).await
}

/// Stop all listeners and child tunnels without restarting them.
pub async fn stop_all(state: &SharedState) {
    let handles = std::mem::take(&mut *state.handles.lock().await);
    for h in handles.values() {
        h.abort();
    }
    for (name, h) in handles {
        if tokio::time::timeout(TASK_STOP_TIMEOUT, h).await.is_err() {
            tracing::warn!("timed out waiting for inbound task {name} to stop");
        }
    }
    // Stop any cloudflared quick tunnels.
    let tunnels = std::mem::take(&mut *state.tunnels.lock().await);
    for (name, mut tunnel) in tunnels {
        let stopped = tokio::time::timeout(TASK_STOP_TIMEOUT, async {
            let _ = tunnel.kill().await;
            let _ = tunnel.wait().await;
        })
        .await;
        if stopped.is_err() {
            tracing::warn!("timed out waiting for cloudflared task {name} to stop");
        }
    }
    state.addrs.lock().await.clear();
    state.runtime.write().await.clear();
}

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/login", post(login))
        .route("/api/account", post(update_account))
        .route("/api/nodes", get(list_nodes).post(add_node))
        .route(
            "/api/nodes/:name",
            get(get_node).put(update_node).delete(delete_node),
        )
        .route(
            "/api/subscription/regenerate",
            post(regenerate_subscription),
        )
        .route("/api/status", get(status))
        .route("/api/admin/status", get(admin_status))
        .route("/api/subscription", get(get_subscription_text))
        .fallback(subscription_handler)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:",
        ),
    );
    response
}

async fn index() -> impl IntoResponse {
    Html(include_str!("ui.html"))
}

#[derive(serde::Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

/// Login with username + password; returns an eight-hour session token.
async fn login(
    State(state): State<SharedState>,
    Json(body): Json<LoginBody>,
) -> Result<Json<Value>, StatusCode> {
    if !state.login_attempts.lock().await.allow() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let (user, password_hash) = {
        let cfg = state.config.read().await;
        (cfg.web.user.clone(), cfg.web.password_hash.clone())
    };
    if util::constant_time_eq(&body.username, &user)
        && util::verify_password(&password_hash, &body.password)
    {
        let token = util::random_token(48);
        state.sessions.lock().await.insert(
            token.clone(),
            Instant::now() + Duration::from_secs(8 * 60 * 60),
        );
        Ok(Json(
            json!({ "ok": true, "token": token, "username": user }),
        ))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[derive(serde::Deserialize)]
struct AccountBody {
    old_password: String,
    username: Option<String>,
    password: Option<String>,
}

/// Change the login username / password (requires the current password).
async fn update_account(
    headers: HeaderMap,
    State(state): State<SharedState>,
    Json(body): Json<AccountBody>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    if body
        .password
        .as_deref()
        .is_some_and(|password| !password.is_empty() && password.len() < 12)
    {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    {
        let mut cfg = state.config.write().await;
        if !util::verify_password(&cfg.web.password_hash, &body.old_password) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let mut next = cfg.clone();
        if let Some(u) = body.username {
            if !u.is_empty() {
                next.web.user = u;
            }
        }
        if let Some(p) = body.password {
            if !p.is_empty() {
                next.web.password_hash =
                    util::hash_password(&p).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                next.web.password.clear();
            }
        }
        next.save(&state.config_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        *cfg = next;
    }
    state.sessions.lock().await.clear();
    Ok(Json(json!({ "ok": true })))
}

fn unauthorized() -> StatusCode {
    StatusCode::UNAUTHORIZED
}

async fn require_admin(headers: HeaderMap, state: &SharedState) -> Result<(), StatusCode> {
    let got = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let now = Instant::now();
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, expires| *expires > now);
    if sessions
        .iter()
        .any(|(token, _)| util::constant_time_eq(token, got))
    {
        return Ok(());
    }
    Err(unauthorized())
}

/// Serve the subscription at the configured random path.
async fn subscription_handler(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<SharedState>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    if !state.subscription_attempts.lock().await.allow() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let path = req.uri().path().to_string();
    let (sub_path, token, enabled) = {
        let cfg = state.config.read().await;
        (
            cfg.subscription.path.clone(),
            cfg.subscription.token.clone(),
            cfg.subscription.enabled,
        )
    };
    if !enabled || path != sub_path {
        return StatusCode::NOT_FOUND.into_response();
    }
    let got = params.get("token").cloned().unwrap_or_default();
    if !util::constant_time_eq(&got, &token) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let fmt = params
        .get("format")
        .cloned()
        .unwrap_or_else(|| "raw".to_string());
    let cfg = state.config.read().await;
    let body = subscription_body(&cfg.inbounds, &fmt);
    drop(cfg);
    (StatusCode::OK, body).into_response()
}

fn subscription_body(inbounds: &[InboundConfig], fmt: &str) -> String {
    match fmt {
        "clash" => util::build_clash_subscription(inbounds),
        _ => util::build_subscription(inbounds),
    }
}

async fn list_nodes(
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    let cfg = state.config.read().await;
    let addrs = state.addrs.lock().await;
    let runtime = state.runtime.read().await;
    let nodes: Vec<Value> = cfg
        .inbounds
        .iter()
        .map(|inb| {
            json!({
                "name": inb.name,
                "type": inb.typ.as_str(),
                "listen": inb.listen,
                "port": inb.effective_port(),
                "addr": addrs.get(&inb.name).map(|a| a.to_string()),
                "via": inb.via,
                "uuid": inb.uuid,
                "password": inb.password,
                "network": inb.network,
                "host": inb.host,
                "path": inb.path,
                "sni": inb.sni,
                "alpn": inb.alpn,
                "obfs": inb.obfs,
                "runtime": runtime.get(&inb.name),
            })
        })
        .collect();
    Ok(Json(json!({ "nodes": nodes, "listen": cfg.web.listen })))
}

async fn get_node(
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    let cfg = state.config.read().await;
    let inb = cfg
        .inbounds
        .iter()
        .find(|i| i.name == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(json!(inb)))
}

async fn add_node(
    headers: HeaderMap,
    State(state): State<SharedState>,
    Json(inb): Json<InboundConfig>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    {
        let cfg = state.config.read().await;
        if cfg.inbound_index(&inb.name).is_some() {
            return Err(StatusCode::CONFLICT);
        }
    }
    let mut next = state.config.read().await.clone();
    next.inbounds.push(inb);
    next.assign_missing_ports()
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    commit_config(&state, next).await?;
    Ok(Json(json!({ "ok": true })))
}

async fn update_node(
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
    State(state): State<SharedState>,
    Json(mut inb): Json<InboundConfig>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    let cfg = state.config.write().await;
    let idx = cfg.inbound_index(&name).ok_or(StatusCode::NOT_FOUND)?;
    if inb.name != name {
        inb.name = name;
    }
    let mut next = cfg.clone();
    drop(cfg);
    next.inbounds[idx] = inb;
    next.assign_missing_ports()
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    commit_config(&state, next).await?;
    Ok(Json(json!({ "ok": true })))
}

async fn delete_node(
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    let mut next = state.config.read().await.clone();
    let idx = next.inbound_index(&name).ok_or(StatusCode::NOT_FOUND)?;
    next.inbounds.remove(idx);
    commit_config(&state, next).await?;
    Ok(Json(json!({ "ok": true })))
}

/// Validate and start a candidate before persisting it. A failed listener or
/// failed atomic save restores the previous working configuration and listeners.
async fn commit_config(state: &SharedState, next: Config) -> Result<(), StatusCode> {
    next.validate()
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    let previous = state.config.read().await.clone();
    preflight_inbounds(state, &previous, &next).await?;
    *state.config.write().await = next;
    if !restart_inbounds(state).await {
        *state.config.write().await = previous;
        let _ = restart_inbounds(state).await;
        return Err(StatusCode::CONFLICT);
    }

    if state.config.read().await.save(&state.config_path).is_err() {
        *state.config.write().await = previous;
        let _ = restart_inbounds(state).await;
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(())
}

/// Prove every new or changed listener can start before the working listeners
/// are touched. A same-socket update is probed on an ephemeral port because the
/// old listener intentionally keeps ownership of its production port until the
/// candidate protocol/TLS setup has succeeded.
async fn preflight_inbounds(
    state: &SharedState,
    previous: &Config,
    next: &Config,
) -> Result<(), StatusCode> {
    for candidate in &next.inbounds {
        let old = previous
            .inbounds
            .iter()
            .find(|inbound| inbound.name == candidate.name);
        if old == Some(candidate) {
            continue;
        }

        let mut probe = candidate.clone();
        if old.is_some_and(|old| same_socket(old, candidate)) {
            probe.port = 0;
            probe.port_assigned = None;
        }
        match proxy::start_inbound(&probe, &state.identity).await {
            Ok((_, handle)) => {
                handle.abort();
                if tokio::time::timeout(TASK_STOP_TIMEOUT, handle)
                    .await
                    .is_err()
                {
                    tracing::warn!("candidate inbound {} did not stop in time", candidate.name);
                    return Err(StatusCode::CONFLICT);
                }
            }
            Err(error) => {
                tracing::warn!(
                    "candidate inbound {} failed preflight: {error}",
                    candidate.name
                );
                record_event(
                    state,
                    format!("candidate validation failed {}", candidate.name),
                )
                .await;
                return Err(StatusCode::CONFLICT);
            }
        }
    }
    Ok(())
}

fn same_socket(left: &InboundConfig, right: &InboundConfig) -> bool {
    left.listen == right.listen
        && left.effective_port() == right.effective_port()
        && (left.typ == crate::config::Protocol::Tuic)
            == (right.typ == crate::config::Protocol::Tuic)
}

async fn regenerate_subscription(
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    let path = format!("/{}", util::random_token(12));
    let token = util::random_token(32);
    {
        let mut cfg = state.config.write().await;
        let mut next = cfg.clone();
        next.subscription.path = path.clone();
        next.subscription.token = token.clone();
        next.save(&state.config_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        *cfg = next;
    }
    let base = base_url(&state).await;
    Ok(Json(json!({
        "ok": true,
        "url": format!("{base}{path}?token={token}")
    })))
}

async fn get_subscription_text(
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Result<impl IntoResponse, StatusCode> {
    require_admin(headers, &state).await?;
    let fmt = params
        .get("format")
        .cloned()
        .unwrap_or_else(|| "raw".to_string());
    let cfg = state.config.read().await;
    let body = subscription_body(&cfg.inbounds, &fmt);
    Ok((StatusCode::OK, body))
}

async fn base_url(state: &SharedState) -> String {
    let cfg = state.config.read().await;
    let listen = cfg.web.listen.clone();
    let host = listen.split(':').next().unwrap_or("127.0.0.1");
    let port = listen.rsplit(':').next().unwrap_or("8080");
    if host == "0.0.0.0" || host == "::" {
        format!("http://127.0.0.1:{port}")
    } else {
        format!("http://{listen}")
    }
}

async fn refresh_runtime(state: &SharedState) {
    let stopped_tunnels: Vec<(String, String)> = {
        let mut tunnels = state.tunnels.lock().await;
        tunnels
            .iter_mut()
            .filter_map(|(name, child)| match child.try_wait() {
                Ok(Some(status)) => Some((name.clone(), status.to_string())),
                Ok(None) => None,
                Err(error) => Some((name.clone(), error.to_string())),
            })
            .collect()
    };
    if !stopped_tunnels.is_empty() {
        let mut runtime = state.runtime.write().await;
        for (name, reason) in stopped_tunnels {
            if let Some(status) = runtime.get_mut(&name) {
                status["tunnel"] = json!("stopped");
                status["error"] = json!(format!("cloudflared stopped: {reason}"));
            }
        }
    }
}

async fn status(State(state): State<SharedState>) -> Json<Value> {
    refresh_runtime(&state).await;
    let cfg = state.config.read().await;
    let runtime = state.runtime.read().await;
    let nodes: Vec<Value> = cfg
        .inbounds
        .iter()
        .map(|inb| {
            let state = public_node_state(inb, runtime.get(&inb.name));
            json!({
                "name": inb.name,
                "type": inb.typ.as_str(),
                "state": state,
            })
        })
        .collect();
    Json(json!({
        "ok": nodes.iter().all(|node| node["state"] == "listening"),
        "nodes": nodes,
        "subscription": {
            "enabled": cfg.subscription.enabled,
        }
    }))
}

fn public_node_state(inbound: &InboundConfig, runtime: Option<&Value>) -> &'static str {
    let listener = runtime
        .and_then(|value| value.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("configured");
    if listener != "listening" {
        return match listener {
            "starting" => "starting",
            "failed" => "failed",
            _ => "configured",
        };
    }
    if inbound.via.as_deref() != Some("cf-quick-tunnel") {
        return "listening";
    }
    match runtime
        .and_then(|value| value.get("tunnel"))
        .and_then(Value::as_str)
    {
        Some("ready") => "listening",
        Some("starting") => "starting",
        _ => "failed",
    }
}

async fn admin_status(
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    refresh_runtime(&state).await;
    let base = base_url(&state).await;
    let events: Vec<String> = state.events.lock().await.iter().cloned().collect();
    let cfg = state.config.read().await;
    let runtime = state.runtime.read().await;
    let nodes: Vec<Value> = cfg
        .inbounds
        .iter()
        .map(|inb| {
            json!({
                "name": inb.name,
                "type": inb.typ.as_str(),
                "port": inb.effective_port(),
                "via": inb.via,
                "runtime": runtime.get(&inb.name),
            })
        })
        .collect();
    Ok(Json(json!({
        "nodes": nodes,
        "events": events,
        "subscription": {
            "enabled": cfg.subscription.enabled,
            "path": cfg.subscription.path,
            "token": cfg.subscription.token,
            "url": { "base": base }
        }
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_event_buffer_is_bounded() {
        let mut events = VecDeque::new();
        for index in 0..(MAX_ADMIN_EVENTS + 10) {
            push_bounded_event(&mut events, format!("event-{index}"));
        }
        assert_eq!(events.len(), MAX_ADMIN_EVENTS);
        assert_eq!(events.front().unwrap(), "event-10");
    }

    #[test]
    fn tunnel_readiness_timeout_only_changes_starting_state() {
        let mut runtime = HashMap::from([
            (
                "starting".to_string(),
                json!({ "state": "listening", "tunnel": "starting", "error": null }),
            ),
            (
                "ready".to_string(),
                json!({ "state": "listening", "tunnel": "ready", "error": null }),
            ),
        ]);
        assert!(mark_tunnel_readiness_timeout(&mut runtime, "starting"));
        assert_eq!(runtime["starting"]["tunnel"], "failed");
        assert_eq!(
            runtime["starting"]["error"],
            "cloudflared readiness timeout"
        );
        assert!(!mark_tunnel_readiness_timeout(&mut runtime, "ready"));
        assert_eq!(runtime["ready"]["tunnel"], "ready");
        assert!(!mark_tunnel_readiness_timeout(&mut runtime, "missing"));
    }

    #[test]
    fn public_health_requires_quick_tunnel_readiness() {
        let mut inbound = Config::default().inbounds.remove(0);
        let listening = json!({ "state": "listening", "tunnel": "ready" });
        assert_eq!(public_node_state(&inbound, Some(&listening)), "listening");

        let starting = json!({ "state": "listening", "tunnel": "starting" });
        assert_eq!(public_node_state(&inbound, Some(&starting)), "starting");
        let failed = json!({ "state": "listening", "tunnel": "failed" });
        assert_eq!(public_node_state(&inbound, Some(&failed)), "failed");

        inbound.via = None;
        assert_eq!(public_node_state(&inbound, Some(&failed)), "listening");
        assert_eq!(public_node_state(&inbound, None), "configured");
    }
}
