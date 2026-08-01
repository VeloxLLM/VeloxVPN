//! Local web UI: subscription URL + Cloud9-style admin panel.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
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
    pub handles: Arc<Mutex<HashMap<String, JoinHandle<Result<(), String>>>>>,
    pub addrs: Arc<Mutex<HashMap<String, SocketAddr>>>,
}

pub type SharedState = Arc<AppState>;

/// Start all inbounds from the current config.
pub async fn spawn_all(state: &SharedState) {
    let config = state.config.read().await;
    let inbounds = config.inbounds.clone();
    drop(config);
    for inb in &inbounds {
        match proxy::start_inbound(inb, &state.identity).await {
            Ok((addr, handle)) => {
                state
                    .addrs
                    .lock()
                    .await
                    .insert(inb.name.clone(), addr);
                state.handles.lock().await.insert(inb.name.clone(), handle);
                tracing::info!(
                    "inbound {} [{}] listening on {} (via {})",
                    inb.name,
                    inb.typ.as_str(),
                    addr,
                    inb.via.as_deref().unwrap_or("-")
                );
            }
            Err(e) => {
                tracing::error!("failed to start inbound {}: {e}", inb.name);
            }
        }
    }
}

/// Abort all running inbounds and start them again from config.
pub async fn restart_inbounds(state: &SharedState) {
    let handles = std::mem::take(&mut *state.handles.lock().await);
    for (_, h) in &handles {
        h.abort();
    }
    for (_, h) in handles {
        let _ = h.await;
    }
    state.addrs.lock().await.clear();
    spawn_all(state).await;
}

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/nodes", get(list_nodes).post(add_node))
        .route("/api/nodes/:name", get(get_node).put(update_node).delete(delete_node))
        .route("/api/subscription/regenerate", post(regenerate_subscription))
        .route("/api/status", get(status))
        .route("/api/subscription", get(get_subscription_text))
        .fallback(subscription_handler)
        .with_state(state)
}

async fn index() -> impl IntoResponse {
    Html(include_str!("ui.html"))
}

fn unauthorized() -> StatusCode {
    StatusCode::UNAUTHORIZED
}

async fn require_admin(headers: HeaderMap, state: &SharedState) -> Result<(), StatusCode> {
    let token = state.config.read().await.web.admin_token.clone();
    if token.is_empty() {
        return Ok(());
    }
    let got = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if got == token {
        Ok(())
    } else {
        Err(unauthorized())
    }
}

/// Serve the subscription at the configured random path.
async fn subscription_handler(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<SharedState>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
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
    if got != token {
        return StatusCode::NOT_FOUND.into_response();
    }
    let cfg = state.config.read().await;
    let body = util::build_subscription(&cfg.inbounds);
    drop(cfg);
    (StatusCode::OK, body).into_response()
}

async fn list_nodes(
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    let cfg = state.config.read().await;
    let addrs = state.addrs.lock().await;
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
            })
        })
        .collect();
    Ok(Json(
        json!({ "nodes": nodes, "admin_token": cfg.web.admin_token, "listen": cfg.web.listen }),
    ))
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
    Json(mut inb): Json<InboundConfig>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    {
        let cfg = state.config.read().await;
        if cfg.inbound_index(&inb.name).is_some() {
            return Err(StatusCode::CONFLICT);
        }
    }
    if inb.port == 0 && inb.port_assigned.is_none() {
        inb.port_assigned = Some(util::random_port());
    }
    {
        let mut cfg = state.config.write().await;
        cfg.inbounds.push(inb);
        cfg.save(&state.config_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    restart_inbounds(&state).await;
    Ok(Json(json!({ "ok": true })))
}

async fn update_node(
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
    State(state): State<SharedState>,
    Json(mut inb): Json<InboundConfig>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    let mut cfg = state.config.write().await;
    let idx = cfg
        .inbound_index(&name)
        .ok_or(StatusCode::NOT_FOUND)?;
    if inb.name != name {
        inb.name = name;
    }
    if inb.port == 0 && inb.port_assigned.is_none() {
        inb.port_assigned = Some(util::random_port());
    }
    cfg.inbounds[idx] = inb;
    cfg.save(&state.config_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    drop(cfg);
    restart_inbounds(&state).await;
    Ok(Json(json!({ "ok": true })))
}

async fn delete_node(
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Result<Json<Value>, StatusCode> {
    require_admin(headers, &state).await?;
    {
        let mut cfg = state.config.write().await;
        let idx = cfg
            .inbound_index(&name)
            .ok_or(StatusCode::NOT_FOUND)?;
        cfg.inbounds.remove(idx);
        cfg.save(&state.config_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    restart_inbounds(&state).await;
    Ok(Json(json!({ "ok": true })))
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
        cfg.subscription.path = path.clone();
        cfg.subscription.token = token.clone();
        cfg.save(&state.config_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    let base = base_url(&state).await;
    Ok(Json(json!({
        "ok": true,
        "url": format!("{base}{path}?token={token}")
    })))
}

async fn get_subscription_text(
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Result<impl IntoResponse, StatusCode> {
    require_admin(headers, &state).await?;
    let cfg = state.config.read().await;
    let body = util::build_subscription(&cfg.inbounds);
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

async fn status(State(state): State<SharedState>) -> Json<Value> {
    let cfg = state.config.read().await;
    let addrs = state.addrs.lock().await;
    let nodes: Vec<Value> = cfg
        .inbounds
        .iter()
        .map(|inb| {
            let addr = addrs.get(&inb.name).map(|a| a.to_string());
            json!({
                "name": inb.name,
                "type": inb.typ.as_str(),
                "port": inb.effective_port(),
                "addr": addr,
                "via": inb.via,
            })
        })
        .collect();
    Json(json!({
        "nodes": nodes,
        "subscription": {
            "enabled": cfg.subscription.enabled,
            "path": cfg.subscription.path,
            "token": cfg.subscription.token,
            "url": {
                "base": base_url(&state).await,
            }
        }
    }))
}
