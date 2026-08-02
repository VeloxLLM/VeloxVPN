//! Configuration model, persistence and first-start randomization.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::util;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    AnyTls,
    Tuic,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Vless => "vless",
            Protocol::AnyTls => "anytls",
            Protocol::Tuic => "tuic",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    pub listen: String,
    #[serde(default)]
    pub admin_token: String,
    #[serde(default = "default_ui_title")]
    pub title: String,
}

fn default_ui_title() -> String {
    "VeloxVPN".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub generated: bool,
}

fn default_true() -> bool {
    true
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        SubscriptionConfig {
            enabled: true,
            path: String::new(),
            token: String::new(),
            generated: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub typ: Protocol,
    #[serde(default = "default_listen")]
    pub listen: String,
    /// 0 means "assign a random port on first start and persist it".
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// VLESS transport: "tcp" (default) or "ws".
    #[serde(default)]
    pub network: Option<String>,
    /// WS Host header / SNI-style camouflage.
    #[serde(default)]
    pub host: Option<String>,
    /// WS path.
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub via: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub obfs: Option<String>,
    /// Public-facing server address used when building subscription URIs.
    #[serde(default)]
    pub server: Option<String>,
    /// Persisted random port, set once at first start.
    #[serde(default)]
    pub port_assigned: Option<u16>,
}

fn default_listen() -> String {
    "127.0.0.1".to_string()
}

impl InboundConfig {
    /// Effective port: assigned random port if present, else configured port.
    pub fn effective_port(&self) -> u16 {
        self.port_assigned.unwrap_or(self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub typ: Protocol,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub obfs: Option<String>,
    /// VLESS transport: "tcp" or "ws".
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    /// Skip TLS certificate verification (for self-signed / IP endpoints).
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub web: WebConfig,
    #[serde(default)]
    pub subscription: SubscriptionConfig,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            web: WebConfig {
                listen: "127.0.0.1:8080".to_string(),
                admin_token: util::random_token(24),
                title: "VeloxVPN".to_string(),
            },
            subscription: SubscriptionConfig {
                enabled: true,
                path: format!("/{}", util::random_token(12)),
                token: util::random_token(32),
                generated: true,
            },
            inbounds: vec![
                InboundConfig {
                    name: "vless-tunnel".to_string(),
                    typ: Protocol::Vless,
                    listen: "127.0.0.1".to_string(),
                    port: 0,
                    uuid: Some(uuid::Uuid::new_v4().to_string()),
                    password: None,
                    network: Some("ws".to_string()),
                    host: Some("www.cloudflare.com".to_string()),
                    path: Some(format!("/{}", util::random_token(10))),
                    via: Some("cf-quick-tunnel".to_string()),
                    sni: None,
                    alpn: None,
                    obfs: None,
                    server: None,
                    port_assigned: None,
                },
                InboundConfig {
                    name: "anytls-main".to_string(),
                    typ: Protocol::AnyTls,
                    listen: "0.0.0.0".to_string(),
                    port: 0,
                    uuid: None,
                    password: Some(util::random_token(24)),
                    network: None,
                    host: Some("www.cloudflare.com".to_string()),
                    path: None,
                    via: None,
                    sni: Some("www.cloudflare.com".to_string()),
                    alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
                    obfs: None,
                    server: None,
                    port_assigned: None,
                },
                InboundConfig {
                    name: "tuic-main".to_string(),
                    typ: Protocol::Tuic,
                    listen: "0.0.0.0".to_string(),
                    port: 0,
                    uuid: Some(uuid::Uuid::new_v4().to_string()),
                    password: Some(util::random_token(24)),
                    network: None,
                    host: None,
                    path: None,
                    via: None,
                    sni: Some("www.cloudflare.com".to_string()),
                    alpn: Some(vec!["h3".to_string()]),
                    obfs: None,
                    server: None,
                    port_assigned: None,
                },
            ],
            outbounds: vec![],
        }
    }
}

impl Config {
    /// Load config from disk, creating the default one if missing.
    /// On first start, assigns random ports, generates a subscription path/token,
    /// generates a self-signed TLS certificate and persists everything.
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        let mut cfg = if path.exists() {
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            serde_json::from_str(&text).map_err(|e| e.to_string())?
        } else {
            Config::default()
        };

        let mut changed = false;

        // Assign random ports once and persist them.
        for inb in cfg.inbounds.iter_mut() {
            if inb.port == 0 && inb.port_assigned.is_none() {
                inb.port_assigned = Some(util::random_port());
                changed = true;
            }
        }

        // Generate subscription path/token once.
        if !cfg.subscription.generated {
            cfg.subscription.path = format!("/{}", util::random_token(12));
            cfg.subscription.token = util::random_token(32);
            cfg.subscription.generated = true;
            changed = true;
        }

        // Generate a self-signed certificate for TLS inbound (anytls/tuic) once.
        let cert_file = path.with_file_name("cert.pem");
        let key_file = path.with_file_name("key.pem");
        if !cert_file.exists() || !key_file.exists() {
            let mut sans: Vec<String> = Vec::new();
            for inb in &cfg.inbounds {
                if let Some(s) = &inb.sni {
                    sans.push(s.clone());
                }
                if let Some(s) = &inb.host {
                    sans.push(s.clone());
                }
                if let Some(s) = &inb.server {
                    sans.push(s.clone());
                }
            }
            util::generate_self_signed(&cert_file, &key_file, &sans)?;
            changed = true;
        }

        if changed {
            cfg.save(path)?;
        }
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| e.to_string())
    }

    pub fn inbound_index(&self, name: &str) -> Option<usize> {
        self.inbounds.iter().position(|i| i.name == name)
    }

    pub fn status_map(&self) -> HashMap<String, serde_json::Value> {
        let mut map = HashMap::new();
        for inb in &self.inbounds {
            map.insert(
                inb.name.clone(),
                serde_json::json!({
                    "type": inb.typ.as_str(),
                    "listen": inb.listen,
                    "port": inb.effective_port(),
                    "via": inb.via,
                }),
            );
        }
        map
    }
}

pub fn default_config_path() -> PathBuf {
    let name = env!("CARGO_PKG_NAME");
    let mut dir = dirs_config();
    dir.push(format!("{name}.json"));
    dir
}

fn dirs_config() -> PathBuf {
    if let Ok(p) = std::env::var("VELOXVPN_CONFIG_DIR") {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("APPDATA") {
        let mut d = PathBuf::from(p);
        d.push("VeloxVPN");
        return d;
    }
    PathBuf::from(".")
}
