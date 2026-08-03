//! Configuration model, persistence and first-start randomization.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::util;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    #[serde(default = "default_user")]
    pub user: String,
    /// Legacy plaintext password. Read during migration but never persisted again.
    #[serde(default = "default_password", skip_serializing)]
    pub password: String,
    #[serde(default)]
    pub password_hash: String,
    #[serde(default = "default_ui_title")]
    pub title: String,
}

fn default_user() -> String {
    "admin".to_string()
}

fn default_password() -> String {
    String::new()
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
                user: "admin".to_string(),
                password: util::random_token(20),
                password_hash: String::new(),
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
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let new_config = !path.exists();
        let mut cfg = if path.exists() {
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            serde_json::from_str(&text).map_err(|e| e.to_string())?
        } else {
            Config::default()
        };

        let mut changed = false;

        // Assign available random ports once and persist them. If another
        // process wins the check-to-bind race during first-start generation,
        // regenerate only the ports that were missing in this load.
        let newly_assigned: Vec<usize> = cfg
            .inbounds
            .iter()
            .enumerate()
            .filter_map(|(index, inb)| {
                (inb.port == 0 && inb.port_assigned.is_none()).then_some(index)
            })
            .collect();
        changed |= cfg.assign_missing_ports()?;

        // Migrate plaintext/default credentials to Argon2id. New installations
        // receive the one-time password in a mode-0600 bootstrap file.
        if cfg.web.password_hash.is_empty() {
            let replace_legacy_password =
                cfg.web.password.is_empty() || cfg.web.password == "admin1234";
            let password = if replace_legacy_password {
                util::random_token(20)
            } else {
                cfg.web.password.clone()
            };
            cfg.web.password_hash = util::hash_password(&password)?;
            cfg.web.password.clear();
            if new_config || replace_legacy_password {
                let bootstrap = path.with_file_name("initial-admin-password.txt");
                std::fs::write(
                    &bootstrap,
                    format!("username={}\npassword={password}\n", cfg.web.user),
                )
                .map_err(|e| e.to_string())?;
                util::restrict_file_permissions(&bootstrap)?;
            }
            changed = true;
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

        cfg.validate()?;
        let mut availability = cfg.ensure_ports_available();
        for _ in 0..16 {
            if availability.is_ok() || newly_assigned.is_empty() {
                break;
            }
            for index in &newly_assigned {
                cfg.inbounds[*index].port_assigned = None;
            }
            cfg.assign_missing_ports()?;
            availability = cfg.ensure_ports_available();
        }
        availability?;
        if changed || new_config {
            cfg.save(path)?;
        }
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
        temp.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        temp.as_file().sync_all().map_err(|e| e.to_string())?;
        temp.persist(path).map_err(|e| e.error.to_string())?;
        util::restrict_file_permissions(path)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.web.listen.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!("invalid web listen address: {}", self.web.listen));
        }
        let mut names = HashSet::new();
        let mut ports = HashSet::new();
        for inb in &self.inbounds {
            if inb.name.trim().is_empty() || !names.insert(inb.name.clone()) {
                return Err(format!("empty or duplicate inbound name: {}", inb.name));
            }
            let port = inb.effective_port();
            if port == 0 {
                return Err(format!("inbound {} has no assigned port", inb.name));
            }
            let udp = inb.typ == Protocol::Tuic;
            if !ports.insert((udp, port)) {
                return Err(format!("duplicate inbound socket for {}", inb.name));
            }
            match inb.typ {
                Protocol::Vless => {
                    let uuid = inb
                        .uuid
                        .as_deref()
                        .ok_or_else(|| format!("VLESS inbound {} requires uuid", inb.name))?;
                    uuid::Uuid::parse_str(uuid)
                        .map_err(|_| format!("VLESS inbound {} has invalid uuid", inb.name))?;
                    if !matches!(inb.network.as_deref(), None | Some("tcp") | Some("ws")) {
                        return Err(format!("VLESS inbound {} has invalid network", inb.name));
                    }
                    if inb.network.as_deref() == Some("ws")
                        && !inb.path.as_deref().is_some_and(|p| p.starts_with('/'))
                    {
                        return Err(format!(
                            "VLESS inbound {} requires an absolute WS path",
                            inb.name
                        ));
                    }
                }
                Protocol::AnyTls | Protocol::Tuic => {
                    if !inb.password.as_deref().is_some_and(|p| !p.is_empty()) {
                        return Err(format!(
                            "{} inbound {} requires password",
                            inb.typ.as_str(),
                            inb.name
                        ));
                    }
                    if inb.typ == Protocol::Tuic {
                        let uuid = inb
                            .uuid
                            .as_deref()
                            .ok_or_else(|| format!("TUIC inbound {} requires uuid", inb.name))?;
                        uuid::Uuid::parse_str(uuid)
                            .map_err(|_| format!("TUIC inbound {} has invalid uuid", inb.name))?;
                    }
                    if inb
                        .sni
                        .as_deref()
                        .is_some_and(|s| s.is_empty() || s.contains(char::is_whitespace))
                    {
                        return Err(format!("inbound {} has invalid SNI", inb.name));
                    }
                    if inb
                        .alpn
                        .as_ref()
                        .is_some_and(|a| a.is_empty() || a.iter().any(String::is_empty))
                    {
                        return Err(format!("inbound {} has invalid ALPN", inb.name));
                    }
                }
            }
        }
        Ok(())
    }

    fn ensure_ports_available(&self) -> Result<(), String> {
        for inb in &self.inbounds {
            let addr = format!("{}:{}", inb.listen, inb.effective_port());
            let available = if inb.typ == Protocol::Tuic {
                UdpSocket::bind(&addr).is_ok()
            } else {
                TcpListener::bind(&addr).is_ok()
            };
            if !available {
                return Err(format!("inbound socket is already in use: {addr}"));
            }
        }
        Ok(())
    }

    pub fn assign_missing_ports(&mut self) -> Result<bool, String> {
        let mut selected: HashSet<(bool, u16)> = self
            .inbounds
            .iter()
            .filter_map(|inb| {
                let port = inb.effective_port();
                (port != 0).then_some((inb.typ == Protocol::Tuic, port))
            })
            .collect();
        let mut changed = false;
        for inb in &mut self.inbounds {
            if inb.port == 0 && inb.port_assigned.is_none() {
                let port = choose_available_port(&inb.listen, inb.typ, &selected)?;
                selected.insert((inb.typ == Protocol::Tuic, port));
                inb.port_assigned = Some(port);
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Select a fresh candidate for an automatically assigned inbound port.
    /// The caller must still perform the real bind and may retry this method
    /// if another process claims the candidate first.
    pub(crate) fn reassign_auto_port(&mut self, name: &str) -> Result<u16, String> {
        let index = self
            .inbound_index(name)
            .ok_or_else(|| format!("inbound not found: {name}"))?;
        if self.inbounds[index].port != 0 {
            return Err(format!("inbound {name} does not use an automatic port"));
        }
        let selected: HashSet<(bool, u16)> = self
            .inbounds
            .iter()
            .enumerate()
            .filter_map(|(other, inb)| {
                let port = inb.effective_port();
                (other != index && port != 0).then_some((inb.typ == Protocol::Tuic, port))
            })
            .collect();
        let inb = &mut self.inbounds[index];
        let port = choose_available_port(&inb.listen, inb.typ, &selected)?;
        inb.port_assigned = Some(port);
        Ok(port)
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

fn choose_available_port(
    listen: &str,
    protocol: Protocol,
    selected: &HashSet<(bool, u16)>,
) -> Result<u16, String> {
    let udp = protocol == Protocol::Tuic;
    for _ in 0..256 {
        let port = util::random_port();
        if selected.contains(&(udp, port)) {
            continue;
        }
        let addr = format!("{listen}:{port}");
        let available = if udp {
            UdpSocket::bind(&addr).is_ok()
        } else {
            TcpListener::bind(&addr).is_ok()
        };
        if available {
            return Ok(port);
        }
    }
    Err(format!("unable to allocate an available port for {listen}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_start_hashes_credentials_and_persists_ports() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let first = Config::load_or_create(&path).unwrap();
        let ports: Vec<u16> = first
            .inbounds
            .iter()
            .map(InboundConfig::effective_port)
            .collect();
        assert!(ports.iter().all(|port| *port > 0));
        assert!(first.web.password.is_empty());
        assert!(first.web.password_hash.starts_with("$argon2"));
        let bootstrap =
            std::fs::read_to_string(dir.path().join("initial-admin-password.txt")).unwrap();
        let password = bootstrap
            .lines()
            .find_map(|line| line.strip_prefix("password="))
            .unwrap();
        assert!(util::verify_password(&first.web.password_hash, password));
        assert!(!std::fs::read_to_string(&path).unwrap().contains(password));

        let second = Config::load_or_create(&path).unwrap();
        assert_eq!(
            ports,
            second
                .inbounds
                .iter()
                .map(InboundConfig::effective_port)
                .collect::<Vec<_>>()
        );
        assert_eq!(first.subscription.path, second.subscription.path);
        assert_eq!(first.subscription.token, second.subscription.token);
    }

    #[test]
    fn malformed_json_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "{not-json").unwrap();
        assert!(Config::load_or_create(&path).is_err());
    }

    #[test]
    fn legacy_default_password_is_replaced_with_random_bootstrap_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut cfg = Config::default();
        cfg.assign_missing_ports().unwrap();
        cfg.web.password_hash.clear();
        let mut legacy = serde_json::to_value(&cfg).unwrap();
        legacy["web"]["password"] = serde_json::Value::String("admin1234".to_string());
        std::fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let migrated = Config::load_or_create(&path).unwrap();
        assert!(!util::verify_password(
            &migrated.web.password_hash,
            "admin1234"
        ));
        let bootstrap =
            std::fs::read_to_string(dir.path().join("initial-admin-password.txt")).unwrap();
        let password = bootstrap
            .lines()
            .find_map(|line| line.strip_prefix("password="))
            .unwrap();
        assert!(util::verify_password(&migrated.web.password_hash, password));
        assert!(!std::fs::read_to_string(&path).unwrap().contains(password));
    }

    #[test]
    fn custom_plaintext_password_is_hashed_without_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut cfg = Config::default();
        cfg.assign_missing_ports().unwrap();
        cfg.web.password_hash.clear();
        let mut legacy = serde_json::to_value(&cfg).unwrap();
        legacy["web"]["password"] = serde_json::Value::String("known-custom-password".to_string());
        std::fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let migrated = Config::load_or_create(&path).unwrap();
        assert!(util::verify_password(
            &migrated.web.password_hash,
            "known-custom-password"
        ));
        assert!(!dir.path().join("initial-admin-password.txt").exists());
    }

    #[test]
    fn invalid_inbounds_are_rejected() {
        let mut cfg = Config::default();
        cfg.assign_missing_ports().unwrap();
        cfg.inbounds[1].name = cfg.inbounds[0].name.clone();
        assert!(cfg.validate().unwrap_err().contains("duplicate"));

        let mut cfg = Config::default();
        cfg.assign_missing_ports().unwrap();
        cfg.inbounds[0].uuid = Some("invalid".into());
        assert!(cfg.validate().unwrap_err().contains("invalid uuid"));

        let mut cfg = Config::default();
        cfg.assign_missing_ports().unwrap();
        cfg.inbounds[1].password = None;
        assert!(cfg.validate().unwrap_err().contains("requires password"));

        let mut cfg = Config::default();
        cfg.assign_missing_ports().unwrap();
        cfg.inbounds[1].sni = Some("bad sni".into());
        assert!(cfg.validate().unwrap_err().contains("invalid SNI"));

        let mut cfg = Config::default();
        cfg.assign_missing_ports().unwrap();
        cfg.inbounds[2].alpn = Some(vec![]);
        assert!(cfg.validate().unwrap_err().contains("invalid ALPN"));
    }

    #[test]
    fn occupied_port_is_rejected_on_load() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut cfg = Config::default();
        cfg.inbounds.truncate(1);
        cfg.inbounds[0].listen = "127.0.0.1".into();
        cfg.inbounds[0].port = port;
        cfg.inbounds[0].port_assigned = None;
        cfg.web.password_hash = util::hash_password("test-password-123").unwrap();
        cfg.web.password.clear();
        cfg.save(&path).unwrap();
        assert!(Config::load_or_create(&path)
            .unwrap_err()
            .contains("already in use"));
    }
}
