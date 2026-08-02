//! Small helpers: randomness, TLS self-signed certs, subscription URI builders.

use std::path::Path;

use rand::Rng;
use sha2::{Digest, Sha256};

use crate::config::{InboundConfig, OutboundConfig, Protocol};

/// Random port in 1024..=65535.
pub fn random_port() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(1024..=65535)
}

const TOKEN_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Random URL-safe token of the given length.
pub fn random_token(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| TOKEN_ALPHABET[rng.gen_range(0..TOKEN_ALPHABET.len())] as char)
        .collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Raw SHA-256 digest (32 bytes).
pub fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Generate a self-signed certificate with the given SANs.
/// Writes PEM files so all TLS inbound share one identity.
pub fn generate_self_signed(cert_path: &Path, key_path: &Path, sans: &[String]) -> Result<(), String> {
    use rcgen::generate_simple_self_signed;
    let mut all = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "*.trycloudflare.com".to_string(),
    ];
    for s in sans {
        if !all.contains(s) {
            all.push(s.clone());
        }
    }
    let certified_key = generate_simple_self_signed(all).map_err(|e| e.to_string())?;
    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.key_pair.serialize_pem();
    std::fs::write(cert_path, cert_pem).map_err(|e| e.to_string())?;
    std::fs::write(key_path, key_pem).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn b64url(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

/// Public address used for subscription URIs: `server` field if set, else listen ip.
pub fn public_host(inb: &InboundConfig, default_port: u16) -> (String, u16) {
    let port = inb.effective_port();
    if let Some(server) = &inb.server {
        let (host, port) = split_host_port(server, port);
        return (host, port);
    }
    let host = match inb.listen.as_str() {
        "0.0.0.0" | "::" => "127.0.0.1".to_string(),
        other => other.to_string(),
    };
    (host, port.max(default_port))
}

fn split_host_port(s: &str, def_port: u16) -> (String, u16) {
    if let Some(idx) = s.rfind(':') {
        if let Ok(p) = s[idx + 1..].parse::<u16>() {
            return (s[..idx].to_string(), p);
        }
    }
    (s.to_string(), def_port)
}

/// Build a single subscription URI for an inbound node.
pub fn build_uri(inb: &InboundConfig) -> Option<String> {
    let name = &inb.name;
    match inb.typ {
        Protocol::Vless => {
            let uuid = inb.uuid.as_ref()?;
            let (host, port) = public_host(inb, 443);
            let network = inb.network.as_deref().unwrap_or("tcp");
            let ws_host = inb.host.as_deref().unwrap_or("www.cloudflare.com");
            let path = inb.path.as_deref().unwrap_or("/");
            if network == "ws" {
                Some(format!(
                    "vless://{uuid}@{host}:{port}?encryption=none&security=tls&type=ws&host={}&path={}#{}",
                    urlencoding::encode(ws_host),
                    urlencoding::encode(path),
                    urlencoding::encode(name)
                ))
            } else {
                Some(format!(
                    "vless://{uuid}@{host}:{port}?encryption=none&security=reality&sni={}#{}",
                    urlencoding::encode(ws_host),
                    urlencoding::encode(name)
                ))
            }
        }
        Protocol::AnyTls => {
            let password = inb.password.as_ref()?;
            let (host, port) = public_host(inb, 443);
            let sni = inb.sni.as_deref().unwrap_or("www.cloudflare.com");
            let alpn = inb
                .alpn
                .as_ref()
                .map(|v| v.join(","))
                .unwrap_or_else(|| "h2,http/1.1".to_string());
            Some(format!(
                "anytls://{}@{}:{}?host={}&alpn={}&insecure=1#{}",
                urlencoding::encode(password),
                host,
                port,
                urlencoding::encode(sni),
                urlencoding::encode(&alpn),
                urlencoding::encode(name)
            ))
        }
        Protocol::Tuic => {
            let uuid = inb.uuid.as_ref()?;
            let password = inb.password.as_deref().unwrap_or("");
            let (host, port) = public_host(inb, 443);
            let sni = inb.sni.as_deref().unwrap_or("www.cloudflare.com");
            Some(format!(
                "tuic://{}:{}@{}:{}?sni={}&alpn=h3&congestion_control=bbr&udp_relay_mode=native#{}",
                urlencoding::encode(uuid),
                urlencoding::encode(password),
                host,
                port,
                urlencoding::encode(sni),
                urlencoding::encode(name)
            ))
        }
    }
}

/// Build the full subscription text (one URI per line).
pub fn build_subscription(inbounds: &[InboundConfig]) -> String {
    inbounds
        .iter()
        .filter_map(build_uri)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build connection parameters for an outbound, used by protocol clients.
pub fn outbound_params(oc: &OutboundConfig) -> ConnParams {
    ConnParams {
        server: oc.server.clone(),
        port: oc.port,
        uuid: oc.uuid.clone(),
        password: oc.password.clone(),
        sni: oc.sni.clone(),
        alpn: oc.alpn.clone(),
        obfs: oc.obfs.clone(),
        network: oc.network.clone(),
        host: oc.host.clone(),
        path: oc.path.clone(),
        insecure: oc.insecure,
    }
}

#[derive(Debug, Clone)]
pub struct ConnParams {
    pub server: String,
    pub port: u16,
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub obfs: Option<String>,
    pub network: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub insecure: bool,
}
