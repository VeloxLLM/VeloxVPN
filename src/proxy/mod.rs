//! Proxy inbound lifecycle shared helpers.

pub mod address;
pub mod anytls;
pub mod hy2;
pub mod vless;

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

use crate::config::{InboundConfig, Protocol};
use crate::tls::TlsIdentity;

pub use address::Addr;

/// Bidirectional copy between two stream pairs.
pub async fn bidirectional<R1, W1, R2, W2>(
    r1: &mut R1,
    w1: &mut W1,
    r2: &mut R2,
    w2: &mut W2,
) where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let a = tokio::io::copy(r1, w2);
    let b = tokio::io::copy(r2, w1);
    let _ = tokio::join!(a, b);
}

pub fn parse_uuid(s: &str) -> Result<[u8; 16], String> {
    let u = uuid::Uuid::parse_str(s).map_err(|e| format!("invalid uuid: {e}"))?;
    Ok(*u.as_bytes())
}

/// Start one inbound listener from config. Returns (bound addr, task handle).
pub async fn start_inbound(
    inb: &InboundConfig,
    identity: &TlsIdentity,
) -> Result<(SocketAddr, JoinHandle<Result<(), String>>), String> {
    let port = inb.effective_port();
    let listen = format!("{}:{}", inb.listen, port);
    match inb.typ {
        Protocol::Vless => {
            let uuid = parse_uuid(inb.uuid.as_deref().unwrap_or("00000000-0000-0000-0000-000000000000"))?;
            if inb.network.as_deref() == Some("ws") {
                vless::serve_ws(&listen, uuid).await
            } else {
                vless::serve_tcp(&listen, uuid).await
            }
        }
        Protocol::AnyTls => {
            let password = inb
                .password
                .clone()
                .unwrap_or_else(|| "".to_string());
            let alpn = inb.alpn.clone().unwrap_or_else(|| vec!["h2".into(), "http/1.1".into()]);
            let cfg = crate::tls::rustls_server_config(identity, &alpn)?;
            anytls::serve(&listen, password, cfg).await
        }
        Protocol::Hysteria2 => {
            let password = inb
                .password
                .clone()
                .unwrap_or_else(|| "".to_string());
            let cfg = crate::tls::quinn_server_config(identity)?;
            hy2::serve(&listen, password, cfg).await
        }
    }
}
