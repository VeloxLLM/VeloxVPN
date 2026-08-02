//! TUIC protocol (v0.05) inbound + outbound over QUIC — sing-box compatible.
//!
//! Commands (Big Endian):
//! - `Authenticate (0x00)`: sent on a uni stream: `[VER=0x05][0x00][uuid:16][token:32]`
//!   token = TLS Keying Material Exporter (RFC 5705) with label = UUID string, context = password
//! - `Connect (0x01)`: sent on a bi stream: `[VER][0x01][ADDR]` then TCP relay data
//! - Address: `[TYPE:1][addr][port:2]` where TYPE 0x00=domain(len byte+name), 0x01=IPv4, 0x02=IPv6
//! UDP relaying (0x02/0x03/0x04) is not implemented yet (TCP only).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;

use crate::proxy::Addr;
use crate::tls::TlsIdentity;

const VER: u8 = 0x05;
const CMD_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
#[allow(dead_code)]
const CMD_PACKET: u8 = 0x02;
#[allow(dead_code)]
const CMD_DISSOCIATE: u8 = 0x03;
#[allow(dead_code)]
const CMD_HEARTBEAT: u8 = 0x04;

const AUTH_LEN: usize = 2 + 16 + 32; // VER + CMD + uuid + token

/// Start a TUIC inbound. Returns (bound addr, task handle).
pub async fn serve(
    listen: &str,
    uuid: [u8; 16],
    password: String,
    server_cfg: quinn::ServerConfig,
) -> Result<(SocketAddr, JoinHandle<Result<(), String>>), String> {
    let addr: SocketAddr = listen.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    let endpoint = quinn::Endpoint::server(server_cfg, addr).map_err(|e| e.to_string())?;
    let local = endpoint.local_addr().map_err(|e| e.to_string())?;
    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let uuid = uuid;
            let password = password.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!("tuic connect error: {e}");
                        return;
                    }
                };
                handle_conn(conn, uuid, &password).await;
            });
        }
        Ok(())
    });
    Ok((local, handle))
}

fn compute_token(
    conn: &quinn::Connection,
    uuid: &[u8; 16],
    password: &str,
) -> Result<[u8; 32], String> {
    // Label is the raw 16-byte UUID (matches sing-box `string(uuid[:])`).
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|e| format!("keying material export failed: {e:?}"))?;
    Ok(token)
}

async fn handle_conn(conn: quinn::Connection, uuid: [u8; 16], password: &str) {
    let authenticated = Arc::new(AtomicBool::new(false));
    let notify = Arc::new(tokio::sync::Notify::new());

    // Auth: uni stream with Authenticate command.
    {
        let conn = conn.clone();
        let auth = authenticated.clone();
        let notify = notify.clone();
        let uuid = uuid;
        let password = password.to_string();
        tokio::spawn(async move {
            let mut recv = match conn.accept_uni().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!("tuic accept auth stream failed: {e}");
                    return;
                }
            };
            let mut buf = [0u8; AUTH_LEN];
            if recv.read_exact(&mut buf).await.is_err() {
                return;
            }
            if buf[0] != VER || buf[1] != CMD_AUTH {
                tracing::debug!("tuic bad auth header");
                return;
            }
            let mut peer = [0u8; 16];
            peer.copy_from_slice(&buf[2..18]);
            let token = &buf[18..50];
            if peer != uuid {
                tracing::debug!("tuic uuid mismatch");
                return;
            }
            match compute_token(&conn, &uuid, &password) {
                Ok(expected) if &expected == token => {
                    auth.store(true, Ordering::SeqCst);
                    notify.notify_one();
                    tracing::debug!("tuic auth ok");
                }
                _ => tracing::debug!("tuic auth failed"),
            }
        });
    }

    // Relay loop: bi streams carry Connect commands.
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(_) => return,
        };
        if !authenticated.load(Ordering::SeqCst) {
            notify.notified().await;
            if !authenticated.load(Ordering::SeqCst) {
                return;
            }
        }
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(send, recv).await {
                tracing::debug!("tuic stream error: {e}");
            }
        });
    }
}

async fn handle_tcp(mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<(), String> {
    let mut ver = [0u8; 1];
    recv.read_exact(&mut ver).await.map_err(|e| e.to_string())?;
    let mut cmd = [0u8; 1];
    recv.read_exact(&mut cmd).await.map_err(|e| e.to_string())?;
    if ver[0] != VER || cmd[0] != CMD_CONNECT {
        return Err("bad tuic connect header".into());
    }
    let target = read_addr(&mut recv).await?;
    let upstream = target.connect().await.map_err(|e| e.to_string())?;
    let (mut ur, mut uw) = upstream.into_split();
    let a = tokio::io::copy(&mut recv, &mut uw);
    let b = tokio::io::copy(&mut ur, &mut send);
    let _ = tokio::join!(a, b);
    Ok(())
}

fn encode_addr(addr: &Addr, out: &mut Vec<u8>) {
    match addr {
        Addr::Ip(IpAddr::V4(ip), port) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Addr::Ip(IpAddr::V6(ip), port) => {
            out.push(0x02);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Addr::Domain(host, port) => {
            out.push(0x00);
            let b = host.as_bytes();
            out.push(b.len() as u8);
            out.extend_from_slice(b);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

async fn read_addr<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<Addr, String> {
    let mut t = [0u8; 1];
    r.read_exact(&mut t).await.map_err(|e| e.to_string())?;
    match t[0] {
        0x00 => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len).await.map_err(|e| e.to_string())?;
            let mut dom = vec![0u8; len[0] as usize];
            r.read_exact(&mut dom).await.map_err(|e| e.to_string())?;
            let mut port = [0u8; 2];
            r.read_exact(&mut port).await.map_err(|e| e.to_string())?;
            Ok(Addr::Domain(String::from_utf8_lossy(&dom).to_string(), u16::from_be_bytes(port)))
        }
        0x01 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            let mut port = [0u8; 2];
            r.read_exact(&mut port).await.map_err(|e| e.to_string())?;
            Ok(Addr::Ip(
                IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                u16::from_be_bytes(port),
            ))
        }
        0x02 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            let mut port = [0u8; 2];
            r.read_exact(&mut port).await.map_err(|e| e.to_string())?;
            Ok(Addr::Ip(IpAddr::V6(Ipv6Addr::from(b)), u16::from_be_bytes(port)))
        }
        other => Err(format!("unsupported tuic address type 0x{other:02x}")),
    }
}

/// A connected TUIC client session.
pub struct TuicClient {
    pub conn: quinn::Connection,
}

impl TuicClient {
    pub async fn connect(
        identity: &TlsIdentity,
        insecure: bool,
        server: &str,
        port: u16,
        sni: &str,
        uuid: &[u8; 16],
        password: &str,
    ) -> Result<Self, String> {
        let cfg = crate::tls::quinn_client_config(identity, insecure, &[b"h3"])?;
        let endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let server_addr = tokio::net::lookup_host(format!("{server}:{port}"))
            .await
            .map_err(|e| e.to_string())?
            .next()
            .ok_or_else(|| "no address for server".to_string())?;
        let conn = endpoint
            .connect_with(cfg, server_addr, sni)
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;

        // Authenticate on a uni stream.
        let mut send = conn.open_uni().await.map_err(|e| e.to_string())?;
        let mut buf = vec![VER, CMD_AUTH];
        buf.extend_from_slice(uuid);
        let token = compute_token(&conn, uuid, password)?;
        buf.extend_from_slice(&token);
        send.write_all(&buf).await.map_err(|e| e.to_string())?;
        let _ = send.finish();

        Ok(TuicClient { conn })
    }

    /// Open a TCP tunnel through the server.
    pub async fn open_tcp(
        &self,
        target: &Addr,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
        let (mut send, recv) = self.conn.open_bi().await.map_err(|e| e.to_string())?;
        let mut buf = vec![VER, CMD_CONNECT];
        encode_addr(target, &mut buf);
        send.write_all(&buf).await.map_err(|e| e.to_string())?;
        Ok((send, recv))
    }
}
