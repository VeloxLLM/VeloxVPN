//! Hysteria2 protocol (inbound + outbound) over QUIC.
//!
//! sing-box compatible:
//! - Auth is sent as the first message on a **uni-directional stream**:
//!   `[TID=0x00][opcode=0x05][len:2 BE][password]`
//! - TCP relay uses **bi-directional streams** with header:
//!   `[version=0x03][payload_len:2 BE][ATYP][addr][port:2 BE]`

use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;

use crate::proxy::Addr;
use crate::tls::TlsIdentity;

/// Start a Hysteria2 inbound. Returns (bound addr, task handle).
pub async fn serve(
    listen: &str,
    password: String,
    server_cfg: quinn::ServerConfig,
) -> Result<(SocketAddr, JoinHandle<Result<(), String>>), String> {
    let addr: SocketAddr = listen.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    let endpoint = quinn::Endpoint::server(server_cfg, addr).map_err(|e| e.to_string())?;
    let local = endpoint.local_addr().map_err(|e| e.to_string())?;
    let handle = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let password = password.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!("hy2 connect error: {e}");
                        return;
                    }
                };
                handle_conn(conn, &password).await;
            });
        }
        Ok(())
    });
    Ok((local, handle))
}

/// Server: read auth from the first uni stream, then relay TCP on bi streams.
async fn handle_conn(conn: quinn::Connection, password: &str) {
    let mut recv = match conn.accept_uni().await {
        Ok(x) => x,
        Err(e) => {
            tracing::debug!("hy2 accept auth stream failed: {e}");
            return;
        }
    };
    let mut head = [0u8; 4];
    if recv.read_exact(&mut head).await.is_err() {
        tracing::debug!("hy2 read auth header failed");
        return;
    }
    if head[0] != 0x00 || head[1] != 0x05 {
        tracing::debug!("hy2 bad auth header: {head:?}");
        return;
    }
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    let mut pw = vec![0u8; len];
    if let Err(e) = recv.read_exact(&mut pw).await {
        tracing::debug!("hy2 read auth payload failed: {e}");
        return;
    }
    if &pw != password.as_bytes() {
        tracing::debug!("hy2 auth failed ({} vs {})", String::from_utf8_lossy(&pw), password);
        return;
    }
    tracing::debug!("hy2 auth ok");
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(_) => return,
        };
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_stream(send, recv).await {
                tracing::debug!("hy2 stream error: {e}");
            }
        });
    }
}

async fn handle_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), String> {
    let mut ver = [0u8; 1];
    recv.read_exact(&mut ver).await.map_err(|e| e.to_string())?;
    let mut plen = [0u8; 2];
    recv.read_exact(&mut plen).await.map_err(|e| e.to_string())?;
    let mut atyp = [0u8; 1];
    recv.read_exact(&mut atyp).await.map_err(|e| e.to_string())?;
    let target = read_addr(&mut recv, atyp[0]).await?;
    let upstream = target.connect().await.map_err(|e| e.to_string())?;
    let (mut ur, mut uw) = upstream.into_split();
    let a = tokio::io::copy(&mut recv, &mut uw);
    let b = tokio::io::copy(&mut ur, &mut send);
    let _ = tokio::join!(a, b);
    Ok(())
}

async fn read_addr<R: tokio::io::AsyncRead + Unpin>(r: &mut R, atype: u8) -> Result<Addr, String> {
    match atype {
        0x01 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            let mut port = [0u8; 2];
            r.read_exact(&mut port).await.map_err(|e| e.to_string())?;
            Ok(Addr::Ip(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                u16::from_be_bytes(port),
            ))
        }
        0x02 => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len).await.map_err(|e| e.to_string())?;
            let mut dom = vec![0u8; len[0] as usize];
            r.read_exact(&mut dom).await.map_err(|e| e.to_string())?;
            let mut port = [0u8; 2];
            r.read_exact(&mut port).await.map_err(|e| e.to_string())?;
            Ok(Addr::Domain(
                String::from_utf8_lossy(&dom).to_string(),
                u16::from_be_bytes(port),
            ))
        }
        0x03 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            let mut port = [0u8; 2];
            r.read_exact(&mut port).await.map_err(|e| e.to_string())?;
            Ok(Addr::Ip(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(b)),
                u16::from_be_bytes(port),
            ))
        }
        other => Err(format!("unsupported hy2 address type 0x{other:02x}")),
    }
}

/// A connected Hysteria2 client session.
pub struct Hy2Client {
    pub conn: quinn::Connection,
}

impl Hy2Client {
    pub async fn connect(
        identity: &TlsIdentity,
        insecure: bool,
        server: &str,
        port: u16,
        sni: &str,
        password: &str,
    ) -> Result<Self, String> {
        let cfg = crate::tls::quinn_client_config(identity, insecure)?;
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

        // Auth over a uni-directional stream (matches hysteria2 spec / sing-box).
        let mut send = conn.open_uni().await.map_err(|e| e.to_string())?;
        let mut head = vec![0x00u8, 0x05];
        let pw = password.as_bytes();
        head.extend_from_slice(&(pw.len() as u16).to_be_bytes());
        head.extend_from_slice(pw);
        send.write_all(&head).await.map_err(|e| e.to_string())?;
        let _ = send.finish();

        Ok(Hy2Client { conn })
    }

    /// Open a TCP tunnel through the server.
    pub async fn open_tcp(
        &self,
        target: &Addr,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
        let (mut send, recv) = self.conn.open_bi().await.map_err(|e| e.to_string())?;
        let mut head = vec![0x03u8, 0x00, 0x00]; // version, payload len = 0
        target.encode(&mut head);
        send.write_all(&head).await.map_err(|e| e.to_string())?;
        Ok((send, recv))
    }
}
