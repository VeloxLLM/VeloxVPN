//! VLESS protocol (inbound + outbound), raw TCP or WebSocket transport.
//!
//! Header layout (spec-compliant): [version=0x00][uuid:16][addons_len][cmd][port:2 BE][ATYP][addr]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::proxy::{bidirectional, Addr};

/// Encode a VLESS client header for `target`.
pub fn vless_encode_header(uuid: &[u8; 16], target: &Addr, out: &mut Vec<u8>) {
    out.push(0x00); // version
    out.extend_from_slice(uuid);
    out.push(0x00); // addons length
    out.push(0x01); // command: TCP
    out.extend_from_slice(&target.port().to_be_bytes());
    // VLESS address types: 0x01 IPv4, 0x02 domain, 0x03 IPv6
    match target {
        Addr::Ip(std::net::IpAddr::V4(ip), _) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        Addr::Ip(std::net::IpAddr::V6(ip), _) => {
            out.push(0x03);
            out.extend_from_slice(&ip.octets());
        }
        Addr::Domain(host, _) => {
            out.push(0x02);
            let b = host.as_bytes();
            out.push(b.len() as u8);
            out.extend_from_slice(b);
        }
    }
}

/// Read and validate a VLESS header from a stream. Returns the target address.
async fn read_vless_header<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    uuid: &[u8; 16],
) -> Result<Addr, String> {
    let mut byte = [0u8; 1];
    r.read_exact(&mut byte).await.map_err(|e| e.to_string())?;
    if byte[0] != 0x00 {
        return Err(format!("unsupported vless version {}", byte[0]));
    }
    let mut peer = [0u8; 16];
    r.read_exact(&mut peer).await.map_err(|e| e.to_string())?;
    if &peer != uuid {
        return Err("uuid mismatch".into());
    }
    r.read_exact(&mut byte).await.map_err(|e| e.to_string())?; // addons len
    r.read_exact(&mut byte).await.map_err(|e| e.to_string())?; // cmd
    if byte[0] != 0x01 {
        return Err(format!("unsupported vless command {}", byte[0]));
    }
    let mut port = [0u8; 2];
    r.read_exact(&mut port).await.map_err(|e| e.to_string())?;
    let port = u16::from_be_bytes(port);
    r.read_exact(&mut byte).await.map_err(|e| e.to_string())?;
    // VLESS address types: 0x01 IPv4, 0x02 domain, 0x03 IPv6
    match byte[0] {
        0x01 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            Ok(Addr::Ip(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])), port))
        }
        0x02 => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len).await.map_err(|e| e.to_string())?;
            let mut dom = vec![0u8; len[0] as usize];
            r.read_exact(&mut dom).await.map_err(|e| e.to_string())?;
            Ok(Addr::Domain(String::from_utf8_lossy(&dom).to_string(), port))
        }
        0x03 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            Ok(Addr::Ip(IpAddr::V6(Ipv6Addr::from(b)), port))
        }
        other => Err(format!("unsupported address type 0x{other:02x}")),
    }
}

/// Handle one accepted connection: parse header, dial target, relay.
async fn handle_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    uuid: [u8; 16],
) {
    let (mut r, mut w) = tokio::io::split(stream);
    let target = match read_vless_header(&mut r, &uuid).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("vless header rejected: {e}");
            return;
        }
    };
    // VLESS server response header: [version=0][addons_len=0]
    if w.write_all(&[0x00, 0x00]).await.is_err() {
        return;
    }
    let upstream = match target.connect().await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("vless dial {target} failed: {e}");
            return;
        }
    };
    let (mut ur, mut uw) = upstream.into_split();
    bidirectional(&mut r, &mut w, &mut ur, &mut uw).await;
}

/// Start a raw-TCP VLESS inbound. Returns (bound addr, task handle).
pub async fn serve_tcp(
    listen: &str,
    uuid: [u8; 16],
) -> Result<(SocketAddr, JoinHandle<Result<(), String>>), String> {
    let listener = TcpListener::bind(listen).await.map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("vless accept error: {e}");
                    continue;
                }
            };
            let uuid = uuid;
            tokio::spawn(async move { handle_stream(stream, uuid).await });
        }
    });
    Ok((addr, handle))
}

/// Start a WebSocket VLESS inbound (for use behind a Cloudflare quick tunnel).
pub async fn serve_ws(
    listen: &str,
    uuid: [u8; 16],
) -> Result<(SocketAddr, JoinHandle<Result<(), String>>), String> {
    let app = Router::new()
        .fallback(get(ws_upgrade))
        .with_state(uuid);
    let listener = TcpListener::bind(listen).await.map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .map_err(|e| e.to_string())
    });
    Ok((addr, handle))
}

async fn ws_upgrade(ws: WebSocketUpgrade, axum::extract::State(uuid): axum::extract::State<[u8; 16]>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        let duplex = axum_ws_to_duplex(socket).await;
        handle_stream(duplex, uuid).await;
    })
}

/// Pump an axum WebSocket into a byte DuplexStream.
async fn axum_ws_to_duplex(ws: WebSocket) -> tokio::io::DuplexStream {
    let (mut sink, mut stream) = ws.split();
    let (d1, d2) = tokio::io::duplex(256 * 1024);
    let (mut dr, mut dw) = tokio::io::split(d1);

    tokio::spawn(async move {
        while let Some(Ok(msg)) = stream.next().await {
            match msg {
                Message::Binary(b) => {
                    if dw.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Message::Text(t) => {
                    if dw.write_all(t.as_bytes()).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = dw.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match dr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if sink.send(Message::Binary(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = sink.close().await;
    });

    d2
}

/// VLESS outbound over raw TCP.
pub async fn dial_tcp(
    server: &str,
    port: u16,
    uuid: &[u8; 16],
    target: &Addr,
) -> Result<(tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf), String> {
    let mut stream = tokio::net::TcpStream::connect(format!("{server}:{port}"))
        .await
        .map_err(|e| e.to_string())?;
    let mut head = Vec::new();
    vless_encode_header(uuid, target, &mut head);
    stream.write_all(&head).await.map_err(|e| e.to_string())?;
    // consume server response header
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.map_err(|e| e.to_string())?;
    Ok(stream.into_split())
}

/// VLESS outbound over WebSocket. `url` like `ws://host:port/path`.
pub async fn dial_ws(
    url: &str,
    uuid: &[u8; 16],
    target: &Addr,
) -> Result<(tokio::io::ReadHalf<tokio::io::DuplexStream>, tokio::io::WriteHalf<tokio::io::DuplexStream>), String>
{
    let (ws, _resp) = tokio_tungstenite::connect_async(url).await.map_err(|e| e.to_string())?;
    let (mut sink, mut stream) = ws.split();
    let (d1, d2) = tokio::io::duplex(256 * 1024);
    let (mut dr, mut dw) = tokio::io::split(d1);

    tokio::spawn(async move {
        while let Some(Ok(msg)) = stream.next().await {
            match msg {
                tokio_tungstenite::tungstenite::Message::Binary(b) => {
                    if dw.write_all(&b).await.is_err() {
                        break;
                    }
                }
                tokio_tungstenite::tungstenite::Message::Text(t) => {
                    if dw.write_all(t.as_bytes()).await.is_err() {
                        break;
                    }
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = dw.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match dr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if sink
                        .send(tokio_tungstenite::tungstenite::Message::Binary(buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = sink.close().await;
    });

    let mut head = Vec::new();
    vless_encode_header(uuid, target, &mut head);
    let (mut caller_r, mut caller_w) = tokio::io::split(d2);
    caller_w.write_all(&head).await.map_err(|e| e.to_string())?;
    // consume server response header
    let mut resp = [0u8; 2];
    caller_r.read_exact(&mut resp).await.map_err(|e| e.to_string())?;
    Ok((caller_r, caller_w))
}
