//! AnyTLS protocol (inbound + outbound) — sing-box compatible.
//!
//! Wire format (see anytls-go/docs/protocol.md):
//! - Auth: `[sha256(password):32][padding0_len:2 BE][padding0]`
//! - Session frame: `[cmd:1][stream_id:4 BE][data_len:2 BE][data]`
//!   commands: 0=waste, 1=SYN, 2=PSH, 3=FIN, 4=settings, 5=alert,
//!             6=update padding, 7=SYNACK, 8=heart req, 9=heart resp, 10=server settings
//! - Target address is the first cmdPSH data on a stream, as SocksAddr `[ATYP][addr][port:2 BE]`.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::proxy::Addr;
use crate::tls::TlsIdentity;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const DEFAULT_PADDING_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000\n";

type TlsTcp = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
type SharedWriter = Arc<Mutex<tokio::io::WriteHalf<TlsTcp>>>;

fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + data.len());
    out.push(cmd);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

async fn send_frame<S: tokio::io::AsyncWrite + Unpin>(
    w: &Arc<Mutex<S>>,
    cmd: u8,
    sid: u32,
    data: &[u8],
) -> Result<(), String> {
    let mut w = w.lock().await;
    w.write_all(&frame(cmd, sid, data)).await.map_err(|e| e.to_string())
}

async fn read_exact_len<R: AsyncRead + Unpin>(r: &mut R, n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Start an AnyTLS inbound. Returns (bound addr, task handle).
pub async fn serve(
    listen: &str,
    password: String,
    server_cfg: Arc<rustls::ServerConfig>,
) -> Result<(SocketAddr, JoinHandle<Result<(), String>>), String> {
    let listener = TcpListener::bind(listen).await.map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let acceptor = TlsAcceptor::from(server_cfg);
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("anytls accept error: {e}");
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let password = password.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::debug!("anytls tls handshake failed: {e}");
                        return;
                    }
                };
                if let Err(e) = handle_conn(tls, &password).await {
                    tracing::debug!("anytls connection closed: {e}");
                }
            });
        }
    });
    Ok((addr, handle))
}

/// Server side: auth, then session frame loop.
async fn handle_conn(tls: TlsTcp, password: &str) -> Result<(), String> {
    let (mut r, w) = tokio::io::split(tls);
    let w: SharedWriter = Arc::new(Mutex::new(w));

    // Auth
    let mut sha = [0u8; 32];
    r.read_exact(&mut sha).await.map_err(|e| e.to_string())?;
    if sha != crate::util::sha256_raw(password.as_bytes()) {
        return Err("anytls auth failed".into());
    }
    let mut plen = [0u8; 2];
    r.read_exact(&mut plen).await.map_err(|e| e.to_string())?;
    let plen = u16::from_be_bytes(plen) as usize;
    if plen > 0 {
        let mut pad = vec![0u8; plen];
        r.read_exact(&mut pad).await.map_err(|e| e.to_string())?;
    }

    let peer_version = Arc::new(AtomicU8::new(0));
    let mut streams: std::collections::HashMap<u32, mpsc::UnboundedSender<Vec<u8>>> =
        std::collections::HashMap::new();
    let mut got_settings = false;

    loop {
        let mut hdr = [0u8; 7];
        if r.read_exact(&mut hdr).await.is_err() {
            break;
        }
        let cmd = hdr[0];
        let sid = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
        let data = if len > 0 { read_exact_len(&mut r, len).await? } else { Vec::new() };

        match cmd {
            CMD_PSH => {
                if let Some(tx) = streams.get(&sid) {
                    if !data.is_empty() {
                        let _ = tx.send(data);
                    }
                }
            }
            CMD_SYN => {
                if !got_settings {
                    let _ = send_frame(&w, CMD_ALERT, 0, b"client did not send its settings").await;
                    break;
                }
                if streams.contains_key(&sid) {
                    continue;
                }
                let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                let w = w.clone();
                let pv = peer_version.clone();
                tokio::spawn(async move {
                    stream_handler(sid, rx, w, pv).await;
                });
                streams.insert(sid, tx);
            }
            CMD_FIN => {
                streams.remove(&sid);
            }
            CMD_WASTE => {}
            CMD_SETTINGS => {
                got_settings = true;
                let text = String::from_utf8_lossy(&data);
                let mut v = 0u8;
                for line in text.split('\n') {
                    if let Some((k, val)) = line.split_once('=') {
                        if k == "v" {
                            v = val.trim().parse().unwrap_or(0);
                        }
                    }
                }
                // Padding scheme negotiation: we always send ours.
                let _ = send_frame(&w, CMD_UPDATE_PADDING, 0, DEFAULT_PADDING_SCHEME.as_bytes()).await;
                if v >= 2 {
                    peer_version.store(2, Ordering::Relaxed);
                    let _ = send_frame(&w, CMD_SERVER_SETTINGS, 0, b"v=2\n").await;
                }
            }
            CMD_HEART_REQUEST => {
                let _ = send_frame(&w, CMD_HEART_RESPONSE, sid, &[]).await;
            }
            // client-only commands (SYNACK / server settings / update padding / alert / heart resp)
            _ => {}
        }
    }
    Ok(())
}

/// Server stream handler: read SocksAddr, dial, then relay.
async fn stream_handler(
    sid: u32,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    w: SharedWriter,
    peer_version: Arc<AtomicU8>,
) {
    let mut reader = ChunkedReader::new(rx);
    let target = match read_socksaddr(&mut reader).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("anytls stream {sid} bad target: {e}");
            return;
        }
    };
    let upstream = match target.connect().await {
        Ok(s) => s,
        Err(e) => {
            if peer_version.load(Ordering::Relaxed) >= 2 {
                let _ = send_frame(&w, CMD_SYNACK, sid, e.to_string().as_bytes()).await;
            }
            return;
        }
    };
    if peer_version.load(Ordering::Relaxed) >= 2 {
        let _ = send_frame(&w, CMD_SYNACK, sid, &[]).await;
    }
    let (mut ur, mut uw) = upstream.into_split();
    let w2 = w.clone();
    // upstream -> client (PSH frames)
    let up_task = tokio::spawn(async move {
        let mut buf = [0u8; 16384];
        loop {
            match ur.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send_frame(&w2, CMD_PSH, sid, &buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = send_frame(&w2, CMD_FIN, sid, &[]).await;
    });
    // client -> upstream
    let a = tokio::io::copy(&mut reader, &mut uw);
    let _ = a.await;
    up_task.abort();
}

async fn read_socksaddr<R: AsyncRead + Unpin>(r: &mut R) -> Result<Addr, String> {
    let mut atyp = [0u8; 1];
    r.read_exact(&mut atyp).await.map_err(|e| e.to_string())?;
    match atyp[0] {
        0x01 => {
            let b = read_exact_len(r, 4).await?;
            let port = read_exact_len(r, 2).await?;
            Ok(Addr::Ip(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                u16::from_be_bytes([port[0], port[1]]),
            ))
        }
        0x03 => {
            let len = read_exact_len(r, 1).await?;
            let dom = read_exact_len(r, len[0] as usize).await?;
            let port = read_exact_len(r, 2).await?;
            Ok(Addr::Domain(
                String::from_utf8_lossy(&dom).to_string(),
                u16::from_be_bytes([port[0], port[1]]),
            ))
        }
        0x04 => {
            let b = read_exact_len(r, 16).await?;
            let port = read_exact_len(r, 2).await?;
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&b);
            Ok(Addr::Ip(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(oct)),
                u16::from_be_bytes([port[0], port[1]]),
            ))
        }
        other => Err(format!("unsupported anytls address type 0x{other:02x}")),
    }
}

/// AsyncRead adapter over a stream of Vec<u8> chunks.
pub struct ChunkedReader {
    buf: Vec<u8>,
    pos: usize,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl ChunkedReader {
    fn new(rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        ChunkedReader { buf: Vec::new(), pos: 0, rx }
    }
}

impl AsyncRead for ChunkedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.pos < self.buf.len() {
                let n = std::cmp::min(dst.remaining(), self.buf.len() - self.pos);
                dst.put_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                if self.pos == self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// AnyTLS outbound: one TLS session + single stream per tunnel.
#[allow(clippy::too_many_arguments)]
pub async fn dial(
    identity: &TlsIdentity,
    insecure: bool,
    server: &str,
    port: u16,
    sni: &str,
    alpn: &[String],
    password: &str,
    target: &Addr,
) -> Result<(tokio::io::ReadHalf<tokio::io::DuplexStream>, tokio::io::WriteHalf<tokio::io::DuplexStream>), String>
{
    let tcp = tokio::net::TcpStream::connect(format!("{server}:{port}"))
        .await
        .map_err(|e| e.to_string())?;
    let cfg = crate::tls::rustls_client_config(identity, insecure, alpn)?;
    let connector = TlsConnector::from(cfg);
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|e| format!("sni: {e}"))?;
    let tls = connector.connect(server_name, tcp).await.map_err(|e| e.to_string())?;
    let (mut r, w) = tokio::io::split(tls);
    let w = Arc::new(Mutex::new(w));

    // Auth: sha256(password) + padding0 len(0)
    let sha = crate::util::sha256_raw(password.as_bytes());
    w.lock().await.write_all(&sha).await.map_err(|e| e.to_string())?;
    w.lock().await.write_all(&[0x00, 0x00]).await.map_err(|e| e.to_string())?;

    // Settings
    let settings = format!(
        "v=2\nclient=veloxvpn/{}\npadding-md5=00000000000000000000000000000000\n",
        env!("CARGO_PKG_VERSION")
    );
    send_frame(&w, CMD_SETTINGS, 0, settings.as_bytes()).await?;

    // Open stream
    let sid = 1u32;
    send_frame(&w, CMD_SYN, sid, &[]).await?;

    // Target as first PSH
    let mut target_buf = Vec::new();
    target.encode(&mut target_buf);
    send_frame(&w, CMD_PSH, sid, &target_buf).await?;

    // Duplex relay
    let (d1, d2) = tokio::io::duplex(256 * 1024);
    let (mut d1r, mut d1w) = tokio::io::split(d1);

    // send task: d1r -> PSH frames
    let w_send = w.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 16384];
        loop {
            match d1r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send_frame(&w_send, CMD_PSH, sid, &buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = send_frame(&w_send, CMD_FIN, sid, &[]).await;
    });

    // recv task: frames -> d1w
    tokio::spawn(async move {
        loop {
            let mut hdr = [0u8; 7];
            if r.read_exact(&mut hdr).await.is_err() {
                break;
            }
            let cmd = hdr[0];
            let fsid = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
            let len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
            let data = match read_exact_len(&mut r, len).await {
                Ok(d) => d,
                Err(_) => break,
            };
            match cmd {
                CMD_PSH if fsid == sid => {
                    if d1w.write_all(&data).await.is_err() {
                        break;
                    }
                }
                CMD_FIN if fsid == sid => break,
                CMD_HEART_REQUEST => {
                    let _ = send_frame(&w, CMD_HEART_RESPONSE, fsid, &[]).await;
                }
                _ => {}
            }
        }
        let _ = d1w.shutdown().await;
    });

    let (caller_r, caller_w) = tokio::io::split(d2);
    Ok((caller_r, caller_w))
}
