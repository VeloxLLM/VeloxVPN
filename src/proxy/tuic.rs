//! TUIC protocol (v0.05) inbound + outbound over QUIC — sing-box compatible.
//!
//! Commands (Big Endian):
//! - `Authenticate (0x00)`: uni stream `[VER=0x05][0x00][uuid:16][token:32]`
//!   token = TLS Keying Material Exporter (RFC 5705), label = raw 16-byte UUID, context = password
//! - `Connect (0x01)`: bi stream `[VER][0x01][ADDR]` then TCP relay data
//! - `Packet (0x02)`: uni stream or datagram
//!   `[VER][0x02][ASSOC:2][PKT_ID:2][FRAG_TOTAL:1][FRAG_ID:1][SIZE:2][ADDR][data:SIZE]`
//! - `Dissociate (0x03)`: uni stream or datagram `[VER][0x03][ASSOC:2]`
//! - `Heartbeat (0x04)`: datagram `[VER][0x04]`
//! - Address: `[TYPE:1][addr][port:2]` TYPE 0x00=domain(len+name), 0x01=IPv4, 0x02=IPv6
//!
//! UDP relaying: 0-RTT full-cone — the server binds a UDP socket per associate ID and
//! relays both directions over QUIC (datagram "native" mode or uni-stream "quic" mode).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::proxy::Addr;
use crate::tls::TlsIdentity;

const VER: u8 = 0x05;
const CMD_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;

const AUTH_LEN: usize = 2 + 16 + 32; // VER + CMD + uuid + token
const AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

type FragmentKey = (u16, u16);
type FragmentList = Vec<(u8, Vec<u8>)>;
type FragmentMap = Arc<Mutex<HashMap<FragmentKey, FragmentList>>>;
type UdpReply = (SocketAddr, Vec<u8>);
type UdpSenderMap = Arc<Mutex<HashMap<u16, mpsc::Sender<UdpReply>>>>;

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
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|e| format!("keying material export failed: {e:?}"))?;
    Ok(token)
}

#[derive(Clone, Copy, PartialEq)]
enum UdpMode {
    Datagram,
    Uni,
}

struct UdpSession {
    socket: Arc<UdpSocket>,
}

struct UdpPacket {
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    addr: Addr,
    data: Vec<u8>,
}

/// Parse a `Packet` command body (starting after the 2-byte command header).
fn parse_packet(b: &[u8]) -> Option<UdpPacket> {
    if b.len() < 8 {
        return None;
    }
    let assoc_id = u16::from_be_bytes([b[0], b[1]]);
    let pkt_id = u16::from_be_bytes([b[2], b[3]]);
    let frag_total = b[4];
    let frag_id = b[5];
    let size = u16::from_be_bytes([b[6], b[7]]) as usize;
    let (addr, used) = parse_addr(&b[8..])?;
    if b.len() < 8 + used + size {
        return None;
    }
    Some(UdpPacket {
        assoc_id,
        pkt_id,
        frag_total,
        frag_id,
        addr,
        data: b[8 + used..8 + used + size].to_vec(),
    })
}

fn parse_addr(b: &[u8]) -> Option<(Addr, usize)> {
    if b.is_empty() {
        return None;
    }
    match b[0] {
        0x00 => {
            let len = *b.get(1)? as usize;
            if b.len() < 2 + len + 2 {
                return None;
            }
            let host = String::from_utf8_lossy(&b[2..2 + len]).to_string();
            let port = u16::from_be_bytes([b[2 + len], b[3 + len]]);
            Some((Addr::Domain(host, port), 2 + len + 2))
        }
        0x01 => {
            if b.len() < 7 {
                return None;
            }
            let ip = Ipv4Addr::new(b[1], b[2], b[3], b[4]);
            let port = u16::from_be_bytes([b[5], b[6]]);
            Some((Addr::Ip(IpAddr::V4(ip), port), 7))
        }
        0x02 => {
            if b.len() < 19 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[1..17]);
            let port = u16::from_be_bytes([b[17], b[18]]);
            Some((Addr::Ip(IpAddr::V6(Ipv6Addr::from(o)), port), 19))
        }
        _ => None,
    }
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

async fn resolve(addr: &Addr) -> Option<SocketAddr> {
    match addr {
        Addr::Ip(ip, port) => Some(SocketAddr::new(*ip, *port)),
        Addr::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .ok()?
            .next(),
    }
}

async fn handle_conn(conn: quinn::Connection, uuid: [u8; 16], password: &str) {
    let authenticated = Arc::new(AtomicBool::new(false));
    let notify = Arc::new(tokio::sync::Notify::new());
    let sessions: Arc<Mutex<HashMap<u16, UdpSession>>> = Arc::new(Mutex::new(HashMap::new()));
    let fragments: FragmentMap = Arc::new(Mutex::new(HashMap::new()));

    // Uni-stream loop: auth / packet / dissociate.
    {
        let conn = conn.clone();
        let auth = authenticated.clone();
        let notify = notify.clone();
        let sessions = sessions.clone();
        let fragments = fragments.clone();
        let password = password.to_string();
        tokio::spawn(async move {
            uni_stream_loop(
                conn, &uuid, &password, &auth, &notify, &sessions, &fragments,
            )
            .await;
        });
    }

    // Datagram loop: packet (native mode) / heartbeat / dissociate.
    {
        let conn = conn.clone();
        let auth = authenticated.clone();
        let notify = notify.clone();
        let sessions = sessions.clone();
        let fragments = fragments.clone();
        tokio::spawn(async move {
            datagram_loop(conn, &auth, &notify, &sessions, &fragments).await;
        });
    }

    // Bi-stream loop: TCP Connect.
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(_) => return,
        };
        if !authenticated.load(Ordering::SeqCst) {
            if tokio::time::timeout(AUTH_TIMEOUT, notify.notified())
                .await
                .is_err()
            {
                conn.close(0_u32.into(), b"authentication timeout");
                return;
            }
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

async fn uni_stream_loop(
    conn: quinn::Connection,
    uuid: &[u8; 16],
    password: &str,
    authenticated: &Arc<AtomicBool>,
    notify: &Arc<tokio::sync::Notify>,
    sessions: &Arc<Mutex<HashMap<u16, UdpSession>>>,
    fragments: &FragmentMap,
) {
    loop {
        let mut recv = match conn.accept_uni().await {
            Ok(x) => x,
            Err(_) => return,
        };
        let mut cmd = [0u8; 2];
        if recv.read_exact(&mut cmd).await.is_err() {
            continue;
        }
        if cmd[0] != VER {
            continue;
        }
        match cmd[1] {
            CMD_AUTH => {
                let mut rest = [0u8; AUTH_LEN - 2];
                if recv.read_exact(&mut rest).await.is_err() {
                    continue;
                }
                let mut peer = [0u8; 16];
                peer.copy_from_slice(&rest[0..16]);
                let token = &rest[16..48];
                if peer == *uuid && compute_token(&conn, uuid, password).is_ok_and(|t| t == token) {
                    authenticated.store(true, Ordering::SeqCst);
                    notify.notify_one();
                    tracing::debug!("tuic auth ok");
                } else {
                    tracing::debug!("tuic auth failed");
                }
            }
            CMD_PACKET => {
                if !authenticated.load(Ordering::SeqCst) {
                    if tokio::time::timeout(AUTH_TIMEOUT, notify.notified())
                        .await
                        .is_err()
                    {
                        conn.close(0_u32.into(), b"authentication timeout");
                        return;
                    }
                    if !authenticated.load(Ordering::SeqCst) {
                        continue;
                    }
                }
                let mut body = Vec::new();
                if tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut body)
                    .await
                    .is_err()
                {
                    continue;
                }
                if let Some(pkt) = parse_packet(&body) {
                    relay_udp(&conn, sessions, fragments, pkt, UdpMode::Uni).await;
                }
            }
            CMD_DISSOCIATE => {
                let mut assoc = [0u8; 2];
                if recv.read_exact(&mut assoc).await.is_ok() {
                    sessions.lock().await.remove(&u16::from_be_bytes(assoc));
                }
            }
            _ => {}
        }
    }
}

async fn datagram_loop(
    conn: quinn::Connection,
    authenticated: &Arc<AtomicBool>,
    notify: &Arc<tokio::sync::Notify>,
    sessions: &Arc<Mutex<HashMap<u16, UdpSession>>>,
    fragments: &FragmentMap,
) {
    loop {
        let dg = match conn.read_datagram().await {
            Ok(b) => b,
            Err(_) => return,
        };
        if dg.len() < 2 || dg[0] != VER {
            continue;
        }
        match dg[1] {
            CMD_PACKET => {
                if !authenticated.load(Ordering::SeqCst) {
                    if tokio::time::timeout(AUTH_TIMEOUT, notify.notified())
                        .await
                        .is_err()
                    {
                        conn.close(0_u32.into(), b"authentication timeout");
                        return;
                    }
                    if !authenticated.load(Ordering::SeqCst) {
                        continue;
                    }
                }
                if let Some(pkt) = parse_packet(&dg[2..]) {
                    relay_udp(&conn, sessions, fragments, pkt, UdpMode::Datagram).await;
                }
            }
            CMD_DISSOCIATE => {
                if dg.len() >= 4 {
                    sessions
                        .lock()
                        .await
                        .remove(&u16::from_be_bytes([dg[2], dg[3]]));
                }
            }
            CMD_HEARTBEAT => {}
            _ => {}
        }
    }
}

async fn relay_udp(
    conn: &quinn::Connection,
    sessions: &Arc<Mutex<HashMap<u16, UdpSession>>>,
    fragments: &FragmentMap,
    pkt: UdpPacket,
    mode: UdpMode,
) {
    let socket = match ensure_session(conn, sessions, pkt.assoc_id, mode).await {
        Ok(s) => s,
        Err(_) => return,
    };
    if pkt.frag_total == 1 {
        if let Some(dst) = resolve(&pkt.addr).await {
            let _ = socket.send_to(&pkt.data, dst).await;
        }
        return;
    }
    // Fragment reassembly.
    let mut ready: Option<Vec<u8>> = None;
    {
        let mut map = fragments.lock().await;
        let list = map.entry((pkt.assoc_id, pkt.pkt_id)).or_default();
        list.push((pkt.frag_id, pkt.data));
        if list.len() == pkt.frag_total as usize {
            list.sort_by_key(|(id, _)| *id);
            let data: Vec<u8> = list.iter().flat_map(|(_, d)| d.iter().copied()).collect();
            map.remove(&(pkt.assoc_id, pkt.pkt_id));
            ready = Some(data);
        }
    }
    if let (Some(data), Some(dst)) = (ready, resolve(&pkt.addr).await) {
        let _ = socket.send_to(&data, dst).await;
    }
}

async fn ensure_session(
    conn: &quinn::Connection,
    sessions: &Arc<Mutex<HashMap<u16, UdpSession>>>,
    assoc_id: u16,
    mode: UdpMode,
) -> Result<Arc<UdpSocket>, String> {
    if let Some(s) = sessions.lock().await.get(&assoc_id) {
        return Ok(s.socket.clone());
    }
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| e.to_string())?,
    );
    {
        let mut map = sessions.lock().await;
        if let Some(s) = map.get(&assoc_id) {
            return Ok(s.socket.clone());
        }
        map.insert(
            assoc_id,
            UdpSession {
                socket: socket.clone(),
            },
        );
    }
    spawn_udp_reader(conn.clone(), socket.clone(), assoc_id, mode);
    Ok(socket)
}

fn spawn_udp_reader(conn: quinn::Connection, socket: Arc<UdpSocket>, assoc_id: u16, mode: UdpMode) {
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let (n, src) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => return,
            };
            let mut out = Vec::with_capacity(n + 64);
            out.push(VER);
            out.push(CMD_PACKET);
            out.extend_from_slice(&assoc_id.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes()); // pkt_id
            out.push(1); // frag_total
            out.push(0); // frag_id
            out.extend_from_slice(&(n as u16).to_be_bytes());
            encode_socket_addr(&src, &mut out);
            out.extend_from_slice(&buf[..n]);

            match mode {
                UdpMode::Datagram => {
                    let len = out.len();
                    if conn.send_datagram(Bytes::from(out)).is_err()
                        && conn.max_datagram_size().is_some_and(|m| len > m)
                    {
                        send_udp_uni(&conn, &buf[..n], assoc_id, &src).await;
                    }
                }
                UdpMode::Uni => {
                    send_udp_uni(&conn, &buf[..n], assoc_id, &src).await;
                }
            }
        }
    });
}

async fn send_udp_uni(conn: &quinn::Connection, data: &[u8], assoc_id: u16, src: &SocketAddr) {
    let mut out = Vec::with_capacity(data.len() + 64);
    out.push(VER);
    out.push(CMD_PACKET);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.push(1);
    out.push(0);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    encode_socket_addr(src, &mut out);
    out.extend_from_slice(data);
    if let Ok(mut s) = conn.open_uni().await {
        let _ = s.write_all(&out).await;
        let _ = s.finish();
    }
}

fn encode_socket_addr(src: &SocketAddr, out: &mut Vec<u8>) {
    match src {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x02);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
}

async fn handle_tcp(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), String> {
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
    let client_to_upstream = async {
        let result = tokio::io::copy(&mut recv, &mut uw).await;
        let _ = uw.shutdown().await;
        result
    };
    let upstream_to_client = async {
        let result = tokio::io::copy(&mut ur, &mut send).await;
        let _ = send.finish();
        result
    };
    let _ = tokio::join!(client_to_upstream, upstream_to_client);
    Ok(())
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
            Ok(Addr::Domain(
                String::from_utf8_lossy(&dom).to_string(),
                u16::from_be_bytes(port),
            ))
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
            Ok(Addr::Ip(
                IpAddr::V6(Ipv6Addr::from(b)),
                u16::from_be_bytes(port),
            ))
        }
        other => Err(format!("unsupported tuic address type 0x{other:02x}")),
    }
}

/// A connected TUIC client session.
pub struct TuicClient {
    pub conn: quinn::Connection,
    next_assoc: Arc<AtomicU16>,
    udp_rx: UdpSenderMap,
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
        let endpoint = quinn::Endpoint::client(
            "0.0.0.0:0"
                .parse::<SocketAddr>()
                .map_err(|e| e.to_string())?,
        )
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

        let client = TuicClient {
            conn: conn.clone(),
            next_assoc: Arc::new(AtomicU16::new(1)),
            udp_rx: Arc::new(Mutex::new(HashMap::new())),
        };

        // Datagram reader: route Packet replies by assoc_id.
        {
            let conn = conn.clone();
            let udp_rx = client.udp_rx.clone();
            tokio::spawn(async move {
                loop {
                    let dg = match conn.read_datagram().await {
                        Ok(b) => b,
                        Err(_) => return,
                    };
                    if dg.len() < 2 || dg[0] != VER {
                        continue;
                    }
                    if dg[1] == CMD_PACKET {
                        if let Some(pkt) = parse_packet(&dg[2..]) {
                            if let Some(tx) = udp_rx.lock().await.get(&pkt.assoc_id) {
                                if let Some(addr) = resolve(&pkt.addr).await {
                                    let _ = tx.try_send((addr, pkt.data));
                                }
                            }
                        }
                    }
                }
            });
        }

        Ok(client)
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

    /// Open a UDP session (native/datagram mode). Send via [`TuicUdp::send_to`],
    /// receive replies via [`TuicUdp::recv`].
    pub async fn open_udp(&self) -> TuicUdp {
        let assoc_id = self.next_assoc.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel::<UdpReply>(256);
        self.udp_rx.lock().await.insert(assoc_id, tx);
        TuicUdp {
            conn: self.conn.clone(),
            assoc_id,
            rx,
        }
    }
}

/// Client-side UDP session over TUIC (native/datagram mode).
pub struct TuicUdp {
    conn: quinn::Connection,
    assoc_id: u16,
    rx: mpsc::Receiver<UdpReply>,
}

impl TuicUdp {
    /// Send one UDP datagram to `target`.
    pub async fn send_to(&self, target: &Addr, data: &[u8]) -> Result<(), String> {
        if data.len() > 65535 {
            return Err("udp packet too large".into());
        }
        let mut buf = vec![VER, CMD_PACKET];
        buf.extend_from_slice(&self.assoc_id.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // pkt_id
        buf.push(1); // frag_total
        buf.push(0); // frag_id
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        encode_addr(target, &mut buf);
        buf.extend_from_slice(data);
        let bytes = Bytes::from(buf);
        self.conn
            .send_datagram(bytes)
            .map_err(|e| format!("send datagram: {e}"))
    }

    /// Receive the next UDP reply from the relay.
    pub async fn recv(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.rx.recv().await
    }
}
