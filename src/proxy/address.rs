//! SOCKS-style target address shared by all protocols.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use tokio::net::lookup_host;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

impl Addr {
    pub fn new(host: &str, port: u16) -> Result<Self, String> {
        if let Ok(ip) = IpAddr::from_str(host) {
            Ok(Addr::Ip(ip, port))
        } else {
            Ok(Addr::Domain(host.to_string(), port))
        }
    }

    /// Parse a SOCKS-style address block: [ATYP(1)] + address + [port(2, BE)].
    /// Returns the address and the number of bytes consumed.
    pub fn parse(buf: &[u8]) -> Result<(Addr, usize), String> {
        if buf.is_empty() {
            return Err("empty address buffer".into());
        }
        let atype = buf[0];
        match atype {
            0x01 => {
                if buf.len() < 1 + 4 + 2 {
                    return Err("short ipv4 address".into());
                }
                let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((Addr::Ip(IpAddr::V4(ip), port), 1 + 4 + 2))
            }
            0x03 => {
                if buf.len() < 2 {
                    return Err("short domain address".into());
                }
                let len = buf[1] as usize;
                if buf.len() < 2 + len + 2 {
                    return Err("short domain address".into());
                }
                let domain = String::from_utf8_lossy(&buf[2..2 + len]).to_string();
                let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
                Ok((Addr::Domain(domain, port), 2 + len + 2))
            }
            0x04 => {
                if buf.len() < 1 + 16 + 2 {
                    return Err("short ipv6 address".into());
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((Addr::Ip(IpAddr::V6(ip), port), 1 + 16 + 2))
            }
            other => Err(format!("unsupported address type 0x{other:02x}")),
        }
    }

    /// Encode into SOCKS-style address block: [ATYP(1)] + address + [port(2, BE)].
    pub fn encode(&self, out: &mut Vec<u8>) {
        self.encode_addr(out);
        let port = self.port();
        out.extend_from_slice(&port.to_be_bytes());
    }

    /// Encode address part only: [ATYP(1)] + address (no port). Used by VLESS header.
    pub fn encode_addr(&self, out: &mut Vec<u8>) {
        match self {
            Addr::Ip(IpAddr::V4(ip), _) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
            }
            Addr::Ip(IpAddr::V6(ip), _) => {
                out.push(0x04);
                out.extend_from_slice(&ip.octets());
            }
            Addr::Domain(host, _) => {
                out.push(0x03);
                let b = host.as_bytes();
                out.push(b.len() as u8);
                out.extend_from_slice(b);
            }
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Addr::Ip(_, p) | Addr::Domain(_, p) => *p,
        }
    }

    /// Resolve (if domain) and connect to the target.
    pub async fn connect(&self) -> Result<tokio::net::TcpStream, std::io::Error> {
        let addr = match self {
            Addr::Ip(ip, port) => SocketAddr::new(*ip, *port),
            Addr::Domain(host, port) => {
                let mut iter = lookup_host((host.as_str(), *port)).await?;
                iter.next().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "host not found")
                })?
            }
        };
        tokio::net::TcpStream::connect(addr).await
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::Ip(ip, port) => write!(f, "{ip}:{port}"),
            Addr::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}
