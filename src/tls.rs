//! TLS helpers shared by AnyTLS (tokio-rustls) and TUIC (quinn).

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, Clone)]
pub struct TlsIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// Load cert.pem / key.pem next to the config file.
pub fn load_identity(config_path: &Path) -> Result<TlsIdentity, String> {
    let cert_pem = std::fs::read(config_path.with_file_name("cert.pem")).map_err(|e| e.to_string())?;
    let key_pem = std::fs::read(config_path.with_file_name("key.pem")).map_err(|e| e.to_string())?;

    let certs = rustls_pemfile_certs(&cert_pem)?;
    let key = rustls_pemfile_private_key(&key_pem)?;
    Ok(TlsIdentity { cert_der: certs, key_der: key })
}

fn rustls_pemfile_certs(pem: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = std::io::BufReader::new(pem);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    certs
        .into_iter()
        .next()
        .map(|c| c.to_vec())
        .ok_or_else(|| "no certificate found".to_string())
}

fn rustls_pemfile_private_key(pem: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = std::io::BufReader::new(pem);
    match rustls_pemfile::private_key(&mut reader)
        .map_err(|e| e.to_string())?
    {
        Some(k) => Ok(k.secret_der().to_vec()),
        None => Err("no private key found".to_string()),
    }
}

/// tokio-rustls server config (rustls 0.23).
pub fn rustls_server_config(
    id: &TlsIdentity,
    alpn: &[String],
) -> Result<Arc<rustls::ServerConfig>, String> {
    ensure_provider();
    let cert = CertificateDer::from(id.cert_der.clone());
    let key = PrivateKeyDer::try_from(id.key_der.clone()).map_err(|e| format!("key parse: {e}"))?;
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| e.to_string())?;
    let mut cfg = cfg;
    cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Ok(Arc::new(cfg))
}

/// tokio-rustls client config (rustls 0.23).
pub fn rustls_client_config(
    id: &TlsIdentity,
    insecure: bool,
    alpn: &[String],
) -> Result<Arc<rustls::ClientConfig>, String> {
    ensure_provider();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cfg = if insecure {
        let verifier = Arc::new(SkipServerVerification);
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        let cert = CertificateDer::from(id.cert_der.clone());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).map_err(|e| e.to_string())?;
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    let mut cfg = cfg;
    cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Ok(Arc::new(cfg))
}

/// QUIC transport tuning: BBR congestion control + datagram buffers (for TUIC UDP relay).
pub fn quinn_transport_config() -> Arc<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    tc.datagram_receive_buffer_size(Some(256 * 1024));
    tc.datagram_send_buffer_size(64 * 1024);
    tc.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(tc)
}

/// quinn server config (rustls 0.23 inside) with the given ALPN.
pub fn quinn_server_config(id: &TlsIdentity, alpn: &[&[u8]]) -> Result<quinn::ServerConfig, String> {
    ensure_provider();
    let cert = rustls::pki_types::CertificateDer::from(id.cert_der.clone());
    let key = rustls::pki_types::PrivateKeyDer::try_from(id.key_der.clone())
        .map_err(|e| format!("key parse: {e}"))?;
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(cfg)
        .map_err(|e| e.to_string())?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
    server.transport_config(quinn_transport_config());
    Ok(server)
}

/// quinn client config (rustls 0.23 inside) with the given ALPN.
/// Trusts our own identity cert, or skips verification when `insecure`.
pub fn quinn_client_config(
    id: &TlsIdentity,
    insecure: bool,
    alpn: &[&[u8]],
) -> Result<quinn::ClientConfig, String> {
    ensure_provider();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cfg = if insecure {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else {
        let cert = rustls::pki_types::CertificateDer::from(id.cert_der.clone());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).map_err(|e| e.to_string())?;
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    let mut cfg = cfg;
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(cfg)
        .map_err(|e| e.to_string())?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic));
    client.transport_config(quinn_transport_config());
    Ok(client)
}

/// Accept any server certificate (for insecure mode).
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Install the process-level crypto provider exactly once (needed by quinn).
fn ensure_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
