//! TLS certificate generation and QUIC endpoint configuration.
//!
//! Uses self-signed certs generated from Bolt Ed25519 keys.
//! The certificate is generated once and persisted alongside the host key
//! so that the fingerprint remains stable across server restarts.

use std::{fs, path::Path, sync::Arc};

use rcgen::{CertificateParams, DistinguishedName};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use thiserror::Error;

use crate::keys::KeyPair;

// ── Server TLS config ─────────────────────────────────────────────────────

/// Build a quinn `ServerConfig` from a Bolt host key.
/// If `cert_path` exists, loads the persisted cert. Otherwise generates one
/// and saves it so the fingerprint stays stable across restarts.
pub fn server_config(
    host_key: &KeyPair,
    cert_path: &Path,
) -> Result<quinn::ServerConfig, TlsError> {
    let (cert_der, key_der) = load_or_generate_cert(host_key, cert_path)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| TlsError::Config(e.to_string()))?;

    tls_config.alpn_protocols = vec![b"bolt/1".to_vec()];

    let quic_server_config =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| TlsError::Config(e.to_string()))?;

    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_server_config)))
}

/// Build a quinn `ClientConfig` that skips CA verification.
/// We verify via known_hosts fingerprint at the application layer (SSH model).
pub fn client_config() -> Result<quinn::ClientConfig, TlsError> {
    client_config_inner(None)
}

/// Build a quinn `ClientConfig` with a file-backed session store for 0-RTT.
pub fn client_config_with_resume(
    session_store: Arc<dyn rustls::client::ClientSessionStore>,
) -> Result<quinn::ClientConfig, TlsError> {
    client_config_inner(Some(session_store))
}

fn client_config_inner(
    session_store: Option<Arc<dyn rustls::client::ClientSessionStore>>,
) -> Result<quinn::ClientConfig, TlsError> {
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"bolt/1".to_vec()];

    if let Some(store) = session_store {
        tls_config.resumption = rustls::client::Resumption::store(store);
    }

    let quic_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| TlsError::Config(e.to_string()))?;

    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

// ── Certificate persistence ───────────────────────────────────────────────

fn load_or_generate_cert(
    key: &KeyPair,
    cert_path: &Path,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), TlsError> {
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.der_bytes().to_vec()));

    // Try loading existing cert
    if cert_path.exists() {
        let cert_bytes = fs::read(cert_path)
            .map_err(|e| TlsError::CertGen(format!("read cert: {e}")))?;
        let cert_der = CertificateDer::from(cert_bytes);
        return Ok((cert_der, key_der));
    }

    // Generate new self-signed cert
    let rcgen_kp = key
        .to_rcgen()
        .map_err(|e| TlsError::CertGen(e.to_string()))?;

    let mut params = CertificateParams::new(vec!["bolt.local".to_string()])
        .map_err(|e| TlsError::CertGen(e.to_string()))?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "bolt");

    let cert = params
        .self_signed(&rcgen_kp)
        .map_err(|e| TlsError::CertGen(e.to_string()))?;

    let cert_raw = cert.der().to_vec();

    // Persist the cert
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| TlsError::CertGen(format!("mkdir: {e}")))?;
    }
    fs::write(cert_path, &cert_raw)
        .map_err(|e| TlsError::CertGen(format!("write cert: {e}")))?;

    Ok((CertificateDer::from(cert_raw), key_der))
}

// ── Custom certificate verifier (skip CA, we use TOFU) ────────────────────

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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("certificate generation: {0}")]
    CertGen(String),
    #[error("TLS config: {0}")]
    Config(String),
}
