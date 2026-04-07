//! Key pair management, known_hosts, and authorized_keys.
//!
//! Keys are Ed25519 (via rcgen/ring). Stored as Base64-encoded PKCS#8 DER.

use std::{
    collections::HashMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rcgen::KeyPair as RcgenKeyPair;
use rustls::pki_types::PrivatePkcs8KeyDer;
use thiserror::Error;
use zeroize::Zeroize;

// ── KeyPair ───────────────────────────────────────────────────────────────

/// Ed25519 key pair stored as PKCS#8 DER-encoded private key.
pub struct KeyPair {
    /// PKCS#8 DER-encoded private key.
    der: Vec<u8>,
    /// Raw 32-byte public key for fingerprinting.
    pub public: [u8; 32],
}

impl KeyPair {
    /// Generate a new Ed25519 key pair.
    pub fn generate() -> Result<Self, KeyError> {
        let kp = RcgenKeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| KeyError::Generate(e.to_string()))?;
        let der = kp.serialize_der();
        let public = Self::extract_public_from_rcgen(&kp)?;
        Ok(Self { der, public })
    }

    /// DER bytes for building TLS certs.
    pub fn der_bytes(&self) -> &[u8] {
        &self.der
    }

    /// Reconstruct an `rcgen::KeyPair` from stored PKCS#8 DER.
    pub fn to_rcgen(&self) -> Result<RcgenKeyPair, KeyError> {
        let pkcs8 = PrivatePkcs8KeyDer::from(self.der.clone());
        RcgenKeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)
            .map_err(|e| KeyError::Generate(e.to_string()))
    }

    /// Base64-encoded public key fingerprint.
    pub fn fingerprint(&self) -> String {
        BASE64.encode(self.public)
    }

    /// Save private key (DER, base64) to `path`, public key to `path.pub`.
    pub fn save(&self, path: &Path) -> Result<(), KeyError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| KeyError::Io(path.to_owned(), e))?;
        }

        let priv_b64 = BASE64.encode(&self.der);
        fs::write(path, format!("{priv_b64}\n"))
            .map_err(|e| KeyError::Io(path.to_owned(), e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }

        let pub_path = path.with_extension("pub");
        let pub_b64 = BASE64.encode(self.public);
        fs::write(&pub_path, format!("{pub_b64}\n"))
            .map_err(|e| KeyError::Io(pub_path, e))?;
        Ok(())
    }

    /// Load a key pair from a base64 PKCS#8 DER private key file.
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let raw = fs::read_to_string(path).map_err(|e| KeyError::Io(path.to_owned(), e))?;
        let der = BASE64
            .decode(raw.trim())
            .map_err(|_| KeyError::InvalidKey(path.to_owned()))?;

        let pkcs8 = PrivatePkcs8KeyDer::from(der.clone());
        let kp = RcgenKeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)
            .map_err(|_| KeyError::InvalidKey(path.to_owned()))?;
        let public = Self::extract_public_from_rcgen(&kp)?;

        Ok(Self { der, public })
    }

    /// Extract 32-byte Ed25519 public key from an rcgen KeyPair.
    fn extract_public_from_rcgen(kp: &RcgenKeyPair) -> Result<[u8; 32], KeyError> {
        let pub_der = kp.public_key_der();
        let raw: &[u8] = pub_der.as_ref();
        // Ed25519 SubjectPublicKeyInfo DER: last 32 bytes are the raw public key
        if raw.len() < 32 {
            return Err(KeyError::Generate("public key too short".into()));
        }
        let mut public = [0u8; 32];
        public.copy_from_slice(&raw[raw.len() - 32..]);
        Ok(public)
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.der.zeroize();
        self.public.zeroize();
    }
}

// ── KnownHosts ────────────────────────────────────────────────────────────

/// Client-side host key cache (TOFU model like SSH).
///
/// Format per line: `<host> <base64-fingerprint>`
pub struct KnownHosts {
    path: PathBuf,
    hosts: HashMap<String, [u8; 32]>,
}

impl KnownHosts {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, KeyError> {
        let path = path.into();
        let mut hosts = HashMap::new();

        match fs::read_to_string(&path) {
            Ok(content) => {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let Some((host, key_b64)) = line.split_once(' ') else {
                        continue;
                    };
                    let Ok(kb) = BASE64.decode(key_b64) else {
                        continue;
                    };
                    let Ok(key) = <[u8; 32]>::try_from(kb.as_slice()) else {
                        continue;
                    };
                    hosts.insert(host.to_owned(), key);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(KeyError::Io(path, e)),
        }

        Ok(Self { path, hosts })
    }

    pub fn lookup(&self, host: &str) -> Option<[u8; 32]> {
        self.hosts.get(host).copied()
    }

    pub fn add(&mut self, host: &str, key: [u8; 32]) -> Result<(), KeyError> {
        self.hosts.insert(host.to_owned(), key);

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| KeyError::Io(self.path.clone(), e))?;
        }

        let mut f = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)
            .map_err(|e| KeyError::Io(self.path.clone(), e))?;

        writeln!(f, "{} {}", host, BASE64.encode(key))
            .map_err(|e| KeyError::Io(self.path.clone(), e))?;
        Ok(())
    }
}

// ── AuthorizedKeys ────────────────────────────────────────────────────────

/// Server-side list of allowed client public keys.
///
/// Format per line: `ed25519 <base64-public-key> [comment]`
pub struct AuthorizedKeys {
    keys: Vec<[u8; 32]>,
}

impl AuthorizedKeys {
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let mut keys = Vec::new();

        match fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let parts: Vec<&str> = line.splitn(3, ' ').collect();
                    if parts.len() < 2 || parts[0] != "ed25519" {
                        continue;
                    }
                    let Ok(kb) = BASE64.decode(parts[1]) else {
                        continue;
                    };
                    let Ok(key) = <[u8; 32]>::try_from(kb.as_slice()) else {
                        continue;
                    };
                    keys.push(key);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(KeyError::Io(path.to_owned(), e)),
        }

        Ok(Self { keys })
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn is_authorized(&self, pub_key: &[u8; 32]) -> bool {
        self.keys.iter().any(|k| k == pub_key)
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("I/O error for {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("invalid key file: {0}")]
    InvalidKey(PathBuf),
    #[error("key generation: {0}")]
    Generate(String),
}
