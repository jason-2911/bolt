//! Curve25519 key pair management, known_hosts, and authorized_keys.

use std::{
    collections::HashMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use thiserror::Error;
use zeroize::Zeroize;

pub const KEY_SIZE: usize = 32;

// ── KeyPair ────────────────────────────────────────────────────────────────

/// Curve25519 key pair (stored as raw 32-byte arrays).
/// Snow handles the actual DH; we only need to persist/load keys.
pub struct KeyPair {
    pub public:  [u8; KEY_SIZE],
    private:     [u8; KEY_SIZE],
}

impl KeyPair {
    /// Generate a new random Curve25519 key pair using snow's DH.
    pub fn generate() -> Result<Self, KeyError> {
        let builder = snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let keypair = builder.generate_keypair().map_err(|e| KeyError::Generate(e.to_string()))?;
        let mut public  = [0u8; KEY_SIZE];
        let mut private = [0u8; KEY_SIZE];
        public.copy_from_slice(&keypair.public);
        private.copy_from_slice(&keypair.private);
        Ok(Self { public, private })
    }

    /// Raw private key bytes (for snow builder).
    pub fn private_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.private
    }

    /// Base64-encoded public key fingerprint.
    pub fn public_key_string(&self) -> String {
        BASE64.encode(self.public)
    }

    /// Save private key to `path`, public key to `path.pub`.
    pub fn save(&self, path: &Path) -> Result<(), KeyError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| KeyError::Io(path.to_owned(), e))?;
        }
        let priv_b64 = BASE64.encode(self.private);
        fs::write(path, format!("{}\n", priv_b64))
            .map_err(|e| KeyError::Io(path.to_owned(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        let pub_path = path.with_extension("pub");
        let pub_b64 = BASE64.encode(self.public);
        fs::write(&pub_path, format!("{}\n", pub_b64))
            .map_err(|e| KeyError::Io(pub_path, e))?;
        Ok(())
    }

    /// Load a key pair from a private key file (derive public via snow).
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let raw = fs::read_to_string(path)
            .map_err(|e| KeyError::Io(path.to_owned(), e))?;
        let priv_bytes = BASE64
            .decode(raw.trim())
            .map_err(|_| KeyError::InvalidKey(path.to_owned()))?;
        if priv_bytes.len() != KEY_SIZE {
            return Err(KeyError::InvalidKey(path.to_owned()));
        }
        let mut private = [0u8; KEY_SIZE];
        private.copy_from_slice(&priv_bytes);

        // Derive public key: build a keypair from private, extract public
        // Snow doesn't expose a "derive public from private" directly,
        // so we use x25519 scalar multiplication with the basepoint.
        let mut clamped = private;
        clamped[0]  &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        let public = x25519_dalek::x25519(clamped, x25519_dalek::X25519_BASEPOINT_BYTES);

        Ok(Self { public, private })
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.private.zeroize();
        self.public.zeroize();
    }
}

// ── KnownHosts ─────────────────────────────────────────────────────────────

pub struct KnownHosts {
    path:  PathBuf,
    hosts: HashMap<String, [u8; KEY_SIZE]>,
}

impl KnownHosts {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, KeyError> {
        let path = path.into();
        let mut hosts = HashMap::new();
        match fs::read_to_string(&path) {
            Ok(content) => {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue; }
                    let mut parts = line.splitn(2, ' ');
                    let host    = parts.next().unwrap_or_default();
                    let key_b64 = parts.next().unwrap_or_default();
                    if let Ok(kb) = BASE64.decode(key_b64) {
                        if kb.len() == KEY_SIZE {
                            let mut key = [0u8; KEY_SIZE];
                            key.copy_from_slice(&kb);
                            hosts.insert(host.to_owned(), key);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(KeyError::Io(path, e)),
        }
        Ok(Self { path, hosts })
    }

    pub fn lookup(&self, host: &str) -> Option<[u8; KEY_SIZE]> {
        self.hosts.get(host).copied()
    }

    pub fn add(&mut self, host: &str, key: [u8; KEY_SIZE]) -> Result<(), KeyError> {
        self.hosts.insert(host.to_owned(), key);
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| KeyError::Io(self.path.clone(), e))?;
        }
        let mut f = fs::OpenOptions::new()
            .append(true).create(true).open(&self.path)
            .map_err(|e| KeyError::Io(self.path.clone(), e))?;
        writeln!(f, "{} {}", host, BASE64.encode(key))
            .map_err(|e| KeyError::Io(self.path.clone(), e))?;
        Ok(())
    }
}

// ── AuthorizedKeys ─────────────────────────────────────────────────────────

pub struct AuthorizedKeys {
    keys: Vec<[u8; KEY_SIZE]>,
}

impl AuthorizedKeys {
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let mut keys = Vec::new();
        match fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue; }
                    let parts: Vec<&str> = line.splitn(3, ' ').collect();
                    if parts.len() < 2 || parts[0] != "curve25519" { continue; }
                    if let Ok(kb) = BASE64.decode(parts[1]) {
                        if kb.len() == KEY_SIZE {
                            let mut key = [0u8; KEY_SIZE];
                            key.copy_from_slice(&kb);
                            keys.push(key);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(KeyError::Io(path.to_owned(), e)),
        }
        Ok(Self { keys })
    }

    pub fn len(&self) -> usize { self.keys.len() }
    pub fn is_empty(&self) -> bool { self.keys.is_empty() }

    pub fn is_authorized(&self, pub_key: &[u8; KEY_SIZE]) -> bool {
        self.keys.iter().any(|k| k == pub_key)
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("I/O error for {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("invalid key file: {0}")]
    InvalidKey(PathBuf),
    #[error("key generation: {0}")]
    Generate(String),
}
