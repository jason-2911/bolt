//! Certificate Authority for Bolt.
//!
//! Simple self-contained cert format (not X.509):
//!   cert = { username, public_key[32], expires_at_unix, ca_signature[64] }
//!
//! CA signs: sha256(username || public_key || expires_at_le_bytes)
//! Server verifies: signature valid with CA key, username matches auth user, not expired.
//!
//! Usage:
//!   bolt ca init              → generates CA keypair → ~/.bolt/ca_key + ca_key.pub
//!   bolt ca sign user [days]  → generates cert for user → ~/.bolt/certs/user.cert
//!   boltd --ca-key ~/.bolt/ca_key  → server trusts CA-signed certs

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::KeyPair;

// ── Cert format ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoltCert {
    pub username: String,
    pub public_key: [u8; 32],
    /// Unix timestamp (seconds) when the cert expires.
    pub expires_at: u64,
    /// Ed25519 signature by the CA over the canonical body.
    pub ca_signature: Vec<u8>,
    /// CA public key (so server can find the right CA).
    pub ca_public_key: [u8; 32],
}

impl BoltCert {
    /// Sign a user's public key with the CA keypair.
    pub fn sign(
        username: &str,
        user_public_key: [u8; 32],
        valid_days: u64,
        ca: &KeyPair,
    ) -> anyhow::Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = now + valid_days * 86400;

        let body = canonical_body(username, &user_public_key, expires_at);
        // Sign using ring's Ed25519KeyPair (rcgen stores the key as PKCS#8)
        let ring_kp = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(ca.der_bytes())
            .map_err(|_| anyhow::anyhow!("load signing key"))?;
        let signature = ring_kp.sign(&body).as_ref().to_vec();

        Ok(Self {
            username: username.to_owned(),
            public_key: user_public_key,
            expires_at,
            ca_signature: signature,
            ca_public_key: ca.public,
        })
    }

    /// Verify the cert:
    /// - signature valid against ca_public_key
    /// - username matches expected
    /// - not expired
    pub fn verify(&self, expected_user: &str, trusted_ca_keys: &[[u8; 32]]) -> anyhow::Result<()> {
        // Check CA is trusted
        if !trusted_ca_keys.contains(&self.ca_public_key) {
            anyhow::bail!("cert issued by untrusted CA");
        }

        // Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > self.expires_at {
            anyhow::bail!("certificate expired");
        }

        // Check username
        if self.username != expected_user {
            anyhow::bail!(
                "cert username '{}' does not match auth user '{}'",
                self.username,
                expected_user
            );
        }

        // Verify signature
        let body = canonical_body(&self.username, &self.public_key, self.expires_at);
        verify_ed25519(&self.ca_public_key, &body, &self.ca_signature)
            .context("cert signature invalid")?;

        Ok(())
    }

    /// Serialize to bytes (bincode).
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).context("serialize cert")
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(data).context("deserialize cert")
    }

    /// Save to file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = self.to_bytes()?;
        std::fs::write(path, data).with_context(|| format!("write cert {}", path.display()))?;
        Ok(())
    }

    /// Load from file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("read cert {}", path.display()))?;
        Self::from_bytes(&data)
    }

    /// Default cert path for a user: `~/.bolt/certs/{username}.cert`
    pub fn default_path(username: &str) -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".bolt/certs")
            .join(format!("{username}.cert"))
    }
}

// ── CA key management ─────────────────────────────────────────────────────

/// Load trusted CA public keys from a file (one base64 key per line).
pub fn load_ca_keys(path: &Path) -> anyhow::Result<Vec<[u8; 32]>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read CA keys {}", path.display()))?;

    let mut keys = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, line)
            .context("decode CA public key")?;
        if bytes.len() != 32 {
            anyhow::bail!("CA public key must be 32 bytes");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        keys.push(key);
    }
    Ok(keys)
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn canonical_body(username: &str, public_key: &[u8; 32], expires_at: u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(username.as_bytes());
    h.update(public_key);
    h.update(expires_at.to_le_bytes());
    h.finalize().to_vec()
}

fn verify_ed25519(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
    use ring::signature::{UnparsedPublicKey, ED25519};
    let key = UnparsedPublicKey::new(&ED25519, public_key.as_ref());
    key.verify(message, signature)
        .map_err(|_| anyhow::anyhow!("signature verification failed"))
}
