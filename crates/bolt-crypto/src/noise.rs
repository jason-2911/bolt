//! Noise_XX_25519_ChaChaPoly_BLAKE2s handshake using the `snow` crate.
//!
//! Pattern XX:
//!   -> e
//!   <- e, ee, s, es
//!   -> s, se

use snow::{Builder, HandshakeState, TransportState};
use thiserror::Error;

use super::keys::KeyPair;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// State carried through a handshake session.
pub struct NoiseHandshake {
    state: HandshakeState,
}

/// Symmetric cipher state after a completed handshake.
/// Wraps snow's TransportState (single object handles both send/recv).
pub struct NoiseCipher {
    transport: TransportState,
}

/// The result of a completed handshake.
pub struct HandshakeResult {
    /// Unified cipher for send/recv (snow manages nonces internally).
    pub cipher: NoiseCipher,
    /// Remote static public key (32 bytes).
    pub remote_key: [u8; 32],
}

impl NoiseHandshake {
    pub fn new_initiator(identity: &KeyPair) -> Result<Self, NoiseError> {
        let state = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(identity.private_bytes())
            .build_initiator()
            .map_err(|e| NoiseError::Build(e.to_string()))?;
        Ok(Self { state })
    }

    pub fn new_responder(identity: &KeyPair) -> Result<Self, NoiseError> {
        let state = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(identity.private_bytes())
            .build_responder()
            .map_err(|e| NoiseError::Build(e.to_string()))?;
        Ok(Self { state })
    }

    /// Write next handshake message, returning it as a new `Vec<u8>`.
    pub fn write_message_vec(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut tmp = vec![0u8; 65535];
        let n = self.state
            .write_message(payload, &mut tmp)
            .map_err(|e| NoiseError::Handshake(e.to_string()))?;
        Ok(tmp[..n].to_vec())
    }

    /// Read a handshake message. Returns decrypted payload.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut tmp = vec![0u8; 65535];
        let n = self.state
            .read_message(msg, &mut tmp)
            .map_err(|e| NoiseError::Handshake(e.to_string()))?;
        Ok(tmp[..n].to_vec())
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Consume the handshake and return transport cipher + remote key.
    pub fn finalize(self) -> Result<HandshakeResult, NoiseError> {
        let remote_key_bytes = self.state
            .get_remote_static()
            .ok_or(NoiseError::NoRemoteKey)?
            .to_vec();
        let mut remote_key = [0u8; 32];
        remote_key.copy_from_slice(&remote_key_bytes[..32]);

        let transport = self.state
            .into_transport_mode()
            .map_err(|e| NoiseError::Finalize(e.to_string()))?;

        Ok(HandshakeResult {
            cipher: NoiseCipher { transport },
            remote_key,
        })
    }
}

impl NoiseCipher {
    /// Encrypt `plaintext`, returning ciphertext (includes AEAD tag).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // AEAD tag = 16 bytes
        let n = self.transport
            .write_message(plaintext, &mut buf)
            .map_err(|e| NoiseError::Cipher(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt `ciphertext`, returning plaintext.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self.transport
            .read_message(ciphertext, &mut buf)
            .map_err(|e| NoiseError::Cipher(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("noise builder: {0}")]
    Build(String),
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("no remote static key after handshake")]
    NoRemoteKey,
    #[error("finalize: {0}")]
    Finalize(String),
    #[error("cipher: {0}")]
    Cipher(String),
}
