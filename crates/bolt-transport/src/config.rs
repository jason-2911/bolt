//! Transport layer configuration.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum transmission unit (bytes).
    pub mtu: usize,
    /// Maximum concurrent server connections.
    pub max_connections: usize,
    /// Handshake completion timeout.
    pub handshake_timeout: Duration,
    /// Close idle connections after this interval.
    pub idle_timeout: Duration,
    /// Enable forward error correction (placeholder).
    pub enable_fec: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mtu:               1400,
            max_connections:   1000,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout:      Duration::from_secs(300),
            enable_fec:        false,
        }
    }
}
