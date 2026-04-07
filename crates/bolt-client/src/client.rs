//! Bolt client: connect, handshake, authenticate, open session.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::Context as _;
use tracing::{debug, info, warn};

use bolt_crypto::{
    keys::{KeyPair, KnownHosts, KEY_SIZE},
    noise::NoiseHandshake,
};
use bolt_proto::packet::{Packet, PacketType};
use bolt_session::Session;
use bolt_transport::{Config as TransportConfig, Connection};

pub struct ClientConfig {
    pub identity_file: PathBuf,
    pub known_hosts:   PathBuf,
    pub transport:     TransportConfig,
}

impl Default for ClientConfig {
    fn default() -> Self {
        let home = dirs_home();
        Self {
            identity_file: home.join(".bolt/id_bolt"),
            known_hosts:   home.join(".bolt/known_hosts"),
            transport:     TransportConfig::default(),
        }
    }
}

pub struct Client {
    identity:    KeyPair,
    known_hosts: Mutex<KnownHosts>,
    config:      ClientConfig,
}

impl Client {
    pub fn new(config: ClientConfig) -> anyhow::Result<Self> {
        let identity = load_or_generate_identity(&config.identity_file)?;
        let known_hosts = KnownHosts::load(&config.known_hosts)
            .unwrap_or_else(|_| KnownHosts::load(&config.known_hosts).unwrap_or_else(|_| {
                // Can't load — start empty
                KnownHosts::load(Path::new("/dev/null")).unwrap()
            }));
        Ok(Self { identity, known_hosts: Mutex::new(known_hosts), config })
    }

    /// Open an authenticated Bolt session to `addr` (e.g. "127.0.0.1:2222").
    pub async fn connect(&self, addr: &str) -> anyhow::Result<Session> {
        let conn = Connection::dial(addr, self.config.transport.clone()).await
            .with_context(|| format!("dial {addr}"))?;

        let result = self.perform_handshake(&conn, addr).await?;
        let session = Session::new(conn, result, false);
        Ok(session)
    }

    async fn perform_handshake(
        &self,
        conn: &Connection,
        addr: &str,
    ) -> anyhow::Result<bolt_crypto::noise::HandshakeResult> {
        let mut hs = NoiseHandshake::new_initiator(&self.identity)?;

        // msg 1: -> e
        let msg1 = hs.write_message_vec(&[])?;
        conn.send_raw(Packet::new(PacketType::Handshake, conn.conn_id(), msg1)).await?;

        // msg 2: <- e, ee, s, es
        let pkt2 = conn.recv().await.context("recv msg2")?;
        let _    = hs.read_message(&pkt2.payload)?;

        // msg 3: -> s, se
        let msg3 = hs.write_message_vec(&[])?;
        conn.send_raw(Packet::new(PacketType::Handshake, conn.conn_id(), msg3)).await?;

        let result = hs.finalize()?;

        // Verify host key (TOFU)
        let mut kh = self.known_hosts.lock().unwrap();
        match kh.lookup(addr) {
            Some(known) => {
                if known != result.remote_key {
                    anyhow::bail!("HOST KEY MISMATCH for {addr} — possible MITM attack");
                }
                debug!(component = "client", addr, "host key verified");
            }
            None => {
                warn!(
                    component   = "client",
                    addr,
                    fingerprint = %hex8(&result.remote_key),
                    "host not in known_hosts, accepting (TOFU)"
                );
                let _ = kh.add(addr, result.remote_key);
            }
        }

        Ok(result)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn load_or_generate_identity(path: &Path) -> anyhow::Result<KeyPair> {
    if path.exists() {
        KeyPair::load(path)
            .with_context(|| format!("identity: read private key: open {}", path.display()))
    } else {
        let kp = KeyPair::generate().context("generate identity key")?;
        kp.save(path).with_context(|| format!("save identity {}", path.display()))?;
        info!(component = "client", "generated new identity key at {}", path.display());
        Ok(kp)
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{:02x}", x)).collect()
}
