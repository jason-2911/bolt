//! Bolt client: QUIC connection, auth handshake, stream opening.
//!
//! Jump host: bolt -J bastion_user@bastion user@host
//!   1. Connect to bastion normally (full auth)
//!   2. Open a PortForward channel: bastion TCP-connects to final_host:port
//!   3. Establish QUIC over that TCP tunnel (not yet — we use direct QUIC through bastion's network)
//!
//! Current jump host implementation: connect to bastion, open a PortForward stream to
//! the final target's address, then tunnel a second QUIC connection over that stream
//! using a custom async adapter.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{bail, Context as _};
use quinn::{Connection, Endpoint};
use tracing::{debug, info, warn};

use bolt_crypto::{
    keys::{KeyPair, KnownHosts},
    session_store::FileSessionStore,
    tls,
};
use bolt_proto::Message;
use rustls::pki_types::CertificateDer;

// ── Config ────────────────────────────────────────────────────────────────

pub struct ClientConfig {
    pub identity_file: PathBuf,
    pub known_hosts: PathBuf,
}

impl Default for ClientConfig {
    fn default() -> Self {
        let home = dirs_home();
        Self {
            identity_file: home.join(".bolt/id_bolt"),
            known_hosts: home.join(".bolt/known_hosts"),
        }
    }
}

// ── Client ────────────────────────────────────────────────────────────────

pub struct Client {
    identity: KeyPair,
    known_hosts: Mutex<KnownHosts>,
}

/// An authenticated Bolt session over QUIC.
pub struct Session {
    pub conn: Connection,
}

impl Client {
    pub fn new(config: ClientConfig) -> anyhow::Result<Self> {
        let identity = load_or_generate_identity(&config.identity_file)?;
        let known_hosts = KnownHosts::load(&config.known_hosts).unwrap_or_else(|_| {
            KnownHosts::load(Path::new("/dev/null")).unwrap_or_else(|_| {
                KnownHosts::load("/dev/null").expect("failed to create empty known_hosts")
            })
        });
        Ok(Self {
            identity,
            known_hosts: Mutex::new(known_hosts),
        })
    }

    /// Connect directly to a Bolt server, verify host key, and authenticate.
    pub async fn connect(&self, addr: &str, user: &str) -> anyhow::Result<Session> {
        self.connect_direct(addr, user).await
    }

    /// Connect through a jump host.
    ///
    /// `jump` = "user@bastion_addr" (addr includes port)
    /// `addr`  = final destination "host:port"
    pub async fn connect_via_jump(
        &self,
        jump: &str,
        addr: &str,
        user: &str,
        jump_port: u16,
    ) -> anyhow::Result<Session> {
        // Parse jump host
        let (jump_user, jump_host) = if let Some(at) = jump.find('@') {
            (&jump[..at], &jump[at + 1..])
        } else {
            ("root", jump)
        };

        let jump_addr = if jump_host.contains(':') {
            jump_host.to_owned()
        } else {
            format!("{jump_host}:{jump_port}")
        };

        info!(jump = %jump_addr, target = %addr, "connecting via jump host");

        // Step 1: Connect to bastion
        let bastion = self.connect_direct(&jump_addr, jump_user).await
            .with_context(|| format!("connect to jump host {jump_addr}"))?;

        eprintln!("bolt: jump host {jump_addr} connected, tunneling to {addr}...");

        // Step 2: Open a forward channel to the final target on the bastion
        let (target_host, target_port) = parse_host_port(addr)?;
        let (mut fwd_send, mut fwd_recv) = bastion.open_bi().await?;

        bolt_proto::write_msg(
            &mut fwd_send,
            &Message::ChannelOpen {
                channel_type: bolt_proto::ChannelType::PortForward,
                command: format!("{target_host}:{target_port}"),
            },
        )
        .await?;

        let Some(resp) = bolt_proto::read_msg(&mut fwd_recv).await? else {
            bail!("jump host closed before forward accept");
        };
        match resp {
            Message::ChannelAccept | Message::ForwardAccept => {}
            Message::ChannelReject { reason } | Message::ForwardReject { reason } => {
                bail!("jump host rejected forward: {reason}");
            }
            other => bail!("unexpected jump forward response: {other:?}"),
        }

        // Step 3: Tunnel QUIC over the QUIC forward stream using a stream adapter
        // We create a new QUIC endpoint using a custom UDP socket that sends
        // framed data over the forward streams.
        // This is complex to implement inline; instead we use the simpler approach:
        // treat the forward as a TCP-like byte stream and use quic-through-stream.
        //
        // For now, we use the forward stream as a transparent byte tunnel
        // by opening a second QUIC connection over the stream pair adapter.
        let conn = connect_quic_over_stream(
            self,
            fwd_send,
            fwd_recv,
            addr,
            user,
        )
        .await
        .with_context(|| format!("establish QUIC session to {addr} via jump host"))?;

        Ok(conn)
    }

    async fn connect_direct(&self, addr: &str, user: &str) -> anyhow::Result<Session> {
        let remote: SocketAddr = addr.parse().with_context(|| format!("parse address: {addr}"))?;

        // Use file-backed session store for 0-RTT resumption
        let session_cache_path = dirs_home().join(".bolt/session_cache");
        let store = FileSessionStore::load(session_cache_path);
        let client_config = tls::client_config_with_resume(store)
            .context("build TLS client config")?;

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .context("bind client endpoint")?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(remote, "bolt.local")
            .context("start QUIC connection")?
            .await
            .with_context(|| format!("QUIC handshake with {addr}"))?;

        debug!(addr, "QUIC connection established");

        self.verify_host_key(&conn, addr)?;
        self.authenticate(&conn, user).await?;

        Ok(Session { conn })
    }

    /// Verify the server's TLS certificate fingerprint against known_hosts.
    fn verify_host_key(&self, conn: &Connection, addr: &str) -> anyhow::Result<()> {
        let certs: Option<Vec<CertificateDer>> = conn
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<CertificateDer>>().ok())
            .map(|v| (*v).clone());

        let Some(certs) = certs else {
            bail!("server did not present a certificate");
        };

        let Some(cert_der) = certs.first() else {
            bail!("server certificate chain is empty");
        };

        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(cert_der.as_ref());
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&digest);

        let mut kh = self.known_hosts.lock().unwrap();
        match kh.lookup(addr) {
            Some(known) if known == fingerprint => {
                debug!(addr, "host key verified");
            }
            Some(_) => {
                bail!("HOST KEY MISMATCH for {addr} — possible MITM attack");
            }
            None => {
                warn!(addr, fingerprint = %hex_short(&fingerprint), "new host, accepting (TOFU)");
                let _ = kh.add(addr, fingerprint);
            }
        }

        Ok(())
    }

    /// Send our public key + username to the server over a control stream.
    async fn authenticate(&self, conn: &Connection, user: &str) -> anyhow::Result<()> {
        let (mut send, mut recv) = conn.open_bi().await.context("open auth stream")?;

        let auth_msg = bolt_proto::encode(&Message::AuthRequest {
            user: user.to_owned(),
            public_key: self.identity.public,
        })?;
        send.write_all(&auth_msg).await.context("send auth request")?;
        send.finish().context("finish auth send")?;

        let response = recv.read_to_end(4096).await.context("read auth response")?;
        if response.len() < 4 {
            bail!("auth response too short");
        }
        let len = u32::from_be_bytes(response[..4].try_into().unwrap()) as usize;
        if response.len() < 4 + len {
            bail!("auth response truncated");
        }
        let msg = bolt_proto::decode(&response[4..4 + len])?;

        match msg {
            Message::AuthSuccess => Ok(()),
            Message::AuthFailure { reason } => bail!("authentication failed: {reason}"),
            other => bail!("unexpected auth response: {other:?}"),
        }
    }

    /// Authenticate with password (fallback when key auth fails or no key).
    pub async fn authenticate_password(
        &self,
        conn: &Connection,
        user: &str,
        password: &str,
    ) -> anyhow::Result<()> {
        let (mut send, mut recv) = conn.open_bi().await.context("open auth stream")?;

        let auth_msg = bolt_proto::encode(&Message::AuthPassword {
            user: user.to_owned(),
            password: password.to_owned(),
        })?;
        send.write_all(&auth_msg).await.context("send password auth")?;
        send.finish().context("finish auth send")?;

        let response = recv.read_to_end(4096).await.context("read auth response")?;
        if response.len() < 4 {
            bail!("auth response too short");
        }
        let len = u32::from_be_bytes(response[..4].try_into().unwrap()) as usize;
        if response.len() < 4 + len {
            bail!("auth response truncated");
        }
        let msg = bolt_proto::decode(&response[4..4 + len])?;

        match msg {
            Message::AuthSuccess => Ok(()),
            Message::AuthFailure { reason } => bail!("password authentication failed: {reason}"),
            other => bail!("unexpected auth response: {other:?}"),
        }
    }
}

impl Session {
    /// Open a new bidirectional QUIC stream for a channel.
    pub async fn open_bi(&self) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
        self.conn.open_bi().await.context("open bidirectional stream")
    }
}

// ── Jump host: QUIC-over-stream ───────────────────────────────────────────

/// Create a QUIC connection tunneled through an existing (send, recv) stream pair.
///
/// We use a UDP-over-stream approach: each QUIC packet is framed as
/// `[u16 BE length][packet bytes]` on the stream. A custom `quinn::AsyncUdpSocket`
/// is not stable, so instead we use a local UDP loopback pair:
///
/// 1. Bind two local UDP sockets: proxy_a (QUIC endpoint) ↔ proxy_b (relay thread)
/// 2. Relay thread: UDP proxy_b ↔ stream pair
/// 3. QUIC connects to proxy_a's address
///
/// This adds ~1 copy overhead but works without unsafe code.
async fn connect_quic_over_stream(
    client: &Client,
    mut fwd_send: quinn::SendStream,
    mut fwd_recv: quinn::RecvStream,
    final_addr: &str,
    user: &str,
) -> anyhow::Result<Session> {
    use tokio::net::UdpSocket;

    // Two UDP sockets for proxying
    let proxy_a = UdpSocket::bind("127.0.0.1:0").await.context("bind proxy_a")?;
    let proxy_b = UdpSocket::bind("127.0.0.1:0").await.context("bind proxy_b")?;
    let addr_a = proxy_a.local_addr()?;
    let addr_b = proxy_b.local_addr()?;

    // Connect them to each other
    proxy_a.connect(addr_b).await?;
    proxy_b.connect(addr_a).await?;

    // Relay: stream → proxy_b (→ proxy_a → QUIC endpoint)
    let (relay_done_tx, relay_done_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let mut len_buf = [0u8; 2];

        loop {
            tokio::select! {
                // proxy_b UDP → stream
                result = proxy_b.recv(&mut buf) => {
                    let Ok(n) = result else { break };
                    let len = n as u16;
                    let _ = fwd_send.write_all(&len.to_be_bytes()).await;
                    let _ = fwd_send.write_all(&buf[..n]).await;
                }
                // stream → proxy_b UDP
                result = fwd_recv.read_exact(&mut len_buf) => {
                    if result.is_err() { break; }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let _ = fwd_recv.read_exact(&mut buf[..len]).await;
                    let _ = proxy_b.send(&buf[..len]).await;
                }
            }
        }
        let _ = relay_done_tx.send(());
    });

    // Build QUIC endpoint using proxy_a
    let client_config = tls::client_config().context("build TLS client config")?;
    let mut endpoint = Endpoint::client(addr_a).context("bind jump QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);

    // Connect QUIC to proxy_a (which will relay to the real server)
    let conn = endpoint
        .connect(addr_a, "bolt.local")
        .context("start QUIC connection via jump")?
        .await
        .with_context(|| format!("QUIC handshake via jump to {final_addr}"))?;

    client.verify_host_key(&conn, final_addr)?;
    client.authenticate(&conn, user).await?;

    let _ = relay_done_rx; // keep rx alive so relay task keeps running
    Ok(Session { conn })
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn load_or_generate_identity(path: &Path) -> anyhow::Result<KeyPair> {
    if path.exists() {
        KeyPair::load(path).with_context(|| format!("load identity key: {}", path.display()))
    } else {
        let kp = KeyPair::generate().context("generate identity key")?;
        kp.save(path)
            .with_context(|| format!("save identity: {}", path.display()))?;
        info!(path = %path.display(), "generated new identity key");
        Ok(kp)
    }
}

fn parse_host_port(addr: &str) -> anyhow::Result<(String, u16)> {
    let colon = addr.rfind(':').context("address must be host:port")?;
    let host = addr[..colon].to_owned();
    let port: u16 = addr[colon + 1..].parse().context("invalid port")?;
    Ok((host, port))
}

fn dirs_home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn hex_short(b: &[u8]) -> String {
    b.iter()
        .take(8)
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
