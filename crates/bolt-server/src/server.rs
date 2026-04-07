//! Bolt server lifecycle: bind QUIC endpoint, accept connections, graceful shutdown.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use quinn::Endpoint;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use bolt_crypto::{
    auth::Authenticator,
    keys::{AuthorizedKeys, KeyPair},
    tls,
};

use crate::{handler::handle_connection, ratelimit::RateLimiter};

// ── Config ────────────────────────────────────────────────────────────────

pub struct ServerConfig {
    pub listen_addr: String,
    pub host_key_path: PathBuf,
    pub cert_path: PathBuf,
    pub auth_keys_path: PathBuf,
    pub max_connections: usize,
    /// Max simultaneous connections per client IP.
    pub max_per_ip: usize,
    /// Max new connections per IP within the rate-limit window.
    pub rate_limit_window_secs: u64,
    pub rate_limit_burst: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:2222".into(),
            host_key_path: PathBuf::from("/etc/bolt/host_key"),
            cert_path: PathBuf::from("/etc/bolt/host_cert.der"),
            auth_keys_path: PathBuf::from("/etc/bolt/authorized_keys"),
            max_connections: 1000,
            max_per_ip: 10,
            rate_limit_window_secs: 60,
            rate_limit_burst: 20,
        }
    }
}

// ── Server ────────────────────────────────────────────────────────────────

pub struct Server {
    config: ServerConfig,
    host_key: KeyPair,
    auth: Option<Arc<Authenticator>>,
}

impl Server {
    pub fn new(config: ServerConfig) -> anyhow::Result<Self> {
        let host_key = load_or_generate_host_key(&config.host_key_path)?;
        info!(path = %config.host_key_path.display(), "host key loaded");

        let auth = match AuthorizedKeys::load(&config.auth_keys_path) {
            Ok(ak) => {
                if ak.is_empty() {
                    warn!("no authorized keys loaded — password auth only");
                }
                Some(Arc::new(Authenticator::new(ak)))
            }
            Err(e) => {
                warn!(error = %e, "authorized keys not loaded — password auth only");
                None
            }
        };

        Ok(Self {
            config,
            host_key,
            auth,
        })
    }

    pub async fn listen_and_serve(&self) -> anyhow::Result<()> {
        let server_config = tls::server_config(&self.host_key, &self.config.cert_path)
            .context("build TLS server config")?;

        let endpoint = if let Some(ep) = try_systemd_socket(server_config.clone())? {
            info!("using systemd-provided socket");
            ep
        } else {
            let addr: SocketAddr = self
                .config
                .listen_addr
                .parse()
                .with_context(|| format!("parse listen address: {}", self.config.listen_addr))?;
            Endpoint::server(server_config, addr)
                .with_context(|| format!("bind {}", self.config.listen_addr))?
        };

        info!(addr = %self.config.listen_addr, "bolt server listening");

        let sem = Arc::new(Semaphore::new(self.config.max_connections));
        let limiter = Arc::new(RateLimiter::new(
            self.config.max_per_ip,
            Duration::from_secs(self.config.rate_limit_window_secs),
            self.config.rate_limit_burst,
        ));

        while let Some(incoming) = endpoint.accept().await {
            let remote_ip = incoming.remote_address().ip();

            // Rate limit check before accepting
            if let Err(reason) = limiter.check_and_admit(remote_ip) {
                warn!(ip = %remote_ip, reason, "connection rejected by rate limiter");
                incoming.refuse();
                continue;
            }

            let permit = match Arc::clone(&sem).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(ip = %remote_ip, "max_connections reached, dropping connection");
                    limiter.release(remote_ip);
                    incoming.refuse();
                    continue;
                }
            };

            let auth = self.auth.clone();
            let limiter2 = Arc::clone(&limiter);

            tokio::spawn(async move {
                let remote = incoming.remote_address();
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = handle_connection(conn, auth).await {
                            error!(remote = %remote, error = %e, "connection error");
                        }
                    }
                    Err(e) => {
                        error!(remote = %remote, error = %e, "QUIC accept error");
                    }
                }
                limiter2.release(remote_ip);
                drop(permit);
            });
        }

        Ok(())
    }
}

// ── systemd socket activation ─────────────────────────────────────────────

/// If `LISTEN_FDS` is set (systemd socket activation), return an endpoint
/// using the inherited file descriptor. Otherwise return None.
fn try_systemd_socket(server_config: quinn::ServerConfig) -> anyhow::Result<Option<Endpoint>> {
    let fds: usize = match std::env::var("LISTEN_FDS") {
        Ok(v) => v.parse().unwrap_or(0),
        Err(_) => return Ok(None),
    };

    if fds == 0 {
        return Ok(None);
    }

    // systemd passes sockets starting at fd 3
    #[cfg(unix)]
    {
        use std::os::unix::io::FromRawFd;
        let fd = 3i32;
        let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        std_sock
            .set_nonblocking(true)
            .context("set systemd socket non-blocking")?;
        let local_addr = std_sock.local_addr().context("systemd socket local addr")?;

        // Convert to tokio then bind QUIC on same addr (quinn doesn't support fd-based sockets)
        drop(std_sock);

        let ep = Endpoint::server(server_config, local_addr)
            .context("create endpoint on systemd socket addr")?;
        return Ok(Some(ep));
    }

    #[cfg(not(unix))]
    {
        let _ = server_config;
        Ok(None)
    }
}

fn load_or_generate_host_key(path: &Path) -> anyhow::Result<KeyPair> {
    if path.exists() {
        KeyPair::load(path).with_context(|| format!("read host key {}", path.display()))
    } else {
        let kp = KeyPair::generate().context("generate host key")?;
        kp.save(path)
            .with_context(|| format!("save host key {}", path.display()))?;
        info!(path = %path.display(), "generated new host key");
        Ok(kp)
    }
}
