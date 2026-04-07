//! ControlMaster — share a single QUIC connection across multiple bolt invocations.
//!
//! Protocol:
//!   Master process binds a Unix socket at `~/.bolt/ctrl/<fingerprint>.sock`.
//!   Slave processes connect to the socket, send a `ControlRequest` (channel
//!   type + command), and the master opens the corresponding QUIC stream on
//!   their behalf, then relays raw bytes bidirectionally.
//!
//! Usage:
//!   // In the first bolt invocation (master):
//!   let master = ControlMaster::start(&session, &socket_path).await?;
//!   // keep alive until done
//!
//!   // In subsequent invocations (slaves):
//!   if let Some(conn) = ControlSlave::try_connect(&socket_path).await? {
//!       conn.run_shell().await?;
//!   }

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use crate::client::Session;

// ── Socket path ───────────────────────────────────────────────────────────

/// Default control socket path for a given server address.
pub fn control_socket_path(addr: &str) -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    // Sanitize addr: replace special chars with _
    let safe: String = addr
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    home.join(".bolt/ctrl").join(format!("{safe}.sock"))
}

// ── Master ────────────────────────────────────────────────────────────────

/// ControlMaster: accepts slave connections on a Unix socket,
/// proxying each one through the shared QUIC session.
pub struct ControlMaster {
    socket_path: PathBuf,
}

impl ControlMaster {
    /// Start listening on the control socket.
    /// Spawns a background task; returns immediately.
    #[cfg(unix)]
    pub async fn start(session: &Session, socket_path: &Path) -> anyhow::Result<Self> {
        use tokio::net::UnixListener;

        // Ensure directory exists
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Remove stale socket
        let _ = std::fs::remove_file(socket_path);

        let listener = UnixListener::bind(socket_path)
            .with_context(|| format!("bind control socket {}", socket_path.display()))?;

        debug!(path = %socket_path.display(), "control socket ready");

        let conn = session.conn.clone();
        let sock_path = socket_path.to_path_buf();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let conn2 = conn.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_slave(conn2, stream).await {
                                warn!(error = %e, "control slave error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "control socket accept error");
                        break;
                    }
                }
            }
            let _ = std::fs::remove_file(&sock_path);
        });

        Ok(Self {
            socket_path: socket_path.to_path_buf(),
        })
    }

    #[cfg(not(unix))]
    pub async fn start(_session: &Session, socket_path: &Path) -> anyhow::Result<Self> {
        warn!("ControlMaster is not supported on this platform");
        Ok(Self {
            socket_path: socket_path.to_path_buf(),
        })
    }
}

impl Drop for ControlMaster {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Handle one slave connection: open a QUIC stream and relay bytes.
#[cfg(unix)]
async fn handle_slave(
    conn: quinn::Connection,
    mut unix_stream: tokio::net::UnixStream,
) -> anyhow::Result<()> {
    // Read 1-byte channel type + variable-length command
    let mut header = [0u8; 2];
    unix_stream.read_exact(&mut header).await?;
    let _channel_type = header[0];
    let cmd_len = header[1] as usize;

    let mut cmd_buf = vec![0u8; cmd_len];
    if cmd_len > 0 {
        unix_stream.read_exact(&mut cmd_buf).await?;
    }
    let _command = String::from_utf8_lossy(&cmd_buf).into_owned();

    // Open a QUIC stream for this slave
    let (mut quic_send, mut quic_recv) =
        conn.open_bi().await.context("open QUIC stream for slave")?;

    // The slave connection itself is a raw byte relay
    // (The slave has already done channel-level negotiation through the master)
    let (mut unix_r, mut unix_w) = unix_stream.into_split();

    let t1 = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match unix_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if quic_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        quic_send.finish().ok();
    });

    let t2 = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(None) | Err(_) => break,
                Ok(Some(n)) => {
                    if unix_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let _ = tokio::join!(t1, t2);
    Ok(())
}

// ── Slave ─────────────────────────────────────────────────────────────────

/// ControlSlave: connects to an existing master's Unix socket.
pub struct ControlSlave {
    #[cfg(unix)]
    stream: tokio::net::UnixStream,
    #[cfg(not(unix))]
    _phantom: (),
}

impl ControlSlave {
    /// Try to connect to an existing master. Returns `None` if no master is running.
    pub async fn try_connect(socket_path: &Path) -> anyhow::Result<Option<Self>> {
        #[cfg(unix)]
        {
            if !socket_path.exists() {
                return Ok(None);
            }
            match tokio::net::UnixStream::connect(socket_path).await {
                Ok(stream) => Ok(Some(Self { stream })),
                Err(_) => Ok(None),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            Ok(None)
        }
    }

    /// Send a channel request to the master, then relay stdin/stdout.
    #[cfg(unix)]
    pub async fn relay_stdio(mut self, channel_type: u8, command: &str) -> anyhow::Result<()> {
        use tokio::io::{stdin, stdout};

        // Send header
        let cmd_bytes = command.as_bytes();
        let header = [channel_type, cmd_bytes.len().min(255) as u8];
        self.stream.write_all(&header).await?;
        if !cmd_bytes.is_empty() {
            self.stream
                .write_all(&cmd_bytes[..header[1] as usize])
                .await?;
        }

        let (mut r, mut w) = self.stream.into_split();

        let t1 = tokio::spawn(async move {
            let mut stdin = stdin();
            let mut buf = vec![0u8; 4096];
            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let t2 = tokio::spawn(async move {
            let mut stdout = stdout();
            let mut buf = vec![0u8; 4096];
            loop {
                match r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stdout.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let _ = tokio::join!(t1, t2);
        Ok(())
    }

    #[cfg(not(unix))]
    pub async fn relay_stdio(self, _channel_type: u8, _command: &str) -> anyhow::Result<()> {
        bail!("ControlMaster not supported on this platform");
    }
}
