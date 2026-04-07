//! Client-side port forwarding.
//!
//! Local forwarding (-L local_port:remote_host:remote_port):
//!   - Binds a local TCP port
//!   - Each incoming connection opens a new QUIC stream to the server
//!   - Server connects to remote_host:remote_port and relays bytes
//!
//! Remote forwarding (-R remote_port:local_host:local_port):
//!   - Server binds a port, server sends ForwardOpen when clients connect
//!   - Client connects to local_host:local_port, relays bytes back

use anyhow::{bail, Context as _};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::info;

use bolt_proto::{read_msg, write_msg, ChannelType, Message};

use crate::client::Session;

const BUF: usize = 32 * 1024;

// ── Local forwarding: -L local_port:remote_host:remote_port ──────────────

/// Parse "-L" spec: "local_port:remote_host:remote_port"
pub struct LocalForward {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

impl LocalForward {
    pub fn parse(spec: &str) -> anyhow::Result<Self> {
        // Format: local_port:remote_host:remote_port
        // Or: local_host:local_port:remote_host:remote_port
        let parts: Vec<&str> = spec.splitn(4, ':').collect();
        match parts.as_slice() {
            [lport, rhost, rport] => Ok(Self {
                local_port: lport.parse().context("invalid local port")?,
                remote_host: rhost.to_string(),
                remote_port: rport.parse().context("invalid remote port")?,
            }),
            [_lhost, lport, rhost, rport] => Ok(Self {
                local_port: lport.parse().context("invalid local port")?,
                remote_host: rhost.to_string(),
                remote_port: rport.parse().context("invalid remote port")?,
            }),
            _ => bail!("invalid -L spec: expected local_port:remote_host:remote_port"),
        }
    }
}

/// Run local port forwarding until cancelled.
/// Binds `0.0.0.0:local_port`, accepts TCP connections, tunnels each through a new QUIC stream.
pub async fn run_local_forward(session: &Session, fwd: LocalForward) -> anyhow::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", fwd.local_port))
        .await
        .with_context(|| format!("bind local port {}", fwd.local_port))?;

    info!(
        local_port = fwd.local_port,
        remote = %format!("{}:{}", fwd.remote_host, fwd.remote_port),
        "local port forwarding active"
    );

    eprintln!(
        "bolt: forwarding 127.0.0.1:{} -> {}:{}",
        fwd.local_port, fwd.remote_host, fwd.remote_port
    );

    loop {
        let (tcp, peer) = listener.accept().await.context("accept local TCP")?;
        info!(peer = %peer, "new forward connection");

        let (send, recv) = session.open_bi().await?;
        let rhost = fwd.remote_host.clone();
        let rport = fwd.remote_port;

        tokio::spawn(async move {
            if let Err(e) = handle_local_forward(tcp, send, recv, &rhost, rport).await {
                tracing::warn!(error = %e, "forward error");
            }
        });
    }
}

async fn handle_local_forward(
    mut tcp: TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    remote_host: &str,
    remote_port: u16,
) -> anyhow::Result<()> {
    // Open port-forward channel on the server
    write_msg(
        &mut send,
        &Message::ChannelOpen {
            channel_type: ChannelType::PortForward,
            command: format!("{remote_host}:{remote_port}"),
        },
    )
    .await?;

    let Some(msg) = read_msg(&mut recv).await? else {
        bail!("connection closed waiting for forward accept");
    };
    match msg {
        Message::ChannelAccept => {}
        Message::ChannelReject { reason } => bail!("forward rejected: {reason}"),
        // Server's handle_forward sends ForwardAccept after opening TCP
        Message::ForwardAccept => {}
        other => bail!("unexpected forward response: {other:?}"),
    }

    // Bidirectional relay: local TCP ↔ QUIC stream
    let mut tcp_buf = vec![0u8; BUF];

    loop {
        tokio::select! {
            // Local TCP → QUIC
            result = tcp.read(&mut tcp_buf) => {
                let n = result.context("read local TCP")?;
                if n == 0 {
                    write_msg(&mut send, &Message::Eof).await.ok();
                    break;
                }
                write_msg(&mut send, &Message::Data(tcp_buf[..n].to_vec())).await?;
            }
            // QUIC → local TCP
            result = read_msg(&mut recv) => {
                match result? {
                    Some(Message::Data(data)) => {
                        tcp.write_all(&data).await.context("write local TCP")?;
                    }
                    Some(Message::Eof) | None => break,
                    Some(other) => bail!("unexpected forward data: {other:?}"),
                }
            }
        }
    }

    Ok(())
}
