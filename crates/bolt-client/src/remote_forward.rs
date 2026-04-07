//! Client-side remote port forwarding (-R remote_port:local_host:local_port).
//!
//! The server binds `remote_port` and for each incoming TCP connection opens
//! a new QUIC stream to the client with RemoteForwardIncoming. The client
//! then connects to `local_host:local_port` and relays bytes.

use anyhow::{bail, Context as _};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::info;

use bolt_proto::{read_msg, write_msg, ChannelType, Message};

use crate::client::Session;

const BUF: usize = 32 * 1024;

pub struct RemoteForward {
    pub remote_port: u16,
    pub local_host: String,
    pub local_port: u16,
}

impl RemoteForward {
    /// Parse "-R remote_port:local_host:local_port"
    pub fn parse(spec: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = spec.splitn(3, ':').collect();
        match parts.as_slice() {
            [rport, lhost, lport] => Ok(Self {
                remote_port: rport.parse().context("invalid remote port")?,
                local_host: lhost.to_string(),
                local_port: lport.parse().context("invalid local port")?,
            }),
            _ => bail!("invalid -R spec: expected remote_port:local_host:local_port"),
        }
    }
}

/// Run remote port forwarding until cancelled.
/// Opens a control stream to the server, asks it to bind `remote_port`,
/// then handles server-initiated streams for each incoming TCP connection.
pub async fn run_remote_forward(session: &Session, fwd: RemoteForward) -> anyhow::Result<()> {
    let (mut ctrl_send, mut ctrl_recv) = session.open_bi().await?;

    write_msg(
        &mut ctrl_send,
        &Message::ChannelOpen {
            channel_type: ChannelType::RemoteForward,
            command: fwd.remote_port.to_string(),
        },
    )
    .await?;

    // Wait for ChannelAccept
    match read_msg(&mut ctrl_recv).await? {
        Some(Message::ChannelAccept) => {}
        Some(Message::ChannelReject { reason }) => bail!("remote forward rejected: {reason}"),
        other => bail!("unexpected: {other:?}"),
    }

    // Wait for RemoteForwardBound to learn actual port
    let bound_port = match read_msg(&mut ctrl_recv).await? {
        Some(Message::RemoteForwardBound { bound_port }) => bound_port,
        other => bail!("expected RemoteForwardBound, got {other:?}"),
    };

    eprintln!(
        "bolt: remote forward :{} -> {}:{}",
        bound_port, fwd.local_host, fwd.local_port
    );
    info!(remote_port = bound_port, local = %format!("{}:{}", fwd.local_host, fwd.local_port), "remote forward active");

    let lhost = fwd.local_host.clone();
    let lport = fwd.local_port;
    let conn = session.conn.clone();

    // Background: accept server-initiated streams (RemoteForwardIncoming)
    let forward_task = tokio::spawn(async move {
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(_) => break,
            };

            match read_msg(&mut recv).await {
                Ok(Some(Message::RemoteForwardIncoming { peer })) => {
                    let lh = lhost.clone();
                    let lp = lport;
                    tokio::spawn(async move {
                        if let Err(e) = relay_to_local(&mut send, &mut recv, &lh, lp, &peer).await {
                            tracing::warn!(error = %e, peer, "remote forward relay error");
                        }
                    });
                }
                _ => break,
            }
        }
    });

    // Keep control stream open until Ctrl+C
    tokio::signal::ctrl_c().await.ok();
    write_msg(&mut ctrl_send, &Message::RemoteForwardClose).await.ok();
    forward_task.abort();

    Ok(())
}

async fn relay_to_local(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    local_host: &str,
    local_port: u16,
    peer: &str,
) -> anyhow::Result<()> {
    let addr = format!("{local_host}:{local_port}");
    let mut tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("connect to local {addr}"))?;

    info!(peer, local = %addr, "remote forward connection");
    write_msg(send, &Message::ForwardAccept).await?;

    let mut buf = vec![0u8; BUF];
    loop {
        tokio::select! {
            // QUIC → local TCP
            result = read_msg(recv) => {
                match result? {
                    Some(Message::Data(data)) => {
                        tcp.write_all(&data).await.context("write local")?;
                    }
                    Some(Message::Eof) | None => break,
                    Some(other) => bail!("unexpected: {other:?}"),
                }
            }
            // local TCP → QUIC
            result = tcp.read(&mut buf) => {
                let n = result.context("read local")?;
                if n == 0 {
                    write_msg(send, &Message::Eof).await.ok();
                    break;
                }
                write_msg(send, &Message::Data(buf[..n].to_vec())).await?;
            }
        }
    }
    Ok(())
}
