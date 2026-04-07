//! Server-side remote port forwarding (-R).
//!
//! Flow:
//!   1. Client opens ChannelType::RemoteForward, command = "bind_port"
//!   2. Server binds TCP on bind_port (0 = OS picks port)
//!   3. Server replies RemoteForwardBound { bound_port }
//!   4. For each incoming TCP connection:
//!      - Server calls conn.open_bi() to client
//!      - Sends RemoteForwardIncoming { peer }
//!      - Relays bytes bidirectionally until EOF

use anyhow::Context as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::info;

use bolt_proto::{read_msg, write_msg, Message};

const BUF: usize = 32 * 1024;

pub async fn handle_remote_forward(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    command: &str,
    conn: &quinn::Connection,
) -> anyhow::Result<()> {
    let bind_port: u16 = command.trim().parse().unwrap_or(0);

    let listener = TcpListener::bind(format!("0.0.0.0:{bind_port}"))
        .await
        .with_context(|| format!("bind remote forward port {bind_port}"))?;

    let bound_port = listener.local_addr()?.port();
    info!(port = bound_port, "remote forward listening");

    write_msg(send, &Message::RemoteForwardBound { bound_port }).await?;

    // Accept TCP connections and notify client via new QUIC streams
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (tcp, peer) = result.context("accept remote forward TCP")?;
                let peer_str = peer.to_string();
                let conn2 = conn.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_incoming(tcp, conn2, peer_str).await {
                        tracing::warn!(error = %e, "remote forward error");
                    }
                });
            }
            // If client closes the control stream, stop forwarding
            msg = read_msg(recv) => {
                match msg {
                    Ok(Some(Message::RemoteForwardClose)) | Ok(None) => break,
                    _ => {}
                }
            }
        }
    }

    info!(port = bound_port, "remote forward closed");
    Ok(())
}

async fn handle_incoming(
    mut tcp: TcpStream,
    conn: quinn::Connection,
    peer: String,
) -> anyhow::Result<()> {
    // Open a new QUIC stream to the client for this TCP connection
    let (mut send, mut recv) = conn.open_bi().await.context("open remote forward stream")?;

    write_msg(&mut send, &Message::RemoteForwardIncoming { peer: peer.clone() }).await?;

    // Wait for client to accept
    match read_msg(&mut recv).await? {
        Some(Message::ForwardAccept) => {}
        Some(Message::ForwardReject { reason }) => {
            anyhow::bail!("client rejected remote forward: {reason}");
        }
        other => anyhow::bail!("unexpected remote forward response: {other:?}"),
    }

    // Relay bytes
    let mut buf = vec![0u8; BUF];
    loop {
        tokio::select! {
            result = tcp.read(&mut buf) => {
                let n = result.context("read TCP")?;
                if n == 0 {
                    write_msg(&mut send, &Message::Eof).await.ok();
                    break;
                }
                write_msg(&mut send, &Message::Data(buf[..n].to_vec())).await?;
            }
            result = read_msg(&mut recv) => {
                match result? {
                    Some(Message::Data(data)) => {
                        tcp.write_all(&data).await.context("write TCP")?;
                    }
                    Some(Message::Eof) | None => break,
                    Some(other) => anyhow::bail!("unexpected: {other:?}"),
                }
            }
        }
    }

    Ok(())
}
