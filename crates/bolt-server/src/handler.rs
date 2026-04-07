//! Per-connection handler: Noise_XX handshake → auth → stream dispatch.

use std::sync::Arc;

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use bolt_crypto::{auth::Authenticator, keys::KeyPair, noise::NoiseHandshake};
use bolt_proto::{
    channel::{ChannelOpenMsg, ChannelType, MsgType},
    packet::{Packet, PacketType},
};
use bolt_session::{Session, Stream};
use bolt_transport::Connection;

use super::{exec::handle_exec_channel, shell::handle_shell_channel, transfer::handle_transfer_channel};

pub async fn handle_connection(
    conn: Connection,
    host_key: KeyPair,
    auth: Option<Arc<Authenticator>>,
) -> anyhow::Result<()> {
    let remote = conn.remote_addr();
    info!(component = "server", remote = %remote, "new connection");

    // ── Noise_XX handshake (responder) ─────────────────────────────────────

    let mut hs = NoiseHandshake::new_responder(&host_key)?;

    // msg 1: -> e
    let pkt1 = conn.recv().await.context("recv msg1")?;
    let _    = hs.read_message(&pkt1.payload)?;

    // msg 2: <- e, ee, s, es
    let msg2 = hs.write_message_vec(&[])?;
    conn.send_raw(Packet::new(PacketType::Handshake, conn.conn_id(), msg2)).await?;

    // msg 3: -> s, se
    let pkt3    = conn.recv().await.context("recv msg3")?;
    let _payload = hs.read_message(&pkt3.payload)?;

    let result = hs.finalize()?;
    let remote_key = result.remote_key;

    info!(
        component = "server",
        remote    = %remote,
        peer_key  = %hex8(&remote_key),
        "handshake complete"
    );

    // ── Authentication ─────────────────────────────────────────────────────

    if let Some(auth) = auth {
        if let Err(e) = auth.authenticate(&remote_key) {
            warn!(component = "server", remote = %remote, error = %e, "authentication failed");
            return Ok(());
        }
        info!(component = "server", remote = %remote, "client authenticated");
    }

    // ── Session ────────────────────────────────────────────────────────────

    let session = Session::new(conn, result, true);
    info!(component = "server", remote = %remote, "session established");

    loop {
        let stream = match session.accept_stream().await {
            Some(s) => s,
            None    => break,
        };
        let remote2 = remote;
        tokio::spawn(async move {
            if let Err(e) = handle_stream(stream, remote2).await {
                warn!(component = "server", remote = %remote2, "stream error: {e}");
            }
        });
    }

    info!(component = "server", remote = %remote, "session ended");
    Ok(())
}

// ── Stream dispatch ────────────────────────────────────────────────────────

async fn handle_stream(mut stream: Stream, remote: std::net::SocketAddr) -> anyhow::Result<()> {
    // Read the channel-open message
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 || buf[0] != MsgType::ChannelOpen as u8 {
        return Ok(());
    }

    let open_msg = ChannelOpenMsg::unmarshal(&buf[..n])?;
    info!(
        component = "server",
        r#type    = %open_msg.channel_type,
        command   = %open_msg.command,
        remote    = %remote,
        "channel opened"
    );

    // SCP manages its own confirm — dispatch immediately
    match open_msg.channel_type {
        ChannelType::Scp => {
            handle_transfer_channel(&mut stream, &open_msg.command).await?;
        }
        other => {
            // All other channels receive a generic confirm first
            stream.write_all(&[MsgType::ChannelOpenConfirm as u8]).await?;

            match other {
                ChannelType::Shell => handle_shell_channel(&mut stream).await?,
                ChannelType::Exec  => handle_exec_channel(&mut stream, &open_msg.command).await?,
                _ => {
                    stream.write_all(&[MsgType::ChannelOpenFail as u8]).await?;
                }
            }
        }
    }
    Ok(())
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{:02x}", x)).collect()
}
