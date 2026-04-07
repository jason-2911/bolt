//! Server-side SSH agent forwarding.
//!
//! Creates a Unix socket for the remote shell's SSH_AUTH_SOCK.
//! Forwards agent protocol messages back to the client over QUIC.

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use bolt_proto::{read_msg, write_msg, Message};

/// Path of the forwarded agent socket for a session.
/// Format: /tmp/bolt-agent-{pid}-{rand}
pub fn agent_sock_path() -> String {
    format!("/tmp/bolt-agent-{}", std::process::id())
}

pub async fn handle_agent_forward(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> anyhow::Result<()> {
    // Expect AgentForwardRequest
    match read_msg(recv).await? {
        Some(Message::AgentForwardRequest) => {}
        other => anyhow::bail!("expected AgentForwardRequest, got {other:?}"),
    }

    #[cfg(unix)]
    {
        use tokio::net::UnixListener;

        let sock_path = agent_sock_path();
        // Remove stale socket
        let _ = std::fs::remove_file(&sock_path);

        let listener = UnixListener::bind(&sock_path)
            .with_context(|| format!("bind agent socket {sock_path}"))?;

        debug!(path = %sock_path, "agent socket ready");
        write_msg(send, &Message::AgentForwardAccept).await?;

        // Accept one connection at a time (typical ssh-agent usage)
        loop {
            let (mut unix_conn, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };

            // Forward each request from the local process to the client
            loop {
                // Read SSH agent request from local process
                let mut len_buf = [0u8; 4];
                match unix_conn.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(_) => break,
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                if unix_conn.read_exact(&mut body).await.is_err() { break; }

                let mut req_data = Vec::with_capacity(4 + len);
                req_data.extend_from_slice(&len_buf);
                req_data.extend_from_slice(&body);

                // Send to client
                if write_msg(send, &Message::AgentMessage { data: req_data }).await.is_err() {
                    break;
                }

                // Get response from client
                match read_msg(recv).await {
                    Ok(Some(Message::AgentMessage { data })) => {
                        if unix_conn.write_all(&data).await.is_err() { break; }
                    }
                    _ => break,
                }
            }
        }

        let _ = std::fs::remove_file(&sock_path);
    }
    #[cfg(not(unix))]
    {
        warn!("SSH agent forwarding not supported on this platform");
        write_msg(send, &Message::AgentForwardAccept).await.ok();
    }

    Ok(())
}
