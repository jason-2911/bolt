//! SSH agent forwarding.
//!
//! Client connects to local SSH_AUTH_SOCK, forwards agent protocol
//! messages through a QUIC stream to the server.
//! Server creates a Unix socket the remote shell's SSH_AUTH_SOCK points to.
//!
//! Protocol:
//!   Client → Server: AgentForwardRequest
//!   Server → Client: AgentForwardAccept
//!   Each agent message: AgentMessage { data }  (bidirectional)

use anyhow::{bail, Context as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use bolt_proto::{read_msg, write_msg, ChannelType, Message};

use crate::client::Session;

/// Start agent forwarding for a session.
/// This must be called before `shell()` so the server can set SSH_AUTH_SOCK.
pub async fn request_agent_forward(session: &Session) -> anyhow::Result<AgentForwardHandle> {
    let agent_sock =
        std::env::var("SSH_AUTH_SOCK").context("SSH_AUTH_SOCK not set — no ssh-agent running?")?;

    let (mut send, mut recv) = session.open_bi().await?;
    write_msg(
        &mut send,
        &Message::ChannelOpen {
            channel_type: ChannelType::AgentForward,
            command: String::new(),
        },
    )
    .await?;

    match read_msg(&mut recv).await? {
        Some(Message::ChannelAccept) => {}
        Some(Message::ChannelReject { reason }) => bail!("agent forward rejected: {reason}"),
        other => bail!("unexpected: {other:?}"),
    }

    write_msg(&mut send, &Message::AgentForwardRequest).await?;

    match read_msg(&mut recv).await? {
        Some(Message::AgentForwardAccept) => {}
        other => bail!("agent forward not accepted: {other:?}"),
    }

    // Spawn relay task: QUIC ↔ local SSH agent socket
    let handle = tokio::spawn(relay_agent(send, recv, agent_sock));

    Ok(AgentForwardHandle { _task: handle })
}

pub struct AgentForwardHandle {
    _task: tokio::task::JoinHandle<()>,
}

async fn relay_agent(mut send: quinn::SendStream, mut recv: quinn::RecvStream, agent_path: String) {
    #[cfg(unix)]
    {
        use tokio::net::UnixStream;

        loop {
            // Each agent request from server: receive, forward to local agent, reply
            let req = match read_msg(&mut recv).await {
                Ok(Some(Message::AgentMessage { data })) => data,
                _ => break,
            };

            // Connect to local agent for each request (stateless per-request)
            let mut agent = match UnixStream::connect(&agent_path).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "connect to ssh-agent failed");
                    break;
                }
            };

            // Forward request to agent
            if agent.write_all(&req).await.is_err() {
                break;
            }

            // Read agent response (SSH agent: u32 length + body)
            let mut len_buf = [0u8; 4];
            if agent.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            if agent.read_exact(&mut body).await.is_err() {
                break;
            }

            let mut resp = Vec::with_capacity(4 + len);
            resp.extend_from_slice(&len_buf);
            resp.extend_from_slice(&body);

            if write_msg(&mut send, &Message::AgentMessage { data: resp })
                .await
                .is_err()
            {
                break;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (send, recv, agent_path);
        tracing::warn!("SSH agent forwarding not supported on this platform");
    }
}
