//! Server-side port forwarding: relay TCP connections to the requested destination.
//!
//! Local forwarding (-L): client opens a QUIC stream with ChannelOpen { PortForward, "host:port" }.
//! Server opens a TCP connection to host:port and relays bytes bidirectionally.

use anyhow::Context as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::info;

use bolt_proto::{read_msg, write_msg, Message};

const BUF: usize = 32 * 1024;

/// `command` format: "host:port"
pub async fn handle_forward(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    command: &str,
) -> anyhow::Result<()> {
    // Parse host:port from command
    let (host, port) = parse_host_port(command)?;
    let addr = format!("{host}:{port}");

    info!(target = %addr, "opening forward connection");

    let mut tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("TCP connect to {addr}"))?;

    write_msg(send, &Message::ForwardAccept).await?;

    // Bidirectional relay: QUIC ↔ TCP
    let (mut tcp_r, mut tcp_w) = tcp.split();

    let net_buf = vec![0u8; BUF];
    let mut tcp_buf = vec![0u8; BUF];

    loop {
        tokio::select! {
            // QUIC → TCP
            result = read_msg(recv) => {
                match result {
                    Ok(Some(Message::Data(data))) => {
                        tcp_w.write_all(&data).await.context("write to TCP")?;
                    }
                    Ok(Some(Message::Eof)) | Ok(None) => break,
                    Ok(Some(other)) => {
                        anyhow::bail!("unexpected forward message: {other:?}");
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            // TCP → QUIC
            result = tcp_r.read(&mut tcp_buf) => {
                let n = result.context("read from TCP")?;
                if n == 0 {
                    write_msg(send, &Message::Eof).await.ok();
                    break;
                }
                let _ = net_buf; // silence unused
                write_msg(send, &Message::Data(tcp_buf[..n].to_vec())).await?;
            }
        }
    }

    info!(target = %addr, "forward connection closed");
    Ok(())
}

fn parse_host_port(s: &str) -> anyhow::Result<(String, u16)> {
    // Handle IPv6: [::1]:80
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest
            .find(']')
            .context("invalid IPv6 address in forward target")?;
        let host = rest[..end].to_owned();
        let port_str = rest[end + 1..].trim_start_matches(':');
        let port: u16 = port_str.parse().context("invalid port")?;
        return Ok((host, port));
    }

    // host:port
    let colon = s.rfind(':').context("forward target must be host:port")?;
    let host = s[..colon].to_owned();
    let port: u16 = s[colon + 1..].parse().context("invalid port")?;
    Ok((host, port))
}
