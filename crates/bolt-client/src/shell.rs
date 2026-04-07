//! Client interactive shell: PTY request, raw mode, bidirectional relay.

use std::os::unix::io::AsRawFd;

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use bolt_proto::channel::{ChannelOpenMsg, ChannelType, MsgType, PtyRequest, WindowChangeRequest};
use bolt_session::{Session, PRIORITY_HIGH};

use super::terminal::{terminal_size, TermState};

pub async fn shell(session: &Session) -> anyhow::Result<()> {
    let mut stream = session.open_stream(PRIORITY_HIGH)?;

    // Open shell channel
    let open = ChannelOpenMsg { channel_type: ChannelType::Shell, command: String::new() };
    stream.write_all(&open.marshal()).await?;

    // Wait for confirm
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;
    if buf[0] != MsgType::ChannelOpenConfirm as u8 {
        anyhow::bail!("shell channel rejected");
    }

    // Request PTY
    let stdin_fd = std::io::stdin().as_raw_fd();
    let (cols, rows) = terminal_size(stdin_fd);
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let pty_req = PtyRequest { term, width_chars: cols, height_chars: rows };
    stream.write_all(&pty_req.marshal()).await?;

    // Raw mode
    let _raw = TermState::make_raw(stdin_fd)?;

    // Relay — use two separate tasks with channel
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // stdin + SIGWINCH → tx
    let stdin_handle = {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 4096];

            #[cfg(unix)]
            let mut sig = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::window_change()
            ).ok();

            loop {
                tokio::select! {
                    n = stdin.read(&mut buf) => {
                        match n {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let mut msg = vec![MsgType::ChannelData as u8];
                                msg.extend_from_slice(&(n as u32).to_be_bytes());
                                msg.extend_from_slice(&buf[..n]);
                                if tx.send(msg).await.is_err() { break; }
                            }
                        }
                    }
                    _ = async {
                        #[cfg(unix)]
                        if let Some(ref mut s) = sig { s.recv().await; } else { std::future::pending::<()>().await; }
                        #[cfg(not(unix))]
                        std::future::pending::<()>().await;
                    } => {
                        let (c, r) = terminal_size(stdin_fd);
                        let wc = WindowChangeRequest { width_chars: c, height_chars: r };
                        if tx.send(wc.marshal()).await.is_err() { break; }
                    }
                }
            }
        })
    };

    // Bidirectional relay using stream + rx
    let mut stdout = tokio::io::stdout();
    let mut read_buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(data) => { if stream.write_all(&data).await.is_err() { break; } }
                    None => break,
                }
            }
            n = stream.read(&mut read_buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data = &read_buf[..n];
                        let payload = if data[0] == MsgType::ChannelData as u8 && n > 5 {
                            &data[5..n]
                        } else {
                            data
                        };
                        let _ = stdout.write_all(payload).await;
                        let _ = stdout.flush().await;
                    }
                }
            }
        }
    }

    stdin_handle.abort();
    Ok(())
}
