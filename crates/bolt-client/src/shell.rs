//! Client interactive shell: PTY request, raw mode, env forwarding, bidirectional relay.

use std::os::unix::io::AsRawFd;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use bolt_proto::{read_msg, write_msg, ChannelType, Message};

use crate::client::Session;
use crate::terminal::{terminal_size, TermState};

/// Environment variables forwarded to the remote shell by default.
const FORWARD_ENV: &[&str] = &[
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "COLORTERM",
    "TERM_PROGRAM",
    "EDITOR",
    "VISUAL",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
];

pub async fn shell(session: &Session, extra_env: &[(String, String)]) -> anyhow::Result<()> {
    let (mut send, mut recv) = session.open_bi().await?;

    // Open shell channel
    write_msg(
        &mut send,
        &Message::ChannelOpen {
            channel_type: ChannelType::Shell,
            command: String::new(),
        },
    )
    .await?;

    // Wait for accept
    let Some(msg) = read_msg(&mut recv).await? else {
        anyhow::bail!("connection closed before channel accept");
    };
    match msg {
        Message::ChannelAccept => {}
        Message::ChannelReject { reason } => anyhow::bail!("shell rejected: {reason}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    // Forward selected environment variables
    for key in FORWARD_ENV {
        if let Ok(val) = std::env::var(key) {
            write_msg(
                &mut send,
                &Message::EnvSet {
                    key: key.to_string(),
                    val,
                },
            )
            .await?;
        }
    }

    for (key, val) in extra_env {
        write_msg(
            &mut send,
            &Message::EnvSet {
                key: key.clone(),
                val: val.clone(),
            },
        )
        .await?;
    }

    // Request PTY
    let stdin_fd = std::io::stdin().as_raw_fd();
    let (cols, rows) = terminal_size(stdin_fd);
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    write_msg(&mut send, &Message::PtyRequest { term, cols, rows }).await?;

    // Switch to raw mode
    let _raw = TermState::make_raw(stdin_fd)?;

    // Spawn stdin reader + SIGWINCH handler
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(64);

    let stdin_task = {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 4096];

            #[cfg(unix)]
            let mut sig_winch =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok();

            loop {
                tokio::select! {
                    result = stdin.read(&mut buf) => {
                        match result {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let msg = Message::Data(buf[..n].to_vec());
                                if tx.send(msg).await.is_err() { break; }
                            }
                        }
                    }
                    _ = async {
                        #[cfg(unix)]
                        if let Some(ref mut s) = sig_winch {
                            s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                        #[cfg(not(unix))]
                        std::future::pending::<()>().await;
                    } => {
                        let (c, r) = terminal_size(stdin_fd);
                        let msg = Message::WindowChange { cols: c, rows: r };
                        if tx.send(msg).await.is_err() { break; }
                    }
                }
            }
        })
    };

    // Bidirectional relay
    let mut stdout = tokio::io::stdout();

    loop {
        tokio::select! {
            msg = rx.recv() => {
                let Some(msg) = msg else { break };
                if write_msg(&mut send, &msg).await.is_err() { break; }
            }
            result = read_msg(&mut recv) => {
                match result {
                    Ok(Some(Message::Data(data))) => {
                        stdout.write_all(&data).await.ok();
                        stdout.flush().await.ok();
                    }
                    Ok(Some(Message::ExitStatus { code })) => {
                        debug!(code, "remote exit");
                        break;
                    }
                    // Respond to server keepalive pings
                    Ok(Some(Message::Ping)) => {
                        write_msg(&mut send, &Message::Pong).await.ok();
                    }
                    Ok(Some(Message::Eof)) | Ok(None) | Err(_) => break,
                    Ok(Some(_)) => {}
                }
            }
        }
    }

    stdin_task.abort();
    Ok(())
}
