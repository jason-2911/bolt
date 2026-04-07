//! Client remote command execution.

use anyhow::Context as _;
use tokio::io::AsyncWriteExt;

use bolt_proto::{read_msg, write_msg, ChannelType, Message};

use crate::client::Session;

/// Execute `command` on the remote end. Returns the exit code.
pub async fn exec(session: &Session, command: &str) -> anyhow::Result<i32> {
    let (mut send, mut recv) = session.open_bi().await?;

    // Open exec channel
    write_msg(
        &mut send,
        &Message::ChannelOpen {
            channel_type: ChannelType::Exec,
            command: command.to_owned(),
        },
    )
    .await?;

    // Wait for accept
    let Some(msg) = read_msg(&mut recv).await? else {
        anyhow::bail!("connection closed before channel accept");
    };
    match msg {
        Message::ChannelAccept => {}
        Message::ChannelReject { reason } => anyhow::bail!("exec rejected: {reason}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    let mut stdout = tokio::io::stdout();
    let mut exit_code = 0i32;

    loop {
        let Some(msg) = read_msg(&mut recv).await.context("read exec output")? else {
            break;
        };
        match msg {
            Message::Data(data) => {
                stdout.write_all(&data).await?;
                stdout.flush().await?;
            }
            Message::ExitStatus { code } => {
                exit_code = code;
                break;
            }
            Message::Eof => break,
            _ => {}
        }
    }

    Ok(exit_code)
}
