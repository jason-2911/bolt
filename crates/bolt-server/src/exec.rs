//! Server-side exec channel: run a command and relay stdout/exit code.

use anyhow::Context as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tracing::error;

use bolt_proto::channel::{ExitStatusMsg, MsgType};
use bolt_session::Stream;

pub async fn handle_exec_channel(stream: &mut Stream, command: &str) -> anyhow::Result<()> {
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .output()
        .await
        .context("exec command")?;

    // Relay stdout
    if !output.stdout.is_empty() {
        // Prefix with MsgChannelData
        let mut msg = vec![MsgType::ChannelData as u8];
        msg.extend_from_slice(&(output.stdout.len() as u32).to_be_bytes());
        msg.extend_from_slice(&output.stdout);
        stream.write_all(&msg).await?;
    }

    // Send exit status
    let code = output.status.code().unwrap_or(1) as u32;
    stream.write_all(&ExitStatusMsg { exit_code: code }.marshal()).await?;

    Ok(())
}
