//! Client remote command execution.

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use bolt_proto::channel::{ChannelOpenMsg, ChannelType, ExitStatusMsg, MsgType, RequestType};
use bolt_session::{Session, PRIORITY_HIGH};

/// Execute `command` on the remote end. Returns the exit code.
pub async fn exec(session: &Session, command: &str) -> anyhow::Result<i32> {
    let mut stream = session.open_stream(PRIORITY_HIGH)?;

    // Open exec channel
    let open = ChannelOpenMsg {
        channel_type: ChannelType::Exec,
        command:      command.to_owned(),
    };
    stream.write_all(&open.marshal()).await?;

    // Wait for confirm
    let mut hdr = [0u8; 1];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != MsgType::ChannelOpenConfirm as u8 {
        anyhow::bail!("exec channel rejected");
    }

    let mut stdout = tokio::io::stdout();
    let mut exit_code = 0i32;
    let mut buf = vec![0u8; 4096];

    loop {
        let n = stream.read(&mut buf).await.context("read exec output")?;
        if n == 0 { break; }

        let data = &buf[..n];
        match data[0] {
            b if b == MsgType::ChannelData as u8 && n > 5 => {
                stdout.write_all(&data[5..n]).await?;
                stdout.flush().await?;
            }
            b if b == MsgType::ChannelRequest as u8
                && n >= 2
                && data[1] == RequestType::ExitStatus as u8 =>
            {
                if let Ok(msg) = ExitStatusMsg::unmarshal(data) {
                    exit_code = msg.exit_code as i32;
                }
                break;
            }
            _ => {}
        }
    }

    Ok(exit_code)
}
