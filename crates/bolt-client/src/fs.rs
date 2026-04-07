//! Client SFTP-like filesystem commands.
//!
//! `bolt fs stat user@host:/path`
//! `bolt fs ls   user@host:/path`
//! `bolt fs mv   user@host:/old user@host:/new`
//! `bolt fs rm   [-r] user@host:/path`
//! `bolt fs mkdir user@host:/path`
//! `bolt fs chmod 755 user@host:/path`

use anyhow::bail;

use bolt_proto::{read_msg, write_msg, ChannelType, Message};

use crate::client::Session;

// ── Low-level helpers ─────────────────────────────────────────────────────

async fn open_fs_channel(session: &Session) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = session.open_bi().await?;
    write_msg(
        &mut send,
        &Message::ChannelOpen {
            channel_type: ChannelType::Fs,
            command: String::new(),
        },
    )
    .await?;
    match read_msg(&mut recv).await? {
        Some(Message::ChannelAccept) => Ok((send, recv)),
        Some(Message::ChannelReject { reason }) => bail!("fs channel rejected: {reason}"),
        other => bail!("unexpected: {other:?}"),
    }
}

async fn send_and_expect_ok(session: &Session, msg: Message) -> anyhow::Result<()> {
    let (mut send, mut recv) = open_fs_channel(session).await?;
    write_msg(&mut send, &msg).await?;
    match read_msg(&mut recv).await? {
        Some(Message::FsOk) => Ok(()),
        Some(Message::FsFail { reason }) => bail!("{reason}"),
        other => bail!("unexpected: {other:?}"),
    }
}

// ── Public API ────────────────────────────────────────────────────────────

pub async fn fs_stat(session: &Session, path: &str) -> anyhow::Result<()> {
    let (mut send, mut recv) = open_fs_channel(session).await?;
    write_msg(&mut send, &Message::FsStat { path: path.to_owned() }).await?;

    match read_msg(&mut recv).await? {
        Some(Message::FsStatResult { name, size, mtime, mode, is_dir, is_symlink }) => {
            let kind = if is_symlink { "symlink" } else if is_dir { "dir" } else { "file" };
            let dt = format_mtime(mtime);
            println!("{name}");
            println!("  type:  {kind}");
            println!("  size:  {size} bytes");
            println!("  mode:  {:o}", mode & 0o7777);
            println!("  mtime: {dt}");
            Ok(())
        }
        Some(Message::FsFail { reason }) => bail!("{reason}"),
        other => bail!("unexpected: {other:?}"),
    }
}

pub async fn fs_ls(session: &Session, path: &str) -> anyhow::Result<()> {
    let (mut send, mut recv) = open_fs_channel(session).await?;
    write_msg(&mut send, &Message::DirList { path: path.to_owned() }).await?;

    loop {
        match read_msg(&mut recv).await? {
            Some(Message::DirEntry { name, is_dir, size, mtime, mode }) => {
                let kind  = if is_dir { 'd' } else { '-' };
                let perms = format_perms(mode);
                let dt    = format_mtime(mtime);
                println!("{kind}{perms}  {:>10}  {}  {}", size, dt, name);
            }
            Some(Message::DirEnd) => break,
            Some(Message::FsFail { reason }) => bail!("{reason}"),
            other => bail!("unexpected: {other:?}"),
        }
    }
    Ok(())
}

pub async fn fs_rename(session: &Session, from: &str, to: &str) -> anyhow::Result<()> {
    send_and_expect_ok(
        session,
        Message::FsRename { from: from.to_owned(), to: to.to_owned() },
    )
    .await
}

pub async fn fs_remove(session: &Session, path: &str, recursive: bool) -> anyhow::Result<()> {
    send_and_expect_ok(
        session,
        Message::FsRemove { path: path.to_owned(), recursive },
    )
    .await
}

pub async fn fs_mkdir(session: &Session, path: &str, mode: u32) -> anyhow::Result<()> {
    send_and_expect_ok(
        session,
        Message::FsMkdir { path: path.to_owned(), mode },
    )
    .await
}

pub async fn fs_chmod(session: &Session, path: &str, mode: u32) -> anyhow::Result<()> {
    send_and_expect_ok(
        session,
        Message::FsChmod { path: path.to_owned(), mode },
    )
    .await
}

// ── Formatting ────────────────────────────────────────────────────────────

fn format_perms(mode: u32) -> String {
    let bits = mode & 0o777;
    let chars = [
        (0o400, 'r'), (0o200, 'w'), (0o100, 'x'),
        (0o040, 'r'), (0o020, 'w'), (0o010, 'x'),
        (0o004, 'r'), (0o002, 'w'), (0o001, 'x'),
    ];
    chars.iter().map(|(b, c)| if bits & b != 0 { *c } else { '-' }).collect()
}

fn format_mtime(secs: u64) -> String {
    // Simple ISO-ish format without chrono dependency
    use std::time::{Duration, UNIX_EPOCH};
    let t = UNIX_EPOCH + Duration::from_secs(secs);
    // Format as seconds since epoch for simplicity; real projects use chrono
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            // Convert to rough "YYYY-MM-DD HH:MM" via seconds math
            let s = d.as_secs();
            let mins  = s / 60;
            let hours = mins / 60;
            let days  = hours / 24;
            let years = 1970 + days / 365;
            let month = (days % 365) / 30 + 1;
            let day   = (days % 365) % 30 + 1;
            let hh    = hours % 24;
            let mm    = mins % 60;
            format!("{years:04}-{month:02}-{day:02} {hh:02}:{mm:02}")
        }
        Err(_) => "unknown".into(),
    }
}
