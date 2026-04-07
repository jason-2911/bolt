//! Server-side filesystem operations (SFTP-like).
//!
//! Handles a stream of FsXxx messages until EOF.
//! Each request gets either FsOk / FsStatResult or FsFail.

use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
};

use anyhow::Context as _;
use tokio::fs;
use tracing::debug;

use bolt_proto::{read_msg, write_msg, Message};

pub async fn handle_fs(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    _user: &str,
) -> anyhow::Result<()> {
    loop {
        let Some(msg) = read_msg(recv).await? else {
            break;
        };

        let result = match msg {
            Message::FsStat   { path }               => fs_stat(&path).await,
            Message::FsRename { from, to }           => fs_rename(&from, &to).await,
            Message::FsRemove { path, recursive }    => fs_remove(&path, recursive).await,
            Message::FsMkdir  { path, mode }         => fs_mkdir(&path, mode).await,
            Message::FsChmod  { path, mode }         => fs_chmod(&path, mode).await,
            Message::DirList  { path }               => {
                // Delegate to transfer's dir list logic inline
                return handle_dir_stream(send, recv, &path).await;
            }
            Message::Eof | _ => break,
        };

        match result {
            Ok(reply) => write_msg(send, &reply).await?,
            Err(e)    => write_msg(send, &Message::FsFail { reason: e.to_string() }).await?,
        }
    }
    Ok(())
}

// ── Operations ────────────────────────────────────────────────────────────

async fn fs_stat(path: &str) -> anyhow::Result<Message> {
    let meta = fs::metadata(path)
        .await
        .with_context(|| format!("stat {path}"))?;

    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mode = meta.permissions().mode();
    let is_symlink = fs::symlink_metadata(path)
        .await
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);

    debug!(path, "stat");
    Ok(Message::FsStatResult {
        name: Path::new(path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        size: if meta.is_file() { meta.len() } else { 0 },
        mtime,
        mode,
        is_dir: meta.is_dir(),
        is_symlink,
    })
}

async fn fs_rename(from: &str, to: &str) -> anyhow::Result<Message> {
    // Ensure destination parent exists
    if let Some(parent) = Path::new(to).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).await.ok();
        }
    }
    fs::rename(from, to)
        .await
        .with_context(|| format!("rename {from} -> {to}"))?;
    debug!(from, to, "rename");
    Ok(Message::FsOk)
}

async fn fs_remove(path: &str, recursive: bool) -> anyhow::Result<Message> {
    let meta = fs::metadata(path).await.with_context(|| format!("stat {path}"))?;
    if meta.is_dir() {
        if recursive {
            fs::remove_dir_all(path).await.with_context(|| format!("rmdir -r {path}"))?;
        } else {
            fs::remove_dir(path).await.with_context(|| format!("rmdir {path}"))?;
        }
    } else {
        fs::remove_file(path).await.with_context(|| format!("rm {path}"))?;
    }
    debug!(path, recursive, "remove");
    Ok(Message::FsOk)
}

async fn fs_mkdir(path: &str, mode: u32) -> anyhow::Result<Message> {
    fs::create_dir_all(path)
        .await
        .with_context(|| format!("mkdir {path}"))?;

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use nix::libc;
        if let Ok(c) = CString::new(path) {
            unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) };
        }
    }
    let _ = mode;
    debug!(path, "mkdir");
    Ok(Message::FsOk)
}

async fn fs_chmod(path: &str, mode: u32) -> anyhow::Result<Message> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use nix::libc;
        let c = CString::new(path).context("invalid path")?;
        let ret = unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) };
        if ret != 0 {
            anyhow::bail!("chmod {path}: {}", std::io::Error::last_os_error());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        anyhow::bail!("chmod not supported on this platform");
    }
    debug!(path, mode, "chmod");
    Ok(Message::FsOk)
}

async fn handle_dir_stream(
    send: &mut quinn::SendStream,
    _recv: &mut quinn::RecvStream,
    path: &str,
) -> anyhow::Result<()> {
    let mut rd = match fs::read_dir(path).await {
        Ok(rd) => rd,
        Err(e) => {
            write_msg(send, &Message::FsFail { reason: e.to_string() }).await.ok();
            return Ok(());
        }
    };

    loop {
        let entry = match rd.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                write_msg(send, &Message::FsFail { reason: e.to_string() }).await.ok();
                return Ok(());
            }
        };
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        write_msg(
            send,
            &Message::DirEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                is_dir: meta.is_dir(),
                size: if meta.is_file() { meta.len() } else { 0 },
                mtime,
                mode: meta.permissions().mode(),
            },
        )
        .await?;
    }

    write_msg(send, &Message::DirEnd).await?;
    Ok(())
}
