//! Client directory transfer: recursive upload and download.

use std::{
    io::BufRead as _,
    path::Path,
};

use anyhow::Context as _;
use walkdir::WalkDir;

use bolt_session::Session;

use super::{exec::exec, transfer::{download, upload}};

// ── UploadDir ──────────────────────────────────────────────────────────────

/// Recursively upload `local_dir` to `remote_dst` on the server.
pub async fn upload_dir(
    session:    &Session,
    local_dir:  &Path,
    remote_dst: &str,
) -> anyhow::Result<()> {
    // Collect all files
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for entry in WalkDir::new(local_dir).follow_links(false) {
        let e = entry?;
        if e.file_type().is_file() {
            files.push(e.into_path());
        }
    }

    if files.is_empty() {
        eprintln!("bolt: {} is empty", local_dir.display());
        return Ok(());
    }

    eprintln!(
        "bolt: uploading {} file(s) from {} → {}",
        files.len(),
        local_dir.display(),
        remote_dst
    );

    let total = files.len();
    for (i, local_path) in files.iter().enumerate() {
        let rel = local_path.strip_prefix(local_dir).unwrap_or(local_path);
        let remote_path = format!("{}/{}", remote_dst.trim_end_matches('/'), rel.display());

        eprint!("[{}/{}] ", i + 1, total);
        upload(session, local_path, &remote_path)
            .await
            .with_context(|| format!("upload {}", rel.display()))?;
    }

    eprintln!("bolt: upload complete — {} file(s)", total);
    Ok(())
}

// ── DownloadDir ────────────────────────────────────────────────────────────

/// Recursively download `remote_dir` from the server to `local_dst`.
///
/// Uses an exec channel to run `find` on the remote to list files.
pub async fn download_dir(
    session:    &Session,
    remote_dir: &str,
    local_dst:  &Path,
) -> anyhow::Result<()> {
    // List remote files via exec
    let remote_dir = remote_dir.trim_end_matches('/');
    let cmd        = format!("find '{}' -type f 2>/dev/null | sort", shell_quote(remote_dir));
    let listing    = exec_output(session, &cmd).await?;

    let remote_paths: Vec<&str> = listing
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    if remote_paths.is_empty() {
        eprintln!("bolt: {}:{} is empty or does not exist", "server", remote_dir);
        return Ok(());
    }

    eprintln!(
        "bolt: downloading {} file(s) from :{} → {}",
        remote_paths.len(),
        remote_dir,
        local_dst.display()
    );

    let total = remote_paths.len();
    for (i, remote_path) in remote_paths.iter().enumerate() {
        let rel = remote_path
            .strip_prefix(remote_dir)
            .unwrap_or(remote_path)
            .trim_start_matches('/');
        let local_path = local_dst.join(rel);

        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }

        eprint!("[{}/{}] ", i + 1, total);
        download(session, remote_path, &local_path)
            .await
            .with_context(|| format!("download {}", rel))?;
    }

    eprintln!("bolt: download complete — {} file(s)", total);
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Run a command via exec channel and capture its stdout as a String.
async fn exec_output(session: &Session, command: &str) -> anyhow::Result<String> {
    use bolt_proto::channel::{ChannelOpenMsg, ChannelType, MsgType, RequestType};
    use bolt_session::PRIORITY_HIGH;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = session.open_stream(PRIORITY_HIGH)?;
    let open = ChannelOpenMsg { channel_type: ChannelType::Exec, command: command.to_owned() };
    stream.write_all(&open.marshal()).await?;

    // Wait for confirm
    let mut hdr = [0u8; 1];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != MsgType::ChannelOpenConfirm as u8 {
        anyhow::bail!("exec channel rejected");
    }

    let mut out = String::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 { break; }
        let data = &buf[..n];
        if data[0] == MsgType::ChannelData as u8 && n > 5 {
            out.push_str(&String::from_utf8_lossy(&data[5..n]));
        } else if data[0] == MsgType::ChannelRequest as u8
            && n >= 2
            && data[1] == RequestType::ExitStatus as u8
        {
            break;
        }
    }
    Ok(out)
}

/// Wrap `s` in single quotes, escaping embedded single quotes.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
