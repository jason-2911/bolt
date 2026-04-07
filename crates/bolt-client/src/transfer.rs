//! Client file transfer: rsync delta sync, resume, zstd compression, timestamp preservation.

use std::{path::Path, time::UNIX_EPOCH};

use anyhow::{bail, Context as _};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::fs;

use bolt_proto::{read_msg, write_msg, ChannelType, Message};

use crate::client::Session;

const CHUNK: usize = 32 * 1024;

// ── Upload (with delta sync) ──────────────────────────────────────────────

pub async fn upload(session: &Session, local: &Path, remote: &str) -> anyhow::Result<()> {
    upload_opts(session, local, remote, false).await
}

/// `preserve` = keep mtime.
pub async fn upload_opts(
    session: &Session,
    local: &Path,
    remote: &str,
    preserve: bool,
) -> anyhow::Result<()> {
    let local_data = fs::read(local)
        .await
        .with_context(|| format!("read {}", local.display()))?;

    let meta = fs::metadata(local).await.context("stat")?;
    let mode = get_file_mode(&meta);
    let file_size = local_data.len() as u64;
    let mtime = if preserve {
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    } else {
        0
    };

    let (mut send, mut recv) = session.open_bi().await?;

    write_msg(
        &mut send,
        &Message::ChannelOpen {
            channel_type: ChannelType::Scp,
            command: String::new(),
        },
    )
    .await?;
    expect_accept(&mut recv).await?;

    write_msg(
        &mut send,
        &Message::SyncRequest {
            name: remote.to_owned(),
            size: file_size,
            mode,
        },
    )
    .await?;

    let Some(msg) = read_msg(&mut recv).await? else {
        bail!("connection closed during sync handshake");
    };

    let file_name = local.file_name().unwrap_or_default().to_string_lossy();

    match msg {
        Message::SyncSignature { signature } => {
            upload_delta(&mut send, &mut recv, &local_data, &signature, &file_name).await
        }
        Message::SyncNotFound => {
            upload_full(
                &mut send,
                &mut recv,
                &local_data,
                &file_name,
                file_size,
                mtime,
            )
            .await
        }
        Message::FileFail { reason } => bail!("server error: {reason}"),
        other => bail!("unexpected sync response: {other:?}"),
    }
}

/// Send only the delta (rsync diff).
async fn upload_delta(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    local_data: &[u8],
    signature_bytes: &[u8],
    file_name: &str,
) -> anyhow::Result<()> {
    let signature = fast_rsync::Signature::deserialize(signature_bytes.to_vec())
        .context("deserialize server signature")?;
    let indexed = signature.index();

    let mut delta = Vec::new();
    fast_rsync::diff(&indexed, local_data, &mut delta).context("compute delta")?;

    if delta.is_empty() {
        eprintln!("{file_name}: up to date");
        return Ok(());
    }

    let delta_size = delta.len() as u64;
    let full_size = local_data.len() as u64;
    let saved_pct = if full_size > 0 {
        100.0 - (delta_size as f64 / full_size as f64 * 100.0)
    } else {
        0.0
    };

    let pb = make_progress_bar(&format!("delta {file_name}"), delta_size);

    let mut offset = 0;
    while offset < delta.len() {
        let end = (offset + CHUNK).min(delta.len());
        let chunk = &delta[offset..end];
        write_msg(
            send,
            &Message::SyncDelta {
                delta: chunk.to_vec(),
            },
        )
        .await?;
        pb.inc(chunk.len() as u64);
        offset = end;
    }

    let sha256: [u8; 32] = Sha256::digest(local_data).into();
    write_msg(send, &Message::FileEnd { sha256 }).await?;
    pb.finish_with_message(format!("done (saved {saved_pct:.0}%)"));

    expect_ack(recv).await
}

/// Send full file. Optionally resume from `start_offset`.
async fn upload_full(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    local_data: &[u8],
    file_name: &str,
    file_size: u64,
    mtime: u64,
) -> anyhow::Result<()> {
    // Use zstd for large files
    let compress = local_data.len() > 4096;

    // Send FileHeader with metadata
    write_msg(
        send,
        &Message::FileHeader {
            name: file_name.to_owned(),
            size: file_size,
            mode: 0o644,
            mtime,
            compress,
        },
    )
    .await?;

    let pb = make_progress_bar(&format!("upload {file_name}"), file_size);
    let mut hasher = Sha256::new();

    let mut offset = 0;
    while offset < local_data.len() {
        let end = (offset + CHUNK).min(local_data.len());
        let chunk = &local_data[offset..end];
        hasher.update(chunk);

        let payload = if compress {
            zstd::encode_all(chunk, 3).context("compress chunk")?
        } else {
            chunk.to_vec()
        };

        write_msg(send, &Message::FileChunk(payload)).await?;
        pb.inc(chunk.len() as u64);
        offset = end;
    }

    let sha256: [u8; 32] = hasher.finalize().into();
    write_msg(send, &Message::FileEnd { sha256 }).await?;
    pb.finish_with_message(if compress {
        "done (compressed)"
    } else {
        "done (full)"
    });

    expect_ack(recv).await
}

// ── Upload with resume ────────────────────────────────────────────────────

/// Upload a large file with resume support (skips already-uploaded bytes).
pub async fn upload_resume(session: &Session, local: &Path, remote: &str) -> anyhow::Result<()> {
    let local_data = fs::read(local)
        .await
        .with_context(|| format!("read {}", local.display()))?;

    let (mut send, mut recv) = session.open_bi().await?;

    write_msg(
        &mut send,
        &Message::ChannelOpen {
            channel_type: ChannelType::Scp,
            command: String::new(),
        },
    )
    .await?;
    expect_accept(&mut recv).await?;

    // Ask server how many bytes it already has
    write_msg(
        &mut send,
        &Message::ResumeRequest {
            path: remote.to_owned(),
        },
    )
    .await?;
    let offset = match read_msg(&mut recv).await? {
        Some(Message::ResumeOffset { offset }) => offset as usize,
        _ => 0,
    };

    if offset >= local_data.len() {
        eprintln!("{}: already complete", local.display());
        return Ok(());
    }

    let remaining = &local_data[offset..];
    let file_name = local.file_name().unwrap_or_default().to_string_lossy();

    if offset > 0 {
        eprintln!("{file_name}: resuming from byte {offset}");
    }

    let compress = remaining.len() > 4096;
    write_msg(
        &mut send,
        &Message::FileHeader {
            name: remote.to_owned(),
            size: local_data.len() as u64,
            mode: 0o644,
            mtime: 0,
            compress,
        },
    )
    .await?;

    let pb = make_progress_bar(&format!("upload {file_name}"), remaining.len() as u64);

    // Hash the whole original file (server will reconstruct)
    let mut hasher = Sha256::new();
    hasher.update(&local_data[..]);

    let mut pos = 0;
    while pos < remaining.len() {
        let end = (pos + CHUNK).min(remaining.len());
        let chunk = &remaining[pos..end];

        let payload = if compress {
            zstd::encode_all(chunk, 3).context("compress chunk")?
        } else {
            chunk.to_vec()
        };

        write_msg(&mut send, &Message::FileChunk(payload)).await?;
        pb.inc(chunk.len() as u64);
        pos = end;
    }

    let sha256: [u8; 32] = hasher.finalize().into();
    write_msg(&mut send, &Message::FileEnd { sha256 }).await?;
    pb.finish_with_message("done (resumed)");

    expect_ack(&mut recv).await
}

// ── Download ──────────────────────────────────────────────────────────────

pub async fn download(session: &Session, remote: &str, local: &Path) -> anyhow::Result<()> {
    download_opts(session, remote, local, false).await
}

pub async fn download_opts(
    session: &Session,
    remote: &str,
    local: &Path,
    preserve: bool,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = session.open_bi().await?;

    write_msg(
        &mut send,
        &Message::ChannelOpen {
            channel_type: ChannelType::Scp,
            command: format!("download {remote}"),
        },
    )
    .await?;
    expect_accept(&mut recv).await?;

    let local_data = if local.exists() && local.is_file() {
        fs::read(local).await.ok()
    } else {
        None
    };

    if let Some(ref data) = local_data {
        let sig = compute_signature(data);
        write_msg(&mut send, &Message::SyncSignature { signature: sig }).await?;
    } else {
        write_msg(&mut send, &Message::SyncNotFound).await?;
    }

    let Some(msg) = read_msg(&mut recv).await? else {
        bail!("connection closed during download");
    };

    let out_path = resolve_download_path(local, remote);

    match msg {
        Message::FileHeader {
            name,
            size,
            mtime,
            compress,
            ..
        } => {
            download_full(
                &mut send, &mut recv, &out_path, &name, size, mtime, compress, preserve,
            )
            .await
        }
        Message::SyncDelta { delta } => {
            let ld = local_data.context("local file disappeared")?;
            download_delta(
                &mut send, &mut recv, &out_path, &ld, delta, remote, preserve,
            )
            .await
        }
        Message::SyncUpToDate => {
            eprintln!(
                "{}: up to date",
                Path::new(remote)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            Ok(())
        }
        Message::FileFail { reason } => bail!("server error: {reason}"),
        other => bail!("unexpected download response: {other:?}"),
    }
}

async fn download_full(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    out_path: &Path,
    file_name: &str,
    file_size: u64,
    mtime: u64,
    compress: bool,
    preserve: bool,
) -> anyhow::Result<()> {
    let display_name = Path::new(file_name)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

    let tmp_path = format!("{}.bolt-tmp", out_path.display());
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .await
        .context("create output file")?;

    let pb = make_progress_bar(&format!("download {display_name}"), file_size);
    let mut hasher = Sha256::new();

    loop {
        let Some(msg) = read_msg(recv).await? else {
            bail!("connection closed during transfer");
        };
        match msg {
            Message::FileChunk(data) => {
                let data = if compress {
                    zstd::decode_all(data.as_slice()).context("decompress chunk")?
                } else {
                    data
                };
                tokio::io::AsyncWriteExt::write_all(&mut out, &data)
                    .await
                    .context("write")?;
                hasher.update(&data);
                pb.inc(data.len() as u64);
            }
            Message::FileEnd { sha256 } => {
                tokio::io::AsyncWriteExt::flush(&mut out).await?;
                drop(out);
                pb.finish_with_message("done");

                let computed: [u8; 32] = hasher.finalize().into();
                if computed != sha256 {
                    fs::remove_file(&tmp_path).await.ok();
                    bail!("checksum mismatch");
                }

                fs::rename(&tmp_path, out_path).await.context("rename")?;

                if preserve && mtime > 0 {
                    set_mtime(out_path, mtime);
                }

                write_msg(send, &Message::FileAck).await.ok();
                return Ok(());
            }
            other => {
                fs::remove_file(&tmp_path).await.ok();
                bail!("unexpected: {other:?}");
            }
        }
    }
}

async fn download_delta(
    _send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    out_path: &Path,
    local_data: &[u8],
    first_delta: Vec<u8>,
    remote: &str,
    preserve: bool,
) -> anyhow::Result<()> {
    let display_name = Path::new(remote)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

    let mut full_delta = first_delta;

    loop {
        let Some(msg) = read_msg(recv).await? else {
            bail!("connection closed during delta transfer");
        };
        match msg {
            Message::SyncDelta { delta } => {
                full_delta.extend_from_slice(&delta);
            }
            Message::FileEnd { sha256 } => {
                let mut result = Vec::new();
                fast_rsync::apply(local_data, &full_delta, &mut result).context("apply delta")?;

                let computed: [u8; 32] = Sha256::digest(&result).into();
                if computed != sha256 {
                    bail!("checksum mismatch after delta apply");
                }

                fs::write(out_path, &result).await.context("write")?;
                let saved_pct = if !result.is_empty() {
                    100.0 - (full_delta.len() as f64 / result.len() as f64 * 100.0)
                } else {
                    0.0
                };
                eprintln!("{display_name}: synced (saved {saved_pct:.0}%)");
                let _ = preserve; // mtime comes with SyncDelta — not preserved in delta mode
                return Ok(());
            }
            other => bail!("unexpected: {other:?}"),
        }
    }
}

// ── Directory listing ─────────────────────────────────────────────────────

/// Remote directory entry returned from `list_dir`.
pub struct RemoteDirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: u64,
    pub mode: u32,
}

/// List a remote directory. Returns entries in server-order.
pub async fn list_dir(session: &Session, remote_path: &str) -> anyhow::Result<Vec<RemoteDirEntry>> {
    let (mut send, mut recv) = session.open_bi().await?;

    write_msg(
        &mut send,
        &Message::ChannelOpen {
            channel_type: ChannelType::Scp,
            command: String::new(),
        },
    )
    .await?;
    expect_accept(&mut recv).await?;

    write_msg(
        &mut send,
        &Message::DirList {
            path: remote_path.to_owned(),
        },
    )
    .await?;

    let mut entries = Vec::new();
    loop {
        let Some(msg) = read_msg(&mut recv).await? else {
            bail!("connection closed during dir list");
        };
        match msg {
            Message::DirEntry {
                name,
                is_dir,
                size,
                mtime,
                mode,
            } => {
                entries.push(RemoteDirEntry {
                    name,
                    is_dir,
                    size,
                    mtime,
                    mode,
                });
            }
            Message::DirEnd => break,
            Message::FileFail { reason } => bail!("dir list error: {reason}"),
            other => bail!("unexpected dir list message: {other:?}"),
        }
    }

    Ok(entries)
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn compute_signature(data: &[u8]) -> Vec<u8> {
    let sig = fast_rsync::Signature::calculate(
        data,
        fast_rsync::SignatureOptions {
            block_size: 4096,
            crypto_hash_size: 8,
        },
    );
    sig.serialized().to_vec()
}

async fn expect_accept(recv: &mut quinn::RecvStream) -> anyhow::Result<()> {
    let Some(msg) = read_msg(recv).await? else {
        bail!("connection closed, expected ChannelAccept");
    };
    match msg {
        Message::ChannelAccept => Ok(()),
        Message::ChannelReject { reason } => bail!("rejected: {reason}"),
        other => bail!("expected ChannelAccept, got {other:?}"),
    }
}

async fn expect_ack(recv: &mut quinn::RecvStream) -> anyhow::Result<()> {
    let Some(msg) = read_msg(recv).await? else {
        bail!("connection closed, expected FileAck");
    };
    match msg {
        Message::FileAck | Message::SyncUpToDate => Ok(()),
        Message::FileFail { reason } => bail!("transfer failed: {reason}"),
        other => bail!("expected FileAck, got {other:?}"),
    }
}

fn resolve_download_path(local: &Path, remote: &str) -> std::path::PathBuf {
    if local.to_str() == Some(".") || local.to_string_lossy().ends_with('/') {
        local.join(Path::new(remote).file_name().unwrap_or_default())
    } else {
        local.to_path_buf()
    }
}

fn get_file_mode(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        0o644
    }
}

fn set_mtime(path: &Path, mtime_secs: u64) {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
            let times = [
                libc::timespec {
                    tv_sec: mtime_secs as i64,
                    tv_nsec: 0,
                },
                libc::timespec {
                    tv_sec: mtime_secs as i64,
                    tv_nsec: 0,
                },
            ];
            unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mtime_secs);
    }
}

fn make_progress_bar(label: &str, total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix:.bold} [{bar:30.cyan/dim}] {bytes}/{total_bytes} {bytes_per_sec} ETA {eta}",
        )
        .unwrap()
        .progress_chars("=> "),
    );
    pb.set_prefix(label.to_owned());
    pb
}

#[cfg(unix)]
use nix::libc;
