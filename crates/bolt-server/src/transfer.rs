//! Server-side file transfer with rsync-style delta sync, resume, compression, timestamps.
//!
//! Upload flow:
//!   1. Client sends SyncRequest { name, size, mode }
//!   2. Server checks if file exists:
//!      - Exists → compute rsync signature, send SyncSignature
//!      - Not exists → send SyncNotFound
//!   3. Client sends SyncDelta chunks OR FileChunk (full)
//!   4. Server applies delta or writes full, sends FileAck
//!
//! Download flow:
//!   1. Client sends SyncSignature (if has local copy) or SyncNotFound
//!   2. Server:
//!      - Got signature → compute delta, send SyncDelta chunks
//!      - Got SyncNotFound → send full file via FileChunk
//!
//! Directory listing:
//!   Client sends DirList { path } → server sends DirEntry* then DirEnd
//!
//! Resume:
//!   Client sends ResumeRequest { path } → server replies ResumeOffset { offset }

use std::{path::Path, time::UNIX_EPOCH};

use anyhow::Context as _;
use sha2::{Digest, Sha256};
use tokio::{fs, io::AsyncWriteExt};
use tracing::info;

use bolt_proto::{read_msg, write_msg, Message};

const CHUNK: usize = 32 * 1024;

// ── Dispatch ──────────────────────────────────────────────────────────────

pub async fn handle_transfer(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    command: &str,
) -> anyhow::Result<()> {
    let Some(msg) = read_msg(recv).await? else {
        return Ok(());
    };

    match msg {
        Message::SyncRequest { name, size, mode } => {
            handle_upload(send, recv, &name, size, mode).await
        }
        Message::ResumeRequest { path } => handle_resume_query(send, &path).await,
        Message::DirList { path } => handle_dir_list(send, &path).await,
        Message::SyncSignature { .. } | Message::SyncNotFound
            if command.starts_with("download ") =>
        {
            let remote_path = command.trim_start_matches("download ").trim();
            handle_download(send, recv, remote_path, msg).await
        }
        other => {
            write_msg(
                send,
                &Message::FileFail {
                    reason: format!("unexpected: {other:?}"),
                },
            )
            .await
            .ok();
            anyhow::bail!("unexpected transfer message");
        }
    }
}

// ── Resume query ──────────────────────────────────────────────────────────

async fn handle_resume_query(send: &mut quinn::SendStream, path: &str) -> anyhow::Result<()> {
    let offset = match fs::metadata(path).await {
        Ok(meta) => meta.len(),
        Err(_) => 0,
    };
    write_msg(send, &Message::ResumeOffset { offset }).await?;
    Ok(())
}

// ── Directory listing ─────────────────────────────────────────────────────

async fn handle_dir_list(send: &mut quinn::SendStream, path: &str) -> anyhow::Result<()> {
    let mut rd = match fs::read_dir(path).await {
        Ok(rd) => rd,
        Err(e) => {
            write_msg(
                send,
                &Message::FileFail {
                    reason: format!("readdir {path}: {e}"),
                },
            )
            .await
            .ok();
            return Ok(());
        }
    };

    loop {
        let entry = match rd.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                write_msg(
                    send,
                    &Message::FileFail {
                        reason: e.to_string(),
                    },
                )
                .await
                .ok();
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
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mode = get_file_mode(&meta);

        write_msg(
            send,
            &Message::DirEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                is_dir: meta.is_dir(),
                size: if meta.is_file() { meta.len() } else { 0 },
                mtime,
                mode,
            },
        )
        .await?;
    }

    write_msg(send, &Message::DirEnd).await?;
    Ok(())
}

// ── Upload: client → server ───────────────────────────────────────────────

async fn handle_upload(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    remote_path: &str,
    _size: u64,
    mode: u32,
) -> anyhow::Result<()> {
    let path = Path::new(remote_path);

    if path.exists() && path.is_file() {
        let existing_data = fs::read(path).await.context("read existing file")?;
        let sig = compute_signature(&existing_data);
        write_msg(send, &Message::SyncSignature { signature: sig }).await?;
        receive_delta(send, recv, remote_path, &existing_data, mode).await
    } else {
        write_msg(send, &Message::SyncNotFound).await?;
        receive_full(send, recv, remote_path, mode).await
    }
}

async fn receive_delta(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    remote_path: &str,
    existing_data: &[u8],
    mode: u32,
) -> anyhow::Result<()> {
    let mut full_delta = Vec::new();

    loop {
        let Some(msg) = read_msg(recv).await? else {
            anyhow::bail!("connection closed during delta upload");
        };

        match msg {
            Message::SyncDelta { delta } => {
                full_delta.extend_from_slice(&delta);
            }
            Message::FileEnd { sha256 } => {
                let mut result = Vec::new();
                fast_rsync::apply(existing_data, &full_delta, &mut result)
                    .context("apply delta")?;

                let computed: [u8; 32] = Sha256::digest(&result).into();
                if computed != sha256 {
                    write_msg(
                        send,
                        &Message::FileFail {
                            reason: "checksum mismatch after delta apply".into(),
                        },
                    )
                    .await
                    .ok();
                    anyhow::bail!("delta checksum mismatch for {remote_path}");
                }

                ensure_parent(remote_path).await?;
                write_file_atomic(remote_path, &result, mode, None).await?;

                info!(
                    path = remote_path,
                    delta_size = full_delta.len(),
                    full_size = result.len(),
                    "upload complete (delta)"
                );
                write_msg(send, &Message::FileAck).await?;
                return Ok(());
            }
            Message::FileChunk(_) => {
                return receive_full_from(send, recv, remote_path, mode, msg, false, 0).await;
            }
            other => {
                anyhow::bail!("unexpected during delta upload: {other:?}");
            }
        }
    }
}

async fn receive_full(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    remote_path: &str,
    mode: u32,
) -> anyhow::Result<()> {
    // Read FileHeader to get mtime + compress flag
    let Some(msg) = read_msg(recv).await? else {
        anyhow::bail!("connection closed waiting for FileHeader");
    };

    let (mtime, compress, resume_offset) = match &msg {
        Message::FileHeader {
            mtime, compress, ..
        } => (*mtime, *compress, 0u64),
        // Legacy: no header, treat first message as chunk with no metadata
        other => {
            return receive_full_from(send, recv, remote_path, mode, other.clone(), false, 0).await;
        }
    };

    // Check if client wants resume — look at tmp file
    let tmp_path = format!("{remote_path}.bolt-tmp");
    let offset = if Path::new(&tmp_path).exists() {
        fs::metadata(&tmp_path).await.map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    let _ = (resume_offset, offset); // resume is client-driven via ResumeRequest

    let first_chunk = read_msg(recv).await?;
    let first = first_chunk.unwrap_or(Message::Eof);
    receive_full_from(send, recv, remote_path, mode, first, compress, mtime).await
}

async fn receive_full_from(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    remote_path: &str,
    mode: u32,
    first_msg: Message,
    compress: bool,
    mtime: u64,
) -> anyhow::Result<()> {
    ensure_parent(remote_path).await?;

    let tmp_path = format!("{remote_path}.bolt-tmp");
    let mut out = create_file(&tmp_path, mode).await?;
    let mut hasher = Sha256::new();
    let mut received = 0u64;

    let process_chunk = |data: Vec<u8>| -> anyhow::Result<Vec<u8>> {
        if compress {
            zstd::decode_all(data.as_slice()).context("decompress chunk")
        } else {
            Ok(data)
        }
    };

    if let Message::FileChunk(data) = first_msg {
        let data = process_chunk(data)?;
        out.write_all(&data).await.context("write chunk")?;
        hasher.update(&data);
        received += data.len() as u64;
    }

    loop {
        let Some(msg) = read_msg(recv).await? else {
            fs::remove_file(&tmp_path).await.ok();
            anyhow::bail!("connection closed during upload");
        };

        match msg {
            Message::FileChunk(data) => {
                let data = process_chunk(data)?;
                out.write_all(&data).await.context("write chunk")?;
                hasher.update(&data);
                received += data.len() as u64;
            }
            Message::FileEnd { sha256 } => {
                out.flush().await?;
                drop(out);

                let computed: [u8; 32] = hasher.finalize().into();
                if computed != sha256 {
                    fs::remove_file(&tmp_path).await.ok();
                    write_msg(
                        send,
                        &Message::FileFail {
                            reason: "checksum mismatch".into(),
                        },
                    )
                    .await
                    .ok();
                    anyhow::bail!("upload checksum mismatch for {remote_path}");
                }

                fs::rename(&tmp_path, remote_path).await.context("rename")?;

                // Restore mtime if provided
                if mtime > 0 {
                    set_mtime(remote_path, mtime);
                }

                info!(
                    path = remote_path,
                    size = received,
                    "upload complete (full)"
                );
                write_msg(send, &Message::FileAck).await?;
                return Ok(());
            }
            other => {
                fs::remove_file(&tmp_path).await.ok();
                anyhow::bail!("unexpected during full upload: {other:?}");
            }
        }
    }
}

// ── Download: server → client ─────────────────────────────────────────────

async fn handle_download(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    remote_path: &str,
    client_msg: Message,
) -> anyhow::Result<()> {
    let file_data = match fs::read(remote_path).await {
        Ok(data) => data,
        Err(e) => {
            write_msg(
                send,
                &Message::FileFail {
                    reason: format!("open {remote_path}: {e}"),
                },
            )
            .await
            .ok();
            return Err(e.into());
        }
    };

    let meta = fs::metadata(remote_path).await.context("stat")?;
    let mode = get_file_mode(&meta);
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match client_msg {
        Message::SyncSignature { signature } => {
            send_delta(send, recv, remote_path, &file_data, &signature).await
        }
        Message::SyncNotFound => send_full(send, recv, remote_path, &file_data, mode, mtime).await,
        _ => unreachable!(),
    }
}

async fn send_delta(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    remote_path: &str,
    file_data: &[u8],
    client_signature: &[u8],
) -> anyhow::Result<()> {
    let signature = match fast_rsync::Signature::deserialize(client_signature.to_vec()) {
        Ok(sig) => sig,
        Err(_) => {
            let meta = fs::metadata(remote_path).await?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            return send_full(
                send,
                recv,
                remote_path,
                file_data,
                get_file_mode(&meta),
                mtime,
            )
            .await;
        }
    };

    let indexed = signature.index();
    let mut delta = Vec::new();
    fast_rsync::diff(&indexed, file_data, &mut delta).context("compute delta")?;

    if delta.is_empty() {
        write_msg(send, &Message::SyncUpToDate).await?;
        return Ok(());
    }

    let mut offset = 0;
    while offset < delta.len() {
        let end = (offset + CHUNK).min(delta.len());
        write_msg(
            send,
            &Message::SyncDelta {
                delta: delta[offset..end].to_vec(),
            },
        )
        .await?;
        offset = end;
    }

    let sha256: [u8; 32] = Sha256::digest(file_data).into();
    write_msg(send, &Message::FileEnd { sha256 }).await?;

    info!(
        path = remote_path,
        delta_size = delta.len(),
        full_size = file_data.len(),
        "download complete (delta)"
    );

    Ok(())
}

async fn send_full(
    send: &mut quinn::SendStream,
    _recv: &mut quinn::RecvStream,
    remote_path: &str,
    file_data: &[u8],
    mode: u32,
    mtime: u64,
) -> anyhow::Result<()> {
    // Use zstd compression if file is large enough to benefit
    let compress = file_data.len() > 4096;

    write_msg(
        send,
        &Message::FileHeader {
            name: remote_path.to_owned(),
            size: file_data.len() as u64,
            mode,
            mtime,
            compress,
        },
    )
    .await?;

    let mut hasher = Sha256::new();
    let mut offset = 0;
    while offset < file_data.len() {
        let end = (offset + CHUNK).min(file_data.len());
        let chunk = &file_data[offset..end];
        hasher.update(chunk);

        let payload = if compress {
            zstd::encode_all(chunk, 3).context("compress chunk")?
        } else {
            chunk.to_vec()
        };

        write_msg(send, &Message::FileChunk(payload)).await?;
        offset = end;
    }

    let sha256: [u8; 32] = hasher.finalize().into();
    write_msg(send, &Message::FileEnd { sha256 }).await?;

    info!(
        path = remote_path,
        size = file_data.len(),
        compress,
        "download complete (full)"
    );
    Ok(())
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

async fn ensure_parent(path: &str) -> anyhow::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
    }
    Ok(())
}

async fn create_file(path: &str, _mode: u32) -> anyhow::Result<fs::File> {
    #[cfg(unix)]
    {
        use tokio::fs::OpenOptions;
        Ok(OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(_mode)
            .open(path)
            .await
            .context("create file")?)
    }
    #[cfg(not(unix))]
    {
        Ok(fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .await
            .context("create file")?)
    }
}

async fn write_file_atomic(
    path: &str,
    data: &[u8],
    mode: u32,
    mtime: Option<u64>,
) -> anyhow::Result<()> {
    let tmp = format!("{path}.bolt-tmp");
    {
        let mut f = create_file(&tmp, mode).await?;
        f.write_all(data).await.context("write")?;
        f.flush().await?;
    }
    fs::rename(&tmp, path).await.context("rename")?;
    if let Some(mt) = mtime {
        if mt > 0 {
            set_mtime(path, mt);
        }
    }
    Ok(())
}

fn set_mtime(path: &str, mtime_secs: u64) {
    #[cfg(unix)]
    {
        use nix::libc;
        use std::ffi::CString;

        if let Ok(c_path) = CString::new(path) {
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
