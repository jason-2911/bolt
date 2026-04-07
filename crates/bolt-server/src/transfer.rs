//! Server-side SCP transfer channel: upload and download with SHA256 verification.
//!
//! SCP wire frames: [type(1)][payload_len(4 BE)][payload(N)]
//!
//! Commands:
//!   "upload <size_dec> <mode_oct> <remote_path>"
//!   "download <remote_path>"

use std::path::Path;

use anyhow::Context as _;
use sha2::{Digest, Sha256};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
};
use tracing::{error, info};

use bolt_proto::channel::MsgType;
use bolt_session::Stream;

const CHUNK: usize = 32 * 1024;

// ── Dispatch ───────────────────────────────────────────────────────────────

pub async fn handle_transfer_channel(stream: &mut Stream, command: &str) -> anyhow::Result<()> {
    let mut parts = command.splitn(2, ' ');
    match parts.next() {
        Some("upload")   => receive_upload(stream, parts.next().unwrap_or("")).await,
        Some("download") => send_download(stream, parts.next().unwrap_or("").trim()).await,
        other => {
            send_frame(stream, MsgType::ChannelFailure, b"unknown command").await?;
            anyhow::bail!("unknown transfer command: {:?}", other)
        }
    }
}

// ── Upload: client → server ────────────────────────────────────────────────

async fn receive_upload(stream: &mut Stream, args: &str) -> anyhow::Result<()> {
    // args: "<size_dec> <mode_oct> <path>"
    let fields: Vec<&str> = args.trim().splitn(3, ' ').collect();
    if fields.len() != 3 {
        send_frame(stream, MsgType::ChannelFailure, b"bad args").await?;
        anyhow::bail!("invalid upload args: {args}");
    }

    let mode = u32::from_str_radix(fields[1], 8).unwrap_or(0o644);
    let remote_path = Path::new(fields[2]);

    // Ensure parent directory exists
    if let Some(parent) = remote_path.parent() {
        fs::create_dir_all(parent).await
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }

    // Write to temp file → atomic rename on success
    let tmp_path = format!("{}.bolt-tmp", fields[2]);
    let mut out = fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .mode(mode)
        .open(&tmp_path)
        .await
        .context("create temp file")?;

    // Signal client we are ready
    send_frame(stream, MsgType::ChannelSuccess, &[]).await?;

    let mut hasher   = Sha256::new();
    let mut received = 0i64;

    loop {
        let (msg_type, payload) = read_frame(stream).await?;

        match msg_type {
            t if t == MsgType::ChannelData as u8 => {
                out.write_all(&payload).await.context("write chunk")?;
                hasher.update(&payload);
                received += payload.len() as i64;
            }
            t if t == MsgType::ChannelEof as u8 => {
                if payload.len() != 32 {
                    send_frame(stream, MsgType::ChannelFailure, b"bad checksum length").await?;
                    anyhow::bail!("bad EOF checksum length: {}", payload.len());
                }
                out.flush().await?;
                drop(out);

                let sum = hasher.finalize();
                if sum.as_slice() != payload.as_slice() {
                    let _ = fs::remove_file(&tmp_path).await;
                    send_frame(stream, MsgType::ChannelFailure, b"checksum mismatch").await?;
                    anyhow::bail!("upload checksum mismatch for {}", fields[2]);
                }

                fs::rename(&tmp_path, fields[2]).await.context("rename")?;
                info!(
                    component = "server",
                    path      = fields[2],
                    size      = fmt_bytes(received),
                    sha256    = %hex4(&sum),
                    "upload complete"
                );
                send_frame(stream, MsgType::ChannelSuccess, &[]).await?;
                return Ok(());
            }
            other => {
                let _ = fs::remove_file(&tmp_path).await;
                anyhow::bail!("unexpected frame 0x{:02x}", other);
            }
        }
    }
}

// ── Download: server → client ──────────────────────────────────────────────

async fn send_download(stream: &mut Stream, remote_path: &str) -> anyhow::Result<()> {
    let mut f = fs::File::open(remote_path).await
        .with_context(|| format!("open {remote_path}"))?;
    let meta = f.metadata().await.context("stat")?;

    // OK frame carries 8-byte file size
    let size_bytes = meta.len().to_be_bytes();
    send_frame(stream, MsgType::ChannelSuccess, &size_bytes).await?;

    let mut hasher = Sha256::new();
    let mut buf    = vec![0u8; CHUNK];
    let mut sent   = 0u64;

    loop {
        let n = f.read(&mut buf).await.context("read file")?;
        if n == 0 { break; }
        let chunk = &buf[..n];
        hasher.update(chunk);
        send_frame(stream, MsgType::ChannelData, chunk).await?;
        sent += n as u64;
    }

    let sum = hasher.finalize();
    send_frame(stream, MsgType::ChannelEof, &sum).await?;

    info!(
        component = "server",
        path      = remote_path,
        size      = fmt_bytes(sent as i64),
        "download complete"
    );

    // Wait for client ACK
    let (msg_type, _) = read_frame(stream).await?;
    if msg_type != MsgType::ChannelSuccess as u8 {
        anyhow::bail!("client did not ACK download");
    }
    Ok(())
}

// ── Frame I/O ──────────────────────────────────────────────────────────────

async fn send_frame(stream: &mut Stream, msg_type: MsgType, payload: &[u8]) -> anyhow::Result<()> {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(msg_type as u8);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    stream.write_all(&buf).await.context("send frame")
}

async fn read_frame(stream: &mut Stream) -> anyhow::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await.context("read frame header")?;
    let msg_type    = hdr[0];
    let payload_len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let payload = if payload_len > 0 {
        let mut p = vec![0u8; payload_len];
        stream.read_exact(&mut p).await.context("read frame payload")?;
        p
    } else {
        vec![]
    };
    Ok((msg_type, payload))
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn fmt_bytes(b: i64) -> String {
    match b.unsigned_abs() {
        n if n >= 1 << 30 => format!("{:.2} GB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.2} MB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.2} KB", n as f64 / (1u64 << 10) as f64),
        n                 => format!("{} B", n),
    }
}

fn hex4(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{:02x}", x)).collect::<String>() + "…"
}
