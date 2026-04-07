//! Client file transfer: upload and download with SHA256 + progress bar.
//!
//! SCP frames: [type(1)][payload_len(4 BE)][payload(N)]

use std::{
    io::Write as _,
    path::Path,
    time::Instant,
};

use anyhow::Context as _;
use sha2::{Digest, Sha256};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
};

use bolt_proto::channel::{ChannelOpenMsg, ChannelType, MsgType};
use bolt_session::{Session, Stream, PRIORITY_HIGH};

const CHUNK: usize = 32 * 1024;

// ── Upload ─────────────────────────────────────────────────────────────────

pub async fn upload(session: &Session, local: &Path, remote: &str) -> anyhow::Result<()> {
    let mut f = fs::File::open(local)
        .await
        .with_context(|| format!("open {}", local.display()))?;
    let meta = f.metadata().await.context("stat")?;

    let mut stream = session.open_stream(PRIORITY_HIGH)?;
    open_scp_channel(
        &mut stream,
        &format!(
            "upload {} {:o} {}",
            meta.len(),
            meta.permissions().mode(),
            remote
        ),
    )
    .await?;

    // Wait for server ready
    recv_frame_type(&mut stream, MsgType::ChannelSuccess)
        .await
        .context("server not ready")?;

    let label = format!("⬆ {}", local.file_name().unwrap_or_default().to_string_lossy());
    let mut hasher = Sha256::new();
    let mut buf    = vec![0u8; CHUNK];
    let mut sent   = 0u64;
    let start      = Instant::now();

    loop {
        let n = f.read(&mut buf).await.context("read file")?;
        if n == 0 { break; }
        let chunk = &buf[..n];
        send_frame(&mut stream, MsgType::ChannelData, chunk).await?;
        hasher.update(chunk);
        sent += n as u64;
        render_progress(&label, sent, meta.len(), start);
    }

    // EOF frame carries SHA256
    let sum = hasher.finalize();
    send_frame(&mut stream, MsgType::ChannelEof, &sum).await?;
    finish_progress(&label, sent, start);

    // Wait for server ACK
    recv_frame_type(&mut stream, MsgType::ChannelSuccess)
        .await
        .context("upload failed")?;

    Ok(())
}

// ── Download ───────────────────────────────────────────────────────────────

pub async fn download(session: &Session, remote: &str, local: &Path) -> anyhow::Result<()> {
    let mut stream = session.open_stream(PRIORITY_HIGH)?;
    open_scp_channel(&mut stream, &format!("download {}", remote)).await?;

    // Read OK frame — server appends 8-byte file size
    let (_, size_payload) = read_frame(&mut stream).await?;
    if size_payload.len() < 8 {
        anyhow::bail!("missing file size in server response");
    }
    let file_size = u64::from_be_bytes(size_payload[..8].try_into().unwrap());

    // Resolve output path
    let out_path = if local.to_str() == Some(".") || local.to_string_lossy().ends_with('/') {
        local.join(Path::new(remote).file_name().unwrap_or_default())
    } else {
        local.to_path_buf()
    };

    let tmp_path = format!("{}.bolt-tmp", out_path.display());
    let mut out  = fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(&tmp_path)
        .await
        .context("create output file")?;

    let label    = format!("⬇ {}", Path::new(remote).file_name().unwrap_or_default().to_string_lossy());
    let mut hasher   = Sha256::new();
    let mut received = 0u64;
    let start        = Instant::now();

    loop {
        let (msg_type, payload) = read_frame(&mut stream).await?;
        match msg_type {
            t if t == MsgType::ChannelData as u8 => {
                out.write_all(&payload).await.context("write file")?;
                hasher.update(&payload);
                received += payload.len() as u64;
                render_progress(&label, received, file_size, start);
            }
            t if t == MsgType::ChannelEof as u8 => {
                if payload.len() != 32 {
                    anyhow::bail!("invalid checksum length {}", payload.len());
                }
                out.flush().await?;
                drop(out);
                finish_progress(&label, received, start);

                let sum = hasher.finalize();
                if sum.as_slice() != payload.as_slice() {
                    fs::remove_file(&tmp_path).await.ok();
                    anyhow::bail!("checksum mismatch — file corrupted");
                }

                fs::rename(&tmp_path, &out_path).await.context("rename")?;

                // ACK the server
                send_frame(&mut stream, MsgType::ChannelSuccess, &[]).await.ok();
                return Ok(());
            }
            other => {
                fs::remove_file(&tmp_path).await.ok();
                anyhow::bail!("unexpected frame 0x{:02x}", other);
            }
        }
    }
}

// ── SCP channel helpers ────────────────────────────────────────────────────

async fn open_scp_channel(stream: &mut Stream, command: &str) -> anyhow::Result<()> {
    let open = ChannelOpenMsg {
        channel_type: ChannelType::Scp,
        command:      command.to_owned(),
    };
    stream.write_all(&open.marshal()).await.context("send channel open")
}

async fn send_frame(stream: &mut Stream, msg_type: MsgType, payload: &[u8]) -> anyhow::Result<()> {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(msg_type as u8);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    stream.write_all(&buf).await.context("send frame")
}

async fn recv_frame_type(stream: &mut Stream, expected: MsgType) -> anyhow::Result<Vec<u8>> {
    let (got, payload) = read_frame(stream).await?;
    if got != expected as u8 {
        anyhow::bail!("expected frame 0x{:02x}, got 0x{:02x}", expected as u8, got);
    }
    Ok(payload)
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

// ── Progress rendering ─────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};
static LAST_RENDER_NS: AtomicU64 = AtomicU64::new(0);

fn render_progress(label: &str, done: u64, total: u64, start: Instant) {
    let now_ns = Instant::now().duration_since(start).as_nanos() as u64;
    let last   = LAST_RENDER_NS.load(Ordering::Relaxed);
    if now_ns.saturating_sub(last) < 100_000_000 { return; } // 100 ms throttle
    LAST_RENDER_NS.store(now_ns, Ordering::Relaxed);

    let elapsed = start.elapsed().as_secs_f64();
    let speed   = if elapsed > 0.0 { done as f64 / elapsed } else { 0.0 };

    const BAR_W: usize = 20;
    let bar = if total > 0 {
        let pct    = (done as f64 / total as f64).min(1.0);
        let filled = (pct * BAR_W as f64) as usize;
        format!(
            "[{}{}] {:3.0}%",
            "█".repeat(filled),
            "░".repeat(BAR_W - filled),
            pct * 100.0
        )
    } else {
        format!("[{}] ?%", "█".repeat(BAR_W))
    };

    let eta = if speed > 0.0 && total > done {
        fmt_duration(std::time::Duration::from_secs_f64((total - done) as f64 / speed))
    } else {
        String::new()
    };

    let label_trunc = truncate(label, 18);
    eprint!(
        "\r{:<18} {}  {}  {}   ",
        label_trunc, bar, fmt_speed(speed), eta
    );
    let _ = std::io::stderr().flush();
}

fn finish_progress(label: &str, done: u64, start: Instant) {
    let elapsed = start.elapsed().as_secs_f64();
    let speed   = if elapsed > 0.0 { done as f64 / elapsed } else { 0.0 };
    eprintln!(
        "\r{:<18} [{}] 100%  {}  {}  done",
        truncate(label, 18),
        "█".repeat(20),
        fmt_speed(speed),
        fmt_bytes(done as i64),
    );
}

fn fmt_speed(bps: f64) -> String {
    match bps as u64 {
        n if n >= 1 << 30 => format!("{:5.1} GB/s", bps / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:5.1} MB/s", bps / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:5.1} KB/s", bps / (1u64 << 10) as f64),
        _                  => format!("{:5.0}  B/s", bps),
    }
}

fn fmt_bytes(b: i64) -> String {
    match b.unsigned_abs() {
        n if n >= 1 << 30 => format!("{:.2} GB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.2} MB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.2} KB", n as f64 / (1u64 << 10) as f64),
        n                  => format!("{} B", n),
    }
}

fn fmt_duration(d: std::time::Duration) -> String {
    let s = d.as_secs();
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let s = s % 60;
    if h > 0 { format!("{}h{:02}m{:02}s", h, m, s) }
    else if m > 0 { format!("{}m{:02}s", m, s) }
    else { format!("{}s", s) }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_owned() }
    else {
        let mut t: String = s.chars().take(n - 1).collect();
        t.push('…');
        t
    }
}

/// Export fmt_bytes for transfer_dir
pub fn format_bytes(b: i64) -> String { fmt_bytes(b) }

use std::os::unix::fs::PermissionsExt;
