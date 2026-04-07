//! Bolt protocol messages — serialized with bincode, length-prefixed.
//!
//! Wire format: `[u32 BE length][bincode-encoded Message]`

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum single message size (16 MB).
pub const MAX_MSG_SIZE: u32 = 16 * 1024 * 1024;

// ── Message enum ──────────────────────────────────────────────────────────

/// Every message exchanged over a QUIC stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // ── Auth (control stream) ──
    AuthRequest {
        user: String,
        public_key: [u8; 32],
    },
    /// Password auth fallback when no keypair available.
    AuthPassword {
        user: String,
        password: String,
    },
    AuthSuccess,
    AuthFailure { reason: String },

    // ── Channel open ──
    ChannelOpen {
        channel_type: ChannelType,
        command: String,
    },
    ChannelAccept,
    ChannelReject { reason: String },

    // ── Data ──
    Data(Vec<u8>),
    Eof,

    // ── Shell / PTY ──
    /// Send before PtyRequest to forward environment variables.
    EnvSet {
        key: String,
        val: String,
    },
    PtyRequest {
        term: String,
        cols: u32,
        rows: u32,
    },
    WindowChange {
        cols: u32,
        rows: u32,
    },
    Signal {
        name: String,
    },
    ExitStatus {
        code: i32,
    },

    // ── Keepalive ──
    Ping,
    Pong,

    // ── File transfer ──
    FileHeader {
        name: String,
        size: u64,
        mode: u32,
        /// Unix mtime (seconds since epoch). 0 = not preserved.
        mtime: u64,
        /// Whether FileChunk payloads are zstd-compressed.
        compress: bool,
    },
    FileChunk(Vec<u8>),
    FileEnd {
        sha256: [u8; 32],
    },
    FileAck,
    FileFail {
        reason: String,
    },

    // ── Transfer resume ──
    /// Client asks: "I want to resume upload at this path; how many bytes do you have?"
    ResumeRequest {
        path: String,
    },
    /// Server replies with how many bytes it has already (0 = start fresh).
    ResumeOffset {
        offset: u64,
    },

    // ── Delta sync (rsync-style) ──
    /// Client asks server: "do you have this file? I want to sync it"
    SyncRequest {
        name: String,
        size: u64,
        mode: u32,
    },
    /// Server responds with rsync signature of existing file
    SyncSignature {
        signature: Vec<u8>,
    },
    /// Server says file doesn't exist — client should send full
    SyncNotFound,
    /// Client sends computed delta (only the diff)
    SyncDelta {
        delta: Vec<u8>,
    },
    /// Server says files are identical, no transfer needed
    SyncUpToDate,

    // ── Directory listing ──
    /// Client requests directory listing from server.
    DirList {
        path: String,
    },
    /// Server sends one entry per file/dir.
    DirEntry {
        name: String,
        is_dir: bool,
        size: u64,
        mtime: u64,
        mode: u32,
    },
    /// Server signals end of directory listing.
    DirEnd,

    // ── Port forwarding ──
    /// Open forward channel: command = "host:port"
    ForwardOpen {
        host: String,
        port: u16,
    },
    ForwardAccept,
    ForwardReject { reason: String },
}

/// Channel types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    Shell,
    Exec,
    Scp,
    PortForward,
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shell => write!(f, "shell"),
            Self::Exec => write!(f, "exec"),
            Self::Scp => write!(f, "scp"),
            Self::PortForward => write!(f, "port-forward"),
        }
    }
}

// ── Encode / Decode (sync) ────────────────────────────────────────────────

/// Encode a message into a length-prefixed frame: `[u32 BE len][bincode payload]`.
pub fn encode(msg: &Message) -> Result<Vec<u8>, ProtoError> {
    let payload = bincode::serialize(msg).map_err(ProtoError::Encode)?;
    let len = payload.len() as u32;
    if len > MAX_MSG_SIZE {
        return Err(ProtoError::MessageTooLarge(len));
    }
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Decode a message from a bincode payload (without the length prefix).
pub fn decode(payload: &[u8]) -> Result<Message, ProtoError> {
    bincode::deserialize(payload).map_err(ProtoError::Decode)
}

// ── Async framed read / write ─────────────────────────────────────────────

/// Write a length-prefixed bincode message to an async writer.
pub async fn write_msg<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &Message,
) -> Result<(), ProtoError> {
    let frame = encode(msg)?;
    w.write_all(&frame).await?;
    Ok(())
}

/// Read a length-prefixed bincode message from an async reader.
/// Returns `None` on clean EOF.
pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Message>, ProtoError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MSG_SIZE {
        return Err(ProtoError::MessageTooLarge(len));
    }

    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    let msg = bincode::deserialize(&payload).map_err(ProtoError::Decode)?;
    Ok(Some(msg))
}

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("encode: {0}")]
    Encode(#[source] bincode::Error),
    #[error("decode: {0}")]
    Decode(#[source] bincode::Error),
    #[error("message too large: {0} bytes")]
    MessageTooLarge(u32),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
