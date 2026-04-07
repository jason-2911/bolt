//! Bolt protocol messages — serialized with bincode, length-prefixed.
//!
//! Wire format: `[u32 BE length][bincode-encoded Message]`

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum single message size (16 MB).
pub const MAX_MSG_SIZE: u32 = 16 * 1024 * 1024;

// ── Message enum ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // ── Auth ──
    AuthRequest {
        user: String,
        public_key: [u8; 32],
    },
    /// Password auth fallback.
    AuthPassword {
        user: String,
        password: String,
    },
    /// CA-signed certificate auth.
    AuthCert {
        cert: Vec<u8>,
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
    EnvSet { key: String, val: String },
    PtyRequest { term: String, cols: u32, rows: u32 },
    WindowChange { cols: u32, rows: u32 },
    Signal { name: String },
    ExitStatus { code: i32 },

    // ── Keepalive ──
    Ping,
    Pong,

    // ── File transfer ──
    FileHeader {
        name: String,
        size: u64,
        mode: u32,
        mtime: u64,
        compress: bool,
    },
    FileChunk(Vec<u8>),
    FileEnd { sha256: [u8; 32] },
    FileAck,
    FileFail { reason: String },

    // ── Transfer resume ──
    ResumeRequest { path: String },
    ResumeOffset { offset: u64 },

    // ── Delta sync ──
    SyncRequest { name: String, size: u64, mode: u32 },
    SyncSignature { signature: Vec<u8> },
    SyncNotFound,
    SyncDelta { delta: Vec<u8> },
    SyncUpToDate,

    // ── Directory listing ──
    DirList { path: String },
    DirEntry { name: String, is_dir: bool, size: u64, mtime: u64, mode: u32 },
    DirEnd,

    // ── Local port forwarding ──
    ForwardOpen { host: String, port: u16 },
    ForwardAccept,
    ForwardReject { reason: String },

    // ── Remote port forwarding (-R) ──
    /// Client asks server to bind a TCP port; "0" = pick any free port.
    RemoteForwardBind { bind_port: u16 },
    /// Server confirms and tells client which port was actually bound.
    RemoteForwardBound { bound_port: u16 },
    /// Server notifies client of a new incoming connection on the bound port.
    RemoteForwardIncoming { peer: String },
    /// Server (or client) signals no more remote forward connections.
    RemoteForwardClose,

    // ── Filesystem (SFTP-like) ──
    FsRename { from: String, to: String },
    FsRemove { path: String, recursive: bool },
    FsMkdir  { path: String, mode: u32 },
    FsChmod  { path: String, mode: u32 },
    FsStat   { path: String },
    FsStatResult {
        name: String,
        size: u64,
        mtime: u64,
        mode: u32,
        is_dir: bool,
        is_symlink: bool,
    },
    FsOk,
    FsFail { reason: String },

    // ── SSH agent forwarding ──
    /// Client requests that the server create a forwarded agent socket.
    AgentForwardRequest,
    AgentForwardAccept,
    /// Raw SSH agent protocol message (length-prefixed, direction: client→server or server→client).
    AgentMessage { data: Vec<u8> },
}

/// Channel types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    Shell,
    Exec,
    Scp,
    PortForward,
    RemoteForward,
    Fs,
    AgentForward,
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shell         => write!(f, "shell"),
            Self::Exec          => write!(f, "exec"),
            Self::Scp           => write!(f, "scp"),
            Self::PortForward   => write!(f, "port-forward"),
            Self::RemoteForward => write!(f, "remote-forward"),
            Self::Fs            => write!(f, "fs"),
            Self::AgentForward  => write!(f, "agent-forward"),
        }
    }
}

// ── Encode / Decode ───────────────────────────────────────────────────────

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

pub fn decode(payload: &[u8]) -> Result<Message, ProtoError> {
    bincode::deserialize(payload).map_err(ProtoError::Decode)
}

pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &Message) -> Result<(), ProtoError> {
    let frame = encode(msg)?;
    w.write_all(&frame).await?;
    Ok(())
}

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
