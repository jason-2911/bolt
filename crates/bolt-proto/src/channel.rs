//! Application-layer channel messages (shell, exec, SCP, port-forward).
//!
//! ChannelOpenMsg wire format:
//!   [MsgChannelOpen(1)][channel_type(1)][cmd_len(2 BE)][cmd...]

use thiserror::Error;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    Shell       = 0x01,
    Exec        = 0x02,
    Scp         = 0x03,
    PortForward = 0x04,
}

impl TryFrom<u8> for ChannelType {
    type Error = ChannelError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Shell),
            0x02 => Ok(Self::Exec),
            0x03 => Ok(Self::Scp),
            0x04 => Ok(Self::PortForward),
            _ => Err(ChannelError::UnknownChannelType(v)),
        }
    }
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shell       => write!(f, "shell"),
            Self::Exec        => write!(f, "exec"),
            Self::Scp         => write!(f, "scp"),
            Self::PortForward => write!(f, "port-forward"),
        }
    }
}

// ── Message types ──────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    ChannelOpen        = 0x01,
    ChannelOpenConfirm = 0x02,
    ChannelOpenFail    = 0x03,
    ChannelClose       = 0x04,
    ChannelData        = 0x05,
    ChannelEof         = 0x06,
    ChannelRequest     = 0x07,
    ChannelSuccess     = 0x08,
    ChannelFailure     = 0x09,
}

impl TryFrom<u8> for MsgType {
    type Error = ChannelError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::ChannelOpen),
            0x02 => Ok(Self::ChannelOpenConfirm),
            0x03 => Ok(Self::ChannelOpenFail),
            0x04 => Ok(Self::ChannelClose),
            0x05 => Ok(Self::ChannelData),
            0x06 => Ok(Self::ChannelEof),
            0x07 => Ok(Self::ChannelRequest),
            0x08 => Ok(Self::ChannelSuccess),
            0x09 => Ok(Self::ChannelFailure),
            _ => Err(ChannelError::UnknownMsgType(v)),
        }
    }
}

// ── Channel request types ──────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    Pty          = 0x01,
    Shell        = 0x02,
    Exec         = 0x03,
    WindowChange = 0x04,
    Signal       = 0x05,
    ExitStatus   = 0x06,
    Subsystem    = 0x07,
}

// ── ChannelOpenMsg ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChannelOpenMsg {
    pub channel_type: ChannelType,
    pub command:      String,
}

impl ChannelOpenMsg {
    pub fn marshal(&self) -> Vec<u8> {
        let cmd = self.command.as_bytes();
        let mut buf = Vec::with_capacity(4 + cmd.len());
        buf.push(MsgType::ChannelOpen as u8);
        buf.push(self.channel_type as u8);
        buf.extend_from_slice(&(cmd.len() as u16).to_be_bytes());
        buf.extend_from_slice(cmd);
        buf
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self, ChannelError> {
        if data.len() < 4 {
            return Err(ChannelError::TooShort("ChannelOpen"));
        }
        let cmd_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + cmd_len {
            return Err(ChannelError::Truncated("ChannelOpen"));
        }
        Ok(Self {
            channel_type: ChannelType::try_from(data[1])?,
            command:      String::from_utf8_lossy(&data[4..4 + cmd_len]).into_owned(),
        })
    }
}

// ── PtyRequest ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PtyRequest {
    pub term:         String,
    pub width_chars:  u32,
    pub height_chars: u32,
}

impl PtyRequest {
    pub fn marshal(&self) -> Vec<u8> {
        let term = self.term.as_bytes();
        let mut buf = Vec::with_capacity(3 + term.len() + 8);
        buf.push(MsgType::ChannelRequest as u8);
        buf.push(RequestType::Pty as u8);
        buf.push(term.len() as u8);
        buf.extend_from_slice(term);
        buf.extend_from_slice(&self.width_chars.to_be_bytes());
        buf.extend_from_slice(&self.height_chars.to_be_bytes());
        buf
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self, ChannelError> {
        if data.len() < 3 {
            return Err(ChannelError::TooShort("PtyRequest"));
        }
        let term_len = data[2] as usize;
        if data.len() < 3 + term_len + 8 {
            return Err(ChannelError::Truncated("PtyRequest"));
        }
        let off = 3 + term_len;
        Ok(Self {
            term:         String::from_utf8_lossy(&data[3..3 + term_len]).into_owned(),
            width_chars:  u32::from_be_bytes(data[off..off + 4].try_into().unwrap()),
            height_chars: u32::from_be_bytes(data[off + 4..off + 8].try_into().unwrap()),
        })
    }
}

// ── WindowChangeRequest ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct WindowChangeRequest {
    pub width_chars:  u32,
    pub height_chars: u32,
}

impl WindowChangeRequest {
    pub fn marshal(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 10];
        buf[0] = MsgType::ChannelRequest as u8;
        buf[1] = RequestType::WindowChange as u8;
        buf[2..6].copy_from_slice(&self.width_chars.to_be_bytes());
        buf[6..10].copy_from_slice(&self.height_chars.to_be_bytes());
        buf
    }
}

// ── SignalRequest ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SignalRequest {
    pub signal: String,
}

impl SignalRequest {
    pub fn marshal(&self) -> Vec<u8> {
        let sig = self.signal.as_bytes();
        let mut buf = Vec::with_capacity(3 + sig.len());
        buf.push(MsgType::ChannelRequest as u8);
        buf.push(RequestType::Signal as u8);
        buf.push(sig.len() as u8);
        buf.extend_from_slice(sig);
        buf
    }
}

// ── ExitStatusMsg ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct ExitStatusMsg {
    pub exit_code: u32,
}

impl ExitStatusMsg {
    pub fn marshal(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 6];
        buf[0] = MsgType::ChannelRequest as u8;
        buf[1] = RequestType::ExitStatus as u8;
        buf[2..6].copy_from_slice(&self.exit_code.to_be_bytes());
        buf
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self, ChannelError> {
        if data.len() < 6 {
            return Err(ChannelError::TooShort("ExitStatus"));
        }
        Ok(Self {
            exit_code: u32::from_be_bytes(data[2..6].try_into().unwrap()),
        })
    }
}

// ── Transfer frame helpers ─────────────────────────────────────────────────
// SCP transfer wire: [type(1)][payload_len(4 BE)][payload(N)]

pub fn write_transfer_frame(msg_type: MsgType, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(msg_type as u8);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

// ── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("{0} message too short")]
    TooShort(&'static str),
    #[error("{0} message truncated")]
    Truncated(&'static str),
    #[error("unknown channel type: 0x{0:02x}")]
    UnknownChannelType(u8),
    #[error("unknown message type: 0x{0:02x}")]
    UnknownMsgType(u8),
}
