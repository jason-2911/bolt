//! Session-layer frames carried inside packet payloads.
//!
//! StreamDataFrame: 16-byte header + data
//!   [type(1)][stream_id(4)][offset(8)][data_len(2)][flags(1)][data(N)]
//!
//! ControlFrame: 13 bytes
//!   [type(1)][stream_id(4)][value(8)]
//!
//! AckFrame: 18 + 16*N bytes
//!   [largest_acked(8)][ack_delay(8)][range_count(2)][ranges...]

use thiserror::Error;

pub const MAX_PAYLOAD: usize = 65535;
pub const STREAM_DATA_HEADER: usize = 16;
pub const CONTROL_FRAME_SIZE: usize = 13;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    StreamData   = 0x01,
    StreamClose  = 0x02,
    StreamReset  = 0x03,
    WindowUpdate = 0x04,
    StreamPrio   = 0x05,
    Ping         = 0x06,
    Pong         = 0x07,
}

impl TryFrom<u8> for FrameType {
    type Error = FrameError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::StreamData),
            0x02 => Ok(Self::StreamClose),
            0x03 => Ok(Self::StreamReset),
            0x04 => Ok(Self::WindowUpdate),
            0x05 => Ok(Self::StreamPrio),
            0x06 => Ok(Self::Ping),
            0x07 => Ok(Self::Pong),
            _ => Err(FrameError::UnknownType(v)),
        }
    }
}

// ── StreamDataFrame ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StreamDataFrame {
    pub stream_id: u32,
    pub offset:    u64,
    pub fin:       bool,
    pub data:      Vec<u8>,
}

impl StreamDataFrame {
    pub fn marshal(&self) -> Result<Vec<u8>, FrameError> {
        let data_len = self.data.len();
        if data_len > MAX_PAYLOAD {
            return Err(FrameError::DataTooLarge(data_len));
        }
        let mut buf = vec![0u8; STREAM_DATA_HEADER + data_len];
        buf[0] = FrameType::StreamData as u8;
        buf[1..5].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[5..13].copy_from_slice(&self.offset.to_be_bytes());
        buf[13..15].copy_from_slice(&(data_len as u16).to_be_bytes());
        buf[15] = if self.fin { 0x01 } else { 0x00 };
        if data_len > 0 {
            buf[STREAM_DATA_HEADER..].copy_from_slice(&self.data);
        }
        Ok(buf)
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < STREAM_DATA_HEADER {
            return Err(FrameError::TooSmall("StreamData", data.len()));
        }
        if data[0] != FrameType::StreamData as u8 {
            return Err(FrameError::WrongType {
                expected: FrameType::StreamData as u8,
                got: data[0],
            });
        }
        let data_len = u16::from_be_bytes([data[13], data[14]]) as usize;
        if data.len() < STREAM_DATA_HEADER + data_len {
            return Err(FrameError::Truncated("StreamData"));
        }
        Ok(Self {
            stream_id: u32::from_be_bytes(data[1..5].try_into().unwrap()),
            offset:    u64::from_be_bytes(data[5..13].try_into().unwrap()),
            fin:       data[15] & 0x01 != 0,
            data:      if data_len > 0 {
                data[STREAM_DATA_HEADER..STREAM_DATA_HEADER + data_len].to_vec()
            } else {
                Vec::new()
            },
        })
    }
}

// ── ControlFrame ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ControlFrame {
    pub frame_type: FrameType,
    pub stream_id:  u32,
    /// Semantics depend on frame type:
    ///   WindowUpdate → window delta
    ///   StreamReset  → error code
    ///   StreamPrio   → priority level
    pub value:      u64,
}

impl ControlFrame {
    pub fn marshal(&self) -> Vec<u8> {
        let mut buf = vec![0u8; CONTROL_FRAME_SIZE];
        buf[0] = self.frame_type as u8;
        buf[1..5].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[5..13].copy_from_slice(&self.value.to_be_bytes());
        buf
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < CONTROL_FRAME_SIZE {
            return Err(FrameError::TooSmall("ControlFrame", data.len()));
        }
        Ok(Self {
            frame_type: FrameType::try_from(data[0])?,
            stream_id:  u32::from_be_bytes(data[1..5].try_into().unwrap()),
            value:      u64::from_be_bytes(data[5..13].try_into().unwrap()),
        })
    }
}

// ── AckFrame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AckFrame {
    pub largest_acked: u64,
    pub ack_delay:     u64, // microseconds
    pub ranges:        Vec<AckRange>,
}

#[derive(Debug, Clone, Copy)]
pub struct AckRange {
    pub gap:    u64,
    pub length: u64,
}

impl AckFrame {
    pub fn marshal(&self) -> Vec<u8> {
        let size = 18 + self.ranges.len() * 16;
        let mut buf = vec![0u8; size];
        buf[0..8].copy_from_slice(&self.largest_acked.to_be_bytes());
        buf[8..16].copy_from_slice(&self.ack_delay.to_be_bytes());
        buf[16..18].copy_from_slice(&(self.ranges.len() as u16).to_be_bytes());
        let mut off = 18;
        for r in &self.ranges {
            buf[off..off + 8].copy_from_slice(&r.gap.to_be_bytes());
            buf[off + 8..off + 16].copy_from_slice(&r.length.to_be_bytes());
            off += 16;
        }
        buf
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < 18 {
            return Err(FrameError::TooSmall("AckFrame", data.len()));
        }
        let range_count = u16::from_be_bytes([data[16], data[17]]) as usize;
        if data.len() < 18 + range_count * 16 {
            return Err(FrameError::Truncated("AckFrame"));
        }
        let mut ranges = Vec::with_capacity(range_count);
        let mut off = 18;
        for _ in 0..range_count {
            ranges.push(AckRange {
                gap:    u64::from_be_bytes(data[off..off + 8].try_into().unwrap()),
                length: u64::from_be_bytes(data[off + 8..off + 16].try_into().unwrap()),
            });
            off += 16;
        }
        Ok(Self {
            largest_acked: u64::from_be_bytes(data[0..8].try_into().unwrap()),
            ack_delay:     u64::from_be_bytes(data[8..16].try_into().unwrap()),
            ranges,
        })
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("{0} frame too small: {1} bytes")]
    TooSmall(&'static str, usize),
    #[error("{0} frame truncated")]
    Truncated(&'static str),
    #[error("data too large: {0} bytes")]
    DataTooLarge(usize),
    #[error("wrong frame type: expected 0x{expected:02x}, got 0x{got:02x}")]
    WrongType { expected: u8, got: u8 },
    #[error("unknown frame type: 0x{0:02x}")]
    UnknownType(u8),
}
