//! Bolt transport-layer packet: 40-byte header + payload.
//!
//! Wire format:
//!   0..16  Connection ID (16 bytes, random)
//!   16     Packet Type   (u8)
//!   17     Flags         (u8)
//!   18..26 Sequence Num  (u64 BE)
//!   26..34 Timestamp     (u64 BE, microseconds)
//!   34..36 Payload Len   (u16 BE)
//!   36..40 CRC32 checksum (u32 BE, over bytes 0..36 + payload)
//!   40..   Payload

use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

pub const CONN_ID_SIZE: usize = 16;
pub const HEADER_SIZE: usize = 40;
pub const MAX_PAYLOAD_SIZE: usize = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub [u8; CONN_ID_SIZE]);

impl ConnectionId {
    pub fn generate() -> Self {
        let mut id = [0u8; CONN_ID_SIZE];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
        Self(id)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0[..8] {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Returns current time in microseconds since UNIX epoch.
pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Handshake  = 0x01,
    Data       = 0x02,
    Ack        = 0x03,
    Nack       = 0x04,
    Ping       = 0x05,
    Pong       = 0x06,
    Migrate    = 0x07,
    MigrateAck = 0x08,
    Close      = 0x09,
    Reset      = 0x0A,
}

impl TryFrom<u8> for PacketType {
    type Error = PacketError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Ack),
            0x04 => Ok(Self::Nack),
            0x05 => Ok(Self::Ping),
            0x06 => Ok(Self::Pong),
            0x07 => Ok(Self::Migrate),
            0x08 => Ok(Self::MigrateAck),
            0x09 => Ok(Self::Close),
            0x0A => Ok(Self::Reset),
            _ => Err(PacketError::UnknownType(v)),
        }
    }
}

impl std::fmt::Display for PacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Handshake  => "Handshake",
            Self::Data       => "Data",
            Self::Ack        => "Ack",
            Self::Nack       => "Nack",
            Self::Ping       => "Ping",
            Self::Pong       => "Pong",
            Self::Migrate    => "Migrate",
            Self::MigrateAck => "MigrateAck",
            Self::Close      => "Close",
            Self::Reset      => "Reset",
        };
        write!(f, "{}", s)
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PacketFlags: u8 {
        const FIN      = 0b0000_0001;
        const SYN      = 0b0000_0010;
        const RST      = 0b0000_0100;
        const FEC      = 0b0000_1000;
        const COMPRESS = 0b0001_0000;
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub conn_id:   ConnectionId,
    pub pkt_type:  PacketType,
    pub flags:     PacketFlags,
    pub seq_num:   u64,
    pub timestamp: u64,
    pub payload:   Vec<u8>,
}

impl Packet {
    pub fn new(pkt_type: PacketType, conn_id: ConnectionId, payload: Vec<u8>) -> Self {
        Self {
            conn_id,
            pkt_type,
            flags: PacketFlags::default(),
            seq_num: 0,
            timestamp: now_micros(),
            payload,
        }
    }

    /// Serialize to wire format.
    pub fn marshal(&self) -> Result<Vec<u8>, PacketError> {
        let payload_len = self.payload.len();
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(PacketError::PayloadTooLarge(payload_len));
        }

        let mut buf = vec![0u8; HEADER_SIZE + payload_len];

        buf[0..16].copy_from_slice(&self.conn_id.0);
        buf[16] = self.pkt_type as u8;
        buf[17] = self.flags.bits();
        buf[18..26].copy_from_slice(&self.seq_num.to_be_bytes());
        buf[26..34].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[34..36].copy_from_slice(&(payload_len as u16).to_be_bytes());

        if payload_len > 0 {
            buf[HEADER_SIZE..].copy_from_slice(&self.payload);
        }

        // CRC32 over bytes 0..36 + payload
        let checksum = crc32_ieee(&buf[..36]);
        let checksum = if payload_len > 0 {
            crc32_ieee_update(checksum, &buf[HEADER_SIZE..])
        } else {
            checksum
        };
        buf[36..40].copy_from_slice(&checksum.to_be_bytes());

        Ok(buf)
    }

    /// Deserialize from wire format.
    pub fn unmarshal(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < HEADER_SIZE {
            return Err(PacketError::TooSmall(data.len()));
        }

        let payload_len = u16::from_be_bytes([data[34], data[35]]) as usize;
        if data.len() < HEADER_SIZE + payload_len {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE + payload_len,
                got: data.len(),
            });
        }

        // Verify CRC32
        let stored = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);
        let computed = crc32_ieee(&data[..36]);
        let computed = if payload_len > 0 {
            crc32_ieee_update(computed, &data[HEADER_SIZE..HEADER_SIZE + payload_len])
        } else {
            computed
        };
        if stored != computed {
            return Err(PacketError::ChecksumMismatch { stored, computed });
        }

        let mut conn_id = [0u8; CONN_ID_SIZE];
        conn_id.copy_from_slice(&data[0..16]);

        let payload = if payload_len > 0 {
            data[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            conn_id:   ConnectionId(conn_id),
            pkt_type:  PacketType::try_from(data[16])?,
            flags:     PacketFlags::from_bits_truncate(data[17]),
            seq_num:   u64::from_be_bytes(data[18..26].try_into().unwrap()),
            timestamp: u64::from_be_bytes(data[26..34].try_into().unwrap()),
            payload,
        })
    }
}

// ── CRC32 (IEEE polynomial) ────────────────────────────────────────────────

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = CRC32_TABLE[idx] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn crc32_ieee_update(mut crc: u32, data: &[u8]) -> u32 {
    // Re-enter with the final XOR undone
    crc ^= 0xFFFF_FFFF;
    for &b in data {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = CRC32_TABLE[idx] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

// Pre-computed CRC32/IEEE table
static CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            if c & 1 != 0 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

// ── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("packet too small: {0} bytes (minimum {HEADER_SIZE})")]
    TooSmall(usize),
    #[error("packet truncated: expected {expected} bytes, got {got}")]
    Truncated { expected: usize, got: usize },
    #[error("payload too large: {0} bytes (max {MAX_PAYLOAD_SIZE})")]
    PayloadTooLarge(usize),
    #[error("checksum mismatch: stored 0x{stored:08x}, computed 0x{computed:08x}")]
    ChecksumMismatch { stored: u32, computed: u32 },
    #[error("unknown packet type: 0x{0:02x}")]
    UnknownType(u8),
}
