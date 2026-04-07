//! UDP protocol for one-way GUI video stream and input stream.
//!
//! Datagram format: bincode-encoded [`UdpGuiPacket`].

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Keep UDP payload small enough to avoid IP fragmentation in common networks.
pub const MAX_UDP_PACKET_SIZE: usize = 1200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UdpGuiPacket {
    /// Client hello / registration.
    Hello { token: String },
    /// Sent from server to client.
    DesktopInventoryChunk(DesktopInventoryChunk),
    /// Sent from client to server.
    AttachWindow { window_id: u64 },
    /// Sent from client to server.
    DetachWindow,
    /// Sent from server to client.
    VideoChunk(VideoChunk),
    /// Sent from client to server.
    InputEvent(InputEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopInventoryChunk {
    pub generation: u64,
    pub chunk_index: u16,
    pub chunk_total: u16,
    pub attached_window_id: Option<u64>,
    pub windows: Vec<DesktopWindow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopWindow {
    pub window_id: u64,
    pub pid: Option<u32>,
    pub process_name: String,
    pub title: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoChunk {
    pub frame_id: u64,
    pub patch_id: u32,
    pub chunk_index: u16,
    pub chunk_total: u16,
    pub rect: Rect,
    pub surface_width: u32,
    pub surface_height: u32,
    pub codec: VideoCodec,
    pub compressed_size: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VideoCodec {
    RawRgb24Zstd,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputEvent {
    Key { code: u32, down: bool },
    MouseMove { x: i32, y: i32 },
    MouseButton { button: MouseButton, down: bool },
    MouseWheel { dx: i32, dy: i32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

pub fn encode_udp_packet(pkt: &UdpGuiPacket) -> Result<Vec<u8>, UdpGuiError> {
    let encoded = bincode::serialize(pkt).map_err(UdpGuiError::Encode)?;
    if encoded.len() > MAX_UDP_PACKET_SIZE {
        return Err(UdpGuiError::PacketTooLarge(encoded.len()));
    }
    Ok(encoded)
}

pub fn decode_udp_packet(bytes: &[u8]) -> Result<UdpGuiPacket, UdpGuiError> {
    bincode::deserialize(bytes).map_err(UdpGuiError::Decode)
}

#[derive(Debug, Error)]
pub enum UdpGuiError {
    #[error("encode: {0}")]
    Encode(#[source] bincode::Error),
    #[error("decode: {0}")]
    Decode(#[source] bincode::Error),
    #[error("UDP packet too large: {0} bytes")]
    PacketTooLarge(usize),
}
