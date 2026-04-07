//! Bolt wire-protocol types and serialization.
//!
//! All messages are framed as `[u32 BE length][bincode payload]` over QUIC streams.

pub mod message;
pub mod udp_gui;

pub use message::*;
pub use udp_gui::*;
