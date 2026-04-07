//! Bolt wire-protocol types and serialization.
//!
//! Layers:
//!   packet  – UDP transport-layer packets (40-byte header + payload)
//!   frame   – Session-layer frames (stream data, control, ACK)
//!   channel – Application-layer channel messages (shell, exec, SCP)
//!   error   – Protocol error codes

pub mod channel;
pub mod error;
pub mod frame;
pub mod packet;

pub use channel::*;
pub use error::*;
pub use frame::*;
pub use packet::*;
