//! Bolt wire-protocol types and serialization.
//!
//! All messages are framed as `[u32 BE length][bincode payload]` over QUIC streams.

pub mod message;

pub use message::*;
