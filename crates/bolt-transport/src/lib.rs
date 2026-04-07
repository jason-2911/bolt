//! Bolt reliable UDP transport layer.
//!
//! Files:
//!   config.rs   – `Config` and `DefaultConfig`
//!   bbr.rs      – BBR congestion control state machine
//!   conn.rs     – `Connection`: send/recv, retransmit, ACK
//!   listener.rs – `Listener`: server-side UDP accept loop

pub mod bbr;
pub mod config;
pub mod conn;
pub mod listener;

pub use config::Config;
pub use conn::Connection;
pub use listener::Listener;
