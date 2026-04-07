//! A bidirectional Bolt stream implementing `AsyncRead + AsyncWrite`.
//!
//! Each stream is backed by two `tokio::sync::mpsc` channels:
//!   read_rx  – data arriving FROM the network
//!   write_tx – data going TO the network (via Session)

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

pub const PRIORITY_HIGH:   u8 = 1;
pub const PRIORITY_NORMAL: u8 = 2;

// ── Stream ─────────────────────────────────────────────────────────────────

/// One half of a Bolt application channel (shell, exec, SCP …).
pub struct Stream {
    pub id:       u32,
    pub priority: u8,

    /// Data received from the remote end (network → application).
    read_rx: mpsc::Receiver<Bytes>,
    /// Buffer for partial reads.
    read_buf: BytesMut,
    /// Set when the remote end has closed its write side.
    read_eof: bool,

    /// Data to send to the remote end (application → network).
    write_tx: mpsc::Sender<Bytes>,
    /// True once this end has called `shutdown()`.
    write_closed: bool,
}

impl Stream {
    /// Create a connected pair: `(stream, read_inject, write_drain)`.
    ///
    /// The session layer injects network data via `read_inject` and drains
    /// application writes via `write_drain`.
    pub fn new_pair(id: u32, priority: u8) -> (Self, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
        let (read_tx, read_rx)   = mpsc::channel::<Bytes>(128);
        let (write_tx, write_rx) = mpsc::channel::<Bytes>(128);
        let stream = Self {
            id,
            priority,
            read_rx,
            read_buf: BytesMut::new(),
            read_eof: false,
            write_tx,
            write_closed: false,
        };
        (stream, read_tx, write_rx)
    }

    /// Signal EOF to the reader (remote closed its write side).
    /// Callers do this by dropping the `read_inject` sender.

    pub fn is_write_closed(&self) -> bool { self.write_closed }
}

// ── AsyncRead ──────────────────────────────────────────────────────────────

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // Serve from buffer first
            if !self.read_buf.is_empty() {
                let n = buf.remaining().min(self.read_buf.len());
                buf.put_slice(&self.read_buf.split_to(n));
                return Poll::Ready(Ok(()));
            }

            if self.read_eof {
                return Poll::Ready(Ok(())); // EOF
            }

            // Poll the channel
            match self.read_rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.read_buf.extend_from_slice(&chunk);
                    // Loop to serve from buffer
                }
                Poll::Ready(None) => {
                    // Sender dropped → EOF
                    self.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ── AsyncWrite ─────────────────────────────────────────────────────────────

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed")));
        }
        let bytes = Bytes::copy_from_slice(buf);
        match self.write_tx.try_send(bytes) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel full — wait for capacity
                let waker = cx.waker().clone();
                let tx = self.write_tx.clone();
                tokio::spawn(async move {
                    let _ = tx.reserve().await;
                    waker.wake();
                });
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_closed = true;
        // Dropping write_tx signals EOF to the remote
        Poll::Ready(Ok(()))
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("stream is closed")]
    Closed,
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
}
