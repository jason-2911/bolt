//! Bolt session: multiplexed streams over an encrypted transport connection.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex,
    },
};

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use bolt_crypto::noise::{HandshakeResult, NoiseCipher};
use bolt_proto::frame::{ControlFrame, FrameType, StreamDataFrame};
use bolt_transport::Connection;

use super::stream::{Stream, PRIORITY_NORMAL};

// ── Session ────────────────────────────────────────────────────────────────

pub struct Session {
    conn:     Connection,
    cipher:   Arc<Mutex<NoiseCipher>>,
    is_server: bool,

    streams:   Arc<Mutex<HashMap<u32, StreamEntry>>>,
    next_id:   Arc<AtomicU32>,
    accept_tx: mpsc::Sender<Stream>,
    accept_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Stream>>>,
    closed:    Arc<AtomicBool>,
}

struct StreamEntry {
    read_inject: mpsc::Sender<Bytes>,
}

impl Session {
    pub fn new(conn: Connection, result: HandshakeResult, is_server: bool) -> Self {
        let (accept_tx, accept_rx) = mpsc::channel(32);
        let streams = Arc::new(Mutex::new(HashMap::<u32, StreamEntry>::new()));
        let closed  = Arc::new(AtomicBool::new(false));
        let next_id = Arc::new(AtomicU32::new(if is_server { 2 } else { 1 }));
        let cipher  = Arc::new(Mutex::new(result.cipher));

        let sess = Self {
            conn:      conn.clone(),
            cipher:    Arc::clone(&cipher),
            is_server,
            streams:   Arc::clone(&streams),
            next_id:   Arc::clone(&next_id),
            accept_tx: accept_tx.clone(),
            accept_rx: Arc::new(tokio::sync::Mutex::new(accept_rx)),
            closed:    Arc::clone(&closed),
        };

        // Close handler: when transport dies, session dies
        {
            let closed2  = Arc::clone(&closed);
            let streams2 = Arc::clone(&streams);
            conn.set_close_handler(move || {
                closed2.store(true, Ordering::SeqCst);
                streams2.lock().unwrap().clear();
            });
        }

        // Spawn receive/dispatch loop
        tokio::spawn(recv_loop(
            conn,
            Arc::clone(&cipher),
            Arc::clone(&streams),
            accept_tx,
            Arc::clone(&closed),
        ));

        debug!(
            component = "session",
            role = if is_server { "server" } else { "client" },
            "session created"
        );

        sess
    }

    /// Open a new outgoing stream.
    pub fn open_stream(&self, priority: u8) -> Result<Stream, SessionError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(SessionError::Closed);
        }
        let id = self.next_id.fetch_add(2, Ordering::Relaxed);
        let (stream, read_inject, mut write_drain) = Stream::new_pair(id, priority);

        self.streams.lock().unwrap().insert(id, StreamEntry { read_inject });

        // Forward stream writes → encrypted transport
        let conn    = self.conn.clone();
        let cipher  = Arc::clone(&self.cipher);
        let streams = Arc::clone(&self.streams);
        let closed  = Arc::clone(&self.closed);

        tokio::spawn(async move {
            let mut offset: u64 = 0;
            loop {
                if closed.load(Ordering::Relaxed) { break; }
                match write_drain.recv().await {
                    Some(chunk) => {
                        let frame = StreamDataFrame {
                            stream_id: id,
                            offset,
                            fin: false,
                            data: chunk.to_vec(),
                        };
                        offset += frame.data.len() as u64;
                        let encrypted = frame.marshal().ok().and_then(|raw| {
                            cipher.lock().unwrap().encrypt(&raw).ok()
                        });
                        if let Some(enc) = encrypted {
                            let _ = conn.send(enc).await;
                        }
                    }
                    None => {
                        // Stream write closed → send FIN
                        let frame = StreamDataFrame { stream_id: id, offset, fin: true, data: vec![] };
                        let encrypted = frame.marshal().ok().and_then(|raw| {
                            cipher.lock().unwrap().encrypt(&raw).ok()
                        });
                        if let Some(enc) = encrypted {
                            let _ = conn.send(enc).await;
                        }
                        streams.lock().unwrap().remove(&id);
                        break;
                    }
                }
            }
        });

        debug!(component = "session", stream_id = id, priority, "stream opened");
        Ok(stream)
    }

    pub async fn accept_stream(&self) -> Option<Stream> {
        self.accept_rx.lock().await.recv().await
    }

    pub async fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.streams.lock().unwrap().clear();
            self.conn.close().await;
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

// ── Receive / dispatch loop ────────────────────────────────────────────────

async fn recv_loop(
    conn:      Connection,
    cipher:    Arc<Mutex<NoiseCipher>>,
    streams:   Arc<Mutex<HashMap<u32, StreamEntry>>>,
    accept_tx: mpsc::Sender<Stream>,
    closed:    Arc<AtomicBool>,
) {
    loop {
        if closed.load(Ordering::Relaxed) { break; }

        let pkt = match conn.recv().await {
            Some(p) => p,
            None    => break,
        };

        // Decrypt
        let plain = match cipher.lock().unwrap().decrypt(&pkt.payload) {
            Ok(p)  => p,
            Err(e) => {
                error!(component = "session", "decrypt: {e}");
                continue;
            }
        };

        if plain.is_empty() { continue; }

        match plain[0] {
            0x01 => { // StreamData
                let frame = match StreamDataFrame::unmarshal(&plain) {
                    Ok(f)  => f,
                    Err(e) => { warn!(component = "session", "bad StreamData: {e}"); continue; }
                };

                let has_entry = streams.lock().unwrap().contains_key(&frame.stream_id);

                if has_entry {
                    let entry = streams.lock().unwrap();
                    if let Some(e) = entry.get(&frame.stream_id) {
                        if !frame.data.is_empty() {
                            let _ = e.read_inject.try_send(Bytes::from(frame.data.clone()));
                        }
                    }
                    drop(entry);
                    if frame.fin {
                        streams.lock().unwrap().remove(&frame.stream_id);
                    }
                } else {
                    // New incoming stream
                    let id = frame.stream_id;
                    let (stream, read_inject, _write_drain) = Stream::new_pair(id, PRIORITY_NORMAL);
                    streams.lock().unwrap().insert(id, StreamEntry { read_inject: read_inject.clone() });

                    if !frame.data.is_empty() {
                        let _ = read_inject.try_send(Bytes::from(frame.data));
                    }

                    if accept_tx.send(stream).await.is_err() { break; }
                }
            }
            0x02..=0x05 => { // Control frames
                if let Ok(ctrl) = ControlFrame::unmarshal(&plain) {
                    match ctrl.frame_type {
                        FrameType::StreamClose | FrameType::StreamReset => {
                            streams.lock().unwrap().remove(&ctrl.stream_id);
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                warn!(component = "session", "unknown frame type 0x{:02x}", plain[0]);
            }
        }
    }
    closed.store(true, Ordering::SeqCst);
}

// ── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session is closed")]
    Closed,
    #[error("transport: {0}")]
    Transport(#[from] anyhow::Error),
}
