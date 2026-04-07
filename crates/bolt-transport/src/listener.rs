//! Server-side UDP listener: accepts new connections and dispatches packets.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use tokio::{net::UdpSocket, sync::mpsc};
use tracing::{debug, error, info};

use bolt_proto::packet::{ConnectionId, Packet, HEADER_SIZE};

use super::{config::Config, conn::Connection};

// ── Listener ───────────────────────────────────────────────────────────────

/// Accepts new Bolt connections on a UDP socket.
pub struct Listener {
    inner: Arc<ListenerInner>,
    /// New connections are delivered here.
    accept_rx: mpsc::Receiver<Connection>,
}

struct ListenerInner {
    socket:  Arc<UdpSocket>,
    config:  Config,
    /// Map remote_addr → (push_tx to feed packets to that connection)
    conns:   Mutex<HashMap<SocketAddr, mpsc::Sender<Packet>>>,
    /// New connections
    accept_tx: mpsc::Sender<Connection>,
}

impl Listener {
    /// Bind and start listening on `addr`.
    pub async fn bind(addr: &str, config: Config) -> anyhow::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let (accept_tx, accept_rx) = mpsc::channel(64);

        let inner = Arc::new(ListenerInner {
            socket: Arc::clone(&socket),
            config,
            conns:     Mutex::new(HashMap::new()),
            accept_tx,
        });

        tokio::spawn(read_loop(Arc::clone(&inner)));

        Ok(Self { inner, accept_rx })
    }

    /// Block until a new connection arrives.
    pub async fn accept(&mut self) -> Option<Connection> {
        self.accept_rx.recv().await
    }

    /// Local address this listener is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.socket.local_addr()
    }
}

// ── Read loop ──────────────────────────────────────────────────────────────

async fn read_loop(inner: Arc<ListenerInner>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, remote) = match inner.socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                error!(component = "transport", "listener recv: {e}");
                continue;
            }
        };

        let data = &buf[..n];
        if data.len() < HEADER_SIZE {
            continue;
        }

        let pkt = match Packet::unmarshal(data) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Try to deliver to existing connection
        let push_tx = inner.conns.lock().unwrap().get(&remote).cloned();

        if let Some(tx) = push_tx {
            let _ = tx.try_send(pkt);
        } else {
            // New connection
            handle_new_connection(&inner, remote, pkt).await;
        }
    }
}

async fn handle_new_connection(inner: &Arc<ListenerInner>, remote: SocketAddr, first_pkt: Packet) {
    let conn_id = first_pkt.conn_id;

    debug!(
        component = "transport",
        remote     = %remote,
        conn_id    = %conn_id,
        "new transport connection"
    );

    let (conn, push_tx) = Connection::new_server(
        Arc::clone(&inner.socket),
        remote,
        conn_id,
        inner.config.clone(),
    );

    // Register in connection table
    inner.conns.lock().unwrap().insert(remote, push_tx.clone());

    // Deliver the first packet
    let _ = push_tx.try_send(first_pkt);

    // Notify accept loop
    if inner.accept_tx.send(conn).await.is_err() {
        inner.conns.lock().unwrap().remove(&remote);
    }
}
