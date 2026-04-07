//! Bolt transport-layer connection: send/recv over UDP with retransmit + ACK.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, Notify},
    time,
};
use tracing::{debug, error, warn};

use bolt_proto::packet::{ConnectionId, Packet, PacketType, now_micros};

use super::{bbr::Bbr, config::Config};

// ── Sent-packet tracking ───────────────────────────────────────────────────

struct SentPacket {
    data:       Vec<u8>,
    sent_at:    Instant,
    acked:      bool,
}

// ── Connection ─────────────────────────────────────────────────────────────

/// Shared inner state (lives behind `Arc`).
struct Inner {
    socket:      Arc<UdpSocket>,
    remote:      SocketAddr,
    conn_id:     ConnectionId,
    config:      Config,
    is_server:   bool,

    // Sequence numbers
    next_seq:    AtomicU64,

    // Sent packets (for retransmission)
    sent:        Mutex<HashMap<u64, SentPacket>>,

    // RTT (Jacobson/Karels)
    rtt_mu:      Mutex<RttState>,

    // BBR congestion control
    bbr:         Mutex<Bbr>,

    // Receive queue (packets → session layer)
    recv_tx:     mpsc::Sender<Packet>,

    // Close signal
    closed:      AtomicBool,
    close_notify: Notify,

    // Optional on-close callback
    on_close:    Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

struct RttState {
    srtt:     Duration,
    rttvar:   Duration,
    rto:      Duration,
}

impl Default for RttState {
    fn default() -> Self {
        Self {
            srtt:   Duration::from_millis(50),
            rttvar: Duration::from_millis(25),
            rto:    Duration::from_millis(200),
        }
    }
}

/// A Bolt transport-layer connection (client or server side).
/// Cheap to clone — all state is behind `Arc`.
#[derive(Clone)]
pub struct Connection {
    inner: Arc<Inner>,
    /// Receive channel — callers read incoming packets from here.
    recv_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
}

impl Connection {
    // ── Constructor helpers ────────────────────────────────────────────────

    fn new_inner(
        socket:    Arc<UdpSocket>,
        remote:    SocketAddr,
        conn_id:   ConnectionId,
        config:    Config,
        is_server: bool,
    ) -> (Arc<Inner>, mpsc::Receiver<Packet>) {
        let (recv_tx, recv_rx) = mpsc::channel(256);
        let inner = Arc::new(Inner {
            socket,
            remote,
            conn_id,
            config,
            is_server,
            next_seq: AtomicU64::new(1),
            sent:     Mutex::new(HashMap::new()),
            rtt_mu:   Mutex::new(RttState::default()),
            bbr:      Mutex::new(Bbr::new()),
            recv_tx,
            closed:   AtomicBool::new(false),
            close_notify: Notify::new(),
            on_close: Mutex::new(None),
        });
        (inner, recv_rx)
    }

    /// Create a **client** connection by dialing a UDP address.
    pub async fn dial(addr: &str, config: Config) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let remote: SocketAddr = addr.parse()?;
        socket.connect(remote).await?;
        let socket = Arc::new(socket);

        let conn_id = ConnectionId::generate();
        let (inner, recv_rx) = Self::new_inner(
            Arc::clone(&socket), remote, conn_id, config, false,
        );

        let conn = Self {
            inner:   Arc::clone(&inner),
            recv_rx: Arc::new(tokio::sync::Mutex::new(recv_rx)),
        };

        // Spawn read loop
        tokio::spawn(client_read_loop(Arc::clone(&inner)));
        // Spawn retransmit loop
        tokio::spawn(retransmit_loop(Arc::clone(&inner)));

        debug!(
            component = "transport",
            conn_id = %conn_id,
            remote  = %remote,
            "dialed connection"
        );

        Ok(conn)
    }

    /// Create a **server** connection from an already-listening socket.
    /// Used by `Listener` when a new peer is seen.
    pub(crate) fn new_server(
        socket:  Arc<UdpSocket>,
        remote:  SocketAddr,
        conn_id: ConnectionId,
        config:  Config,
    ) -> (Self, mpsc::Sender<Packet>) {
        let (inner, recv_rx) = Self::new_inner(socket, remote, conn_id, config, true);

        // Return a Sender so the Listener can push received packets in.
        let push_tx = inner.recv_tx.clone();

        tokio::spawn(retransmit_loop(Arc::clone(&inner)));

        let conn = Self {
            inner:   Arc::clone(&inner),
            recv_rx: Arc::new(tokio::sync::Mutex::new(recv_rx)),
        };
        (conn, push_tx)
    }

    // ── Public API ─────────────────────────────────────────────────────────

    pub fn conn_id(&self) -> ConnectionId { self.inner.conn_id }

    pub fn remote_addr(&self) -> SocketAddr { self.inner.remote }

    /// Send a raw packet (used during the Noise handshake).
    pub async fn send_raw(&self, mut pkt: Packet) -> anyhow::Result<()> {
        if pkt.seq_num == 0 {
            pkt.seq_num = self.inner.next_seq.fetch_add(1, Ordering::Relaxed);
        }
        pkt.timestamp  = now_micros();
        pkt.conn_id    = self.inner.conn_id;
        let data = pkt.marshal()?;
        self.write_udp(&data).await
    }

    /// Send encrypted application data.
    pub async fn send(&self, payload: Vec<u8>) -> anyhow::Result<()> {
        let seq = self.inner.next_seq.fetch_add(1, Ordering::Relaxed);
        let pkt = Packet {
            conn_id:   self.inner.conn_id,
            pkt_type:  PacketType::Data,
            flags:     Default::default(),
            seq_num:   seq,
            timestamp: now_micros(),
            payload:   payload.clone(),
        };
        let data = pkt.marshal()?;

        // Track for retransmission
        self.inner.sent.lock().unwrap().insert(seq, SentPacket {
            data:    data.clone(),
            sent_at: Instant::now(),
            acked:   false,
        });

        self.inner.bbr.lock().unwrap().on_send(data.len());
        self.write_udp(&data).await
    }

    /// Receive the next incoming packet (blocks until one arrives or closed).
    pub async fn recv(&self) -> Option<Packet> {
        self.recv_rx.lock().await.recv().await
    }

    /// Register a callback to be invoked when this connection closes.
    pub fn set_close_handler(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.inner.on_close.lock().unwrap() = Some(Box::new(f));
    }

    /// Gracefully close the connection (sends a Close packet).
    pub async fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return; // already closed
        }
        debug!(component = "transport", conn_id = %self.inner.conn_id, "closing connection");

        let close_pkt = Packet::new(PacketType::Close, self.inner.conn_id, vec![]);
        if let Ok(data) = close_pkt.marshal() {
            let _ = self.write_udp(&data).await;
        }

        self.inner.close_notify.notify_waiters();

        if let Some(cb) = self.inner.on_close.lock().unwrap().take() {
            cb();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Relaxed)
    }

    // ── Internal ───────────────────────────────────────────────────────────

    async fn write_udp(&self, data: &[u8]) -> anyhow::Result<()> {
        if self.inner.is_server {
            // Server sockets are unconnected; must use send_to.
            self.inner.socket.send_to(data, self.inner.remote).await?;
        } else {
            self.inner.socket.send(data).await?;
        }
        Ok(())
    }

    /// Dispatch an incoming packet — called by the listener/read loop.
    pub(crate) fn handle_packet(&self, pkt: Packet) {
        match pkt.pkt_type {
            PacketType::Ack  => self.handle_ack(&pkt),
            PacketType::Nack => self.handle_nack(&pkt),
            PacketType::Ping => {
                let conn = self.clone();
                tokio::spawn(async move {
                    let _ = conn.send_pong().await;
                });
            }
            PacketType::Pong => {}
            PacketType::Close => {
                let conn = self.clone();
                tokio::spawn(async move { conn.close().await });
            }
            PacketType::Handshake | PacketType::Data => {
                if pkt.pkt_type == PacketType::Data {
                    self.send_ack_fire_and_forget(pkt.seq_num);
                }
                let _ = self.inner.recv_tx.try_send(pkt);
            }
            _ => {}
        }
    }

    fn handle_ack(&self, pkt: &Packet) {
        use bolt_proto::frame::AckFrame;
        if let Ok(ack) = AckFrame::unmarshal(&pkt.payload) {
            let now = Instant::now();
            let mut sent = self.inner.sent.lock().unwrap();
            if let Some(sp) = sent.get_mut(&ack.largest_acked) {
                if !sp.acked {
                    sp.acked = true;
                    let rtt = now.saturating_duration_since(sp.sent_at);
                    let mut rtt_state = self.inner.rtt_mu.lock().unwrap();
                    update_rtt(&mut rtt_state, rtt);
                    let mut bbr = self.inner.bbr.lock().unwrap();
                    let data_len = sp.data.len() as u64;
                    bbr.on_ack(data_len, rtt);
                }
            }
            // Clean up old acked packets
            sent.retain(|_, v| !v.acked);
        }
    }

    fn handle_nack(&self, _pkt: &Packet) {
        // Trigger immediate retransmit for indicated seq (simplified)
    }

    fn send_ack_fire_and_forget(&self, seq: u64) {
        use bolt_proto::frame::AckFrame;
        let ack = AckFrame { largest_acked: seq, ack_delay: 0, ranges: vec![] };
        let payload = ack.marshal();
        let pkt = Packet {
            conn_id:   self.inner.conn_id,
            pkt_type:  PacketType::Ack,
            flags:     Default::default(),
            seq_num:   self.inner.next_seq.fetch_add(1, Ordering::Relaxed),
            timestamp: now_micros(),
            payload,
        };
        if let Ok(data) = pkt.marshal() {
            let conn = self.clone();
            tokio::spawn(async move {
                let _ = conn.write_udp(&data).await;
            });
        }
    }

    async fn send_pong(&self) -> anyhow::Result<()> {
        let pkt = Packet::new(PacketType::Pong, self.inner.conn_id, vec![]);
        let data = pkt.marshal()?;
        self.write_udp(&data).await
    }
}

// ── RTT update (Jacobson/Karels) ───────────────────────────────────────────

fn update_rtt(state: &mut RttState, sample: Duration) {
    let err = if sample > state.srtt {
        sample - state.srtt
    } else {
        state.srtt - sample
    };
    state.rttvar = (state.rttvar * 3 + err) / 4;
    state.srtt   = (state.srtt * 7 + sample) / 8;
    state.rto    = (state.srtt + state.rttvar * 4).max(Duration::from_millis(200));
}

// ── Background loops ───────────────────────────────────────────────────────

/// Client-side receive loop (server side is driven by Listener).
async fn client_read_loop(inner: Arc<Inner>) {
    let mut buf = vec![0u8; 65536];
    loop {
        if inner.closed.load(Ordering::Relaxed) { break; }
        match time::timeout(Duration::from_secs(1), inner.socket.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if let Ok(pkt) = Packet::unmarshal(&buf[..n]) {
                    route_packet(&inner, pkt);
                }
            }
            Ok(Err(e)) => {
                if inner.closed.load(Ordering::Relaxed) { break; }
                error!(component = "transport", "recv error: {e}");
            }
            Err(_) => {} // timeout — check closed flag
        }
    }
}

fn route_packet(inner: &Arc<Inner>, pkt: Packet) {
    match pkt.pkt_type {
        PacketType::Ack  => handle_ack_inner(inner, &pkt),
        PacketType::Ping => {
            let inner2 = Arc::clone(inner);
            tokio::spawn(async move {
                let pong = Packet::new(PacketType::Pong, inner2.conn_id, vec![]);
                if let Ok(data) = pong.marshal() {
                    let _ = inner2.socket.send(&data).await;
                }
            });
        }
        PacketType::Close => {
            inner.closed.store(true, Ordering::SeqCst);
            inner.close_notify.notify_waiters();
            if let Some(cb) = inner.on_close.lock().unwrap().take() { cb(); }
        }
        PacketType::Handshake | PacketType::Data => {
            if pkt.pkt_type == PacketType::Data {
                send_ack_inner(inner, pkt.seq_num);
            }
            let _ = inner.recv_tx.try_send(pkt);
        }
        _ => {}
    }
}

fn handle_ack_inner(inner: &Arc<Inner>, pkt: &Packet) {
    use bolt_proto::frame::AckFrame;
    if let Ok(ack) = AckFrame::unmarshal(&pkt.payload) {
        let now = Instant::now();
        let mut sent = inner.sent.lock().unwrap();
        if let Some(sp) = sent.get_mut(&ack.largest_acked) {
            if !sp.acked {
                sp.acked = true;
                let rtt = now.saturating_duration_since(sp.sent_at);
                let mut rtt_state = inner.rtt_mu.lock().unwrap();
                update_rtt(&mut rtt_state, rtt);
                let mut bbr = inner.bbr.lock().unwrap();
                bbr.on_ack(sp.data.len() as u64, rtt);
            }
        }
        sent.retain(|_, v| !v.acked);
    }
}

fn send_ack_inner(inner: &Arc<Inner>, seq: u64) {
    use bolt_proto::frame::AckFrame;
    let ack = AckFrame { largest_acked: seq, ack_delay: 0, ranges: vec![] };
    let payload = ack.marshal();
    let pkt = Packet {
        conn_id:   inner.conn_id,
        pkt_type:  PacketType::Ack,
        flags:     Default::default(),
        seq_num:   inner.next_seq.fetch_add(1, Ordering::Relaxed),
        timestamp: now_micros(),
        payload,
    };
    if let Ok(data) = pkt.marshal() {
        let inner2 = Arc::clone(inner);
        tokio::spawn(async move {
            let _ = inner2.socket.send(&data).await;
        });
    }
}

async fn retransmit_loop(inner: Arc<Inner>) {
    let mut interval = time::interval(Duration::from_millis(50));
    loop {
        interval.tick().await;
        if inner.closed.load(Ordering::Relaxed) { break; }

        let rto = inner.rtt_mu.lock().unwrap().rto;
        let now = Instant::now();

        let to_retransmit: Vec<Vec<u8>> = {
            let sent = inner.sent.lock().unwrap();
            sent.values()
                .filter(|sp| !sp.acked && now.saturating_duration_since(sp.sent_at) > rto)
                .map(|sp| sp.data.clone())
                .collect()
        };

        for data in to_retransmit {
            if inner.is_server {
                let _ = inner.socket.send_to(&data, inner.remote).await;
            } else {
                let _ = inner.socket.send(&data).await;
            }
        }
    }
}
