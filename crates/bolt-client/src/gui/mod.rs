//! GUI streaming client: UDP video receive + minifb window rendering.

mod bitmap_text;
mod render;

use std::{net::SocketAddr, sync::{Arc, Mutex}};

use anyhow::{anyhow, Context as _};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use bolt_proto::{
    decode_udp_packet, encode_udp_packet, UdpGuiPacket,
    MAX_UDP_PACKET_SIZE,
};

pub use render::RenderState;

// ── Public API ────────────────────────────────────────────────────────────────

pub struct GuiClientConfig {
    pub listen_addr: String,
    pub server_addr: String,
    pub token: String,
}

pub async fn run_gui_client(cfg: GuiClientConfig) -> anyhow::Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(&cfg.listen_addr)
            .await
            .with_context(|| format!("bind UDP {}", cfg.listen_addr))?,
    );
    let server: SocketAddr = cfg
        .server_addr
        .parse()
        .with_context(|| format!("parse server addr: {}", cfg.server_addr))?;

    info!(
        listen = %cfg.listen_addr,
        server = %cfg.server_addr,
        "GUI UDP client started"
    );

    let hello = encode_udp_packet(&UdpGuiPacket::Hello {
        token: cfg.token.clone(),
    })?;
    socket
        .send_to(&hello, server)
        .await
        .context("send GUI hello")?;

    let state = Arc::new(Mutex::new(RenderState::new()));

    let recv_socket = Arc::clone(&socket);
    let recv_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(e) = receive_udp_loop(recv_socket, recv_state).await {
            warn!(error = %e, "GUI UDP receive loop stopped");
        }
    });

    render::run_window_loop(state, Arc::clone(&socket), server, cfg.token)?;
    Ok(())
}

// ── UDP receive loop ──────────────────────────────────────────────────────────

async fn receive_udp_loop(
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<RenderState>>,
) -> anyhow::Result<()> {
    let mut buf = vec![0_u8; MAX_UDP_PACKET_SIZE];
    loop {
        let (n, _peer) = socket
            .recv_from(&mut buf)
            .await
            .context("recv video packet")?;
        let mut guard = state.lock().map_err(|_| anyhow!("render state poisoned"))?;
        match decode_udp_packet(&buf[..n])? {
            UdpGuiPacket::VideoChunk(chunk) => {
                if let Some(decoded) = guard.on_chunk(chunk)? {
                    guard.render_patch(decoded)?;
                }
            }
            UdpGuiPacket::DesktopInventoryChunk(chunk) => {
                guard.on_inventory_chunk(chunk)?;
            }
            UdpGuiPacket::Hello { .. }
            | UdpGuiPacket::AttachWindow { .. }
            | UdpGuiPacket::DetachWindow
            | UdpGuiPacket::InputEvent(_) => {}
        }
    }
}
