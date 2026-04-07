//! GUI streaming server: UDP video+input forwarding with desktop window inventory.

mod demo;
mod encode;
#[cfg(target_os = "linux")]
pub(super) mod linux;
#[cfg(target_os = "macos")]
pub(super) mod macos;

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context as _;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use bolt_proto::{
    decode_udp_packet, encode_udp_packet, DesktopWindow, InputEvent, UdpGuiPacket,
    MAX_UDP_PACKET_SIZE,
};

// ── Shared constants ──────────────────────────────────────────────────────────

/// RGB bytes per pixel — shared with platform capture backends and encoder.
pub(super) const CHANNELS_RGB: usize = 3;

const INVENTORY_SEND_INTERVAL: Duration = Duration::from_millis(500);

// ── Public API ────────────────────────────────────────────────────────────────

pub struct GuiServerConfig {
    pub listen_addr: String,
    pub client_addr: Option<String>,
    pub fps: u32,
    pub source: String,
}

// ── Internal shared types ─────────────────────────────────────────────────────

#[derive(Clone)]
pub(super) struct CapturedFrame {
    pub(super) width: u32,
    pub(super) height: u32,
    pub(super) rgb: Vec<u8>,
}

pub(super) trait Capturer {
    fn capture<'a>(
        &'a mut self,
        frame_id: u64,
        attached_window_id: Option<u64>,
        claim_token: Option<&'a str>,
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = anyhow::Result<Option<CapturedFrame>>> + Send + 'a>,
    >;
}

#[derive(Clone)]
struct ActiveGuiClient {
    peer: SocketAddr,
    token: String,
    attached_window_id: Option<u64>,
}

#[derive(Clone, Default)]
struct DesktopSnapshot {
    generation: u64,
    windows: Vec<DesktopWindow>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run_gui_server(cfg: GuiServerConfig) -> anyhow::Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(&cfg.listen_addr)
            .await
            .with_context(|| format!("bind UDP {}", cfg.listen_addr))?,
    );
    let desktop = Arc::new(Mutex::new(DesktopSnapshot::default()));
    start_desktop_agent(&cfg.source, Arc::clone(&desktop));
    let target = Arc::new(tokio::sync::RwLock::new(None::<ActiveGuiClient>));
    if let Some(addr) = cfg.client_addr.as_deref() {
        let parsed: SocketAddr = addr
            .parse()
            .with_context(|| format!("parse client addr: {addr}"))?;
        *target.write().await = Some(ActiveGuiClient {
            peer: parsed,
            token: String::new(),
            attached_window_id: None,
        });
    }

    info!(
        listen = %cfg.listen_addr,
        client = ?cfg.client_addr,
        fps = cfg.fps,
        source = %cfg.source,
        "GUI UDP server started"
    );

    let recv_socket = Arc::clone(&socket);
    let recv_target = Arc::clone(&target);
    tokio::spawn(async move {
        if let Err(e) = input_receive_loop(recv_socket, recv_target).await {
            warn!(error = %e, "input receive loop stopped");
        }
    });

    let frame_time = Duration::from_millis((1000_u64).saturating_div(cfg.fps.max(1) as u64).max(1));
    let mut interval = tokio::time::interval(frame_time);
    let mut frame_id: u64 = 0;
    let mut patch_id: u32 = 0;

    let mut capturer = build_capturer(&cfg.source);
    let mut prev_frame: Option<CapturedFrame> = None;
    let mut capture_fail_streak: u32 = 0;
    let mut last_capture_warn = Instant::now() - Duration::from_secs(10);
    let mut last_inventory_sent_at = Instant::now() - INVENTORY_SEND_INTERVAL;
    let mut last_inventory_generation = 0_u64;
    let mut last_inventory_peer = None::<SocketAddr>;
    let mut last_inventory_attached = None::<u64>;

    loop {
        interval.tick().await;
        frame_id = frame_id.wrapping_add(1);

        let active = target.read().await.clone();
        let mut attached_window_id = active.as_ref().and_then(|client| client.attached_window_id);
        let claim_token = active
            .as_ref()
            .and_then(|client| (!client.token.is_empty()).then_some(client.token.as_str()));

        let snapshot = desktop
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        if let Some(client) = active.as_ref() {
            let needs_inventory = last_inventory_sent_at.elapsed() >= INVENTORY_SEND_INTERVAL
                || snapshot.generation != last_inventory_generation
                || Some(client.peer) != last_inventory_peer
                || client.attached_window_id != last_inventory_attached;
            if needs_inventory {
                let normalized_attached = client.attached_window_id.filter(|window_id| {
                    snapshot
                        .windows
                        .iter()
                        .any(|window| window.window_id == *window_id)
                });
                if normalized_attached != client.attached_window_id {
                    let mut guard = target.write().await;
                    if let Some(client_state) = guard.as_mut() {
                        client_state.attached_window_id = normalized_attached;
                    }
                }
                attached_window_id = normalized_attached;
                send_inventory(
                    &socket,
                    client.peer,
                    snapshot.generation,
                    normalized_attached,
                    &snapshot.windows,
                )
                .await;
                last_inventory_sent_at = Instant::now();
                last_inventory_generation = snapshot.generation;
                last_inventory_peer = Some(client.peer);
                last_inventory_attached = normalized_attached;
            }
        }

        let captured = match capturer
            .capture(frame_id, attached_window_id, claim_token)
            .await
        {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                prev_frame = None;
                capture_fail_streak = 0;
                continue;
            }
            Err(e) => {
                capture_fail_streak = capture_fail_streak.saturating_add(1);
                if last_capture_warn.elapsed() >= Duration::from_secs(1) {
                    warn!(error = %e, streak = capture_fail_streak, "capture failed");
                    last_capture_warn = Instant::now();
                }
                if matches!(cfg.source.as_str(), "screen" | "window") && capture_fail_streak >= 20 {
                    warn!("window capture keeps failing; fallback to demo source");
                    capturer = Box::new(demo::DemoCapturer::new(1280, 720));
                    capture_fail_streak = 0;
                    prev_frame = None;
                }
                continue;
            }
        };
        capture_fail_streak = 0;

        let dirty = match encode::detect_dirty_rect(prev_frame.as_ref(), &captured) {
            Some(r) => r,
            None => {
                prev_frame = Some(captured);
                continue;
            }
        };

        let rgb_patch = encode::extract_rgb_patch(&captured, dirty)?;
        let compressed =
            zstd::stream::encode_all(rgb_patch.as_slice(), 3).context("zstd encode")?;

        let chunks = encode::build_chunks(
            frame_id,
            patch_id,
            dirty,
            captured.width,
            captured.height,
            &compressed,
        )?;
        patch_id = patch_id.wrapping_add(1);

        for pkt in chunks {
            let wire = encode_udp_packet(&UdpGuiPacket::VideoChunk(pkt))?;
            let client = { target.read().await.clone() };
            let Some(client) = client else {
                continue;
            };
            if let Err(e) = socket.send_to(&wire, client.peer).await {
                warn!(error = %e, client = %client.peer, "send video UDP packet failed");
            }
        }

        prev_frame = Some(captured);
    }
}

// ── Platform dispatch ─────────────────────────────────────────────────────────

fn build_capturer(source: &str) -> Box<dyn Capturer + Send> {
    match source {
        "window" | "screen" => {
            #[cfg(target_os = "macos")]
            {
                Box::new(macos::MacWindowCapturer)
            }
            #[cfg(target_os = "linux")]
            {
                match linux::LinuxX11Capturer::new() {
                    Ok(capturer) => Box::new(capturer),
                    Err(e) => {
                        warn!(error = %e, "failed to initialize X11 capturer, falling back to demo");
                        Box::new(demo::DemoCapturer::new(1280, 720))
                    }
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                warn!("window source requires macOS or Linux/X11; falling back to demo");
                Box::new(demo::DemoCapturer::new(1280, 720))
            }
        }
        "demo" => Box::new(demo::DemoCapturer::new(1280, 720)),
        other => {
            warn!(source = other, "unknown source, falling back to demo");
            Box::new(demo::DemoCapturer::new(1280, 720))
        }
    }
}

fn start_desktop_agent(source: &str, desktop: Arc<Mutex<DesktopSnapshot>>) {
    #[cfg(target_os = "linux")]
    if matches!(source, "window" | "screen") {
        std::thread::spawn(move || {
            let mut agent = match linux::LinuxDesktopAgent::new() {
                Ok(agent) => agent,
                Err(e) => {
                    warn!(error = %e, "desktop agent disabled");
                    return;
                }
            };
            loop {
                match agent.poll() {
                    Ok(windows) => {
                        if let Ok(mut guard) = desktop.lock() {
                            if guard.windows != windows {
                                guard.generation = guard.generation.wrapping_add(1);
                                guard.windows = windows;
                            }
                        }
                    }
                    Err(e) => warn!(error = %e, "desktop agent poll failed"),
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        });
        return;
    }

    let _ = (source, desktop);
}

// ── Input receive loop ────────────────────────────────────────────────────────

async fn input_receive_loop(
    socket: Arc<UdpSocket>,
    target: Arc<tokio::sync::RwLock<Option<ActiveGuiClient>>>,
) -> anyhow::Result<()> {
    let mut buf = vec![0_u8; MAX_UDP_PACKET_SIZE];
    loop {
        let (n, peer) = socket
            .recv_from(&mut buf)
            .await
            .context("recv input packet")?;
        let packet = match decode_udp_packet(&buf[..n]) {
            Ok(pkt) => pkt,
            Err(e) => {
                warn!(error = %e, "drop malformed input packet");
                continue;
            }
        };
        match packet {
            UdpGuiPacket::Hello { token } => {
                *target.write().await = Some(ActiveGuiClient {
                    peer,
                    token,
                    attached_window_id: None,
                });
                debug!(peer = %peer, "GUI client registered");
            }
            UdpGuiPacket::AttachWindow { window_id } => {
                let mut guard = target.write().await;
                if let Some(client) = guard.as_mut() {
                    client.attached_window_id = Some(window_id);
                    info!(peer = %client.peer, window_id, "GUI attach window");
                }
            }
            UdpGuiPacket::DetachWindow => {
                let mut guard = target.write().await;
                if let Some(client) = guard.as_mut() {
                    client.attached_window_id = None;
                    info!(peer = %client.peer, "GUI detach window");
                }
            }
            UdpGuiPacket::InputEvent(ev) => {
                let attached_window_id = target
                    .read()
                    .await
                    .as_ref()
                    .and_then(|client| client.attached_window_id);
                inject_input(attached_window_id, ev);
            }
            UdpGuiPacket::VideoChunk(_) | UdpGuiPacket::DesktopInventoryChunk(_) => {}
        }
    }
}

fn inject_input(attached_window_id: Option<u64>, event: InputEvent) {
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = linux::inject_input_linux(attached_window_id, &event) {
            warn!(error = %e, "inject input failed");
        }
        return;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = attached_window_id;
        match event {
            InputEvent::Key { code, down } => {
                info!(code, down, "inject key");
            }
            InputEvent::MouseMove { x, y } => {
                info!(x, y, "inject mouse move");
            }
            InputEvent::MouseButton { button, down } => {
                info!(?button, down, "inject mouse button");
            }
            InputEvent::MouseWheel { dx, dy } => {
                info!(dx, dy, "inject mouse wheel");
            }
        }
    }
}

// ── Inventory helpers ─────────────────────────────────────────────────────────

async fn send_inventory(
    socket: &Arc<UdpSocket>,
    peer: SocketAddr,
    generation: u64,
    attached_window_id: Option<u64>,
    windows: &[DesktopWindow],
) {
    let packets = match encode::build_inventory_packets(generation, attached_window_id, windows) {
        Ok(packets) => packets,
        Err(e) => {
            warn!(error = %e, "build inventory packets failed");
            return;
        }
    };
    for packet in packets {
        let wire = match encode_udp_packet(&packet) {
            Ok(wire) => wire,
            Err(e) => {
                warn!(error = %e, "encode inventory packet failed");
                continue;
            }
        };
        if let Err(e) = socket.send_to(&wire, peer).await {
            warn!(error = %e, client = %peer, "send inventory packet failed");
        }
    }
}
