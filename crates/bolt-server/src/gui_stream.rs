use std::{
    ffi::c_void,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::os::raw::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong};

use anyhow::{anyhow, Context as _};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use bolt_proto::{
    decode_udp_packet, encode_udp_packet, DesktopInventoryChunk, DesktopWindow, InputEvent, Rect,
    UdpGuiPacket, VideoChunk, VideoCodec, MAX_UDP_PACKET_SIZE,
};

const UDP_SEND_PAYLOAD_BUDGET: usize = 900;
const CHANNELS_RGB: usize = 3;
const GUI_CLAIM_DIR: &str = "/tmp/bolt-gui-claims";
const INVENTORY_SEND_INTERVAL: Duration = Duration::from_millis(500);

pub struct GuiServerConfig {
    pub listen_addr: String,
    pub client_addr: Option<String>,
    pub fps: u32,
    pub source: String,
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
                    capturer = Box::new(DemoCapturer::new(1280, 720));
                    capture_fail_streak = 0;
                    prev_frame = None;
                }
                continue;
            }
        };
        capture_fail_streak = 0;

        let dirty = match detect_dirty_rect(prev_frame.as_ref(), &captured) {
            Some(r) => r,
            None => {
                prev_frame = Some(captured);
                continue;
            }
        };

        let rgb_patch = extract_rgb_patch(&captured, dirty)?;
        let compressed =
            zstd::stream::encode_all(rgb_patch.as_slice(), 3).context("zstd encode")?;

        let chunks = build_chunks(
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

fn build_capturer(source: &str) -> Box<dyn Capturer + Send> {
    match source {
        "window" | "screen" => {
            #[cfg(target_os = "macos")]
            {
                Box::new(MacWindowCapturer)
            }
            #[cfg(target_os = "linux")]
            {
                match LinuxX11Capturer::new() {
                    Ok(capturer) => Box::new(capturer),
                    Err(e) => {
                        warn!(error = %e, "failed to initialize X11 window capturer, fallback to demo");
                        Box::new(DemoCapturer::new(1280, 720))
                    }
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                warn!("window source is only implemented on macOS and Linux/X11 in this build, fallback to demo");
                Box::new(DemoCapturer::new(1280, 720))
            }
        }
        "demo" => Box::new(DemoCapturer::new(1280, 720)),
        other => {
            warn!(source = other, "unknown source, fallback to demo");
            Box::new(DemoCapturer::new(1280, 720))
        }
    }
}

fn start_desktop_agent(source: &str, desktop: Arc<Mutex<DesktopSnapshot>>) {
    #[cfg(target_os = "linux")]
    if matches!(source, "window" | "screen") {
        std::thread::spawn(move || {
            let mut agent = match LinuxDesktopAgent::new() {
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

async fn send_inventory(
    socket: &Arc<UdpSocket>,
    peer: SocketAddr,
    generation: u64,
    attached_window_id: Option<u64>,
    windows: &[DesktopWindow],
) {
    let packets = match build_inventory_packets(generation, attached_window_id, windows) {
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

fn build_inventory_packets(
    generation: u64,
    attached_window_id: Option<u64>,
    windows: &[DesktopWindow],
) -> anyhow::Result<Vec<UdpGuiPacket>> {
    let normalized_windows: Vec<DesktopWindow> =
        windows.iter().cloned().map(trim_desktop_window).collect();
    if normalized_windows.is_empty() {
        return Ok(vec![UdpGuiPacket::DesktopInventoryChunk(
            DesktopInventoryChunk {
                generation,
                chunk_index: 0,
                chunk_total: 1,
                attached_window_id,
                windows: Vec::new(),
            },
        )]);
    }

    let mut chunks = Vec::<Vec<DesktopWindow>>::new();
    let mut cursor = 0;
    while cursor < normalized_windows.len() {
        let mut entries = Vec::new();
        while cursor < normalized_windows.len() {
            entries.push(normalized_windows[cursor].clone());
            let candidate = UdpGuiPacket::DesktopInventoryChunk(DesktopInventoryChunk {
                generation,
                chunk_index: 0,
                chunk_total: 1,
                attached_window_id,
                windows: entries.clone(),
            });
            if encode_udp_packet(&candidate).is_err() {
                if entries.len() == 1 {
                    anyhow::bail!("desktop inventory entry is too large for UDP packet");
                }
                entries.pop();
                break;
            }
            cursor += 1;
        }
        if entries.is_empty() {
            anyhow::bail!("desktop inventory chunking made no progress");
        }
        chunks.push(entries);
    }

    let total = u16::try_from(chunks.len()).context("too many inventory chunks")?;
    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(idx, windows)| {
            UdpGuiPacket::DesktopInventoryChunk(DesktopInventoryChunk {
                generation,
                chunk_index: idx as u16,
                chunk_total: total,
                attached_window_id,
                windows,
            })
        })
        .collect())
}

fn trim_desktop_window(mut window: DesktopWindow) -> DesktopWindow {
    fn trim(text: &str, limit: usize) -> String {
        text.chars().take(limit).collect()
    }
    window.process_name = trim(&window.process_name, 48);
    window.title = trim(&window.title, 96);
    window
}

async fn input_receive_loop(
    socket: Arc<UdpSocket>,
    target: Arc<tokio::sync::RwLock<Option<ActiveGuiClient>>>,
) -> anyhow::Result<()> {
    let mut buf = vec![0_u8; MAX_UDP_PACKET_SIZE];
    loop {
        let (n, _peer) = socket
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
                    peer: _peer,
                    token,
                    attached_window_id: None,
                });
                debug!(peer = %_peer, "GUI client registered");
            }
            UdpGuiPacket::AttachWindow { window_id } => {
                let mut guard = target.write().await;
                if let Some(client) = guard.as_mut() {
                    client.attached_window_id = Some(window_id);
                }
            }
            UdpGuiPacket::DetachWindow => {
                let mut guard = target.write().await;
                if let Some(client) = guard.as_mut() {
                    client.attached_window_id = None;
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
        if let Err(e) = inject_input_linux(attached_window_id, &event) {
            warn!(error = %e, "inject input failed");
        }
        return;
    }

    #[cfg(not(target_os = "linux"))]
    let _ = attached_window_id;

    // Hook point: replace with XTest/uinput/win32 SendInput implementation.
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

fn build_chunks(
    frame_id: u64,
    patch_id: u32,
    rect: Rect,
    surface_width: u32,
    surface_height: u32,
    compressed: &[u8],
) -> anyhow::Result<Vec<VideoChunk>> {
    let total = compressed.len().div_ceil(UDP_SEND_PAYLOAD_BUDGET);
    if total > u16::MAX as usize {
        return Err(anyhow!("too many UDP chunks: {}", total));
    }

    let mut out = Vec::with_capacity(total);
    for (idx, part) in compressed.chunks(UDP_SEND_PAYLOAD_BUDGET).enumerate() {
        out.push(VideoChunk {
            frame_id,
            patch_id,
            chunk_index: idx as u16,
            chunk_total: total as u16,
            rect,
            surface_width,
            surface_height,
            codec: VideoCodec::RawRgb24Zstd,
            compressed_size: compressed.len() as u32,
            payload: part.to_vec(),
        });
    }
    Ok(out)
}

fn detect_dirty_rect(prev: Option<&CapturedFrame>, curr: &CapturedFrame) -> Option<Rect> {
    if prev.is_none() {
        return Some(Rect {
            x: 0,
            y: 0,
            w: curr.width,
            h: curr.height,
        });
    }

    let prev = prev.expect("checked");
    if prev.width != curr.width || prev.height != curr.height {
        return Some(Rect {
            x: 0,
            y: 0,
            w: curr.width,
            h: curr.height,
        });
    }

    let w = curr.width as usize;
    let h = curr.height as usize;
    let mut min_x = w;
    let mut min_y = h;
    let mut max_x = 0usize;
    let mut max_y = 0usize;
    let mut changed = false;

    for y in 0..h {
        for x in 0..w {
            let idx = (y * w + x) * CHANNELS_RGB;
            let a = &prev.rgb[idx..idx + CHANNELS_RGB];
            let b = &curr.rgb[idx..idx + CHANNELS_RGB];
            if a != b {
                changed = true;
                min_x = min_x.min(x);
                min_y = min_y.min(y);
                max_x = max_x.max(x);
                max_y = max_y.max(y);
            }
        }
    }

    if !changed {
        return None;
    }

    Some(Rect {
        x: min_x as u32,
        y: min_y as u32,
        w: (max_x - min_x + 1) as u32,
        h: (max_y - min_y + 1) as u32,
    })
}

fn extract_rgb_patch(frame: &CapturedFrame, rect: Rect) -> anyhow::Result<Vec<u8>> {
    let fw = frame.width as usize;
    let fh = frame.height as usize;
    if rect.x as usize >= fw || rect.y as usize >= fh {
        return Err(anyhow!("rect out of bounds"));
    }
    let rw = rect.w.min(frame.width - rect.x) as usize;
    let rh = rect.h.min(frame.height - rect.y) as usize;

    let mut out = vec![0_u8; rw * rh * CHANNELS_RGB];
    for row in 0..rh {
        let src_y = rect.y as usize + row;
        let src_off = (src_y * fw + rect.x as usize) * CHANNELS_RGB;
        let dst_off = row * rw * CHANNELS_RGB;
        let len = rw * CHANNELS_RGB;
        out[dst_off..dst_off + len].copy_from_slice(&frame.rgb[src_off..src_off + len]);
    }
    Ok(out)
}

#[derive(Clone)]
struct CapturedFrame {
    width: u32,
    height: u32,
    rgb: Vec<u8>,
}

trait Capturer {
    fn capture<'a>(
        &'a mut self,
        frame_id: u64,
        attached_window_id: Option<u64>,
        claim_token: Option<&'a str>,
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = anyhow::Result<Option<CapturedFrame>>> + Send + 'a>,
    >;
}

struct DemoCapturer {
    width: u32,
    height: u32,
}

impl DemoCapturer {
    fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }
}

impl Capturer for DemoCapturer {
    fn capture<'a>(
        &'a mut self,
        frame_id: u64,
        _attached_window_id: Option<u64>,
        _claim_token: Option<&'a str>,
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = anyhow::Result<Option<CapturedFrame>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut rgb = vec![0_u8; self.width as usize * self.height as usize * CHANNELS_RGB];
            for y in 0..self.height {
                for x in 0..self.width {
                    let idx = ((y * self.width + x) as usize) * CHANNELS_RGB;
                    rgb[idx] = ((x + frame_id as u32) & 0xff) as u8;
                    rgb[idx + 1] = ((y + frame_id as u32 * 2) & 0xff) as u8;
                    rgb[idx + 2] = (((x ^ y) + frame_id as u32 * 3) & 0xff) as u8;
                }
            }
            debug!(
                frame_id,
                width = self.width,
                height = self.height,
                "captured demo frame"
            );
            Ok(Some(CapturedFrame {
                width: self.width,
                height: self.height,
                rgb,
            }))
        })
    }
}

#[derive(Clone, Debug)]
struct GuiClaim {
    owner_name: String,
    pid: Option<i64>,
}

fn read_gui_claim(token: &str) -> anyhow::Result<Option<GuiClaim>> {
    let path = std::path::Path::new(GUI_CLAIM_DIR).join(token);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read GUI claim {}", path.display())),
    };

    let mut owner_name = None;
    let mut pid = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "owner" => owner_name = Some(value.to_string()),
            "pid" => pid = value.parse::<i64>().ok(),
            _ => {}
        }
    }

    let Some(owner_name) = owner_name else {
        return Ok(None);
    };

    Ok(Some(GuiClaim { owner_name, pid }))
}

#[cfg(target_os = "linux")]
struct LinuxDesktopAgent {
    display: *mut XDisplay,
    atoms: LinuxAtoms,
    seen_pids: std::collections::HashSet<i64>,
    seen_windows: std::collections::HashSet<XWindow>,
}

#[cfg(target_os = "linux")]
unsafe impl Send for LinuxDesktopAgent {}

#[cfg(target_os = "linux")]
impl LinuxDesktopAgent {
    fn new() -> anyhow::Result<Self> {
        initialize_xlib();
        let display = unsafe { XOpenDisplay(std::ptr::null()) };
        if display.is_null() {
            anyhow::bail!(
                "XOpenDisplay failed; ensure boltd runs inside an X11 session with DISPLAY set"
            );
        }
        let atoms = LinuxAtoms::intern(display)?;
        Ok(Self {
            display,
            atoms,
            seen_pids: std::collections::HashSet::new(),
            seen_windows: std::collections::HashSet::new(),
        })
    }

    fn poll(&mut self) -> anyhow::Result<Vec<DesktopWindow>> {
        let windows = linux_client_windows(self.display, &self.atoms)?;
        let mut inventory = Vec::new();
        let mut current_windows = std::collections::HashSet::new();
        let mut current_pids = std::collections::HashSet::new();

        for window in windows {
            current_windows.insert(window);
            if let Some(entry) = linux_window_inventory_entry(self.display, &self.atoms, window)? {
                if let Some(pid) = entry.pid {
                    current_pids.insert(i64::from(pid));
                }
                inventory.push(entry);
            }
        }

        for pid in current_pids.difference(&self.seen_pids) {
            if let Some(name) = linux_process_name(*pid) {
                debug!(pid = *pid, process = %name, "desktop agent saw new process");
            }
        }
        for window in current_windows.difference(&self.seen_windows) {
            debug!(window_id = *window as u64, "desktop agent saw new window");
        }

        self.seen_pids = current_pids;
        self.seen_windows = current_windows;
        Ok(inventory)
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxDesktopAgent {
    fn drop(&mut self) {
        if !self.display.is_null() {
            unsafe {
                XCloseDisplay(self.display);
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct LinuxX11Capturer {
    display: *mut XDisplay,
}

#[cfg(target_os = "linux")]
unsafe impl Send for LinuxX11Capturer {}

#[cfg(target_os = "linux")]
impl LinuxX11Capturer {
    fn new() -> anyhow::Result<Self> {
        initialize_xlib();
        let display = unsafe { XOpenDisplay(std::ptr::null()) };
        if display.is_null() {
            anyhow::bail!(
                "XOpenDisplay failed; ensure boltd runs inside an X11 session with DISPLAY set"
            );
        }
        Ok(Self { display })
    }

    fn capture_selected_window(&mut self, window_id: u64) -> anyhow::Result<Option<CapturedFrame>> {
        let Some(target) = linux_window_geometry(self.display, window_id as XWindow)? else {
            return Ok(None);
        };
        capture_linux_window_image(self.display, &target).map(Some)
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxX11Capturer {
    fn drop(&mut self) {
        if !self.display.is_null() {
            unsafe {
                XCloseDisplay(self.display);
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Capturer for LinuxX11Capturer {
    fn capture<'a>(
        &'a mut self,
        _frame_id: u64,
        attached_window_id: Option<u64>,
        claim_token: Option<&'a str>,
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = anyhow::Result<Option<CapturedFrame>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let _ = claim_token;
            let Some(window_id) = attached_window_id else {
                return Ok(None);
            };
            self.capture_selected_window(window_id)
        })
    }
}

#[cfg(target_os = "linux")]
fn inject_input_linux(attached_window_id: Option<u64>, event: &InputEvent) -> anyhow::Result<()> {
    let Some(window_id) = attached_window_id else {
        return Ok(());
    };

    initialize_xlib();
    let display = unsafe { XOpenDisplay(std::ptr::null()) };
    if display.is_null() {
        anyhow::bail!("XOpenDisplay failed for input injection");
    }
    let target = linux_window_geometry(display, window_id as XWindow)?;
    let Some(target) = target else {
        unsafe {
            XCloseDisplay(display);
        }
        return Ok(());
    };

    let result = inject_linux_event(display, &target, event);
    unsafe {
        XCloseDisplay(display);
    }
    result
}

#[cfg(target_os = "linux")]
fn inject_linux_event(
    display: *mut XDisplay,
    target: &LinuxWindowTarget,
    event: &InputEvent,
) -> anyhow::Result<()> {
    unsafe {
        match *event {
            InputEvent::Key { code, down } => {
                if let Some(keysym) = minifb_key_to_x11_keysym(code) {
                    let keycode = XKeysymToKeycode(display, keysym);
                    if keycode == 0 {
                        return Ok(());
                    }
                    XSetInputFocus(display, target.window, REVERT_TO_POINTER_ROOT, CURRENT_TIME);
                    XRaiseWindow(display, target.window);
                    XTestFakeKeyEvent(display, keycode as u32, bool_to_x11(down), CURRENT_TIME);
                }
            }
            InputEvent::MouseMove { x, y } => {
                let local_x = x.clamp(0, target.width.saturating_sub(1) as i32);
                let local_y = y.clamp(0, target.height.saturating_sub(1) as i32);
                XTestFakeMotionEvent(
                    display,
                    -1,
                    target.root_x.saturating_add(local_x),
                    target.root_y.saturating_add(local_y),
                    CURRENT_TIME,
                );
            }
            InputEvent::MouseButton { button, down } => {
                let button_id = match button {
                    bolt_proto::MouseButton::Left => 1,
                    bolt_proto::MouseButton::Middle => 2,
                    bolt_proto::MouseButton::Right => 3,
                };
                XSetInputFocus(display, target.window, REVERT_TO_POINTER_ROOT, CURRENT_TIME);
                XRaiseWindow(display, target.window);
                XTestFakeButtonEvent(display, button_id, bool_to_x11(down), CURRENT_TIME);
            }
            InputEvent::MouseWheel { dx, dy } => {
                if dx > 0 {
                    for _ in 0..dx {
                        XTestFakeButtonEvent(display, 7, TRUE, CURRENT_TIME);
                        XTestFakeButtonEvent(display, 7, FALSE, CURRENT_TIME);
                    }
                } else {
                    for _ in 0..dx.unsigned_abs() {
                        XTestFakeButtonEvent(display, 6, TRUE, CURRENT_TIME);
                        XTestFakeButtonEvent(display, 6, FALSE, CURRENT_TIME);
                    }
                }
                if dy > 0 {
                    for _ in 0..dy {
                        XTestFakeButtonEvent(display, 4, TRUE, CURRENT_TIME);
                        XTestFakeButtonEvent(display, 4, FALSE, CURRENT_TIME);
                    }
                } else {
                    for _ in 0..dy.unsigned_abs() {
                        XTestFakeButtonEvent(display, 5, TRUE, CURRENT_TIME);
                        XTestFakeButtonEvent(display, 5, FALSE, CURRENT_TIME);
                    }
                }
            }
        }
        XFlush(display);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bool_to_x11(value: bool) -> i32 {
    if value {
        TRUE
    } else {
        FALSE
    }
}

#[cfg(target_os = "linux")]
fn linux_window_inventory_entry(
    display: *mut XDisplay,
    atoms: &LinuxAtoms,
    window: XWindow,
) -> anyhow::Result<Option<DesktopWindow>> {
    let Some(target) = linux_window_geometry(display, window)? else {
        return Ok(None);
    };
    if target.width < 64 || target.height < 64 {
        return Ok(None);
    }

    let pid = linux_window_pid(display, atoms, window)?;
    let class_name = linux_window_class(display, atoms, window)?;
    let title = linux_window_title(display, atoms, window)?;
    let process_name = pid
        .and_then(|pid| linux_process_name(pid))
        .or(class_name)
        .unwrap_or_else(|| "window".to_string());
    let title = title.unwrap_or_else(|| process_name.clone());

    if linux_should_exclude_inventory_window(&process_name, &title) {
        return Ok(None);
    }

    Ok(Some(DesktopWindow {
        window_id: window as u64,
        pid: pid.and_then(|pid| u32::try_from(pid).ok()),
        process_name,
        title,
        width: target.width,
        height: target.height,
    }))
}

#[cfg(target_os = "linux")]
fn linux_should_exclude_inventory_window(process_name: &str, title: &str) -> bool {
    let process = normalize_linux_name(process_name);
    let title = normalize_linux_name(title);
    matches!(process.as_str(), "bolt" | "boltd")
        || process.contains("gnome-shell")
        || process.contains("plasmashell")
        || process.contains("xfdesktop")
        || title.contains("bolt gui stream")
}

#[cfg(target_os = "linux")]
fn linux_client_windows(
    display: *mut XDisplay,
    atoms: &LinuxAtoms,
) -> anyhow::Result<Vec<XWindow>> {
    if let Some(root) = linux_root_window(display) {
        if let Some(mut windows) =
            linux_window_list_property(display, root, atoms.net_client_list_stacking)?
        {
            windows.retain(|window| *window != 0);
            if !windows.is_empty() {
                return Ok(windows);
            }
        }

        let mut root_return: XWindow = 0;
        let mut parent_return: XWindow = 0;
        let mut children: *mut XWindow = std::ptr::null_mut();
        let mut count: u32 = 0;
        let status = unsafe {
            XQueryTree(
                display,
                root,
                &mut root_return,
                &mut parent_return,
                &mut children,
                &mut count,
            )
        };
        if status == 0 {
            return Ok(Vec::new());
        }

        let windows = if children.is_null() || count == 0 {
            Vec::new()
        } else {
            let slice = unsafe { std::slice::from_raw_parts(children, count as usize) };
            slice.to_vec()
        };
        if !children.is_null() {
            unsafe {
                XFree(children.cast());
            }
        }
        return Ok(windows);
    }

    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
fn linux_root_window(display: *mut XDisplay) -> Option<XWindow> {
    unsafe {
        let screen = XDefaultScreen(display);
        if screen < 0 {
            return None;
        }
        let root = XRootWindow(display, screen);
        (root != 0).then_some(root)
    }
}

#[cfg(target_os = "linux")]
fn normalize_linux_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

#[cfg(target_os = "linux")]
fn linux_process_name(pid: i64) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

#[cfg(target_os = "linux")]
fn linux_window_geometry(
    display: *mut XDisplay,
    window: XWindow,
) -> anyhow::Result<Option<LinuxWindowTarget>> {
    let mut attrs = XWindowAttributes::default();
    let status = unsafe { XGetWindowAttributes(display, window, &mut attrs) };
    if status == 0 || attrs.map_state != IS_VIEWABLE {
        return Ok(None);
    }

    let Some(root) = linux_root_window(display) else {
        return Ok(None);
    };

    let mut root_x = 0;
    let mut root_y = 0;
    let mut child: XWindow = 0;
    unsafe {
        XTranslateCoordinates(
            display,
            window,
            root,
            0,
            0,
            &mut root_x,
            &mut root_y,
            &mut child,
        );
    }

    Ok(Some(LinuxWindowTarget {
        window,
        root_x,
        root_y,
        width: attrs.width.max(0) as u32,
        height: attrs.height.max(0) as u32,
    }))
}

#[cfg(target_os = "linux")]
fn linux_window_pid(
    display: *mut XDisplay,
    atoms: &LinuxAtoms,
    window: XWindow,
) -> anyhow::Result<Option<i64>> {
    let Some(prop) = linux_get_property(display, window, atoms.net_wm_pid)? else {
        return Ok(None);
    };
    let pid = if prop.format == 32 && !prop.ptr.is_null() && prop.items > 0 {
        let slice =
            unsafe { std::slice::from_raw_parts(prop.ptr as *const c_ulong, prop.items as usize) };
        slice.first().copied().map(|value| value as i64)
    } else {
        None
    };
    drop(prop);
    Ok(pid)
}

#[cfg(target_os = "linux")]
fn linux_window_class(
    display: *mut XDisplay,
    atoms: &LinuxAtoms,
    window: XWindow,
) -> anyhow::Result<Option<String>> {
    let Some(prop) = linux_get_property(display, window, atoms.wm_class)? else {
        return Ok(None);
    };
    let value = linux_property_string(&prop);
    drop(prop);
    Ok(value)
}

#[cfg(target_os = "linux")]
fn linux_window_title(
    display: *mut XDisplay,
    atoms: &LinuxAtoms,
    window: XWindow,
) -> anyhow::Result<Option<String>> {
    if let Some(prop) = linux_get_property(display, window, atoms.net_wm_name)? {
        let value = linux_property_string(&prop);
        drop(prop);
        if value.is_some() {
            return Ok(value);
        }
    }

    let mut raw_name: *mut c_char = std::ptr::null_mut();
    let ok = unsafe { XFetchName(display, window, &mut raw_name) };
    if ok == 0 || raw_name.is_null() {
        return Ok(None);
    }
    let name = unsafe { std::ffi::CStr::from_ptr(raw_name) }
        .to_string_lossy()
        .trim()
        .to_string();
    unsafe {
        XFree(raw_name.cast());
    }
    Ok((!name.is_empty()).then_some(name))
}

#[cfg(target_os = "linux")]
fn linux_property_string(prop: &LinuxProperty) -> Option<String> {
    if prop.ptr.is_null() || prop.items == 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(prop.ptr as *const u8, prop.items as usize) };
    let text = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .filter_map(|part| std::str::from_utf8(part).ok())
        .collect::<Vec<_>>()
        .join(" ");
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

#[cfg(target_os = "linux")]
fn linux_window_list_property(
    display: *mut XDisplay,
    window: XWindow,
    atom: XAtom,
) -> anyhow::Result<Option<Vec<XWindow>>> {
    let Some(prop) = linux_get_property(display, window, atom)? else {
        return Ok(None);
    };
    if prop.format != 32 || prop.ptr.is_null() || prop.items == 0 {
        return Ok(None);
    }
    let slice =
        unsafe { std::slice::from_raw_parts(prop.ptr as *const c_ulong, prop.items as usize) };
    let windows = slice
        .iter()
        .copied()
        .map(|value| value as XWindow)
        .collect();
    drop(prop);
    Ok(Some(windows))
}

#[cfg(target_os = "linux")]
fn linux_get_property(
    display: *mut XDisplay,
    window: XWindow,
    atom: XAtom,
) -> anyhow::Result<Option<LinuxProperty>> {
    let mut actual_type: XAtom = 0;
    let mut actual_format = 0;
    let mut items: c_ulong = 0;
    let mut bytes_after: c_ulong = 0;
    let mut ptr: *mut c_uchar = std::ptr::null_mut();
    let status = unsafe {
        XGetWindowProperty(
            display,
            window,
            atom,
            0,
            4096,
            FALSE,
            ANY_PROPERTY_TYPE,
            &mut actual_type,
            &mut actual_format,
            &mut items,
            &mut bytes_after,
            &mut ptr,
        )
    };
    if status != X_SUCCESS {
        if !ptr.is_null() {
            unsafe {
                XFree(ptr.cast());
            }
        }
        anyhow::bail!("XGetWindowProperty failed with status {status}");
    }
    if ptr.is_null() {
        return Ok(None);
    }
    Ok(Some(LinuxProperty {
        ptr,
        items,
        format: actual_format,
    }))
}

#[cfg(target_os = "linux")]
fn capture_linux_window_image(
    display: *mut XDisplay,
    target: &LinuxWindowTarget,
) -> anyhow::Result<CapturedFrame> {
    let image = unsafe {
        XGetImage(
            display,
            target.window,
            0,
            0,
            target.width,
            target.height,
            ALL_PLANES,
            Z_PIXMAP,
        )
    };
    if image.is_null() {
        anyhow::bail!("XGetImage returned null");
    }

    let frame = unsafe { decode_ximage(image) };
    unsafe {
        XDestroyImage(image);
    }
    frame
}

#[cfg(target_os = "linux")]
unsafe fn decode_ximage(image: *mut XImage) -> anyhow::Result<CapturedFrame> {
    let image = &*image;
    if image.data.is_null() || image.width <= 0 || image.height <= 0 {
        anyhow::bail!("XImage is empty");
    }

    let width = image.width as usize;
    let height = image.height as usize;
    let bits_per_pixel = image.bits_per_pixel.max(1) as usize;
    let bytes_per_pixel = bits_per_pixel.div_ceil(8).max(1);
    let bytes_per_line = image.bytes_per_line.max(0) as usize;
    let total = bytes_per_line
        .checked_mul(height)
        .ok_or_else(|| anyhow!("XImage stride overflow"))?;
    let bytes = std::slice::from_raw_parts(image.data as *const u8, total);

    let mut rgb = vec![0_u8; width * height * CHANNELS_RGB];
    for y in 0..height {
        let row = &bytes[y * bytes_per_line..(y + 1) * bytes_per_line];
        for x in 0..width {
            let src = x * bytes_per_pixel;
            if src + bytes_per_pixel > row.len() {
                anyhow::bail!("XImage row is truncated");
            }
            let pixel = read_x11_pixel(&row[src..src + bytes_per_pixel], image.byte_order);
            let dst = (y * width + x) * CHANNELS_RGB;
            rgb[dst] = x11_mask_component(pixel, image.red_mask);
            rgb[dst + 1] = x11_mask_component(pixel, image.green_mask);
            rgb[dst + 2] = x11_mask_component(pixel, image.blue_mask);
        }
    }

    Ok(CapturedFrame {
        width: width as u32,
        height: height as u32,
        rgb,
    })
}

#[cfg(target_os = "linux")]
fn read_x11_pixel(bytes: &[u8], byte_order: i32) -> u64 {
    let mut buf = [0_u8; 8];
    let len = bytes.len().min(buf.len());
    if byte_order == MSB_FIRST {
        buf[buf.len() - len..].copy_from_slice(&bytes[..len]);
        u64::from_be_bytes(buf)
    } else {
        buf[..len].copy_from_slice(&bytes[..len]);
        u64::from_le_bytes(buf)
    }
}

#[cfg(target_os = "linux")]
fn x11_mask_component(pixel: u64, mask: c_ulong) -> u8 {
    if mask == 0 {
        return 0;
    }
    let mask = mask as u64;
    let shift = mask.trailing_zeros();
    let max = mask >> shift;
    if max == 0 {
        return 0;
    }
    let value = (pixel & mask) >> shift;
    ((value * 255 + max / 2) / max) as u8
}

#[cfg(target_os = "linux")]
fn minifb_key_to_x11_keysym(code: u32) -> Option<c_ulong> {
    Some(match code {
        0..=9 => XK_0 + code as c_ulong,
        10..=35 => XK_a + (code as c_ulong - 10),
        36 => XK_F1,
        37 => XK_F2,
        38 => XK_F3,
        39 => XK_F4,
        40 => XK_F5,
        41 => XK_F6,
        42 => XK_F7,
        43 => XK_F8,
        44 => XK_F9,
        45 => XK_F10,
        46 => XK_F11,
        47 => XK_F12,
        51 => XK_Left,
        52 => XK_Right,
        53 => XK_Up,
        50 => XK_Down,
        54 => XK_apostrophe,
        55 => XK_grave,
        56 => XK_backslash,
        57 => XK_comma,
        58 => XK_equal,
        59 => XK_bracketleft,
        60 => XK_minus,
        61 => XK_period,
        62 => XK_bracketright,
        63 => XK_semicolon,
        64 => XK_slash,
        65 => XK_BackSpace,
        66 => XK_Delete,
        67 => XK_End,
        68 => XK_Return,
        69 => XK_Escape,
        70 => XK_Home,
        71 => XK_Insert,
        72 => XK_Menu,
        73 => XK_Page_Down,
        74 => XK_Page_Up,
        75 => XK_Pause,
        76 => XK_space,
        77 => XK_Tab,
        78 => XK_Num_Lock,
        79 => XK_Caps_Lock,
        80 => XK_Scroll_Lock,
        81 => XK_Shift_L,
        82 => XK_Shift_R,
        83 => XK_Control_L,
        84 => XK_Control_R,
        85 => XK_KP_0,
        86 => XK_KP_1,
        87 => XK_KP_2,
        88 => XK_KP_3,
        89 => XK_KP_4,
        90 => XK_KP_5,
        91 => XK_KP_6,
        92 => XK_KP_7,
        93 => XK_KP_8,
        94 => XK_KP_9,
        95 => XK_KP_Decimal,
        96 => XK_KP_Divide,
        97 => XK_KP_Multiply,
        98 => XK_KP_Subtract,
        99 => XK_KP_Add,
        100 => XK_KP_Enter,
        101 => XK_Alt_L,
        102 => XK_Alt_R,
        103 => XK_Super_L,
        104 => XK_Super_R,
        _ => return None,
    })
}

#[cfg(target_os = "linux")]
fn initialize_xlib() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        XInitThreads();
    });
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct LinuxWindowTarget {
    window: XWindow,
    root_x: i32,
    root_y: i32,
    width: u32,
    height: u32,
}

#[cfg(target_os = "linux")]
struct LinuxAtoms {
    net_client_list_stacking: XAtom,
    net_wm_pid: XAtom,
    wm_class: XAtom,
    net_wm_name: XAtom,
}

#[cfg(target_os = "linux")]
impl LinuxAtoms {
    fn intern(display: *mut XDisplay) -> anyhow::Result<Self> {
        Ok(Self {
            net_client_list_stacking: intern_x_atom(display, "_NET_CLIENT_LIST_STACKING")?,
            net_wm_pid: intern_x_atom(display, "_NET_WM_PID")?,
            wm_class: intern_x_atom(display, "WM_CLASS")?,
            net_wm_name: intern_x_atom(display, "_NET_WM_NAME")?,
        })
    }
}

#[cfg(target_os = "linux")]
fn intern_x_atom(display: *mut XDisplay, name: &str) -> anyhow::Result<XAtom> {
    let c_name = std::ffi::CString::new(name).context("atom name contains NUL")?;
    let atom = unsafe { XInternAtom(display, c_name.as_ptr(), FALSE) };
    if atom == 0 {
        anyhow::bail!("XInternAtom returned 0 for {name}");
    }
    Ok(atom)
}

#[cfg(target_os = "linux")]
struct LinuxProperty {
    ptr: *mut c_uchar,
    items: c_ulong,
    format: i32,
}

#[cfg(target_os = "linux")]
impl Drop for LinuxProperty {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                XFree(self.ptr.cast());
            }
        }
    }
}

#[cfg(target_os = "linux")]
type XWindow = c_ulong;
#[cfg(target_os = "linux")]
type XAtom = c_ulong;

#[cfg(target_os = "linux")]
enum XDisplay {}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default)]
struct XWindowAttributes {
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
    border_width: c_int,
    depth: c_int,
    visual: *mut c_void,
    root: XWindow,
    class: c_int,
    bit_gravity: c_int,
    win_gravity: c_int,
    backing_store: c_int,
    backing_planes: c_ulong,
    backing_pixel: c_ulong,
    save_under: c_int,
    colormap: c_ulong,
    map_installed: c_int,
    map_state: c_int,
    all_event_masks: c_long,
    your_event_mask: c_long,
    do_not_propagate_mask: c_long,
    override_redirect: c_int,
    screen: *mut c_void,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct XImageFuncs {
    create_image: *mut c_void,
    destroy_image: *mut c_void,
    get_pixel: *mut c_void,
    put_pixel: *mut c_void,
    sub_image: *mut c_void,
    add_pixel: *mut c_void,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct XImage {
    width: c_int,
    height: c_int,
    xoffset: c_int,
    format: c_int,
    data: *mut c_char,
    byte_order: c_int,
    bitmap_unit: c_int,
    bitmap_bit_order: c_int,
    bitmap_pad: c_int,
    depth: c_int,
    bytes_per_line: c_int,
    bits_per_pixel: c_int,
    red_mask: c_ulong,
    green_mask: c_ulong,
    blue_mask: c_ulong,
    obdata: *mut c_char,
    f: XImageFuncs,
}

#[cfg(target_os = "linux")]
const FALSE: c_int = 0;
#[cfg(target_os = "linux")]
const TRUE: c_int = 1;
#[cfg(target_os = "linux")]
const X_SUCCESS: c_int = 0;
#[cfg(target_os = "linux")]
const ANY_PROPERTY_TYPE: XAtom = 0;
#[cfg(target_os = "linux")]
const CURRENT_TIME: c_ulong = 0;
#[cfg(target_os = "linux")]
const REVERT_TO_POINTER_ROOT: c_int = 1;
#[cfg(target_os = "linux")]
const IS_VIEWABLE: c_int = 2;
#[cfg(target_os = "linux")]
const Z_PIXMAP: c_int = 2;
#[cfg(target_os = "linux")]
const MSB_FIRST: c_int = 1;
#[cfg(target_os = "linux")]
const ALL_PLANES: c_ulong = !0;

#[cfg(target_os = "linux")]
const XK_0: c_ulong = 0x0030;
#[cfg(target_os = "linux")]
const XK_a: c_ulong = 0x0061;
#[cfg(target_os = "linux")]
const XK_F1: c_ulong = 0xffbe;
#[cfg(target_os = "linux")]
const XK_F2: c_ulong = 0xffbf;
#[cfg(target_os = "linux")]
const XK_F3: c_ulong = 0xffc0;
#[cfg(target_os = "linux")]
const XK_F4: c_ulong = 0xffc1;
#[cfg(target_os = "linux")]
const XK_F5: c_ulong = 0xffc2;
#[cfg(target_os = "linux")]
const XK_F6: c_ulong = 0xffc3;
#[cfg(target_os = "linux")]
const XK_F7: c_ulong = 0xffc4;
#[cfg(target_os = "linux")]
const XK_F8: c_ulong = 0xffc5;
#[cfg(target_os = "linux")]
const XK_F9: c_ulong = 0xffc6;
#[cfg(target_os = "linux")]
const XK_F10: c_ulong = 0xffc7;
#[cfg(target_os = "linux")]
const XK_F11: c_ulong = 0xffc8;
#[cfg(target_os = "linux")]
const XK_F12: c_ulong = 0xffc9;
#[cfg(target_os = "linux")]
const XK_Left: c_ulong = 0xff51;
#[cfg(target_os = "linux")]
const XK_Up: c_ulong = 0xff52;
#[cfg(target_os = "linux")]
const XK_Right: c_ulong = 0xff53;
#[cfg(target_os = "linux")]
const XK_Down: c_ulong = 0xff54;
#[cfg(target_os = "linux")]
const XK_Page_Up: c_ulong = 0xff55;
#[cfg(target_os = "linux")]
const XK_Page_Down: c_ulong = 0xff56;
#[cfg(target_os = "linux")]
const XK_End: c_ulong = 0xff57;
#[cfg(target_os = "linux")]
const XK_Home: c_ulong = 0xff50;
#[cfg(target_os = "linux")]
const XK_BackSpace: c_ulong = 0xff08;
#[cfg(target_os = "linux")]
const XK_Return: c_ulong = 0xff0d;
#[cfg(target_os = "linux")]
const XK_Escape: c_ulong = 0xff1b;
#[cfg(target_os = "linux")]
const XK_Tab: c_ulong = 0xff09;
#[cfg(target_os = "linux")]
const XK_Delete: c_ulong = 0xffff;
#[cfg(target_os = "linux")]
const XK_Insert: c_ulong = 0xff63;
#[cfg(target_os = "linux")]
const XK_Pause: c_ulong = 0xff13;
#[cfg(target_os = "linux")]
const XK_Menu: c_ulong = 0xff67;
#[cfg(target_os = "linux")]
const XK_space: c_ulong = 0x0020;
#[cfg(target_os = "linux")]
const XK_apostrophe: c_ulong = 0x0027;
#[cfg(target_os = "linux")]
const XK_grave: c_ulong = 0x0060;
#[cfg(target_os = "linux")]
const XK_backslash: c_ulong = 0x005c;
#[cfg(target_os = "linux")]
const XK_comma: c_ulong = 0x002c;
#[cfg(target_os = "linux")]
const XK_equal: c_ulong = 0x003d;
#[cfg(target_os = "linux")]
const XK_bracketleft: c_ulong = 0x005b;
#[cfg(target_os = "linux")]
const XK_minus: c_ulong = 0x002d;
#[cfg(target_os = "linux")]
const XK_period: c_ulong = 0x002e;
#[cfg(target_os = "linux")]
const XK_bracketright: c_ulong = 0x005d;
#[cfg(target_os = "linux")]
const XK_semicolon: c_ulong = 0x003b;
#[cfg(target_os = "linux")]
const XK_slash: c_ulong = 0x002f;
#[cfg(target_os = "linux")]
const XK_Num_Lock: c_ulong = 0xff7f;
#[cfg(target_os = "linux")]
const XK_Caps_Lock: c_ulong = 0xffe5;
#[cfg(target_os = "linux")]
const XK_Scroll_Lock: c_ulong = 0xff14;
#[cfg(target_os = "linux")]
const XK_Shift_L: c_ulong = 0xffe1;
#[cfg(target_os = "linux")]
const XK_Shift_R: c_ulong = 0xffe2;
#[cfg(target_os = "linux")]
const XK_Control_L: c_ulong = 0xffe3;
#[cfg(target_os = "linux")]
const XK_Control_R: c_ulong = 0xffe4;
#[cfg(target_os = "linux")]
const XK_Alt_L: c_ulong = 0xffe9;
#[cfg(target_os = "linux")]
const XK_Alt_R: c_ulong = 0xffea;
#[cfg(target_os = "linux")]
const XK_Super_L: c_ulong = 0xffeb;
#[cfg(target_os = "linux")]
const XK_Super_R: c_ulong = 0xffec;
#[cfg(target_os = "linux")]
const XK_KP_0: c_ulong = 0xffb0;
#[cfg(target_os = "linux")]
const XK_KP_1: c_ulong = 0xffb1;
#[cfg(target_os = "linux")]
const XK_KP_2: c_ulong = 0xffb2;
#[cfg(target_os = "linux")]
const XK_KP_3: c_ulong = 0xffb3;
#[cfg(target_os = "linux")]
const XK_KP_4: c_ulong = 0xffb4;
#[cfg(target_os = "linux")]
const XK_KP_5: c_ulong = 0xffb5;
#[cfg(target_os = "linux")]
const XK_KP_6: c_ulong = 0xffb6;
#[cfg(target_os = "linux")]
const XK_KP_7: c_ulong = 0xffb7;
#[cfg(target_os = "linux")]
const XK_KP_8: c_ulong = 0xffb8;
#[cfg(target_os = "linux")]
const XK_KP_9: c_ulong = 0xffb9;
#[cfg(target_os = "linux")]
const XK_KP_Decimal: c_ulong = 0xffae;
#[cfg(target_os = "linux")]
const XK_KP_Divide: c_ulong = 0xffaf;
#[cfg(target_os = "linux")]
const XK_KP_Multiply: c_ulong = 0xffaa;
#[cfg(target_os = "linux")]
const XK_KP_Subtract: c_ulong = 0xffad;
#[cfg(target_os = "linux")]
const XK_KP_Add: c_ulong = 0xffab;
#[cfg(target_os = "linux")]
const XK_KP_Enter: c_ulong = 0xff8d;

#[cfg(target_os = "linux")]
#[link(name = "X11")]
unsafe extern "C" {
    fn XInitThreads() -> c_int;
    fn XOpenDisplay(name: *const c_char) -> *mut XDisplay;
    fn XCloseDisplay(display: *mut XDisplay) -> c_int;
    fn XDefaultScreen(display: *mut XDisplay) -> c_int;
    fn XRootWindow(display: *mut XDisplay, screen_number: c_int) -> XWindow;
    fn XInternAtom(display: *mut XDisplay, name: *const c_char, only_if_exists: c_int) -> XAtom;
    fn XGetWindowProperty(
        display: *mut XDisplay,
        window: XWindow,
        property: XAtom,
        long_offset: c_long,
        long_length: c_long,
        delete: c_int,
        req_type: XAtom,
        actual_type_return: *mut XAtom,
        actual_format_return: *mut c_int,
        nitems_return: *mut c_ulong,
        bytes_after_return: *mut c_ulong,
        prop_return: *mut *mut c_uchar,
    ) -> c_int;
    fn XFree(data: *mut c_void) -> c_int;
    fn XQueryTree(
        display: *mut XDisplay,
        window: XWindow,
        root_return: *mut XWindow,
        parent_return: *mut XWindow,
        children_return: *mut *mut XWindow,
        nchildren_return: *mut c_uint,
    ) -> c_int;
    fn XGetWindowAttributes(
        display: *mut XDisplay,
        window: XWindow,
        attributes_return: *mut XWindowAttributes,
    ) -> c_int;
    fn XTranslateCoordinates(
        display: *mut XDisplay,
        src_window: XWindow,
        dest_window: XWindow,
        src_x: c_int,
        src_y: c_int,
        dest_x_return: *mut c_int,
        dest_y_return: *mut c_int,
        child_return: *mut XWindow,
    ) -> c_int;
    fn XGetImage(
        display: *mut XDisplay,
        drawable: XWindow,
        x: c_int,
        y: c_int,
        width: c_uint,
        height: c_uint,
        plane_mask: c_ulong,
        format: c_int,
    ) -> *mut XImage;
    fn XDestroyImage(image: *mut XImage) -> c_int;
    fn XFetchName(display: *mut XDisplay, window: XWindow, name_return: *mut *mut c_char) -> c_int;
    fn XKeysymToKeycode(display: *mut XDisplay, keysym: c_ulong) -> c_uchar;
    fn XSetInputFocus(
        display: *mut XDisplay,
        focus: XWindow,
        revert_to: c_int,
        time: c_ulong,
    ) -> c_int;
    fn XRaiseWindow(display: *mut XDisplay, window: XWindow) -> c_int;
    fn XFlush(display: *mut XDisplay) -> c_int;
}

#[cfg(target_os = "linux")]
#[link(name = "Xtst")]
unsafe extern "C" {
    fn XTestFakeKeyEvent(
        display: *mut XDisplay,
        keycode: c_uint,
        is_press: c_int,
        delay: c_ulong,
    ) -> c_int;
    fn XTestFakeButtonEvent(
        display: *mut XDisplay,
        button: c_uint,
        is_press: c_int,
        delay: c_ulong,
    ) -> c_int;
    fn XTestFakeMotionEvent(
        display: *mut XDisplay,
        screen_number: c_int,
        x: c_int,
        y: c_int,
        delay: c_ulong,
    ) -> c_int;
}

#[cfg(target_os = "macos")]
struct MacWindowCapturer;

#[cfg(target_os = "macos")]
impl Capturer for MacWindowCapturer {
    fn capture<'a>(
        &'a mut self,
        _frame_id: u64,
        _attached_window_id: Option<u64>,
        claim_token: Option<&'a str>,
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = anyhow::Result<Option<CapturedFrame>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let Some(token) = claim_token else {
                return Ok(None);
            };
            capture_claimed_window(token)
        })
    }
}

#[cfg(target_os = "macos")]
fn capture_claimed_window(token: &str) -> anyhow::Result<Option<CapturedFrame>> {
    let Some(claim) = read_gui_claim(token)? else {
        return Ok(None);
    };
    let Some(target) = query_claimed_window(&claim)? else {
        return Ok(None);
    };

    unsafe {
        let image = CGWindowListCreateImage(
            target.bounds,
            K_CG_WINDOW_LIST_OPTION_INCLUDING_WINDOW,
            target.window_id,
            K_CG_WINDOW_IMAGE_BOUNDS_IGNORE_FRAMING,
        );
        if image.is_null() {
            return Err(anyhow!("CGWindowListCreateImage returned null"));
        }

        let frame = cgimage_to_frame(image);
        CFRelease(image.cast());
        frame.map(Some)
    }
}

#[cfg(target_os = "macos")]
fn query_claimed_window(claim: &GuiClaim) -> anyhow::Result<Option<MacWindowTarget>> {
    unsafe {
        let array = CGWindowListCopyWindowInfo(
            K_CG_WINDOW_LIST_OPTION_ON_SCREEN_ONLY | K_CG_WINDOW_LIST_EXCLUDE_DESKTOP_ELEMENTS,
            0,
        );
        if array.is_null() {
            return Ok(None);
        }

        let count = CFArrayGetCount(array);
        let mut out = None;
        for idx in 0..count {
            let dict = CFArrayGetValueAtIndex(array, idx) as CFDictionaryRef;
            if dict.is_null() {
                continue;
            }
            let Some(info) = MacWindowInfo::from_dict(dict)? else {
                continue;
            };
            if info.layer != 0 || info.bounds.size.width < 64.0 || info.bounds.size.height < 64.0 {
                continue;
            }
            if is_excluded_owner(&info.owner_name) {
                continue;
            }
            if !claim.matches(&info) {
                continue;
            }
            out = Some(MacWindowTarget {
                window_id: info.window_id,
                bounds: info.bounds,
            });
            break;
        }
        CFRelease(array.cast());
        Ok(out)
    }
}

#[cfg(target_os = "macos")]
fn is_excluded_owner(owner: &str) -> bool {
    matches!(
        owner,
        "Window Server"
            | "Dock"
            | "ControlCenter"
            | "SystemUIServer"
            | "Terminal"
            | "iTerm2"
            | "bolt"
            | "boltd"
    )
}

#[cfg(target_os = "macos")]
fn cgimage_to_frame(image: CGImageRef) -> anyhow::Result<CapturedFrame> {
    unsafe {
        let width = CGImageGetWidth(image);
        let height = CGImageGetHeight(image);
        let bytes_per_row = CGImageGetBytesPerRow(image);
        let bits_per_pixel = CGImageGetBitsPerPixel(image);
        let provider = CGImageGetDataProvider(image);
        if provider.is_null() {
            return Err(anyhow!("CGImage has no data provider"));
        }
        let data = CGDataProviderCopyData(provider);
        if data.is_null() {
            return Err(anyhow!("CGDataProviderCopyData returned null"));
        }

        let len = CFDataGetLength(data) as usize;
        let ptr = CFDataGetBytePtr(data);
        if ptr.is_null() {
            CFRelease(data.cast());
            return Err(anyhow!("CFDataGetBytePtr returned null"));
        }
        let bytes = std::slice::from_raw_parts(ptr, len);
        let frame = decode_cgimage_bytes(width, height, bytes_per_row, bits_per_pixel, bytes);
        CFRelease(data.cast());
        frame
    }
}

#[cfg(target_os = "macos")]
fn decode_cgimage_bytes(
    width: usize,
    height: usize,
    bytes_per_row: usize,
    bits_per_pixel: usize,
    bytes: &[u8],
) -> anyhow::Result<CapturedFrame> {
    let bytes_per_pixel = (bits_per_pixel / 8).max(4);
    if bytes.len() < bytes_per_row.saturating_mul(height) {
        return Err(anyhow!("CGImage buffer too small"));
    }

    let mut rgb = vec![0_u8; width * height * CHANNELS_RGB];
    for y in 0..height {
        let row = &bytes[y * bytes_per_row..(y + 1) * bytes_per_row];
        for x in 0..width {
            let src = x * bytes_per_pixel;
            let dst = (y * width + x) * CHANNELS_RGB;
            if src + 3 >= row.len() {
                return Err(anyhow!("CGImage row is truncated"));
            }
            // CoreGraphics window captures on macOS are commonly 32-bit BGRA.
            rgb[dst] = row[src + 2];
            rgb[dst + 1] = row[src + 1];
            rgb[dst + 2] = row[src];
        }
    }

    Ok(CapturedFrame {
        width: width as u32,
        height: height as u32,
        rgb,
    })
}

#[cfg(target_os = "macos")]
struct MacWindowTarget {
    window_id: u32,
    bounds: CGRect,
}

#[cfg(target_os = "macos")]
struct MacWindowInfo {
    owner_name: String,
    owner_pid: i64,
    window_id: u32,
    layer: i64,
    bounds: CGRect,
}

#[cfg(target_os = "macos")]
impl MacWindowInfo {
    fn from_dict(dict: CFDictionaryRef) -> anyhow::Result<Option<Self>> {
        unsafe {
            let count = CFDictionaryGetCount(dict);
            if count <= 0 {
                return Ok(None);
            }
            let mut keys = vec![std::ptr::null(); count as usize];
            let mut values = vec![std::ptr::null(); count as usize];
            CFDictionaryGetKeysAndValues(dict, keys.as_mut_ptr(), values.as_mut_ptr());

            let mut owner_name = None;
            let mut owner_pid = None;
            let mut window_id = None;
            let mut layer = None;
            let mut bounds = None;

            for (&key_ref, &val_ref) in keys.iter().zip(values.iter()) {
                let Some(key) = cfstring_to_string(key_ref as CFStringRef) else {
                    continue;
                };
                match key.as_str() {
                    "kCGWindowOwnerName" => {
                        owner_name = cfstring_to_string(val_ref as CFStringRef);
                    }
                    "kCGWindowOwnerPID" => {
                        owner_pid = cfnumber_to_i64(val_ref.cast());
                    }
                    "kCGWindowNumber" => {
                        window_id = cfnumber_to_i64(val_ref.cast()).map(|v| v as u32);
                    }
                    "kCGWindowLayer" => {
                        layer = cfnumber_to_i64(val_ref.cast());
                    }
                    "kCGWindowBounds" => {
                        bounds = cfrect_from_dict(val_ref as CFDictionaryRef)?;
                    }
                    _ => {}
                }
            }

            let Some(owner_name) = owner_name else {
                return Ok(None);
            };
            let Some(owner_pid) = owner_pid else {
                return Ok(None);
            };
            let Some(window_id) = window_id else {
                return Ok(None);
            };
            let Some(layer) = layer else {
                return Ok(None);
            };
            let Some(bounds) = bounds else {
                return Ok(None);
            };

            Ok(Some(Self {
                owner_name,
                owner_pid,
                window_id,
                layer,
                bounds,
            }))
        }
    }
}

#[cfg(target_os = "macos")]
fn cfrect_from_dict(dict: CFDictionaryRef) -> anyhow::Result<Option<CGRect>> {
    unsafe {
        if dict.is_null() {
            return Ok(None);
        }

        let count = CFDictionaryGetCount(dict);
        if count <= 0 {
            return Ok(None);
        }
        let mut keys = vec![std::ptr::null(); count as usize];
        let mut values = vec![std::ptr::null(); count as usize];
        CFDictionaryGetKeysAndValues(dict, keys.as_mut_ptr(), values.as_mut_ptr());

        let mut x = None;
        let mut y = None;
        let mut width = None;
        let mut height = None;

        for (&key_ref, &val_ref) in keys.iter().zip(values.iter()) {
            let Some(key) = cfstring_to_string(key_ref as CFStringRef) else {
                continue;
            };
            match key.as_str() {
                "X" => x = cfnumber_to_f64(val_ref.cast()),
                "Y" => y = cfnumber_to_f64(val_ref.cast()),
                "Width" => width = cfnumber_to_f64(val_ref.cast()),
                "Height" => height = cfnumber_to_f64(val_ref.cast()),
                _ => {}
            }
        }

        let (Some(x), Some(y), Some(width), Some(height)) = (x, y, width, height) else {
            return Ok(None);
        };

        Ok(Some(CGRect {
            origin: CGPoint { x, y },
            size: CGSize { width, height },
        }))
    }
}

#[cfg(target_os = "macos")]
fn cfstring_to_string(s: CFStringRef) -> Option<String> {
    unsafe {
        if s.is_null() || CFGetTypeID(s.cast()) != CFStringGetTypeID() {
            return None;
        }
        let mut buf = vec![0_i8; 1024];
        if !CFStringGetCString(
            s,
            buf.as_mut_ptr(),
            buf.len() as isize,
            K_CF_STRING_ENCODING_UTF8,
        ) {
            return None;
        }
        let bytes: Vec<u8> = buf
            .into_iter()
            .take_while(|b| *b != 0)
            .map(|b| b as u8)
            .collect();
        String::from_utf8(bytes).ok()
    }
}

#[cfg(target_os = "macos")]
fn cfnumber_to_i64(n: CFTypeRef) -> Option<i64> {
    unsafe {
        if n.is_null() || CFGetTypeID(n) != CFNumberGetTypeID() {
            return None;
        }
        let mut out = 0_i64;
        if CFNumberGetValue(
            n as CFNumberRef,
            K_CF_NUMBER_SINT64_TYPE,
            (&mut out as *mut i64).cast(),
        ) {
            Some(out)
        } else {
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn cfnumber_to_f64(n: CFTypeRef) -> Option<f64> {
    unsafe {
        if n.is_null() || CFGetTypeID(n) != CFNumberGetTypeID() {
            return None;
        }
        let mut out = 0_f64;
        if CFNumberGetValue(
            n as CFNumberRef,
            K_CF_NUMBER_FLOAT64_TYPE,
            (&mut out as *mut f64).cast(),
        ) {
            Some(out)
        } else {
            None
        }
    }
}

#[cfg(target_os = "macos")]
impl GuiClaim {
    fn matches(&self, info: &MacWindowInfo) -> bool {
        if let Some(pid) = self.pid {
            if info.owner_pid == pid {
                return true;
            }
        }
        info.owner_name == self.owner_name
    }
}

#[cfg(target_os = "macos")]
type CFTypeRef = *const c_void;
#[cfg(target_os = "macos")]
type CFArrayRef = *const c_void;
#[cfg(target_os = "macos")]
type CFDictionaryRef = *const c_void;
#[cfg(target_os = "macos")]
type CFStringRef = *const c_void;
#[cfg(target_os = "macos")]
type CFDataRef = *const c_void;
#[cfg(target_os = "macos")]
type CFNumberRef = *const c_void;
#[cfg(target_os = "macos")]
type CGImageRef = *const c_void;
#[cfg(target_os = "macos")]
type CGDataProviderRef = *const c_void;

#[cfg(target_os = "macos")]
const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
#[cfg(target_os = "macos")]
const K_CF_NUMBER_SINT64_TYPE: i32 = 4;
#[cfg(target_os = "macos")]
const K_CF_NUMBER_FLOAT64_TYPE: i32 = 6;
#[cfg(target_os = "macos")]
const K_CG_WINDOW_LIST_OPTION_ON_SCREEN_ONLY: u32 = 1 << 0;
#[cfg(target_os = "macos")]
const K_CG_WINDOW_LIST_OPTION_INCLUDING_WINDOW: u32 = 1 << 3;
#[cfg(target_os = "macos")]
const K_CG_WINDOW_LIST_EXCLUDE_DESKTOP_ELEMENTS: u32 = 1 << 4;
#[cfg(target_os = "macos")]
const K_CG_WINDOW_IMAGE_BOUNDS_IGNORE_FRAMING: u32 = 1 << 0;

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct CGPoint {
    x: f64,
    y: f64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct CGSize {
    width: f64,
    height: f64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct CGRect {
    origin: CGPoint,
    size: CGSize,
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFArrayGetCount(array: CFArrayRef) -> isize;
    fn CFArrayGetValueAtIndex(array: CFArrayRef, index: isize) -> *const c_void;
    fn CFDictionaryGetCount(dict: CFDictionaryRef) -> isize;
    fn CFDictionaryGetKeysAndValues(
        dict: CFDictionaryRef,
        keys: *mut *const c_void,
        values: *mut *const c_void,
    );
    fn CFStringGetTypeID() -> usize;
    fn CFStringGetCString(
        string: CFStringRef,
        buffer: *mut i8,
        buffer_size: isize,
        encoding: u32,
    ) -> bool;
    fn CFNumberGetTypeID() -> usize;
    fn CFNumberGetValue(number: CFNumberRef, number_type: i32, value_ptr: *mut c_void) -> bool;
    fn CFDataGetLength(data: CFDataRef) -> isize;
    fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
}

#[cfg(target_os = "macos")]
#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn CGWindowListCopyWindowInfo(option: u32, relative_to_window: u32) -> CFArrayRef;
    fn CGWindowListCreateImage(
        screen_bounds: CGRect,
        list_option: u32,
        window_id: u32,
        image_option: u32,
    ) -> CGImageRef;
    fn CGImageGetWidth(image: CGImageRef) -> usize;
    fn CGImageGetHeight(image: CGImageRef) -> usize;
    fn CGImageGetBytesPerRow(image: CGImageRef) -> usize;
    fn CGImageGetBitsPerPixel(image: CGImageRef) -> usize;
    fn CGImageGetDataProvider(image: CGImageRef) -> CGDataProviderRef;
    fn CGDataProviderCopyData(provider: CGDataProviderRef) -> CFDataRef;
}
