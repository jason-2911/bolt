//! minifb window rendering, framebuffer management, and user input forwarding.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context as _};
use minifb::{
    Key, KeyRepeat, MouseButton as FbMouseButton, MouseMode, Scale, Window, WindowOptions,
};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use bolt_proto::{
    encode_udp_packet, DesktopInventoryChunk, DesktopWindow, InputEvent, MouseButton, Rect,
    UdpGuiPacket, VideoChunk, VideoCodec,
};

use super::bitmap_text::BitmapText;

const FRAMEBUFFER_CHANNELS: usize = 3;
const INVENTORY_WIDTH: usize = 960;
const INVENTORY_HEIGHT: usize = 540;

// ── Public render state ───────────────────────────────────────────────────────

pub struct RenderState {
    pub(super) surface_w: u32,
    pub(super) surface_h: u32,
    pub(super) fb: Vec<u8>,
    partials: HashMap<(u64, u32), PartialPatch>,
    inventory_partials: HashMap<u64, PartialInventory>,
    pub(super) inventory: Vec<DesktopWindow>,
    inventory_generation: u64,
    pub(super) selected_index: usize,
    pub(super) attached_window_id: Option<u64>,
    pending_auto_attach_window_id: Option<u64>,
    last_log: Instant,
    last_inventory_log: Instant,
    frames_rendered: u64,
    pub(super) last_window_w: u32,
    pub(super) last_window_h: u32,
}

impl RenderState {
    pub fn new() -> Self {
        Self {
            surface_w: 0,
            surface_h: 0,
            fb: Vec::new(),
            partials: HashMap::new(),
            inventory_partials: HashMap::new(),
            inventory: Vec::new(),
            inventory_generation: 0,
            selected_index: 0,
            attached_window_id: None,
            pending_auto_attach_window_id: None,
            last_log: Instant::now(),
            last_inventory_log: Instant::now() - Duration::from_secs(10),
            frames_rendered: 0,
            last_window_w: 0,
            last_window_h: 0,
        }
    }

    pub fn on_chunk(&mut self, chunk: VideoChunk) -> anyhow::Result<Option<DecodedPatch>> {
        if !matches!(chunk.codec, VideoCodec::RawRgb24Zstd) {
            return Err(anyhow!("unsupported video codec"));
        }

        let key = (chunk.frame_id, chunk.patch_id);
        let slot = self
            .partials
            .entry(key)
            .or_insert_with(|| PartialPatch::new(&chunk));
        slot.insert(chunk)?;

        if !slot.complete() {
            return Ok(None);
        }
        let rect = slot.rect;
        let surface_w = slot.surface_w;
        let surface_h = slot.surface_h;
        let full = slot.reassemble()?;
        self.partials.remove(&key);

        let patch_rgb = zstd::stream::decode_all(full.as_slice()).context("zstd decode")?;
        Ok(Some(DecodedPatch {
            frame_id: key.0,
            rect,
            surface_w,
            surface_h,
            rgb: patch_rgb,
        }))
    }

    pub fn on_inventory_chunk(&mut self, chunk: DesktopInventoryChunk) -> anyhow::Result<()> {
        let generation = chunk.generation;
        let slot = self
            .inventory_partials
            .entry(generation)
            .or_insert_with(|| PartialInventory::new(&chunk));
        slot.insert(chunk)?;
        if !slot.complete() {
            return Ok(());
        }

        let Some(assembled) = self
            .inventory_partials
            .remove(&generation)
            .map(PartialInventory::reassemble)
        else {
            return Ok(());
        };
        self.inventory_partials
            .retain(|remaining_generation, _| *remaining_generation > assembled.generation);
        self.apply_inventory(assembled);
        Ok(())
    }

    fn apply_inventory(&mut self, assembled: CompletedInventory) {
        let previous_window_ids: HashSet<u64> = self
            .inventory
            .iter()
            .map(|window| window.window_id)
            .collect();
        let previous_selected = self.selected_window_id();
        self.inventory_generation = assembled.generation;
        self.inventory = assembled.windows;
        self.attached_window_id = assembled.attached_window_id;

        if let Some(attached) = self.attached_window_id {
            if let Some(index) = self
                .inventory
                .iter()
                .position(|window| window.window_id == attached)
            {
                self.selected_index = index;
            }
        } else if let Some(previous_selected) = previous_selected {
            if let Some(index) = self
                .inventory
                .iter()
                .position(|window| window.window_id == previous_selected)
            {
                self.selected_index = index;
            } else if self.selected_index >= self.inventory.len() {
                self.selected_index = self.inventory.len().saturating_sub(1);
            }
        } else if self.selected_index >= self.inventory.len() {
            self.selected_index = self.inventory.len().saturating_sub(1);
        }

        if self.attached_window_id.is_none() {
            if let Some(window_id) =
                preferred_auto_attach_window(&self.inventory, &previous_window_ids)
            {
                self.pending_auto_attach_window_id = Some(window_id);
                if let Some(index) = self
                    .inventory
                    .iter()
                    .position(|window| window.window_id == window_id)
                {
                    self.selected_index = index;
                }
                if let Some(window) = self.inventory.get(self.selected_index) {
                    info!(
                        window_id,
                        process = %window.process_name,
                        title = %window.title,
                        "auto-selecting new GUI window"
                    );
                }
            }
        } else {
            self.pending_auto_attach_window_id = None;
        }

        if self.last_inventory_log.elapsed() >= Duration::from_secs(1) {
            info!(
                generation = self.inventory_generation,
                windows = self.inventory.len(),
                attached = ?self.attached_window_id,
                selected = self.selected_window_id(),
                "received desktop inventory"
            );
            self.last_inventory_log = Instant::now();
        }
    }

    pub fn render_patch(&mut self, patch: DecodedPatch) -> anyhow::Result<()> {
        self.ensure_surface(patch.surface_w, patch.surface_h);

        blit_patch(
            &mut self.fb,
            self.surface_w,
            self.surface_h,
            patch.rect,
            &patch.rgb,
        )?;

        self.frames_rendered = self.frames_rendered.wrapping_add(1);
        if self.last_log.elapsed() >= Duration::from_secs(1) {
            let checksum = checksum32(&self.fb);
            info!(
                frame_id = patch.frame_id,
                rendered = self.frames_rendered,
                surface = format!("{}x{}", self.surface_w, self.surface_h),
                dirty = format!(
                    "{}x{}+{},{}",
                    patch.rect.w, patch.rect.h, patch.rect.x, patch.rect.y
                ),
                window = format!("{}x{}", self.last_window_w, self.last_window_h),
                checksum,
                "rendered local window patch"
            );
            self.last_log = Instant::now();
        }
        Ok(())
    }

    fn ensure_surface(&mut self, w: u32, h: u32) {
        if self.surface_w == w && self.surface_h == h {
            return;
        }
        self.surface_w = w;
        self.surface_h = h;
        self.fb = vec![0_u8; (w as usize) * (h as usize) * FRAMEBUFFER_CHANNELS];
    }

    pub fn selected_window_id(&self) -> Option<u64> {
        self.inventory
            .get(self.selected_index)
            .map(|window| window.window_id)
    }

    pub fn take_pending_auto_attach(&mut self) -> Option<u64> {
        self.pending_auto_attach_window_id.take()
    }

    pub fn move_selection(&mut self, delta: isize) {
        if self.inventory.is_empty() {
            self.selected_index = 0;
            return;
        }
        let len = self.inventory.len() as isize;
        let next = (self.selected_index as isize + delta).clamp(0, len - 1);
        self.selected_index = next as usize;
    }

    pub fn select_index(&mut self, index: usize) {
        self.selected_index = index.min(self.inventory.len().saturating_sub(1));
    }

    pub fn select_last(&mut self) {
        self.selected_index = self.inventory.len().saturating_sub(1);
    }

    pub fn cycle_selection(&mut self, delta: isize) -> Option<u64> {
        if self.inventory.is_empty() {
            return None;
        }
        let len = self.inventory.len() as isize;
        let current = self
            .inventory
            .iter()
            .position(|window| Some(window.window_id) == self.attached_window_id)
            .unwrap_or(self.selected_index) as isize;
        let mut next = current + delta;
        if next < 0 {
            next = len - 1;
        } else if next >= len {
            next = 0;
        }
        self.selected_index = next as usize;
        self.inventory
            .get(self.selected_index)
            .map(|window| window.window_id)
    }

    pub fn selector_window_title(&self) -> String {
        let selected = self.inventory.get(self.selected_index);
        match selected {
            Some(window) => format!(
                "Bolt Desktop Agent [{} / {}] {} - {}",
                self.selected_index + 1,
                self.inventory.len(),
                window.process_name,
                truncate_text(&window.title, 64)
            ),
            None => "Bolt Desktop Agent - Waiting For Windows".to_string(),
        }
    }

    pub fn attached_window_title(&self) -> String {
        let attached = self.attached_window_id.and_then(|attached| {
            self.inventory
                .iter()
                .find(|window| window.window_id == attached)
        });
        match attached {
            Some(window) => format!(
                "Bolt GUI Stream - {} - {}",
                window.process_name,
                truncate_text(&window.title, 64)
            ),
            None => "Bolt GUI Stream".to_string(),
        }
    }
}

// ── Window loop ───────────────────────────────────────────────────────────────

pub fn run_window_loop(
    state: Arc<Mutex<RenderState>>,
    socket: Arc<UdpSocket>,
    server: SocketAddr,
    token: String,
) -> anyhow::Result<()> {
    let mut window: Option<Window> = None;
    let text = BitmapText::new(2);

    send_input_event(&socket, server, UdpGuiPacket::Hello { token });

    let mut rgba_u32 = vec![0_u32; INVENTORY_WIDTH * INVENTORY_HEIGHT];
    let mut last_mouse: Option<(i32, i32)> = None;
    let mut last_left = false;
    let mut last_right = false;
    let mut last_middle = false;

    loop {
        let attached_mode;
        let auto_attach_window_id;
        {
            let mut guard = state.lock().map_err(|_| anyhow!("render state poisoned"))?;
            let should_show_window = (guard.surface_w > 0 && guard.surface_h > 0)
                || !guard.inventory.is_empty()
                || guard.attached_window_id.is_some();
            if window.is_none() && should_show_window {
                let initial_w = guard.surface_w.max(INVENTORY_WIDTH as u32) as usize;
                let initial_h = guard.surface_h.max(INVENTORY_HEIGHT as u32) as usize;
                let mut w = Window::new(
                    "Bolt Desktop Agent",
                    initial_w,
                    initial_h,
                    WindowOptions {
                        resize: true,
                        scale: Scale::X1,
                        ..WindowOptions::default()
                    },
                )
                .context("create client window")?;
                w.set_target_fps(60);
                window = Some(w);
            }

            let Some(window) = window.as_mut() else {
                thread::sleep(Duration::from_millis(16));
                continue;
            };

            if !window.is_open() {
                break;
            }

            attached_mode = guard.attached_window_id.is_some();
            if attached_mode && guard.surface_w > 0 && guard.surface_h > 0 {
                let w = guard.surface_w as usize;
                let h = guard.surface_h as usize;
                if rgba_u32.len() != w * h {
                    rgba_u32.resize(w * h, 0);
                }
                rgb_to_u32(&guard.fb, &mut rgba_u32);
                window
                    .update_with_buffer(&rgba_u32, w, h)
                    .context("update window buffer")?;
                window.set_title(&guard.attached_window_title());
            } else {
                let (w, h) = window.get_size();
                if rgba_u32.len() != w * h {
                    rgba_u32.resize(w * h, 0);
                }
                render_inventory_screen(&mut rgba_u32, w, h, &guard, &text);
                window
                    .update_with_buffer(&rgba_u32, w, h)
                    .context("update inventory buffer")?;
                window.set_title(&guard.selector_window_title());
            }

            guard.last_window_w = window.get_size().0 as u32;
            guard.last_window_h = window.get_size().1 as u32;
            auto_attach_window_id = if guard.attached_window_id.is_none() {
                guard.take_pending_auto_attach()
            } else {
                None
            };
        }

        let Some(window) = window.as_mut() else {
            continue;
        };
        if let Some(window_id) = auto_attach_window_id {
            info!(window_id, "auto-attaching GUI window");
            send_input_event(&socket, server, UdpGuiPacket::AttachWindow { window_id });
            continue;
        }
        if attached_mode {
            if handle_attached_shortcuts(&state, &socket, server, window)? {
                last_mouse = None;
                last_left = false;
                last_right = false;
                last_middle = false;
                continue;
            }

            for key in window.get_keys_pressed(KeyRepeat::No) {
                if is_local_attached_key(key) {
                    continue;
                }
                let code = key_to_code(key);
                send_input_event(
                    &socket,
                    server,
                    UdpGuiPacket::InputEvent(InputEvent::Key { code, down: true }),
                );
            }
            for key in window.get_keys_released() {
                if is_local_attached_key(key) {
                    continue;
                }
                let code = key_to_code(key);
                send_input_event(
                    &socket,
                    server,
                    UdpGuiPacket::InputEvent(InputEvent::Key { code, down: false }),
                );
            }

            if let Some((mx, my)) = window.get_mouse_pos(MouseMode::Pass) {
                let p = (mx as i32, my as i32);
                if last_mouse != Some(p) {
                    last_mouse = Some(p);
                    send_input_event(
                        &socket,
                        server,
                        UdpGuiPacket::InputEvent(InputEvent::MouseMove { x: p.0, y: p.1 }),
                    );
                }
            }

            let left = window.get_mouse_down(FbMouseButton::Left);
            if left != last_left {
                last_left = left;
                send_input_event(
                    &socket,
                    server,
                    UdpGuiPacket::InputEvent(InputEvent::MouseButton {
                        button: MouseButton::Left,
                        down: left,
                    }),
                );
            }

            let right = window.get_mouse_down(FbMouseButton::Right);
            if right != last_right {
                last_right = right;
                send_input_event(
                    &socket,
                    server,
                    UdpGuiPacket::InputEvent(InputEvent::MouseButton {
                        button: MouseButton::Right,
                        down: right,
                    }),
                );
            }

            let middle = window.get_mouse_down(FbMouseButton::Middle);
            if middle != last_middle {
                last_middle = middle;
                send_input_event(
                    &socket,
                    server,
                    UdpGuiPacket::InputEvent(InputEvent::MouseButton {
                        button: MouseButton::Middle,
                        down: middle,
                    }),
                );
            }

            if let Some((sx, sy)) = window.get_scroll_wheel() {
                let dx = sx as i32;
                let dy = sy as i32;
                if dx != 0 || dy != 0 {
                    send_input_event(
                        &socket,
                        server,
                        UdpGuiPacket::InputEvent(InputEvent::MouseWheel { dx, dy }),
                    );
                }
            }
        } else {
            last_mouse = None;
            last_left = false;
            last_right = false;
            last_middle = false;
            handle_selector_shortcuts(&state, &socket, server, window)?;
        }
    }

    Ok(())
}

// ── Input helpers ─────────────────────────────────────────────────────────────

fn send_input_event(socket: &Arc<UdpSocket>, server: SocketAddr, packet: UdpGuiPacket) {
    debug!(packet = %packet_kind(&packet), server = %server, "queue GUI packet");
    let wire = match encode_udp_packet(&packet) {
        Ok(w) => w,
        Err(e) => {
            warn!(error = %e, "encode input event failed");
            return;
        }
    };
    if let Err(e) = socket.try_send_to(&wire, server) {
        warn!(error = %e, "send input event failed");
    }
}

fn packet_kind(packet: &UdpGuiPacket) -> &'static str {
    match packet {
        UdpGuiPacket::Hello { .. } => "hello",
        UdpGuiPacket::AttachWindow { .. } => "attach_window",
        UdpGuiPacket::DetachWindow => "detach_window",
        UdpGuiPacket::InputEvent(_) => "input_event",
        UdpGuiPacket::VideoChunk(_) => "video_chunk",
        UdpGuiPacket::DesktopInventoryChunk(_) => "desktop_inventory_chunk",
    }
}

fn preferred_auto_attach_window(
    inventory: &[DesktopWindow],
    previous_window_ids: &HashSet<u64>,
) -> Option<u64> {
    let new_windows: Vec<&DesktopWindow> = inventory
        .iter()
        .filter(|window| !previous_window_ids.contains(&window.window_id))
        .collect();
    if new_windows.is_empty() {
        return None;
    }

    new_windows
        .iter()
        .rev()
        .find(|window| !is_terminal_like_process(&window.process_name))
        .copied()
        .or_else(|| {
            (previous_window_ids.is_empty() && new_windows.len() == 1)
                .then(|| new_windows.last().copied())
                .flatten()
        })
        .map(|window| window.window_id)
}

fn is_terminal_like_process(process_name: &str) -> bool {
    matches!(
        process_name.trim().to_ascii_lowercase().as_str(),
        "xterm"
            | "gnome-terminal"
            | "gnome-terminal-server"
            | "konsole"
            | "alacritty"
            | "kitty"
            | "wezterm-gui"
            | "wezterm"
            | "terminal"
            | "tmux"
            | "screen"
            | "bash"
            | "sh"
            | "zsh"
            | "fish"
    )
}

fn key_to_code(k: Key) -> u32 {
    k as u32
}

fn is_local_attached_key(key: Key) -> bool {
    matches!(key, Key::F6 | Key::F7 | Key::F8)
}

fn handle_attached_shortcuts(
    state: &Arc<Mutex<RenderState>>,
    socket: &Arc<UdpSocket>,
    server: SocketAddr,
    window: &mut Window,
) -> anyhow::Result<bool> {
    if window.is_key_pressed(Key::F6, KeyRepeat::No)
        || window.is_key_pressed(Key::Escape, KeyRepeat::No)
    {
        send_input_event(socket, server, UdpGuiPacket::DetachWindow);
        if let Ok(mut guard) = state.lock() {
            guard.attached_window_id = None;
        }
        return Ok(true);
    }

    if window.is_key_pressed(Key::F7, KeyRepeat::No) {
        if let Some(window_id) = state
            .lock()
            .map_err(|_| anyhow!("render state poisoned"))?
            .cycle_selection(-1)
        {
            send_input_event(socket, server, UdpGuiPacket::AttachWindow { window_id });
        }
        return Ok(true);
    }

    if window.is_key_pressed(Key::F8, KeyRepeat::No) {
        if let Some(window_id) = state
            .lock()
            .map_err(|_| anyhow!("render state poisoned"))?
            .cycle_selection(1)
        {
            send_input_event(socket, server, UdpGuiPacket::AttachWindow { window_id });
        }
        return Ok(true);
    }

    Ok(false)
}

fn handle_selector_shortcuts(
    state: &Arc<Mutex<RenderState>>,
    socket: &Arc<UdpSocket>,
    server: SocketAddr,
    window: &mut Window,
) -> anyhow::Result<()> {
    let mut guard = state.lock().map_err(|_| anyhow!("render state poisoned"))?;

    if window.is_key_pressed(Key::Up, KeyRepeat::No) {
        guard.move_selection(-1);
    }
    if window.is_key_pressed(Key::Down, KeyRepeat::No) {
        guard.move_selection(1);
    }
    if window.is_key_pressed(Key::PageUp, KeyRepeat::No) {
        guard.move_selection(-5);
    }
    if window.is_key_pressed(Key::PageDown, KeyRepeat::No) {
        guard.move_selection(5);
    }
    if window.is_key_pressed(Key::Home, KeyRepeat::No) {
        guard.select_index(0);
    }
    if window.is_key_pressed(Key::End, KeyRepeat::No) {
        guard.select_last();
    }
    if window.is_key_pressed(Key::Enter, KeyRepeat::No) {
        if let Some(window_id) = guard.selected_window_id() {
            if let Some(selected) = guard.inventory.get(guard.selected_index) {
                info!(
                    window_id,
                    process = %selected.process_name,
                    title = %selected.title,
                    "selector attach requested"
                );
            } else {
                info!(window_id, "selector attach requested");
            }
            send_input_event(socket, server, UdpGuiPacket::AttachWindow { window_id });
        } else {
            warn!("selector attach requested, but inventory is empty");
        }
    }

    Ok(())
}

// ── Inventory rendering ───────────────────────────────────────────────────────

fn render_inventory_screen(
    screen: &mut [u32],
    width: usize,
    height: usize,
    state: &RenderState,
    text: &BitmapText,
) {
    clear_u32(screen, 0x10161d);
    fill_rect(screen, width, height, 0, 0, width, 72, 0x172333);
    draw_text_with_shadow(
        screen,
        width,
        height,
        text,
        (20, 14),
        "Bolt Desktop Agent",
        0xf6f8fb,
    );
    draw_text_with_shadow(
        screen,
        width,
        height,
        text,
        (20, 34),
        "Enter attach  Up/Down select  F6 detach  F7/F8 switch",
        0x9fb3c8,
    );

    let status = if state.attached_window_id.is_some() {
        "Attached"
    } else {
        "Browsing"
    };
    let inventory_label = format!(
        "{} windows={} generation={}",
        status,
        state.inventory.len(),
        state.inventory_generation
    );
    draw_text_with_shadow(
        screen,
        width,
        height,
        text,
        (20, 54),
        &inventory_label,
        0x7ad7a8,
    );

    if state.inventory.is_empty() {
        draw_text_with_shadow(
            screen,
            width,
            height,
            text,
            (20, 110),
            "No GUI windows are visible on the server yet.",
            0xf4c95d,
        );
        draw_text_with_shadow(
            screen,
            width,
            height,
            text,
            (20, 132),
            "Launch an app remotely and it will appear here automatically.",
            0xc8d2dc,
        );
        return;
    }

    let line_height = text.line_height();
    let row_height = line_height + 10;
    let top = 94;
    let visible_rows = ((height.saturating_sub(top + 16)) / row_height).max(1);
    let start = state
        .selected_index
        .saturating_sub(visible_rows.saturating_sub(1) / 2)
        .min(state.inventory.len().saturating_sub(visible_rows));

    for (row, window) in state
        .inventory
        .iter()
        .enumerate()
        .skip(start)
        .take(visible_rows)
    {
        let y = top + (row - start) * row_height;
        let is_selected = row == state.selected_index;
        let is_attached = Some(window.window_id) == state.attached_window_id;
        let background = if is_attached {
            0x1f4d3a
        } else if is_selected {
            0x25374c
        } else {
            0x14202d
        };
        fill_rect(
            screen,
            width,
            height,
            16,
            y.saturating_sub(4),
            width.saturating_sub(32),
            row_height.saturating_sub(2),
            background,
        );

        let prefix = if is_attached {
            "*"
        } else if is_selected {
            ">"
        } else {
            " "
        };
        let pid = window
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".to_string());
        let line = format!(
            "{} {:02} {} [{}] {} ({}x{})",
            prefix,
            row + 1,
            truncate_text(&window.process_name, 18),
            pid,
            truncate_text(&window.title, 52),
            window.width,
            window.height
        );
        draw_text_with_shadow(screen, width, height, text, (28, y), &line, 0xf6f8fb);
    }
}

// ── Drawing primitives ────────────────────────────────────────────────────────

fn clear_u32(screen: &mut [u32], color: u32) {
    screen.fill(color);
}

fn fill_rect(
    screen: &mut [u32],
    width: usize,
    height: usize,
    x: usize,
    y: usize,
    rect_w: usize,
    rect_h: usize,
    color: u32,
) {
    let max_y = y.saturating_add(rect_h).min(height);
    let max_x = x.saturating_add(rect_w).min(width);
    for draw_y in y.min(height)..max_y {
        let row = &mut screen[draw_y * width..(draw_y + 1) * width];
        for draw_x in x.min(width)..max_x {
            row[draw_x] = color;
        }
    }
}

fn draw_text_with_shadow(
    screen: &mut [u32],
    width: usize,
    height: usize,
    text: &BitmapText,
    pos: (usize, usize),
    value: &str,
    color: u32,
) {
    text.draw(
        screen,
        width,
        height,
        (pos.0.saturating_add(2), pos.1.saturating_add(2)),
        value,
        0x000000,
    );
    text.draw(screen, width, height, pos, value, color);
}

fn rgb_to_u32(rgb: &[u8], out: &mut [u32]) {
    for (i, px) in out.iter_mut().enumerate() {
        let idx = i * 3;
        let r = rgb[idx] as u32;
        let g = rgb[idx + 1] as u32;
        let b = rgb[idx + 2] as u32;
        *px = (r << 16) | (g << 8) | b;
    }
}

fn truncate_text(text: &str, limit: usize) -> String {
    let mut out = String::new();
    for (idx, ch) in text.chars().enumerate() {
        if idx >= limit {
            out.push_str("...");
            break;
        }
        out.push(if ch.is_control() { ' ' } else { ch });
    }
    if out.is_empty() {
        "-".to_string()
    } else {
        out
    }
}

fn checksum32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0_u32, |acc, b| acc.rotate_left(5) ^ (*b as u32))
}

// ── Patch reassembly ──────────────────────────────────────────────────────────

pub struct DecodedPatch {
    pub frame_id: u64,
    pub rect: Rect,
    pub surface_w: u32,
    pub surface_h: u32,
    pub rgb: Vec<u8>,
}

struct PartialPatch {
    rect: Rect,
    surface_w: u32,
    surface_h: u32,
    total: u16,
    chunks: Vec<Option<Vec<u8>>>,
    compressed_size: u32,
}

impl PartialPatch {
    fn new(chunk: &VideoChunk) -> Self {
        Self {
            rect: chunk.rect,
            surface_w: chunk.surface_width,
            surface_h: chunk.surface_height,
            total: chunk.chunk_total,
            chunks: vec![None; chunk.chunk_total as usize],
            compressed_size: chunk.compressed_size,
        }
    }

    fn insert(&mut self, chunk: VideoChunk) -> anyhow::Result<()> {
        if chunk.chunk_total != self.total {
            return Err(anyhow!("chunk total mismatch"));
        }
        let idx = chunk.chunk_index as usize;
        if idx >= self.chunks.len() {
            return Err(anyhow!("chunk index out of bounds"));
        }
        self.chunks[idx] = Some(chunk.payload);
        Ok(())
    }

    fn complete(&self) -> bool {
        self.chunks.iter().all(|c| c.is_some())
    }

    fn reassemble(&self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.compressed_size as usize);
        for maybe in &self.chunks {
            let bytes = maybe.as_ref().ok_or_else(|| anyhow!("missing chunk"))?;
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }
}

// ── Inventory reassembly ──────────────────────────────────────────────────────

struct PartialInventory {
    generation: u64,
    total: u16,
    attached_window_id: Option<u64>,
    chunks: Vec<Option<Vec<DesktopWindow>>>,
}

impl PartialInventory {
    fn new(chunk: &DesktopInventoryChunk) -> Self {
        Self {
            generation: chunk.generation,
            total: chunk.chunk_total,
            attached_window_id: chunk.attached_window_id,
            chunks: vec![None; chunk.chunk_total as usize],
        }
    }

    fn insert(&mut self, chunk: DesktopInventoryChunk) -> anyhow::Result<()> {
        if chunk.generation != self.generation {
            return Err(anyhow!("inventory generation mismatch"));
        }
        if chunk.chunk_total != self.total {
            return Err(anyhow!("inventory total mismatch"));
        }
        let index = chunk.chunk_index as usize;
        if index >= self.chunks.len() {
            return Err(anyhow!("inventory chunk index out of bounds"));
        }
        self.attached_window_id = chunk.attached_window_id;
        self.chunks[index] = Some(chunk.windows);
        Ok(())
    }

    fn complete(&self) -> bool {
        self.chunks.iter().all(|chunk| chunk.is_some())
    }

    fn reassemble(self) -> CompletedInventory {
        let mut windows = Vec::new();
        for chunk in self.chunks.into_iter().flatten() {
            windows.extend(chunk);
        }
        CompletedInventory {
            generation: self.generation,
            attached_window_id: self.attached_window_id,
            windows,
        }
    }
}

struct CompletedInventory {
    generation: u64,
    attached_window_id: Option<u64>,
    windows: Vec<DesktopWindow>,
}

// ── Framebuffer ops ───────────────────────────────────────────────────────────

fn blit_patch(
    fb: &mut [u8],
    surface_w: u32,
    surface_h: u32,
    rect: Rect,
    rgb: &[u8],
) -> anyhow::Result<()> {
    if rect.x >= surface_w || rect.y >= surface_h {
        return Err(anyhow!("rect outside surface"));
    }
    let rw = rect.w.min(surface_w - rect.x) as usize;
    let rh = rect.h.min(surface_h - rect.y) as usize;
    let expected = rw * rh * FRAMEBUFFER_CHANNELS;
    if rgb.len() != expected {
        return Err(anyhow!(
            "patch size mismatch: got {}, expected {}",
            rgb.len(),
            expected
        ));
    }

    let sw = surface_w as usize;
    for row in 0..rh {
        let dst_y = rect.y as usize + row;
        let dst_off = (dst_y * sw + rect.x as usize) * FRAMEBUFFER_CHANNELS;
        let src_off = row * rw * FRAMEBUFFER_CHANNELS;
        let len = rw * FRAMEBUFFER_CHANNELS;
        fb[dst_off..dst_off + len].copy_from_slice(&rgb[src_off..src_off + len]);
    }
    Ok(())
}
