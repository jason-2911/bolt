//! Linux/X11 screen capture, window inventory, and XTest input injection.

use std::{
    collections::{HashMap, HashSet},
    os::raw::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong},
};

use anyhow::Context as _;
use bolt_proto::{DesktopWindow, InputEvent};
use tracing::{debug, warn};

use super::{CapturedFrame, Capturer, CHANNELS_RGB};

// ── Desktop agent (window inventory) ─────────────────────────────────────────

pub(super) struct LinuxDesktopAgent {
    display: *mut XDisplay,
    atoms: LinuxAtoms,
    seen_pids: HashSet<i64>,
    seen_windows: HashSet<XWindow>,
}

unsafe impl Send for LinuxDesktopAgent {}

impl LinuxDesktopAgent {
    pub(super) fn new() -> anyhow::Result<Self> {
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
            seen_pids: HashSet::new(),
            seen_windows: HashSet::new(),
        })
    }

    pub(super) fn poll(&mut self) -> anyhow::Result<Vec<DesktopWindow>> {
        let windows = linux_client_windows(self.display, &self.atoms)?;
        let mut inventory = Vec::new();
        let mut current_windows = HashSet::new();
        let mut current_pids = HashSet::new();

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

impl Drop for LinuxDesktopAgent {
    fn drop(&mut self) {
        if !self.display.is_null() {
            unsafe {
                XCloseDisplay(self.display);
            }
        }
    }
}

// ── X11 screen capturer ───────────────────────────────────────────────────────

pub(super) struct LinuxX11Capturer {
    display: *mut XDisplay,
}

unsafe impl Send for LinuxX11Capturer {}

impl LinuxX11Capturer {
    pub(super) fn new() -> anyhow::Result<Self> {
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

impl Drop for LinuxX11Capturer {
    fn drop(&mut self) {
        if !self.display.is_null() {
            unsafe {
                XCloseDisplay(self.display);
            }
        }
    }
}

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

// ── Input injection ───────────────────────────────────────────────────────────

pub(super) fn inject_input_linux(
    attached_window_id: Option<u64>,
    event: &InputEvent,
) -> anyhow::Result<()> {
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

fn inject_linux_event(
    display: *mut XDisplay,
    target: &LinuxWindowTarget,
    event: &InputEvent,
) -> anyhow::Result<()> {
    unsafe {
        match event {
            InputEvent::Key { code, down } => {
                if let Some(keysym) = minifb_key_to_x11_keysym(*code) {
                    let keycode = XKeysymToKeycode(display, keysym);
                    if keycode == 0 {
                        return Ok(());
                    }
                    XSetInputFocus(display, target.window, REVERT_TO_POINTER_ROOT, CURRENT_TIME);
                    XRaiseWindow(display, target.window);
                    XTestFakeKeyEvent(display, keycode as u32, bool_to_x11(*down), CURRENT_TIME);
                }
            }
            InputEvent::MouseMove { x, y } => {
                let local_x = (*x).clamp(0, target.width.saturating_sub(1) as i32);
                let local_y = (*y).clamp(0, target.height.saturating_sub(1) as i32);
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
                XTestFakeButtonEvent(display, button_id, bool_to_x11(*down), CURRENT_TIME);
            }
            InputEvent::MouseWheel { dx, dy } => {
                if *dx > 0 {
                    for _ in 0..*dx {
                        XTestFakeButtonEvent(display, 7, TRUE, CURRENT_TIME);
                        XTestFakeButtonEvent(display, 7, FALSE, CURRENT_TIME);
                    }
                } else {
                    for _ in 0..(*dx).unsigned_abs() {
                        XTestFakeButtonEvent(display, 6, TRUE, CURRENT_TIME);
                        XTestFakeButtonEvent(display, 6, FALSE, CURRENT_TIME);
                    }
                }
                if *dy > 0 {
                    for _ in 0..*dy {
                        XTestFakeButtonEvent(display, 4, TRUE, CURRENT_TIME);
                        XTestFakeButtonEvent(display, 4, FALSE, CURRENT_TIME);
                    }
                } else {
                    for _ in 0..(*dy).unsigned_abs() {
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

fn bool_to_x11(value: bool) -> c_int {
    if value {
        TRUE
    } else {
        FALSE
    }
}

// ── Window inventory helpers ──────────────────────────────────────────────────

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
        .and_then(linux_process_name)
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

fn linux_should_exclude_inventory_window(process_name: &str, title: &str) -> bool {
    let process = normalize_linux_name(process_name);
    let title = normalize_linux_name(title);
    matches!(process.as_str(), "bolt" | "boltd")
        || process.contains("gnome-shell")
        || process.contains("plasmashell")
        || process.contains("xfdesktop")
        || title.contains("bolt gui stream")
}

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

fn normalize_linux_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn linux_process_name(pid: i64) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

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

// ── Window image capture ──────────────────────────────────────────────────────

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
        .ok_or_else(|| anyhow::anyhow!("XImage stride overflow"))?;
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

fn read_x11_pixel(bytes: &[u8], byte_order: c_int) -> u64 {
    let mut buf = [0_u8; 8];
    let len = bytes.len().min(buf.len());
    if byte_order == MSB_FIRST {
        let start = buf.len() - len;
        buf[start..].copy_from_slice(&bytes[..len]);
        u64::from_be_bytes(buf)
    } else {
        buf[..len].copy_from_slice(&bytes[..len]);
        u64::from_le_bytes(buf)
    }
}

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

// ── Key mapping ───────────────────────────────────────────────────────────────

fn minifb_key_to_x11_keysym(code: u32) -> Option<c_ulong> {
    Some(match code {
        0..=9 => XK_0 + code as c_ulong,
        10..=35 => XK_A + (code as c_ulong - 10),
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
        51 => XK_LEFT,
        52 => XK_RIGHT,
        53 => XK_UP,
        50 => XK_DOWN,
        54 => XK_APOSTROPHE,
        55 => XK_GRAVE,
        56 => XK_BACKSLASH,
        57 => XK_COMMA,
        58 => XK_EQUAL,
        59 => XK_BRACKETLEFT,
        60 => XK_MINUS,
        61 => XK_PERIOD,
        62 => XK_BRACKETRIGHT,
        63 => XK_SEMICOLON,
        64 => XK_SLASH,
        65 => XK_BACK_SPACE,
        66 => XK_DELETE,
        67 => XK_END,
        68 => XK_RETURN,
        69 => XK_ESCAPE,
        70 => XK_HOME,
        71 => XK_INSERT,
        72 => XK_MENU,
        73 => XK_PAGE_DOWN,
        74 => XK_PAGE_UP,
        75 => XK_PAUSE,
        76 => XK_SPACE,
        77 => XK_TAB,
        78 => XK_NUM_LOCK,
        79 => XK_CAPS_LOCK,
        80 => XK_SCROLL_LOCK,
        81 => XK_SHIFT_L,
        82 => XK_SHIFT_R,
        83 => XK_CONTROL_L,
        84 => XK_CONTROL_R,
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
        95 => XK_KP_DECIMAL,
        96 => XK_KP_DIVIDE,
        97 => XK_KP_MULTIPLY,
        98 => XK_KP_SUBTRACT,
        99 => XK_KP_ADD,
        100 => XK_KP_ENTER,
        101 => XK_ALT_L,
        102 => XK_ALT_R,
        103 => XK_SUPER_L,
        104 => XK_SUPER_R,
        _ => return None,
    })
}

fn initialize_xlib() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        XInitThreads();
    });
}

// ── Internal structs ──────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct LinuxWindowTarget {
    window: XWindow,
    root_x: i32,
    root_y: i32,
    width: u32,
    height: u32,
}

struct LinuxAtoms {
    net_client_list_stacking: XAtom,
    net_wm_pid: XAtom,
    wm_class: XAtom,
    net_wm_name: XAtom,
}

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

fn intern_x_atom(display: *mut XDisplay, name: &str) -> anyhow::Result<XAtom> {
    let c_name = std::ffi::CString::new(name).context("atom name contains NUL")?;
    let atom = unsafe { XInternAtom(display, c_name.as_ptr(), FALSE) };
    if atom == 0 {
        anyhow::bail!("XInternAtom returned 0 for {name}");
    }
    Ok(atom)
}

struct LinuxProperty {
    ptr: *mut c_uchar,
    items: c_ulong,
    format: i32,
}

impl Drop for LinuxProperty {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                XFree(self.ptr.cast());
            }
        }
    }
}

// ── X11 type aliases ──────────────────────────────────────────────────────────

type XWindow = c_ulong;
type XAtom = c_ulong;

enum XDisplay {}

#[repr(C)]
#[derive(Default)]
struct XWindowAttributes {
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
    border_width: c_int,
    depth: c_int,
    visual: *mut std::ffi::c_void,
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
    screen: *mut std::ffi::c_void,
}

#[repr(C)]
struct XImageFuncs {
    create_image: *mut std::ffi::c_void,
    destroy_image: *mut std::ffi::c_void,
    get_pixel: *mut std::ffi::c_void,
    put_pixel: *mut std::ffi::c_void,
    sub_image: *mut std::ffi::c_void,
    add_pixel: *mut std::ffi::c_void,
}

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

// ── X11 integer constants ─────────────────────────────────────────────────────

const FALSE: c_int = 0;
const TRUE: c_int = 1;
const X_SUCCESS: c_int = 0;
const ANY_PROPERTY_TYPE: XAtom = 0;
const CURRENT_TIME: c_ulong = 0;
const REVERT_TO_POINTER_ROOT: c_int = 1;
const IS_VIEWABLE: c_int = 2;
const Z_PIXMAP: c_int = 2;
const MSB_FIRST: c_int = 1;
const ALL_PLANES: c_ulong = !0;

// ── X11 keysym constants ──────────────────────────────────────────────────────

const XK_0: c_ulong = 0x0030;
const XK_A: c_ulong = 0x0061;
const XK_F1: c_ulong = 0xffbe;
const XK_F2: c_ulong = 0xffbf;
const XK_F3: c_ulong = 0xffc0;
const XK_F4: c_ulong = 0xffc1;
const XK_F5: c_ulong = 0xffc2;
const XK_F6: c_ulong = 0xffc3;
const XK_F7: c_ulong = 0xffc4;
const XK_F8: c_ulong = 0xffc5;
const XK_F9: c_ulong = 0xffc6;
const XK_F10: c_ulong = 0xffc7;
const XK_F11: c_ulong = 0xffc8;
const XK_F12: c_ulong = 0xffc9;
const XK_LEFT: c_ulong = 0xff51;
const XK_UP: c_ulong = 0xff52;
const XK_RIGHT: c_ulong = 0xff53;
const XK_DOWN: c_ulong = 0xff54;
const XK_PAGE_UP: c_ulong = 0xff55;
const XK_PAGE_DOWN: c_ulong = 0xff56;
const XK_END: c_ulong = 0xff57;
const XK_HOME: c_ulong = 0xff50;
const XK_BACK_SPACE: c_ulong = 0xff08;
const XK_RETURN: c_ulong = 0xff0d;
const XK_ESCAPE: c_ulong = 0xff1b;
const XK_TAB: c_ulong = 0xff09;
const XK_DELETE: c_ulong = 0xffff;
const XK_INSERT: c_ulong = 0xff63;
const XK_PAUSE: c_ulong = 0xff13;
const XK_MENU: c_ulong = 0xff67;
const XK_SPACE: c_ulong = 0x0020;
const XK_APOSTROPHE: c_ulong = 0x0027;
const XK_GRAVE: c_ulong = 0x0060;
const XK_BACKSLASH: c_ulong = 0x005c;
const XK_COMMA: c_ulong = 0x002c;
const XK_EQUAL: c_ulong = 0x003d;
const XK_BRACKETLEFT: c_ulong = 0x005b;
const XK_MINUS: c_ulong = 0x002d;
const XK_PERIOD: c_ulong = 0x002e;
const XK_BRACKETRIGHT: c_ulong = 0x005d;
const XK_SEMICOLON: c_ulong = 0x003b;
const XK_SLASH: c_ulong = 0x002f;
const XK_NUM_LOCK: c_ulong = 0xff7f;
const XK_CAPS_LOCK: c_ulong = 0xffe5;
const XK_SCROLL_LOCK: c_ulong = 0xff14;
const XK_SHIFT_L: c_ulong = 0xffe1;
const XK_SHIFT_R: c_ulong = 0xffe2;
const XK_CONTROL_L: c_ulong = 0xffe3;
const XK_CONTROL_R: c_ulong = 0xffe4;
const XK_ALT_L: c_ulong = 0xffe9;
const XK_ALT_R: c_ulong = 0xffea;
const XK_SUPER_L: c_ulong = 0xffeb;
const XK_SUPER_R: c_ulong = 0xffec;
const XK_KP_0: c_ulong = 0xffb0;
const XK_KP_1: c_ulong = 0xffb1;
const XK_KP_2: c_ulong = 0xffb2;
const XK_KP_3: c_ulong = 0xffb3;
const XK_KP_4: c_ulong = 0xffb4;
const XK_KP_5: c_ulong = 0xffb5;
const XK_KP_6: c_ulong = 0xffb6;
const XK_KP_7: c_ulong = 0xffb7;
const XK_KP_8: c_ulong = 0xffb8;
const XK_KP_9: c_ulong = 0xffb9;
const XK_KP_DECIMAL: c_ulong = 0xffae;
const XK_KP_DIVIDE: c_ulong = 0xffaf;
const XK_KP_MULTIPLY: c_ulong = 0xffaa;
const XK_KP_SUBTRACT: c_ulong = 0xffad;
const XK_KP_ADD: c_ulong = 0xffab;
const XK_KP_ENTER: c_ulong = 0xff8d;

// ── X11 / Xtst FFI ────────────────────────────────────────────────────────────

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
    fn XFree(data: *mut std::ffi::c_void) -> c_int;
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
