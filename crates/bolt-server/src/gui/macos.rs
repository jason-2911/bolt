//! macOS screen capture using CoreGraphics / CoreFoundation APIs.

use std::ffi::c_void;

use anyhow::anyhow;

use super::{CapturedFrame, Capturer, CHANNELS_RGB};

const GUI_CLAIM_DIR: &str = "/tmp/bolt-gui-claims";

// ── Capturer impl ─────────────────────────────────────────────────────────────

pub(super) struct MacWindowCapturer;

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

// ── Claim-based capture ───────────────────────────────────────────────────────

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

// ── CGImage decoding ──────────────────────────────────────────────────────────

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

// ── Claim file reader ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct GuiClaim {
    owner_name: String,
    pid: Option<i64>,
}

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

fn read_gui_claim(token: &str) -> anyhow::Result<Option<GuiClaim>> {
    use anyhow::Context as _;
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

// ── macOS window info ─────────────────────────────────────────────────────────

struct MacWindowTarget {
    window_id: u32,
    bounds: CGRect,
}

struct MacWindowInfo {
    owner_name: String,
    owner_pid: i64,
    window_id: u32,
    layer: i64,
    bounds: CGRect,
}

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

// ── CoreFoundation / CoreGraphics types ───────────────────────────────────────

type CFTypeRef = *const c_void;
type CFArrayRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFStringRef = *const c_void;
type CFDataRef = *const c_void;
type CFNumberRef = *const c_void;
type CGImageRef = *const c_void;
type CGDataProviderRef = *const c_void;

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_CF_NUMBER_SINT64_TYPE: i32 = 4;
const K_CF_NUMBER_FLOAT64_TYPE: i32 = 6;
const K_CG_WINDOW_LIST_OPTION_ON_SCREEN_ONLY: u32 = 1 << 0;
const K_CG_WINDOW_LIST_OPTION_INCLUDING_WINDOW: u32 = 1 << 3;
const K_CG_WINDOW_LIST_EXCLUDE_DESKTOP_ELEMENTS: u32 = 1 << 4;
const K_CG_WINDOW_IMAGE_BOUNDS_IGNORE_FRAMING: u32 = 1 << 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct CGPoint {
    x: f64,
    y: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CGSize {
    width: f64,
    height: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CGRect {
    origin: CGPoint,
    size: CGSize,
}

// ── CoreFoundation / ApplicationServices FFI ──────────────────────────────────

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
