//! Encode/decode helpers: dirty-rect detection, patch extraction, UDP chunking,
//! and desktop inventory packet building.

use anyhow::{anyhow, Context as _};

use bolt_proto::{
    encode_udp_packet, DesktopInventoryChunk, DesktopWindow, Rect, UdpGuiPacket, VideoChunk,
    VideoCodec,
};

use super::{CapturedFrame, CHANNELS_RGB};

const UDP_SEND_PAYLOAD_BUDGET: usize = 900;

// ── Frame delta ───────────────────────────────────────────────────────────────

/// Returns the bounding box of changed pixels between two frames, or `None` if
/// the frames are identical.  Returns the full frame rect when there is no
/// previous frame or when the dimensions changed.
pub(super) fn detect_dirty_rect(prev: Option<&CapturedFrame>, curr: &CapturedFrame) -> Option<Rect> {
    if prev.is_none() {
        return Some(Rect {
            x: 0,
            y: 0,
            w: curr.width,
            h: curr.height,
        });
    }

    let prev = prev.expect("checked above");
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

/// Extract the raw RGB bytes for a sub-rectangle of a captured frame.
pub(super) fn extract_rgb_patch(frame: &CapturedFrame, rect: Rect) -> anyhow::Result<Vec<u8>> {
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

// ── UDP chunking ──────────────────────────────────────────────────────────────

/// Split a compressed patch into UDP-sized `VideoChunk`s.
pub(super) fn build_chunks(
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

// ── Inventory packet building ─────────────────────────────────────────────────

/// Serialize a window inventory into one or more UDP packets, chunking as
/// needed to stay under `MAX_UDP_PACKET_SIZE`.
pub(super) fn build_inventory_packets(
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
