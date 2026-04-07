//! Synthetic colour-cycling demo capturer — useful for testing without a display.

use tracing::debug;

use super::{CapturedFrame, Capturer, CHANNELS_RGB};

pub(super) struct DemoCapturer {
    width: u32,
    height: u32,
}

impl DemoCapturer {
    pub(super) fn new(width: u32, height: u32) -> Self {
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
