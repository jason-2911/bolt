//! Per-IP rate limiting and connection tracking.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Tracks connection counts and recent connect timestamps per IP.
pub struct RateLimiter {
    inner: Mutex<Inner>,
    max_per_ip: usize,
    window: Duration,
    window_limit: usize,
}

struct Inner {
    /// Current active connection count per IP.
    active: HashMap<IpAddr, usize>,
    /// Recent connect timestamps per IP (for rate limiting).
    recent: HashMap<IpAddr, Vec<Instant>>,
}

impl RateLimiter {
    /// `max_per_ip` — max simultaneous connections from one IP.
    /// `window_limit` — max new connections per IP within `window`.
    pub fn new(max_per_ip: usize, window: Duration, window_limit: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                active: HashMap::new(),
                recent: HashMap::new(),
            }),
            max_per_ip,
            window,
            window_limit,
        }
    }

    /// Returns `Ok(())` if the connection is allowed, `Err(reason)` if denied.
    pub fn check_and_admit(&self, ip: IpAddr) -> Result<(), &'static str> {
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();

        // Clean up old timestamps and check rate limit
        {
            let recent = g.recent.entry(ip).or_default();
            recent.retain(|t| now.duration_since(*t) < self.window);
            if recent.len() >= self.window_limit {
                return Err("too many connections from your IP");
            }
        }

        // Max simultaneous connections per IP
        {
            let active = g.active.entry(ip).or_default();
            if *active >= self.max_per_ip {
                return Err("max simultaneous connections per IP exceeded");
            }
            *active += 1;
        }

        g.recent.entry(ip).or_default().push(now);
        Ok(())
    }

    /// Call when a connection from this IP closes.
    pub fn release(&self, ip: IpAddr) {
        let mut g = self.inner.lock().unwrap();
        if let Some(count) = g.active.get_mut(&ip) {
            *count = count.saturating_sub(1);
        }
    }
}
