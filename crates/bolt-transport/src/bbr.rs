//! BBR congestion control state machine.
//!
//! States:  Startup → Drain → ProbeBW → ProbeRTT
//! Tracks bottleneck bandwidth (btl_bw) and minimum RTT (rt_prop).

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrState {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

impl std::fmt::Display for BbrState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Startup  => write!(f, "Startup"),
            Self::Drain    => write!(f, "Drain"),
            Self::ProbeBw  => write!(f, "ProbeBW"),
            Self::ProbeRtt => write!(f, "ProbeRTT"),
        }
    }
}

/// ProbeBW pacing-gain cycle: [1.25, 0.75, 1.0 × 6]
const PROBE_BW_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
const STARTUP_GAIN: f64 = 2.77;

#[derive(Debug)]
struct BwSample {
    bw: f64, // bytes/sec
    at: Instant,
}

pub struct Bbr {
    state: BbrState,

    // Core metrics
    btl_bw:      f64,          // bottleneck bandwidth (bytes/sec)
    rt_prop:     Duration,     // minimum RTT observed
    cwnd:        f64,          // congestion window (bytes)
    pacing_rate: f64,          // bytes/sec

    // Gains
    pacing_gain: f64,
    cwnd_gain:   f64,

    // Windowed max bandwidth (last N samples)
    bw_samples:    Vec<BwSample>,
    bw_window_size: usize,

    // RTT tracking
    rt_prop_expiry: Instant,
    last_rtt_probe: Instant,

    // ProbeBW cycle
    cycle_index: usize,
    cycle_start: Instant,

    // In-flight / delivered
    inflight:  i64,
    delivered: u64,

    // Startup exit detection
    full_bw_reached: bool,
    full_bw_count:   u32,
    last_bw:         f64,
}

impl Bbr {
    pub fn new() -> Self {
        let now = Instant::now();
        let mut bbr = Bbr {
            state:           BbrState::Startup,
            pacing_gain:     STARTUP_GAIN,
            cwnd_gain:       STARTUP_GAIN,
            btl_bw:          100_000.0,        // 100 KB/s initial estimate
            rt_prop:         Duration::from_millis(100),
            cwnd:            0.0,
            pacing_rate:     0.0,
            bw_samples:      Vec::new(),
            bw_window_size:  10,
            rt_prop_expiry:  now + Duration::from_secs(10),
            last_rtt_probe:  now,
            cycle_index:     0,
            cycle_start:     now,
            inflight:        0,
            delivered:       0,
            full_bw_reached: false,
            full_bw_count:   0,
            last_bw:         0.0,
        };
        bbr.update_cwnd();
        bbr
    }

    /// Update congestion window from current estimates.
    fn update_cwnd(&mut self) {
        let bdp = self.btl_bw * self.rt_prop.as_secs_f64();
        self.cwnd = self.cwnd_gain * bdp;
        if self.cwnd < 4096.0 {
            self.cwnd = 4096.0;
        }
        self.pacing_rate = self.pacing_gain * self.btl_bw;
    }

    /// Called on each ACK with the number of bytes delivered and the RTT sample.
    pub fn on_ack(&mut self, bytes_delivered: u64, rtt: Duration) {
        self.delivered += bytes_delivered;
        self.inflight -= bytes_delivered as i64;

        // Update minimum RTT
        let now = Instant::now();
        if rtt < self.rt_prop || now >= self.rt_prop_expiry {
            self.rt_prop = rtt;
            self.rt_prop_expiry = now + Duration::from_secs(10);
        }

        // Bandwidth sample: delivered / rtt
        if rtt.as_secs_f64() > 0.0 {
            let bw = bytes_delivered as f64 / rtt.as_secs_f64();
            self.bw_samples.push(BwSample { bw, at: now });
            if self.bw_samples.len() > self.bw_window_size {
                self.bw_samples.remove(0);
            }
            let max_bw = self.bw_samples.iter().map(|s| s.bw).fold(0.0_f64, f64::max);
            if max_bw > self.btl_bw {
                self.btl_bw = max_bw;
            }
        }

        // State machine transitions
        match self.state {
            BbrState::Startup => self.check_startup_exit(),
            BbrState::Drain => {
                if self.inflight as f64 <= self.bdp() {
                    self.enter_probe_bw(now);
                }
            }
            BbrState::ProbeBw => self.advance_cycle(now),
            BbrState::ProbeRtt => {
                if now >= self.last_rtt_probe + Duration::from_millis(200) {
                    self.last_rtt_probe = now;
                    self.enter_probe_bw(now);
                }
            }
        }

        self.update_cwnd();
    }

    fn bdp(&self) -> f64 {
        self.btl_bw * self.rt_prop.as_secs_f64()
    }

    fn check_startup_exit(&mut self) {
        if self.btl_bw <= self.last_bw * 1.25 {
            self.full_bw_count += 1;
            if self.full_bw_count >= 3 {
                self.full_bw_reached = true;
                self.state        = BbrState::Drain;
                self.pacing_gain  = 1.0 / STARTUP_GAIN;
                self.cwnd_gain    = STARTUP_GAIN;
            }
        } else {
            self.full_bw_count = 0;
        }
        self.last_bw = self.btl_bw;
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.state       = BbrState::ProbeBw;
        self.pacing_gain = PROBE_BW_GAINS[self.cycle_index];
        self.cwnd_gain   = 2.0;
        self.cycle_start = now;
    }

    fn advance_cycle(&mut self, now: Instant) {
        if now >= self.cycle_start + self.rt_prop {
            self.cycle_index = (self.cycle_index + 1) % PROBE_BW_GAINS.len();
            self.pacing_gain = PROBE_BW_GAINS[self.cycle_index];
            self.cycle_start = now;
        }
        // Check if we should probe RTT
        if now >= self.last_rtt_probe + Duration::from_secs(10) {
            self.state       = BbrState::ProbeRtt;
            self.pacing_gain = 0.75;
            self.cwnd_gain   = 0.75;
            self.last_rtt_probe = now;
        }
    }

    /// Return the maximum number of bytes allowed in-flight.
    pub fn congestion_window(&self) -> usize {
        self.cwnd.max(4096.0) as usize
    }

    /// Return the current pacing rate in bytes/sec.
    pub fn pacing_rate(&self) -> f64 {
        self.pacing_rate
    }

    /// Notify that `bytes` are now in-flight.
    pub fn on_send(&mut self, bytes: usize) {
        self.inflight += bytes as i64;
    }

    pub fn state(&self) -> BbrState { self.state }
}

impl Default for Bbr {
    fn default() -> Self { Self::new() }
}
