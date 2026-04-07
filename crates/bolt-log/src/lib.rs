//! Unified structured logger for the Bolt protocol stack.
//!
//! Thin wrapper over `tracing` / `tracing-subscriber` providing:
//!   - one-shot initialisation with configurable level and format
//!   - component-scoped child loggers (`with_component`)
//!   - JSON and human-readable text output

use tracing::Level;
use tracing_subscriber::{fmt, EnvFilter};

/// Logger output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Text,
    Json,
}

/// Logger configuration.
pub struct Config {
    pub level:  Level,
    pub format: Format,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            level:  Level::WARN,
            format: Format::Text,
        }
    }
}

/// Initialise the global subscriber.
/// Must be called once at program start (before any `tracing::*` macros).
pub fn init(cfg: Config) {
    let filter = EnvFilter::new(cfg.level.as_str());

    match cfg.format {
        Format::Text => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .with_thread_ids(false)
                .init();
        }
        Format::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .with_target(true)
                .init();
        }
    }
}

/// Parse a format string ("json" | anything else → text).
pub fn parse_format(s: &str) -> Format {
    if s.eq_ignore_ascii_case("json") { Format::Json } else { Format::Text }
}

/// Re-export tracing macros so callers only need `bolt-log`.
pub use tracing::{debug, error, info, warn};
