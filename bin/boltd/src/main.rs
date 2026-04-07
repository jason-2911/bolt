//! boltd — Bolt protocol server daemon.
//!
//! Configuration file: /etc/bolt/boltd.toml (or ~/.bolt/boltd.toml)
//!
//! ```toml
//! listen = "0.0.0.0:2222"
//! max_connections = 1000
//! max_per_ip = 10
//! rate_limit_burst = 20
//! rate_limit_window_secs = 60
//! host_key = "/etc/bolt/host_key"
//! cert = "/etc/bolt/host_cert.der"
//! authorized_keys = "/etc/bolt/authorized_keys"
//! log_format = "text"
//! ```

use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use tokio::signal;
use tracing::info;

use bolt_log::{init as log_init, parse_format, Config as LogConfig};
use bolt_server::{
    gui::{run_gui_server, GuiServerConfig},
    Server, ServerConfig,
};

// ── CLI ───────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "boltd",
    about = "Bolt — Lightning-fast secure remote shell daemon",
    version
)]
struct Args {
    #[command(subcommand)]
    command: Option<Cmd>,

    /// Config file path
    #[arg(long)]
    config: Option<PathBuf>,

    /// Listen address (host:port)
    #[arg(long)]
    listen: Option<String>,

    /// Path to host private key
    #[arg(long)]
    host_key: Option<PathBuf>,

    /// Path to TLS certificate (auto-generated if missing)
    #[arg(long)]
    cert: Option<PathBuf>,

    /// Path to authorized keys file
    #[arg(long = "authorized-keys")]
    auth_keys: Option<PathBuf>,

    /// Maximum concurrent connections
    #[arg(long)]
    max_connections: Option<usize>,

    /// Max simultaneous connections per IP
    #[arg(long)]
    max_per_ip: Option<usize>,

    /// Path to trusted CA public keys file (one base64 key per line)
    #[arg(long = "ca-keys")]
    ca_keys: Option<PathBuf>,

    /// Log format: "text" or "json"
    #[arg(long = "log-format")]
    log_format: Option<String>,

    /// Verbose logging (debug level)
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// UDP GUI streaming server (video send + input receive)
    #[command(name = "gui")]
    Gui {
        /// UDP listen address on server
        #[arg(long, default_value = "0.0.0.0:5600")]
        listen: String,
        /// Optional fixed UDP client endpoint to stream video to
        #[arg(long)]
        client: Option<String>,
        /// Target FPS
        #[arg(long, default_value_t = 20)]
        fps: u32,
        /// Capture source: window|demo
        #[arg(long, default_value = "window")]
        source: String,
    },
}

// ── Config file ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    listen: Option<String>,
    max_connections: Option<usize>,
    max_per_ip: Option<usize>,
    rate_limit_burst: Option<usize>,
    rate_limit_window_secs: Option<u64>,
    host_key: Option<String>,
    cert: Option<String>,
    authorized_keys: Option<String>,
    ca_keys: Option<String>,
    log_format: Option<String>,
}

impl FileConfig {
    fn load(path: &std::path::Path) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => return Self::default(),
        };
        toml::from_str(&text).unwrap_or_else(|e| {
            eprintln!("boltd: warning: {} parse error: {e}", path.display());
            Self::default()
        })
    }
}

// ── Entry point ───────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(Cmd::Gui {
        listen,
        client,
        fps,
        source,
    }) = &args.command
    {
        log_init(LogConfig {
            level: if args.verbose {
                tracing::Level::DEBUG
            } else {
                tracing::Level::INFO
            },
            format: parse_format(args.log_format.as_deref().unwrap_or("text")),
        });

        return run_gui_server(GuiServerConfig {
            listen_addr: listen.clone(),
            client_addr: client.clone(),
            fps: *fps,
            source: source.clone(),
        })
        .await;
    }

    // Load config file
    let file_cfg = {
        let config_path = args.config.clone().or_else(|| {
            // Search order: /etc/bolt/boltd.toml, ~/.bolt/boltd.toml
            let etc = std::path::Path::new("/etc/bolt/boltd.toml");
            if etc.exists() {
                return Some(etc.to_path_buf());
            }
            dirs::home_dir().map(|h| h.join(".bolt/boltd.toml"))
        });
        config_path
            .as_deref()
            .map(FileConfig::load)
            .unwrap_or_default()
    };

    // Merge: CLI > config file > defaults
    let log_format_str = args
        .log_format
        .as_deref()
        .or(file_cfg.log_format.as_deref())
        .unwrap_or("text");

    log_init(LogConfig {
        level: if args.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        },
        format: parse_format(log_format_str),
    });

    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));

    let config = ServerConfig {
        listen_addr: args
            .listen
            .or(file_cfg.listen)
            .unwrap_or_else(|| "0.0.0.0:2222".into()),

        host_key_path: args
            .host_key
            .or_else(|| file_cfg.host_key.map(PathBuf::from))
            .unwrap_or_else(|| home.join(".bolt/host_key")),

        cert_path: args
            .cert
            .or_else(|| file_cfg.cert.map(PathBuf::from))
            .unwrap_or_else(|| home.join(".bolt/host_cert.der")),

        auth_keys_path: args
            .auth_keys
            .or_else(|| file_cfg.authorized_keys.map(PathBuf::from))
            .unwrap_or_else(|| home.join(".bolt/authorized_keys")),

        max_connections: args
            .max_connections
            .or(file_cfg.max_connections)
            .unwrap_or(1000),

        max_per_ip: args.max_per_ip.or(file_cfg.max_per_ip).unwrap_or(10),

        ca_keys_path: args.ca_keys.or_else(|| file_cfg.ca_keys.map(PathBuf::from)),

        rate_limit_window_secs: file_cfg.rate_limit_window_secs.unwrap_or(60),
        rate_limit_burst: file_cfg.rate_limit_burst.unwrap_or(20),
    };

    let server = Server::new(config).context("init server")?;

    // Built-in GUI UDP service (X-like streaming): no manual setup required.
    tokio::spawn(async {
        if let Err(e) = run_gui_server(GuiServerConfig {
            listen_addr: "0.0.0.0:5600".to_string(),
            client_addr: None,
            fps: 30,
            source: "window".to_string(),
        })
        .await
        {
            tracing::warn!(error = %e, "built-in GUI service stopped");
        }
    });

    tokio::select! {
        res = server.listen_and_serve() => res?,
        _ = signal::ctrl_c() => {
            info!("shutting down (SIGINT)");
        }
    }

    Ok(())
}
