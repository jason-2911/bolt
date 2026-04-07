//! boltd — Bolt protocol server daemon.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;
use tokio::signal;
use tracing::info;

use bolt_log::{init as log_init, Config as LogConfig, Format, parse_format};
use bolt_server::{Server, ServerConfig};

const VERSION: &str = concat!("boltd ", env!("CARGO_PKG_VERSION"));

#[derive(Parser, Debug)]
#[command(name = "boltd", about = "Bolt — Lightning-fast secure remote shell daemon")]
struct Args {
    /// Listen address (host:port)
    #[arg(long, default_value = "0.0.0.0:2222")]
    listen: String,

    /// Path to host private key
    #[arg(long, default_value = "/etc/bolt/host_key")]
    host_key: PathBuf,

    /// Path to authorized keys file
    #[arg(long = "authorized-keys", default_value = "/etc/bolt/authorized_keys")]
    auth_keys: PathBuf,

    /// Maximum concurrent connections
    #[arg(long, default_value_t = 1000)]
    max_connections: usize,

    /// Log format: "text" or "json"
    #[arg(long = "log-format", default_value = "text")]
    log_format: String,

    /// Verbose logging (debug level)
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Print version and exit
    #[arg(long)]
    version: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.version {
        println!("{VERSION}");
        return Ok(());
    }

    log_init(LogConfig {
        level:  if args.verbose { tracing::Level::DEBUG } else { tracing::Level::INFO },
        format: parse_format(&args.log_format),
    });

    let config = ServerConfig {
        listen_addr:     args.listen,
        host_key_path:   args.host_key,
        auth_keys_path:  args.auth_keys,
        max_connections: args.max_connections,
        ..Default::default()
    };

    let server = Server::new(config).context("init server")?;

    tokio::select! {
        res = server.listen_and_serve() => res?,
        _ = signal::ctrl_c() => {
            info!(component = "server", "shutting down (SIGINT)");
        }
    }

    Ok(())
}
