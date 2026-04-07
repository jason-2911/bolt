//! bolt — Bolt protocol client CLI.

use std::path::{Path, PathBuf};
use std::process;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use tracing::Level;

use bolt_client::{
    client::{Client, ClientConfig},
    exec::exec,
    shell::shell,
    transfer::{download, upload},
    transfer_dir::{download_dir, upload_dir},
};
use bolt_crypto::keys::KeyPair;
use bolt_log::{init as log_init, Config as LogConfig, parse_format};

const VERSION: &str = concat!("bolt ", env!("CARGO_PKG_VERSION"));

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name    = "bolt",
    about   = "Bolt — Lightning-fast secure remote shell",
    version,
)]
struct Args {
    /// Identity (private key) file
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Remote port
    #[arg(short = 'p', long, default_value_t = 2222)]
    port: u16,

    /// Verbose output (debug level)
    #[arg(short = 'v', long)]
    verbose: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Open an interactive shell on [user@]host
    #[command(name = "shell", alias = "s")]
    Shell {
        /// [user@]host
        target: String,
    },

    /// Execute a remote command: bolt exec [user@]host -- <cmd>
    #[command(name = "exec", alias = "e")]
    Exec {
        target:  String,
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Copy files/directories (like scp -r)
    #[command(name = "cp")]
    Cp {
        /// Source (local path or [user@]host:path)
        source: String,
        /// Destination (local path or [user@]host:path)
        dest:   String,

        /// Recursive directory copy
        #[arg(short = 'r', long)]
        recursive: bool,
    },

    /// Generate a new Curve25519 keypair
    #[command(name = "keygen")]
    Keygen {
        /// Output path for the private key (default: ~/.bolt/id_bolt)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
}

// ── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("bolt: {e}");
        process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    log_init(LogConfig {
        level:  if args.verbose { Level::DEBUG } else { Level::WARN },
        format: bolt_log::Format::Text,
    });

    match &args.command {
        Cmd::Keygen { output } => {
            run_keygen(output.as_deref())?;
        }

        Cmd::Shell { target } => {
            let client = make_client(&args)?;
            let (_, host) = parse_target(target);
            let addr      = format!("{}:{}", host, args.port);
            let session   = client.connect(&addr).await?;
            shell(&session).await?;
        }

        Cmd::Exec { target, command } => {
            let client  = make_client(&args)?;
            let (_, host) = parse_target(target);
            let addr      = format!("{}:{}", host, args.port);
            let cmd       = command.join(" ");
            let session   = client.connect(&addr).await?;
            let code      = exec(&session, &cmd).await?;
            process::exit(code);
        }

        Cmd::Cp { source, dest, recursive } => {
            run_copy(&args, source, dest, *recursive).await?;
        }
    }

    Ok(())
}

// ── Subcommand implementations ─────────────────────────────────────────────

fn run_keygen(output: Option<&Path>) -> anyhow::Result<()> {
    let home = dirs_home();
    let path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| home.join(".bolt/id_bolt"));

    let kp = KeyPair::generate().context("keygen")?;
    kp.save(&path).context("save keypair")?;

    println!("Identity key:  {}", path.display());
    println!("Public key:    {}.pub", path.display());
    println!("Fingerprint:   {}", kp.public_key_string());
    Ok(())
}

async fn run_copy(args: &Args, source: &str, dest: &str, recursive: bool) -> anyhow::Result<()> {
    let src_remote = source.contains(':');
    let dst_remote = dest.contains(':');

    if src_remote && dst_remote {
        anyhow::bail!("cannot copy between two remote hosts");
    }
    if !src_remote && !dst_remote {
        anyhow::bail!("one of source/destination must be remote (user@host:path)");
    }

    let client = make_client(args)?;

    if dst_remote {
        // Upload: local → remote
        let (remote_target, remote_path) = parse_remote_path(dest);
        let (_, host) = parse_target(&remote_target);
        let addr      = format!("{}:{}", host, args.port);
        let session   = client.connect(&addr).await?;
        let local     = Path::new(source);

        if recursive || local.is_dir() {
            upload_dir(&session, local, &remote_path).await?;
        } else {
            upload(&session, local, &remote_path).await?;
            let size = std::fs::metadata(source).map(|m| m.len()).unwrap_or(0);
            eprintln!("bolt: {} → {}:{} ({})", source, host, remote_path, fmt_bytes(size as i64));
        }
    } else {
        // Download: remote → local
        let (remote_target, remote_path) = parse_remote_path(source);
        let (_, host) = parse_target(&remote_target);
        let addr      = format!("{}:{}", host, args.port);
        let session   = client.connect(&addr).await?;
        let local     = Path::new(dest);

        if recursive {
            download_dir(&session, &remote_path, local).await?;
        } else {
            download(&session, &remote_path, local).await?;
        }
    }
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn make_client(args: &Args) -> anyhow::Result<Client> {
    let home = dirs_home();
    let mut config = ClientConfig::default();
    if let Some(id) = &args.identity {
        config.identity_file = id.clone();
    }
    Client::new(config)
}

/// Split "user@host" into (user, host). Returns ("", host) if no @.
fn parse_target(target: &str) -> (String, String) {
    if let Some(at) = target.find('@') {
        (target[..at].to_owned(), target[at + 1..].to_owned())
    } else {
        (String::new(), target.to_owned())
    }
}

/// Split "user@host:path" into ("user@host", "path").
fn parse_remote_path(s: &str) -> (String, String) {
    if let Some(colon) = s.find(':') {
        (s[..colon].to_owned(), s[colon + 1..].to_owned())
    } else {
        (s.to_owned(), ".".to_owned())
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn fmt_bytes(b: i64) -> String {
    match b.unsigned_abs() {
        n if n >= 1 << 30 => format!("{:.2} GB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.2} MB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.2} KB", n as f64 / (1u64 << 10) as f64),
        n                  => format!("{} B", n),
    }
}
