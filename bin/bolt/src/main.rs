//! bolt — Lightning-fast secure remote shell.
//!
//! Usage:
//!   bolt user@host                          # interactive shell
//!   bolt user@host -c "ls -la"              # execute remote command
//!   bolt -J user@bastion user@host          # jump through bastion
//!   bolt -L 8080:localhost:80 user@host     # local port forward
//!   bolt cp file.txt user@host:/path        # upload file
//!   bolt cp user@host:/path ./local         # download file
//!   bolt cp -r dir/ user@host:/path         # upload directory
//!   bolt cp -p file user@host:/path         # upload, preserve timestamps
//!   bolt keygen                             # generate Ed25519 keypair
//!   bolt completions bash                   # shell completion script

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{bail, Context as _};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use tracing::Level;

use bolt_client::{
    client::{Client, ClientConfig},
    config::{BoltConfig, parse_ssh_config},
    exec::exec,
    forward::{run_local_forward, LocalForward},
    shell::shell,
    transfer::{download_opts, upload_opts},
    transfer_dir::{download_dir_opts, upload_dir_opts},
};
use bolt_crypto::keys::KeyPair;
use bolt_log::{init as log_init, Config as LogConfig};

// ── CLI ───────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "bolt",
    about = "Bolt — Lightning-fast secure remote shell",
    version,
)]
struct Args {
    /// Identity (private key) file
    #[arg(short = 'i', long, global = true)]
    identity: Option<PathBuf>,

    /// Remote port
    #[arg(short = 'p', long, default_value_t = 2222, global = true)]
    port: u16,

    /// Verbose output (debug level)
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    /// Jump host: user@host[:port]
    #[arg(short = 'J', long, global = true)]
    jump: Option<String>,

    /// Local port forwarding: local_port:remote_host:remote_port
    #[arg(short = 'L', long, global = true)]
    forward_local: Option<String>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Copy files/directories: bolt cp [-r] [-p] <src> <dest>
    #[command(name = "cp")]
    Cp {
        source: String,
        dest: String,
        /// Recursive directory copy
        #[arg(short = 'r', long)]
        recursive: bool,
        /// Preserve file timestamps
        #[arg(short = 'p', long)]
        preserve: bool,
    },

    /// Generate a new Ed25519 keypair
    #[command(name = "keygen")]
    Keygen {
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },

    /// Print shell completion script: bolt completions <bash|zsh|fish|powershell|elvish>
    #[command(name = "completions")]
    Completions {
        shell: Shell,
    },

    /// Catch-all: bolt [user@host] [-c command]
    #[command(external_subcommand)]
    Remote(Vec<OsString>),
}

// ── Entry point ───────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("bolt: {e:#}");
        process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    log_init(LogConfig {
        level: if args.verbose { Level::DEBUG } else { Level::WARN },
        format: bolt_log::Format::Text,
    });

    match args.command {
        Cmd::Keygen { ref output } => run_keygen(output.as_deref()),
        Cmd::Completions { shell } => run_completions(shell),
        Cmd::Cp { ref source, ref dest, recursive, preserve } => {
            run_copy(&args, source, dest, recursive, preserve).await
        }
        Cmd::Remote(ref remote_args) => run_remote(&args, remote_args).await,
    }
}

// ── bolt user@host [-c command] [-L ...] ─────────────────────────────────

async fn run_remote(args: &Args, remote_args: &[OsString]) -> anyhow::Result<()> {
    if remote_args.is_empty() {
        bail!("usage: bolt user@host [-c command]");
    }

    let target = remote_args[0].to_str().context("invalid target encoding")?;
    let command = parse_remote_command(&remote_args[1..])?;

    let cfg = BoltConfig::load();
    let resolved = cfg.resolve_target(target, args.port, args.identity.as_deref());

    // Merge jump: CLI -J overrides config
    let jump = args.jump.as_deref().or(resolved.jump.as_deref());

    let client = make_client(args, &resolved.identity)?;

    let session = if let Some(jump_spec) = jump {
        client
            .connect_via_jump(jump_spec, &resolved.addr(), &resolved.user, args.port)
            .await?
    } else {
        client.connect(&resolved.addr(), &resolved.user).await?
    };

    // Local port forwarding: start in background, then run shell/exec
    if let Some(ref fwd_spec) = args.forward_local {
        let fwd = LocalForward::parse(fwd_spec)?;

        if command.is_none() {
            // -L only, no shell: just forward until Ctrl+C
            tokio::select! {
                res = run_local_forward(&session, fwd) => res?,
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("\nbolt: port forwarding stopped");
                }
            }
            return Ok(());
        }

        // -L with -c: forward in background, run command
        let fwd_session_conn = session.conn.clone();
        tokio::spawn(async move {
            let fwd_session = bolt_client::client::Session { conn: fwd_session_conn };
            if let Err(e) = run_local_forward(&fwd_session, fwd).await {
                tracing::warn!("forward: {e}");
            }
        });
    }

    match command {
        Some(cmd) => {
            let code = exec(&session, &cmd).await?;
            process::exit(code);
        }
        None => shell(&session).await,
    }
}

fn parse_remote_command(args: &[OsString]) -> anyhow::Result<Option<String>> {
    if args.is_empty() {
        return Ok(None);
    }

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let s = arg.to_string_lossy();
        if s == "-c" {
            let cmd_parts: Vec<String> = iter.map(|a| a.to_string_lossy().into_owned()).collect();
            if cmd_parts.is_empty() {
                bail!("-c requires a command argument");
            }
            return Ok(Some(cmd_parts.join(" ")));
        }
    }

    let unknown: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    bail!(
        "unknown arguments: {}. Use -c to run a command: bolt user@host -c \"command\"",
        unknown.join(" ")
    );
}

// ── bolt cp ───────────────────────────────────────────────────────────────

async fn run_copy(
    args: &Args,
    source: &str,
    dest: &str,
    recursive: bool,
    preserve: bool,
) -> anyhow::Result<()> {
    let src_remote = is_remote_path(source);
    let dst_remote = is_remote_path(dest);

    if src_remote && dst_remote {
        bail!("cannot copy between two remote hosts");
    }
    if !src_remote && !dst_remote {
        bail!("one of source/dest must be remote (user@host:path)");
    }

    let cfg = BoltConfig::load();

    if dst_remote {
        let (user, host, remote_path) = parse_remote_path(dest)?;
        let target = format!("{user}@{host}");
        let resolved = cfg.resolve_target(&target, args.port, args.identity.as_deref());
        let addr = format!("{}:{}", resolved.host, resolved.port);
        let client = make_client(args, &resolved.identity)?;
        let session = client.connect(&addr, &resolved.user).await?;
        let local = Path::new(source);

        if recursive || local.is_dir() {
            upload_dir_opts(&session, local, &remote_path, preserve).await
        } else {
            upload_opts(&session, local, &remote_path, preserve).await
        }
    } else {
        let (user, host, remote_path) = parse_remote_path(source)?;
        let target = format!("{user}@{host}");
        let resolved = cfg.resolve_target(&target, args.port, args.identity.as_deref());
        let addr = format!("{}:{}", resolved.host, resolved.port);
        let client = make_client(args, &resolved.identity)?;
        let session = client.connect(&addr, &resolved.user).await?;
        let local = Path::new(dest);

        if recursive {
            download_dir_opts(&session, &remote_path, local, preserve).await
        } else {
            download_opts(&session, &remote_path, local, preserve).await
        }
    }
}

// ── bolt keygen ───────────────────────────────────────────────────────────

fn run_keygen(output: Option<&Path>) -> anyhow::Result<()> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(".bolt/id_bolt"));

    let kp = KeyPair::generate().context("keygen")?;
    kp.save(&path).context("save keypair")?;

    eprintln!("Identity key:  {}", path.display());
    eprintln!("Public key:    {}.pub", path.display());
    eprintln!("Fingerprint:   {}", kp.fingerprint());
    Ok(())
}

// ── bolt completions ──────────────────────────────────────────────────────

fn run_completions(shell: Shell) -> anyhow::Result<()> {
    let mut cmd = Args::command();
    let bin_name = cmd.get_name().to_owned();
    clap_complete::generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
    std::io::stdout().flush().ok();
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn make_client(
    args: &Args,
    config_identity: &Option<PathBuf>,
) -> anyhow::Result<Client> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let identity_file = args
        .identity
        .clone()
        .or_else(|| config_identity.clone())
        .unwrap_or_else(|| home.join(".bolt/id_bolt"));

    // Also merge SSH config entries as fallback
    let _ssh_hosts = parse_ssh_config(); // available for future host alias merging

    Client::new(ClientConfig {
        identity_file,
        known_hosts: home.join(".bolt/known_hosts"),
    })
}

fn is_remote_path(s: &str) -> bool {
    if let Some(at_pos) = s.find('@') {
        s[at_pos..].contains(':')
    } else {
        false
    }
}

fn parse_remote_path(s: &str) -> anyhow::Result<(String, String, String)> {
    let Some(at) = s.find('@') else {
        bail!("remote path must be user@host:path (got: {s})");
    };
    let user = &s[..at];
    let rest = &s[at + 1..];
    let Some(colon) = rest.find(':') else {
        bail!("remote path must be user@host:path (got: {s})");
    };
    let host = &rest[..colon];
    let path = &rest[colon + 1..];

    if user.is_empty() || host.is_empty() {
        bail!("user and host cannot be empty");
    }

    let path = if path.is_empty() { "." } else { path };
    Ok((user.to_owned(), host.to_owned(), path.to_owned()))
}
