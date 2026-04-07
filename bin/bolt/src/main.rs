//! bolt — Lightning-fast secure remote shell.
//!
//! Usage:
//!   bolt user@host                          # interactive shell
//!   bolt user@host -c "ls -la"              # execute remote command
//!   bolt -J user@bastion user@host          # jump through bastion
//!   bolt -L 8080:localhost:80 user@host     # local port forward
//!   bolt -R 2222:localhost:22 user@host     # remote port forward
//!   bolt --agent user@host                  # SSH agent forwarding
//!   bolt cp file.txt user@host:/path        # upload file
//!   bolt cp user@host:/path ./local         # download file
//!   bolt cp -r dir/ user@host:/path         # upload directory
//!   bolt cp -p file user@host:/path         # upload, preserve timestamps
//!   bolt fs stat user@host:/path            # stat remote file
//!   bolt fs ls user@host:/path              # list remote directory
//!   bolt fs mv user@host:/old user@host:/new
//!   bolt fs rm [-r] user@host:/path
//!   bolt fs mkdir user@host:/path
//!   bolt fs chmod 755 user@host:/path
//!   bolt ca init                            # generate CA keypair
//!   bolt ca sign <user> [days]              # sign a user cert
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
    agent::request_agent_forward,
    client::{Client, ClientConfig},
    config::{parse_ssh_config, BoltConfig},
    exec::exec,
    forward::{run_local_forward, LocalForward},
    fs::{fs_chmod, fs_ls, fs_mkdir, fs_remove, fs_rename, fs_stat},
    gui_stream::{run_gui_client, GuiClientConfig},
    remote_forward::{run_remote_forward, RemoteForward},
    shell::shell,
    transfer::{download_opts, upload_opts},
    transfer_dir::{download_dir_opts, upload_dir_opts},
};
use bolt_crypto::{ca::BoltCert, keys::KeyPair};
use bolt_log::{init as log_init, Config as LogConfig};

// ── CLI ───────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "bolt",
    about = "Bolt — Lightning-fast secure remote shell",
    version
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

    /// Remote port forwarding: remote_port:local_host:local_port
    #[arg(short = 'R', long, global = true)]
    forward_remote: Option<String>,

    /// Enable SSH agent forwarding
    #[arg(long, global = true)]
    agent: bool,

    /// Enable GUI forwarding window (X-like over UDP stream)
    #[arg(short = 'X', long, global = true)]
    x11: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// UDP GUI streaming client (video receive + input send)
    #[command(name = "gui")]
    Gui {
        /// Local UDP listen address (client side)
        #[arg(long, default_value = "0.0.0.0:5601")]
        listen: String,
        /// Server UDP address
        #[arg(long, default_value = "127.0.0.1:5600")]
        server: String,
        /// GUI session token used to bind this GUI client to a remote shell
        #[arg(long, default_value = "")]
        token: String,
    },

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

    /// Remote filesystem operations: stat, ls, mv, rm, mkdir, chmod
    #[command(name = "fs")]
    Fs {
        #[command(subcommand)]
        op: FsOp,
    },

    /// Certificate authority operations: init, sign
    #[command(name = "ca")]
    Ca {
        #[command(subcommand)]
        op: CaOp,
    },

    /// Generate a new Ed25519 keypair
    #[command(name = "keygen")]
    Keygen {
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },

    /// Print shell completion script: bolt completions <bash|zsh|fish|powershell|elvish>
    #[command(name = "completions")]
    Completions { shell: Shell },

    /// Catch-all: bolt [user@host] [-c command]
    #[command(external_subcommand)]
    Remote(Vec<OsString>),
}

#[derive(Subcommand, Debug)]
enum FsOp {
    /// Print file metadata
    #[command(name = "stat")]
    Stat { target: String },

    /// List directory
    #[command(name = "ls")]
    Ls { target: String },

    /// Rename / move
    #[command(name = "mv")]
    Mv { from: String, to: String },

    /// Remove file or directory
    #[command(name = "rm")]
    Rm {
        target: String,
        #[arg(short = 'r', long)]
        recursive: bool,
    },

    /// Create directory
    #[command(name = "mkdir")]
    Mkdir {
        target: String,
        /// Octal permissions (default 755)
        #[arg(long, default_value_t = 0o755)]
        mode: u32,
    },

    /// Change file permissions
    #[command(name = "chmod")]
    Chmod {
        /// Octal mode, e.g. 644
        mode: String,
        target: String,
    },
}

#[derive(Subcommand, Debug)]
enum CaOp {
    /// Generate CA keypair → ~/.bolt/ca_key[.pub]
    #[command(name = "init")]
    Init {
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Sign a user certificate → ~/.bolt/certs/<user>.cert
    #[command(name = "sign")]
    Sign {
        /// Username to certify
        user: String,
        /// Path to the user's public key file
        #[arg(long)]
        pubkey: PathBuf,
        /// Validity in days (default 365)
        #[arg(long, default_value_t = 365)]
        days: u64,
        /// CA private key (default ~/.bolt/ca_key)
        #[arg(long)]
        ca_key: Option<PathBuf>,
        /// Output certificate path
        #[arg(long)]
        output: Option<PathBuf>,
    },
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
        level: if args.verbose {
            Level::DEBUG
        } else {
            Level::WARN
        },
        format: bolt_log::Format::Text,
    });

    match args.command {
        Cmd::Gui {
            ref listen,
            ref server,
            ref token,
        } => run_gui(listen, server, token).await,
        Cmd::Keygen { ref output } => run_keygen(output.as_deref()),
        Cmd::Completions { shell } => run_completions(shell),
        Cmd::Cp {
            ref source,
            ref dest,
            recursive,
            preserve,
        } => run_copy(&args, source, dest, recursive, preserve).await,
        Cmd::Fs { ref op } => run_fs(&args, op).await,
        Cmd::Ca { ref op } => run_ca(op),
        Cmd::Remote(ref remote_args) => run_remote(&args, remote_args).await,
    }
}

async fn run_gui(listen: &str, server: &str, token: &str) -> anyhow::Result<()> {
    run_gui_client(GuiClientConfig {
        listen_addr: listen.to_owned(),
        server_addr: server.to_owned(),
        token: token.to_owned(),
    })
    .await
}

// ── bolt user@host [-c command] [-L ...] [-R ...] [--agent] ──────────────

async fn run_remote(args: &Args, remote_args: &[OsString]) -> anyhow::Result<()> {
    if remote_args.is_empty() {
        bail!("usage: bolt user@host [-c command]");
    }

    let target = remote_args[0].to_str().context("invalid target encoding")?;
    let command = parse_remote_command(&remote_args[1..])?;

    let cfg = BoltConfig::load();
    let resolved = cfg.resolve_target(target, args.port, args.identity.as_deref());

    let jump = args.jump.as_deref().or(resolved.jump.as_deref());

    let client = make_client(args, &resolved.identity)?;

    let session = if let Some(jump_spec) = jump {
        client
            .connect_via_jump(jump_spec, &resolved.addr(), &resolved.user, args.port)
            .await?
    } else {
        client.connect(&resolved.addr(), &resolved.user).await?
    };

    let gui_token = if args.x11 {
        Some(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    } else {
        None
    };

    let mut gui_child = if let Some(gui_token) = gui_token.as_ref() {
        let gui_server = format!("{}:5600", resolved.host);
        eprintln!("bolt: GUI forwarding enabled -> {gui_server}");
        let exe = std::env::current_exe().context("resolve current bolt executable")?;
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("gui")
            .arg("--listen")
            .arg("0.0.0.0:5601")
            .arg("--server")
            .arg(gui_server)
            .arg("--token")
            .arg(gui_token);
        if args.verbose {
            cmd.arg("-v");
        }
        Some(cmd.spawn().context("spawn GUI forwarding process")?)
    } else {
        None
    };

    // SSH agent forwarding
    let _agent_handle = if args.agent {
        match request_agent_forward(&session).await {
            Ok(h) => {
                eprintln!("bolt: agent forwarding active");
                Some(h)
            }
            Err(e) => {
                eprintln!("bolt: agent forward failed: {e}");
                None
            }
        }
    } else {
        None
    };

    // Remote port forwarding: start in background
    if let Some(ref rfwd_spec) = args.forward_remote {
        let rfwd = RemoteForward::parse(rfwd_spec)?;
        let fwd_conn = session.conn.clone();
        tokio::spawn(async move {
            let s = bolt_client::client::Session { conn: fwd_conn };
            if let Err(e) = run_remote_forward(&s, rfwd).await {
                tracing::warn!("remote forward: {e}");
            }
        });
    }

    // Local port forwarding
    if let Some(ref fwd_spec) = args.forward_local {
        let fwd = LocalForward::parse(fwd_spec)?;

        if command.is_none() && args.forward_remote.is_none() {
            // -L only, no shell: just forward until Ctrl+C
            tokio::select! {
                res = run_local_forward(&session, fwd) => res?,
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("\nbolt: port forwarding stopped");
                }
            }
            return Ok(());
        }

        // -L with shell/command: forward in background
        let fwd_conn = session.conn.clone();
        tokio::spawn(async move {
            let s = bolt_client::client::Session { conn: fwd_conn };
            if let Err(e) = run_local_forward(&s, fwd).await {
                tracing::warn!("forward: {e}");
            }
        });
    }

    match command {
        Some(cmd) => {
            let code = exec(&session, &cmd).await?;
            process::exit(code);
        }
        None => {
            let extra_env = gui_token
                .as_ref()
                .map(|token| vec![("BOLT_GUI_TOKEN".to_string(), token.clone())])
                .unwrap_or_default();
            let res = shell(&session, &extra_env).await;
            if let Some(child) = gui_child.as_mut() {
                let _ = child.kill();
            }
            res
        }
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

    let unknown: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
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

// ── bolt fs ───────────────────────────────────────────────────────────────

async fn run_fs(args: &Args, op: &FsOp) -> anyhow::Result<()> {
    let cfg = BoltConfig::load();

    match op {
        FsOp::Stat { target } => {
            let (user, host, path) = parse_remote_path(target)?;
            let session = connect_for_host(args, &cfg, &user, &host).await?;
            fs_stat(&session, &path).await
        }
        FsOp::Ls { target } => {
            let (user, host, path) = parse_remote_path(target)?;
            let session = connect_for_host(args, &cfg, &user, &host).await?;
            fs_ls(&session, &path).await
        }
        FsOp::Mv { from, to } => {
            // Both must be on the same host (parsed from `from`)
            let (user, host, from_path) = parse_remote_path(from)?;
            let (_, _, to_path) =
                parse_remote_path(to).unwrap_or_else(|_| (user.clone(), host.clone(), to.clone()));
            let session = connect_for_host(args, &cfg, &user, &host).await?;
            fs_rename(&session, &from_path, &to_path).await
        }
        FsOp::Rm { target, recursive } => {
            let (user, host, path) = parse_remote_path(target)?;
            let session = connect_for_host(args, &cfg, &user, &host).await?;
            fs_remove(&session, &path, *recursive).await
        }
        FsOp::Mkdir { target, mode } => {
            let (user, host, path) = parse_remote_path(target)?;
            let session = connect_for_host(args, &cfg, &user, &host).await?;
            fs_mkdir(&session, &path, *mode).await
        }
        FsOp::Chmod { mode, target } => {
            let mode_val = u32::from_str_radix(mode, 8)
                .with_context(|| format!("invalid octal mode: {mode}"))?;
            let (user, host, path) = parse_remote_path(target)?;
            let session = connect_for_host(args, &cfg, &user, &host).await?;
            fs_chmod(&session, &path, mode_val).await
        }
    }
}

async fn connect_for_host(
    args: &Args,
    cfg: &BoltConfig,
    user: &str,
    host: &str,
) -> anyhow::Result<bolt_client::client::Session> {
    let target = format!("{user}@{host}");
    let resolved = cfg.resolve_target(&target, args.port, args.identity.as_deref());
    let addr = format!("{}:{}", resolved.host, resolved.port);
    let client = make_client(args, &resolved.identity)?;
    client.connect(&addr, &resolved.user).await
}

// ── bolt ca ───────────────────────────────────────────────────────────────

fn run_ca(op: &CaOp) -> anyhow::Result<()> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));

    match op {
        CaOp::Init { output } => {
            let key_path = output.clone().unwrap_or_else(|| home.join(".bolt/ca_key"));
            let ca = KeyPair::generate().context("generate CA keypair")?;
            ca.save(&key_path).context("save CA key")?;

            eprintln!("CA private key:  {}", key_path.display());
            eprintln!("CA public key:   {}.pub", key_path.display());
            eprintln!("Fingerprint:     {}", ca.fingerprint());
            eprintln!();
            eprintln!("Add the CA public key to boltd's trusted keys:");
            eprintln!(
                "  echo $(cat {}.pub) >> ~/.bolt/ca_keys",
                key_path.display()
            );

            Ok(())
        }

        CaOp::Sign {
            user,
            pubkey,
            days,
            ca_key,
            output,
        } => {
            let ca_key_path = ca_key.clone().unwrap_or_else(|| home.join(".bolt/ca_key"));

            let ca = KeyPair::load(&ca_key_path)
                .with_context(|| format!("load CA key: {}", ca_key_path.display()))?;

            // Load user's public key (raw 32-byte or base64)
            let pubkey_bytes = std::fs::read(pubkey)
                .with_context(|| format!("read pubkey: {}", pubkey.display()))?;
            let user_public_key = parse_public_key(&pubkey_bytes)?;

            let cert =
                BoltCert::sign(user, user_public_key, *days, &ca).context("sign certificate")?;

            let cert_path = output
                .clone()
                .unwrap_or_else(|| BoltCert::default_path(user));

            cert.save(&cert_path)
                .with_context(|| format!("save cert: {}", cert_path.display()))?;

            eprintln!("Certificate:  {}", cert_path.display());
            eprintln!("User:         {user}");
            eprintln!("Valid for:    {days} days");
            Ok(())
        }
    }
}

fn parse_public_key(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    // Try raw 32 bytes first
    if bytes.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(bytes);
        return Ok(k);
    }
    // Try base64 (with or without trailing newline)
    let trimmed = std::str::from_utf8(bytes)?.trim();
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed)
        .context("decode public key as base64")?;
    if decoded.len() != 32 {
        bail!("public key must be 32 bytes (got {})", decoded.len());
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&decoded);
    Ok(k)
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

fn make_client(args: &Args, config_identity: &Option<PathBuf>) -> anyhow::Result<Client> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let identity_file = args
        .identity
        .clone()
        .or_else(|| config_identity.clone())
        .unwrap_or_else(|| home.join(".bolt/id_bolt"));

    let _ssh_hosts = parse_ssh_config();

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
