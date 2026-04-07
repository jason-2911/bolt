# Bolt

**Lightning-fast secure remote shell — QUIC/TLS 1.3, rsync delta sync, SSH-style UX**

---

## Quick Info

| | |
|---|---|
| **Binaries** | `bolt` (client), `boltd` (server daemon) |
| **Language** | Rust 2021 |
| **Transport** | QUIC (quinn 0.11) over UDP |
| **Crypto** | TLS 1.3 (rustls 0.23) + Ed25519 (rcgen 0.13) |
| **Protocol** | bincode length-prefixed messages over QUIC streams |
| **File sync** | rsync-style delta (fast_rsync) + zstd compression |
| **Default port** | 2222/UDP |

---

## Quick Start

### Build

```bash
git clone https://github.com/jason-2911/bolt
cd bolt
cargo build --release
# binaries: target/release/bolt  target/release/boltd
```

### Generate client keypair

```bash
bolt keygen
# → ~/.bolt/id_bolt (private)
# → ~/.bolt/id_bolt.pub (public)
```

### Start server

```bash
# First run: auto-generates host key + TLS cert
boltd

# Custom options
boltd --listen 0.0.0.0:2222 \
      --host-key /etc/bolt/host_key \
      --authorized-keys /etc/bolt/authorized_keys

# With config file
boltd --config /etc/bolt/boltd.toml
```

### Add client public key to server

```bash
cat ~/.bolt/id_bolt.pub >> ~/.bolt/authorized_keys
```

---

## CLI Reference

### Shell & Exec

```bash
# Interactive shell
bolt user@host

# Execute remote command
bolt user@host -c "ls -la /tmp"

# Custom port / identity
bolt -p 2222 -i ~/.bolt/id_bolt user@host

# Verbose (debug logging)
bolt -v user@host
```

### UDP GUI Forwarding (`-X`)

```bash
# Server: just run boltd (built-in GUI UDP service is started automatically)
boltd

# Client: SSH-X style usage (auth + shell + GUI window forwarding)
bolt -X -i ~/.bolt/id_bolt user@host

# Optional: standalone GUI mode
boltd gui --listen 0.0.0.0:5600 --source window
bolt gui --listen 0.0.0.0:5601 --server <SERVER_IP>:5600
```

Notes:
- Video path is one-way server→client over UDP chunks (no per-frame round-trip).
- Input path is one-way client→server over UDP.
- `bolt -X ...` does not force a window by itself. The desktop agent publishes attachable windows; the client opens its local window when inventory or streamed video arrives.
- On Linux/X11, `boltd` must run inside the same X11 session as the GUI apps it launches, with valid `DISPLAY` and `XAUTHORITY`.
- On Linux/X11, a desktop agent tracks new processes and windows, maps PID↔window, and publishes an inventory to the client.
- On Linux/X11, the client selector uses `Up`/`Down`/`PageUp`/`PageDown`/`Home`/`End` to move and `Enter` to attach. `F6` detaches. `F7`/`F8` switch between known windows while attached.
- On Linux/X11, input is injected into the attached target window via XTest (`libXtst`).
- On macOS, server process needs Screen Recording permission to capture display.

### Jump Host (Bastion)

```bash
# Connect through a bastion server
bolt -J admin@bastion.example.com user@internal-host

# Jump host uses same port as target by default
bolt -J admin@bastion:2223 user@internal -p 2222
```

### Port Forwarding

```bash
# Local forward: 127.0.0.1:8080 → remote localhost:80
bolt -L 8080:localhost:80 user@host

# Only forwarding, no shell
bolt -L 5432:db-host:5432 user@host

# Forward in background + run command
bolt -L 8080:localhost:80 user@host -c "echo forwarding active && sleep 3600"

# Remote forward: server binds :2222, tunnels to localhost:22
bolt -R 2222:localhost:22 user@host
```

### SSH Agent Forwarding

```bash
# Forward your local SSH agent to the remote session
bolt --agent user@host

# Useful for Git operations via SSH on the remote host
bolt --agent user@host -c "git clone git@github.com:org/repo"
```

### Filesystem Operations

```bash
# Stat a remote file
bolt fs stat user@host:/etc/hosts

# List remote directory
bolt fs ls user@host:/var/log

# Rename / move
bolt fs mv user@host:/tmp/old.txt user@host:/tmp/new.txt

# Remove file (recursive with -r)
bolt fs rm user@host:/tmp/file.txt
bolt fs rm -r user@host:/tmp/dir

# Create directory with permissions
bolt fs mkdir --mode 755 user@host:/var/app

# Change permissions
bolt fs chmod 644 user@host:/etc/app/config.toml
```

### Certificate Authority

```bash
# Initialize CA (generates ~/.bolt/ca_key + ca_key.pub)
bolt ca init

# Sign a user certificate (valid 365 days)
bolt ca sign alice --pubkey ~/.bolt/id_bolt.pub --days 365

# Custom CA key and output path
bolt ca sign alice --pubkey alice.pub --ca-key /etc/bolt/ca_key \
     --output /etc/bolt/certs/alice.cert

# Server: trust a CA (add pub key to trusted list)
echo $(cat ~/.bolt/ca_key.pub) >> ~/.bolt/ca_keys

# Server: start with CA key trust
boltd --ca-keys ~/.bolt/ca_keys
```

### File Transfer

```bash
# Upload (rsync delta — only diffs sent if file already exists)
bolt cp file.txt user@host:/remote/path/file.txt

# Download
bolt cp user@host:/remote/path/file.txt ./local/

# Preserve timestamps (-p)
bolt cp -p file.txt user@host:/remote/file.txt
bolt cp -p user@host:/remote/file.txt ./local/

# Recursive directory upload
bolt cp -r ./dir user@host:/remote/dir

# Recursive directory download
bolt cp -r user@host:/remote/dir ./local/dir

# Recursive + preserve timestamps
bolt cp -r -p ./project user@host:/backup/project
```

### Resume Interrupted Transfer

```bash
# Resume a large upload that was interrupted
# (skips bytes already received by server)
bolt cp --resume large-file.iso user@host:/uploads/large-file.iso
```

### Shell Completion

```bash
# bash
bolt completions bash >> ~/.bashrc

# zsh
bolt completions zsh >> ~/.zshrc

# fish
bolt completions fish > ~/.config/fish/completions/bolt.fish
```

### Key Management

```bash
# Generate default keypair → ~/.bolt/id_bolt
bolt keygen

# Generate with custom path
bolt keygen -o ~/.bolt/work_key
```

---

## Configuration

### Client: `~/.bolt/config`

```toml
[defaults]
port     = 2222
identity = "~/.bolt/id_bolt"

[host.prod]
hostname = "10.0.0.1"
port     = 2222
user     = "deploy"
identity = "~/.bolt/prod_key"

[host.dev]
hostname = "dev.example.com"
user     = "admin"
# jump through bastion for dev hosts
jump     = "admin@bastion.example.com"

[host.db]
hostname = "db.internal"
port     = 2222
user     = "dba"
```

With the above config:
```bash
bolt prod              # → deploy@10.0.0.1:2222 with prod_key
bolt dev               # → admin@dev.example.com via bastion
bolt -c "psql" db      # → dba@db.internal:2222 -c "psql"
```

### Server: `/etc/bolt/boltd.toml`

```toml
listen               = "0.0.0.0:2222"
max_connections      = 1000
max_per_ip           = 10
rate_limit_burst     = 20
rate_limit_window_secs = 60
host_key             = "/etc/bolt/host_key"
cert                 = "/etc/bolt/host_cert.der"
authorized_keys      = "/etc/bolt/authorized_keys"
ca_keys              = "/etc/bolt/ca_keys"   # optional: enable cert auth
log_format           = "text"   # or "json"
```

### SSH Config Compatibility

Bolt also reads `~/.ssh/config` for host aliases as a fallback:

```ssh-config
Host myserver
    HostName 192.168.1.100
    Port 2222
    User admin
    IdentityFile ~/.bolt/id_bolt
```

```bash
bolt myserver   # resolves from ~/.ssh/config
```

---

## Tutorial

### 1. First-time Setup

```bash
# Server: install boltd
cargo install --path bin/boltd

# Server: start daemon (generates keys automatically)
boltd -v
# INFO bolt server listening addr="0.0.0.0:2222"

# Client: generate your keypair
bolt keygen
# Identity key:  /home/you/.bolt/id_bolt
# Public key:    /home/you/.bolt/id_bolt.pub
# Fingerprint:   ab:cd:ef:12:34:56:78:90

# Client: authorize your key on the server
cat ~/.bolt/id_bolt.pub | ssh user@server "cat >> ~/.bolt/authorized_keys"

# Client: connect (TOFU on first connect)
bolt user@server
# WARN new host, accepting (TOFU) fingerprint="ab:cd:12:34"
# $   ← you're in
```

### 2. File Sync (Delta)

```bash
# First upload — sends full file
bolt cp ./app.tar.gz user@server:/backups/app.tar.gz
# upload app.tar.gz [==============================] 120 MB/120 MB 95 MB/s ETA 0s
# done (full)

# Update one line in a config, re-upload
echo "# updated" >> config.toml
bolt cp config.toml user@server:/etc/app/config.toml
# delta config.toml [==============================] 22 B/22 B 1 KB/s ETA 0s
# done (saved 99%)
```

### 3. Port Forwarding

```bash
# Forward local :5432 to Postgres on the remote network
bolt -L 5432:postgres-host:5432 user@server

# Now connect locally
psql -h 127.0.0.1 -p 5432 -U myapp mydb
```

### 4. Jump Host

```bash
# ~/.bolt/config
[host.internal]
hostname = "10.10.0.50"
user     = "admin"
jump     = "ops@bastion.company.com"

# Then just:
bolt internal
bolt cp -r ./deploy internal:/opt/app
```

### 5. Environment Forwarding

These variables are automatically forwarded to the remote shell:
`LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `COLORTERM`, `TERM_PROGRAM`,
`EDITOR`, `VISUAL`, `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, etc.

```bash
# Set EDITOR locally → available in remote shell
EDITOR=nvim bolt user@host
# Remote shell: $EDITOR is nvim
```

### 6. Deployment with systemd

```ini
# /etc/systemd/system/boltd.service
[Unit]
Description=Bolt Secure Shell Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/boltd --config /etc/bolt/boltd.toml
Restart=on-failure
RestartSec=5s
# Socket activation: set LISTEN_FDS=1 to pass fd 3
```

```bash
systemctl enable --now boltd
journalctl -u boltd -f
```

---

## How It Works

### Transport: QUIC + TLS 1.3

Every connection is a QUIC session (via `quinn`). The server presents a self-signed Ed25519 certificate. On first connect the client records the SHA-256 fingerprint of that cert in `~/.bolt/known_hosts` (TOFU). Subsequent connects verify the fingerprint matches.

```
Client                           Server
  │  QUIC handshake (TLS 1.3)      │
  │◄──────────────────────────────►│
  │  AuthRequest { user, pub_key } │
  │──────────────────────────────► │
  │  AuthSuccess                   │
  │◄────────────────────────────── │
  │  ChannelOpen(Shell/Exec/Scp/   │
  │             PortForward)       │
  │──────────────────────────────► │
  │  ChannelAccept                 │
  │◄────────────────────────────── │
  │  ... bidirectional data ...    │
```

### File Transfer: Delta + Compression

```
Upload (file already on server):
  Client ──SyncRequest──────────► Server
  Client ◄──SyncSignature──────── Server  (rsync block sigs)
  Client ──SyncDelta chunks─────► Server  (only the diff)
  Client ──FileEnd { sha256 }───► Server
  Client ◄──FileAck────────────── Server

Upload (new file):
  Client ──SyncRequest──────────► Server
  Client ◄──SyncNotFound───────── Server
  Client ──FileHeader { mtime }─► Server
  Client ──FileChunk (zstd)─────► Server  (multiple)
  Client ──FileEnd { sha256 }───► Server
  Client ◄──FileAck────────────── Server

Files identical:
  Server sends SyncUpToDate → nothing transferred
```

### Keepalive

Server sends `Ping` every 30 seconds on a new stream. Client responds with `Pong`. No response within 10 seconds → connection closed.

### Port Forwarding (-L)

```
Local TCP :8080 ──► QUIC stream ──► Server TCP→ target:80
```

Client binds local TCP port. Each incoming connection opens a new QUIC bidirectional stream. Server opens TCP to the target and relays bytes.

### Jump Host (-J)

```
Client ──QUIC──► Bastion ──TCP(PortForward)──► Target
                            └─────QUIC──────────┘
```

Client connects to bastion normally, opens a PortForward channel to the final target, then tunnels a second QUIC connection through that byte stream using a UDP loopback proxy.

---

## Crate Structure

```
bolt-rs/
├── bin/
│   ├── bolt/          # Client CLI
│   └── boltd/         # Server daemon
└── crates/
    ├── bolt-proto/    # Wire protocol (Message enum, encode/decode)
    ├── bolt-crypto/   # Keys, TLS config, TOFU known-hosts, auth
    ├── bolt-client/   # Connect, shell, exec, transfer, forward, config
    ├── bolt-server/   # Handler, shell, exec, transfer, forward, ratelimit
    └── bolt-log/      # Logging (tracing + tracing-subscriber)
```

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `quinn 0.11` | QUIC transport (multiplexed streams over UDP) |
| `rustls 0.23` | TLS 1.3 |
| `rcgen 0.13` | Self-signed Ed25519 certificate generation |
| `serde` + `bincode` | Message serialization |
| `fast_rsync` | rsync-style signature + delta computation |
| `zstd` | File transfer compression |
| `sha2` | SHA-256 checksums (transfer integrity + TOFU) |
| `tokio` | Async runtime |
| `clap` + `clap_complete` | CLI + shell completion |
| `indicatif` | Progress bars for file transfer |
| `tracing` | Structured logging |
| `walkdir` | Recursive directory listing |
| `toml` + `dirs` | Config file parsing |
| `nix` (unix) | PTY, getpwnam, setuid/setgid, utimensat |

---

## Security Model

| Property | How |
|----------|-----|
| Encryption | TLS 1.3 (AES-128-GCM / ChaCha20-Poly1305) |
| Forward secrecy | TLS ephemeral key exchange per session |
| Host verification | TOFU SHA-256 fingerprint in `~/.bolt/known_hosts` |
| Client auth | Ed25519 public key, password (Linux), or CA-signed cert |
| Certificate auth | BoltCert: `sha256(user\|\|pubkey\|\|expiry)` signed with CA Ed25519 |
| Transfer integrity | SHA-256 checksum on every file/delta |
| Rate limiting | Max connections per IP + burst limit |
| Env forwarding | Server-side allowlist (LANG, TZ, EDITOR, GIT_*, ...) |
| Agent forwarding | SSH agent socket proxied over QUIC (SSH_AUTH_SOCK) |

Key locations:

```
~/.bolt/id_bolt              # Client private key (PKCS#8 DER)
~/.bolt/id_bolt.pub          # Client public key (base64)
~/.bolt/known_hosts          # host → SHA-256 fingerprint
~/.bolt/host_key             # Server private key
~/.bolt/host_cert.der        # Server TLS cert (persisted for stable fingerprint)
~/.bolt/authorized_keys      # Server: one ed25519 pubkey per line
~/.bolt/ca_key               # CA private key (bolt ca init)
~/.bolt/ca_key.pub           # CA public key
~/.bolt/ca_keys              # Server: trusted CA public keys (one per line)
~/.bolt/certs/<user>.cert    # Signed user certificate
~/.bolt/session_cache        # TLS session cache (0-RTT)
~/.bolt/ctrl/<host>.sock     # ControlMaster socket
~/.bolt/config               # Client config (TOML)
/etc/bolt/boltd.toml         # Server config (TOML)
```

---

## Development

```bash
# Build
cargo build

# Lint (zero warnings policy)
cargo clippy -- -D warnings

# Format
cargo fmt

# Run server locally (no auth check, verbose)
cargo run --bin boltd -- -v

# Connect (separate terminal)
cargo run --bin bolt -- $USER@127.0.0.1 -c "whoami"

# File transfer test
cargo run --bin bolt -- cp ./Cargo.toml $USER@127.0.0.1:/tmp/test.toml
cargo run --bin bolt -- cp $USER@127.0.0.1:/tmp/test.toml /tmp/downloaded.toml

# Port forward test
cargo run --bin bolt -- -L 8080:localhost:8080 $USER@127.0.0.1
```

---

## Roadmap

- [x] QUIC transport (quinn)
- [x] TLS 1.3 + Ed25519 self-signed certs (rustls + rcgen)
- [x] TOFU host key verification
- [x] Ed25519 client authentication
- [x] Password auth fallback (Linux)
- [x] Interactive PTY shell (login shell, env, window resize)
- [x] Signal forwarding (SIGINT, SIGTERM, SIGTSTP, SIGCONT, ...)
- [x] Environment variable forwarding
- [x] Remote command execution
- [x] rsync delta file sync (fast_rsync)
- [x] zstd compression on transfer
- [x] Preserve timestamps (`-p`)
- [x] Resume interrupted transfer
- [x] Directory upload/download (proper DirList protocol)
- [x] SSH-style CLI (`bolt user@host -c "cmd"`)
- [x] Local port forwarding (`-L`)
- [x] Jump host / bastion (`-J`)
- [x] Client config file (`~/.bolt/config`)
- [x] Server config file (`/etc/bolt/boltd.toml`)
- [x] SSH config parse (`~/.ssh/config` aliases)
- [x] Rate limiting + max connections per IP
- [x] Audit log (structured session events)
- [x] Keepalive / heartbeat (Ping/Pong)
- [x] Shell completion (bash/zsh/fish)
- [x] systemd socket activation
- [x] Remote port forwarding (`-R`)
- [x] 0-RTT session resume (in-process; file-backed store available)
- [x] Windows ConPTY support (`#[cfg(windows)]` via `windows-sys`)
- [x] SFTP subsystem (`bolt fs stat/ls/mv/rm/mkdir/chmod`)
- [x] SSH agent forwarding (`--agent`)
- [x] ControlMaster (connection multiplexing via Unix socket)
- [x] Certificate authority (`bolt ca init` / `bolt ca sign`)

---

## License

MIT
