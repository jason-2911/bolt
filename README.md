# Bolt

**A modern secure remote shell built on QUIC — faster connections, rsync-style file sync, and GUI forwarding over a single UDP stream.**

Bolt is a drop-in SSH alternative that replaces the TCP+SSH stack with QUIC/TLS 1.3, bringing sub-100ms 0-RTT reconnects, built-in delta file sync, multiplexed channels, and UDP-based GUI window forwarding — all with a familiar `bolt user@host` interface.

---

## Features

| Category | Capability |
|---|---|
| **Transport** | QUIC (quinn 0.11) · TLS 1.3 · 0-RTT session resume |
| **Authentication** | Ed25519 public key · Password (Linux PAM) · CA-signed certificate |
| **Shell** | Interactive PTY (Unix + Windows ConPTY) · Signal forwarding · Env forwarding |
| **File Transfer** | rsync delta sync · zstd compression · Preserve timestamps · Resume interrupted |
| **Port Forwarding** | Local `-L` · Remote `-R` · Jump host / bastion `-J` |
| **Filesystem** | SFTP-like `bolt fs` (stat, ls, mv, rm, mkdir, chmod) |
| **GUI Forwarding** | UDP video stream · XTest input injection (Linux) · Desktop window inventory |
| **Agent Forwarding** | SSH agent proxied over QUIC (`SSH_AUTH_SOCK`) |
| **Multiplexing** | ControlMaster connection reuse via Unix socket |
| **PKI** | Built-in certificate authority (`bolt ca init / sign`) |
| **Platform** | Linux · macOS · Windows (shell only) |

---

## Quick Start

### 1 — Build

```bash
git clone https://github.com/your-org/bolt-rs
cd bolt-rs
cargo build --release
# → target/release/bolt   (client)
# → target/release/boltd  (server daemon)
```

### 2 — Server

```bash
# Auto-generates host key + TLS cert on first run
boltd

# Or with explicit config
boltd --listen 0.0.0.0:2222 \
      --host-key /etc/bolt/host_key \
      --authorized-keys /etc/bolt/authorized_keys
```

### 3 — Client

```bash
# Generate Ed25519 keypair
bolt keygen
# → ~/.bolt/id_bolt      (private key)
# → ~/.bolt/id_bolt.pub  (public key)

# Authorize your key on the server
cat ~/.bolt/id_bolt.pub >> ~/.bolt/authorized_keys

# Connect (TOFU fingerprint check on first connect)
bolt user@host
```

---

## CLI Reference

### Shell & Exec

```bash
bolt user@host                          # Interactive PTY shell
bolt user@host -c "ls -la /tmp"         # Remote command, no PTY
bolt -p 2222 -i ~/.bolt/id_bolt user@host
bolt -v user@host                       # Verbose / debug logging
```

### File Transfer

```bash
# Upload (rsync delta — only diffs sent when file exists on server)
bolt cp ./app.tar.gz user@host:/backups/app.tar.gz

# Download
bolt cp user@host:/var/log/app.log ./local/

# Recursive directory
bolt cp -r ./dist user@host:/var/www/app

# Preserve timestamps
bolt cp -p config.toml user@host:/etc/app/config.toml

# Resume interrupted upload
bolt cp --resume large.iso user@host:/uploads/large.iso
```

### Port Forwarding

```bash
# Local forward — tunnel local :8080 → remote localhost:80
bolt -L 8080:localhost:80 user@host

# Remote forward — server binds :2222, tunnels back to local :22
bolt -R 2222:localhost:22 user@host

# Jump host / bastion
bolt -J admin@bastion.example.com user@internal-host
```

### GUI Window Forwarding

```bash
# Launch session with GUI forwarding enabled
bolt -X user@host

# Standalone GUI mode (server side)
boltd gui --listen 0.0.0.0:5600 --source window

# Standalone GUI mode (client side)
bolt gui --listen 0.0.0.0:5601 --server <SERVER_IP>:5600
```

**How it works:** Video frames (server → client) and input events (client → server) travel over separate UDP streams, decoupled from the QUIC control channel. The client auto-attaches newly discovered app windows such as `code`; if you need to choose manually, use the window picker with `Enter` to attach, `F6` to detach, and `F7`/`F8` to cycle windows.

Platform notes:
- **Linux/X11** — `boltd` must run inside an X11 session (`DISPLAY` set). Input is injected via `libXtst` XTest. Requires `libX11` + `libXtst` at link time.
- **macOS** — Server process needs Screen Recording permission in System Settings.

### Filesystem Operations

```bash
bolt fs stat  user@host:/etc/hosts
bolt fs ls    user@host:/var/log
bolt fs mv    user@host:/tmp/old.txt user@host:/tmp/new.txt
bolt fs rm    user@host:/tmp/file.txt
bolt fs rm -r user@host:/tmp/dir
bolt fs mkdir --mode 755 user@host:/var/app
bolt fs chmod 644 user@host:/etc/app/config.toml
```

### SSH Agent Forwarding

```bash
bolt --agent user@host
bolt --agent user@host -c "git clone git@github.com:org/repo"
```

### Certificate Authority

```bash
# One-time CA setup
bolt ca init
# → ~/.bolt/ca_key   (CA private key)
# → ~/.bolt/ca_key.pub

# Sign a user certificate (30-day validity)
bolt ca sign alice --pubkey ~/.bolt/id_bolt.pub --days 30

# Trust a CA on the server
echo $(cat ~/.bolt/ca_key.pub) >> ~/.bolt/ca_keys
boltd --ca-keys ~/.bolt/ca_keys
```

### Key Management & Completions

```bash
bolt keygen                    # Generate default keypair
bolt keygen -o ~/.bolt/work    # Custom path

bolt completions bash >> ~/.bashrc
bolt completions zsh  >> ~/.zshrc
bolt completions fish > ~/.config/fish/completions/bolt.fish
```

---

## Configuration

### Client — `~/.bolt/config`

```toml
[defaults]
port     = 2222
identity = "~/.bolt/id_bolt"

[host.prod]
hostname = "10.0.0.1"
user     = "deploy"
identity = "~/.bolt/prod_key"

[host.dev]
hostname = "dev.example.com"
user     = "admin"
jump     = "admin@bastion.example.com"
```

```bash
bolt prod              # deploy@10.0.0.1 with prod_key
bolt dev               # admin@dev.example.com via bastion
bolt -c "psql" dev     # run command on dev host
```

Bolt also reads `~/.ssh/config` as a fallback for host aliases.

### Server — `/etc/bolt/boltd.toml`

```toml
listen               = "0.0.0.0:2222"
max_connections      = 1000
max_per_ip           = 10
rate_limit_burst     = 20
rate_limit_window_secs = 60
host_key             = "/etc/bolt/host_key"
cert                 = "/etc/bolt/host_cert.der"
authorized_keys      = "/etc/bolt/authorized_keys"
ca_keys              = "/etc/bolt/ca_keys"    # optional: enable cert auth
log_format           = "json"                 # or "text"
```

### systemd

```ini
[Unit]
Description=Bolt Secure Shell Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/boltd --config /etc/bolt/boltd.toml
Restart=on-failure
RestartSec=5s
```

---

## How It Works

### Protocol Flow

```
Client                              Server
  │                                   │
  │   QUIC handshake (TLS 1.3)        │
  │◄─────────────────────────────────►│
  │   AuthRequest { user, pub_key }   │
  │──────────────────────────────────►│
  │   AuthSuccess                     │
  │◄──────────────────────────────────│
  │   ChannelOpen(Shell|Exec|Scp|…)   │
  │──────────────────────────────────►│  ← each channel = one QUIC stream
  │   ChannelAccept                   │
  │◄──────────────────────────────────│
  │   [length-prefixed bincode msgs]  │
  │◄─────────────────────────────────►│
```

Each logical channel (shell, exec, file transfer, port forward, agent, fs) runs as an independent QUIC bidirectional stream. Multiplexing is free — no head-of-line blocking.

### File Transfer: Delta + Compression

```
Upload (file already on server):
  Client ──SyncRequest──────────────► Server
  Client ◄──SyncSignature──────────── Server  (rsync block signatures)
  Client ──SyncDelta chunks──────────► Server  (only the diff)
  Client ──FileEnd { sha256 }────────► Server
  Client ◄──FileAck────────────────── Server

Upload (new file):
  Client ──SyncRequest──────────────► Server
  Client ◄──SyncNotFound───────────── Server
  Client ──FileHeader { mtime }──────► Server
  Client ──FileChunk (zstd) × N ─────► Server
  Client ──FileEnd { sha256 }────────► Server
  Client ◄──FileAck────────────────── Server
```

### GUI Forwarding: UDP Overlay

```
Server ─[VideoChunk UDP]──────────────────────────► Client window
Client ─[InputEvent UDP]──────────────────────────► Server XTest
        (independent of QUIC control channel)
```

Video path: screen capture → dirty-rect detection → RGB patch → zstd → chunked UDP → decompress → blit to framebuffer.

---

## Crate Structure

```
bolt-rs/
├── bin/
│   ├── bolt/          CLI client binary
│   └── boltd/         Server daemon binary
└── crates/
    ├── bolt-proto/    Wire protocol — Message enum, encode/decode, UDP GUI types
    ├── bolt-crypto/   Keys, TLS config, TOFU known-hosts, CA, session store
    ├── bolt-log/      Logging (tracing + tracing-subscriber)
    ├── bolt-client/   Connection, shell, exec, transfer, forward, fs, GUI client
    │   └── gui/       ├── mod.rs      UDP client, receive loop
    │                  ├── render.rs   minifb window, RenderState, input
    │                  └── bitmap_text.rs  Terminal font renderer
    └── bolt-server/   Handler, shell, exec, transfer, forward, ratelimit, GUI server
        └── gui/       ├── mod.rs      UDP server, frame loop, platform dispatch
                       ├── encode.rs   Delta detection, chunking, inventory packing
                       ├── demo.rs     Synthetic colour-cycle capturer
                       ├── linux.rs    X11 capture + XTest input injection
                       └── macos.rs    CGImage capture + CoreFoundation FFI
```

### Key Dependencies

| Crate | Role |
|---|---|
| `quinn 0.11` | QUIC transport — multiplexed streams over UDP |
| `rustls 0.23` | TLS 1.3 |
| `rcgen 0.13` | Self-signed Ed25519 certificate generation |
| `serde` + `bincode` | Binary protocol serialization |
| `fast_rsync` | rsync-style block signatures + delta |
| `zstd` | Transfer compression |
| `sha2` | SHA-256 for file integrity + TOFU fingerprint |
| `tokio` | Async runtime |
| `clap 4` + `clap_complete` | CLI + shell completion generation |
| `indicatif` | Transfer progress bars |
| `minifb` | GUI client window (cross-platform framebuffer) |
| `nix` (unix) | PTY alloc, getpwnam, setuid/gid, utimensat |
| `windows-sys` | ConPTY, Win32 file/pipe APIs |

---

## Security Model

| Property | Implementation |
|---|---|
| **Encryption** | TLS 1.3 — AES-128-GCM or ChaCha20-Poly1305 |
| **Forward secrecy** | TLS ephemeral key exchange per session |
| **Host verification** | TOFU — SHA-256 fingerprint stored in `~/.bolt/known_hosts` |
| **Client auth** | Ed25519 public key, Linux password/PAM, or CA-signed cert |
| **Certificate auth** | `BoltCert { user, pubkey, expiry }` signed by Ed25519 CA |
| **Transfer integrity** | SHA-256 checksum on every file and delta |
| **Rate limiting** | Per-IP connection count + burst window |
| **Env allowlist** | Server-side: only `LANG`, `TZ`, `EDITOR`, `GIT_*`, … forwarded |
| **Agent security** | SSH agent socket proxied over QUIC, never stored server-side |

### Key Locations

```
~/.bolt/id_bolt              Client private key (PKCS#8 DER, mode 600)
~/.bolt/id_bolt.pub          Client public key (base64)
~/.bolt/known_hosts          host → SHA-256 fingerprint (TOFU)
~/.bolt/host_key             Server private key
~/.bolt/host_cert.der        Server TLS cert (stable fingerprint across restarts)
~/.bolt/authorized_keys      Server: one ed25519 pubkey per line
~/.bolt/ca_key               CA private key  (bolt ca init)
~/.bolt/ca_key.pub           CA public key
~/.bolt/ca_keys              Server: trusted CA public keys
~/.bolt/certs/<user>.cert    Signed user certificates
~/.bolt/session_cache        TLS 0-RTT session tickets
~/.bolt/ctrl/<host>.sock     ControlMaster Unix socket
~/.bolt/config               Client config (TOML)
/etc/bolt/boltd.toml         Server config (TOML)
```

---

## Development

```bash
# Build
cargo build

# Lint (zero-warnings policy)
cargo clippy -- -D warnings

# Format
cargo fmt

# Local end-to-end test
cargo run --bin boltd -- -v &
cargo run --bin bolt -- $USER@127.0.0.1 -c "whoami"

# File transfer smoke-test
cargo run --bin bolt -- cp ./Cargo.toml $USER@127.0.0.1:/tmp/test.toml
cargo run --bin bolt -- cp $USER@127.0.0.1:/tmp/test.toml /tmp/roundtrip.toml
diff Cargo.toml /tmp/roundtrip.toml
```

---

## License

MIT
