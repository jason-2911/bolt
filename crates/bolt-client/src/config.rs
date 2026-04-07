//! Client configuration: ~/.bolt/config TOML + basic SSH config parse.
//!
//! # ~/.bolt/config format
//!
//! ```toml
//! [defaults]
//! port     = 2222
//! identity = "~/.bolt/id_bolt"
//!
//! [host.prod]
//! hostname = "10.0.0.1"
//! port     = 2222
//! user     = "admin"
//! identity = "~/.bolt/prod_key"
//!
//! [host.dev]
//! hostname = "dev.example.com"
//! ```

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BoltConfig {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub host: HashMap<String, HostEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Defaults {
    pub port: Option<u16>,
    pub identity: Option<String>,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            port: None,
            identity: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HostEntry {
    /// Real hostname or IP (overrides the alias key).
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity: Option<String>,
    /// Jump host: "user@bastion"
    pub jump: Option<String>,
}

// ── Load ──────────────────────────────────────────────────────────────────

impl BoltConfig {
    /// Load from `~/.bolt/config`. Returns empty config on missing file.
    pub fn load() -> Self {
        let path = config_path();
        Self::load_from(&path)
    }

    pub fn load_from(path: &Path) -> Self {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => return Self::default(),
        };
        toml::from_str(&text).unwrap_or_else(|e| {
            eprintln!("bolt: warning: {} parse error: {e}", path.display());
            Self::default()
        })
    }

    /// Look up a host alias. Returns the entry if found.
    pub fn host(&self, alias: &str) -> Option<&HostEntry> {
        self.host.get(alias)
    }

    /// Resolve a target string: either an alias or raw user@host.
    /// Returns (user, hostname, port, identity, jump).
    pub fn resolve_target(
        &self,
        target: &str,
        cli_port: u16,
        cli_identity: Option<&Path>,
    ) -> ResolvedTarget {
        // Try alias lookup first
        if let Some(entry) = self.host.get(target) {
            return ResolvedTarget {
                user: entry.user.clone().unwrap_or_else(|| whoami()),
                host: entry.hostname.clone().unwrap_or_else(|| target.to_owned()),
                port: entry.port.or(self.defaults.port).unwrap_or(cli_port),
                identity: cli_identity
                    .map(|p| p.to_path_buf())
                    .or_else(|| entry.identity.as_deref().map(expand_tilde))
                    .or_else(|| self.defaults.identity.as_deref().map(expand_tilde)),
                jump: entry.jump.clone(),
            };
        }

        // Try "alias" where target has no @ (host alias without user)
        // Parse user@host or just host
        let (user, host) = if let Some(at) = target.find('@') {
            (target[..at].to_owned(), target[at + 1..].to_owned())
        } else {
            (whoami(), target.to_owned())
        };

        // Check if the host part is an alias
        let (real_host, port, identity, jump) = if let Some(entry) = self.host.get(&host) {
            (
                entry.hostname.clone().unwrap_or(host),
                entry.port.or(self.defaults.port).unwrap_or(cli_port),
                cli_identity
                    .map(|p| p.to_path_buf())
                    .or_else(|| entry.identity.as_deref().map(expand_tilde))
                    .or_else(|| self.defaults.identity.as_deref().map(expand_tilde)),
                entry.jump.clone(),
            )
        } else {
            (
                host,
                self.defaults.port.unwrap_or(cli_port),
                cli_identity
                    .map(|p| p.to_path_buf())
                    .or_else(|| self.defaults.identity.as_deref().map(expand_tilde)),
                None,
            )
        };

        ResolvedTarget {
            user,
            host: real_host,
            port,
            identity,
            jump,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub identity: Option<PathBuf>,
    pub jump: Option<String>,
}

impl ResolvedTarget {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// ── SSH config parse ──────────────────────────────────────────────────────

/// Parse `~/.ssh/config` and return a map of alias → HostEntry.
/// Only reads HostName, Port, User, IdentityFile — ignores everything else.
pub fn parse_ssh_config() -> HashMap<String, HostEntry> {
    let path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ssh/config");

    parse_ssh_config_file(&path)
}

pub fn parse_ssh_config_file(path: &Path) -> HashMap<String, HostEntry> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return HashMap::new(),
    };

    let mut result = HashMap::new();
    let mut current_hosts: Vec<String> = Vec::new();
    let mut current_entry = HostEntry::default();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, val) = match line.split_once(char::is_whitespace) {
            Some((k, v)) => (k.to_ascii_lowercase(), v.trim().to_owned()),
            None => continue,
        };

        if key == "host" {
            // Save previous block
            if !current_hosts.is_empty() {
                for h in &current_hosts {
                    result.insert(h.clone(), current_entry.clone());
                }
            }
            // Start new block (may be multiple space-separated patterns)
            current_hosts = val.split_whitespace()
                .filter(|s| *s != "*")  // skip wildcard entries
                .map(|s| s.to_owned())
                .collect();
            current_entry = HostEntry::default();
        } else {
            match key.as_str() {
                "hostname" => current_entry.hostname = Some(val),
                "port" => current_entry.port = val.parse().ok(),
                "user" => current_entry.user = Some(val),
                "identityfile" => current_entry.identity = Some(val),
                _ => {}
            }
        }
    }

    // Save last block
    if !current_hosts.is_empty() {
        for h in &current_hosts {
            result.insert(h.clone(), current_entry.clone());
        }
    }

    result
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".bolt/config")
}

fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(rest)
    } else {
        PathBuf::from(s)
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_owned())
}
