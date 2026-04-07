//! Bolt server lifecycle: bind, accept connections, graceful shutdown.

use std::{path::PathBuf, sync::Arc};

use anyhow::Context as _;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use bolt_crypto::{auth::Authenticator, keys::{AuthorizedKeys, KeyPair}};
use bolt_transport::{Config as TransportConfig, Listener};

use super::handler::handle_connection;

pub struct ServerConfig {
    pub listen_addr:     String,
    pub host_key_path:   PathBuf,
    pub auth_keys_path:  PathBuf,
    pub max_connections: usize,
    pub transport:       TransportConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr:     "0.0.0.0:2222".into(),
            host_key_path:   PathBuf::from("/etc/bolt/host_key"),
            auth_keys_path:  PathBuf::from("/etc/bolt/authorized_keys"),
            max_connections: 1000,
            transport:       TransportConfig::default(),
        }
    }
}

pub struct Server {
    config:   ServerConfig,
    host_key: KeyPair,
    auth:     Option<Arc<Authenticator>>,
}

impl Server {
    pub fn new(config: ServerConfig) -> anyhow::Result<Self> {
        let host_key = load_or_generate_host_key(&config.host_key_path)?;
        info!(component = "server", "host key: {}", config.host_key_path.display());

        let auth = match AuthorizedKeys::load(&config.auth_keys_path) {
            Ok(ak) => {
                if ak.is_empty() {
                    warn!(component = "server", "no authorized keys loaded, all clients will be rejected");
                }
                Some(Arc::new(Authenticator::new(ak)))
            }
            Err(e) => {
                warn!(component = "server", "load authorized keys: {e}");
                None
            }
        };

        Ok(Self { config, host_key, auth })
    }

    pub async fn listen_and_serve(&self) -> anyhow::Result<()> {
        let mut listener = Listener::bind(&self.config.listen_addr, self.config.transport.clone()).await
            .with_context(|| format!("bind {}", self.config.listen_addr))?;

        info!(
            component = "server",
            addr      = %self.config.listen_addr,
            "bolt server listening"
        );

        let sem = Arc::new(Semaphore::new(self.config.max_connections));

        loop {
            let conn = match listener.accept().await {
                Some(c) => c,
                None => break,
            };

            let permit = Arc::clone(&sem).acquire_owned().await?;
            let host_key = KeyPair::load(&self.config.host_key_path)
                .unwrap_or_else(|_| KeyPair::generate().unwrap());
            let auth = self.auth.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn, host_key, auth).await {
                    error!(component = "server", "connection error: {e}");
                }
                drop(permit);
            });
        }
        Ok(())
    }
}

fn load_or_generate_host_key(path: &PathBuf) -> anyhow::Result<KeyPair> {
    if path.exists() {
        KeyPair::load(path).with_context(|| format!("read host key {}", path.display()))
    } else {
        let kp = KeyPair::generate().context("generate host key")?;
        kp.save(path).with_context(|| format!("save host key {}", path.display()))?;
        info!(component = "server", "generated new host key at {}", path.display());
        Ok(kp)
    }
}
