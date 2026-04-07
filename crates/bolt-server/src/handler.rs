//! Per-connection handler: auth handshake → stream dispatch.

use std::{sync::Arc, time::Duration};

use anyhow::Context as _;
use quinn::Connection;
use tracing::{info, warn};

use bolt_crypto::auth::Authenticator;
use bolt_proto::{read_msg, write_msg, ChannelType, Message};

use crate::{
    exec::handle_exec,
    forward::handle_forward,
    shell::handle_shell,
    transfer::handle_transfer,
};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn handle_connection(
    conn: Connection,
    auth: Option<Arc<Authenticator>>,
) -> anyhow::Result<()> {
    let remote = conn.remote_address();
    let remote_ip = remote.ip();
    info!(remote = %remote, "new connection");

    // ── Auth handshake (first bidirectional stream) ────────────────────────
    let (mut auth_send, mut auth_recv) = conn
        .accept_bi()
        .await
        .context("accept auth stream")?;

    let Some(msg) = read_msg(&mut auth_recv).await? else {
        anyhow::bail!("client closed before auth");
    };

    let (client_user, _client_key) = match msg {
        Message::AuthRequest { user, public_key } => {
            // Key auth
            if let Some(ref auth) = auth {
                if let Err(e) = auth.authenticate(&public_key) {
                    warn!(remote = %remote, user = %user, error = %e, "key auth failed");
                    write_msg(&mut auth_send, &Message::AuthFailure { reason: e.to_string() })
                        .await.ok();
                    auth_send.finish().ok();
                    return Ok(());
                }
            }
            info!(remote = %remote, user = %user, method = "publickey", "authenticated");
            (user, public_key)
        }
        Message::AuthPassword { user, password } => {
            // Password auth — validate via PAM or simple check
            if let Err(reason) = verify_password(&user, &password) {
                warn!(remote = %remote, user = %user, "password auth failed");
                write_msg(&mut auth_send, &Message::AuthFailure { reason }).await.ok();
                auth_send.finish().ok();
                return Ok(());
            }
            info!(remote = %remote, user = %user, method = "password", "authenticated");
            (user, [0u8; 32])
        }
        other => {
            write_msg(
                &mut auth_send,
                &Message::AuthFailure {
                    reason: format!("expected AuthRequest, got {other:?}"),
                },
            )
            .await
            .ok();
            auth_send.finish().ok();
            anyhow::bail!("bad auth message: {other:?}");
        }
    };

    write_msg(&mut auth_send, &Message::AuthSuccess).await?;
    auth_send.finish().context("finish auth response")?;

    // Audit log
    info!(
        event = "session_start",
        remote = %remote,
        ip = %remote_ip,
        user = %client_user,
        "session started"
    );

    // ── Accept channel streams ────────────────────────────────────────────
    loop {
        // Race between new stream and keepalive timer
        let (send, recv) = tokio::select! {
            result = conn.accept_bi() => {
                match result {
                    Ok(s) => s,
                    Err(
                        quinn::ConnectionError::ApplicationClosed(_)
                        | quinn::ConnectionError::ConnectionClosed(_)
                        | quinn::ConnectionError::TimedOut
                        | quinn::ConnectionError::LocallyClosed,
                    ) => break,
                    Err(e) => {
                        warn!(remote = %remote, error = %e, "accept stream error");
                        break;
                    }
                }
            }
            // Keepalive: open a short-lived stream, ping, expect pong
            _ = tokio::time::sleep(KEEPALIVE_INTERVAL) => {
                if let Err(e) = send_keepalive(&conn).await {
                    warn!(remote = %remote, error = %e, "keepalive failed — disconnecting");
                    break;
                }
                continue;
            }
        };

        let remote_addr = remote;
        let user = client_user.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, &user).await {
                warn!(remote = %remote_addr, error = %e, "stream error");
            }
        });
    }

    info!(
        event = "session_end",
        remote = %remote,
        user = %client_user,
        "session ended"
    );
    Ok(())
}

/// Send a Ping on a new stream and wait for Pong.
async fn send_keepalive(conn: &Connection) -> anyhow::Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open keepalive stream")?;
    write_msg(&mut send, &Message::Ping).await?;
    send.finish().ok();

    let result = tokio::time::timeout(KEEPALIVE_TIMEOUT, read_msg(&mut recv)).await;
    match result {
        Ok(Ok(Some(Message::Pong))) => Ok(()),
        Ok(Ok(_)) => anyhow::bail!("unexpected keepalive response"),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => anyhow::bail!("keepalive timeout"),
    }
}

// ── Stream dispatch ───────────────────────────────────────────────────────

async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    user: &str,
) -> anyhow::Result<()> {
    // First message must be ChannelOpen or Ping (keepalive from client)
    let Some(msg) = read_msg(&mut recv).await? else {
        return Ok(());
    };

    // Handle client-initiated keepalive ping
    if let Message::Ping = msg {
        write_msg(&mut send, &Message::Pong).await.ok();
        return Ok(());
    }

    let (channel_type, command) = match msg {
        Message::ChannelOpen {
            channel_type,
            command,
        } => (channel_type, command),
        other => {
            write_msg(
                &mut send,
                &Message::ChannelReject {
                    reason: format!("expected ChannelOpen, got {other:?}"),
                },
            )
            .await
            .ok();
            return Ok(());
        }
    };

    // Accept the channel
    write_msg(&mut send, &Message::ChannelAccept).await?;

    match channel_type {
        ChannelType::Shell => handle_shell(&mut send, &mut recv, user).await,
        ChannelType::Exec => handle_exec(&mut send, &mut recv, &command, user).await,
        ChannelType::Scp => handle_transfer(&mut send, &mut recv, &command).await,
        ChannelType::PortForward => handle_forward(&mut send, &mut recv, &command).await,
    }
}

// ── Password verification ─────────────────────────────────────────────────

/// Verify password via system PAM (Unix) or always-reject on non-Unix.
fn verify_password(user: &str, password: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        verify_password_pam(user, password)
    }
    #[cfg(not(unix))]
    {
        let _ = (user, password);
        Err("password auth not supported on this platform".into())
    }
}

#[cfg(unix)]
fn verify_password_pam(user: &str, password: &str) -> Result<(), String> {
    // Use shadow/pam if available; fall back to /etc/shadow comparison.
    // For simplicity we use getspnam + crypt — works on Linux.
    // On macOS, PAM would be needed; we return an error for now.
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use nix::libc;

        let c_user = CString::new(user).map_err(|e| e.to_string())?;
        let sp = unsafe { libc::getspnam(c_user.as_ptr()) };
        if sp.is_null() {
            // Fall back to passwd (no shadow)
            return verify_password_passwd(user, password);
        }
        let sp = unsafe { &*sp };
        let hash = unsafe { std::ffi::CStr::from_ptr(sp.sp_pwdp) }
            .to_string_lossy()
            .to_string();
        verify_crypt(password, &hash)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (user, password);
        Err("password auth requires PAM (not available on this platform)".into())
    }
}

#[cfg(all(unix, target_os = "linux"))]
fn verify_password_passwd(user: &str, password: &str) -> Result<(), String> {
    use std::ffi::CString;
    use nix::libc;

    let c_user = CString::new(user).map_err(|e| e.to_string())?;
    let pw = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if pw.is_null() {
        return Err(format!("unknown user: {user}"));
    }
    let pw = unsafe { &*pw };
    let hash = unsafe { std::ffi::CStr::from_ptr(pw.pw_passwd) }
        .to_string_lossy()
        .to_string();
    verify_crypt(password, &hash)
}

#[cfg(all(unix, target_os = "linux"))]
fn verify_crypt(password: &str, hash: &str) -> Result<(), String> {
    use std::ffi::CString;
    use nix::libc;

    let c_pw = CString::new(password).map_err(|e| e.to_string())?;
    let c_hash = CString::new(hash).map_err(|e| e.to_string())?;
    let result = unsafe { libc::crypt(c_pw.as_ptr(), c_hash.as_ptr()) };
    if result.is_null() {
        return Err("crypt failed".into());
    }
    let computed = unsafe { std::ffi::CStr::from_ptr(result) }.to_string_lossy();
    if computed == hash {
        Ok(())
    } else {
        Err("incorrect password".into())
    }
}
