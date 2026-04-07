//! Server-side shell channel: PTY allocation and bidirectional I/O relay.

use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::process::Stdio;

use anyhow::Context as _;
use nix::{
    libc,
    pty::openpty,
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use tokio::{process::Command, sync::mpsc};
use tracing::debug;

use bolt_proto::{read_msg, write_msg, Message};

pub async fn handle_shell(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    user: &str,
) -> anyhow::Result<()> {
    // Collect EnvSet messages, then read PtyRequest
    let mut extra_env: Vec<(String, String)> = Vec::new();

    let (term, cols, rows) = loop {
        let Some(msg) = read_msg(recv).await? else {
            return Ok(());
        };
        match msg {
            Message::EnvSet { key, val } => {
                // Only forward a safe allowlist
                if is_safe_env_key(&key) {
                    extra_env.push((key, val));
                }
            }
            Message::PtyRequest { term, cols, rows } => break (term, cols, rows),
            other => {
                debug!("expected PtyRequest, got {other:?}");
                return Ok(());
            }
        }
    };

    debug!(term = %term, cols, rows, "PTY request");

    // Allocate PTY
    let pty = openpty(None, None).context("openpty")?;
    let master_fd: RawFd = pty.master.into_raw_fd();
    let slave_fd: RawFd = pty.slave.into_raw_fd();
    set_winsize(master_fd, cols as u16, rows as u16);

    // Resolve user info
    let (shell_path, home_dir, uid, gid) = resolve_user(user)?;
    debug!(user, shell = %shell_path, home = %home_dir, uid, gid, "resolved user");

    // Dup slave fd for stdin/stdout/stderr (each Stdio::from_raw_fd takes ownership)
    let slave_stdin = slave_fd;
    let slave_stdout = unsafe { libc::dup(slave_fd) };
    let slave_stderr = unsafe { libc::dup(slave_fd) };

    // Spawn login shell
    let mut cmd = Command::new(&shell_path);
    cmd.arg("-l")
        .env_clear()
        .env("TERM", &term)
        .env("HOME", &home_dir)
        .env("USER", user)
        .env("LOGNAME", user)
        .env("SHELL", &shell_path)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .env(
            "LANG",
            std::env::var("LANG").unwrap_or_else(|_| "en_US.UTF-8".into()),
        )
        .current_dir(&home_dir);

    // Apply forwarded environment variables
    for (k, v) in &extra_env {
        cmd.env(k, v);
    }

    let mut child = unsafe {
        cmd
            .stdin(Stdio::from_raw_fd(slave_stdin))
            .stdout(Stdio::from_raw_fd(slave_stdout))
            .stderr(Stdio::from_raw_fd(slave_stderr))
            .pre_exec(move || {
                libc::setgid(gid);
                libc::setuid(uid);
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY as _, 0);
                Ok(())
            })
            .spawn()
            .context("spawn shell")?
    };

    let child_pid = child.id().unwrap_or(0) as i32;

    // Use blocking threads for PTY I/O (macOS doesn't support async poll on PTY fds)
    // PTY read thread → channel → network
    let (pty_tx, mut pty_rx) = mpsc::channel::<Vec<u8>>(64);
    let read_fd = master_fd;
    let pty_reader = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            if pty_tx.blocking_send(buf[..n as usize].to_vec()).is_err() {
                break;
            }
        }
    });

    // Network → channel → PTY write thread
    let (net_tx, mut net_rx) = mpsc::channel::<Vec<u8>>(64);
    let write_fd = unsafe { libc::dup(master_fd) };
    let pty_writer = tokio::task::spawn_blocking(move || {
        while let Some(data) = net_rx.blocking_recv() {
            let mut offset = 0;
            while offset < data.len() {
                let n = unsafe {
                    libc::write(
                        write_fd,
                        data[offset..].as_ptr().cast(),
                        data.len() - offset,
                    )
                };
                if n <= 0 {
                    return;
                }
                offset += n as usize;
            }
        }
        unsafe { libc::close(write_fd) };
    });

    // Main relay loop
    loop {
        tokio::select! {
            // PTY output → network
            data = pty_rx.recv() => {
                let Some(data) = data else { break };
                if write_msg(send, &Message::Data(data)).await.is_err() {
                    break;
                }
            }
            // Network → PTY input / control messages
            result = read_msg(recv) => {
                match result {
                    Ok(Some(Message::Data(data))) => {
                        if net_tx.send(data).await.is_err() { break; }
                    }
                    Ok(Some(Message::WindowChange { cols, rows })) => {
                        set_winsize(master_fd, cols as u16, rows as u16);
                    }
                    Ok(Some(Message::Signal { name })) => {
                        if let Some(sig) = parse_signal(&name) {
                            let _ = kill(Pid::from_raw(child_pid), sig);
                        }
                    }
                    Ok(Some(Message::Eof)) | Ok(None) | Err(_) => break,
                    Ok(Some(_)) => {}
                }
            }
            // Child exited
            status = child.wait() => {
                let code = status
                    .map(|s| s.code().unwrap_or(1))
                    .unwrap_or(1);
                // Drain remaining PTY output
                drop(net_tx);
                while let Some(data) = pty_rx.recv().await {
                    write_msg(send, &Message::Data(data)).await.ok();
                }
                write_msg(send, &Message::ExitStatus { code }).await.ok();
                break;
            }
        }
    }

    pty_reader.abort();
    pty_writer.abort();
    Ok(())
}

fn set_winsize(fd: RawFd, cols: u16, rows: u16) {
    let ws = libc::winsize {
        ws_col: cols,
        ws_row: rows,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
}

fn parse_signal(name: &str) -> Option<Signal> {
    match name {
        "TERM" => Some(Signal::SIGTERM),
        "KILL" => Some(Signal::SIGKILL),
        "HUP" => Some(Signal::SIGHUP),
        "INT" => Some(Signal::SIGINT),
        "QUIT" => Some(Signal::SIGQUIT),
        "TSTP" => Some(Signal::SIGTSTP),
        "CONT" => Some(Signal::SIGCONT),
        "USR1" => Some(Signal::SIGUSR1),
        "USR2" => Some(Signal::SIGUSR2),
        "WINCH" => Some(Signal::SIGWINCH),
        "PIPE" => Some(Signal::SIGPIPE),
        _ => None,
    }
}

/// Allowlist of environment variable keys safe to forward from client.
fn is_safe_env_key(key: &str) -> bool {
    matches!(
        key,
        "LANG"
            | "LC_ALL"
            | "LC_CTYPE"
            | "LC_MESSAGES"
            | "LC_MONETARY"
            | "LC_NUMERIC"
            | "LC_TIME"
            | "TZ"
            | "COLORTERM"
            | "TERM_PROGRAM"
            | "TERM_PROGRAM_VERSION"
            | "EDITOR"
            | "VISUAL"
            | "PAGER"
            | "MANPAGER"
            | "GIT_AUTHOR_NAME"
            | "GIT_AUTHOR_EMAIL"
            | "GIT_COMMITTER_NAME"
            | "GIT_COMMITTER_EMAIL"
            | "CARGO_HOME"
            | "RUSTUP_HOME"
    )
}

/// Resolve username → (shell, home, uid, gid) via getpwnam.
fn resolve_user(user: &str) -> anyhow::Result<(String, String, u32, u32)> {
    use std::ffi::CString;

    let c_user = CString::new(user).context("invalid username")?;
    let pw = unsafe { libc::getpwnam(c_user.as_ptr()) };

    if pw.is_null() {
        anyhow::bail!("unknown user: {user}");
    }

    let pw = unsafe { &*pw };
    let shell = unsafe { std::ffi::CStr::from_ptr(pw.pw_shell) }
        .to_string_lossy()
        .into_owned();
    let home = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) }
        .to_string_lossy()
        .into_owned();

    let shell = if shell.is_empty() {
        "/bin/sh".to_owned()
    } else {
        shell
    };

    Ok((shell, home, pw.pw_uid, pw.pw_gid))
}
