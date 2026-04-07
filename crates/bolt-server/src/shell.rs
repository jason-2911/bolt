//! Server-side shell channel: PTY allocation and bidirectional I/O relay.

use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::process::Stdio;

use anyhow::Context as _;
use nix::{
    libc,
    pty::{openpty, OpenptyResult},
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tracing::debug;

use bolt_proto::channel::{MsgType, PtyRequest, RequestType};
use bolt_session::Stream;

pub async fn handle_shell_channel(stream: &mut Stream) -> anyhow::Result<()> {
    // Read PTY request
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).await?;
    if n < 2 || buf[1] != RequestType::Pty as u8 {
        return Ok(());
    }

    let pty_req = PtyRequest::unmarshal(&buf[..n])?;
    debug!(component = "server", term = %pty_req.term, "PTY request");

    // Allocate PTY
    let pty = openpty(None, None).context("openpty")?;
    let master_fd: RawFd = pty.master.into_raw_fd();
    let slave_fd:  RawFd = pty.slave.into_raw_fd();

    set_winsize(master_fd, pty_req.width_chars as u16, pty_req.height_chars as u16);

    // Spawn shell
    let mut child = unsafe {
        Command::new("/bin/sh")
            .env("TERM", &pty_req.term)
            .stdin(Stdio::from_raw_fd(slave_fd))
            .stdout(Stdio::from_raw_fd(slave_fd))
            .stderr(Stdio::from_raw_fd(slave_fd))
            .pre_exec(|| {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY as _, 0);
                Ok(())
            })
            .spawn()
            .context("spawn shell")?
    };

    let child_pid = child.id().unwrap_or(0) as i32;

    // Async I/O on master PTY
    let master_read  = unsafe { tokio::fs::File::from_raw_fd(master_fd) };
    let master_write = unsafe { tokio::fs::File::from_raw_fd(libc::dup(master_fd)) };
    let mut master_read  = tokio::io::BufReader::new(master_read);
    let mut master_write = tokio::io::BufWriter::new(master_write);

    // Use channels to relay between stream and PTY
    let (net_tx, mut net_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (pty_tx, mut pty_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // PTY master → network
    let pty_read_task = {
        let pty_tx = pty_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match master_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut msg = vec![MsgType::ChannelData as u8];
                        msg.extend_from_slice(&(n as u32).to_be_bytes());
                        msg.extend_from_slice(&buf[..n]);
                        if pty_tx.send(msg).await.is_err() { break; }
                    }
                }
            }
        })
    };

    // Network → PTY master
    let pty_write_task = tokio::spawn(async move {
        while let Some(data) = net_rx.recv().await {
            if master_write.write_all(&data).await.is_err() { break; }
            let _ = master_write.flush().await;
        }
    });

    // Main relay loop
    let mut read_buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            msg = pty_rx.recv() => {
                match msg {
                    Some(data) => { if stream.write_all(&data).await.is_err() { break; } }
                    None => break,
                }
            }
            n = stream.read(&mut read_buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data = &read_buf[..n];
                        if data[0] == MsgType::ChannelRequest as u8 && n > 1 {
                            match data[1] {
                                b if b == RequestType::WindowChange as u8 && n >= 10 => {
                                    let w = u32::from_be_bytes(data[2..6].try_into().unwrap());
                                    let h = u32::from_be_bytes(data[6..10].try_into().unwrap());
                                    set_winsize(master_fd, w as u16, h as u16);
                                }
                                b if b == RequestType::Signal as u8 && n > 3 => {
                                    let sig_len = data[2] as usize;
                                    if n >= 3 + sig_len {
                                        let sig_name = std::str::from_utf8(&data[3..3 + sig_len]).unwrap_or("");
                                        if let Some(sig) = parse_signal(sig_name) {
                                            let _ = kill(Pid::from_raw(child_pid), sig);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        } else if data[0] == MsgType::ChannelData as u8 && n > 5 {
                            let _ = net_tx.send(data[5..n].to_vec()).await;
                        }
                    }
                }
            }
            status = child.wait() => {
                break;
            }
        }
    }

    pty_read_task.abort();
    pty_write_task.abort();
    Ok(())
}

fn set_winsize(fd: RawFd, cols: u16, rows: u16) {
    let ws = libc::winsize { ws_col: cols, ws_row: rows, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
}

fn parse_signal(name: &str) -> Option<Signal> {
    match name {
        "TERM"  => Some(Signal::SIGTERM),
        "KILL"  => Some(Signal::SIGKILL),
        "HUP"   => Some(Signal::SIGHUP),
        "INT"   => Some(Signal::SIGINT),
        "QUIT"  => Some(Signal::SIGQUIT),
        "USR1"  => Some(Signal::SIGUSR1),
        "USR2"  => Some(Signal::SIGUSR2),
        "WINCH" => Some(Signal::SIGWINCH),
        _       => None,
    }
}
