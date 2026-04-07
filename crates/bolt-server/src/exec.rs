//! Server-side exec channel: run a command as the authenticated user.

use std::ffi::CString;

use anyhow::Context as _;
use nix::libc;
use tokio::process::Command;

use bolt_proto::{write_msg, Message};

pub async fn handle_exec(
    send: &mut quinn::SendStream,
    _recv: &mut quinn::RecvStream,
    command: &str,
    user: &str,
) -> anyhow::Result<()> {
    let (shell, home, uid, gid) = resolve_user(user)?;

    let output = unsafe {
        Command::new(&shell)
            .arg("-c")
            .arg(command)
            .env_clear()
            .env("HOME", &home)
            .env("USER", user)
            .env("LOGNAME", user)
            .env("SHELL", &shell)
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
            .env(
                "LANG",
                std::env::var("LANG").unwrap_or_else(|_| "en_US.UTF-8".into()),
            )
            .current_dir(&home)
            .pre_exec(move || {
                libc::setgid(gid);
                libc::setuid(uid);
                Ok(())
            })
            .output()
            .await
            .context("exec command")?
    };

    if !output.stdout.is_empty() {
        write_msg(send, &Message::Data(output.stdout)).await?;
    }

    if !output.stderr.is_empty() {
        write_msg(send, &Message::Data(output.stderr)).await?;
    }

    let code = output.status.code().unwrap_or(1);
    write_msg(send, &Message::ExitStatus { code }).await?;

    Ok(())
}

fn resolve_user(user: &str) -> anyhow::Result<(String, String, u32, u32)> {
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
