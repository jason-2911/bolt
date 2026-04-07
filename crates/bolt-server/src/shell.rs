//! Server-side shell channel: PTY allocation and bidirectional I/O relay.
//!
//! Unix: uses openpty(2) with login shell under the user's uid/gid.
//! Windows: uses the ConPTY API (CreatePseudoConsole) with cmd.exe or pwsh.

pub async fn handle_shell(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    user: &str,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    return unix::handle_shell_unix(send, recv, user).await;

    #[cfg(windows)]
    return windows::handle_shell_windows(send, recv, user).await;

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (send, recv, user);
        anyhow::bail!("shell not supported on this platform");
    }
}

/// Allowlist of environment variable keys safe to forward from client.
pub fn is_safe_env_key(key: &str) -> bool {
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
            | "BOLT_GUI_TOKEN"
    )
}

// ── Unix ──────────────────────────────────────────────────────────────────

#[cfg(unix)]
mod unix {
    use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
    use std::process::Stdio;

    #[cfg(target_os = "macos")]
    use std::fs;

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

    pub async fn handle_shell_unix(
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
                    if super::is_safe_env_key(&key) {
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

        let pty = openpty(None, None).context("openpty")?;
        let master_fd: RawFd = pty.master.into_raw_fd();
        let slave_fd: RawFd = pty.slave.into_raw_fd();
        set_winsize(master_fd, cols as u16, rows as u16);

        let (shell_path, home_dir, uid, gid) = resolve_user(user)?;
        debug!(user, shell = %shell_path, home = %home_dir, uid, gid, "resolved user");

        let gui_token = extra_env
            .iter()
            .find(|(k, _)| k == "BOLT_GUI_TOKEN")
            .map(|(_, v)| v.clone());
        let base_path = server_base_path();
        let gui_wrapper_dir = setup_gui_wrappers(gui_token.as_deref())?;
        let shell_path_env = if let Some(dir) = gui_wrapper_dir.as_deref() {
            format!("{}:{base_path}", dir.display())
        } else {
            base_path.clone()
        };

        let slave_stdin = slave_fd;
        let slave_stdout = unsafe { libc::dup(slave_fd) };
        let slave_stderr = unsafe { libc::dup(slave_fd) };

        let mut cmd = Command::new(&shell_path);
        cmd.arg("-l")
            .env_clear()
            .env("TERM", &term)
            .env("HOME", &home_dir)
            .env("USER", user)
            .env("LOGNAME", user)
            .env("SHELL", &shell_path)
            .env("PATH", &shell_path_env)
            .env(
                "LANG",
                std::env::var("LANG").unwrap_or_else(|_| "en_US.UTF-8".into()),
            )
            .current_dir(&home_dir);

        populate_server_gui_env(&mut cmd);

        for (k, v) in &extra_env {
            cmd.env(k, v);
        }
        if gui_wrapper_dir.is_some() {
            cmd.env("BOLT_ORIG_PATH", base_path)
                .env("BOLT_GUI_CLAIM_DIR", gui_claim_dir().display().to_string());
        }

        let mut child = unsafe {
            cmd.stdin(Stdio::from_raw_fd(slave_stdin))
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

        loop {
            tokio::select! {
                data = pty_rx.recv() => {
                    let Some(data) = data else { break };
                    if write_msg(send, &Message::Data(data)).await.is_err() {
                        break;
                    }
                }
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
                status = child.wait() => {
                    let code = status
                        .map(|s| s.code().unwrap_or(1))
                        .unwrap_or(1);
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

    fn gui_claim_dir() -> std::path::PathBuf {
        std::path::PathBuf::from("/tmp/bolt-gui-claims")
    }

    fn server_base_path() -> String {
        std::env::var("PATH")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string())
    }

    fn populate_server_gui_env(cmd: &mut Command) {
        #[cfg(target_os = "linux")]
        for key in [
            "DISPLAY",
            "XAUTHORITY",
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_RUNTIME_DIR",
            "XDG_SESSION_TYPE",
            "DESKTOP_SESSION",
        ] {
            if let Ok(value) = std::env::var(key) {
                if !value.is_empty() {
                    cmd.env(key, value);
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        let _ = cmd;
    }

    fn setup_gui_wrappers(gui_token: Option<&str>) -> anyhow::Result<Option<std::path::PathBuf>> {
        #[cfg(target_os = "macos")]
        {
            let Some(gui_token) = gui_token else {
                return Ok(None);
            };

            let claim_dir = gui_claim_dir();
            fs::create_dir_all(&claim_dir).context("create GUI claim dir")?;

            let wrapper_dir =
                std::path::PathBuf::from(format!("/tmp/bolt-gui-wrapper-{gui_token}"));
            fs::create_dir_all(&wrapper_dir).context("create GUI wrapper dir")?;

            write_wrapper(
                &wrapper_dir.join("bolt-gui-claim"),
                r#"#!/bin/sh
set -eu
token=${BOLT_GUI_TOKEN:?}
claim_dir=${BOLT_GUI_CLAIM_DIR:?}
owner=${1:?}
pid=${2:-}
mkdir -p "$claim_dir"
tmp="$claim_dir/$token.tmp"
{
  printf 'owner=%s\n' "$owner"
  if [ -n "$pid" ]; then
    printf 'pid=%s\n' "$pid"
  fi
  printf 'updated=%s\n' "$(/bin/date +%s)"
} > "$tmp"
/bin/mv "$tmp" "$claim_dir/$token"
"#,
            )?;

            write_wrapper(
                &wrapper_dir.join("code"),
                r#"#!/bin/sh
set -eu
PATH=${BOLT_ORIG_PATH:?}
/usr/bin/open -na "Visual Studio Code" --args "$@"
/bin/sleep 1
pid=$(/usr/bin/pgrep -nx Code || true)
"$(dirname "$0")/bolt-gui-claim" "Code" "$pid"
"#,
            )?;

            write_wrapper(
                &wrapper_dir.join("open"),
                r#"#!/bin/sh
set -eu
PATH=${BOLT_ORIG_PATH:?}
if [ "${1:-}" = "-a" ] && [ -n "${2:-}" ]; then
  app="$2"
  shift 2
  /usr/bin/open -na "$app" "$@"
  /bin/sleep 1
  case "$app" in
    "Google Chrome") proc_name="Google Chrome" ;;
    "Visual Studio Code") proc_name="Code" ;;
    "Cursor") proc_name="Cursor" ;;
    *) proc_name="$app" ;;
  esac
  pid=$(/usr/bin/pgrep -nx "$proc_name" || true)
  "$(dirname "$0")/bolt-gui-claim" "$proc_name" "$pid"
  exit 0
fi
/usr/bin/open "$@"
"#,
            )?;

            Ok(Some(wrapper_dir))
        }

        #[cfg(target_os = "linux")]
        {
            let _ = gui_token;
            Ok(None)
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = gui_token;
            Ok(None)
        }
    }

    #[cfg(target_os = "macos")]
    fn write_wrapper(path: &std::path::Path, body: &str) -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, body).with_context(|| format!("write wrapper {}", path.display()))?;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(path, perms)
            .with_context(|| format!("chmod wrapper {}", path.display()))?;
        Ok(())
    }
}

// ── Windows ConPTY ────────────────────────────────────────────────────────

#[cfg(windows)]
mod windows {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use anyhow::{bail, Context as _};
    use tokio::sync::mpsc;
    use tracing::debug;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{ReadFile, WriteFile},
        System::{
            Console::{ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON},
            Pipes::CreatePipe,
            Threading::{
                CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
                InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
                EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTF_USESTDHANDLES, STARTUPINFOEXW,
            },
        },
    };

    use bolt_proto::{read_msg, write_msg, Message};

    pub async fn handle_shell_windows(
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        _user: &str,
    ) -> anyhow::Result<()> {
        // Collect EnvSet messages, then read PtyRequest
        let mut _extra_env: Vec<(String, String)> = Vec::new();

        let (_term, cols, rows) = loop {
            let Some(msg) = read_msg(recv).await? else {
                return Ok(());
            };
            match msg {
                Message::EnvSet { key, val } => {
                    if super::is_safe_env_key(&key) {
                        _extra_env.push((key, val));
                    }
                }
                Message::PtyRequest { term, cols, rows } => break (term, cols, rows),
                other => {
                    debug!("expected PtyRequest, got {other:?}");
                    return Ok(());
                }
            }
        };

        debug!(cols, rows, "ConPTY request");

        // Create pipes: pty_input_read → ConPTY input, ConPTY output → pty_output_write
        let (pty_input_read, pty_input_write) = create_pipe()?;
        let (pty_output_read, pty_output_write) = create_pipe()?;

        // Create ConPTY
        let size = COORD {
            X: cols as i16,
            Y: rows as i16,
        };
        let hpc = unsafe {
            let mut hpc: HPCON = std::ptr::null_mut();
            let hr = CreatePseudoConsole(size, pty_input_read, pty_output_write, 0, &mut hpc);
            if hr != 0 {
                bail!("CreatePseudoConsole failed: 0x{hr:08X}");
            }
            // Close the handles that are now owned by the ConPTY
            CloseHandle(pty_input_read);
            CloseHandle(pty_output_write);
            hpc
        };

        // Build STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
        let mut siex = build_startup_info(hpc)?;

        // Determine shell: pwsh.exe → powershell.exe → cmd.exe
        let shell_cmd = find_windows_shell();
        let mut cmd_wide: Vec<u16> = OsStr::new(&shell_cmd)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmd_wide.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0, // bInheritHandles = FALSE
                EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                std::ptr::null(),
                &mut siex.StartupInfo as *mut _ as *mut _,
                &mut pi,
            )
        };
        if ok == 0 {
            bail!("CreateProcessW failed");
        }

        unsafe { DeleteProcThreadAttributeList(siex.lpAttributeList) };

        let hprocess = pi.hProcess;
        let hthread = pi.hThread;
        unsafe { CloseHandle(hthread) };

        // I/O relay via blocking threads
        let (pty_tx, mut pty_rx) = mpsc::channel::<Vec<u8>>(64);
        let out_handle = pty_output_read;
        let pty_reader = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 4096];
            loop {
                let mut read = 0u32;
                let ok = unsafe {
                    ReadFile(
                        out_handle,
                        buf.as_mut_ptr().cast(),
                        buf.len() as u32,
                        &mut read,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 || read == 0 {
                    break;
                }
                if pty_tx.blocking_send(buf[..read as usize].to_vec()).is_err() {
                    break;
                }
            }
        });

        let (net_tx, mut net_rx) = mpsc::channel::<Vec<u8>>(64);
        let in_handle = pty_input_write;
        let pty_writer = tokio::task::spawn_blocking(move || {
            while let Some(data) = net_rx.blocking_recv() {
                let mut written = 0u32;
                unsafe {
                    WriteFile(
                        in_handle,
                        data.as_ptr().cast(),
                        data.len() as u32,
                        &mut written,
                        std::ptr::null_mut(),
                    );
                }
            }
            unsafe { CloseHandle(in_handle) };
        });

        // Main relay loop
        loop {
            tokio::select! {
                data = pty_rx.recv() => {
                    let Some(data) = data else { break };
                    if write_msg(send, &Message::Data(data)).await.is_err() {
                        break;
                    }
                }
                result = read_msg(recv) => {
                    match result {
                        Ok(Some(Message::Data(data))) => {
                            if net_tx.send(data).await.is_err() { break; }
                        }
                        Ok(Some(Message::WindowChange { cols, rows })) => {
                            let sz = COORD { X: cols as i16, Y: rows as i16 };
                            unsafe { ResizePseudoConsole(hpc, sz) };
                        }
                        Ok(Some(Message::Signal { .. })) => {
                            // Windows: send Ctrl+C via GenerateConsoleCtrlEvent (not via signal)
                        }
                        Ok(Some(Message::Eof)) | Ok(None) | Err(_) => break,
                        Ok(Some(_)) => {}
                    }
                }
                // Poll process exit
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    let mut exit_code = 0u32;
                    let exited = unsafe {
                        GetExitCodeProcess(hprocess, &mut exit_code) != 0 && exit_code != 259 // STILL_ACTIVE
                    };
                    if exited {
                        drop(net_tx);
                        while let Some(data) = pty_rx.recv().await {
                            write_msg(send, &Message::Data(data)).await.ok();
                        }
                        write_msg(send, &Message::ExitStatus { code: exit_code as i32 }).await.ok();
                        break;
                    }
                }
            }
        }

        pty_reader.abort();
        pty_writer.abort();
        unsafe {
            WaitForSingleObject(hprocess, 1000);
            CloseHandle(hprocess);
            ClosePseudoConsole(hpc);
        }

        Ok(())
    }

    fn create_pipe() -> anyhow::Result<(HANDLE, HANDLE)> {
        let mut read: HANDLE = INVALID_HANDLE_VALUE;
        let mut write: HANDLE = INVALID_HANDLE_VALUE;
        let ok = unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) };
        if ok == 0 {
            bail!("CreatePipe failed");
        }
        Ok((read, write))
    }

    fn build_startup_info(hpc: HPCON) -> anyhow::Result<STARTUPINFOEXW> {
        let mut attr_list_size: usize = 0;
        // First call to get required size
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_list_size);
        }
        let mut attr_list_buf = vec![0u8; attr_list_size];
        let attr_list = attr_list_buf.as_mut_ptr() as _;

        let ok = unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_list_size) };
        if ok == 0 {
            bail!("InitializeProcThreadAttributeList failed");
        }

        let ok = unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                hpc as *mut _,
                std::mem::size_of::<HPCON>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            bail!("UpdateProcThreadAttribute failed");
        }

        let mut siex: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        siex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        siex.lpAttributeList = attr_list;
        // Keep attr_list_buf alive for the lifetime of siex
        std::mem::forget(attr_list_buf);

        Ok(siex)
    }

    fn find_windows_shell() -> String {
        // Try modern PowerShell, then Windows PowerShell, then cmd.exe
        for candidate in &["pwsh.exe", "powershell.exe", "cmd.exe"] {
            if std::path::Path::new(candidate).exists() {
                return candidate.to_string();
            }
        }
        // Fall back to cmd.exe via system path
        "cmd.exe".to_string()
    }
}
