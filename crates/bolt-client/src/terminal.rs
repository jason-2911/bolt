//! Raw terminal mode helpers (macOS / Linux).

use std::os::unix::io::{BorrowedFd, RawFd};

use nix::{
    libc,
    sys::termios::{self, Termios},
};

/// Saved terminal state for restore.
pub struct TermState {
    fd:   RawFd,
    orig: Termios,
}

impl TermState {
    /// Switch the terminal on `fd` to raw mode. Returns a guard that
    /// restores the original settings when dropped.
    pub fn make_raw(fd: RawFd) -> anyhow::Result<Self> {
        let bfd = unsafe { BorrowedFd::borrow_raw(fd) };
        let orig = termios::tcgetattr(&bfd)?;
        let mut raw = orig.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&bfd, termios::SetArg::TCSANOW, &raw)?;
        Ok(Self { fd, orig })
    }

    pub fn restore(&self) {
        let bfd = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let _ = termios::tcsetattr(&bfd, termios::SetArg::TCSANOW, &self.orig);
    }
}

impl Drop for TermState {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Return (cols, rows) of the terminal on `fd`.
pub fn terminal_size(fd: RawFd) -> (u32, u32) {
    let mut ws = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    (ws.ws_col as u32, ws.ws_row as u32)
}
