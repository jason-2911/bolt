//! Raw terminal mode helpers (macOS / Linux).

use std::os::unix::io::{BorrowedFd, RawFd};

use nix::{
    libc,
    sys::termios::{self, Termios},
};

/// Saved terminal state — restores original settings on drop.
pub struct TermState {
    fd: RawFd,
    orig: Termios,
}

impl TermState {
    /// Switch the terminal on `fd` to raw mode.
    pub fn make_raw(fd: RawFd) -> anyhow::Result<Self> {
        let bfd = unsafe { BorrowedFd::borrow_raw(fd) };
        let orig = termios::tcgetattr(bfd)?;
        let mut raw = orig.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(bfd, termios::SetArg::TCSANOW, &raw)?;
        Ok(Self { fd, orig })
    }
}

impl Drop for TermState {
    fn drop(&mut self) {
        let bfd = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let _ = termios::tcsetattr(bfd, termios::SetArg::TCSANOW, &self.orig);
    }
}

/// Return (cols, rows) of the terminal on `fd`.
pub fn terminal_size(fd: RawFd) -> (u32, u32) {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    (u32::from(ws.ws_col), u32::from(ws.ws_row))
}
