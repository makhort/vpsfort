//! The few libc constants vpsfort declares itself (it has no libc crate). Their values are
//! per architecture; these are those of the release targets: x86_64, aarch64 and 32-bit ARM
//! (Linux, and macOS for development). Another architecture must check them before it builds:
//! MIPS, SPARC and Alpha number signals differently, s390x has its own `POSIX_FADV_DONTNEED`.

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
compile_error!("vpsfort declares libc constants for x86_64, aarch64 and arm only: check src/sys.rs for this architecture");

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
mod consts {
    pub const SIGKILL: i32 = 9;
    pub const SIGPIPE: i32 = 13;
    /// Linux only (`posix_fadvise`).
    pub const POSIX_FADV_DONTNEED: i32 = 4;
    /// `open(2)` flags for files a root process reads at a path someone else may control:
    /// never through a link, never blocking on a pipe or a terminal.
    pub const O_NOFOLLOW: i32 = if !cfg!(target_os = "linux") {
        0x0100
    } else if cfg!(any(target_arch = "arm", target_arch = "aarch64")) {
        0o100000
    } else {
        0o400000
    };
    pub const O_NONBLOCK: i32 = if cfg!(target_os = "linux") { 0o4000 } else { 0x0004 };
    pub const O_NOCTTY: i32 = if cfg!(target_os = "linux") { 0o400 } else { 0x20000 };
}

pub use consts::*;
