//! The kernel says when a watched file changes (inotify), so the cron watch scans at once
//! instead of at its next minute: a change undone within the minute is still seen, and an
//! alert comes seconds after the write. The minute scan stays as the fallback (inotify
//! misses nothing on a local filesystem, but watches are per directory and bounded).
//!
//! Directories are watched, not files: a file replaced by rename (what editors and
//! installers do) keeps its watch that way, and a new file in `/etc/cron.d` is seen.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Most directories watched (each costs one inotify watch; the default limit per user is
/// 8192 or more).
pub const MAX_WATCHES: usize = 512;
/// Changes within this long of each other make one scan.
pub const DEBOUNCE: Duration = Duration::from_secs(2);

/// The paths a pattern matches now, with `*` and `?` in any component (`/home/*/.ssh/*`):
/// files and directories alike.
pub fn expand(pattern: &str) -> Vec<PathBuf> {
    let mut current = vec![PathBuf::from("/")];
    for part in pattern.split('/').filter(|p| !p.is_empty()) {
        let mut next = Vec::new();
        for dir in &current {
            if part.contains(['*', '?']) {
                if let Ok(rd) = std::fs::read_dir(dir) {
                    next.extend(
                        rd.flatten().filter(|e| e.file_name().to_str().is_some_and(|n| crate::sshaudit::glob(part, n))).map(|e| e.path()),
                    );
                }
            } else {
                let p = dir.join(part);
                if p.exists() {
                    next.push(p);
                }
            }
            if next.len() > 4096 {
                break;
            }
        }
        current = next;
    }
    current
}

/// The directories to watch for a set of file patterns and directories: a pattern's fixed
/// part before its first `*` (so a new home or crontab is seen), and the directory of every
/// file it matches now.
pub fn directories(patterns: &[String], dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = BTreeSet::new();
    for d in dirs {
        out.insert(d.clone());
    }
    for p in patterns {
        let fixed = match p.find(['*', '?']) {
            Some(i) => &p[..i],
            None => p.as_str(),
        };
        let fixed = Path::new(fixed);
        let dir = if fixed.is_dir() { fixed.to_path_buf() } else { fixed.parent().map(Path::to_path_buf).unwrap_or_default() };
        if !dir.as_os_str().is_empty() {
            out.insert(dir);
        }
        for f in expand(p) {
            if f.is_dir() {
                out.insert(f);
            } else if let Some(parent) = f.parent() {
                out.insert(parent.to_path_buf());
            }
        }
    }
    out.into_iter().filter(|d| d.is_dir()).take(MAX_WATCHES).collect()
}

/// Watches `dirs` and wakes the receiver (one message per burst of changes) until `stop`.
/// Returns how many directories are watched; None where inotify isn't available (not
/// Linux, the watch limit reached, a kernel without it): the caller then only polls.
pub fn watch(dirs: &[PathBuf], stop: Arc<AtomicBool>) -> (Receiver<()>, Option<usize>) {
    let (tx, rx) = mpsc::sync_channel::<()>(1);
    let watched = linux::start(dirs, tx, stop);
    (rx, watched)
}

/// Waits for the next scan: a change (debounced) or the interval, whichever comes first.
/// False when stopping.
pub fn wait(rx: &Receiver<()>, interval: Duration, stop: &AtomicBool) -> bool {
    let until = Instant::now() + interval;
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        match rx.recv_timeout(left.min(Duration::from_secs(1))) {
            Ok(()) => {
                // more changes within the debounce window make one scan
                let quiet_until = Instant::now() + DEBOUNCE;
                while let Ok(()) = rx.recv_timeout(quiet_until.saturating_duration_since(Instant::now())) {}
                return !stop.load(Ordering::Relaxed);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                thread::sleep(left.min(Duration::from_secs(1)));
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::mpsc::SyncSender;

    pub fn start(dirs: &[PathBuf], tx: SyncSender<()>, stop: Arc<AtomicBool>) -> Option<usize> {
        // SAFETY: plain syscalls with checked arguments; the descriptor is owned by the thread.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        let mask = libc::IN_CREATE
            | libc::IN_MODIFY
            | libc::IN_CLOSE_WRITE
            | libc::IN_MOVED_TO
            | libc::IN_MOVED_FROM
            | libc::IN_DELETE
            | libc::IN_ATTRIB
            | libc::IN_ONLYDIR;
        let mut watched = 0;
        for d in dirs.iter().take(MAX_WATCHES) {
            let Ok(c) = CString::new(d.as_os_str().as_bytes()) else { continue };
            // SAFETY: `c` is a valid C string for the call's duration.
            if unsafe { libc::inotify_add_watch(fd, c.as_ptr(), mask) } >= 0 {
                watched += 1;
            }
        }
        if watched == 0 {
            // SAFETY: fd is ours and open.
            unsafe { libc::close(fd) };
            return None;
        }
        thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                // SAFETY: buf is valid for its length; read blocks until an event or an error.
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if stop.load(Ordering::Relaxed) || n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
                if n > 0 {
                    // one wake-up per burst: a full channel means a scan is already due
                    let _ = tx.try_send(());
                }
            }
            // SAFETY: fd is ours and open.
            unsafe { libc::close(fd) };
        });
        Some(watched)
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    use super::*;
    use std::sync::mpsc::SyncSender;

    pub fn start(_dirs: &[PathBuf], _tx: SyncSender<()>, _stop: Arc<AtomicBool>) -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directories_come_from_patterns_and_their_matches() {
        let d = std::env::temp_dir().join(format!("lg-inotify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("cron.d")).unwrap();
        std::fs::create_dir_all(d.join("home/alice/.ssh")).unwrap();
        std::fs::write(d.join("home/alice/.ssh/authorized_keys"), "k").unwrap();
        std::fs::write(d.join("crontab"), "").unwrap();
        let base = d.display().to_string();
        let patterns = [
            format!("{base}/cron.d/*"),
            format!("{base}/home/*/.ssh/authorized_keys"),
            format!("{base}/crontab"),
            format!("{base}/missing/file"),
        ];
        let dirs = directories(&patterns, &[d.join("cron.d"), d.join("nowhere")]);
        let names: Vec<String> = dirs.iter().map(|p| p.strip_prefix(&d).unwrap().display().to_string()).collect();
        assert_eq!(names, ["", "cron.d", "home", "home/alice/.ssh"], "{names:?}");
        let files: Vec<PathBuf> = expand(&patterns[1]);
        assert_eq!(files, [d.join("home/alice/.ssh/authorized_keys")]);
        assert!(expand(&patterns[3]).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn wait_returns_at_the_interval_or_a_change() {
        let (tx, rx) = mpsc::sync_channel::<()>(1);
        let stop = AtomicBool::new(false);
        let t = Instant::now();
        assert!(wait(&rx, Duration::from_millis(300), &stop));
        assert!(t.elapsed() >= Duration::from_millis(300), "the interval passed");
        tx.try_send(()).unwrap();
        let t = Instant::now();
        assert!(wait(&rx, Duration::from_secs(30), &stop));
        assert!(t.elapsed() < Duration::from_secs(5), "woken by the change (after the debounce)");
        stop.store(true, Ordering::Relaxed);
        assert!(!wait(&rx, Duration::from_secs(30), &stop));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_write_wakes_the_watcher() {
        let d = std::env::temp_dir().join(format!("lg-inotify-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (rx, watched) = watch(std::slice::from_ref(&d), Arc::clone(&stop));
        assert_eq!(watched, Some(1));
        thread::sleep(Duration::from_millis(200));
        std::fs::write(d.join("crontab"), "* * * * * root true\n").unwrap();
        let t = Instant::now();
        assert!(wait(&rx, Duration::from_secs(30), &stop));
        assert!(t.elapsed() < Duration::from_secs(10));
        stop.store(true, Ordering::Relaxed);
        let _ = std::fs::remove_dir_all(&d);
    }
}
