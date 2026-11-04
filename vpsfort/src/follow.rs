//! Follows a log file (a `[[patterns]] file`, an app's log of `[sources] apps`, auditd's
//! file) and remembers where it was: `file-positions.json` next to the state file holds each
//! file's inode and offset, saved every 30 seconds and at stop. After a restart or an upgrade
//! the lines written meanwhile are read too, instead of being skipped as `tail -F` from the
//! end would. A position older than [`MAX_CATCHUP`] is not resumed (the lines would be scored
//! as if they were new); a file whose inode changed while vpsfort was down (rotated) is read
//! from its start, up to [`MAX_CATCHUP_BYTES`] behind its end.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::time::{self, Micros, SEC};

/// A saved position older than this is left alone: the file is read from its end.
pub const MAX_CATCHUP: Micros = 24 * 3600 * SEC;
/// At most this much of a file is read back after a restart.
pub const MAX_CATCHUP_BYTES: u64 = 64 * 1024 * 1024;
/// The longest line taken as one (the rest of a longer one is dropped).
pub const MAX_LINE: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePos {
    pub inode: u64,
    /// The offset after the last complete line read.
    pub offset: u64,
    /// When it was last updated.
    pub at: Micros,
}

/// The followed files' positions, shared by their follower threads and saved by one of them.
pub struct Positions {
    path: Option<PathBuf>,
    inner: Mutex<BTreeMap<String, FilePos>>,
    dirty: AtomicBool,
}

impl Positions {
    /// The positions kept next to `state_file` (none: in memory only, for tests and replays).
    pub fn load(state_file: &Path) -> Arc<Self> {
        let path = state_file.parent().map(|d| d.join("file-positions.json"));
        let inner = path
            .as_deref()
            .and_then(|p| fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<BTreeMap<String, FilePos>>(&b).ok())
            .unwrap_or_default();
        Arc::new(Positions { path, inner: Mutex::new(inner), dirty: AtomicBool::new(false) })
    }

    pub fn in_memory() -> Arc<Self> {
        Arc::new(Positions { path: None, inner: Mutex::default(), dirty: AtomicBool::new(false) })
    }

    pub fn get(&self, file: &str) -> Option<FilePos> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).get(file).copied()
    }

    pub fn set(&self, file: &str, pos: FilePos) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).insert(file.to_string(), pos);
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Writes the file when something changed since the last save (atomically, mode 0600).
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return Ok(());
        }
        let bytes = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            serde_json::to_vec(&*inner)?
        };
        let tmp = path.with_extension("json.tmp");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            std::io::Write::write_all(&mut f, &bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
    }

    /// Saves every 30 seconds while something changed, and once more when `stop` is set.
    pub fn save_periodically(self: &Arc<Self>, stop: Arc<AtomicBool>) {
        let me = Arc::clone(self);
        thread::spawn(move || {
            let mut ticks = 0u32;
            loop {
                thread::sleep(Duration::from_secs(1));
                ticks += 1;
                let stopping = stop.load(Ordering::Relaxed);
                if ticks.is_multiple_of(30) || stopping {
                    if let Err(e) = me.save() {
                        eprintln!("vpsfort: file positions: cannot save: {e}");
                    }
                }
                if stopping {
                    return;
                }
            }
        });
    }
}

/// Where to start reading `path` now, given its saved position (if any): the offset, and
/// a note for the journal when lines are read back.
pub fn start_offset(saved: Option<FilePos>, inode: u64, size: u64, now: Micros) -> (u64, Option<String>) {
    match saved {
        Some(p) if now.saturating_sub(p.at) <= MAX_CATCHUP && p.inode == inode && p.offset <= size => {
            let behind = size - p.offset;
            (p.offset, (behind > 0).then(|| format!("reading {behind} bytes written since the last run")))
        }
        // rotated while vpsfort was down: the new file is all unread
        Some(p) if now.saturating_sub(p.at) <= MAX_CATCHUP && p.inode != inode => {
            let from = size.saturating_sub(MAX_CATCHUP_BYTES);
            (from, Some(format!("the file was rotated since the last run: reading it from {from}")))
        }
        _ => (size, None),
    }
}

/// Opens a followed log as a root process should: the path itself, never a link (a service's
/// user who owns the log directory, as postgres, mysql or redis do, could otherwise point
/// the reader at any file of the host), and a regular file only (a pipe would hold the
/// reader forever, a device feed it endless lines).
fn open_log(path: &str) -> std::io::Result<(File, fs::Metadata)> {
    use std::os::unix::fs::OpenOptionsExt;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::other("a symbolic link: not followed (a log is read at its own path only)"));
    }
    let flags = crate::sys::O_NOFOLLOW | crate::sys::O_NONBLOCK | crate::sys::O_NOCTTY;
    let f = fs::OpenOptions::new().read(true).custom_flags(flags).open(path)?;
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(std::io::Error::other("not a regular file (a pipe, a device, a directory): not read"));
    }
    Ok((f, m))
}

/// Follows `path`, calling `line` for each complete line (without its line end), until
/// `stop`. Lines read before the saved position, or written while vpsfort was down longer
/// than [`MAX_CATCHUP`], are not read. Returns when `stop` is set or `line` says so (false).
pub fn follow(path: &str, positions: &Positions, stop: &AtomicBool, mut line: impl FnMut(String) -> bool) {
    let mut warned = false;
    let mut current: Option<(File, u64, u64)> = None; // (file, inode, offset)
    while !stop.load(Ordering::Relaxed) {
        if current.is_none() {
            match open_log(path) {
                Ok((f, m)) => {
                    let (offset, note) = start_offset(positions.get(path), m.ino(), m.len(), time::now());
                    if let Some(note) = note {
                        eprintln!("vpsfort: {path}: {note}");
                    }
                    current = Some((f, m.ino(), offset));
                    warned = false;
                }
                Err(e) => {
                    if !warned {
                        warned = true;
                        eprintln!("vpsfort: {path}: cannot open (will keep trying): {e}");
                    }
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
            }
        }
        let Some((file, inode, offset)) = current.as_mut() else { continue };
        let mut reader = BufReader::new(&*file);
        if reader.seek(SeekFrom::Start(*offset)).is_err() {
            current = None;
            continue;
        }
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match crate::record::read_line_capped(&mut reader, &mut buf, MAX_LINE) {
                Ok(0) => break,
                Ok(n) if buf.last() == Some(&b'\n') || n as u64 >= MAX_LINE => {
                    *offset += n as u64;
                    let text = String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string();
                    if !line(text) {
                        return;
                    }
                }
                // an incomplete line: wait for the rest
                Ok(_) => break,
                Err(_) => break,
            }
        }
        positions.set(path, FilePos { inode: *inode, offset: *offset, at: time::now() });
        drop(reader);
        thread::sleep(Duration::from_secs(1));
        // rotated or truncated: the next round opens the new file from its start
        match fs::metadata(path) {
            Ok(m) if m.ino() != *inode => {
                positions.set(path, FilePos { inode: m.ino(), offset: 0, at: time::now() });
                current = None;
            }
            Ok(m) if m.len() < *offset => *offset = 0,
            Ok(_) => {}
            Err(_) => current = None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lg-follow-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn start_offset_resumes_rotations_and_old_positions() {
        let now = 1_000_000 * SEC;
        let fresh = FilePos { inode: 7, offset: 100, at: now - 60 * SEC };
        assert_eq!(start_offset(None, 7, 500, now).0, 500, "a new file is read from its end");
        assert_eq!(start_offset(Some(fresh), 7, 500, now).0, 100, "resumed");
        assert_eq!(start_offset(Some(fresh), 7, 50, now).0, 50, "truncated below the offset: from the end");
        assert_eq!(start_offset(Some(fresh), 8, 500, now).0, 0, "rotated: the new file from its start");
        assert_eq!(start_offset(Some(fresh), 8, MAX_CATCHUP_BYTES + 10, now).0, 10, "but at most 64 MB back");
        let old = FilePos { at: now - MAX_CATCHUP - SEC, ..fresh };
        assert_eq!(start_offset(Some(old), 7, 500, now).0, 500, "too old to resume");
    }

    /// A link, a pipe or a directory at the path is not read: a root process follows a
    /// log at its own path only, whatever a user who can write the log's directory puts there.
    #[test]
    fn links_pipes_and_directories_are_not_read() {
        let d = dir("links");
        let real = d.join("real.log");
        fs::write(&real, "secret line\n").unwrap();
        std::os::unix::fs::symlink(&real, d.join("app.log")).unwrap();
        let fifo = d.join("fifo.log");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        for (path, what) in [(d.join("app.log"), "a link"), (fifo.clone(), "a pipe"), (d.clone(), "a directory")] {
            let e = open_log(path.to_str().unwrap()).unwrap_err().to_string();
            assert!(e.contains("link") || e.contains("not a regular file"), "{what}: {e}");
        }
        let (f, _) = open_log(real.to_str().unwrap()).unwrap();
        drop(f);
        // and the follower itself: nothing comes from a link, and it returns on stop
        let positions = Positions::in_memory();
        let stop = Arc::new(AtomicBool::new(false));
        let got = Arc::new(Mutex::new(Vec::new()));
        let t = {
            let (p, s, g, path) = (Arc::clone(&positions), Arc::clone(&stop), Arc::clone(&got), d.join("app.log").display().to_string());
            thread::spawn(move || {
                follow(&path, &p, &s, |l| {
                    g.lock().unwrap().push(l);
                    true
                })
            })
        };
        thread::sleep(Duration::from_millis(1200));
        fs::OpenOptions::new().append(true).open(&real).unwrap().write_all(b"another\n").unwrap();
        thread::sleep(Duration::from_millis(1200));
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
        assert!(got.lock().unwrap().is_empty(), "nothing through the link: {:?}", got.lock().unwrap());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn lines_survive_a_restart_and_a_rotation() {
        let d = dir("lines");
        let log = d.join("app.log");
        let log_s = log.display().to_string();
        let positions = Positions::load(&d.join("state.json"));
        fs::write(&log, "old line\n").unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let got = Arc::new(Mutex::new(Vec::new()));
        let t = {
            let (p, s, g, path) = (Arc::clone(&positions), Arc::clone(&stop), Arc::clone(&got), log_s.clone());
            thread::spawn(move || {
                follow(&path, &p, &s, |l| {
                    g.lock().unwrap().push(l);
                    true
                })
            })
        };
        thread::sleep(Duration::from_millis(1500));
        {
            let mut f = fs::OpenOptions::new().append(true).open(&log).unwrap();
            f.write_all(b"new line\npartial").unwrap();
        }
        thread::sleep(Duration::from_millis(2500));
        assert_eq!(*got.lock().unwrap(), ["new line"], "the old line is skipped, the partial one waits");
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
        positions.save().unwrap();
        let pos = positions.get(&log_s).unwrap();
        assert_eq!(pos.offset, "old line\nnew line\n".len() as u64);

        // a restart: the partial line was completed and more was written meanwhile
        {
            let mut f = fs::OpenOptions::new().append(true).open(&log).unwrap();
            f.write_all(b" line\nwhile down\n").unwrap();
        }
        let positions = Positions::load(&d.join("state.json"));
        assert_eq!(positions.get(&log_s), Some(pos), "read back from disk");
        let stop = Arc::new(AtomicBool::new(false));
        let got = Arc::new(Mutex::new(Vec::new()));
        let t = {
            let (p, s, g, path) = (Arc::clone(&positions), Arc::clone(&stop), Arc::clone(&got), log_s.clone());
            thread::spawn(move || {
                follow(&path, &p, &s, |l| {
                    g.lock().unwrap().push(l);
                    true
                })
            })
        };
        thread::sleep(Duration::from_millis(1500));
        // a rotation: the file is replaced by a new one
        fs::rename(&log, d.join("app.log.1")).unwrap();
        fs::write(&log, "after rotation\n").unwrap();
        thread::sleep(Duration::from_millis(3500));
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
        assert_eq!(*got.lock().unwrap(), ["partial line", "while down", "after rotation"]);
        let _ = fs::remove_dir_all(&d);
    }
}
