//! Exclusive locks on the directories a running bot writes in: its state's (state.json, and by
//! default the OMEMO keys, the pins and the outbox), the OMEMO store's and the outbox. Several
//! bots on one host (instances, one per XMPP domain: README, "Several domains") must each have
//! their own: two accounts on one OMEMO store would publish the same device and overwrite each
//! other's sessions, two bots on one state.json each other's users, and on one outbox each
//! would refuse the other's alerts. The locks are flock(2) on the directories themselves:
//! nothing to create or clean up, and the kernel drops them when the bot ends, crashed or not.

use std::fs::{File, TryLockError};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The held locks; dropping them releases the directories.
#[derive(Debug)]
pub struct DirLocks {
    _held: Vec<File>,
}

/// Why a directory could not be locked.
#[derive(Debug)]
pub struct Refused {
    /// The setting naming the directory, for the message.
    pub setting: &'static str,
    pub dir: PathBuf,
    /// Another process holds it (else `error` says what failed).
    pub busy: bool,
    pub error: io::Error,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.busy {
            write!(f, "{} {} is in use by another vpsfort-xmpp-bot", self.setting, self.dir.display())
        } else {
            write!(f, "{} {}: can't lock it: {}", self.setting, self.dir.display(), self.error)
        }
    }
}

/// Locks each directory of `dirs` (setting, directory), each one once: settings naming the
/// same directory share its lock. A directory that doesn't exist yet is skipped: nothing of
/// the bot's is there to share.
pub fn lock(dirs: &[(&'static str, &Path)]) -> Result<DirLocks, Refused> {
    let mut held: Vec<(u64, u64, File)> = Vec::new();
    for &(setting, dir) in dirs {
        let refused = |busy, error| Refused { setting, dir: dir.to_path_buf(), busy, error };
        // a directory opens read-only like a file, and flock(2) takes any open file
        let file = match File::open(dir) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(refused(false, e)),
        };
        let meta = file.metadata().map_err(|e| refused(false, e))?;
        if !meta.is_dir() {
            return Err(refused(false, io::Error::other("not a directory")));
        }
        // a second lock of the same directory from here would wait for the first one
        if held.iter().any(|(dev, ino, _)| (*dev, *ino) == (meta.dev(), meta.ino())) {
            continue;
        }
        match file.try_lock() {
            Ok(()) => held.push((meta.dev(), meta.ino(), file)),
            Err(TryLockError::WouldBlock) => return Err(refused(true, io::ErrorKind::WouldBlock.into())),
            Err(TryLockError::Error(e)) => return Err(refused(false, e)),
        }
    }
    Ok(DirLocks { _held: held.into_iter().map(|(_, _, f)| f).collect() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vpsfort-xmpp-bot-dirlock-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("outbox")).unwrap();
        dir
    }

    #[test]
    fn a_second_bot_is_refused_until_the_first_ends() {
        let dir = temp("second");
        let outbox = dir.join("outbox");
        let first = lock(&[("BOT_STATE_PATH's directory", &dir), ("OUTBOX_DIR", &outbox)]).unwrap();
        // another instance whose config names the same state directory
        let e = lock(&[("BOT_STATE_PATH's directory", &dir)]).unwrap_err();
        assert!(e.busy && e.setting == "BOT_STATE_PATH's directory", "{e:?}");
        assert!(e.to_string().ends_with("is in use by another vpsfort-xmpp-bot"), "{e}");
        // or only the same outbox
        let other = temp("second-other");
        let e = lock(&[("BOT_STATE_PATH's directory", &other), ("OUTBOX_DIR", &outbox)]).unwrap_err();
        assert!(e.busy && e.setting == "OUTBOX_DIR", "{e:?}");
        // the refused attempt holds nothing: the other's own directory is free
        drop(lock(&[("BOT_STATE_PATH's directory", &other)]).unwrap());
        drop(first);
        lock(&[("BOT_STATE_PATH's directory", &dir), ("OUTBOX_DIR", &outbox)]).unwrap();
    }

    #[test]
    fn one_directory_under_two_settings_is_locked_once() {
        let dir = temp("same");
        let alias = dir.join("outbox").join("..");
        let _held = lock(&[("BOT_STATE_PATH's directory", &dir), ("OMEMO_STORE's directory", &alias)]).unwrap();
    }

    #[test]
    fn missing_directories_are_skipped_and_files_refused() {
        let dir = temp("missing");
        let _held = lock(&[("OUTBOX_DIR", &dir.join("nowhere"))]).unwrap();
        std::fs::write(dir.join("state.json"), "{}").unwrap();
        let e = lock(&[("OUTBOX_DIR", &dir.join("state.json"))]).unwrap_err();
        assert!(!e.busy && e.to_string().contains("not a directory"), "{e}");
    }
}
