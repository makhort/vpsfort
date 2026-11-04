//! The outbox: a directory vpsfort (as root) writes into and the bot empties. The format
//! is vpsfort-xmpp-bot's, so vpsfort's side (its module `botbox`) serves every bot:
//!
//! - admin messages (alerts, the daily digest): `alert-*.msg`, with `To:` and `Subject:`
//!   lines, a blank line, the text. The bot claims one by renaming it to
//!   `.<name>.sending`, sends it, deletes it; if sending fails it renames it back.
//! - files (the weekly abuse report): any other regular file, written under a dot name
//!   first and then renamed into place. Deleted once sent, or unsent after the retention
//!   time.
//!
//! Unlike vpsfort-xmpp-bot's, this outbox has no fallback on vpsfort's side: a message waits
//! here until the bot sends it or it gets too old (vpsfort warns when one waits too long).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Larger files are left alone (and deleted when they expire): a weekly report is ~50 KB,
/// and the services take uploads of tens of MB (a bot with a smaller limit passes its own
/// to [`scan_with_limit`]).
pub const MAX_FILE: u64 = 20 * 1024 * 1024;

/// What is in the outbox: files to send now (oldest name first), and files older than the
/// retention time, to delete unsent.
#[derive(Debug, Default, PartialEq)]
pub struct Pending {
    pub ready: Vec<PathBuf>,
    pub expired: Vec<PathBuf>,
}

/// An alert larger than this is not one of vpsfort's (they are a few KB): it is not read.
pub const MAX_MESSAGE: u64 = 1 << 20;

/// An alert file's text, if it is one: at most [`MAX_MESSAGE`] bytes of UTF-8 in the
/// format of [`parse_message`].
pub fn read_message(path: &Path) -> Option<String> {
    read_message_text(path).and_then(|t| parse_message(&t))
}

/// The file's text, if it is small enough and UTF-8.
fn read_message_text(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path).ok()?.take(MAX_MESSAGE + 1).read_to_string(&mut text).ok()?;
    if text.len() as u64 > MAX_MESSAGE {
        return None;
    }
    Some(text)
}

/// Whether the bot can create (and so rename and delete) entries in `dir`: a dot file it
/// removes again, which vpsfort and the scans ignore.
pub fn writable(dir: &Path) -> std::io::Result<()> {
    let probe = dir.join(format!(".vpsfort-bot-probe-{}", std::process::id()));
    std::fs::OpenOptions::new().write(true).create_new(true).open(&probe)?;
    std::fs::remove_file(&probe)
}

/// vpsfort's alert messages: `alert-*.msg`.
pub fn is_message(name: &str) -> bool {
    name.starts_with("alert-") && name.ends_with(".msg")
}

/// The name a message has while the bot sends it.
pub fn claimed(path: &Path, state: &str) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(".{name}.{state}"))
}

/// The messages waiting (oldest first) with their age: regular files only.
pub fn scan_messages(dir: &Path, now: SystemTime) -> std::io::Result<Vec<(PathBuf, Duration)>> {
    let mut v = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else { continue };
        if meta.file_type().is_file() && entry.file_name().to_str().is_some_and(is_message) {
            let age = meta.modified().ok().and_then(|m| now.duration_since(m).ok()).unwrap_or_default();
            v.push((entry.path(), age));
        }
    }
    v.sort();
    Ok(v)
}

/// Messages left half-sent by a bot that stopped (`.alert-*.msg.sending`), put back to be
/// sent again. Returns how many.
pub fn recover(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let mut n = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(base) = name.to_str().and_then(|n| n.strip_prefix('.')?.strip_suffix(".sending")) else { continue };
        if is_message(base) && std::fs::rename(entry.path(), dir.join(base)).is_ok() {
            n += 1;
        }
    }
    n
}

/// An alert message's text (its first line is the subject already). The recipient, an
/// XMPP address, is checked to be there and otherwise ignored: the bot has one admin.
pub fn parse_message(text: &str) -> Option<String> {
    parse_subject_and_message(text).map(|(_, body)| body)
}

/// An alert file's subject and text (the mail bot's way: the subject becomes the mail's),
/// if it is one.
pub fn read_subject_and_message(path: &Path) -> Option<(String, String)> {
    read_message_text(path).and_then(|t| parse_subject_and_message(&t))
}

/// An alert message's subject and text. The recipient (an XMPP address, or `admin`) is
/// checked to be there and otherwise ignored. Without a subject, the text's first line is
/// the subject.
pub fn parse_subject_and_message(text: &str) -> Option<(String, String)> {
    let (head, body) = text.split_once("\n\n")?;
    let (mut to, mut subject) = (None, None);
    for line in head.lines() {
        match line.split_once(": ") {
            Some(("To", v)) => to = Some(v.trim()),
            Some(("Subject", v)) => subject = Some(v.trim().to_string()),
            _ => return None,
        }
    }
    to.filter(|t| !t.is_empty())?;
    let subject = subject.filter(|s| !s.is_empty()).unwrap_or_else(|| body.lines().next().unwrap_or("vpsfort").to_string());
    Some((subject, body.to_string()))
}

/// Files to send: regular files only (no links, no directories), not dot files (still
/// being written or claimed) and not alert messages.
pub fn scan(dir: &Path, max_age: Duration, now: SystemTime) -> std::io::Result<Pending> {
    scan_with_limit(dir, max_age, MAX_FILE, now)
}

/// [`scan`] with the bot's own size limit for files.
pub fn scan_with_limit(dir: &Path, max_age: Duration, max_file: u64, now: SystemTime) -> std::io::Result<Pending> {
    let mut p = Pending::default();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else { continue };
        if name.starts_with('.') || is_message(name) || !meta.file_type().is_file() {
            continue;
        }
        let age = meta.modified().ok().and_then(|m| now.duration_since(m).ok()).unwrap_or_default();
        if age > max_age || meta.len() > max_file {
            p.expired.push(entry.path());
        } else {
            p.ready.push(entry.path());
        }
    }
    p.ready.sort();
    p.expired.sort();
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[PathBuf]) -> Vec<String> {
        v.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect()
    }

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vpsfort-botlib-outbox-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn oversized_or_binary_messages_are_not_read() {
        let dir = tmp("read");
        let ok = dir.join("alert-1.msg");
        std::fs::write(&ok, "To: a\nSubject: s\n\nbody").unwrap();
        assert_eq!(read_message(&ok).as_deref(), Some("body"));
        let big = dir.join("alert-2.msg");
        std::fs::write(&big, format!("To: a\nSubject: s\n\n{}", "x".repeat(MAX_MESSAGE as usize))).unwrap();
        assert_eq!(read_message(&big), None);
        let binary = dir.join("alert-3.msg");
        std::fs::write(&binary, b"To: a\nSubject: s\n\n\xff\xfe").unwrap();
        assert_eq!(read_message(&binary), None);
        assert_eq!(read_message(&dir.join("missing.msg")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_picks_finished_regular_files() {
        let dir = tmp("files");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("abuse-report-2026-10-19.txt"), "b").unwrap();
        std::fs::write(dir.join("abuse-report-2026-10-12.txt"), "a").unwrap();
        std::fs::write(dir.join(".abuse-report-2026-10-26.txt.tmp"), "being written").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("link.txt")).unwrap();
        let now = SystemTime::now();
        let p = scan(&dir, Duration::from_secs(7 * 86400), now).unwrap();
        assert_eq!(names(&p.ready), ["abuse-report-2026-10-12.txt", "abuse-report-2026-10-19.txt"]);
        assert!(p.expired.is_empty());
        // eight days later both are past a seven-day retention
        let later = scan(&dir, Duration::from_secs(7 * 86400), now + Duration::from_secs(8 * 86400)).unwrap();
        assert_eq!(names(&later.expired), ["abuse-report-2026-10-12.txt", "abuse-report-2026-10-19.txt"]);
        assert!(later.ready.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn alert_messages() {
        // what vpsfort's botbox::render writes
        let text = "To: Admin@Example.org\nSubject: [xmpp] vpsfort: system\n\n[xmpp] vpsfort: system\n\n[High] line\n\nlast";
        assert_eq!(parse_message(text).as_deref(), Some("[xmpp] vpsfort: system\n\n[High] line\n\nlast"));
        assert_eq!(parse_message("To: a@b\nFrom: x\n\nbody"), None);
        assert_eq!(parse_message("Subject: s\n\nbody"), None);
        assert_eq!(parse_message("To: \nSubject: s\n\nbody"), None);
        assert_eq!(parse_message("no header"), None);

        let dir = tmp("messages");
        std::fs::write(dir.join("alert-2.msg"), text).unwrap();
        std::fs::write(dir.join("alert-1.msg"), text).unwrap();
        std::fs::write(dir.join(".alert-0.msg.sending"), text).unwrap();
        std::fs::write(dir.join(".alert-3.msg.tmp"), text).unwrap();
        std::fs::write(dir.join("abuse-report-2026-10-19.txt"), "r").unwrap();
        let now = SystemTime::now();
        let waiting = |d: &Path| scan_messages(d, now).unwrap().into_iter().map(|(p, _)| p).collect::<Vec<_>>();
        assert_eq!(names(&waiting(&dir)), ["alert-1.msg", "alert-2.msg"]);
        assert_eq!(
            names(&scan(&dir, Duration::from_secs(60), now).unwrap().ready),
            ["abuse-report-2026-10-19.txt"],
            "messages aren't files"
        );
        assert_eq!(recover(&dir), 1);
        assert_eq!(names(&waiting(&dir)), ["alert-0.msg", "alert-1.msg", "alert-2.msg"]);
        assert!(dir.join(".alert-3.msg.tmp").exists(), "vpsfort's file being written stays vpsfort's");
        assert_eq!(claimed(&dir.join("alert-1.msg"), "sending"), dir.join(".alert-1.msg.sending"));
        let ages = scan_messages(&dir, now + Duration::from_secs(3600)).unwrap();
        assert!(ages.iter().all(|(_, age)| *age >= Duration::from_secs(3599)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
