//! Admin messages handed to the XMPP admin bot (vpsfort-xmpp-bot), which sends them OMEMO-encrypted,
//! with ejabberd's plain `send_message` as the fallback.
//!
//! The bot's outbox is a directory both sides share (root:ejabberd 1770, sticky). One file
//! per message, `alert-<time>-<n>-<signature>.msg`: `To:` and `Subject:` lines, a blank line,
//! the body; the signature is the keyed hash of name and text under root's key ([`Key`]).
//! It is written under a dot name, given to the bot's user and renamed into place. Then:
//!
//! - the bot claims it by renaming it to `.<name>.sending`, sends it and deletes it; if
//!   sending fails it renames it back. A message for anyone but its admin it renames to
//!   `.<name>.rejected`.
//! - vpsfort looks every few seconds ([`BotBox::sweep`]). A message the bot hasn't taken
//!   within `grace`, one it rejected, and one stuck in `.sending` (the bot died while sending)
//!   is claimed back by a rename to `.<name>.fallback` and sent the old way, with a line
//!   saying why it isn't encrypted. Renames are atomic, so only one side sends a message
//!   (unless the bot hangs mid-send for over ten minutes and then finishes). Only a file whose
//!   name carries its text's signature: the bot's user writes in the directory too, and a file
//!   of its own under one of these names is deleted and reported instead.
//!
//! The same sweep notices the bot's other files (the weekly abuse report) waiting longer than
//! `stuck_after`, and says so once per file.
//!
//! The Telegram bot (vpsfort-tg-bot) reads the same format from its own outbox ([`BotBox::without_fallback`]):
//! there vpsfort takes nothing back, as each message there is a copy of one that goes the
//! XMPP way too. A message vpsfort-tg-bot hasn't sent within `stuck_after` is named like a file.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{KeyInit, OsRng};
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};

use crate::notify::Notice;

/// How long a `.sending` message may sit beyond `grace` before vpsfort takes it back: the
/// bot's sends (OMEMO key fetches, a reconnect) finish well within this.
const STALLED: Duration = Duration::from_secs(10 * 60);
/// A message whose plain fallback keeps failing is dropped after this long.
const GIVE_UP: Duration = Duration::from_secs(24 * 3600);
/// A dot file still being written after this long is a leftover of a crash.
const TMP_LEFTOVER: Duration = Duration::from_secs(60);
/// Largest message read back from the outbox: alerts and the digest are a few KB.
const MAX_MESSAGE: u64 = 1 << 20;

pub const PREFIX: &str = "alert-";
pub const SUFFIX: &str = ".msg";

/// Length of the signature in a message's name: hex digits of the keyed hash (64 bits).
const SIG_LEN: usize = 16;

/// Signs the messages vpsfort writes, in their names. The bot's user writes in the outbox too,
/// and could put a file of its own under one of vpsfort's names: the fallback would send it to
/// the admins as vpsfort's word (an unencrypted alert through ejabberd's API looks like any
/// other). So a name ends in the keyed hash (HMAC-SHA256) of the name's head and the file's
/// text, with a key only root has (`botbox.key` next to the state file, see [`key_path`]), and
/// the sweep checks it before any fallback: what doesn't match is deleted and reported. The
/// bot itself checks nothing; it sends what it finds under `alert-*.msg` to its admin, as before.
#[derive(Clone)]
pub struct Key([u8; 32]);

/// The message key's file: root's, next to the state file.
pub fn key_path(state_file: &Path) -> PathBuf {
    state_file.with_file_name("botbox.key")
}

impl Key {
    /// The key in `path` (0600), made there when missing. When it can neither be read nor
    /// written, a key for this run (said on stderr): messages from before a restart then
    /// fail the check and are dropped, never sent plain.
    pub fn load_or_make(path: &Path) -> Key {
        match fs::read(path) {
            Ok(bytes) if bytes.len() == 32 => return Key(bytes.try_into().expect("32 bytes")),
            Ok(_) => eprintln!("vpsfort: {} is not a 32-byte key: replaced", path.display()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => eprintln!("vpsfort: cannot read {}: {e}", path.display()),
        }
        let key = Key::random();
        let write = || -> io::Result<()> {
            let _ = fs::remove_file(path);
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
            f.write_all(&key.0)?;
            f.sync_all()
        };
        if let Err(e) = write() {
            eprintln!("vpsfort: cannot write {}: {e}; the message key is this run's only", path.display());
        }
        key
    }

    pub fn random() -> Key {
        let mut k = [0u8; 32];
        k.copy_from_slice(&XChaCha20Poly1305::generate_key(&mut OsRng));
        Key(k)
    }

    /// HMAC-SHA256 of `head` and `text`, cut to `SIG_LEN` hex digits.
    fn sign(&self, head: &str, text: &str) -> String {
        let (mut ipad, mut opad) = ([0x36u8; 64], [0x5cu8; 64]);
        for (i, b) in self.0.iter().enumerate() {
            ipad[i] ^= b;
            opad[i] ^= b;
        }
        let inner = Sha256::new().chain_update(ipad).chain_update(head).chain_update([0u8]).chain_update(text).finalize();
        let mac = Sha256::new().chain_update(opad).chain_update(inner).finalize();
        mac.iter().take(SIG_LEN / 2).map(|b| format!("{b:02x}")).collect()
    }
}

/// The messages among `names` without a signature (written by a version before 2026-11-07):
/// those there when vpsfort starts may still go out plain; any that turn up later aren't
/// vpsfort's.
fn unsigned(names: impl Iterator<Item = String>) -> HashSet<String> {
    names.filter_map(|n| split_state(&n).map(|(b, _)| b.to_string())).filter(|b| signature(b).is_none()).collect()
}

/// [`unsigned`] for the files of `dir`, if it can be read.
fn unsigned_in(dir: &Path) -> Option<HashSet<String>> {
    let entries = fs::read_dir(dir).ok()?;
    Some(unsigned(entries.filter_map(|e| e.ok()?.file_name().into_string().ok())))
}

/// The head and the signature of a message name (`alert-<time>-<n>-<signature>.msg`), if it
/// has one.
fn signature(base: &str) -> Option<(&str, &str)> {
    let (head, sig) = base.strip_suffix(SUFFIX)?.rsplit_once('-')?;
    (sig.len() == SIG_LEN && sig.bytes().all(|b| b.is_ascii_hexdigit())).then_some((head, sig))
}

/// Why a message went out unencrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// Not taken within `grace` (the bot is down, offline or behind).
    NotTaken(Duration),
    /// The bot refused it (a recipient other than its admin).
    Refused,
    /// The bot started sending it and never finished.
    Stalled,
    /// An earlier fallback attempt failed or was interrupted; trying again.
    Retry,
}

impl Why {
    pub fn note(self) -> String {
        match self {
            Why::NotTaken(g) => format!("(Sent unencrypted: the admin bot didn't pick this up within {} min.)", g.as_secs().div_ceil(60)),
            Why::Refused => "(Sent unencrypted: the admin bot only writes to its own admin.)".into(),
            Why::Stalled => "(Sent unencrypted: the admin bot started sending this and didn't finish.)".into(),
            Why::Retry => "(Sent unencrypted: the admin bot didn't send this.)".into(),
        }
    }
}

/// A message vpsfort took back, to send the old way.
#[derive(Debug, PartialEq)]
pub struct Fallback {
    /// The claimed file (`.<name>.fallback`); delete it once sent.
    pub path: PathBuf,
    pub notice: Notice,
    pub why: Why,
}

/// Entries of an outbox one sweep looks at.
const MAX_SWEPT: usize = 10_000;
/// Stuck files are reported this often at most.
const STUCK_EVERY: Duration = Duration::from_secs(3600);

/// What a sweep found.
#[derive(Debug, Default, PartialEq)]
pub struct Sweep {
    pub fallback: Vec<Fallback>,
    /// The bot's other files waiting longer than `stuck_after` (name, age), each named once.
    pub stuck: Vec<(String, Duration)>,
    /// Files under vpsfort's names that vpsfort didn't write, or that were changed since:
    /// deleted, to be reported.
    pub forged: Vec<String>,
}

/// The file's text. Header values are kept on one line.
pub fn render(n: &Notice) -> String {
    let one_line = |s: &str| s.replace(['\r', '\n'], " ");
    format!("To: {}\nSubject: {}\n\n{}", one_line(&n.to), one_line(&n.subject), n.body)
}

/// The message in a file's text, if it is one.
pub fn parse(text: &str) -> Option<Notice> {
    let (head, body) = text.split_once("\n\n")?;
    let (mut to, mut subject) = (None, None);
    for line in head.lines() {
        match line.split_once(": ") {
            Some(("To", v)) => to = Some(v.trim().to_string()),
            Some(("Subject", v)) => subject = Some(v.to_string()),
            _ => return None,
        }
    }
    Some(Notice {
        to: to.filter(|t| !t.is_empty())?,
        subject: subject.unwrap_or_default(),
        body: body.to_string(),
        channel: Default::default(),
    })
}

/// A message file's text, as vpsfort (root) reads one back. The bot's user writes in the
/// outbox too: so only a regular file, never through a symlink (swapped in after the
/// check), and at most `MAX_MESSAGE` (a huge one would exhaust the daemon's memory).
fn read_message(path: &Path) -> Option<String> {
    use std::io::Read;
    // Linux numbers the flag per architecture: arm, aarch64 and powerpc have 0o100000 where
    // x86, riscv, s390x and loongarch have 0o400000 (CI's arm64 runner caught the difference).
    const O_NOFOLLOW: i32 = if !cfg!(target_os = "linux") {
        0x0100
    } else if cfg!(any(target_arch = "arm", target_arch = "aarch64", target_arch = "powerpc", target_arch = "powerpc64")) {
        0o100000
    } else {
        0o400000
    };
    const O_NONBLOCK: i32 = if cfg!(target_os = "linux") { 0o4000 } else { 0x0004 };
    const O_NOCTTY: i32 = if cfg!(target_os = "linux") { 0o400 } else { 0x20000 };
    let f = fs::OpenOptions::new().read(true).custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY).open(path).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    f.take(MAX_MESSAGE + 1).read_to_string(&mut text).ok()?;
    (text.len() as u64 <= MAX_MESSAGE).then_some(text)
}

/// The message name inside one of the dot names (`.alert-x.msg.sending` → `alert-x.msg`) and
/// the state suffix, or the name itself with an empty state.
fn split_state(name: &str) -> Option<(&str, &str)> {
    if let Some(rest) = name.strip_prefix('.') {
        let (base, state) = rest.rsplit_once('.')?;
        return (base.starts_with(PREFIX) && base.ends_with(SUFFIX)).then_some((base, state));
    }
    (name.starts_with(PREFIX) && name.ends_with(SUFFIX)).then_some((name, ""))
}

/// The uid and gid of a user, from /etc/passwd (`name:x:uid:gid:...`).
pub fn user_ids(passwd: &str, user: &str) -> Option<(u32, u32)> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 4 && f[0] == user).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?))).flatten()
    })
}

/// The name of the user with id `uid`, from /etc/passwd.
pub fn user_name(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 3 && f[2].parse() == Ok(uid)).then(|| crate::event::clean(f[0], 32))
    })
}

pub struct BotBox {
    pub dir: PathBuf,
    /// Who the files are given to (the bot's user), if they are given away at all.
    owner: Option<(u32, u32)>,
    grace: Duration,
    stuck_after: Duration,
    /// Messages not taken in time are taken back and sent the usual way (vpsfort-xmpp-bot), or only
    /// named as stuck (vpsfort-tg-bot).
    fallback: bool,
    seq: u64,
    /// Stuck files already reported, and fallbacks whose failure was already logged.
    reported: HashSet<String>,
    /// When stuck files were last reported.
    stuck_told: Option<SystemTime>,
    pub failing: HashSet<PathBuf>,
    /// Signs the names of the messages written, and checks them before a fallback.
    key: Key,
    /// Messages without a signature (an older version's) in the outbox when this was made
    /// (or at the first sweep, if it wasn't there yet): the only unsigned ones a fallback may send.
    legacy: Option<HashSet<String>>,
}

impl BotBox {
    pub fn new(dir: PathBuf, owner: Option<(u32, u32)>, grace: Duration, stuck_after: Duration) -> Self {
        BotBox {
            owner,
            grace,
            stuck_after,
            fallback: true,
            seq: 0,
            reported: HashSet::new(),
            stuck_told: None,
            failing: HashSet::new(),
            key: Key::random(),
            legacy: unsigned_in(&dir),
            dir,
        }
    }

    /// With root's persistent message key (the daemon's and `notify-test`'s) instead of one for
    /// this run: the sweep then still knows the messages written before a restart.
    pub fn with_key(self, key: Key) -> Self {
        BotBox { key, ..self }
    }

    /// Whether `base` carries the signature of `text` under this key, i.e. vpsfort wrote it
    /// and nobody changed it. A name without one (written by a version before 2026-11-07)
    /// passes only if it was there at the first sweep.
    fn genuine(&self, base: &str, text: &str) -> bool {
        match signature(base) {
            Some((head, sig)) => {
                let want = self.key.sign(head, text);
                want.len() == sig.len() && want.bytes().zip(sig.bytes()).fold(0, |d, (a, b)| d | (a ^ b)) == 0
            }
            None => self.legacy.as_ref().is_some_and(|l| l.contains(base)),
        }
    }

    /// An outbox without a fallback (vpsfort-tg-bot's): messages wait there until the bot sends them,
    /// and sweeps only name those waiting longer than `stuck_after`.
    pub fn without_fallback(dir: PathBuf, owner: Option<(u32, u32)>, stuck_after: Duration) -> Self {
        BotBox { fallback: false, ..Self::new(dir, owner, stuck_after, stuck_after) }
    }

    /// Whether the bot's outbox is there (the bot is installed on this server).
    pub fn ready(&self) -> bool {
        self.dir.is_dir()
    }

    /// Puts a message in the outbox for the bot. Returns the file it went to.
    pub fn put(&mut self, n: &Notice, now: SystemTime) -> io::Result<PathBuf> {
        self.seq += 1;
        let t = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        // sorts in sending order: time, then the counter for messages in the same instant;
        // then the text's signature, checked before any fallback
        let text = render(n);
        let head = format!("{PREFIX}{:012}{:09}-{:06}", t.as_secs(), t.subsec_nanos(), self.seq % 1_000_000);
        let name = format!("{head}-{}{SUFFIX}", self.key.sign(&head, &text));
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let dest = self.dir.join(&name);
        let write = || -> io::Result<()> {
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            if let Some((uid, gid)) = self.owner {
                std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
            }
            fs::rename(&tmp, &dest)
        };
        write().inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
        Ok(dest)
    }

    /// Takes back what the bot hasn't sent in time (see the module comment), and finds its
    /// other files waiting too long.
    pub fn sweep(&mut self, now: SystemTime) -> io::Result<Sweep> {
        let mut out = Sweep::default();
        let mut present = HashSet::new();
        // The bot's user can write here: a sweep takes the first `MAX_SWEPT` entries, not
        // millions of names into the daemon's memory (the rest wait for the next sweeps,
        // once these are sent or deleted).
        let mut entries: Vec<_> = fs::read_dir(&self.dir)?.filter_map(|e| e.ok()).take(MAX_SWEPT).collect();
        entries.sort_by_key(|e| e.file_name());
        if self.legacy.is_none() {
            // the outbox wasn't there when this BotBox was made
            self.legacy = Some(unsigned(entries.iter().filter_map(|e| e.file_name().into_string().ok())));
        }
        for entry in entries {
            let Ok(name) = entry.file_name().into_string() else { continue };
            let Ok(meta) = fs::symlink_metadata(entry.path()) else { continue };
            if !meta.file_type().is_file() {
                continue;
            }
            let age = meta.modified().ok().and_then(|m| now.duration_since(m).ok()).unwrap_or_default();
            let Some((base, state)) = split_state(&name) else {
                // the bot's other files: the weekly report
                if !name.starts_with('.') {
                    present.insert(name.clone());
                    if age > self.stuck_after && self.reported.insert(name.clone()) {
                        out.stuck.push((name, age));
                    }
                }
                continue;
            };
            if !self.fallback {
                match state {
                    // waiting, or left half-sent by a bot that stopped (it puts those back
                    // when it starts again)
                    "" | "sending" => {
                        present.insert(name.clone());
                        if age > self.stuck_after && self.reported.insert(name.clone()) {
                            out.stuck.push((name, age));
                        }
                    }
                    "tmp" if age > TMP_LEFTOVER => {
                        let _ = fs::remove_file(entry.path());
                    }
                    _ => {}
                }
                continue;
            }
            let why = match state {
                "" if age > self.grace => Why::NotTaken(self.grace),
                "rejected" => Why::Refused,
                "sending" if age > self.grace + STALLED => Why::Stalled,
                "fallback" if age > GIVE_UP => {
                    eprintln!("vpsfort: admin message {base} could not be sent for a day, dropped");
                    let _ = fs::remove_file(entry.path());
                    self.failing.remove(&entry.path());
                    continue;
                }
                "fallback" => Why::Retry,
                "tmp" if age > TMP_LEFTOVER => {
                    let _ = fs::remove_file(entry.path());
                    continue;
                }
                _ => continue,
            };
            let claimed = self.dir.join(format!(".{base}.fallback"));
            if state != "fallback" {
                match fs::rename(entry.path(), &claimed) {
                    Ok(()) => {}
                    // the bot took it in the meantime
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                }
            }
            let text = read_message(&claimed);
            if text.as_deref().is_some_and(|t| !self.genuine(base, t)) {
                eprintln!(
                    "vpsfort: {} was not written by vpsfort (its name carries no valid signature of its text): deleted, not sent",
                    claimed.display()
                );
                let _ = fs::remove_file(&claimed);
                self.failing.remove(&claimed);
                out.forged.push(base.to_string());
                continue;
            }
            match text.as_deref().and_then(parse) {
                Some(notice) => out.fallback.push(Fallback { path: claimed, notice, why }),
                None => {
                    eprintln!("vpsfort: {} is not an admin message, deleted", claimed.display());
                    let _ = fs::remove_file(&claimed);
                }
            }
        }
        // a file sent (or deleted) and later one of the same name is new again
        self.reported.retain(|n| present.contains(n));
        // Stuck files are told of once an hour at most (all of them in one message): the
        // bot's user can make any number of them, each a High message to every admin.
        if !out.stuck.is_empty() {
            if self.stuck_told.is_some_and(|t| now.duration_since(t).is_ok_and(|d| d < STUCK_EVERY)) {
                for (name, _) in out.stuck.drain(..) {
                    self.reported.remove(&name);
                }
            } else {
                self.stuck_told = Some(now);
            }
        }
        Ok(out)
    }

    /// The text to send in place of the bot: the message and why it isn't encrypted.
    pub fn plain(f: &Fallback) -> Notice {
        Notice { body: format!("{}\n\n{}", f.notice.body, f.why.note()), ..f.notice.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    fn notice() -> Notice {
        Notice {
            channel: Default::default(),
            to: "admin@example.org".into(),
            subject: "[xmpp] vpsfort: system\nx".into(),
            body: "[xmpp] vpsfort: system\n\nline 1\n\nline 3 → ✓".into(),
        }
    }

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vpsfort-botbox-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn names(d: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        v.sort();
        v
    }

    #[test]
    fn file_format_round_trip() {
        let n = notice();
        let text = render(&n);
        assert!(text.starts_with("To: admin@example.org\nSubject: [xmpp] vpsfort: system x\n\n"), "{text}");
        let back = parse(&text).unwrap();
        assert_eq!(back.to, n.to);
        assert_eq!(back.subject, "[xmpp] vpsfort: system x", "the subject stays on its line");
        assert_eq!(back.body, n.body, "blank lines in the body survive");
        assert_eq!(parse("no header"), None);
        assert_eq!(parse("From: x\n\nbody"), None);
        assert_eq!(parse("Subject: s\n\nbody"), None, "a recipient is required");
    }

    /// What the bot's user writes under vpsfort's names isn't vpsfort's word: the fallback
    /// sends only a file whose name carries the signature of its text under root's key.
    #[test]
    fn forged_messages_never_go_out_plain() {
        let d = dir("forged");
        let grace = Duration::from_secs(120);
        let key = Key::load_or_make(&d.join("botbox.key"));
        assert_eq!(fs::metadata(d.join("botbox.key")).unwrap().mode() & 0o777, 0o600);
        let now = SystemTime::now();
        // a message an older version wrote (no signature), there when this one starts
        let old = "alert-000000000001000000000-000001.msg";
        fs::write(d.join(old), render(&notice())).unwrap();
        let mut b = BotBox::new(d.clone(), None, grace, Duration::from_secs(3600)).with_key(key.clone());
        assert_eq!(b.sweep(now).unwrap(), Sweep::default(), "within the grace time");
        let real = b.put(&notice(), now).unwrap();
        let name = real.file_name().unwrap().to_str().unwrap().to_string();
        assert_eq!(name.len(), PREFIX.len() + 21 + 1 + 6 + 1 + SIG_LEN + SUFFIX.len(), "{name}");
        // the bot's user: a file under a made-up signature, one under an old-style name that
        // wasn't there before, and a real message's signature over a changed text
        fs::write(d.join("alert-000000000002000000000-000002-0123456789abcdef.msg"), render(&notice())).unwrap();
        fs::write(d.join("alert-000000000003000000000-000003.msg"), render(&notice())).unwrap();
        let head = "alert-000000000004000000000-000004";
        let forged = format!("{head}-{}{SUFFIX}", key.sign(head, &render(&notice())));
        fs::write(d.join(&forged), "To: admin@example.org\nSubject: all clear\n\nnothing to see").unwrap();
        let s = b.sweep(now + Duration::from_secs(180)).unwrap();
        let sent: Vec<String> = s.fallback.iter().map(|f| f.path.file_name().unwrap().to_str().unwrap().to_string()).collect();
        assert_eq!(sent, [format!(".{old}.fallback"), format!(".{name}.fallback")], "the real one and the old one");
        let mut forged_names = s.forged.clone();
        forged_names.sort();
        assert_eq!(
            forged_names,
            ["alert-000000000002000000000-000002-0123456789abcdef.msg", "alert-000000000003000000000-000003.msg", forged.as_str()]
        );
        for f in &s.fallback {
            fs::remove_file(&f.path).unwrap();
        }
        assert_eq!(names(&d), ["botbox.key"], "the forged ones are deleted");
        // the key is read back, so messages written before a restart still pass
        assert_eq!(Key::load_or_make(&d.join("botbox.key")).sign("a", "b"), key.sign("a", "b"));
        assert_ne!(Key::random().sign("a", "b"), key.sign("a", "b"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn passwd_lookup() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nejabberd:x:998:997::/opt/ejabberd:/bin/sh\nbroken:x:abc:1::/:/bin/false\n";
        assert_eq!(user_ids(passwd, "ejabberd"), Some((998, 997)));
        assert_eq!(user_ids(passwd, "ejabber"), None);
        assert_eq!(user_ids(passwd, "broken"), None);
        assert_eq!((user_name(passwd, 998).as_deref(), user_name(passwd, 5)), (Some("ejabberd"), None));
    }

    #[test]
    fn the_bot_takes_it_or_vpsfort_takes_it_back() {
        let d = dir("flow");
        let grace = Duration::from_secs(120);
        let mut b = BotBox::new(d.clone(), None, grace, Duration::from_secs(3600));
        let now = SystemTime::now();
        let p1 = b.put(&notice(), now).unwrap();
        let p2 = b.put(&notice(), now).unwrap();
        assert!(p1 < p2, "names sort in sending order");
        assert_eq!(names(&d).len(), 2, "no temporary file left: {:?}", names(&d));
        let mode = fs::metadata(&p1).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // within the grace time nothing happens
        assert_eq!(b.sweep(now + Duration::from_secs(60)).unwrap(), Sweep::default());

        // the bot claims the first, and is still sending it when the grace time is up
        let base1 = p1.file_name().unwrap().to_str().unwrap().to_string();
        fs::rename(&p1, d.join(format!(".{base1}.sending"))).unwrap();
        let s = b.sweep(now + Duration::from_secs(180)).unwrap();
        assert_eq!(s.fallback.len(), 1, "only the untaken one");
        assert_eq!(s.fallback[0].why, Why::NotTaken(grace));
        assert_eq!(s.fallback[0].notice.body, notice().body);
        let plain = BotBox::plain(&s.fallback[0]);
        assert!(plain.body.ends_with("(Sent unencrypted: the admin bot didn't pick this up within 2 min.)"), "{}", plain.body);
        assert!(s.fallback[0].path.file_name().unwrap().to_str().unwrap().ends_with(".msg.fallback"));
        assert!(!p2.exists(), "claimed by rename");

        // a fallback not deleted (sending failed) is tried again
        let s = b.sweep(now + Duration::from_secs(200)).unwrap();
        assert_eq!(s.fallback.iter().map(|f| f.why).collect::<Vec<_>>(), [Why::Retry]);
        fs::remove_file(&s.fallback[0].path).unwrap();

        // a bot that died while sending: taken back 10 minutes after the grace time
        assert!(b.sweep(now + Duration::from_secs(600)).unwrap().fallback.is_empty());
        let s = b.sweep(now + Duration::from_secs(780)).unwrap();
        assert_eq!(s.fallback.iter().map(|f| f.why).collect::<Vec<_>>(), [Why::Stalled]);
        fs::remove_file(&s.fallback[0].path).unwrap();
        assert!(names(&d).is_empty(), "{:?}", names(&d));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn refused_messages_go_out_at_once_and_junk_is_cleared() {
        let d = dir("refused");
        let mut b = BotBox::new(d.clone(), None, Duration::from_secs(120), Duration::from_secs(3600));
        let now = SystemTime::now();
        let p = b.put(&notice(), now).unwrap();
        let base = p.file_name().unwrap().to_str().unwrap().to_string();
        fs::rename(&p, d.join(format!(".{base}.rejected"))).unwrap();
        let s = b.sweep(now).unwrap();
        assert_eq!(s.fallback.iter().map(|f| f.why).collect::<Vec<_>>(), [Why::Refused]);
        fs::remove_file(&s.fallback[0].path).unwrap();

        // a crash leftover, a message without a header, the bot's own dot files
        fs::write(d.join(".alert-1.msg.tmp"), "half").unwrap();
        fs::write(d.join("alert-2.msg"), "garbage").unwrap();
        fs::write(d.join(".abuse-report-2026-10-19.txt.tmp"), "being written").unwrap();
        // a message too big to be one isn't read into memory: deleted
        let big = format!("To: admin@example.org\nSubject: s\n\n{}", "x".repeat(MAX_MESSAGE as usize));
        fs::write(d.join(".alert-3.msg.rejected"), big).unwrap();
        let s = b.sweep(now + Duration::from_secs(3 * 60)).unwrap();
        assert!(s.fallback.is_empty());
        assert_eq!(names(&d), [".abuse-report-2026-10-19.txt.tmp"], "only what isn't vpsfort's is left");
        // nor is anything read through a symlink
        std::os::unix::fs::symlink("/etc/hosts", d.join("link")).unwrap();
        assert_eq!(read_message(&d.join("link")), None);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn without_fallback_messages_wait_for_the_bot() {
        let d = dir("nofallback");
        let mut b = BotBox::without_fallback(d.clone(), None, Duration::from_secs(3600));
        let now = SystemTime::now();
        let p = b.put(&notice(), now).unwrap();
        let p2 = b.put(&notice(), now).unwrap();
        let base2 = p2.file_name().unwrap().to_str().unwrap().to_string();
        fs::rename(&p2, d.join(format!(".{base2}.sending"))).unwrap();
        fs::write(d.join(".alert-9.msg.tmp"), "half").unwrap();
        assert_eq!(b.sweep(now + Duration::from_secs(600)).unwrap(), Sweep::default(), "nothing taken back after a grace time");
        let s = b.sweep(now + Duration::from_secs(4000)).unwrap();
        assert!(s.fallback.is_empty());
        let sending = format!(".{base2}.sending");
        assert_eq!(
            s.stuck.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            [sending.as_str(), p.file_name().unwrap().to_str().unwrap()],
            "waiting, and left half-sent by a bot that died: each named once"
        );
        assert!(b.sweep(now + Duration::from_secs(5000)).unwrap().stuck.is_empty());
        assert!(p.exists() && d.join(format!(".{base2}.sending")).exists(), "the bot's to send");
        assert!(!d.join(".alert-9.msg.tmp").exists(), "crash leftovers are cleared");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_waiting_report_is_named_once() {
        let d = dir("stuck");
        let mut b = BotBox::new(d.clone(), None, Duration::from_secs(120), Duration::from_secs(3600));
        fs::write(d.join("abuse-report-2026-10-19.txt"), "report").unwrap();
        let now = SystemTime::now();
        assert!(b.sweep(now + Duration::from_secs(1800)).unwrap().stuck.is_empty());
        let s = b.sweep(now + Duration::from_secs(4000)).unwrap();
        assert_eq!(s.stuck.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["abuse-report-2026-10-19.txt"]);
        assert!(s.fallback.is_empty(), "the report itself is the bot's to send");
        assert!(b.sweep(now + Duration::from_secs(5000)).unwrap().stuck.is_empty(), "named once");
        // sent, and next week's waits too long again: named again
        fs::remove_file(d.join("abuse-report-2026-10-19.txt")).unwrap();
        b.sweep(now + Duration::from_secs(5000)).unwrap();
        fs::write(d.join("abuse-report-2026-10-19.txt"), "report").unwrap();
        assert_eq!(b.sweep(now + Duration::from_secs(9000)).unwrap().stuck.len(), 1);
        assert!(d.join("abuse-report-2026-10-19.txt").exists(), "vpsfort never touches the report");
        let _ = fs::remove_dir_all(&d);
    }
}
