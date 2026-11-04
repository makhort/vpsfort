//! The bot: vpsfort's outbox to a push service (ntfy, Gotify) or a webhook. Send only: it
//! reads nothing back and takes no orders for the servers (that stays on SSH). Nothing it
//! sends is encrypted end to end, so alerts go with account names and the servers' own
//! addresses replaced (as on Telegram), and files only encrypted to the admin's OpenPGP key.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use tokio::signal::unix::{signal, SignalKind};

use crate::outbox;
use crate::push::{Priority, Push, PushError, Sent, MESSAGE_LIMIT};
use crate::redact::Pseudonyms;
use crate::seal::Recipient;
use crate::servers::ServerNames;

/// A setting or a token that restarting will not fix; the process exits with 78, which
/// the unit does not restart.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

impl Refused {
    pub const EXIT_CODE: u8 = 78;
}

pub struct Config {
    pub outbox: PathBuf,
    /// Files waiting longer are deleted unsent.
    pub outbox_max_age: Duration,
    /// Alerts waiting longer are dropped unsent (counted in one message instead).
    pub alert_max_age: Duration,
    /// The servers' own addresses and names, replaced by their node ids in alerts.
    pub servers: ServerNames,
    /// The admin's OpenPGP key: files go out encrypted to it, as a whole, or not at all.
    pub recipient: Option<Recipient>,
}

/// The caption of an encrypted file: nothing about what is in it.
pub const FILE_CAPTION: &str = "Encrypted (OpenPGP). Open it with OpenKeychain (Android) or iPGMail (iPhone).";

/// The name a file goes out under: neutral, with the original's extension (the apps name
/// the decrypted file after it, without `.pgp`).
pub fn sealed_name(original: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    let ext = std::path::Path::new(original)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty() && e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("bin");
    format!("report-{}.{ext}.pgp", now.format("%Y-%m-%d"))
}

/// Text as a message: no control characters except line breaks and tabs, `\r\n` as `\n`.
pub fn clean(text: &str) -> String {
    text.replace("\r\n", "\n").chars().filter(|&c| c == '\n' || c == '\t' || !c.is_control()).collect()
}

/// Pieces of at most `limit` characters, cut after a line where possible, without blanks at
/// their ends; an empty text gives no piece.
pub fn split(text: &str, limit: usize) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut len = 0;
    let mut flush = |cur: &mut String, len: &mut usize| {
        // whole lines, indentation kept (the digest's columns), no blank lines at the ends
        let piece = cur.trim_end().trim_start_matches('\n');
        if !piece.trim().is_empty() {
            parts.push(piece.to_string());
        }
        cur.clear();
        *len = 0;
    };
    for line in text.split_inclusive('\n') {
        let n = line.chars().count();
        if len + n > limit {
            flush(&mut cur, &mut len);
        }
        if n <= limit {
            cur.push_str(line);
            len += n;
            continue;
        }
        for c in line.chars() {
            if len + 1 > limit {
                flush(&mut cur, &mut len);
            }
            cur.push(c);
            len += 1;
        }
    }
    flush(&mut cur, &mut len);
    parts
}

/// A vpsfort admin message as (title, bodies): its first line is the subject, the rest the
/// body, in pieces of at most [`MESSAGE_LIMIT`] characters (later ones marked as continued).
pub fn pieces(text: &str) -> (String, Vec<String>) {
    let text = clean(text);
    let text = text.trim();
    let (subject, body) = match text.split_once('\n') {
        Some((s, b)) => (s.trim(), b.trim_start_matches(['\n', '\r']).trim_end()),
        None => (text, ""),
    };
    let subject: String = subject.chars().take(250).collect();
    let subject = if subject.is_empty() { "vpsfort".to_string() } else { subject };
    let bodies = split(body, MESSAGE_LIMIT - 20);
    let bodies = if bodies.is_empty() {
        vec![String::new()]
    } else {
        bodies.into_iter().enumerate().map(|(i, p)| if i == 0 { p } else { format!("(continued)\n{p}") }).collect()
    };
    (subject, bodies)
}

#[derive(Default)]
pub struct Stats {
    pub alerts: u64,
    pub files: u64,
    pub last_sent: Option<i64>,
    pub last_error: Option<(i64, String)>,
}

pub struct Bot {
    pub push: Push,
    pub cfg: Config,
    pub names: Pseudonyms,
    pub stats: Stats,
    /// Nothing is sent before this (the service's rate limit, or after a failure).
    not_before: Option<Instant>,
    /// The last warning logged and when: repeated failures are logged every 10 minutes.
    last_warning: Option<(String, Instant)>,
    /// When the admin was last told that files can't go out (at most daily).
    file_notice: Option<Instant>,
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl Bot {
    pub fn new(push: Push, cfg: Config, names: Pseudonyms) -> Bot {
        Bot { push, cfg, names, stats: Stats::default(), not_before: None, last_warning: None, file_notice: None }
    }

    fn warn_repeated(&mut self, msg: String) {
        let again = self.last_warning.as_ref().is_none_or(|(m, t)| *m != msg || t.elapsed() >= Duration::from_secs(600));
        if again {
            log::warn!("{msg}");
            self.last_warning = Some((msg, Instant::now()));
        }
    }

    fn throttled(&self) -> bool {
        self.not_before.is_some_and(|t| Instant::now() < t)
    }

    /// Remembers a failed call: what to show, and how long to hold off.
    fn failed(&mut self, e: &PushError) {
        self.stats.last_error = Some((unix_now(), e.to_string()));
        let pause = match e {
            _ if e.retry_after().is_some() => e.retry_after().unwrap_or_default(),
            // this request will never go through, but the next one may: no pause; a refused
            // token stops the bot anyway
            _ if e.permanent() || e.token_refused() => return,
            PushError::Transport(_) => Duration::from_secs(30),
            PushError::Refused { .. } => Duration::from_secs(60),
        };
        self.not_before = Some(Instant::now() + pause);
    }

    /// Sends a message in its pieces, in order; stops at the first failure. A refused token
    /// is final (exit 78).
    async fn send(&mut self, text: &str) -> Result<(), PushError> {
        let (subject, bodies) = pieces(text);
        let priority = Priority::of(text);
        for body in &bodies {
            if let Err(e) = self.push.send_message(&subject, body, priority).await {
                self.failed(&e);
                return Err(e);
            }
        }
        Ok(())
    }

    /// vpsfort's alerts in the outbox, with account names and the servers' addresses and
    /// names replaced. `Err` only for a refused token, which stops the bot.
    pub async fn deliver_alerts(&mut self) -> Result<(), Refused> {
        if self.throttled() {
            return Ok(());
        }
        let dir = self.cfg.outbox.clone();
        let waiting = match outbox::scan_messages(&dir, SystemTime::now()) {
            Ok(w) => w,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                self.warn_repeated(format!("outbox {}: {e}", dir.display()));
                return Ok(());
            }
        };
        let mut dropped = 0;
        for (path, age) in waiting {
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            if age > self.cfg.alert_max_age {
                if std::fs::remove_file(&path).is_ok() {
                    dropped += 1;
                }
                continue;
            }
            let sending = outbox::claimed(&path, "sending");
            match std::fs::rename(&path, &sending) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    self.warn_repeated(format!("outbox: can't take {name}: {e}"));
                    continue;
                }
            }
            let Some(text) = outbox::read_message(&sending) else {
                log::warn!("outbox: {name} is not an admin message (or larger than 1 MB); deleted");
                let _ = std::fs::remove_file(&sending);
                continue;
            };
            let text = crate::redact::sanitize(&self.names, &self.cfg.servers, &text);
            match self.send(&text).await {
                Ok(()) => {
                    log::info!("outbox: alert {name} sent");
                    if let Err(e) = std::fs::remove_file(&sending) {
                        log::error!("outbox: deleting {} after sending: {e}", sending.display());
                    }
                    self.stats.alerts += 1;
                    self.stats.last_sent = Some(unix_now());
                }
                Err(e) if e.token_refused() => {
                    let _ = std::fs::rename(&sending, &path);
                    return Err(Refused(format!("{} refused the token ({e}): check PUSH_TOKEN", self.push.kind.name())));
                }
                // the same request would be refused forever, and hold up every alert after it
                Err(e) if e.permanent() => {
                    log::error!("outbox: alert {name} dropped: {} refuses it ({e})", self.push.kind.name());
                    let _ = std::fs::remove_file(&sending);
                    let note = format!(
                        "An alert was dropped: {} refused it ({e}). It is in vpsfort's actions log on the server.",
                        self.push.kind.name()
                    );
                    let _ = self.send(&format!("vpsfort-push-bot\n\n{note}")).await;
                }
                Err(e) => {
                    let _ = std::fs::rename(&sending, &path);
                    self.warn_repeated(format!("outbox: alert {name} not sent ({e}); trying again"));
                    break;
                }
            }
        }
        if dropped > 0 {
            let hours = self.cfg.alert_max_age.as_secs() / 3600;
            log::warn!("outbox: {dropped} alert(s) older than {hours} h dropped unsent");
            let note = format!(
                "{dropped} alert(s) waited more than {hours} h and were dropped unsent (the bot was down, or {} out of reach). vpsfort's actions log on the server has them.",
                self.push.kind.name()
            );
            let _ = self.send(&format!("vpsfort-push-bot\n\n{note}")).await;
        }
        Ok(())
    }

    /// Files in the outbox (the weekly abuse report), encrypted to the admin's OpenPGP key;
    /// deletes those that waited too long. Without a key, or to a service without
    /// attachments, nothing is sent and the admin is told once a day.
    pub async fn deliver_files(&mut self) -> Result<(), Refused> {
        let dir = self.cfg.outbox.clone();
        let pending = match outbox::scan(&dir, self.cfg.outbox_max_age, SystemTime::now()) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                self.warn_repeated(format!("outbox {}: {e}", dir.display()));
                return Ok(());
            }
        };
        for path in pending.expired {
            match std::fs::remove_file(&path) {
                Ok(()) => log::warn!(
                    "outbox: {} not sent within {} days (or too large), deleted",
                    path.display(),
                    self.cfg.outbox_max_age.as_secs() / 86400
                ),
                Err(e) => log::error!("outbox: deleting {}: {e}", path.display()),
            }
        }
        if pending.ready.is_empty() {
            return Ok(());
        }
        let n = pending.ready.len();
        let days = self.cfg.outbox_max_age.as_secs() / 86400;
        if !self.push.kind.takes_files() {
            self.warn_repeated(format!("outbox: {n} file(s) wait: {} takes no attachments", self.push.kind.name()));
            let note = format!(
                "{n} file(s) (the weekly abuse report) wait on the server: {} takes no attachments. Read them there (vpsfort's outbox), or use ntfy or a webhook for files; they are deleted after {days} days.",
                self.push.kind.name()
            );
            return self.file_notice(note).await;
        }
        if self.cfg.recipient.is_none() {
            self.warn_repeated(format!("outbox: {n} file(s) wait: files go out encrypted only, and OPENPGP_KEY is not set"));
            return Ok(());
        }
        let now = unix_now() as u32;
        if let Some(Err(e)) = self.cfg.recipient.as_ref().map(|r| r.check(now)) {
            self.warn_repeated(format!("outbox: {n} file(s) wait: OPENPGP_KEY {e}"));
            let note = format!("{n} file(s) can't be sent: your OpenPGP key {e}. Install a valid public key as OPENPGP_KEY on the server and restart the bot; files wait {days} days at most.");
            return self.file_notice(note).await;
        }
        for path in pending.ready {
            if self.throttled() {
                return Ok(());
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    self.warn_repeated(format!("outbox: reading {name}: {e}"));
                    continue;
                }
            };
            let sealed = match self.cfg.recipient.as_ref().map(|r| r.seal(data, now)) {
                Some(Ok(s)) => s,
                Some(Err(e)) => {
                    self.warn_repeated(format!("outbox: {name} not sent: {e}"));
                    continue;
                }
                None => return Ok(()),
            };
            let sent_as = sealed_name(&name, chrono::Utc::now());
            match self.push.send_file(&sent_as, sealed, FILE_CAPTION).await {
                Ok(Sent::Delivered) => {
                    log::info!("outbox: {name} sent encrypted as {sent_as}");
                    if let Err(e) = std::fs::remove_file(&path) {
                        log::error!("outbox: deleting {} after sending: {e}", path.display());
                    }
                    self.stats.files += 1;
                    self.stats.last_sent = Some(unix_now());
                }
                Ok(Sent::Unsupported) => return Ok(()),
                Err(e) if e.token_refused() => {
                    return Err(Refused(format!("{} refused the token ({e}): check PUSH_TOKEN", self.push.kind.name())));
                }
                // too large, or otherwise refused for good: it would hold up every file after it
                Err(e) if e.permanent() => {
                    log::error!("outbox: {name} dropped: {} refuses it ({e})", self.push.kind.name());
                    let _ = std::fs::remove_file(&path);
                    let note = format!("A file was dropped: {} refused it ({e}).", self.push.kind.name());
                    let _ = self.send(&format!("vpsfort-push-bot\n\n{note}")).await;
                }
                Err(e) => {
                    self.failed(&e);
                    self.warn_repeated(format!("outbox: {name} not sent ({e}); trying again later"));
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Tells the admin something about files, at most once a day.
    async fn file_notice(&mut self, note: String) -> Result<(), Refused> {
        if self.file_notice.is_some_and(|t| t.elapsed() < Duration::from_secs(86400)) || self.throttled() {
            return Ok(());
        }
        match self.send(&format!("vpsfort-push-bot\n\n{note}")).await {
            Ok(()) => self.file_notice = Some(Instant::now()),
            Err(e) if e.token_refused() => {
                return Err(Refused(format!("{} refused the token ({e}): check PUSH_TOKEN", self.push.kind.name())));
            }
            Err(_) => {}
        }
        Ok(())
    }

    /// What `/status` would say, for the log and `send-test`.
    pub fn status(&self) -> String {
        let now = unix_now();
        let mut s = format!("vpsfort-push-bot {} to {}\n", env!("CARGO_PKG_VERSION"), self.push.kind.name());
        s += &format!("Sent since the start: {} alert(s), {} file(s)", self.stats.alerts, self.stats.files);
        if let Some(t) = self.stats.last_sent {
            s += &format!(", the last {} s ago", now - t);
        }
        s += "\n";
        if let Some((t, e)) = &self.stats.last_error {
            s += &format!("Last error, {} s ago: {e}\n", now - t);
        }
        s
    }
}

pub async fn run(mut bot: Bot) -> anyhow::Result<()> {
    let recovered = outbox::recover(&bot.cfg.outbox);
    if recovered > 0 {
        log::info!("outbox: {recovered} alert(s) left half-sent at the last stop, sending again");
    }
    if !bot.cfg.outbox.is_dir() {
        log::warn!("no outbox {} yet: nothing to deliver until it exists", bot.cfg.outbox.display());
    } else if let Err(e) = outbox::writable(&bot.cfg.outbox) {
        // e.g. an OUTBOX_DIR outside the unit's ReadWritePaths: messages could be read but never taken
        log::error!(
            "the outbox {} is not writable for the bot ({e}): it can't take or delete what vpsfort puts there",
            bot.cfg.outbox.display()
        );
    }
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    // vpsfort's alerts; the first tick is now
    let mut alerts = tokio::time::interval(Duration::from_secs(5));
    alerts.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // files (the weekly report)
    let mut files = tokio::time::interval(Duration::from_secs(60));
    files.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = loop {
        tokio::select! {
            _ = alerts.tick() => if let Err(e) = bot.deliver_alerts().await { break Err(e.into()) },
            _ = files.tick() => if let Err(e) = bot.deliver_files().await { break Err(e.into()) },
            _ = sigterm.recv() => break Ok(()),
            _ = sigint.recv() => break Ok(()),
        }
    };
    log::info!("Shutting down");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_cut_into_pieces() {
        let (subject, bodies) = pieces("[xmpp] vpsfort: system ✓\r\n\r\n[High] ban 1.2.3.4\u{0} → 1h\n  10-16 12:00 Привіт\n");
        assert_eq!(subject, "[xmpp] vpsfort: system ✓");
        assert_eq!(bodies, ["[High] ban 1.2.3.4 → 1h\n  10-16 12:00 Привіт"]);
        let (subject, bodies) = pieces("only a subject");
        assert_eq!((subject.as_str(), bodies.as_slice()), ("only a subject", &[String::new()][..]));
        assert_eq!(pieces("   \n\n").0, "vpsfort");
        let body: String = (0..400).map(|i| format!("  {i:>4} 1.2.3.{} 😀 points\n", i % 250)).collect();
        let (_, bodies) = pieces(&format!("[vpn] vpsfort daily digest\n\n{body}"));
        assert!(bodies.len() >= 3);
        assert!(bodies.iter().all(|b| b.chars().count() <= MESSAGE_LIMIT));
        assert!(bodies[1].starts_with("(continued)\n  "), "{}", &bodies[1][..40]);
        let lines: usize = bodies.iter().map(|b| b.lines().filter(|l| l.starts_with("  ")).count()).sum();
        assert_eq!(lines, 400, "no line lost");
        assert_eq!(split(&"x".repeat(10), 4).iter().map(String::len).collect::<Vec<_>>(), [4, 4, 2]);
    }

    #[test]
    fn sealed_files_have_neutral_names() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-19T06:20:00Z").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(sealed_name("abuse-report-2026-10-19.txt", now), "report-2026-10-19.txt.pgp");
        assert_eq!(sealed_name("noext", now), "report-2026-10-19.bin.pgp");
        assert!(!FILE_CAPTION.to_lowercase().contains("abuse"));
    }
}
