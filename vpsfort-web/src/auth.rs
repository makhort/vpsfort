//! The admins: each a password (Argon2id, `vpsfort-web passwd`) and, unless switched off, a
//! code from an authenticator app (`vpsfort-web totp-setup`). The first is "admin"
//! (`PASSWORD_FILE`, `TOTP_FILE`); others are made the same way with `--user <name>`, their
//! files in `ADMINS_DIR` (`<name>.password`, `<name>.totp`). All may do the same: there are
//! no roles. A login opens a session kept in memory (a restart ends them all) and named by a
//! random cookie; removing an account's files, or setting its password anew, ends its
//! sessions at their next request.
//!
//! Guessing is slowed three ways: Argon2's cost (one check at a time), a lockout of the
//! address after [`MAX_FAILURES`] failures, and vpsfort itself, which reads the failures
//! from the journal and bans the address (`[sources] apps = ["vpsfort-web"]`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::Engine as _;
use sha2::Digest;

use crate::say;
use crate::time::Micros;
use serde::{Deserialize, Serialize};

/// The session cookie: `__Host-` makes browsers keep it to this host, over HTTPS, path `/`.
pub const COOKIE: &str = "__Host-lgw";
/// Failures from one address within [`WINDOW`] before it is locked out for [`WINDOW`].
pub const MAX_FAILURES: u32 = 5;
pub const WINDOW: Duration = Duration::from_secs(15 * 60);
/// Failed logins at one account from anywhere within [`WINDOW`] before it is locked for
/// [`WINDOW`], except from addresses that logged in to it before (the admin's own).
pub const MAX_ACCOUNT_FAILURES: u32 = 10;
/// Sessions at once: a few browsers of each admin...
const MAX_SESSIONS: usize = 8;
/// ...and of all of them.
const MAX_ALL_SESSIONS: usize = 64;
/// The first admin's name: its files are `PASSWORD_FILE` and `TOTP_FILE`.
pub const MAIN: &str = "admin";
/// Addresses whose failures are remembered.
const MAX_TRACKED: usize = 10_000;
pub const MIN_PASSWORD: usize = 12;

#[derive(Clone, Debug)]
pub struct AuthCfg {
    /// The first admin's ("admin") password hash.
    pub password_file: PathBuf,
    /// Its TOTP secret's file; None: password only for every admin (`TOTP=off`).
    pub totp_file: Option<PathBuf>,
    /// The other admins' files: `<name>.password` and `<name>.totp`.
    pub admins_dir: PathBuf,
    /// A session ends after this long without a request...
    pub idle: Duration,
    /// ...and this long after the login, whatever.
    pub max: Duration,
    /// Where lockouts, the failure counters, the sessions and the login records are kept
    /// across restarts (`STATE_DIR`); None: in memory, a restart forgets them.
    pub state_dir: Option<PathBuf>,
}

struct Session {
    user: String,
    created: Instant,
    last: Instant,
    /// The same, as wall-clock times for the page.
    created_at: Micros,
    last_at: Micros,
    ip: IpAddr,
    /// The browser, as it says (shown to its admin, to tell sessions apart).
    agent: String,
    /// The admin's login before this one, and the failures since (shown once after the login).
    previous: LoginRecord,
    /// The password the session was opened under ([`password_tag`]): it ends when the
    /// account's password is another.
    pw: [u8; 8],
}

/// An admin's last good login and the failed attempts since (kept in `STATE_DIR` across
/// restarts; in memory otherwise).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LoginRecord {
    pub at: Option<Micros>,
    pub ip: Option<IpAddr>,
    pub failed_since: u32,
}

/// One session, as the page shows it to its admin.
#[derive(Clone, Debug, Serialize)]
pub struct SessionView {
    /// A short name for it (from its digest: nothing to log in with).
    pub id: String,
    pub user: String,
    pub ip: IpAddr,
    pub agent: String,
    pub created: Micros,
    pub last: Micros,
    /// When it ends however busy (`SESSION_MAX_HOURS` after the login).
    pub ends: Micros,
    /// Minutes without a request that end it.
    pub idle_secs: u64,
    pub current: bool,
}

#[derive(Default)]
struct AccountFailures {
    count: u32,
    first: Option<Instant>,
    locked_until: Option<Instant>,
    known_ips: Vec<IpAddr>,
}

#[derive(Default)]
struct Failures {
    count: u32,
    first: Option<Instant>,
    locked_until: Option<Instant>,
    /// Failures in the window, not reset by a lockout (the proof of work's difficulty).
    lately: u32,
    lately_since: Option<Instant>,
}

pub struct Auth {
    pub cfg: AuthCfg,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    /// Each admin's logins since the start.
    records: Mutex<HashMap<String, LoginRecord>>,
    failures: Mutex<HashMap<IpAddr, Failures>>,
    /// Each account's failures from anywhere, and the addresses it was logged in to from.
    accounts_hit: Mutex<HashMap<String, AccountFailures>>,
    /// When every failure of the window happened, for the proof of work's difficulty.
    all_failures: Mutex<std::collections::VecDeque<Instant>>,
    /// Each admin's newest TOTP time step used: each code works once.
    last_step: Mutex<HashMap<String, u64>>,
    /// One Argon2 check at a time (each takes ~19 MB and tens of milliseconds).
    checking: Mutex<()>,
    /// One change of a passkeys file at a time (read, changed, written whole).
    passkeys_lock: Mutex<()>,
    /// Logins since start: succeeded, failed, refused while locked out (for /metrics).
    pub logins: [AtomicU64; 3],
    /// `lockouts.json` and `sessions.json` in `STATE_DIR` (None: in memory).
    lockouts_path: Option<PathBuf>,
    sessions_path: Option<PathBuf>,
}

/// The lockout state as it is written: wall-clock times, read back against the clock.
#[derive(Default, Serialize, Deserialize)]
struct SavedLockouts {
    by_ip: Vec<(IpAddr, SavedFailures)>,
    accounts: Vec<(String, SavedAccount)>,
    all: Vec<Micros>,
    /// Each admin's newest TOTP time step used: a restart must not make a used code good again.
    #[serde(default)]
    steps: Vec<(String, u64)>,
}

#[derive(Default, Serialize, Deserialize)]
struct SavedFailures {
    count: u32,
    first: Option<Micros>,
    locked_until: Option<Micros>,
    lately: u32,
    lately_since: Option<Micros>,
}

#[derive(Default, Serialize, Deserialize)]
struct SavedAccount {
    count: u32,
    first: Option<Micros>,
    locked_until: Option<Micros>,
    known_ips: Vec<IpAddr>,
}

#[derive(Default, Serialize, Deserialize)]
struct SavedSessions {
    sessions: Vec<SavedSession>,
    records: Vec<(String, LoginRecord)>,
}

#[derive(Serialize, Deserialize)]
struct SavedSession {
    /// The cookie's digest, hex (nothing to log in with).
    key: String,
    user: String,
    created_at: Micros,
    last_at: Micros,
    ip: IpAddr,
    agent: String,
    previous: LoginRecord,
    /// [`password_tag`], hex; empty in a file from before sessions carried one.
    #[serde(default)]
    pw: String,
}

/// What a session remembers of the password it was opened under: the start of the hash's
/// digest. Nothing to log in with, and another for every `passwd`, even with the same password.
fn password_tag(hash: &str) -> [u8; 8] {
    let d = sha2::Sha256::digest(hash.trim().as_bytes());
    d[..8].try_into().expect("8 bytes")
}

/// An admin's TOTP secret from its file: 16 bytes at least (`totp-setup` writes 20). A file
/// that holds less, or nothing, would make codes anyone can work out.
fn totp_secret(file: &Path) -> Option<Vec<u8>> {
    read_secret(file).ok().and_then(|t| crate::totp::unbase32(&t)).filter(|s| s.len() >= 16)
}

/// Wall-clock times to the monotonic clock, around the moment of reading.
struct Clock {
    instant: Instant,
    wall: Micros,
}

impl Clock {
    fn now() -> Self {
        Clock { instant: Instant::now(), wall: crate::time::now() }
    }

    fn to_instant(&self, t: Micros) -> Instant {
        if t >= self.wall {
            self.instant + Duration::from_micros((t - self.wall) as u64)
        } else {
            self.instant.checked_sub(Duration::from_micros((self.wall - t) as u64)).unwrap_or(self.instant)
        }
    }

    fn to_wall(&self, t: Instant) -> Micros {
        if t >= self.instant {
            self.wall + (t - self.instant).as_micros() as Micros
        } else {
            self.wall - (self.instant - t).as_micros() as Micros
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Login {
    /// The new session's cookie value.
    Ok(String),
    Wrong,
    /// The passkey is the account's, but it only proved it was touched (no fingerprint, no
    /// PIN): the password is needed beside it. Not a failed login.
    NeedsPassword,
    /// Locked out for this long.
    Locked(Duration),
}

fn digest(token: &str) -> [u8; 32] {
    sha2::Sha256::digest(token.as_bytes()).into()
}

/// The session cookie's value in a `Cookie` header.
pub fn cookie_value(header: &str) -> Option<&str> {
    header.split(';').find_map(|c| c.trim().strip_prefix(COOKIE)?.strip_prefix('='))
}

/// Hashes a new password for the password file (Argon2id, the crate's recommended cost).
pub fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    crate::wire::getrandom(&mut salt)?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    Ok(Argon2::default().hash_password(password.as_bytes(), &salt).map_err(|e| anyhow::anyhow!("hashing: {e}"))?.to_string())
}

/// The account a login names: "" is the first admin.
pub fn login_name(user: &str) -> &str {
    if user.is_empty() {
        MAIN
    } else {
        user
    }
}

/// An admin's name: 1-32 lowercase letters, digits, `_` and `-`, starting with a letter.
pub fn user_ok(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// A hash no password matches, for logins to accounts that don't exist: they cost the same
/// Argon2 check, so the time taken tells nothing.
fn nobody() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_password("no account has this password").unwrap_or_default())
}

/// Makes the hash for logins to accounts that don't exist, so the first such login takes
/// no longer than the others (run at start).
pub fn warm() {
    nobody();
}

/// One admin's files.
#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub name: String,
    pub password_file: PathBuf,
    /// None with `TOTP=off`.
    pub totp_file: Option<PathBuf>,
    /// The admin's passkeys (`webauthn`): `<STATE_DIR>/passkeys/<name>.passkeys`, the one
    /// place the console's unit may write; without a `STATE_DIR`, next to the password file.
    pub passkeys_file: PathBuf,
    /// With a `STATE_DIR`: the file next to the password file, read while the one above
    /// doesn't exist (a setup from before passkeys moved, or files put there by hand).
    pub legacy_passkeys: Option<PathBuf>,
}

/// A passkey's answer at the login, as the page sends it, with what the console knows about
/// the request it came in.
#[derive(Clone, Debug)]
pub struct Assertion {
    /// The credential id (base64url).
    pub id: String,
    pub client_data: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
    /// The challenge the page answered (already taken back from the console's table).
    pub challenge: String,
    pub rp_id: String,
    pub origin: String,
}

/// The second factor given at a login.
#[derive(Clone, Debug)]
pub enum Second {
    /// A one-time code (empty with `TOTP=off`).
    Code(String),
    Passkey(Assertion),
}

/// Byte strings equal, in a time that doesn't depend on where they differ.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    let (a, b) = (sha2::Sha256::digest(a), sha2::Sha256::digest(b));
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Reads a secret file: a single line.
pub fn read_secret(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text.trim().to_string())
}

impl Auth {
    pub fn new(cfg: AuthCfg) -> Self {
        let lockouts_path = cfg.state_dir.as_ref().map(|d| d.join("lockouts.json"));
        let sessions_path = cfg.state_dir.as_ref().map(|d| d.join("sessions.json"));
        let auth = Auth {
            cfg,
            sessions: Mutex::default(),
            records: Mutex::default(),
            failures: Mutex::default(),
            accounts_hit: Mutex::default(),
            all_failures: Mutex::default(),
            last_step: Mutex::default(),
            checking: Mutex::new(()),
            passkeys_lock: Mutex::new(()),
            logins: Default::default(),
            lockouts_path,
            sessions_path,
        };
        auth.load();
        auth
    }

    /// The admins' files only, for the commands (`passkeys`, `admins`, `passwd`, `check`): the
    /// running console's sessions and lockouts are neither read (nothing to say about them)
    /// nor ever written from a root shell.
    pub fn files(cfg: AuthCfg) -> Self {
        Auth {
            cfg,
            sessions: Mutex::default(),
            records: Mutex::default(),
            failures: Mutex::default(),
            accounts_hit: Mutex::default(),
            all_failures: Mutex::default(),
            last_step: Mutex::default(),
            checking: Mutex::new(()),
            passkeys_lock: Mutex::new(()),
            logins: Default::default(),
            lockouts_path: None,
            sessions_path: None,
        }
    }

    /// Reads the lockouts and sessions back (a restart, or an attacker who made the console
    /// crash, must not reset a lockout or log every admin out).
    fn load(&self) {
        let clock = Clock::now();
        if let Some(v) = self.lockouts_path.as_deref().and_then(crate::store::load) {
            let saved: SavedLockouts = serde_json::from_value(v).unwrap_or_default();
            let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
            for (ip, f) in saved.by_ip.into_iter().take(MAX_TRACKED) {
                failures.insert(
                    ip,
                    Failures {
                        count: f.count,
                        first: f.first.map(|t| clock.to_instant(t)),
                        locked_until: f.locked_until.map(|t| clock.to_instant(t)),
                        lately: f.lately,
                        lately_since: f.lately_since.map(|t| clock.to_instant(t)),
                    },
                );
            }
            let mut hit = self.accounts_hit.lock().unwrap_or_else(|e| e.into_inner());
            for (user, a) in saved.accounts.into_iter().take(1000) {
                hit.insert(
                    user,
                    AccountFailures {
                        count: a.count,
                        first: a.first.map(|t| clock.to_instant(t)),
                        locked_until: a.locked_until.map(|t| clock.to_instant(t)),
                        known_ips: a.known_ips.into_iter().take(32).collect(),
                    },
                );
            }
            let mut all = self.all_failures.lock().unwrap_or_else(|e| e.into_inner());
            all.extend(saved.all.into_iter().take(100_000).map(|t| clock.to_instant(t)));
            self.last_step.lock().unwrap_or_else(|e| e.into_inner()).extend(saved.steps.into_iter().take(1000));
            let locked = failures.values().filter(|f| f.locked_until.is_some_and(|u| u > clock.instant)).count();
            if locked > 0 {
                say!("{locked} address(es) still locked out, read back from {}", self.lockouts_path.as_ref().expect("set").display());
            }
        }
        if let Some(v) = self.sessions_path.as_deref().and_then(crate::store::load) {
            let saved: SavedSessions = serde_json::from_value(v).unwrap_or_default();
            let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            for s in saved.sessions.into_iter().take(MAX_ALL_SESSIONS) {
                let Ok(bytes) = crate::wire::unhex(&s.key) else { continue };
                let Ok(key) = <[u8; 32]>::try_from(bytes) else { continue };
                // (a session from before they carried one goes on under the password of now)
                let pw = crate::wire::unhex(&s.pw)
                    .ok()
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .or_else(|| self.current_tag(&s.user))
                    .unwrap_or_default();
                sessions.insert(
                    key,
                    Session {
                        pw,
                        user: s.user,
                        created: clock.to_instant(s.created_at),
                        // the idle clock starts afresh: how long the console was down is unknown
                        last: clock.instant,
                        created_at: s.created_at,
                        last_at: s.last_at,
                        ip: s.ip,
                        agent: s.agent,
                        previous: s.previous,
                    },
                );
            }
            self.expire(&mut sessions, clock.instant);
            if !sessions.is_empty() {
                say!("{} session(s) read back from {}", sessions.len(), self.sessions_path.as_ref().expect("set").display());
            }
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records.extend(saved.records.into_iter().take(1000));
        }
    }

    /// Writes the lockouts and failure counters (after each failure or lockout: rare).
    fn save_lockouts(&self) {
        let Some(path) = &self.lockouts_path else { return };
        let clock = Clock::now();
        let saved = {
            let failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
            let hit = self.accounts_hit.lock().unwrap_or_else(|e| e.into_inner());
            let all = self.all_failures.lock().unwrap_or_else(|e| e.into_inner());
            SavedLockouts {
                by_ip: failures
                    .iter()
                    .filter(|(_, f)| {
                        f.locked_until.is_some_and(|u| u > clock.instant) || f.first.is_some_and(|t| clock.instant - t < WINDOW)
                    })
                    .map(|(ip, f)| {
                        (
                            *ip,
                            SavedFailures {
                                count: f.count,
                                first: f.first.map(|t| clock.to_wall(t)),
                                locked_until: f.locked_until.map(|t| clock.to_wall(t)),
                                lately: f.lately,
                                lately_since: f.lately_since.map(|t| clock.to_wall(t)),
                            },
                        )
                    })
                    .collect(),
                accounts: hit
                    .iter()
                    .map(|(u, a)| {
                        (
                            u.clone(),
                            SavedAccount {
                                count: a.count,
                                first: a.first.map(|t| clock.to_wall(t)),
                                locked_until: a.locked_until.map(|t| clock.to_wall(t)),
                                known_ips: a.known_ips.clone(),
                            },
                        )
                    })
                    .collect(),
                all: all.iter().filter(|t| clock.instant - **t < WINDOW).map(|t| clock.to_wall(*t)).collect(),
                steps: self.last_step.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(u, s)| (u.clone(), *s)).collect(),
            }
        };
        if let Ok(v) = serde_json::to_value(&saved) {
            crate::store::save(path, &v);
        }
    }

    /// Writes the sessions and login records (at a login, a logout, a session ended).
    fn save_sessions(&self) {
        let Some(path) = &self.sessions_path else { return };
        let saved = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            SavedSessions {
                sessions: sessions
                    .iter()
                    .map(|(k, s)| SavedSession {
                        key: crate::wire::hex(k),
                        user: s.user.clone(),
                        created_at: s.created_at,
                        last_at: s.last_at,
                        ip: s.ip,
                        agent: s.agent.clone(),
                        previous: s.previous.clone(),
                        pw: crate::wire::hex(&s.pw),
                    })
                    .collect(),
                records: records.iter().map(|(u, r)| (u.clone(), r.clone())).collect(),
            }
        };
        if let Ok(v) = serde_json::to_value(&saved) {
            crate::store::save(path, &v);
        }
    }

    /// Whether the lockouts and sessions survive a restart.
    pub fn kept(&self) -> bool {
        self.lockouts_path.is_some()
    }

    /// The files of admin `name` (whether they exist or not); None for a name that can't be one.
    pub fn account(&self, name: &str) -> Option<Account> {
        // the admins' directories are root's (the console only reads them): passkeys, which the
        // console writes, go to its own state directory
        let passkeys = |beside: PathBuf| match &self.cfg.state_dir {
            Some(d) => (d.join("passkeys").join(format!("{name}.passkeys")), Some(beside)),
            None => (beside, None),
        };
        if name == MAIN {
            let (passkeys_file, legacy_passkeys) = passkeys(crate::webauthn::file_for(&self.cfg.password_file));
            return Some(Account {
                name: MAIN.into(),
                password_file: self.cfg.password_file.clone(),
                totp_file: self.cfg.totp_file.clone(),
                passkeys_file,
                legacy_passkeys,
            });
        }
        user_ok(name).then(|| {
            let (passkeys_file, legacy_passkeys) = passkeys(self.cfg.admins_dir.join(format!("{name}.passkeys")));
            Account {
                name: name.into(),
                password_file: self.cfg.admins_dir.join(format!("{name}.password")),
                totp_file: self.cfg.totp_file.as_ref().map(|_| self.cfg.admins_dir.join(format!("{name}.totp"))),
                passkeys_file,
                legacy_passkeys,
            }
        })
    }

    /// An admin's passkeys as stored: the console's own file, else the older one beside the
    /// password file.
    fn load_passkeys(a: &Account) -> Result<Vec<crate::webauthn::Credential>> {
        match &a.legacy_passkeys {
            Some(old) if !a.passkeys_file.exists() => crate::webauthn::load(old),
            _ => crate::webauthn::load(&a.passkeys_file),
        }
    }

    /// Writes them to the console's own file (kept, even empty, while an older file exists
    /// that would otherwise be read again).
    fn save_passkeys(a: &Account, creds: &[crate::webauthn::Credential]) -> Result<()> {
        let keep_empty = a.legacy_passkeys.as_ref().is_some_and(|old| old.exists());
        crate::webauthn::save(&a.passkeys_file, creds, keep_empty)
    }

    /// Whether a passkey registered now could be kept: asked before the browser makes one.
    pub fn passkeys_writable(&self, user: &str) -> Result<()> {
        let a = self.account(user).context("no such admin")?;
        crate::webauthn::writable(&a.passkeys_file)
    }

    /// Every admin: "admin", then those in `ADMINS_DIR` (by their password files), by name.
    pub fn accounts(&self) -> Vec<Account> {
        let mut names: Vec<String> = std::fs::read_dir(&self.cfg.admins_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.strip_suffix(".password").map(str::to_string))
            .filter(|n| n != MAIN && user_ok(n))
            .collect();
        names.sort();
        std::iter::once(MAIN.to_string()).chain(names).filter_map(|n| self.account(&n)).collect()
    }

    /// Checks that an admin's password (and TOTP) files can be read and hold what they should.
    pub fn check_account(&self, a: &Account) -> Result<()> {
        let user = if a.name == MAIN { String::new() } else { format!(" --user {}", a.name) };
        let hash = read_secret(&a.password_file)?;
        PasswordHash::new(&hash).map_err(|e| {
            anyhow::anyhow!("{}: not a password hash ({e}): set it with `vpsfort-web passwd{user}`", a.password_file.display())
        })?;
        if let Some(f) = &a.totp_file {
            if totp_secret(f).is_none() {
                bail!("{}: no TOTP secret: make one with `vpsfort-web totp-setup{user}`", f.display());
            }
        }
        Ok(())
    }

    /// Checks the first admin's files: without them the console doesn't start. (Another
    /// admin's broken files only keep that admin out: see [`Auth::accounts`].)
    pub fn check_files(&self) -> Result<()> {
        self.check_account(&self.account(MAIN).expect("the first admin"))
    }

    /// Whether `ip` is locked out now, and for how long still.
    fn locked(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        f.get(&ip).and_then(|f| f.locked_until).filter(|u| *u > now).map(|u| u - now)
    }

    /// Failures lately: from `ip`, at `user`, and from everyone (for the proof of work).
    pub fn failures_lately(&self, ip: IpAddr, user: &str) -> (u32, u32, u32) {
        let now = Instant::now();
        let by_ip = self
            .failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&ip)
            .filter(|f| f.lately_since.is_some_and(|t| now - t < WINDOW))
            .map_or(0, |f| f.lately);
        let user = if user.is_empty() { MAIN } else { user };
        let by_account = self
            .accounts_hit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(user)
            .filter(|a| a.first.is_some_and(|t| now - t < WINDOW))
            .map_or(0, |a| a.count);
        let mut all = self.all_failures.lock().unwrap_or_else(|e| e.into_inner());
        while all.front().is_some_and(|t| now - *t >= WINDOW) {
            all.pop_front();
        }
        (by_ip, by_account, all.len() as u32)
    }

    /// Whether `user` is locked for everyone but its own addresses, and for how long still.
    fn account_locked(&self, user: &str, ip: IpAddr, now: Instant) -> Option<Duration> {
        let hit = self.accounts_hit.lock().unwrap_or_else(|e| e.into_inner());
        let a = hit.get(user)?;
        if a.known_ips.contains(&ip) {
            return None;
        }
        a.locked_until.filter(|u| *u > now).map(|u| u - now)
    }

    fn account_failed(&self, user: &str, now: Instant) {
        let mut hit = self.accounts_hit.lock().unwrap_or_else(|e| e.into_inner());
        if hit.len() >= 1000 && !hit.contains_key(user) {
            hit.retain(|_, a| a.locked_until.is_some_and(|u| u > now) || !a.known_ips.is_empty());
            if hit.len() >= 1000 {
                // all of them locked: the one whose lock ends first makes room, never an
                // account that was logged in to (those are real). Leaving this failure
                // uncounted would keep a real account without its lock for as long as
                // made-up names fill the table.
                let first_out =
                    hit.iter().filter(|(_, a)| a.known_ips.is_empty()).min_by_key(|(_, a)| a.locked_until).map(|(u, _)| u.clone());
                match first_out {
                    Some(u) => hit.remove(&u),
                    None => return,
                };
            }
        }
        let a = hit.entry(user.to_string()).or_default();
        if a.first.is_none_or(|t| now - t >= WINDOW) {
            a.count = 0;
            a.first = Some(now);
        }
        a.count += 1;
        if a.count >= MAX_ACCOUNT_FAILURES && a.locked_until.is_none_or(|u| u <= now) {
            a.locked_until = Some(now + WINDOW);
            say!("account {user} locked for {} minutes after {MAX_ACCOUNT_FAILURES} failed logins from anywhere (its own addresses may still log in)", WINDOW.as_secs() / 60);
        }
        let mut all = self.all_failures.lock().unwrap_or_else(|e| e.into_inner());
        all.push_back(now);
        if all.len() > 100_000 {
            all.pop_front();
        }
    }

    /// Whether `code` is `user`'s current one-time code (not marking it used: the login does).
    fn code_ok_for(&self, user: &str, code: &str) -> bool {
        let Some(a) = self.account(user).filter(|a| a.password_file.exists()) else { return false };
        let Some(f) = a.totp_file.as_ref() else { return false };
        let Some(secret) = totp_secret(f) else { return false };
        let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let used = self.last_step.lock().unwrap_or_else(|e| e.into_inner()).get(user).copied().unwrap_or(0);
        crate::totp::verify(&secret, code, unix, used).is_some()
    }

    fn account_succeeded(&self, user: &str, ip: IpAddr) {
        let mut hit = self.accounts_hit.lock().unwrap_or_else(|e| e.into_inner());
        let a = hit.entry(user.to_string()).or_default();
        a.count = 0;
        a.first = None;
        if !a.known_ips.contains(&ip) {
            if a.known_ips.len() >= 32 {
                a.known_ips.remove(0);
            }
            a.known_ips.push(ip);
        }
    }

    fn failed(&self, ip: IpAddr, now: Instant) {
        let mut all = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        if all.len() >= MAX_TRACKED {
            all.retain(|_, f| f.locked_until.is_some_and(|u| u > now) || f.first.is_some_and(|t| now - t < WINDOW));
            if all.len() >= MAX_TRACKED {
                // a flood from many addresses: vpsfort bans them; forget the oldest here
                all.retain(|_, f| f.locked_until.is_some_and(|u| u > now));
            }
        }
        let f = all.entry(ip).or_default();
        if f.first.is_none_or(|t| now - t >= WINDOW) {
            *f = Failures { count: 0, first: Some(now), locked_until: f.locked_until, lately: f.lately, lately_since: f.lately_since };
        }
        if f.lately_since.is_none_or(|t| now - t >= WINDOW) {
            f.lately = 0;
            f.lately_since = Some(now);
        }
        f.lately = f.lately.saturating_add(1);
        f.count += 1;
        if f.count >= MAX_FAILURES {
            f.locked_until = Some(now + WINDOW);
            f.count = 0;
            f.first = None;
        }
    }

    /// A login attempt from `ip` as admin `user` (empty: "admin"). Every attempt costs the
    /// same Argon2 check, however it fails, also for an account that doesn't exist.
    /// The admin's passkeys (none for a name that can't be one, or without a file).
    pub fn passkeys(&self, user: &str) -> Vec<crate::webauthn::Credential> {
        self.account(user).and_then(|a| Self::load_passkeys(&a).ok()).unwrap_or_default()
    }

    /// Adds a passkey to the admin's file (at most [`crate::webauthn::MAX_PER_ADMIN`]).
    pub fn add_passkey(&self, user: &str, cred: crate::webauthn::Credential) -> Result<()> {
        let a = self.account(user).context("no such admin")?;
        let _one = self.passkeys_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut creds = Self::load_passkeys(&a)?;
        if creds.iter().any(|c| c.id == cred.id) {
            bail!("this passkey is registered already");
        }
        if creds.len() >= crate::webauthn::MAX_PER_ADMIN {
            bail!("at most {} passkeys per admin: remove one first", crate::webauthn::MAX_PER_ADMIN);
        }
        creds.push(cred);
        Self::save_passkeys(&a, &creds)
    }

    /// Removes a passkey by its id; false when there was none.
    pub fn remove_passkey(&self, user: &str, id: &str) -> Result<bool> {
        let a = self.account(user).context("no such admin")?;
        let _one = self.passkeys_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut creds = Self::load_passkeys(&a)?;
        let before = creds.len();
        creds.retain(|c| c.id != id);
        if creds.len() == before {
            return Ok(false);
        }
        Self::save_passkeys(&a, &creds)?;
        Ok(true)
    }

    /// An assertion checked against the admin's passkeys (pure: the counter is stored by the
    /// caller on a successful login).
    fn passkey_check(&self, user: &str, a: &Assertion) -> std::result::Result<(crate::webauthn::Credential, u32, bool), &'static str> {
        let creds = self.passkeys(user);
        let cred = creds.iter().find(|c| c.id == a.id).ok_or("no such passkey for this account")?;
        let count = crate::webauthn::verify_assertion(&a.rp_id, &a.origin, &a.challenge, cred, &a.client_data, &a.auth_data, &a.signature)
            .map_err(|e| {
                say!("passkey refused for {user}: {e:#}");
                "the passkey's answer doesn't verify"
            })?;
        Ok((cred.clone(), count, crate::webauthn::user_verified(&a.auth_data)))
    }

    /// A login with a one-time code (or none, with `TOTP=off`).
    pub fn login(&self, ip: IpAddr, user: &str, password: &str, code: &str) -> Result<Login> {
        self.login_with(ip, user, password, Second::Code(code.to_string()))
    }

    pub fn login_with(&self, ip: IpAddr, user: &str, password: &str, second: Second) -> Result<Login> {
        let now = Instant::now();
        // a passkey's answer is checked once, up front (it can open a locked account too)
        let passkey = match &second {
            Second::Passkey(a) => Some(self.passkey_check(login_name(user), a)),
            Second::Code(_) => None,
        };
        let code: &str = match &second {
            Second::Code(c) => c,
            Second::Passkey(_) => "",
        };
        if let Some(left) = self.locked(ip, now) {
            self.logins[2].fetch_add(1, Ordering::Relaxed);
            say!("login refused from {ip}: locked out for {}s more after {MAX_FAILURES} failures", left.as_secs());
            return Ok(Login::Locked(left));
        }
        let user = login_name(user);
        // An account locked by failures from anywhere stays open to its own addresses, and to
        // whoever has its authenticator: a guesser can't produce the code, so the admin on a
        // new address isn't locked out with the attacker. (Password only: the lock holds.)
        let account_lock = self.account_locked(user, ip, now);
        if let Some(left) = account_lock {
            // only something shaped like a code is worth reading the account's files for
            let shaped = code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit());
            let code_opens =
                (shaped && self.cfg.totp_file.is_some() && self.code_ok_for(user, code)) || passkey.as_ref().is_some_and(|p| p.is_ok());
            if !code_opens {
                self.logins[2].fetch_add(1, Ordering::Relaxed);
                say!("login refused from {ip}: account {user} locked for {}s more", left.as_secs());
                return Ok(Login::Locked(left));
            }
        }
        // the main admin's files must be there (the console doesn't start without them);
        // another admin's may be missing: then nobody's hash is checked
        let account = self.account(user).filter(|a| a.name == MAIN || a.password_file.exists());
        let hash = match &account {
            Some(a) => read_secret(&a.password_file)?,
            None => nobody().to_string(),
        };
        let parsed = PasswordHash::new(&hash)
            .map_err(|e| anyhow::anyhow!("{}'s password file: {e}", account.as_ref().map_or("?", |a| a.name.as_str())))?;
        let password_ok = {
            let _one = self.checking.lock().unwrap_or_else(|e| e.into_inner());
            password.len() <= 1024 && Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
        } && account.is_some();
        // A passkey that checked its holder (fingerprint, face, PIN) is two factors in itself,
        // and is the login on its own. One that was only touched stands in for the code beside
        // the password. A password that is given must still be right.
        if password.is_empty() && account.is_some() {
            match &passkey {
                Some(Ok((_, _, true))) => {}
                Some(Ok((_, _, false))) => {
                    say!("login from {ip} as {user}: the passkey didn't check its holder, the password is needed too");
                    return Ok(Login::NeedsPassword);
                }
                _ => {}
            }
        }
        let password_ok = password_ok || (password.is_empty() && account.is_some() && matches!(&passkey, Some(Ok((_, _, true)))));
        let code_ok = match (&account, &self.cfg.totp_file, &passkey) {
            // a passkey stands in for the code, whether or not TOTP is on
            (Some(a), _, Some(Ok((cred, count, _)))) => {
                if password_ok {
                    let _one = self.passkeys_lock.lock().unwrap_or_else(|e| e.into_inner());
                    let mut creds = Self::load_passkeys(a).unwrap_or_default();
                    if let Some(c) = creds.iter_mut().find(|c| c.id == cred.id) {
                        c.sign_count = *count;
                        // the console's own count: a synced passkey's counter never moves
                        c.logins = c.logins.saturating_add(1);
                        c.last_used = Some(crate::time::now());
                        if let Err(e) = Self::save_passkeys(a, &creds) {
                            say!("passkeys of {}: {e:#}", a.name);
                        }
                    }
                }
                Ok(())
            }
            (None, _, Some(_)) => Err("no such account"),
            (Some(_), _, Some(Err(why))) => Err(*why),
            (_, None, None) => Ok(()),
            (None, Some(_), None) => Err("no such account"),
            (Some(a), Some(_), None) => {
                let f = a.totp_file.as_ref().expect("TOTP is on");
                match totp_secret(f) {
                    None => Err("no TOTP secret for this account yet (totp-setup)"),
                    Some(secret) => {
                        let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                        let mut last = self.last_step.lock().unwrap_or_else(|e| e.into_inner());
                        let used = last.get(&a.name).copied().unwrap_or(0);
                        match crate::totp::verify(&secret, code, unix, used) {
                            Some(step) if password_ok => {
                                last.insert(a.name.clone(), step);
                                Ok(())
                            }
                            Some(_) => Ok(()),
                            None if crate::totp::verify(&secret, code, unix, 0).is_some() => Err("code already used"),
                            None => Err("wrong code"),
                        }
                    }
                }
            }
        };
        // the name as tried, if it can be one (nothing else a stranger typed reaches the log)
        let who = account.as_ref().map_or_else(|| "an unknown account".to_string(), |a| format!("account {}", a.name));
        match (password_ok, code_ok) {
            (true, Ok(())) => {
                let user = account.expect("checked").name;
                self.failures.lock().unwrap_or_else(|e| e.into_inner()).remove(&ip);
                self.account_succeeded(&user, ip);
                let previous = {
                    let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
                    let r = records.entry(user.clone()).or_default();
                    std::mem::replace(r, LoginRecord { at: Some(crate::time::now()), ip: Some(ip), failed_since: 0 })
                };
                let token = self.open_session(&user, ip, previous, now, password_tag(&hash))?;
                self.logins[0].fetch_add(1, Ordering::Relaxed);
                say!("login from {ip} as {user}");
                self.save_lockouts();
                self.save_sessions();
                Ok(Login::Ok(token))
            }
            (pw, code) => {
                let why = match (pw, code) {
                    (false, Err(_)) => "wrong password and code",
                    (false, Ok(())) => "wrong password",
                    (true, Err(why)) => why,
                    (true, Ok(())) => unreachable!(),
                };
                say!("login failed from {ip}: {why} ({who})");
                if let Some(a) = &account {
                    let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
                    if records.len() < 1000 || records.contains_key(&a.name) {
                        let r = records.entry(a.name.clone()).or_default();
                        r.failed_since = r.failed_since.saturating_add(1);
                    }
                }
                self.logins[1].fetch_add(1, Ordering::Relaxed);
                self.failed(ip, now);
                // an account that can be one, whether it exists or not (a guesser learns nothing)
                if let Some(a) = &account {
                    self.account_failed(&a.name, now);
                } else if user_ok(user) {
                    self.account_failed(user, now);
                }
                self.save_lockouts();
                self.save_sessions();
                Ok(Login::Wrong)
            }
        }
    }

    /// The tag of the password `user` has now; None when its file can't be read.
    fn current_tag(&self, user: &str) -> Option<[u8; 8]> {
        self.account(user).and_then(|a| read_secret(&a.password_file).ok()).map(|hash| password_tag(&hash))
    }

    fn open_session(&self, user: &str, ip: IpAddr, previous: LoginRecord, now: Instant, pw: [u8; 8]) -> Result<String> {
        let mut raw = [0u8; 32];
        crate::wire::getrandom(&mut raw)?;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut sessions, now);
        // the least recently used goes: of this admin's, else of all
        let theirs = sessions.values().filter(|s| s.user == user).count();
        if theirs >= MAX_SESSIONS || sessions.len() >= MAX_ALL_SESSIONS {
            let mine = theirs >= MAX_SESSIONS;
            if let Some(oldest) = sessions.iter().filter(|(_, s)| !mine || s.user == user).min_by_key(|(_, s)| s.last).map(|(k, _)| *k) {
                sessions.remove(&oldest);
            }
        }
        let at = crate::time::now();
        sessions.insert(
            digest(&token),
            Session {
                user: user.to_string(),
                created: now,
                last: now,
                created_at: at,
                last_at: at,
                ip,
                agent: String::new(),
                previous,
                pw,
            },
        );
        Ok(token)
    }

    fn expire(&self, sessions: &mut HashMap<[u8; 32], Session>, now: Instant) {
        sessions.retain(|_, s| now - s.last < self.cfg.idle && now - s.created < self.cfg.max);
    }

    /// The admin whose live session `token` names; it counts as activity. A session of an
    /// admin whose password file was removed ends here.
    pub fn session(&self, token: &str) -> Option<String> {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut sessions, now);
        let key = digest(token);
        let user = sessions.get(&key)?.user.clone();
        if user != MAIN && !self.account(&user).is_some_and(|a| a.password_file.exists()) {
            sessions.remove(&key);
            say!("session of {user} ended: the account is gone");
            return None;
        }
        // a password set anew ends the sessions opened under the old one (a file that can't
        // be read just now ends nothing)
        if self.current_tag(&user).is_some_and(|tag| sessions.get(&key).is_some_and(|s| s.pw != tag)) {
            sessions.remove(&key);
            say!("session of {user} ended: the account's password was changed");
            return None;
        }
        let s = sessions.get_mut(&key)?;
        s.last = now;
        s.last_at = crate::time::now();
        Some(user)
    }

    fn view(&self, key: &[u8; 32], s: &Session, current: bool) -> SessionView {
        SessionView {
            id: key[..4].iter().map(|b| format!("{b:02x}")).collect(),
            user: s.user.clone(),
            ip: s.ip,
            agent: s.agent.clone(),
            created: s.created_at,
            last: s.last_at,
            ends: s.created_at.saturating_add(self.cfg.max.as_micros() as Micros),
            idle_secs: self.cfg.idle.as_secs(),
            current,
        }
    }

    /// Notes the browser of the session `token` (its User-Agent, cut short).
    pub fn set_agent(&self, token: &str, agent: &str) {
        let changed = {
            let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            match sessions.get_mut(&digest(token)) {
                Some(s) => {
                    let agent: String = agent.chars().filter(|c| !c.is_control()).take(160).collect();
                    let changed = s.agent != agent;
                    s.agent = agent;
                    changed
                }
                None => false,
            }
        };
        if changed {
            self.save_sessions();
        }
    }

    /// The session `token`, and its admin's login before it.
    pub fn about(&self, token: &str) -> Option<(SessionView, LoginRecord)> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut sessions, Instant::now());
        let key = digest(token);
        let s = sessions.get(&key)?;
        Some((self.view(&key, s, true), s.previous.clone()))
    }

    /// The sessions of the admin of `token`, newest first.
    pub fn list(&self, token: &str) -> Vec<SessionView> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut sessions, Instant::now());
        let me = digest(token);
        let Some(user) = sessions.get(&me).map(|s| s.user.clone()) else { return vec![] };
        let mut out: Vec<SessionView> = sessions.iter().filter(|(_, s)| s.user == user).map(|(k, s)| self.view(k, s, *k == me)).collect();
        out.sort_by_key(|v| std::cmp::Reverse(v.created));
        out
    }

    /// Ends the other sessions of the admin of `token`; how many.
    pub fn end_others(&self, token: &str) -> usize {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let me = digest(token);
        let Some(user) = sessions.get(&me).map(|s| s.user.clone()) else { return 0 };
        let before = sessions.len();
        sessions.retain(|k, s| *k == me || s.user != user);
        let ended = before - sessions.len();
        drop(sessions);
        if ended > 0 {
            say!("{user} ended {ended} other session(s)");
            self.save_sessions();
        }
        ended
    }

    /// Sessions open now.
    pub fn sessions(&self) -> usize {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        self.expire(&mut sessions, Instant::now());
        sessions.len()
    }

    pub fn logout(&self, token: &str) {
        let gone = self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&digest(token));
        if let Some(s) = gone {
            say!("{} logged out from {}", s.user, s.ip);
            self.save_sessions();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(test: &str, totp: bool) -> (Auth, PathBuf, Vec<u8>) {
        let dir = std::env::temp_dir().join(format!("lgw-auth-{}-{test}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pw"), hash_password("correct horse battery").unwrap()).unwrap();
        let secret = b"0123456789abcdefghij".to_vec();
        std::fs::write(dir.join("totp"), crate::totp::base32(&secret)).unwrap();
        let cfg = AuthCfg {
            password_file: dir.join("pw"),
            totp_file: totp.then(|| dir.join("totp")),
            admins_dir: dir.join("admins"),
            idle: Duration::from_secs(60),
            state_dir: None,
            max: Duration::from_secs(3600),
        };
        let auth = Auth::new(cfg);
        auth.check_files().unwrap();
        (auth, dir, secret)
    }

    /// The console's unit may write only its state directory: passkeys live there, and the
    /// file beside the password file (root's directory) is only read.
    #[test]
    fn passkeys_live_in_the_state_dir() {
        use crate::webauthn::tests::Authenticator;
        let (plain, dir, _) = setup("passkeys-state", false);
        let state = dir.join("state");
        let auth = Auth::new(AuthCfg { state_dir: Some(state.clone()), ..plain.cfg.clone() });
        let a = auth.account("admin").unwrap();
        assert_eq!(a.passkeys_file, state.join("passkeys").join("admin.passkeys"));
        assert_eq!(a.legacy_passkeys, Some(dir.join("pw.passkeys")));
        assert_eq!(auth.account("ann").unwrap().passkeys_file, state.join("passkeys").join("ann.passkeys"));
        assert_eq!(plain.account("admin").unwrap().passkeys_file, dir.join("pw.passkeys"), "no STATE_DIR: beside the password file");
        let (rp, origin) = ("console.example.org", "https://console.example.org");
        // the fake authenticator's credential id is fixed: one of its own per passkey
        let cred = |alg: i64, challenge: &str, name: &str| {
            let mut key = Authenticator::new(alg);
            key.id = name.as_bytes().to_vec();
            let (cd, att) = key.register(rp, origin, challenge);
            crate::webauthn::finish_registration(rp, origin, challenge, &cd, &att, name, 1).unwrap()
        };
        auth.passkeys_writable("admin").unwrap();
        auth.add_passkey("admin", cred(-7, "c1", "laptop")).unwrap();
        assert!(a.passkeys_file.exists() && !dir.join("pw.passkeys").exists(), "written to the state directory only");
        assert_eq!(auth.passkeys("admin").len(), 1);
        // an older file beside the password file is read until the console writes its own...
        let old = cred(-7, "c2", "old key");
        crate::webauthn::save(&dir.join("admins").join("ann.passkeys"), std::slice::from_ref(&old), false).unwrap();
        assert_eq!(auth.passkeys("ann").iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["old key"]);
        auth.add_passkey("ann", cred(-8, "c3", "phone")).unwrap();
        assert_eq!(auth.passkeys("ann").len(), 2, "the older one carried over");
        // ...and doesn't come back when the last one is removed
        for c in auth.passkeys("ann") {
            assert!(auth.remove_passkey("ann", &c.id).unwrap());
        }
        assert!(auth.passkeys("ann").is_empty());
        // a state directory the console can't make: said before the browser is asked
        std::fs::write(dir.join("file"), "x").unwrap();
        let blocked = Auth::new(AuthCfg { state_dir: Some(dir.join("file").join("under")), ..plain.cfg.clone() });
        assert!(blocked.passkeys_writable("admin").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A second factor that is one: a secret file that holds none (empty, or a few bytes)
    /// would make codes anyone can work out, so it counts as no secret at the login too, not
    /// only at the start-up check of the first admin's.
    #[test]
    fn a_short_totp_secret_opens_nothing() {
        let (auth, dir, _) = setup("short-totp", true);
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        std::fs::create_dir_all(dir.join("admins")).unwrap();
        std::fs::write(dir.join("admins/ann.password"), hash_password("a long password of ann").unwrap()).unwrap();
        let code_of = |secret: &[u8]| {
            let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            format!("{:06}", crate::totp::code(secret, unix / crate::totp::STEP_SECS))
        };
        for secret in [&b""[..], &b"short"[..]] {
            std::fs::write(dir.join("admins/ann.totp"), crate::totp::base32(secret)).unwrap();
            assert_eq!(auth.login(ip, "ann", "a long password of ann", &code_of(secret)).unwrap(), Login::Wrong, "{secret:?}");
            assert!(!auth.code_ok_for("ann", &code_of(secret)));
        }
        let real = b"0123456789abcdefghij";
        std::fs::write(dir.join("admins/ann.totp"), crate::totp::base32(real)).unwrap();
        assert!(matches!(auth.login(ip, "ann", "a long password of ann", &code_of(real)).unwrap(), Login::Ok(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A password that is changed ends the account's sessions: whoever had it before must
    /// not stay in for the rest of the session's twelve hours.
    #[test]
    fn a_changed_password_ends_the_sessions() {
        let (auth, dir, _) = setup("pw-change", false);
        let ip: IpAddr = "192.0.2.8".parse().unwrap();
        let Login::Ok(token) = auth.login(ip, "", "correct horse battery", "").unwrap() else { panic!("login") };
        assert_eq!(auth.session(&token).as_deref(), Some("admin"));
        std::fs::write(dir.join("pw"), hash_password("another long password").unwrap()).unwrap();
        assert_eq!(auth.session(&token), None, "the old password's session");
        let Login::Ok(new) = auth.login(ip, "", "another long password", "").unwrap() else { panic!("login") };
        assert_eq!(auth.session(&new).as_deref(), Some("admin"));
        // the same password written again (another salt) is a change too: `passwd` was run
        std::fs::write(dir.join("pw"), hash_password("another long password").unwrap()).unwrap();
        assert_eq!(auth.session(&new), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The code just used, and the sessions' passwords, are kept with the state: a restart
    /// (or a crash someone caused) brings neither a used code nor an old password's session back.
    #[test]
    fn used_codes_and_password_tags_survive_a_restart() {
        let (plain, dir, secret) = setup("kept-steps", true);
        let cfg = AuthCfg { state_dir: Some(dir.join("state")), ..plain.cfg.clone() };
        let auth = Auth::new(cfg.clone());
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let code = format!("{:06}", crate::totp::code(&secret, unix / crate::totp::STEP_SECS));
        let Login::Ok(token) = auth.login(ip, "", "correct horse battery", &code).unwrap() else { panic!("login") };
        let again = Auth::new(cfg.clone());
        assert_eq!(again.login(ip, "", "correct horse battery", &code).unwrap(), Login::Wrong, "the code was used before the restart");
        assert_eq!(again.session(&token).as_deref(), Some("admin"), "the session is read back");
        std::fs::write(dir.join("pw"), hash_password("another long password").unwrap()).unwrap();
        assert_eq!(Auth::new(cfg).session(&token), None, "and ends with its password, restart or not");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A thousand made-up names, all locked, must not keep a real account's failures from
    /// being counted (its own lock would never come).
    #[test]
    fn a_full_table_of_locked_names_still_counts_a_new_one() {
        let (auth, dir, _) = setup("full-accounts", false);
        let now = Instant::now();
        {
            let mut hit = auth.accounts_hit.lock().unwrap();
            for i in 0..1000 {
                hit.insert(
                    format!("x{i}"),
                    AccountFailures { count: 10, first: Some(now), locked_until: Some(now + WINDOW), known_ips: vec![] },
                );
            }
            hit.insert("ann".into(), AccountFailures { known_ips: vec!["192.0.2.1".parse().unwrap()], ..Default::default() });
        }
        for _ in 0..MAX_ACCOUNT_FAILURES {
            auth.account_failed("bob", now);
        }
        let hit = auth.accounts_hit.lock().unwrap();
        assert!(hit.get("bob").is_some_and(|a| a.locked_until.is_some()), "counted, and locked in its turn");
        assert!(hit.contains_key("ann"), "an account that was logged in to is never the one to go");
        assert!(hit.len() <= 1001);
        drop(hit);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_passkey_stands_in_for_the_code() {
        use crate::webauthn::tests::Authenticator;
        let (auth, dir, secret) = setup("passkey", true);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let (rp, origin) = ("console.example.org", "https://console.example.org:7948");
        let mut key = Authenticator::new(-7);
        let (cd, att) = key.register(rp, origin, "reg-1");
        let cred = crate::webauthn::finish_registration(rp, origin, "reg-1", &cd, &att, "laptop", 1).unwrap();
        assert!(auth.passkeys("admin").is_empty());
        auth.add_passkey("admin", cred.clone()).unwrap();
        assert_eq!(auth.passkeys("admin").len(), 1);
        assert!(auth.add_passkey("admin", cred.clone()).unwrap_err().to_string().contains("already"));
        let assertion = |key: &mut Authenticator, challenge: &str| {
            let (client_data, auth_data, signature) = key.assert(rp, origin, challenge);
            Second::Passkey(Assertion {
                id: cred.id.clone(),
                client_data,
                auth_data,
                signature,
                challenge: challenge.into(),
                rp_id: rp.into(),
                origin: origin.into(),
            })
        };
        // the passkey instead of the code; the password still counts
        let Login::Ok(token) = auth.login_with(ip, "admin", "correct horse battery", assertion(&mut key, "c-1")).unwrap() else {
            panic!("login failed")
        };
        assert_eq!(auth.session(&token).as_deref(), Some("admin"));
        assert_eq!(auth.passkeys("admin")[0].sign_count, 1, "the counter is kept");
        assert_eq!(auth.passkeys("admin")[0].logins, 1, "and the console's own count of logins");
        assert!(auth.passkeys("admin")[0].last_used.is_some());
        assert_eq!(auth.login_with(ip, "admin", "wrong", assertion(&mut key, "c-2")).unwrap(), Login::Wrong);
        // a replayed answer (the counter didn't advance), and another account's key
        let (client_data, auth_data, signature) = key.assert(rp, origin, "c-3");
        let replay = Assertion {
            id: cred.id.clone(),
            client_data,
            auth_data,
            signature,
            challenge: "c-3".into(),
            rp_id: rp.into(),
            origin: origin.into(),
        };
        assert!(matches!(auth.login_with(ip, "admin", "correct horse battery", Second::Passkey(replay.clone())).unwrap(), Login::Ok(_)));
        assert_eq!(auth.login_with(ip, "admin", "correct horse battery", Second::Passkey(replay)).unwrap(), Login::Wrong, "replayed");
        assert_eq!(auth.login_with(ip, "alice", "correct horse battery", assertion(&mut key, "c-4")).unwrap(), Login::Wrong);
        // a passkey that checked its holder logs in on its own; a password given must be right
        assert!(matches!(auth.login_with(ip, "admin", "", assertion(&mut key, "c-5")).unwrap(), Login::Ok(_)), "the passkey alone");
        assert_eq!(
            auth.login_with(ip, "admin", "wrong", assertion(&mut key, "c-6")).unwrap(),
            Login::Wrong,
            "a wrong password still fails"
        );
        assert_eq!(auth.login_with(ip, "alice", "", assertion(&mut key, "c-7")).unwrap(), Login::Wrong, "not another account");
        // one that was only touched needs the password beside it, and that isn't a failure
        key.verifies = false;
        assert_eq!(auth.login_with(ip, "admin", "", assertion(&mut key, "c-8")).unwrap(), Login::NeedsPassword);
        assert!(matches!(auth.login_with(ip, "admin", "correct horse battery", assertion(&mut key, "c-9")).unwrap(), Login::Ok(_)));
        // no password and no passkey is nothing
        assert_eq!(auth.login(ip, "admin", "", &now_code(&secret)).unwrap(), Login::Wrong, "a code alone is not a login");
        // the code still works, and the key can be removed
        assert!(matches!(auth.login(ip, "", "correct horse battery", &now_code(&secret)).unwrap(), Login::Ok(_)));
        assert!(auth.remove_passkey("admin", &cred.id).unwrap() && !auth.remove_passkey("admin", &cred.id).unwrap());
        assert!(!dir.join("pw.passkeys").exists() && !crate::webauthn::file_for(&dir.join("pw")).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn now_code(secret: &[u8]) -> String {
        let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        format!("{:06}", crate::totp::code(secret, unix / crate::totp::STEP_SECS))
    }

    #[test]
    fn password_and_code() {
        let (auth, dir, secret) = setup("both", true);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(auth.login(ip, "", "correct horse battery", "000000").unwrap(), Login::Wrong);
        let code = now_code(&secret);
        assert_eq!(auth.login(ip, "", "wrong", &code).unwrap(), Login::Wrong, "the code alone isn't enough");
        let Login::Ok(token) = auth.login(ip, "", "correct horse battery", &code).unwrap() else { panic!("login failed") };
        assert_eq!(auth.session(&token).as_deref(), Some("admin"));
        assert!(auth.session("forged").is_none());
        assert_eq!(auth.login(ip, "", "correct horse battery", &code).unwrap(), Login::Wrong, "a code works once");
        auth.logout(&token);
        assert!(auth.session(&token).is_none());
        assert_eq!(cookie_value(&format!("a=b; {COOKIE}={token}; c=d")), Some(token.as_str()));
        assert_eq!(cookie_value("__Host-lgwx=1"), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn several_admins() {
        let (auth, dir, secret) = setup("admins", true);
        let ip: IpAddr = "192.0.2.5".parse().unwrap();
        std::fs::create_dir_all(dir.join("admins")).unwrap();
        std::fs::write(dir.join("admins/alice.password"), hash_password("alice's long password").unwrap()).unwrap();
        let alice_secret = b"alice-0123456789-abc".to_vec();
        // her password is set, her TOTP secret not yet: she can't log in, the console runs
        assert!(auth.check_files().is_ok());
        let alice = auth.account("alice").unwrap();
        assert!(auth.check_account(&alice).unwrap_err().to_string().contains("totp-setup --user alice"));
        assert_eq!(auth.login(ip, "alice", "alice's long password", &now_code(&alice_secret)).unwrap(), Login::Wrong);
        std::fs::write(dir.join("admins/alice.totp"), crate::totp::base32(&alice_secret)).unwrap();
        assert_eq!(auth.accounts().iter().map(|a| a.name.as_str()).collect::<Vec<_>>(), ["admin", "alice"]);

        // her code with the admin's password, the admin's code with hers: no
        assert_eq!(auth.login(ip, "alice", "correct horse battery", &now_code(&alice_secret)).unwrap(), Login::Wrong);
        assert_eq!(auth.login(ip, "alice", "alice's long password", &now_code(&secret)).unwrap(), Login::Wrong);
        let Login::Ok(t) = auth.login(ip, "alice", "alice's long password", &now_code(&alice_secret)).unwrap() else { panic!() };
        assert_eq!(auth.session(&t).as_deref(), Some("alice"));
        // each admin's codes are used up separately
        let Login::Ok(a) = auth.login(ip, "admin", "correct horse battery", &now_code(&secret)).unwrap() else { panic!() };
        assert_eq!(auth.session(&a).as_deref(), Some("admin"));

        // accounts that don't exist, or can't: refused alike
        for user in ["bob", "Alice", "../pw", "admin/../x", &"a".repeat(40)] {
            assert_eq!(
                auth.login("192.0.2.6".parse().unwrap(), user, "correct horse battery", &now_code(&secret)).unwrap(),
                Login::Wrong,
                "{user}"
            );
        }
        // her files removed: her session ends, the admin's stays
        std::fs::remove_file(dir.join("admins/alice.password")).unwrap();
        assert!(auth.session(&t).is_none());
        assert_eq!(auth.session(&a).as_deref(), Some("admin"));
        assert!(auth.account("admin2").is_some() && auth.account("2x").is_none() && auth.account("a.b").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sessions_and_last_login() {
        let (auth, dir, _) = setup("seen", false);
        let (a, b): (IpAddr, IpAddr) = ("192.0.2.7".parse().unwrap(), "192.0.2.8".parse().unwrap());
        let Login::Ok(first) = auth.login(a, "", "correct horse battery", "").unwrap() else { panic!() };
        assert_eq!(auth.about(&first).unwrap().1, LoginRecord::default(), "the first login since the start");
        assert_eq!(auth.login(b, "admin", "wrong", "").unwrap(), Login::Wrong);
        let Login::Ok(second) = auth.login(b, "", "correct horse battery", "").unwrap() else { panic!() };
        auth.set_agent(&second, "Firefox\n<b>");
        let (me, prev) = auth.about(&second).unwrap();
        assert_eq!((prev.ip, prev.failed_since), (Some(a), 1), "the login before, and the failure since");
        assert_eq!((me.ip, me.agent.as_str(), me.current), (b, "Firefox<b>", true));
        assert_eq!(auth.list(&second).len(), 2);
        assert_eq!(auth.end_others(&second), 1);
        assert!(auth.session(&first).is_none() && auth.session(&second).is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn account_lockout_from_anywhere() {
        let (auth, dir, _) = setup("account", false);
        let home: IpAddr = "192.0.2.10".parse().unwrap();
        assert!(matches!(auth.login(home, "admin", "correct horse battery", "").unwrap(), Login::Ok(_)), "the admin's own address");
        // a distributed guess: one failure per address, each below the address lockout
        for i in 0..MAX_ACCOUNT_FAILURES {
            let ip: IpAddr = format!("198.51.100.{i}").parse().unwrap();
            assert_eq!(auth.login(ip, "admin", "nope", "").unwrap(), Login::Wrong);
        }
        assert_eq!(auth.failures_lately(home, "admin"), (0, MAX_ACCOUNT_FAILURES, MAX_ACCOUNT_FAILURES));
        let fresh: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(matches!(auth.login(fresh, "admin", "correct horse battery", "").unwrap(), Login::Locked(_)), "locked for strangers");
        assert!(matches!(auth.login(home, "admin", "correct horse battery", "").unwrap(), Login::Ok(_)), "not for its own addresses");
        assert_eq!(auth.failures_lately(home, "admin").1, 0, "a login clears the account's count");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The address lockout resets its own count, not the proof of work's: a locked-out
    /// guesser's difficulty stays up.
    #[test]
    fn lockout_keeps_the_work_count() {
        let (auth, dir, _) = setup("workcount", false);
        let guesser: IpAddr = "198.51.100.200".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert_eq!(auth.login(guesser, "admin", "nope", "").unwrap(), Login::Wrong);
        }
        assert!(auth.locked(guesser, Instant::now()).is_some(), "locked out now");
        assert_eq!(auth.failures_lately(guesser, "admin").0, MAX_FAILURES, "still counted after the lockout");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The admin's authenticator opens an account locked by a guesser, from any address.
    #[test]
    fn the_code_opens_a_locked_account() {
        let (auth, dir, secret) = setup("codeopens", true);
        for i in 0..MAX_ACCOUNT_FAILURES {
            let ip: IpAddr = format!("198.51.100.{i}").parse().unwrap();
            assert_eq!(auth.login(ip, "admin", "nope", "000000").unwrap(), Login::Wrong);
        }
        let phone: IpAddr = "203.0.113.77".parse().unwrap();
        assert!(matches!(auth.login(phone, "admin", "correct horse battery", "000000").unwrap(), Login::Locked(_)), "a wrong code: locked");
        assert!(
            matches!(auth.login(phone, "admin", "correct horse battery", "").unwrap(), Login::Locked(_)),
            "no code: locked, without reading the files"
        );
        assert!(
            matches!(auth.login(phone, "admin", "correct horse battery", "x".repeat(6).as_str()).unwrap(), Login::Locked(_)),
            "not a code: locked"
        );
        assert!(
            matches!(auth.login(phone, "admin", "correct horse battery", &now_code(&secret)).unwrap(), Login::Ok(_)),
            "the right code: in"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lockout() {
        let (auth, dir, _) = setup("lockout", false);
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert_eq!(auth.login(ip, "admin", "nope", "").unwrap(), Login::Wrong);
        }
        assert!(matches!(auth.login(ip, "", "correct horse battery", "").unwrap(), Login::Locked(_)), "even the right password");
        let other: IpAddr = "192.0.2.3".parse().unwrap();
        assert!(matches!(auth.login(other, "admin", "correct horse battery", "").unwrap(), Login::Ok(_)), "other addresses aren't");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sessions_end() {
        let (mut auth, dir, _) = setup("end", false);
        auth.cfg.idle = Duration::from_millis(50);
        let ip: IpAddr = "192.0.2.4".parse().unwrap();
        let Login::Ok(token) = auth.login(ip, "", "correct horse battery", "").unwrap() else { panic!() };
        assert!(auth.session(&token).is_some());
        std::thread::sleep(Duration::from_millis(80));
        assert!(auth.session(&token).is_none(), "idle too long");
        for _ in 0..MAX_SESSIONS + 2 {
            auth.login(ip, "", "correct horse battery", "").unwrap();
        }
        assert!(auth.sessions.lock().unwrap().len() <= MAX_SESSIONS);
        let _ = std::fs::remove_dir_all(dir);
    }
}
