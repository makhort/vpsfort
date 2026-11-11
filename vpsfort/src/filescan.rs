//! Scans of changed files: what the integrity watches report new or changed (cron jobs and
//! the scripts they run, watched files, package files that differ from the package database,
//! set-uid programs, programs running from temporary or deleted files) is scanned with
//! ClamAV, YARA or both (`[antivirus] scan_changed`), right after it is reported.
//!
//! vpsfort's own memory is limited (its unit's `MemoryMax`), and clamscan needs over a
//! gigabyte for its signatures: scanners run as a transient systemd service of their own
//! (`systemd-run`, with `scan_memory` and `scan_timeout`), or through clamd, which keeps
//! its signatures loaded and reads the files vpsfort passes it (`clamdscan --fdpass`).
//!
//! File names come from wherever the files are: names with control characters are not
//! scanned (they would break the scanners' file lists), only regular files are (a link to
//! `/dev/zero` would never end), and results are matched back to the names vpsfort asked
//! about, never read from the scanners' output alone.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::time::Micros;

/// Which scanners look at changed files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scanners {
    #[default]
    None,
    Clamav,
    Yara,
    Both,
}

impl Scanners {
    pub fn clamav(self) -> bool {
        matches!(self, Scanners::Clamav | Scanners::Both)
    }

    pub fn yara(self) -> bool {
        matches!(self, Scanners::Yara | Scanners::Both)
    }
}

/// The settings in `[antivirus]` (`avscan::AvCfg`) for the scans of changed files.
pub type ScanCfg = crate::avscan::AvCfg;

impl ScanCfg {
    pub fn validate_scans(&self) -> Result<()> {
        let scanners = self.scan_changed;
        let mut paths = vec![&self.clamscan, &self.clamdscan, &self.clamd_socket, &self.yara];
        paths.extend(&self.yara_rules);
        if let Some(p) = paths.iter().find(|p| !p.is_absolute()) {
            bail!("[antivirus]: '{}' must be an absolute path", p.display());
        }
        if !self.systemd_run.as_os_str().is_empty() && !self.systemd_run.is_absolute() {
            bail!("[antivirus] systemd_run must be an absolute path, or empty");
        }
        if !self.clamd_config.as_os_str().is_empty() && !self.clamd_config.is_absolute() {
            bail!("[antivirus] clamd_config must be an absolute path, or empty");
        }
        if scanners.yara() && self.yara_rules.is_empty() {
            bail!(
                "[antivirus] scan_changed = \"{}\" needs yara_rules: rule files or directories of them",
                if scanners == Scanners::Both { "both" } else { "yara" }
            );
        }
        if self.yara_rules.len() > 1 && self.yara_rules.iter().any(|p| is_compiled(p)) {
            bail!("[antivirus] yara_rules: a compiled rules file (.yarc) must be the only entry");
        }
        let m = self.scan_memory.trim_end_matches(['K', 'M', 'G', 'T']);
        if m.is_empty() || !m.chars().all(|c| c.is_ascii_digit()) || self.scan_memory.len() - m.len() > 1 {
            bail!("[antivirus] scan_memory '{}' must look like 2G or 1500M", self.scan_memory);
        }
        if self.scan_timeout.0 < 60 || self.scan_max_mb == 0 {
            bail!("[antivirus] scan_timeout must be at least 1m, scan_max_mb at least 1");
        }
        Ok(())
    }
}

fn is_compiled(p: &Path) -> bool {
    p.extension().is_some_and(|e| e == "yarc")
}

/// A file to scan, and why it is scanned (the finding that named it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub path: String,
    pub why: String,
    /// The local user whose own file this is (`Finding::owner`): what the scan finds in it
    /// shares that user's alert budget.
    pub owner: Option<u32>,
}

/// What became of one file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileResult {
    pub path: String,
    pub why: String,
    /// `ClamAV: Unix.Trojan.Mirai-1`, `YARA: SUSP_ELF_Miner`.
    pub hits: Vec<String>,
    /// Why it wasn't scanned, or what a scanner said about this file (`Access denied`).
    pub note: Option<String>,
    /// [`Job::owner`].
    pub owner: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub started: Micros,
    pub finished: Micros,
    /// `ClamAV (clamd) and YARA (12 rule files)`.
    pub scanners: String,
    pub files: Vec<FileResult>,
    /// Scanners that failed as a whole (not installed, rules that don't compile, timeout).
    pub errors: Vec<String>,
}

impl ScanReport {
    pub fn infected(&self) -> impl Iterator<Item = &FileResult> {
        self.files.iter().filter(|f| !f.hits.is_empty())
    }
}

/// Whether `path` is one of the YARA rule files (`yara_rules`: files, or anything in those
/// directories). Rules hold malware fragments by design: ClamAV flags them, and YARA would
/// match its own rules' strings.
fn is_rule_file(path: &str, rules: &[PathBuf]) -> bool {
    rules.iter().any(|r| Path::new(path).starts_with(r))
}

/// Whether a file can be scanned: a regular file, not too large, with a name the scanners'
/// file lists can hold. `None`: it can.
fn unscannable(path: &str, max_bytes: u64) -> Option<String> {
    if path.chars().any(|c| c.is_control()) {
        return Some("not scanned: control characters in its name".into());
    }
    match std::fs::metadata(path) {
        Err(_) if running_program(path).is_some() => Some(GONE.into()),
        Err(_) => Some("not scanned: no longer there".into()),
        Ok(m) if !m.is_file() => Some("not scanned: not a regular file".into()),
        Ok(m) if m.len() > max_bytes => Some(format!("not scanned: larger than {} MB", max_bytes >> 20)),
        Ok(_) => None,
    }
}

const GONE: &str = "not scanned: the process has exited";

/// `/proc/<pid>/exe`, a program as it runs (the process watch names them): its pid.
fn running_program(path: &str) -> Option<u32> {
    path.strip_prefix("/proc/")?.strip_suffix("/exe")?.parse().ok()
}

/// Copies the program `path` (`/proc/<pid>/exe`) runs into `work`, for the scanners to read:
/// following that link takes ptrace access to the process, which vpsfort has (`CAP_SYS_PTRACE`)
/// and the scan sandbox hasn't (`CAP_DAC_READ_SEARCH` alone: yara's `could not open file`),
/// and the process may be gone by the time ClamAV is done. The copy's path, or why there is none.
fn snapshot(path: &str, pid: u32, work: &Path, max: u64) -> Result<(String, u64), String> {
    let copy = work.join(format!("file-scan-{pid}.bin"));
    let _ = std::fs::remove_file(&copy);
    let src = std::fs::File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => GONE.to_string(),
        _ => format!("not scanned: cannot read the running program: {e}"),
    })?;
    let cannot = |e: std::io::Error| format!("not scanned: cannot copy the running program to {}: {e}", copy.display());
    let mut dst = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&copy).map_err(cannot)?;
    let n = std::io::copy(&mut src.take(max.saturating_add(1)), &mut dst).map_err(cannot)?;
    if n > max {
        let _ = std::fs::remove_file(&copy);
        return Err(format!("{TOO_LARGE} {} MB", max >> 20));
    }
    Ok((copy.display().to_string(), n))
}

const TOO_LARGE: &str = "not scanned: larger than";
const COPIES_FULL: &str = "not scanned: this scan's copies of running programs are at their limit";
/// One scan's copies of running programs take at most this many times `scan_max_mb` in all:
/// any user can start a batch of programs from a temporary directory, each up to that size,
/// and the copies are on the disk vpsfort's state is on.
const COPIES_PER_SCAN: u64 = 4;

/// [`snapshot`] within what is left for this scan's copies (`room`, less the copy made).
fn snapshot_within(path: &str, pid: u32, work: &Path, max: u64, room: &mut u64) -> Result<String, String> {
    let limit = max.min(*room);
    match snapshot(path, pid, work, limit) {
        Ok((copy, size)) => {
            *room -= size;
            Ok(copy)
        }
        Err(why) if limit < max && why.starts_with(TOO_LARGE) => Err(COPIES_FULL.into()),
        Err(why) => Err(why),
    }
}

/// Removes the copies a scan left when vpsfort was stopped in the middle of it (one scan
/// runs at a time, so any there are stale).
fn remove_stale_copies(work: &Path) {
    let Ok(entries) = std::fs::read_dir(work) else { return };
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("file-scan-") && name.ends_with(".bin") {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The rule files of `yara_rules`: files as they are, directories' `.yar`/`.yara` files.
fn rule_files(rules: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for r in rules {
        if r.is_dir() {
            let mut found: Vec<PathBuf> = std::fs::read_dir(r)
                .map_err(|e| format!("YARA rules {}: {e}", r.display()))?
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "yar" || e == "yara"))
                .collect();
            found.sort();
            out.extend(found);
        } else if r.is_file() {
            out.push(r.clone());
        } else {
            return Err(format!("YARA rules {}: not there", r.display()));
        }
    }
    if out.is_empty() {
        return Err("no YARA rule files (.yar, .yara) in yara_rules".into());
    }
    Ok(out)
}

/// `program args` as a transient service of its own (outside vpsfort's memory limit), or
/// directly without `systemd_run`.
/// clamdscan's `--config-file`: `clamd_config` when set. Else, when clamdscan's own default
/// (`/etc/clamd.conf`; Debian's build reads `/etc/clamav/clamd.conf`) is absent and Fedora's
/// `/etc/clamd.d/scan.conf` is there, that one: Fedora's clamd reads it, its clamdscan isn't told.
fn clamd_config_arg(configured: &Path, exists: &dyn Fn(&Path) -> bool) -> Option<String> {
    if !configured.as_os_str().is_empty() {
        return Some(format!("--config-file={}", configured.display()));
    }
    const FEDORA: &str = "/etc/clamd.d/scan.conf";
    let default_there = ["/etc/clamd.conf", "/etc/clamav/clamd.conf"].iter().any(|p| exists(Path::new(p)));
    (!default_there && exists(Path::new(FEDORA))).then(|| format!("--config-file={FEDORA}"))
}

/// The transient scan service's sandbox, as vpsfort-avscan.service's: the scanners parse
/// hostile files as root (a file any user planted where the integrity watches look), so a
/// hole in ClamAV's or YARA's parsers must not give more than reading. Everything is
/// read-only but the cache directory (archives are unpacked there: `TMPDIR`), there is no
/// network, no new privileges, and reading past file modes is the only capability kept.
const SCAN_SANDBOX: &[&str] = &[
    "Nice=10",
    "IOSchedulingClass=idle",
    "CacheDirectory=vpsfort-avscan",
    "ProtectSystem=strict",
    "ProtectHome=read-only",
    "PrivateNetwork=yes",
    "RestrictAddressFamilies=AF_UNIX",
    "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
    "NoNewPrivileges=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "SystemCallErrorNumber=EPERM",
];

fn command(cfg: &ScanCfg, program: &Path, args: &[String]) -> Command {
    if cfg.systemd_run.as_os_str().is_empty() {
        let mut c = Command::new(program);
        c.args(args);
        return c;
    }
    let mut c = Command::new(&cfg.systemd_run);
    c.args(["--quiet", "--wait", "--pipe", "--collect", "--description=vpsfort scan of changed files"]);
    let limits = [format!("MemoryMax={}", cfg.scan_memory), format!("RuntimeMaxSec={}", cfg.scan_timeout.0)];
    for p in limits.iter().map(String::as_str).chain(SCAN_SANDBOX.iter().copied()) {
        c.args(["--property", p]);
    }
    c.arg("--setenv=TMPDIR=/var/cache/vpsfort-avscan");
    c.arg("--").arg(program).args(args);
    c
}

/// The file a scanner's output line names, of those asked about: the longest name that
/// ends where the scanner's own text begins (`path: Signature FOUND`, `Rule path`).
fn which(names: &[String], f: impl Fn(&str) -> bool) -> Option<&String> {
    names.iter().filter(|n| f(n)).max_by_key(|n| n.len())
}

/// (file, what a scanner said about it) for each line naming a file asked about.
type Said = Vec<(String, String)>;

/// clamscan's and clamdscan's `path: Signature FOUND` and `path: what ERROR` lines.
fn read_clamav(out: &str, names: &[String]) -> (Said, Said) {
    let (mut hits, mut notes) = (Vec::new(), Vec::new());
    for line in out.lines() {
        for (suffix, list) in [(" FOUND", &mut hits), (" ERROR", &mut notes)] {
            let Some(rest) = line.strip_suffix(suffix) else { continue };
            if let Some(n) = which(names, |n| rest.strip_prefix(n).is_some_and(|t| t.starts_with(": "))) {
                list.push((n.clone(), crate::event::clean(&rest[n.len() + 2..], 120)));
            }
        }
    }
    (hits, notes)
}

/// yara's `Rule path` lines (a rule name has no spaces) and `error scanning path: why`.
fn read_yara(stdout: &str, stderr: &str, names: &[String]) -> (Said, Said) {
    let mut hits = Vec::new();
    for line in stdout.lines() {
        let found = which(names, |n| {
            line.strip_suffix(n).and_then(|r| r.strip_suffix(' ')).is_some_and(|rule| !rule.is_empty() && !rule.contains(' '))
        });
        if let Some(n) = found {
            hits.push((n.clone(), crate::event::clean(&line[..line.len() - n.len() - 1], 120)));
        }
    }
    let mut notes = Vec::new();
    for line in stderr.lines() {
        let Some(rest) = line.strip_prefix("error scanning ") else { continue };
        if let Some(n) = which(names, |n| rest.strip_prefix(n).is_some_and(|t| t.starts_with(": "))) {
            notes.push((n.clone(), crate::event::clean(&rest[n.len() + 2..], 120)));
        }
    }
    (hits, notes)
}

/// The scanners' names for the files, where they aren't the files' own: a running
/// program's copy (`snapshot`) by the `/proc/<pid>/exe` it stands for.
type Copies = BTreeMap<String, String>;

/// The report's entry for the file a scanner's line names.
fn file_of<'a>(report: &'a mut ScanReport, copies: &Copies, name: &str) -> Option<&'a mut FileResult> {
    let own = copies.get(name).map_or(name, String::as_str);
    report.files.iter_mut().find(|f| f.path == own)
}

/// Checks the files again right before a scanner reads them, and writes its list of the
/// ones still scannable. A file swapped meanwhile for a link to a device or a pipe (whose
/// reads never end) gets the reason it isn't scanned instead. False: nothing to scan.
fn ready(report: &mut ScanReport, copies: &Copies, names: &mut Vec<String>, max: u64, list: &Path) -> bool {
    names.retain(|n| match unscannable(n, max) {
        None => true,
        Some(note) => {
            if let Some(f) = file_of(report, copies, n) {
                f.note = Some(note);
            }
            false
        }
    });
    if names.is_empty() {
        return false;
    }
    // the names of what changed on this host: root's alone
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(list)
        .and_then(|mut f| std::io::Write::write_all(&mut f, (names.join("\n") + "\n").as_bytes()));
    if let Err(e) = written {
        report.errors.push(format!("cannot write the list of files to scan ({}): {e}", list.display()));
        names.clear();
    }
    !names.is_empty()
}

/// Scans `jobs` with the configured scanners. `work` is a directory for the file list.
pub fn scan(cfg: &ScanCfg, jobs: Vec<Job>, work: &Path, now: &dyn Fn() -> Micros) -> ScanReport {
    let scanners = cfg.scan_changed;
    let mut report = ScanReport { started: now(), ..Default::default() };
    let max = cfg.scan_max_mb.saturating_mul(1 << 20);
    let mut names = Vec::new();
    let mut copies = Copies::new();
    remove_stale_copies(work);
    let mut room = max.saturating_mul(COPIES_PER_SCAN);
    for j in jobs {
        if report.files.iter().any(|f| f.path == j.path) {
            continue;
        }
        let mut note = if is_rule_file(&j.path, &cfg.yara_rules) {
            Some("not scanned: a YARA rule file (malware patterns by design)".into())
        } else {
            unscannable(&j.path, max)
        };
        let mut name = j.path.clone();
        if let Some(pid) = running_program(&j.path).filter(|_| note.is_none()) {
            match snapshot_within(&j.path, pid, work, max, &mut room) {
                Ok(copy) => {
                    copies.insert(copy.clone(), j.path.clone());
                    name = copy;
                }
                Err(why) => note = Some(why),
            }
        }
        if note.is_none() {
            names.push(name);
        }
        report.files.push(FileResult { path: j.path, why: j.why, hits: vec![], note, owner: j.owner });
    }
    let list = work.join("file-scan.list");
    let limit = Duration::from_secs(cfg.scan_timeout.0 + 60);
    let mut used = Vec::new();
    let record = |report: &mut ScanReport, scanner: &str, hits: Said, notes: Said| {
        for (path, what) in hits {
            if let Some(f) = file_of(report, &copies, &path) {
                f.hits.push(format!("{scanner}: {what}"));
            }
        }
        for (path, what) in notes {
            if let Some(f) = file_of(report, &copies, &path) {
                f.note.get_or_insert(format!("{scanner}: {what}"));
            }
        }
    };
    if scanners.clamav() && ready(&mut report, &copies, &mut names, max, &list) {
        let list_arg = format!("--file-list={}", list.display());
        let (what, cmd) = if cfg.clamd_socket.exists() {
            // clamd reads the files vpsfort opens for it: it runs as its own user
            let mut args = ["--fdpass", "--no-summary", "--infected", &list_arg].map(String::from).to_vec();
            args.extend(clamd_config_arg(&cfg.clamd_config, &|p| p.exists()));
            let mut c = Command::new(&cfg.clamdscan);
            c.args(args);
            ("ClamAV (clamd)", c)
        } else {
            let max_arg = |k: &str| format!("--{k}={}M", cfg.scan_max_mb);
            let args = vec!["--no-summary".into(), "--infected".into(), list_arg.clone(), max_arg("max-filesize"), max_arg("max-scansize")];
            ("ClamAV (clamscan)", command(cfg, &cfg.clamscan, &args))
        };
        used.push(what.to_string());
        match crate::proc::run(cmd, None, limit) {
            // 0 clean, 1 found, 2 some files could not be read: the lines say which
            Ok(o) => {
                let out = String::from_utf8_lossy(&o.stdout).into_owned();
                let (hits, notes) = read_clamav(&out, &names);
                let failed = !matches!(o.status.code(), Some(0 | 1)) && hits.is_empty() && notes.is_empty();
                record(&mut report, "ClamAV", hits, notes);
                if failed {
                    report.errors.push(format!("{what} failed ({}): {}", o.status, crate::event::clean(&o.complaint(), 300)));
                }
            }
            Err(e) => report.errors.push(format!("{what}: {e}")),
        }
    }
    // ClamAV may have taken minutes: what YARA reads is checked again
    if scanners.yara() && ready(&mut report, &copies, &mut names, max, &list) {
        match rule_files(&cfg.yara_rules) {
            Err(e) => report.errors.push(e),
            Ok(rules) => {
                let mut args: Vec<String> = vec!["--no-warnings".into(), "--timeout=120".into(), "--scan-list".into()];
                if rules.len() == 1 && is_compiled(&rules[0]) {
                    args.push("--compiled-rules".into());
                    args.push(rules[0].display().to_string());
                } else {
                    // a namespace each: the same rule name in two files is no error
                    args.extend(rules.iter().enumerate().map(|(i, r)| format!("r{i}:{}", r.display())));
                }
                args.push(list.display().to_string());
                let what = format!("YARA ({} rule {})", rules.len(), if rules.len() == 1 { "file" } else { "files" });
                used.push(what.clone());
                match crate::proc::run(command(cfg, &cfg.yara, &args), None, limit) {
                    Ok(o) => {
                        let (out, err) = (String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned());
                        let (hits, notes) = read_yara(&out, &err, &names);
                        let failed = !o.status.success() && hits.is_empty() && notes.is_empty();
                        record(&mut report, "YARA", hits, notes);
                        if failed {
                            report.errors.push(format!("{what} failed ({}): {}", o.status, crate::event::clean(&o.complaint(), 300)));
                        }
                    }
                    Err(e) => report.errors.push(format!("{what}: {e}")),
                }
            }
        }
    }
    let _ = std::fs::remove_file(&list);
    for copy in copies.keys() {
        let _ = std::fs::remove_file(copy);
    }
    report.scanners = used.join(" and ");
    report.finished = now();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Dur;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn output_is_matched_to_the_files_asked_about() {
        let names = vec!["/srv/a b.php".to_string(), "/srv/x: y FOUND".to_string(), "/tmp/m".to_string()];
        let out = "/srv/a b.php: Php.Webshell-1 FOUND\n/srv/x: y FOUND: Eicar FOUND\n/other: Evil FOUND\n/tmp/m: Access denied. ERROR\n";
        let (hits, notes) = read_clamav(out, &names);
        assert_eq!(
            hits,
            vec![("/srv/a b.php".into(), "Php.Webshell-1".into()), ("/srv/x: y FOUND".into(), "Eicar".into())],
            "a name holding ': ... FOUND' is matched whole; a file not asked about is left out"
        );
        assert_eq!(notes, vec![("/tmp/m".into(), "Access denied.".into())]);
        let (hits, notes) = read_yara(
            "SUSP_Miner /tmp/m\nWebshell_Generic /srv/a b.php\nnot a rule /tmp/m\nRule /elsewhere\n",
            "error scanning /srv/x: y FOUND: could not open file\nwarning: x\n",
            &names,
        );
        assert_eq!(hits, vec![("/tmp/m".into(), "SUSP_Miner".into()), ("/srv/a b.php".into(), "Webshell_Generic".into())]);
        assert_eq!(notes, vec![("/srv/x: y FOUND".into(), "could not open file".into())]);
    }

    #[test]
    fn only_regular_files_with_plain_names() {
        let dir = std::env::temp_dir().join(format!("vpsfort-scan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("f");
        std::fs::write(&f, "x".repeat(2 << 20)).unwrap();
        let link = dir.join("zero");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        assert_eq!(unscannable(f.to_str().unwrap(), 4 << 20), None);
        assert!(unscannable(f.to_str().unwrap(), 1 << 20).unwrap().contains("larger than 1 MB"));
        assert!(unscannable(link.to_str().unwrap(), 4 << 20).unwrap().contains("not a regular file"), "a link to a device");
        // devices whose reads never end, by their names or through links; a named pipe
        for dev in ["/dev/random", "/dev/urandom"] {
            assert!(unscannable(dev, 4 << 20).unwrap().contains("not a regular file"), "{dev}");
            let l = dir.join(dev.trim_start_matches("/dev/"));
            std::os::unix::fs::symlink(dev, &l).unwrap();
            assert!(unscannable(l.to_str().unwrap(), 4 << 20).unwrap().contains("not a regular file"), "a link to {dev}");
        }
        let fifo = dir.join("pipe");
        assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        assert!(unscannable(fifo.to_str().unwrap(), 4 << 20).unwrap().contains("not a regular file"), "a named pipe");
        assert!(unscannable(dir.to_str().unwrap(), 4 << 20).unwrap().contains("not a regular file"));
        assert!(unscannable("/srv/a\nb", 4 << 20).unwrap().contains("control characters"));
        assert!(unscannable("/nonexistent/x", 4 << 20).unwrap().contains("no longer there"));
        assert_eq!(unscannable("/proc/4000001/exe", 4 << 20).as_deref(), Some(GONE), "a pid that is no more");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A program as it runs is read by vpsfort and copied for the scanners, which can't follow
    /// `/proc/<pid>/exe` from their sandbox (no ptrace access), and whose turn may come after
    /// the process is gone.
    #[test]
    fn running_programs_are_copied_for_the_scanners() {
        assert_eq!(running_program("/proc/24869/exe"), Some(24869));
        assert_eq!(running_program("/proc/self/exe"), None, "the pid is what names a process");
        assert_eq!(running_program("/proc/1/exe/x"), None);
        assert_eq!(running_program("/tmp/proc/1/exe"), None);
        let dir = std::env::temp_dir().join(format!("vpsfort-scan4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("program");
        std::fs::write(&program, "ELF program").unwrap();
        let (copy, size) = snapshot(program.to_str().unwrap(), 7, &dir, 1 << 20).unwrap();
        assert_eq!(size, 11);
        assert_eq!(copy, dir.join("file-scan-7.bin").display().to_string());
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), "ELF program");
        assert_eq!(std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(snapshot(program.to_str().unwrap(), 7, &dir, 4).unwrap_err().contains("larger than 0 MB"));
        assert!(!Path::new(&copy).exists(), "an oversized copy is removed");
        assert_eq!(snapshot(dir.join("gone").to_str().unwrap(), 7, &dir, 1 << 20).unwrap_err(), GONE);
        // one scan's copies have a size in all: a batch of programs started for it can't
        // fill the disk the state is on
        let mut room = 15;
        let first = snapshot_within(program.to_str().unwrap(), 8, &dir, 1 << 20, &mut room).unwrap();
        assert_eq!(room, 4);
        assert_eq!(snapshot_within(program.to_str().unwrap(), 9, &dir, 1 << 20, &mut room).unwrap_err(), COPIES_FULL);
        assert!(Path::new(&first).exists() && !dir.join("file-scan-9.bin").exists());
        assert!(snapshot_within(program.to_str().unwrap(), 9, &dir, 4, &mut 1000).unwrap_err().starts_with(TOO_LARGE), "its own size");
        // a copy left by a scan vpsfort was stopped in goes at the next scan
        let r = scan(&ScanCfg::default(), vec![], &dir, &|| 7);
        assert!(r.errors.is_empty() && !Path::new(&first).exists(), "{:?}", r.errors);
        assert!(program.exists(), "only the copies");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// This test's own program through the whole scan: the scanners' list names the copy,
    /// the report names `/proc/<pid>/exe`, and the copy is gone afterwards.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_running_program_is_scanned_from_its_copy() {
        let dir = std::env::temp_dir().join(format!("vpsfort-scan5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let clamscan = script(
            &dir,
            "clamscan",
            r#"for a; do case $a in --file-list=*) list=${a#--file-list=};; esac; done
cp "$list" "$(dirname "$0")/clamscan.list"
while IFS= read -r f; do head -c 4 "$f" | grep -q ELF && echo "$f: Unix.Self FOUND"; done < "$list"; exit 1"#,
        );
        let cfg = ScanCfg {
            scan_changed: Scanners::Clamav,
            clamscan,
            clamd_socket: dir.join("no-clamd"),
            systemd_run: PathBuf::new(),
            // this program is the test binary, which carries its debug information on Linux:
            // well over the 100 MB a scan takes by default
            scan_max_mb: 4096,
            ..Default::default()
        };
        let me = format!("/proc/{}/exe", std::process::id());
        let job = |p: &str| Job { path: p.into(), why: "procwatch".into(), owner: None };
        let r = scan(&cfg, vec![job(&me), job("/proc/4000001/exe")], &dir, &|| 7);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(r.files[0].note, None, "the program was copied and scanned");
        let copy = dir.join(format!("file-scan-{}.bin", std::process::id()));
        assert_eq!(std::fs::read_to_string(dir.join("clamscan.list")).unwrap(), format!("{}\n", copy.display()));
        assert_eq!((r.files[0].path.as_str(), &r.files[0].hits[..]), (me.as_str(), &["ClamAV: Unix.Self".to_string()][..]));
        assert_eq!((r.files[1].path.as_str(), r.files[1].note.as_deref()), ("/proc/4000001/exe", Some(GONE)));
        assert!(!copy.exists(), "the copy is removed after the scan");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// The scanners as stand-ins: clamscan and yara read the file list they are given and
    /// flag files holding EVIL; systemd-run records its options and runs the program.
    #[test]
    fn both_scanners_through_systemd_run() {
        let dir = std::env::temp_dir().join(format!("vpsfort-scan2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let clamscan = script(
            &bin,
            "clamscan",
            r#"for a; do case $a in --file-list=*) list=${a#--file-list=};; esac; done
cp "$list" "$(dirname "$0")/clamscan.list"
ls -l "$list" | cut -c1-10 > "$(dirname "$0")/list.mode"
while IFS= read -r f; do grep -q EVIL "$f" && echo "$f: Unix.Trojan.Evil FOUND"; done < "$list"; exit 1"#,
        );
        let yara = script(
            &bin,
            "yara",
            r#"for a; do last=$a; done; echo "$@" > "$(dirname "$0")/yara.args"
while IFS= read -r f; do grep -q EVIL "$f" && echo "Evil_Rule $f"; done < "$last"; exit 0"#,
        );
        let run = script(
            &bin,
            "systemd-run",
            r#"echo "$@" > "$(dirname "$0")/run.args"; while [ "$1" != "--" ]; do shift; done; shift; exec "$@""#,
        );
        std::fs::write(dir.join("rules/a.yar"), "rule a { condition: false }").unwrap();
        std::fs::write(dir.join("rules/b.yara"), "rule b { condition: false }").unwrap();
        let (bad, good, gone) = (dir.join("evil file"), dir.join("good"), dir.join("gone"));
        std::fs::write(&bad, "EVIL").unwrap();
        std::fs::write(&good, "fine").unwrap();
        let cfg = ScanCfg {
            clamscan,
            clamd_socket: dir.join("no-clamd"),
            yara,
            yara_rules: vec![dir.join("rules")],
            systemd_run: run,
            scan_changed: Scanners::Both,
            ..Default::default()
        };
        cfg.validate_scans().unwrap();
        let job = |p: &Path| Job { path: p.display().to_string(), why: "cron: new file".into(), owner: None };
        let rule = dir.join("rules/a.yar");
        let r = scan(&cfg, vec![job(&bad), job(&good), job(&gone), job(&bad), job(&rule)], &dir, &|| 7);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(r.scanners, "ClamAV (clamscan) and YARA (2 rule files)");
        assert_eq!(r.files.len(), 4, "each file once");
        assert_eq!(r.files[3].note.as_deref(), Some("not scanned: a YARA rule file (malware patterns by design)"));
        assert!(!std::fs::read_to_string(bin.join("clamscan.list")).unwrap().contains("a.yar"), "the rules aren't scanned");
        assert_eq!(r.files[0].hits, vec!["ClamAV: Unix.Trojan.Evil", "YARA: Evil_Rule"]);
        assert!(r.files[1].hits.is_empty() && r.files[1].note.is_none());
        assert_eq!(r.files[2].note.as_deref(), Some("not scanned: no longer there"));
        assert_eq!(r.infected().count(), 1);
        let run_args = std::fs::read_to_string(bin.join("run.args")).unwrap();
        assert!(run_args.contains("--property MemoryMax=2G") && run_args.contains("--property RuntimeMaxSec=1800"), "{run_args}");
        for p in ["ProtectSystem=strict", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH", "PrivateNetwork=yes", "NoNewPrivileges=yes"] {
            assert!(run_args.contains(&format!("--property {p}")), "{p}: {run_args}");
        }
        assert!(run_args.contains("--setenv=TMPDIR=/var/cache/vpsfort-avscan"), "{run_args}");
        let yara_args = std::fs::read_to_string(bin.join("yara.args")).unwrap();
        assert!(yara_args.contains("--scan-list r0:") && yara_args.contains("rules/a.yar r1:"), "{yara_args}");
        assert!(!dir.join("file-scan.list").exists(), "the list is removed");
        assert_eq!(std::fs::read_to_string(bin.join("list.mode")).unwrap().trim(), "-rw-------", "it names what changed: root's alone");

        // YARA only, with rules that don't compile: the scanner's error, no hits
        let broken = ScanCfg {
            yara: script(&bin, "yara-broken", "echo 'error: syntax error in rule' >&2; exit 1"),
            scan_changed: Scanners::Yara,
            ..cfg.clone()
        };
        let r = scan(&broken, vec![job(&bad)], &dir, &|| 7);
        assert_eq!((r.infected().count(), r.scanners.as_str()), (0, "YARA (2 rule files)"));
        assert!(r.errors[0].contains("syntax error in rule"), "{:?}", r.errors);
        // clamd, when its socket is there
        std::fs::write(dir.join("clamd.ctl"), "").unwrap();
        let clamd = ScanCfg {
            clamdscan: script(&bin, "clamdscan", r#"echo "$@" > "$(dirname "$0")/clamd.args"; exit 0"#),
            clamd_socket: dir.join("clamd.ctl"),
            clamd_config: dir.join("clamd.conf"),
            scan_changed: Scanners::Clamav,
            ..cfg.clone()
        };
        let r = scan(&clamd, vec![job(&good)], &dir, &|| 7);
        assert_eq!((r.scanners.as_str(), r.errors.len()), ("ClamAV (clamd)", 0));
        let clamd_args = std::fs::read_to_string(bin.join("clamd.args")).unwrap();
        assert!(clamd_args.starts_with("--fdpass"), "{clamd_args}");
        assert!(clamd_args.contains(&format!("--config-file={}", dir.join("clamd.conf").display())), "{clamd_args}");
        // a scanner that isn't there
        let missing = ScanCfg { clamdscan: dir.join("nope"), ..clamd };
        let r = scan(&missing, vec![job(&good)], &dir, &|| 7);
        assert!(r.errors[0].starts_with("ClamAV (clamd): running"), "{:?}", r.errors);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Fedora's clamdscan isn't told where its clamd's configuration is; Debian's is.
    #[test]
    fn clamd_config_is_fedoras_unless_set_or_default_present() {
        let fedora = |p: &Path| p == Path::new("/etc/clamd.d/scan.conf");
        let debian = |p: &Path| p == Path::new("/etc/clamav/clamd.conf");
        let both = |p: &Path| fedora(p) || p == Path::new("/etc/clamd.conf");
        let none = |_: &Path| false;
        assert_eq!(clamd_config_arg(Path::new(""), &fedora).as_deref(), Some("--config-file=/etc/clamd.d/scan.conf"));
        assert_eq!(clamd_config_arg(Path::new(""), &debian), None);
        assert_eq!(clamd_config_arg(Path::new(""), &both), None, "an admin's /etc/clamd.conf is clamdscan's default");
        assert_eq!(clamd_config_arg(Path::new(""), &none), None);
        assert_eq!(clamd_config_arg(Path::new("/srv/clamd.conf"), &none).as_deref(), Some("--config-file=/srv/clamd.conf"));
        let relative = ScanCfg { clamd_config: "clamd.conf".into(), ..Default::default() };
        assert!(relative.validate_scans().unwrap_err().to_string().contains("clamd_config"));
    }

    /// A file swapped for a link to /dev/urandom while ClamAV runs isn't handed to YARA.
    #[test]
    fn files_are_checked_again_before_each_scanner() {
        let dir = std::env::temp_dir().join(format!("vpsfort-scan3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        let (swapped, good) = (dir.join("swapped"), dir.join("good"));
        std::fs::write(&swapped, "x").unwrap();
        std::fs::write(&good, "y").unwrap();
        std::fs::write(dir.join("rules/a.yar"), "rule a { condition: false }").unwrap();
        let clamscan = script(&dir, "clamscan", &format!("rm -f '{0}'; ln -s /dev/urandom '{0}'; exit 0", swapped.display()));
        // yara only copies its list: reading /dev/urandom would never end
        let yara = script(&dir, "yara", r#"for a; do last=$a; done; cp "$last" "$(dirname "$0")/yara.list"; exit 0"#);
        let cfg = ScanCfg {
            scan_changed: Scanners::Both,
            clamscan,
            clamd_socket: dir.join("no-clamd"),
            yara,
            yara_rules: vec![dir.join("rules")],
            systemd_run: PathBuf::new(),
            ..Default::default()
        };
        let job = |p: &Path| Job { path: p.display().to_string(), why: "cron".into(), owner: None };
        let r = scan(&cfg, vec![job(&swapped), job(&good)], &dir, &|| 7);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(
            std::fs::read_to_string(dir.join("yara.list")).unwrap(),
            format!("{}\n", good.display()),
            "YARA gets the good file only"
        );
        assert_eq!(r.files[0].note.as_deref(), Some("not scanned: not a regular file"), "the swapped one says why");
        assert_eq!(r.files[1].note, None);
        // all swapped: YARA isn't started at all
        std::fs::remove_file(dir.join("yara.list")).unwrap();
        std::fs::remove_file(&swapped).unwrap();
        std::fs::write(&swapped, "x").unwrap();
        let r = scan(&cfg, vec![job(&swapped)], &dir, &|| 7);
        assert!(!dir.join("yara.list").exists() && r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(r.scanners, "ClamAV (clamscan)");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validation() {
        let with = |scan_changed: Scanners, yara_rules: Vec<&str>| ScanCfg {
            scan_changed,
            yara_rules: yara_rules.into_iter().map(PathBuf::from).collect(),
            ..Default::default()
        };
        let ok = with(Scanners::Both, vec!["/etc/vpsfort/yara"]);
        ok.validate_scans().unwrap();
        assert!(with(Scanners::Yara, vec![]).validate_scans().unwrap_err().to_string().contains("needs yara_rules"));
        with(Scanners::Clamav, vec![]).validate_scans().unwrap();
        with(Scanners::None, vec![]).validate_scans().unwrap();
        let bad = |c: ScanCfg| c.validate_scans().unwrap_err().to_string();
        assert!(bad(with(Scanners::Both, vec!["rules"])).contains("absolute"));
        assert!(bad(with(Scanners::Both, vec!["/r/a.yarc", "/r/b.yar"])).contains("only entry"));
        assert!(bad(ScanCfg { scan_memory: "lots".into(), ..ok.clone() }).contains("scan_memory"));
        assert!(bad(ScanCfg { scan_memory: "2GG".into(), ..ok.clone() }).contains("scan_memory"));
        assert!(bad(ScanCfg { scan_timeout: Dur(5), ..ok.clone() }).contains("scan_timeout"));
        ScanCfg { systemd_run: PathBuf::new(), ..ok }.validate_scans().unwrap();
    }
}
