//! A small kernel-hardening audit (`[sysctl_audit]`): the sysctls that matter for a server
//! exposed to the internet, read from `/proc/sys` hourly and checked against good practice,
//! in the SSH audit's style. The first reading tells everything; then a new or worse problem
//! is an alert with the values that changed, a value that weakens without a new problem is
//! an info message, fixed problems are told, and open high problems are reminded weekly. A
//! tenth of what Lynis checks, with no benchmark or score: the handful of settings an intruder
//! or a careless tool changes, and the ones that leave a kernel open to a local user.
//!
//! The value read is only this boot's: the sysctl.d files are read too, as systemd-sysctl
//! reads them, for what the next boot sets. A good value the files set back to a bad one
//! (Ubuntu's `kernel.sysrq = 176`), a line they skip (a pasted `sysctl -w` command), and
//! apport resetting `fs.suid_dumpable` at its start are problems of their own; the
//! `key = value` lines that keep every watched sysctl are what `vpsfort sysctl-audit --conf`
//! prints.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cronwatch::Finding;
use crate::engine::Severity;
use crate::sshaudit::Issue;
use crate::time::{self, Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SysctlCfg {
    pub enabled: bool,
    pub interval: Dur,
    /// Problems never reported, by id (`vpsfort sysctl-audit` shows them).
    pub ignore: Vec<String>,
    /// High problems still open are reminded this often ("0s": only in the digest).
    pub remind: Dur,
    /// `/proc/sys`.
    pub proc_sys: PathBuf,
    /// `/sys/class/net`: a VPN, container or bridge interface there makes forwarding expected.
    pub net_class: PathBuf,
    /// The sysctl.d directories in systemd-sysctl's order (a file in an earlier one hides the
    /// later ones' of the same name), read for what the next boot sets.
    pub sysctl_d: Vec<PathBuf>,
    /// Read last by `sysctl --system` and OpenRC; by systemd only through a link in sysctl.d.
    pub sysctl_conf: PathBuf,
}

impl Default for SysctlCfg {
    fn default() -> Self {
        SysctlCfg {
            enabled: true,
            interval: Dur(3600),
            ignore: vec![],
            remind: Dur(7 * 86_400),
            proc_sys: "/proc/sys".into(),
            net_class: "/sys/class/net".into(),
            sysctl_d: ["/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            sysctl_conf: "/etc/sysctl.conf".into(),
        }
    }
}

/// Where `vpsfort sysctl-audit` keeps a setting: late in the order (after the distribution's
/// 10-* and systemd's 50-default.conf), before 99-sysctl.conf.
pub const HARDENING_CONF: &str = "/etc/sysctl.d/90-hardening.conf";
const HARDENING_NAME: &str = "90-hardening.conf";
/// sysctl.d files read at most (per directory and in all), and bytes of each.
const MAX_FILES: usize = 256;
const MAX_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SysctlReport {
    pub read: Micros,
    /// The host forwards on purpose (a VPN, container or bridge interface exists).
    #[serde(default)]
    pub router: bool,
    #[serde(default)]
    pub issues: Vec<Issue>,
    /// The watched sysctls as read (missing ones left out), for reporting changes.
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    #[serde(default)]
    pub errors: Vec<String>,
    /// The `key = value` lines for /etc/sysctl.d/90-hardening.conf that keep the watched
    /// sysctls at good values after a reboot (`vpsfort sysctl-audit --conf`): each one no
    /// sysctl.d file keeps, at its value now when that is good.
    #[serde(default)]
    pub keep: BTreeMap<String, String>,
    /// Where such a line can't help: a file read after it sets the key, or apport resets it.
    #[serde(default)]
    pub keep_notes: Vec<String>,
}

impl SysctlReport {
    fn count(&self, s: Severity) -> usize {
        self.issues.iter().filter(|i| i.severity == s).count()
    }

    /// One line for the dashboard, `status` and the digest.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        for (s, one) in [(Severity::High, "high"), (Severity::Warning, "warning"), (Severity::Info, "note")] {
            match self.count(s) {
                0 => {}
                1 => parts.push(format!("1 {one}")),
                n => parts.push(format!("{n} {one}s")),
            }
        }
        let found = if parts.is_empty() { "no problems".to_string() } else { parts.join(", ") };
        let role = if self.router { "router" } else { "host" };
        format!("{} sysctls ({role}): {found}", self.settings.len())
    }

    /// The problems to act on (high and warnings), one line each, for the digest.
    pub fn concerns(&self) -> Vec<String> {
        self.issues.iter().filter(|i| i.severity >= Severity::Warning).map(|i| format!("sysctl: {}", i.message)).collect()
    }

    pub fn worst(&self) -> Option<Severity> {
        self.issues.iter().map(|i| i.severity).max()
    }
}

/// What a sysctl should be: `Min(n)` at least n, `Exactly(n)`, `Zero` (0 unless the host
/// routes, then a note).
#[derive(Clone, Copy)]
enum Want {
    Min(i64),
    Exactly(i64),
    ZeroUnlessRouter,
}

impl Want {
    fn value(self) -> i64 {
        match self {
            Want::Min(n) | Want::Exactly(n) => n,
            Want::ZeroUnlessRouter => 0,
        }
    }

    fn passes(self, n: i64) -> bool {
        match self {
            Want::Min(m) => n >= m,
            Want::Exactly(m) => n == m,
            Want::ZeroUnlessRouter => n == 0,
        }
    }
}

struct Check {
    key: &'static str,
    want: Want,
    severity: Severity,
    /// Why it matters, in one clause.
    why: &'static str,
}

const CHECKS: &[Check] = &[
    Check {
        key: "net.ipv4.ip_forward",
        want: Want::ZeroUnlessRouter,
        severity: Severity::Warning,
        why: "the host forwards IPv4 packets between its interfaces",
    },
    Check {
        key: "net.ipv6.conf.all.forwarding",
        want: Want::ZeroUnlessRouter,
        severity: Severity::Warning,
        why: "the host forwards IPv6 packets between its interfaces",
    },
    Check {
        key: "net.ipv4.conf.all.accept_redirects",
        want: Want::Exactly(0),
        severity: Severity::Warning,
        why: "ICMP redirects can rewrite the routing table",
    },
    Check {
        key: "net.ipv4.conf.default.accept_redirects",
        want: Want::Exactly(0),
        severity: Severity::Warning,
        why: "ICMP redirects can rewrite the routing table (new interfaces)",
    },
    Check {
        key: "net.ipv6.conf.all.accept_redirects",
        want: Want::Exactly(0),
        severity: Severity::Warning,
        why: "ICMPv6 redirects can rewrite the routing table",
    },
    Check {
        key: "net.ipv6.conf.default.accept_redirects",
        want: Want::Exactly(0),
        severity: Severity::Warning,
        why: "ICMPv6 redirects can rewrite the routing table (new interfaces)",
    },
    Check {
        key: "net.ipv4.conf.all.send_redirects",
        want: Want::Exactly(0),
        severity: Severity::Info,
        why: "a server has no business sending ICMP redirects",
    },
    Check {
        key: "net.ipv4.conf.all.accept_source_route",
        want: Want::Exactly(0),
        severity: Severity::Warning,
        why: "source-routed packets choose their own path through the host",
    },
    Check {
        key: "net.ipv4.conf.default.accept_source_route",
        want: Want::Exactly(0),
        severity: Severity::Warning,
        why: "source-routed packets choose their own path (new interfaces)",
    },
    Check {
        key: "net.ipv6.conf.all.accept_source_route",
        want: Want::Exactly(0),
        severity: Severity::Warning,
        why: "source-routed packets choose their own path through the host",
    },
    Check {
        key: "net.ipv4.conf.all.rp_filter",
        want: Want::Min(1),
        severity: Severity::Warning,
        why: "packets with forged source addresses from the wrong interface are not dropped",
    },
    Check {
        key: "net.ipv4.conf.all.log_martians",
        want: Want::Min(1),
        severity: Severity::Info,
        why: "packets with impossible source addresses go unlogged",
    },
    Check {
        key: "net.ipv4.tcp_syncookies",
        want: Want::Exactly(1),
        severity: Severity::Warning,
        why: "a SYN flood fills the listen queues instead of being answered with cookies",
    },
    Check {
        key: "net.ipv4.icmp_echo_ignore_broadcasts",
        want: Want::Exactly(1),
        severity: Severity::Info,
        why: "the host answers broadcast pings (smurf amplification)",
    },
    Check {
        key: "net.ipv4.icmp_ignore_bogus_error_responses",
        want: Want::Exactly(1),
        severity: Severity::Info,
        why: "bogus ICMP errors are logged",
    },
    Check {
        key: "kernel.randomize_va_space",
        want: Want::Exactly(2),
        severity: Severity::High,
        why: "address space layout randomization is off or partial: exploits get fixed addresses",
    },
    Check {
        key: "kernel.kptr_restrict",
        want: Want::Min(1),
        severity: Severity::Warning,
        why: "kernel pointers are shown to every user (/proc/kallsyms), which helps kernel exploits",
    },
    Check {
        key: "kernel.dmesg_restrict",
        want: Want::Exactly(1),
        severity: Severity::Warning,
        why: "every user reads the kernel log (addresses, hardware, the firewall's lines)",
    },
    Check {
        key: "kernel.yama.ptrace_scope",
        want: Want::Min(1),
        severity: Severity::Warning,
        why: "any process can attach to another of the same user and read its memory (credentials)",
    },
    Check {
        key: "kernel.unprivileged_bpf_disabled",
        want: Want::Min(1),
        severity: Severity::Warning,
        why: "unprivileged users can load BPF programs, a steady source of kernel exploits",
    },
    Check {
        key: "kernel.kexec_load_disabled",
        want: Want::Exactly(1),
        severity: Severity::Info,
        why: "root can replace the running kernel with kexec, past Secure Boot",
    },
    Check {
        key: "kernel.sysrq",
        want: Want::Exactly(0),
        severity: Severity::Info,
        why: "the magic SysRq key is on (a console can crash, sync or kill at will)",
    },
    Check {
        key: "kernel.perf_event_paranoid",
        want: Want::Min(2),
        severity: Severity::Info,
        why: "unprivileged users can profile the kernel (side channels)",
    },
    Check {
        key: "kernel.unprivileged_userns_clone",
        want: Want::Exactly(0),
        severity: Severity::Info,
        why: "unprivileged user namespaces widen the kernel's attack surface (needed by rootless containers and some browsers)",
    },
    Check {
        key: "fs.protected_symlinks",
        want: Want::Exactly(1),
        severity: Severity::High,
        why: "symlinks in world-writable directories are followed (the classic /tmp race)",
    },
    Check {
        key: "fs.protected_hardlinks",
        want: Want::Exactly(1),
        severity: Severity::High,
        why: "any user can hard-link files they can't write (set-uid binaries kept past an upgrade)",
    },
    Check {
        key: "fs.protected_fifos",
        want: Want::Min(1),
        severity: Severity::Warning,
        why: "FIFOs in world-writable directories are opened blindly",
    },
    Check {
        key: "fs.protected_regular",
        want: Want::Min(1),
        severity: Severity::Warning,
        why: "files in world-writable directories owned by others are opened blindly",
    },
    Check {
        key: "fs.suid_dumpable",
        want: Want::Exactly(0),
        severity: Severity::Warning,
        why: "set-uid programs leave core dumps readable by their user",
    },
    Check {
        key: "net.core.bpf_jit_harden",
        want: Want::Min(1),
        severity: Severity::Info,
        why: "the BPF JIT isn't hardened against constant blinding attacks",
    },
    Check {
        key: "vm.unprivileged_userfaultfd",
        want: Want::Exactly(0),
        severity: Severity::Info,
        why: "unprivileged users can use userfaultfd, which helps kernel race exploits",
    },
    Check {
        key: "dev.tty.ldisc_autoload",
        want: Want::Exactly(0),
        severity: Severity::Info,
        why: "unprivileged users can load tty line discipline modules",
    },
];

/// Interfaces whose presence makes forwarding expected.
fn router_interfaces(net_class: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(net_class) else { return false };
    rd.flatten().any(|e| {
        let n = e.file_name().to_string_lossy().into_owned();
        ["wg", "docker", "br-", "podman", "virbr", "tun", "tap", "lxc", "lxd", "incus", "veth", "cni", "flannel", "wt"]
            .iter()
            .any(|p| n.starts_with(p))
    })
}

/// Reads the watched sysctls from `proc_sys` (`net.ipv4.ip_forward` is
/// `<proc_sys>/net/ipv4/ip_forward`); missing ones are left out. The third list: the ones
/// the kernel refuses to show (`net.core.bpf_jit_harden` wants CAP_SYS_ADMIN, which the
/// unit's capability bound drops: seen on a Fedora host), a note and not an error.
pub fn collect(cfg: &SysctlCfg) -> (BTreeMap<String, String>, Vec<String>, Vec<&'static str>) {
    let (mut values, mut errors, mut unreadable) = (BTreeMap::new(), Vec::new(), Vec::new());
    for c in CHECKS {
        let path = cfg.proc_sys.join(c.key.replace('.', "/"));
        match std::fs::read_to_string(&path) {
            Ok(v) => {
                values.insert(c.key.to_string(), v.split_whitespace().next().unwrap_or("").chars().take(64).collect());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => unreadable.push(c.key),
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }
    (values, errors, unreadable)
}

/// Where the boot configuration sets a watched sysctl: the assignment that wins.
#[derive(Clone, Debug, PartialEq)]
pub struct BootSetting {
    pub value: String,
    /// The file as named (a link's target where it is one: 99-sysctl.conf is sysctl.conf).
    pub file: String,
    pub line: usize,
    /// Read after 90-hardening.conf (its name sorts later, or it is sysctl.conf read last),
    /// so a line there loses to this one.
    pub later: bool,
}

/// A line systemd-sysctl and `sysctl --system` skip: not `key = value`.
#[derive(Clone, Debug, PartialEq)]
pub struct Skipped {
    pub file: String,
    pub line: usize,
    pub text: String,
    /// The watched sysctl it names, if any (`sysctl -w kernel.sysrq=0`).
    pub key: Option<&'static str>,
}

/// What the next boot sets, as the sysctl.d files say.
#[derive(Clone, Debug, Default)]
pub struct Boot {
    pub settings: BTreeMap<&'static str, BootSetting>,
    pub skipped: Vec<Skipped>,
    /// sysctl.conf's settings of watched sysctls on a systemd host that doesn't read it at
    /// boot (no link to it in sysctl.d: Debian 13 dropped 99-sysctl.conf).
    pub unread: Vec<(&'static str, BootSetting)>,
}

/// What the audit knows of the host besides the values.
#[derive(Clone, Debug, Default)]
pub struct Host {
    /// It forwards on purpose (a VPN, container or bridge interface exists).
    pub router: bool,
    /// apport is the core handler, which sets fs.suid_dumpable to 2 each time it starts.
    pub apport: bool,
    pub boot: Boot,
}

/// The assignments of the files read, as systemd-sysctl keeps them.
#[derive(Default)]
struct Assignments {
    /// Keys as normalized (`kernel/sysrq`): the last assignment, or None for `-key` (a key
    /// kept out of patterns, as systemd's 50-default.conf does for `all`).
    explicit: BTreeMap<String, Option<BootSetting>>,
    /// Patterns (`net/ipv4/conf/*/rp_filter`) in the order they apply: a repeated one moves to
    /// the end.
    globs: Vec<(String, BootSetting)>,
    skipped: Vec<Skipped>,
}

impl Assignments {
    fn parse(&mut self, text: &str, file: &str, later: bool) {
        for (i, raw) in text.lines().enumerate() {
            let p = raw.trim();
            if p.is_empty() || p.starts_with('#') || p.starts_with(';') {
                continue;
            }
            let skipped = Skipped { file: file.to_string(), line: i + 1, text: crate::event::clean(p, 60), key: named_key(p) };
            let (key, value) = match p.split_once('=') {
                Some((k, v)) => {
                    let k = k.trim();
                    (k.strip_prefix('-').unwrap_or(k).trim(), Some(v.trim()))
                }
                None => match p.strip_prefix('-') {
                    Some(k) => (k.trim(), None),
                    None => {
                        self.skipped.push(skipped);
                        continue;
                    }
                },
            };
            // `sysctl -w kernel.sysrq` names no file under /proc/sys: systemd logs it and goes on
            if key.is_empty() || key.contains(char::is_whitespace) {
                self.skipped.push(skipped);
                continue;
            }
            let key = normalize(key);
            let setting = value.map(|v| BootSetting { value: crate::event::clean(v, 64), file: file.to_string(), line: i + 1, later });
            if key.contains(['*', '?', '[']) {
                let Some(s) = setting else { continue };
                self.globs.retain(|(p, _)| *p != key);
                self.globs.push((key, s));
            } else {
                self.explicit.insert(key, setting);
            }
        }
    }

    /// The assignment that wins for a key: its own, whatever the order, else the last pattern's.
    fn get(&self, key: &str) -> Option<&BootSetting> {
        let k = key.replace('.', "/");
        match self.explicit.get(&k) {
            Some(s) => s.as_ref(),
            None => self.globs.iter().rev().find(|(p, _)| glob_match(p, &k)).map(|(_, s)| s),
        }
    }
}

/// systemd's sysctl_normalize: `/`-separated, the dots and slashes swapped when a dot comes
/// first (`kernel.sysrq` and `kernel/sysrq` are one key).
fn normalize(k: &str) -> String {
    let swap = k.find(['.', '/']).is_some_and(|i| k.as_bytes()[i] == b'.');
    let k: String = if swap {
        k.chars()
            .map(|c| match c {
                '.' => '/',
                '/' => '.',
                c => c,
            })
            .collect()
    } else {
        k.to_string()
    };
    k.split('/').filter(|s| !s.is_empty() && *s != ".").collect::<Vec<_>>().join("/")
}

/// A sysctl.d pattern against a key, both normalized: `*` and `?` stay within a component, as
/// glob(3) over /proc/sys (no `[...]` classes: such a pattern matches nothing here).
fn glob_match(pattern: &str, key: &str) -> bool {
    fn wild(p: &[u8], s: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => (0..=s.len()).any(|i| wild(rest, &s[i..])),
            Some((b'?', rest)) => !s.is_empty() && wild(rest, &s[1..]),
            Some((c, rest)) => s.first() == Some(c) && wild(rest, &s[1..]),
        }
    }
    let (p, k): (Vec<&str>, Vec<&str>) = (pattern.split('/').collect(), key.split('/').collect());
    p.len() == k.len() && p.iter().zip(&k).all(|(p, k)| p.len() <= 64 && wild(p.as_bytes(), k.as_bytes()))
}

/// The watched sysctl a skipped line was meant for (`sysctl -w kernel.sysrq=0`,
/// `echo 0 > /proc/sys/kernel/sysrq`).
fn named_key(line: &str) -> Option<&'static str> {
    line.split_whitespace().find_map(|t| {
        let t = t.split('=').next().unwrap_or(t).trim_matches(['"', '\'']);
        let t = normalize(t.strip_prefix("/proc/sys/").unwrap_or(t));
        CHECKS.iter().find(|c| c.key.replace('.', "/") == t).map(|c| c.key)
    })
}

/// A sysctl.d file's text: a regular file (through links), at most MAX_BYTES. None for one
/// masked by a link to /dev/null (or anything else not a file), or unreadable.
fn read_conf(path: &Path) -> Option<String> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    std::fs::File::open(path).ok()?.take(MAX_BYTES).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Reads the boot configuration as systemd-sysctl does: the `*.conf` files of `dirs` in the
/// order of their names, the first directory's file of a name hiding the others'; a later
/// assignment wins, a key's own wins over a pattern's whatever the order, and `-key` keeps it
/// out of patterns. `conf` (sysctl.conf) comes last where no systemd runs (OpenRC; also what
/// `sysctl --system` does); under systemd it counts only through a link in sysctl.d, and its
/// watched settings are `unread` without one.
pub fn read_boot(dirs: &[PathBuf], conf: &Path, systemd: bool) -> Boot {
    let mut files: BTreeMap<String, PathBuf> = BTreeMap::new();
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(d) else { continue };
        for e in rd.flatten().take(MAX_FILES) {
            let Ok(name) = e.file_name().into_string() else { continue };
            if name.ends_with(".conf") && !name.starts_with('.') {
                files.entry(name).or_insert_with(|| e.path());
            }
        }
    }
    let conf_real = std::fs::canonicalize(conf).ok();
    let shown = |p: &Path| crate::event::clean(&p.to_string_lossy(), 200);
    let mut a = Assignments::default();
    let mut conf_linked = false;
    for (name, path) in files.iter().take(MAX_FILES) {
        let real = std::fs::canonicalize(path).ok();
        conf_linked |= conf_real.is_some() && real == conf_real;
        let file = match real.filter(|_| path.is_symlink()) {
            Some(target) => shown(&target),
            None => shown(path),
        };
        if let Some(text) = read_conf(path) {
            a.parse(&text, &file, name.as_str() > HARDENING_NAME);
        }
    }
    let mut unread = Vec::new();
    if !conf_linked {
        if let Some(text) = read_conf(conf) {
            if systemd {
                let mut c = Assignments::default();
                c.parse(&text, &shown(conf), true);
                unread =
                    CHECKS.iter().filter_map(|k| c.explicit.get(&k.key.replace('.', "/")).cloned().flatten().map(|s| (k.key, s))).collect();
            } else {
                a.parse(&text, &shown(conf), true);
            }
        }
    }
    let settings = CHECKS.iter().filter_map(|c| a.get(c.key).map(|s| (c.key, s.clone()))).collect();
    Boot { settings, skipped: a.skipped, unread }
}

/// apport is the kernel's core handler (`kernel.core_pattern` pipes to it).
fn apport_handles_cores(proc_sys: &Path) -> bool {
    std::fs::read_to_string(proc_sys.join("kernel/core_pattern")).is_ok_and(|p| p.starts_with('|') && p.contains("apport"))
}

fn first_int(s: &str) -> Option<i64> {
    s.split_whitespace().next()?.parse().ok()
}

/// apport's start writes 2 to fs.suid_dumpable, after systemd-sysctl, and its stop 0.
const APPORT: &str = "apport, the crash handler in kernel.core_pattern, sets it to 2 each time it starts (after the \
                      sysctl.d files) and to 0 when it stops: `systemctl disable --now apport` keeps it at 0";

/// Judges the values read, and what the next boot sets.
pub fn audit(values: &BTreeMap<String, String>, host: &Host, errors: Vec<String>, cfg: &SysctlCfg, now: Micros) -> SysctlReport {
    let ignored = |id: &str| cfg.ignore.iter().any(|x| x == id);
    let (mut issues, mut keep, mut keep_notes) = (Vec::new(), BTreeMap::new(), Vec::new());
    let kept = |c: &Check| host.boot.settings.get(c.key).and_then(|s| first_int(&s.value)).is_some_and(|b| c.want.passes(b));
    let exempt = |c: &Check| matches!(c.want, Want::ZeroUnlessRouter) && host.router;
    for c in CHECKS {
        let k = c.key;
        let Some(v) = values.get(k) else { continue };
        let issue = |severity, message: String, fix: String| Issue { id: k.to_string(), severity, message, fix };
        let Ok(n) = v.parse::<i64>() else {
            issues.push(issue(Severity::Info, format!("{k} is '{v}', not a number"), String::new()));
            continue;
        };
        let ok = c.want.passes(n);
        if exempt(c) {
            // expected here: a note, and never kept at 0
            if !ok {
                let why = format!("{k} = {v}: {} (expected here: a VPN, container or bridge interface exists)", c.why);
                issues.push(issue(Severity::Info, why, String::new()));
            }
            continue;
        }
        let want = c.want.value();
        let set = host.boot.settings.get(k);
        let set_bad = set.filter(|s| first_int(&s.value).is_some_and(|b| !c.want.passes(b)));
        let apport = host.apport && k == "fs.suid_dumpable";
        // the line that keeps it, at the value now when that is good (never weaker than it):
        // in 90-hardening.conf, unless a file read after that one sets it otherwise
        let at = if ok { n } else { want };
        let keep_fix = match set_bad {
            Some(s) if s.later => {
                format!("change line {} of {} to `{k} = {at}` (that file is read after {HARDENING_CONF})", s.line, s.file)
            }
            _ => format!("add `{k} = {at}` to {HARDENING_CONF}"),
        };
        if !ignored(k) {
            if !kept(c) {
                match set_bad {
                    Some(s) if s.later => keep_notes.push(format!("{k}: {keep_fix}")),
                    _ => {
                        keep.insert(k.to_string(), at.to_string());
                    }
                }
            }
            if apport {
                keep_notes.push(format!("{k}: {APPORT}"));
            }
        }
        if !ok {
            let fix = if apport {
                if kept(c) {
                    APPORT.to_string()
                } else {
                    format!("{APPORT}; and {keep_fix}")
                }
            } else if let Some(s) = set.filter(|_| kept(c)) {
                format!(
                    "sysctl --system ({} line {} sets {} at boot: added since the boot, or something changed the value after it)",
                    s.file, s.line, s.value
                )
            } else {
                // the file takes `key = value`, not the command: a pasted `sysctl -w` line there is
                // skipped at boot, and the setting is lost with the next reboot
                format!("sysctl -w {k}={want}; to keep it after a reboot, {keep_fix}")
            };
            issues.push(issue(c.severity, format!("{k} = {v}: {}", c.why), fix));
        } else if let Some(s) = set_bad {
            let message =
                format!("{k} = {v} now, but {} line {} sets {} at boot and at every `sysctl --system`: {}", s.file, s.line, s.value, c.why);
            issues.push(issue(c.severity, message, keep_fix));
        } else if apport {
            issues.push(issue(
                c.severity,
                format!("{k} = {v} now, but apport sets it back to 2 when it next starts: {}", c.why),
                APPORT.into(),
            ));
        }
    }
    // the watched sysctls a line meant to keep and nothing else keeps
    let lost = |key: &str| -> Option<&'static Check> {
        let c = CHECKS.iter().find(|c| c.key == key)?;
        (values.contains_key(key) && !exempt(c) && !kept(c) && !ignored(key)).then_some(c)
    };
    let severity = |checks: &[&Check]| checks.iter().map(|c| c.severity).max().unwrap_or(Severity::Info);
    let mut by_file: BTreeMap<&str, Vec<&Skipped>> = BTreeMap::new();
    for s in &host.boot.skipped {
        by_file.entry(s.file.as_str()).or_default().push(s);
    }
    for (file, lines) in by_file {
        let mut meant: Vec<&Check> = Vec::new();
        for c in lines.iter().filter_map(|s| s.key).filter_map(lost) {
            if !meant.iter().any(|m| m.key == c.key) {
                meant.push(c);
            }
        }
        let nums: Vec<String> = lines.iter().map(|s| s.line.to_string()).collect();
        let what = match nums.len() {
            1 => format!("line {} is", nums[0]),
            n if n <= 6 => format!("lines {} are", nums.join(", ")),
            n => format!("lines {} and {} more are", nums[..5].join(", "), n - 5),
        };
        let mut message = format!("{file}: {what} not `key = value`, skipped at boot and by `sysctl --system` (`{}`)", lines[0].text);
        if !meant.is_empty() {
            message.push_str(&format!(", so it doesn't set {}", meant.iter().map(|c| c.key).collect::<Vec<_>>().join(", ")));
        }
        let plain_path = file.chars().all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c));
        let fix = if plain_path && lines.iter().all(|s| s.text.starts_with("sysctl -w ")) {
            format!("sed -i 's/^[[:space:]]*sysctl -w[[:space:]]*//' {file}, then sysctl --system")
        } else {
            "write each as `key = value`: a sysctl.d file takes no commands".to_string()
        };
        issues.push(Issue { id: file.to_string(), severity: severity(&meant), message, fix });
    }
    let unread: Vec<(&Check, &BootSetting)> = host
        .boot
        .unread
        .iter()
        .filter_map(|(k, s)| lost(k).filter(|c| first_int(&s.value).is_some_and(|b| c.want.passes(b))).map(|c| (c, s)))
        .collect();
    if let Some((_, first)) = unread.first() {
        let checks: Vec<&Check> = unread.iter().map(|(c, _)| *c).collect();
        let names = checks.iter().map(|c| c.key).collect::<Vec<_>>().join(", ");
        issues.push(Issue {
            id: first.file.clone(),
            severity: severity(&checks),
            message: format!(
                "{} sets {names}, but systemd-sysctl doesn't read it at boot (nothing in sysctl.d links to it): only `sysctl --system` does",
                first.file
            ),
            fix: format!("move those lines to {HARDENING_CONF}"),
        });
    }
    issues.retain(|i| !ignored(&i.id));
    SysctlReport { read: now, router: host.router, issues, settings: values.clone(), errors, keep, keep_notes }
}

pub fn scan(cfg: &SysctlCfg, now: Micros) -> SysctlReport {
    let (values, errors, unreadable) = collect(cfg);
    let host = Host {
        router: router_interfaces(&cfg.net_class),
        apport: apport_handles_cores(&cfg.proc_sys),
        boot: read_boot(&cfg.sysctl_d, &cfg.sysctl_conf, Path::new("/run/systemd/system").is_dir()),
    };
    let mut r = audit(&values, &host, errors, cfg, now);
    r.issues.extend(unreadable.into_iter().filter(|k| !cfg.ignore.iter().any(|x| x == k)).map(|k| Issue {
        id: k.to_string(),
        severity: Severity::Info,
        message: format!(
            "{k} can't be read here (the kernel shows it only with CAP_SYS_ADMIN, which the unit's capability bound drops): \
             `vpsfort sysctl-audit` in a root shell reads it"
        ),
        fix: String::new(),
    }));
    r
}

/// What was reported before: open problems and the watched values.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SysctlBaseline {
    pub issues: BTreeMap<String, Severity>,
    pub settings: BTreeMap<String, String>,
    #[serde(default)]
    pub reminded: Micros,
}

fn line(i: &Issue) -> String {
    let sev = match i.severity {
        Severity::Info => "note",
        Severity::Warning => "warning",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    };
    if i.fix.is_empty() {
        format!("{sev}: {}", i.message)
    } else {
        format!("{sev}: {} - fix: {}", i.message, i.fix)
    }
}

/// Compares a reading with what was reported before (as the SSH audit's `judge` does).
pub fn judge(baseline: &mut Option<SysctlBaseline>, r: &SysctlReport, cfg: &SysctlCfg) -> Vec<Finding> {
    let now = r.read;
    let finding = |key: String, severity, message: String, evidence: Vec<String>, notify| Finding {
        key,
        every: 0,
        severity,
        message,
        evidence,
        notify,
        owner: None,
        files: vec![],
    };
    let mut out = Vec::new();
    if !r.errors.is_empty() {
        out.push(Finding {
            every: 86_400 * time::SEC,
            ..finding("sysctl-audit-errors".into(), Severity::Info, format!("sysctl audit: {}", r.errors.join("; ")), vec![], false)
        });
    }
    if r.settings.is_empty() {
        return out;
    }
    let issues: BTreeMap<String, &Issue> = r.issues.iter().map(|i| (i.id.clone(), i)).collect();
    let high: Vec<&Issue> = r.issues.iter().filter(|i| i.severity >= Severity::High).collect();
    let Some(b) = baseline.as_mut() else {
        let worst = r.worst().unwrap_or(Severity::Info);
        let shown: Vec<&Issue> = r.issues.iter().filter(|i| i.severity >= Severity::Warning).collect();
        let message = if shown.is_empty() {
            "sysctl audit: no problems".to_string()
        } else {
            format!("sysctl audit: {}", shown.iter().map(|i| i.message.as_str()).take(3).collect::<Vec<_>>().join("; "))
        };
        out.push(finding(format!("sysctl-audit-first:{now}"), worst, message, r.issues.iter().map(line).collect(), !shown.is_empty()));
        *baseline = Some(SysctlBaseline {
            issues: r.issues.iter().map(|i| (i.id.clone(), i.severity)).collect(),
            settings: r.settings.clone(),
            reminded: now,
        });
        return out;
    };
    let changes: Vec<String> = r
        .settings
        .iter()
        .filter_map(|(k, v)| match b.settings.get(k) {
            Some(old) if old != v => Some(format!("{k}: {old} -> {v}")),
            _ => None,
        })
        .collect();
    let new: Vec<&Issue> = r.issues.iter().filter(|i| b.issues.get(&i.id).is_none_or(|old| *old < i.severity)).collect();
    let fixed: Vec<&String> = b.issues.keys().filter(|id| !issues.contains_key(*id)).collect();
    let changed = |c: &[String]| c.iter().map(|c| format!("changed: {c}")).collect::<Vec<_>>();
    if !new.is_empty() {
        let worst = new.iter().map(|i| i.severity).max().unwrap_or(Severity::Info);
        let mut evidence: Vec<String> = new.iter().map(|i| line(i)).collect();
        evidence.extend(changed(&changes));
        let what = new.iter().map(|i| i.message.as_str()).take(3).collect::<Vec<_>>().join("; ");
        let n = if new.len() == 1 { "new problem".to_string() } else { format!("{} new problems", new.len()) };
        out.push(finding(
            format!("sysctl-audit-new:{now}"),
            worst,
            format!("sysctl audit: {n}: {what}"),
            evidence,
            worst >= Severity::Warning,
        ));
    } else if !changes.is_empty() && fixed.is_empty() {
        out.push(finding(
            format!("sysctl-audit-changed:{now}"),
            Severity::Info,
            format!("sysctls changed, no new problems: {}", changes.iter().take(4).cloned().collect::<Vec<_>>().join("; ")),
            changed(&changes),
            true,
        ));
    }
    if !fixed.is_empty() {
        let names: Vec<&str> = fixed.iter().map(|s| s.as_str()).collect();
        // fixed with `sysctl -w` alone: the next boot brings the old value back
        let unkept: Vec<&str> = names.iter().copied().filter(|n| r.keep.contains_key(*n)).collect();
        let mut message = format!("sysctl audit: fixed: {}", names.join(", "));
        if !unkept.is_empty() {
            message.push_str(&format!(
                "; no sysctl.d file keeps {} after a reboot (`vpsfort sysctl-audit --conf` prints the lines)",
                unkept.join(", ")
            ));
        }
        out.push(finding(
            format!("sysctl-audit-fixed:{now}"),
            Severity::Info,
            message,
            if new.is_empty() { changed(&changes) } else { vec![] },
            b.issues.iter().any(|(id, s)| fixed.contains(&id) && *s >= Severity::Warning),
        ));
    }
    let remind = cfg.remind.micros();
    if remind > 0 && !high.is_empty() && new.is_empty() && now - b.reminded >= remind {
        out.push(finding(
            format!("sysctl-audit-remind:{now}"),
            Severity::High,
            format!("sysctl audit: still open: {}", high.iter().map(|i| i.message.as_str()).take(3).collect::<Vec<_>>().join("; ")),
            high.iter().map(|i| line(i)).collect(),
            true,
        ));
        b.reminded = now;
    }
    if !new.is_empty() && new.iter().any(|i| i.severity >= Severity::High) {
        b.reminded = now;
    }
    b.issues = r.issues.iter().map(|i| (i.id.clone(), i.severity)).collect();
    b.settings = r.settings.clone();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Micros = 1_800_000_000 * time::SEC;

    fn hardened() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        for c in CHECKS {
            let v = match c.want {
                Want::Min(n) | Want::Exactly(n) => n,
                Want::ZeroUnlessRouter => 0,
            };
            m.insert(c.key.to_string(), v.to_string());
        }
        m
    }

    fn router() -> Host {
        Host { router: true, ..Host::default() }
    }

    /// No sysctl.d to read (the scan tests' cfg must not see the machine's own).
    fn nowhere() -> SysctlCfg {
        SysctlCfg { sysctl_d: vec![], sysctl_conf: "/nonexistent/sysctl.conf".into(), ..SysctlCfg::default() }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lg-sysctl-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// The VPN node's files (Ubuntu 22.04) after 0.6.0's advice: the `sysctl -w` commands
    /// pasted into 90-hardening.conf, which every boot skips; plus a masked file, a file of
    /// /run hidden by /etc's of the same name, systemd's patterns, a slash-separated key and
    /// sysctl.conf through 99-sysctl.conf.
    fn ubuntu(d: &Path, link_sysctl_conf: bool) -> (Vec<PathBuf>, PathBuf) {
        let (etc, run, lib) = (d.join("etc/sysctl.d"), d.join("run/sysctl.d"), d.join("usr/lib/sysctl.d"));
        write(&etc.join("10-magic-sysrq.conf"), "# The magic SysRq key\n#\nkernel.sysrq = 176\n");
        write(&etc.join("10-network-security.conf"), "net.ipv4.conf.default.rp_filter=2\nnet.ipv4.conf.all.rp_filter=2\n");
        write(&etc.join("10-kernel-hardening.conf"), "kernel/kptr_restrict = 1\n");
        write(
            &etc.join("90-hardening.conf"),
            "sysctl -w net.ipv4.conf.all.send_redirects=0\nsysctl -w kernel.sysrq=0\nsysctl -w fs.suid_dumpable=0\n",
        );
        write(&run.join("10-magic-sysrq.conf"), "kernel.sysrq = 1\n");
        write(
            &lib.join("50-default.conf"),
            "net.ipv4.conf.*.accept_source_route = 0\n-net.ipv4.conf.all.accept_source_route\n\
             net.ipv4.conf.*.accept_redirects = 1\nfs.protected_regular = 1\n",
        );
        write(&lib.join("99-protect-links.conf"), "fs.protected_regular = 2\n");
        write(&lib.join("50-masked.conf"), "kernel.randomize_va_space = 0\n");
        std::os::unix::fs::symlink("/dev/null", etc.join("50-masked.conf")).unwrap();
        write(&d.join("etc/sysctl.conf"), "#kernel.sysrq=438\nnet.ipv4.tcp_syncookies=0\nkernel.dmesg_restrict = 1\n");
        if link_sysctl_conf {
            std::os::unix::fs::symlink("../sysctl.conf", etc.join("99-sysctl.conf")).unwrap();
        }
        (vec![etc, run, d.join("usr/local/lib/sysctl.d"), lib], d.join("etc/sysctl.conf"))
    }

    #[test]
    fn the_boot_configuration_is_read_as_systemd_sysctl_reads_it() {
        let d = tmp("boot");
        let (dirs, conf) = ubuntu(&d, true);
        let b = read_boot(&dirs, &conf, true);
        let at = |k: &str| b.settings.get(k).map(|s| (s.value.as_str(), s.file.rsplit('/').next().unwrap(), s.line, s.later));
        assert_eq!(at("kernel.sysrq"), Some(("176", "10-magic-sysrq.conf", 3, false)), "/etc's file hides /run's");
        assert_eq!(at("kernel.kptr_restrict"), Some(("1", "10-kernel-hardening.conf", 1, false)), "kernel/kptr_restrict is the key");
        assert_eq!(at("net.ipv4.conf.all.rp_filter"), Some(("2", "10-network-security.conf", 2, false)));
        assert_eq!(at("fs.protected_regular"), Some(("2", "99-protect-links.conf", 1, true)), "the later file wins");
        assert_eq!(at("net.ipv4.conf.all.accept_redirects"), Some(("1", "50-default.conf", 3, false)), "a pattern's");
        assert_eq!(at("net.ipv4.conf.all.accept_source_route"), None, "`-key` keeps it out of the pattern");
        assert_eq!(at("kernel.randomize_va_space"), None, "masked by a link to /dev/null");
        // 99-sysctl.conf is sysctl.conf, named as such, read once
        assert_eq!(at("net.ipv4.tcp_syncookies"), Some(("0", "sysctl.conf", 2, true)));
        assert!(b.unread.is_empty());
        // the pasted commands: skipped, each with the key it meant
        let skipped: Vec<(usize, Option<&str>)> = b.skipped.iter().map(|s| (s.line, s.key)).collect();
        assert_eq!(skipped, [(1, Some("net.ipv4.conf.all.send_redirects")), (2, Some("kernel.sysrq")), (3, Some("fs.suid_dumpable"))]);
        assert!(b.skipped.iter().all(|s| s.file.ends_with("/etc/sysctl.d/90-hardening.conf")));
        assert!(!b.settings.contains_key("fs.suid_dumpable"));

        // no 99-sysctl.conf (Debian 13): systemd never reads sysctl.conf, `sysctl --system` and OpenRC last
        let d2 = tmp("boot-unlinked");
        let (dirs, conf) = ubuntu(&d2, false);
        let b = read_boot(&dirs, &conf, true);
        assert!(!b.settings.contains_key("net.ipv4.tcp_syncookies"));
        let unread: Vec<(&str, &str)> = b.unread.iter().map(|(k, s)| (*k, s.value.as_str())).collect();
        assert_eq!(unread, [("net.ipv4.tcp_syncookies", "0"), ("kernel.dmesg_restrict", "1")]);
        let b = read_boot(&dirs, &conf, false);
        assert_eq!(b.settings.get("net.ipv4.tcp_syncookies").map(|s| (s.value.as_str(), s.later)), Some(("0", true)));
        assert!(b.unread.is_empty());
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&d2);
    }

    #[test]
    fn patterns_and_keys_match_as_systemd_matches_them() {
        assert_eq!(normalize("kernel.sysrq"), "kernel/sysrq");
        assert_eq!(normalize("/kernel//sysrq"), "kernel/sysrq");
        // a dot first: dots and slashes swap (an interface name with a dot, written with a slash)
        assert_eq!(normalize("net.ipv4.conf.eth0/100.rp_filter"), "net/ipv4/conf/eth0.100/rp_filter");
        assert!(glob_match("net/ipv4/conf/*/rp_filter", "net/ipv4/conf/all/rp_filter"));
        assert!(glob_match("net/ipv4/conf/a?l/rp_filter", "net/ipv4/conf/all/rp_filter"));
        assert!(!glob_match("net/*/rp_filter", "net/ipv4/conf/all/rp_filter"), "`*` stays within a component");
        assert!(!glob_match("net/ipv4/conf/*/rp_filter", "net/ipv4/conf/all/log_martians"));
        assert_eq!(named_key("echo 0 > /proc/sys/kernel/sysrq"), Some("kernel.sysrq"));
        assert_eq!(named_key("sysctl -w \"fs.suid_dumpable=0\""), Some("fs.suid_dumpable"));
        assert_eq!(named_key("sysctl -p"), None);
        let mut a = Assignments::default();
        a.parse("kernel.sysrq: 0\n- kernel.dmesg_restrict = 1\n; a comment\nnet.ipv4.conf.*.rp_filter = 2\n", "f", false);
        assert_eq!(a.skipped.len(), 1, "no `=`: skipped");
        assert_eq!(a.get("kernel.dmesg_restrict").map(|s| s.value.as_str()), Some("1"), "`-` only ignores a failure");
        assert_eq!(a.get("net.ipv4.conf.all.rp_filter").map(|s| s.value.as_str()), Some("2"));
        // the key's own assignment wins over a later pattern's
        a.parse("net.ipv4.conf.all.rp_filter = 1\n", "g", false);
        a.parse("net.ipv4.conf.*.rp_filter = 0\n", "h", false);
        assert_eq!(a.get("net.ipv4.conf.all.rp_filter").map(|s| (s.value.as_str(), s.file.as_str())), Some(("1", "g")));
    }

    #[test]
    fn a_setting_the_next_boot_undoes_is_a_problem_and_conf_keeps_the_rest() {
        let d = tmp("vpn");
        let (dirs, conf) = ubuntu(&d, true);
        let cfg = SysctlCfg::default();
        // fixed with `sysctl -w` only, as on the VPN node; the stock Ubuntu values otherwise
        let mut now = hardened();
        now.insert("kernel.perf_event_paranoid".into(), "4".into());
        now.insert("net.ipv4.conf.all.rp_filter".into(), "2".into());
        let host = Host { router: true, apport: false, boot: read_boot(&dirs, &conf, true) };
        let r = audit(&now, &host, vec![], &cfg, T);
        let ids: Vec<&str> = r.issues.iter().map(|i| i.id.as_str()).collect();
        let pasted_id = format!("{}/90-hardening.conf", dirs[0].display());
        // the pattern sets both `all` and `default`
        assert_eq!(
            ids,
            [
                "net.ipv4.conf.all.accept_redirects",
                "net.ipv4.conf.default.accept_redirects",
                "net.ipv4.tcp_syncookies",
                "kernel.sysrq",
                pasted_id.as_str()
            ]
        );
        let by = |id: &str| r.issues.iter().find(|i| i.id.ends_with(id)).unwrap();
        let sysrq = by("kernel.sysrq");
        assert_eq!(sysrq.severity, Severity::Info);
        assert!(sysrq.message.starts_with("kernel.sysrq = 0 now, but "), "{}", sysrq.message);
        assert!(sysrq.message.contains("10-magic-sysrq.conf line 3 sets 176 at boot"), "{}", sysrq.message);
        assert_eq!(sysrq.fix, "add `kernel.sysrq = 0` to /etc/sysctl.d/90-hardening.conf");
        // set back by a file read after 90-hardening.conf: change it there
        let syn = by("net.ipv4.tcp_syncookies");
        assert_eq!(syn.severity, Severity::Warning);
        assert!(
            syn.fix.starts_with("change line 2 of ") && syn.fix.contains("sysctl.conf to `net.ipv4.tcp_syncookies = 1`"),
            "{}",
            syn.fix
        );
        // the pasted commands, with the keys nothing else keeps
        let pasted = by("90-hardening.conf");
        assert_eq!(pasted.severity, Severity::Warning, "fs.suid_dumpable's");
        assert!(pasted.message.contains(": lines 1, 2, 3 are not `key = value`, skipped at boot"), "{}", pasted.message);
        assert!(pasted.message.contains("(`sysctl -w net.ipv4.conf.all.send_redirects=0`)"), "{}", pasted.message);
        assert!(
            pasted.message.ends_with("so it doesn't set net.ipv4.conf.all.send_redirects, kernel.sysrq, fs.suid_dumpable"),
            "{}",
            pasted.message
        );
        assert!(pasted.fix.starts_with("sed -i 's/^[[:space:]]*sysctl -w[[:space:]]*//' /"), "{}", pasted.fix);
        // the lines that keep everything: the value now where it's good (perf_event_paranoid 4,
        // not the minimum 2), not what a file keeps already, not what a later file overrides,
        // not forwarding on a router
        assert_eq!(r.keep.get("kernel.perf_event_paranoid").map(String::as_str), Some("4"));
        assert_eq!(r.keep.get("kernel.sysrq").map(String::as_str), Some("0"));
        assert_eq!(r.keep.get("net.ipv4.conf.all.accept_redirects").map(String::as_str), Some("0"));
        assert_eq!(r.keep.get("net.ipv4.conf.all.accept_source_route").map(String::as_str), Some("0"), "kept out of the pattern");
        for k in [
            "kernel.kptr_restrict",
            "net.ipv4.conf.all.rp_filter",
            "fs.protected_regular",
            "net.ipv4.tcp_syncookies",
            "net.ipv4.ip_forward",
        ] {
            assert!(!r.keep.contains_key(k), "{k}: {:?}", r.keep);
        }
        assert_eq!(r.keep_notes.len(), 1);
        assert!(r.keep_notes[0].starts_with("net.ipv4.tcp_syncookies: change line 2 of "), "{:?}", r.keep_notes);

        // a value weakened after the boot, where the files keep it: `sysctl --system` restores it
        let mut weak = now.clone();
        weak.insert("kernel.kptr_restrict".into(), "0".into());
        let r = audit(&weak, &host, vec![], &cfg, T);
        let kptr = r.issues.iter().find(|i| i.id == "kernel.kptr_restrict").unwrap();
        assert!(kptr.fix.starts_with("sysctl --system ("), "{}", kptr.fix);
        assert!(kptr.fix.contains("10-kernel-hardening.conf line 1 sets 1 at boot"), "{}", kptr.fix);
        assert!(!r.keep.contains_key("kernel.kptr_restrict"));

        // ignored keys and files are neither told nor kept
        let quiet =
            SysctlCfg { ignore: vec!["kernel.sysrq".into(), format!("{}/90-hardening.conf", dirs[0].display())], ..SysctlCfg::default() };
        let r = audit(&now, &host, vec![], &quiet, T);
        assert!(!r.issues.iter().any(|i| i.id == "kernel.sysrq" || i.id.ends_with("90-hardening.conf")), "{:?}", r.issues);
        assert!(!r.keep.contains_key("kernel.sysrq"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn apport_sets_suid_dumpable_back_after_the_boot() {
        let cfg = SysctlCfg::default();
        let host = Host { apport: true, ..Host::default() };
        let mut v = hardened();
        // fixed with `sysctl -w`, but apport's next start sets 2 again
        let r = audit(&v, &host, vec![], &cfg, T);
        assert_eq!(r.issues.len(), 1, "{:?}", r.issues);
        assert_eq!(r.issues[0].severity, Severity::Warning);
        assert!(r.issues[0].message.starts_with("fs.suid_dumpable = 0 now, but apport sets it back to 2"), "{}", r.issues[0].message);
        assert!(r.issues[0].fix.contains("`systemctl disable --now apport`"), "{}", r.issues[0].fix);
        // as apport left it: the fix is apport's, and the line too
        v.insert("fs.suid_dumpable".into(), "2".into());
        let r = audit(&v, &host, vec![], &cfg, T);
        assert!(r.issues[0].fix.starts_with("apport, the crash handler"), "{}", r.issues[0].fix);
        assert!(r.issues[0].fix.ends_with("; and add `fs.suid_dumpable = 0` to /etc/sysctl.d/90-hardening.conf"), "{}", r.issues[0].fix);
        assert_eq!(r.keep.get("fs.suid_dumpable").map(String::as_str), Some("0"));
        assert!(r.keep_notes.iter().any(|n| n.starts_with("fs.suid_dumpable: apport")), "{:?}", r.keep_notes);
        // the core handler is read from kernel.core_pattern
        let d = tmp("apport");
        write(&d.join("kernel/core_pattern"), "|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -- %E\n");
        assert!(apport_handles_cores(&d));
        write(&d.join("kernel/core_pattern"), "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n");
        assert!(!apport_handles_cores(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sysctl_conf_unread_at_boot_is_told_for_what_nothing_else_keeps() {
        let d = tmp("trixie");
        let (dirs, conf) = ubuntu(&d, false);
        let host = Host { router: true, apport: false, boot: read_boot(&dirs, &conf, true) };
        let r = audit(&hardened(), &host, vec![], &SysctlCfg::default(), T);
        let unread = r.issues.iter().find(|i| i.id.ends_with("/etc/sysctl.conf")).expect("told");
        // tcp_syncookies = 0 there isn't hardening: only dmesg_restrict = 1 is lost
        assert!(
            unread.message.contains("sysctl.conf sets kernel.dmesg_restrict, but systemd-sysctl doesn't read it"),
            "{}",
            unread.message
        );
        assert_eq!(unread.severity, Severity::Warning);
        assert_eq!(unread.fix, "move those lines to /etc/sysctl.d/90-hardening.conf");
        assert!(r.keep.contains_key("kernel.dmesg_restrict"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_fix_the_files_keep_is_told_as_fixed_alone() {
        let d = tmp("kept");
        write(&d.join("90-hardening.conf"), "fs.protected_symlinks = 1\n");
        let host = Host { boot: read_boot(std::slice::from_ref(&d), &d.join("none"), true), ..Host::default() };
        let cfg = SysctlCfg::default();
        let mut weak = hardened();
        weak.insert("fs.protected_symlinks".into(), "0".into());
        let mut b = None;
        judge(&mut b, &audit(&weak, &host, vec![], &cfg, T), &cfg);
        let f = judge(&mut b, &audit(&hardened(), &host, vec![], &cfg, T + time::SEC), &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].message, "sysctl audit: fixed: fs.protected_symlinks");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_hardened_host_has_no_problems_and_a_stock_one_has() {
        let cfg = SysctlCfg::default();
        let r = audit(&hardened(), &Host::default(), vec![], &cfg, T);
        assert!(r.issues.is_empty(), "{:?}", r.issues);
        assert_eq!(r.summary(), format!("{} sysctls (host): no problems", CHECKS.len()));

        // Debian's stock values on a plain VPS
        let mut stock = hardened();
        stock.insert("kernel.sysrq".into(), "438".into());
        stock.insert("kernel.kptr_restrict".into(), "0".into());
        stock.insert("fs.protected_symlinks".into(), "0".into());
        stock.insert("net.ipv4.ip_forward".into(), "1".into());
        stock.insert("kernel.yama.ptrace_scope".into(), "x".into());
        let r = audit(&stock, &Host::default(), vec![], &cfg, T);
        let ids: Vec<&str> = r.issues.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(
            ids,
            ["net.ipv4.ip_forward", "kernel.kptr_restrict", "kernel.yama.ptrace_scope", "kernel.sysrq", "fs.protected_symlinks"]
        );
        assert_eq!(r.worst(), Some(Severity::High));
        assert!(r.issues[0].message.contains("forwards IPv4"), "{}", r.issues[0].message);
        assert!(r.issues[0].fix.contains("sysctl -w net.ipv4.ip_forward=0"));
        // the line for the file is the key and the value, not the command
        assert!(r.issues[0].fix.contains("add `net.ipv4.ip_forward = 0` to /etc/sysctl.d/"), "{}", r.issues[0].fix);
        assert_eq!(r.concerns().len(), 3, "notes are left out of the digest");
        // the same on a router: forwarding is a note without a fix
        let r = audit(&stock, &router(), vec![], &cfg, T);
        assert_eq!(r.issues[0].severity, Severity::Info);
        assert!(r.issues[0].fix.is_empty());
        assert!(r.summary().contains("(router)"));
        // ignored ids
        let cfg = SysctlCfg { ignore: vec!["kernel.sysrq".into()], ..SysctlCfg::default() };
        assert!(!audit(&stock, &Host::default(), vec![], &cfg, T).issues.iter().any(|i| i.id == "kernel.sysrq"));
    }

    #[test]
    fn collect_reads_proc_sys_and_skips_missing_keys() {
        let d = std::env::temp_dir().join(format!("lg-sysctl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("net/ipv4")).unwrap();
        std::fs::write(d.join("net/ipv4/ip_forward"), "1\n").unwrap();
        std::fs::write(d.join("net/ipv4/tcp_syncookies"), "1\n").unwrap();
        let cfg = SysctlCfg { proc_sys: d.clone(), net_class: d.join("none"), ..nowhere() };
        let (values, errors, unreadable) = collect(&cfg);
        assert!(errors.is_empty() && unreadable.is_empty(), "{errors:?} {unreadable:?}");
        assert_eq!(values.len(), 2);
        assert_eq!(values["net.ipv4.ip_forward"], "1");
        let r = scan(&cfg, T);
        assert_eq!(r.issues.len(), 1, "only the keys present are judged: {:?}", r.issues);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_sysctl_the_kernel_refuses_to_show_is_a_note_not_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("lg-sysctl-eperm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("net/core")).unwrap();
        let f = d.join("net/core/bpf_jit_harden");
        std::fs::write(&f, "0\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        let cfg = SysctlCfg { proc_sys: d.clone(), net_class: d.join("none"), ..nowhere() };
        if std::fs::read_to_string(&f).is_ok() {
            let _ = std::fs::remove_dir_all(&d);
            return; // root reads it anyway: nothing to show here
        }
        let (values, errors, unreadable) = collect(&cfg);
        assert!(values.is_empty() && errors.is_empty(), "{values:?} {errors:?}");
        assert_eq!(unreadable, ["net.core.bpf_jit_harden"]);
        let r = scan(&cfg, T);
        assert!(r.errors.is_empty(), "no error alert: {:?}", r.errors);
        assert_eq!(r.issues.len(), 1);
        assert_eq!(r.issues[0].severity, Severity::Info);
        assert!(r.issues[0].message.contains("can't be read here"), "{}", r.issues[0].message);
        let ignoring = SysctlCfg { ignore: vec!["net.core.bpf_jit_harden".into()], ..cfg };
        assert!(scan(&ignoring, T).issues.is_empty(), "[sysctl_audit] ignore silences it");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn judge_tells_once_then_changes_and_fixes() {
        let cfg = SysctlCfg::default();
        let mut b = None;
        let good = audit(&hardened(), &Host::default(), vec![], &cfg, T);
        let f = judge(&mut b, &good, &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].message, "sysctl audit: no problems");
        assert!(!f[0].notify, "nothing wrong: only logged");
        assert!(judge(&mut b, &good, &cfg).is_empty(), "nothing new");

        let mut weak = hardened();
        weak.insert("fs.protected_symlinks".into(), "0".into());
        let r = audit(&weak, &Host::default(), vec![], &cfg, T + time::SEC);
        let f = judge(&mut b, &r, &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].notify);
        assert!(f[0].evidence.iter().any(|e| e == "changed: fs.protected_symlinks: 1 -> 0"), "{:?}", f[0].evidence);
        // reminded after `remind`
        let later = audit(&weak, &Host::default(), vec![], &cfg, T + 8 * 86_400 * time::SEC);
        let f = judge(&mut b, &later, &cfg);
        assert_eq!(f.len(), 1);
        assert!(f[0].message.starts_with("sysctl audit: still open"));
        // fixed
        let f = judge(&mut b, &audit(&hardened(), &Host::default(), vec![], &cfg, T + 9 * 86_400 * time::SEC), &cfg);
        assert_eq!(f.len(), 1);
        // with `sysctl -w` alone: no sysctl.d file keeps it
        assert_eq!(
            f[0].message,
            "sysctl audit: fixed: fs.protected_symlinks; no sysctl.d file keeps fs.protected_symlinks after a reboot \
             (`vpsfort sysctl-audit --conf` prints the lines)"
        );
        // a value that changes without a new problem
        let mut other = hardened();
        other.insert("kernel.kptr_restrict".into(), "2".into());
        let f = judge(&mut b, &audit(&other, &Host::default(), vec![], &cfg, T + 10 * 86_400 * time::SEC), &cfg);
        assert_eq!(f.len(), 1);
        assert!(f[0].message.starts_with("sysctls changed, no new problems: kernel.kptr_restrict: 1 -> 2"), "{}", f[0].message);
    }
}
