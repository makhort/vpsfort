//! A small kernel-hardening audit (`[sysctl_audit]`): the sysctls that matter for a server
//! exposed to the internet, read from `/proc/sys` hourly and checked against good practice,
//! in the SSH audit's style. The first reading tells everything; then a new or worse problem
//! is an alert with the values that changed, a value that weakens without a new problem is
//! an info message, fixed problems are told, and open high problems are reminded weekly. A
//! tenth of what Lynis checks, with no benchmark or score: the handful of settings an intruder
//! or a careless tool changes, and the ones that leave a kernel open to a local user.

use std::collections::BTreeMap;
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
        }
    }
}

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

/// Judges the values read.
pub fn audit(values: &BTreeMap<String, String>, router: bool, errors: Vec<String>, cfg: &SysctlCfg, now: Micros) -> SysctlReport {
    let mut issues = Vec::new();
    for c in CHECKS {
        let Some(v) = values.get(c.key) else { continue };
        let Ok(n) = v.parse::<i64>() else {
            issues.push(Issue {
                id: c.key.to_string(),
                severity: Severity::Info,
                message: format!("{} is '{v}', not a number", c.key),
                fix: String::new(),
            });
            continue;
        };
        let (ok, want, severity) = match c.want {
            Want::Min(m) => (n >= m, m, c.severity),
            Want::Exactly(m) => (n == m, m, c.severity),
            Want::ZeroUnlessRouter => (n == 0, 0, if router { Severity::Info } else { c.severity }),
        };
        if ok {
            continue;
        }
        let because = if matches!(c.want, Want::ZeroUnlessRouter) && router {
            " (expected here: a VPN, container or bridge interface exists)".to_string()
        } else {
            String::new()
        };
        issues.push(Issue {
            id: c.key.to_string(),
            severity,
            message: format!("{} = {v}: {}{because}", c.key, c.why),
            fix: if matches!(c.want, Want::ZeroUnlessRouter) && router {
                String::new()
            } else {
                format!("sysctl -w {}={want}, and the same line in /etc/sysctl.d/90-hardening.conf", c.key)
            },
        });
    }
    let ignored = |i: &Issue| cfg.ignore.iter().any(|x| x == &i.id);
    issues.retain(|i| !ignored(i));
    SysctlReport { read: now, router, issues, settings: values.clone(), errors }
}

pub fn scan(cfg: &SysctlCfg, now: Micros) -> SysctlReport {
    let (values, errors, unreadable) = collect(cfg);
    let mut r = audit(&values, router_interfaces(&cfg.net_class), errors, cfg, now);
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
        out.push(finding(
            format!("sysctl-audit-fixed:{now}"),
            Severity::Info,
            format!("sysctl audit: fixed: {}", names.join(", ")),
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

    #[test]
    fn a_hardened_host_has_no_problems_and_a_stock_one_has() {
        let cfg = SysctlCfg::default();
        let r = audit(&hardened(), false, vec![], &cfg, T);
        assert!(r.issues.is_empty(), "{:?}", r.issues);
        assert_eq!(r.summary(), format!("{} sysctls (host): no problems", CHECKS.len()));

        // Debian's stock values on a plain VPS
        let mut stock = hardened();
        stock.insert("kernel.sysrq".into(), "438".into());
        stock.insert("kernel.kptr_restrict".into(), "0".into());
        stock.insert("fs.protected_symlinks".into(), "0".into());
        stock.insert("net.ipv4.ip_forward".into(), "1".into());
        stock.insert("kernel.yama.ptrace_scope".into(), "x".into());
        let r = audit(&stock, false, vec![], &cfg, T);
        let ids: Vec<&str> = r.issues.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(
            ids,
            ["net.ipv4.ip_forward", "kernel.kptr_restrict", "kernel.yama.ptrace_scope", "kernel.sysrq", "fs.protected_symlinks"]
        );
        assert_eq!(r.worst(), Some(Severity::High));
        assert!(r.issues[0].message.contains("forwards IPv4"), "{}", r.issues[0].message);
        assert!(r.issues[0].fix.contains("sysctl -w net.ipv4.ip_forward=0"));
        assert_eq!(r.concerns().len(), 3, "notes are left out of the digest");
        // the same on a router: forwarding is a note without a fix
        let r = audit(&stock, true, vec![], &cfg, T);
        assert_eq!(r.issues[0].severity, Severity::Info);
        assert!(r.issues[0].fix.is_empty());
        assert!(r.summary().contains("(router)"));
        // ignored ids
        let cfg = SysctlCfg { ignore: vec!["kernel.sysrq".into()], ..SysctlCfg::default() };
        assert!(!audit(&stock, false, vec![], &cfg, T).issues.iter().any(|i| i.id == "kernel.sysrq"));
    }

    #[test]
    fn collect_reads_proc_sys_and_skips_missing_keys() {
        let d = std::env::temp_dir().join(format!("lg-sysctl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("net/ipv4")).unwrap();
        std::fs::write(d.join("net/ipv4/ip_forward"), "1\n").unwrap();
        std::fs::write(d.join("net/ipv4/tcp_syncookies"), "1\n").unwrap();
        let cfg = SysctlCfg { proc_sys: d.clone(), net_class: d.join("none"), ..SysctlCfg::default() };
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
        let cfg = SysctlCfg { proc_sys: d.clone(), net_class: d.join("none"), ..SysctlCfg::default() };
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
        let good = audit(&hardened(), false, vec![], &cfg, T);
        let f = judge(&mut b, &good, &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].message, "sysctl audit: no problems");
        assert!(!f[0].notify, "nothing wrong: only logged");
        assert!(judge(&mut b, &good, &cfg).is_empty(), "nothing new");

        let mut weak = hardened();
        weak.insert("fs.protected_symlinks".into(), "0".into());
        let r = audit(&weak, false, vec![], &cfg, T + time::SEC);
        let f = judge(&mut b, &r, &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].notify);
        assert!(f[0].evidence.iter().any(|e| e == "changed: fs.protected_symlinks: 1 -> 0"), "{:?}", f[0].evidence);
        // reminded after `remind`
        let later = audit(&weak, false, vec![], &cfg, T + 8 * 86_400 * time::SEC);
        let f = judge(&mut b, &later, &cfg);
        assert_eq!(f.len(), 1);
        assert!(f[0].message.starts_with("sysctl audit: still open"));
        // fixed
        let f = judge(&mut b, &audit(&hardened(), false, vec![], &cfg, T + 9 * 86_400 * time::SEC), &cfg);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].message, "sysctl audit: fixed: fs.protected_symlinks");
        // a value that changes without a new problem
        let mut other = hardened();
        other.insert("kernel.kptr_restrict".into(), "2".into());
        let f = judge(&mut b, &audit(&other, false, vec![], &cfg, T + 10 * 86_400 * time::SEC), &cfg);
        assert_eq!(f.len(), 1);
        assert!(f[0].message.starts_with("sysctls changed, no new problems: kernel.kptr_restrict: 1 -> 2"), "{}", f[0].message);
    }
}
