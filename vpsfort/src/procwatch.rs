//! Process watch: what a break-in runs, read from `/proc` every interval.
//!
//! - **Outbound connections:** TCP connections this host opened (to a port not listening
//!   here), by program and remote port. The pairs are learned for `learn`; afterwards a new
//!   one (a miner reaching its pool, a reverse shell, data going somewhere new) is reported
//!   once and becomes normal. A shell or a network tool (`bash`, `nc`, `socat`) talking out,
//!   or anything reaching a port miners and reverse shells use, is always high.
//! - **Programs running from where nothing should run:** `/tmp`, `/var/tmp`, `/dev/shm`,
//!   memory only (`memfd:`), or a program file deleted after start outside the system's
//!   package directories (an upgrade replacing `/usr/sbin/sshd` is the patch status's business).
//!
//! - **Baselines of what else a break-in leaves behind:** the kernel modules loaded (a
//!   rootkit is one), the containers running (a new one, or one that is privileged, on the
//!   host's network or PID namespace, or with a risky mount: read from Docker's own files,
//!   no `docker` command), and WireGuard's peers (`wg show`: a new peer is a new way into
//!   the VPN). Each is learned for `learn`, then something new is reported once.
//!
//! Connections inside containers have network namespaces of their own and aren't seen, and
//! neither is a WireGuard interface inside a container.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::cronwatch::Finding;
use crate::engine::{is_non_global, Severity};
use crate::time::{self, Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcCfg {
    pub enabled: bool,
    pub interval: Dur,
    /// Outbound (program, port) pairs seen in this time after the first scan are normal.
    pub learn: Dur,
    /// Remote ports that are always worth a high alert: mining pools, reverse shells.
    pub suspicious_ports: Vec<u16>,
    /// Programs (as `/proc/<pid>/comm` names them) left out of both checks.
    pub ignore_processes: Vec<String>,
    /// Remote ports whose connections aren't watched (but shells and network tools are,
    /// whatever the port).
    pub ignore_ports: Vec<u16>,
    /// Report each new (program, remote port) pair after `learn`. False: only shells and
    /// network tools talking out, and `suspicious_ports` (a desktop, where every new app talks).
    pub new_outbound: bool,
    /// AppImages run from a FUSE mount in `/tmp/.mount_*`: not reported as programs running
    /// from a temporary directory. A program merely in a directory of that name still is.
    pub allow_appimages: bool,
    /// Kernel modules (`/proc/modules`): one loaded after `learn` that was never seen before
    /// is high (rootkits live in modules; so do the drivers an upgrade brings).
    pub kernel_modules: bool,
    /// Containers, from Docker's files under `docker_dir`: a new one running after `learn`
    /// is a warning, and one that is privileged, on the host's network or PID namespace, or
    /// mounts the Docker socket, `/`, `/etc` and the like is high.
    pub containers: bool,
    pub docker_dir: PathBuf,
    /// WireGuard peers (`wg show all dump`): a new peer after `learn` is high.
    pub wireguard_peers: bool,
    pub wg: PathBuf,
}

impl Default for ProcCfg {
    fn default() -> Self {
        ProcCfg {
            enabled: true,
            interval: Dur(60),
            learn: Dur(3 * 86_400),
            suspicious_ports: vec![1337, 3333, 4444, 5555, 6666, 7777, 8333, 9999, 14433, 14444, 31337, 45560, 45700],
            ignore_processes: vec![],
            ignore_ports: vec![],
            new_outbound: true,
            allow_appimages: false,
            kernel_modules: true,
            containers: true,
            docker_dir: "/var/lib/docker/containers".into(),
            wireguard_peers: true,
            wg: "/usr/bin/wg".into(),
        }
    }
}

impl ProcCfg {
    pub fn validate(&self) -> Result<()> {
        if self.enabled && self.interval.0 < 10 {
            bail!("[procwatch] interval must be at least 10s");
        }
        Ok(())
    }
}

/// Programs whose talking out is a reverse shell or a tunnel.
const SHELLS: [&str; 12] = ["sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "nc", "ncat", "netcat", "socat", "telnet"];

/// An outbound TCP connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conn {
    pub process: String,
    pub pid: u32,
    pub uid: u32,
    pub remote: IpAddr,
    pub port: u16,
    /// Made inside a container (a network namespace of its own): its id, or the namespace.
    pub container: Option<String>,
}

/// A program running from where nothing should run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Odd {
    pub process: String,
    pub pid: u32,
    pub uid: u32,
    pub exe: String,
    pub why: &'static str,
    /// In a mount namespace of its own (a container).
    pub container: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ProcReport {
    pub scanned: Micros,
    /// False where there is no `/proc` (nothing to judge).
    pub available: bool,
    pub outbound: Vec<Conn>,
    pub odd: Vec<Odd>,
    /// Loaded kernel modules (None: not read).
    pub modules: Option<Vec<String>>,
    /// Containers Docker knows (None: not read, or no Docker here).
    pub containers: Option<Vec<Container>>,
    /// WireGuard's peers (None: not read, or no `wg` here).
    pub wg_peers: Option<Vec<WgPeer>>,
}

/// A container as Docker's `config.v2.json` and `hostconfig.json` describe it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Container {
    pub name: String,
    pub image: String,
    pub running: bool,
    pub privileged: bool,
    pub host_network: bool,
    pub host_pid: bool,
    /// Host paths it mounts that reach the host itself: `/`, `/etc`, the Docker socket, ...
    pub risky_mounts: Vec<String>,
    /// Capabilities added that are as good as root on the host.
    pub risky_caps: Vec<String>,
}

impl Container {
    /// What makes it worth a high alert, in words; empty for an ordinary container.
    pub fn risks(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.privileged {
            v.push("privileged".to_string());
        }
        if self.host_network {
            v.push("on the host's network".to_string());
        }
        if self.host_pid {
            v.push("in the host's PID namespace".to_string());
        }
        for m in &self.risky_mounts {
            v.push(format!("mounts {m}"));
        }
        for c in &self.risky_caps {
            v.push(format!("with CAP_{c}"));
        }
        v
    }
}

/// One WireGuard peer, as `wg show all dump` lists it (the interface's own keys are never kept).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WgPeer {
    pub iface: String,
    /// The peer's public key (base64).
    pub key: String,
    pub endpoint: String,
    pub allowed_ips: String,
}

/// The accepted state, persisted across restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcBaseline {
    pub learning_until: Micros,
    #[serde(default)]
    pub armed: bool,
    /// (program, remote port)
    pub pairs: BTreeSet<(String, u16)>,
    #[serde(default)]
    pub modules: BTreeSet<String>,
    /// Containers by name, each with the risks it had when learned: a recreated container
    /// (an update: new image, same name) is no news, a new risk is.
    #[serde(default)]
    pub containers: BTreeMap<String, Vec<String>>,
    /// `interface key` per WireGuard peer.
    #[serde(default)]
    pub wg_peers: BTreeSet<String>,
}

/// Summary for `status` and the dashboard.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcView {
    pub scanned: Micros,
    pub learning_until: Micros,
    pub pairs: usize,
    pub outbound: usize,
    /// Known kernel modules, containers and WireGuard peers; None where that baseline is
    /// off or can't be read.
    #[serde(default)]
    pub modules: Option<usize>,
    #[serde(default)]
    pub containers: Option<usize>,
    #[serde(default)]
    pub wg_peers: Option<usize>,
}

/// Most entries each baseline keeps: beyond, new ones are still reported, not learned.
const MAX_MODULES: usize = 2000;
const MAX_CONTAINERS: usize = 500;
const MAX_WG_PEERS: usize = 5000;

/// Most (program, port) pairs kept: beyond, new ones are still reported, not learned.
const MAX_PAIRS: usize = 2000;
/// Connections read per scan, and new ones reported one by one per scan (a host scanning
/// out gives thousands): the rest are summed up in one more alert.
const MAX_CONNS: usize = 5000;
const MAX_REPORTED: usize = 20;

/// An established or opening TCP connection: (local port, remote address, remote port, inode).
pub type Socket = (u16, IpAddr, u16, u64);

/// Established and opening TCP connections from `/proc/net/tcp{,6}` text, and the ports
/// listening.
pub fn parse_tcp(text: &str) -> (Vec<Socket>, BTreeSet<u16>) {
    let (mut conns, mut listening) = (Vec::new(), BTreeSet::new());
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let local_port = f[1].rsplit_once(':').and_then(|(_, p)| u16::from_str_radix(p, 16).ok());
        let Some(lp) = local_port else { continue };
        match f[3] {
            "0A" => {
                listening.insert(lp);
            }
            // ESTABLISHED, SYN_SENT
            "01" | "02" => {
                let Some((addr, port)) = f[2].split_once(':') else { continue };
                let (Some(remote), Ok(rp), Ok(inode)) =
                    (crate::exposure::parse_hex_addr(addr), u16::from_str_radix(port, 16), f[9].parse::<u64>())
                else {
                    continue;
                };
                conns.push((lp, remote, rp, inode));
            }
            _ => {}
        }
    }
    (conns, listening)
}

/// Who owns a socket: (pid, program name, uid).
fn socket_owners(proc: &Path) -> HashMap<u64, (u32, String, u32)> {
    let mut owners = HashMap::new();
    let Ok(procs) = std::fs::read_dir(proc) else { return owners };
    for p in procs.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else { continue };
        let mut who: Option<(String, u32)> = None;
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else { continue };
            let Some(inode) = target.to_str().and_then(|t| t.strip_prefix("socket:[")?.strip_suffix(']')?.parse::<u64>().ok()) else {
                continue;
            };
            let (name, uid) = who.get_or_insert_with(|| (comm(&p.path()), uid_of(&p.path())));
            owners.entry(inode).or_insert_with(|| (pid, name.clone(), *uid));
        }
    }
    owners
}

fn comm(dir: &Path) -> String {
    // any user names their own processes: no control characters into alerts
    std::fs::read_to_string(dir.join("comm")).map_or_else(|_| "?".into(), |c| crate::event::clean(c.trim(), 32))
}

fn uid_of(dir: &Path) -> u32 {
    std::fs::read_to_string(dir.join("status"))
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:").and_then(|r| r.split_whitespace().next()?.parse().ok())))
        .unwrap_or(u32::MAX)
}

/// Where packages put programs: a deleted file there was replaced by an upgrade.
/// Where an update replaces a running program's file: the system's, and Snap's and Flatpak's
/// (as an app sees itself, `/app`).
const SYSTEM_DIRS: [&str; 9] = ["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/lib32/", "/libx32/", "/snap/", "/app/"];
const TEMP_DIRS: [&str; 5] = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/dev/mqueue/"];

/// Why a program at `exe` (as `/proc/<pid>/exe` names it) shouldn't run, if it shouldn't.
pub fn odd_exe(exe: &str) -> Option<&'static str> {
    let deleted = exe.ends_with(" (deleted)");
    let path = exe.strip_suffix(" (deleted)").unwrap_or(exe);
    if path.starts_with("/memfd:") {
        // runc runs itself from a sealed memory copy while it starts a container
        return (!path.starts_with("/memfd:runc")).then_some("runs from memory only (memfd), with no file on disk");
    }
    if TEMP_DIRS.iter().any(|d| path.starts_with(d)) {
        return Some(if deleted { "ran from a temporary directory, and its file was deleted" } else { "runs from a temporary directory" });
    }
    if deleted && !SYSTEM_DIRS.iter().any(|d| path.starts_with(d)) {
        return Some("its program file was deleted after it started");
    }
    None
}

fn programs(proc: &Path, ignore: &[String], allow_appimages: bool) -> Vec<Odd> {
    let mut out = Vec::new();
    let own_ns = std::fs::read_link(proc.join("self/ns/mnt")).ok();
    let Ok(rd) = std::fs::read_dir(proc) else { return out };
    for p in rd.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let dir = p.path();
        // kernel threads have no program
        let Ok(exe) = std::fs::read_link(dir.join("exe")) else { continue };
        // judged as the kernel names it: cut to what is shown, a long path lost its
        // " (deleted)", and with it the reason to report it
        let raw = exe.display().to_string();
        let exe = crate::event::clean(&raw, 300);
        // runc's memory copy is root's: the same name on another user's is anyone's choice
        let borrowed_name = || {
            (raw.starts_with("/memfd:runc") && uid_of(&dir) != 0)
                .then_some("runs from memory only (memfd), under runc's name but not as root")
        };
        let Some(why) = odd_exe(&raw).or_else(borrowed_name) else { continue };
        if allow_appimages && appimage(&dir, &exe) {
            continue;
        }
        let process = comm(&dir);
        if ignore.contains(&process) && roots_program(&dir) {
            continue;
        }
        let container = own_ns.is_some() && std::fs::read_link(dir.join("ns/mnt")).ok() != own_ns;
        out.push(Odd { process, pid, uid: uid_of(&dir), exe, why, container });
        if out.len() >= 100 {
            break;
        }
    }
    out
}

/// Reads outbound connections and odd programs from `/proc` (Linux).
pub fn scan(cfg: &ProcCfg) -> ProcReport {
    scan_with(cfg, Path::new(""))
}

/// The connections this host opened itself, as conntrack-tools' `conntrack` lists them:
/// (local port, remote address, remote port) of each flow's original direction. None
/// without the program.
fn opened_here(conntrack: &Path) -> Option<std::collections::HashSet<(u16, IpAddr, u16)>> {
    if conntrack.as_os_str().is_empty() || !conntrack.exists() {
        return None;
    }
    // Only the flows that began at one of this host's addresses: a busy server's whole
    // table is its clients', megabytes of text every minute.
    let own: Vec<IpAddr> = crate::net::local_addresses()
        .into_iter()
        .filter(|ip| match ip {
            IpAddr::V4(a) => !a.is_loopback(),
            IpAddr::V6(a) => !a.is_loopback() && a.segments()[0] & 0xffc0 != 0xfe80,
        })
        .take(16)
        .collect();
    let mut opened = std::collections::HashSet::new();
    let mut asked = false;
    for ip in own {
        let mut cmd = std::process::Command::new(conntrack);
        cmd.args(["-L", "-p", "tcp", "--orig-src", &ip.to_string()]);
        if ip.is_ipv6() {
            cmd.args(["-f", "ipv6"]);
        }
        if let Ok(out) = crate::proc::run(cmd, None, std::time::Duration::from_secs(10)) {
            if out.status.success() {
                asked = true;
                opened.extend(parse_conntrack(&String::from_utf8_lossy(&out.stdout)));
            }
        }
    }
    asked.then_some(opened)
}

/// `conntrack -L -p tcp`: `tcp 6 85 ESTABLISHED src=A dst=B sport=1 dport=2 src=B dst=A ...`.
/// The first `dst`, `sport` and `dport` are the original direction's: who opened it.
pub fn parse_conntrack(text: &str) -> std::collections::HashSet<(u16, IpAddr, u16)> {
    text.lines()
        .filter_map(|line| {
            let first = |key: &str| line.split_whitespace().find_map(|w| w.strip_prefix(key));
            let remote = first("dst=")?.parse::<IpAddr>().ok()?;
            Some((first("sport=")?.parse().ok()?, crate::net::normalize(remote), first("dport=")?.parse().ok()?))
        })
        .collect()
}

/// [`scan`], with the direction of connections from a listening port told by `conntrack`
/// (the path of conntrack-tools' program; empty: as before, they all count as accepted).
pub fn scan_with(cfg: &ProcCfg, conntrack: &Path) -> ProcReport {
    let proc = Path::new("/proc");
    let mut r = ProcReport { scanned: time::now(), ..Default::default() };
    let Ok(v4) = std::fs::read_to_string(proc.join("net/tcp")) else { return r };
    r.available = true;
    let v6 = std::fs::read_to_string(proc.join("net/tcp6")).unwrap_or_default();
    let (mut conns, mut listening) = parse_tcp(&v4);
    let (c6, l6) = parse_tcp(&v6);
    conns.extend(c6);
    listening.extend(l6);
    // A connection from a port that also listens is an accepted one, nearly always. But a
    // program that listens on a port can connect out from it too, and what it opened that
    // way used to count as accepted: unseen. `/proc/net/tcp` doesn't say who opened a
    // connection; conntrack does, so it is asked when there are such connections.
    let ambiguous = conns.iter().any(|(lp, ip, _, _)| listening.contains(lp) && !is_non_global(*ip));
    let opened = if ambiguous { opened_here(conntrack) } else { None };
    let outward_of = |conns: Vec<Socket>,
                      listening: &BTreeSet<u16>,
                      opened: Option<&std::collections::HashSet<(u16, IpAddr, u16)>>|
     -> Vec<(IpAddr, u16, u64)> {
        conns
            .into_iter()
            .filter(|(lp, ip, rp, _)| {
                !is_non_global(*ip)
                    && (!listening.contains(lp) || opened.is_some_and(|o| o.contains(&(*lp, crate::net::normalize(*ip), *rp))))
            })
            .map(|(_, ip, rp, inode)| (ip, rp, inode))
            .collect()
    };
    let mut outward: Vec<(IpAddr, u16, u64, Option<String>)> =
        outward_of(conns, &listening, opened.as_ref()).into_iter().map(|(a, p, i)| (a, p, i, None)).collect();
    // Containers have network namespaces of their own: their tables are read through one of
    // their processes (`/proc/<pid>/net/tcp` is that namespace's), socket inodes are global.
    for (ns, pid) in container_namespaces(proc) {
        let dir = proc.join(pid.to_string());
        let Ok(v4) = std::fs::read_to_string(dir.join("net/tcp")) else { continue };
        let v6 = std::fs::read_to_string(dir.join("net/tcp6")).unwrap_or_default();
        let (mut conns, mut listening) = parse_tcp(&v4);
        let (c6, l6) = parse_tcp(&v6);
        conns.extend(c6);
        listening.extend(l6);
        let label = container_id(&dir).unwrap_or(ns);
        // (a container's flows are in the host's table as the host forwards them: not asked)
        outward.extend(outward_of(conns, &listening, None).into_iter().map(|(a, p, i)| (a, p, i, Some(label.clone()))));
    }
    if !outward.is_empty() {
        let owners = socket_owners(proc);
        let mut seen = std::collections::HashSet::new();
        for (remote, port, inode, container) in outward {
            let Some((pid, process, uid)) = owners.get(&inode).cloned() else { continue };
            // a name on the list excuses a program root installed, not one that took the name
            let excused = if named(cfg, &process) {
                roots_program(&proc.join(pid.to_string())) || ignored_port(cfg, &process, port)
            } else {
                ignored_port(cfg, &process, port)
            };
            if excused || !seen.insert((process.clone(), remote, port)) {
                continue;
            }
            r.outbound.push(Conn { process, pid, uid, remote, port, container });
            if r.outbound.len() >= MAX_CONNS {
                break;
            }
        }
    }
    r.odd = programs(proc, &cfg.ignore_processes, cfg.allow_appimages);
    if cfg.kernel_modules {
        r.modules = std::fs::read_to_string(proc.join("modules")).ok().map(|t| parse_modules(&t));
    }
    if cfg.containers {
        r.containers = read_containers(&cfg.docker_dir);
    }
    if cfg.wireguard_peers && cfg.wg.exists() {
        let mut cmd = std::process::Command::new(&cfg.wg);
        cmd.args(["show", "all", "dump"]);
        r.wg_peers = crate::proc::run(cmd, None, std::time::Duration::from_secs(10))
            .ok()
            .filter(|o| o.status.success())
            .map(|o| parse_wg_dump(&String::from_utf8_lossy(&o.stdout)));
    }
    r
}

/// Most container network namespaces read per scan.
const MAX_NAMESPACES: usize = 64;

/// The network namespaces other than the host's (`/proc/1/ns/net`), each with one process
/// in it: ("net:[4026532345]", pid).
fn container_namespaces(proc: &Path) -> Vec<(String, u32)> {
    let host = std::fs::read_link(proc.join("1/ns/net")).ok();
    let Ok(procs) = std::fs::read_dir(proc) else { return vec![] };
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for p in procs.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(ns) = std::fs::read_link(p.path().join("ns/net")) else { continue };
        if host.as_ref() == Some(&ns) || !seen.insert(ns.clone()) {
            continue;
        }
        out.push((ns.to_string_lossy().into_owned(), pid));
        if out.len() >= MAX_NAMESPACES {
            break;
        }
    }
    out
}

/// A container's short id from a process's cgroup (`docker-<id>.scope`, `/docker/<id>`,
/// `libpod-<id>`), when it is one.
pub fn container_id(dir: &Path) -> Option<String> {
    let cgroup = std::fs::read_to_string(dir.join("cgroup")).ok()?;
    container_id_in(&cgroup)
}

pub fn container_id_in(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        for part in line.split(['/', '-', '.']) {
            if part.len() == 64 && part.bytes().all(|b| b.is_ascii_hexdigit()) {
                let runtime = if line.contains("libpod") || line.contains("podman") { "podman" } else { "container" };
                return Some(format!("{runtime} {}", &part[..12]));
            }
        }
    }
    None
}

/// The names in `/proc/modules` (first field per line).
pub fn parse_modules(text: &str) -> Vec<String> {
    text.lines().filter_map(|l| l.split_whitespace().next()).filter(|n| !n.is_empty()).take(MAX_MODULES).map(String::from).collect()
}

/// Docker's containers from its own files: `<dir>/<id>/config.v2.json` (name, image, state)
/// and `hostconfig.json` (privileges, namespaces, mounts). None without the directory.
pub fn read_containers(dir: &Path) -> Option<Vec<Container>> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut out = Vec::new();
    for e in entries.flatten().take(MAX_CONTAINERS) {
        let p = e.path();
        let Ok(config) = std::fs::read(p.join("config.v2.json")) else { continue };
        let Ok(config) = serde_json::from_slice::<serde_json::Value>(&config) else { continue };
        let host = std::fs::read(p.join("hostconfig.json")).ok().and_then(|h| serde_json::from_slice::<serde_json::Value>(&h).ok());
        out.push(container_from_json(&config, host.as_ref()));
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Some(out)
}

/// Host paths a container must not reach: the whole host, its configuration, the Docker
/// socket (root on the host), and the system's programs.
const RISKY_MOUNTS: &[&str] = &[
    "/",
    "/etc",
    "/root",
    "/home",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/var/lib/docker",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run",
    "/run",
];
const RISKY_CAPS: &[&str] = &["ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH", "BPF", "SYS_BOOT"];

fn risky_mount(src: &str) -> bool {
    let src = src.trim_end_matches('/');
    let src = if src.is_empty() { "/" } else { src };
    RISKY_MOUNTS.iter().any(|r| src == *r || (*r != "/" && src.starts_with(&format!("{r}/")) && !src.starts_with("/dev/net")))
}

pub fn container_from_json(config: &serde_json::Value, host: Option<&serde_json::Value>) -> Container {
    let s = |v: Option<&serde_json::Value>| v.and_then(|v| v.as_str()).unwrap_or("").to_string();
    let host = host.or_else(|| config.get("HostConfig"));
    let mut c = Container {
        name: s(config.get("Name")).trim_start_matches('/').chars().take(100).collect(),
        image: s(config.pointer("/Config/Image")).chars().take(200).collect(),
        running: config.pointer("/State/Running").and_then(|v| v.as_bool()).unwrap_or(false),
        ..Default::default()
    };
    let Some(h) = host else { return c };
    c.privileged = h.get("Privileged").and_then(|v| v.as_bool()).unwrap_or(false);
    c.host_network = s(h.get("NetworkMode")) == "host";
    c.host_pid = s(h.get("PidMode")) == "host";
    for b in h.get("Binds").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|v| v.as_str()) {
        // "host:container[:options]"; a named volume has no leading slash
        let src = b.split(':').next().unwrap_or("");
        if src.starts_with('/') && risky_mount(src) && c.risky_mounts.len() < 20 {
            c.risky_mounts.push(src.to_string());
        }
    }
    for m in h.get("Mounts").and_then(|v| v.as_array()).into_iter().flatten() {
        if s(m.get("Type")) == "bind" {
            let src = s(m.get("Source"));
            if risky_mount(&src) && !c.risky_mounts.contains(&src) && c.risky_mounts.len() < 20 {
                c.risky_mounts.push(src);
            }
        }
    }
    for cap in h.get("CapAdd").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|v| v.as_str()) {
        let cap = cap.trim_start_matches("CAP_");
        if RISKY_CAPS.contains(&cap) {
            c.risky_caps.push(cap.to_string());
        }
    }
    c
}

/// `wg show all dump`: an interface line (5 fields, with its private key: dropped) and one
/// line of 9 fields per peer, tab-separated, the interface's name first on each.
pub fn parse_wg_dump(text: &str) -> Vec<WgPeer> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 9 || out.len() >= MAX_WG_PEERS {
            continue;
        }
        let clean = |s: &str| crate::event::clean(s, 120);
        out.push(WgPeer { iface: clean(f[0]), key: clean(f[1]), endpoint: clean(f[3]), allowed_ips: clean(f[4]) });
    }
    out
}

/// Connections not watched: of `ignore_processes`, and to `ignore_ports` unless a shell or
/// network tool makes them (a reverse shell on port 443 is still one).
#[cfg(test)]
fn ignored(cfg: &ProcCfg, process: &str, port: u16) -> bool {
    named(cfg, process) || ignored_port(cfg, process, port)
}

fn named(cfg: &ProcCfg, process: &str) -> bool {
    cfg.ignore_processes.iter().any(|p| p == process)
}

fn ignored_port(cfg: &ProcCfg, process: &str, port: u16) -> bool {
    cfg.ignore_ports.contains(&port) && !SHELLS.contains(&process)
}

/// Whether the program of `/proc/<pid>` (`dir`) is a file of root's that only root can
/// write. A process names itself (`comm`), so a name in `ignore_processes` alone would let
/// anything called `backup` or `firefox` talk to anyone unreported: the name counts for
/// what root installed, wherever that is (`/usr`, `/opt`, a Snap), deleted since or not.
fn roots_program(dir: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    std::fs::metadata(dir.join("exe")).is_ok_and(|m| m.uid() == 0 && m.permissions().mode() & 0o022 == 0)
}

/// Whether `path` is on a FUSE file system, as `mountinfo` (a process's
/// `/proc/<pid>/mountinfo`) shows its mounts: the longest mount point above it decides.
fn on_fuse(mountinfo: &str, path: &str) -> bool {
    let mut best: Option<(usize, bool)> = None;
    for line in mountinfo.lines() {
        // id parent major:minor root mountpoint options [optional...] - fstype source options
        let Some((left, right)) = line.split_once(" - ") else { continue };
        let Some(point) = left.split(' ').nth(4) else { continue };
        let point = point.replace("\\040", " ");
        let inside = path == point || path.starts_with(&format!("{}/", point.trim_end_matches('/')));
        if inside && best.is_none_or(|(len, _)| point.len() >= len) {
            best = Some((point.len(), right.split(' ').next().is_some_and(|t| t.starts_with("fuse"))));
        }
    }
    best.is_some_and(|(_, fuse)| fuse)
}

/// An AppImage: its program under `/tmp/.mount_*`, on the FUSE mount the AppImage made.
fn appimage(dir: &Path, exe: &str) -> bool {
    exe.starts_with("/tmp/.mount_")
        && !exe.ends_with(" (deleted)")
        && std::fs::read_to_string(dir.join("mountinfo")).is_ok_and(|m| on_fuse(&m, exe))
}

/// The local user (not root) a process runs as, if known: the owner of its findings.
fn local_user(uid: u32) -> Option<u32> {
    (uid != 0 && uid != u32::MAX).then_some(uid)
}

/// Compares a scan with the baseline, learns, and says what is new.
pub fn judge(baseline: &mut Option<ProcBaseline>, r: &ProcReport, cfg: &ProcCfg, place: &dyn Fn(IpAddr) -> Option<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    if !r.available {
        return out;
    }
    let now = r.scanned;
    let day = 86_400 * time::SEC;
    let b = baseline.get_or_insert_with(|| ProcBaseline { learning_until: now + cfg.learn.micros(), ..Default::default() });
    let learning = now < b.learning_until;
    for o in &r.odd {
        let (severity, inside) = if o.container { (Severity::Warning, " in a container") } else { (Severity::High, "") };
        out.push(Finding {
            key: format!("proc-exe:{}:{}", o.process, o.exe),
            every: day,
            severity,
            message: format!(
                "process {} (pid {}, uid {}){inside} {}: {} - check what it is (ls -l /proc/{}/exe; cat /proc/{}/cmdline)",
                o.process, o.pid, o.uid, o.why, o.exe, o.pid, o.pid
            ),
            evidence: vec![],
            notify: true,
            owner: local_user(o.uid),
            // the program as it runs: readable there even when its file was deleted
            files: vec![format!("/proc/{}/exe", o.pid)],
        });
    }
    let (mut more, mut more_uids): (Vec<String>, BTreeSet<u32>) = (Vec::new(), BTreeSet::new());
    let daemon = std::process::id();
    // by process and not by name, which anything can take: vpsfort's own connections (its
    // cluster peers, feeds, lookups) are short, so a scan may first catch one months in
    for c in r.outbound.iter().filter(|c| c.pid != daemon) {
        let shell = SHELLS.contains(&c.process.as_str());
        let odd_port = cfg.suspicious_ports.contains(&c.port);
        let pair = (c.process.clone(), c.port);
        let known = b.pairs.contains(&pair);
        if !shell && !odd_port && (known || learning || !cfg.new_outbound) {
            if !known && b.pairs.len() < MAX_PAIRS {
                b.pairs.insert(pair);
            }
            continue;
        }
        let reported = out.iter().filter(|f| f.key.starts_with("proc-out:")).count();
        if reported >= MAX_REPORTED {
            if more.len() < 30 {
                more.push(format!("{} (pid {}) to {}:{}", c.process, c.pid, c.remote, c.port));
            }
            more_uids.insert(c.uid);
            if !shell && !odd_port && b.pairs.len() < MAX_PAIRS {
                b.pairs.insert(pair);
            }
            continue;
        }
        let at = place(c.remote).map(|p| format!(" [{p}]")).unwrap_or_default();
        let at = match &c.container {
            Some(id) => format!("{at} (in {id})"),
            None => at,
        };
        let (severity, why) = match (shell, odd_port) {
            (true, _) => (Severity::High, " - a shell or network tool talking out: a reverse shell?"),
            (_, true) => (Severity::High, " - a port miners and reverse shells use"),
            _ => (Severity::Warning, ""),
        };
        out.push(Finding {
            key: format!("proc-out:{}:{}", c.process, c.port),
            every: if shell || odd_port { 3600 * time::SEC } else { 0 },
            severity,
            message: format!("new outbound connection: {} (pid {}, uid {}) to {}:{}{at}{why}", c.process, c.pid, c.uid, c.remote, c.port),
            evidence: vec![],
            notify: true,
            owner: local_user(c.uid),
            files: vec![],
        });
        if !shell && !odd_port && b.pairs.len() < MAX_PAIRS {
            b.pairs.insert(pair);
        }
    }
    if !more.is_empty() {
        out.push(Finding {
            key: "proc-out-more".into(),
            every: 3600 * time::SEC,
            severity: Severity::High,
            message: format!("and more new outbound connections in the same minute (a scan from this host?): {}", more.join(", ")),
            evidence: vec![],
            notify: true,
            // one user's own, if they all are
            owner: (more_uids.len() == 1).then(|| more_uids.first().copied().and_then(local_user)).flatten(),
            files: vec![],
        });
    }
    let finding = |key: String, severity: Severity, message: String| Finding {
        key,
        every: day,
        severity,
        message,
        evidence: vec![],
        notify: true,
        owner: None,
        files: vec![],
    };
    for m in r.modules.iter().flatten() {
        if b.modules.contains(m) {
            continue;
        }
        if !learning {
            out.push(finding(
                format!("proc-mod:{m}"),
                Severity::High,
                format!(
                    "kernel module {m} loaded, never seen before: a rootkit lives in one, and so does a driver an upgrade \
                     brought - lsmod; modinfo {m}; journalctl -k | grep -i {m}"
                ),
            ));
        }
        if b.modules.len() < MAX_MODULES {
            b.modules.insert(m.clone());
        }
    }
    for c in r.containers.iter().flatten().filter(|c| c.running) {
        let risks = c.risks();
        match b.containers.get_mut(&c.name) {
            None => {
                if !learning {
                    let how = if risks.is_empty() { String::new() } else { format!(", {}", risks.join(", ")) };
                    out.push(finding(
                        format!("proc-ctr:{}", c.name),
                        if risks.is_empty() { Severity::Warning } else { Severity::High },
                        format!("new container {} ({}) is running{how} - docker inspect {}", c.name, c.image, c.name),
                    ));
                }
                if b.containers.len() < MAX_CONTAINERS {
                    b.containers.insert(c.name.clone(), risks);
                }
            }
            Some(known) => {
                let new: Vec<&String> = risks.iter().filter(|r| !known.contains(r)).collect();
                if !new.is_empty() {
                    if !learning {
                        out.push(finding(
                            format!("proc-ctr-risk:{}", c.name),
                            Severity::High,
                            format!(
                                "container {} ({}) now runs {} - it reaches the host that way; docker inspect {}",
                                c.name,
                                c.image,
                                new.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                                c.name
                            ),
                        ));
                    }
                    known.extend(new.into_iter().cloned());
                }
            }
        }
    }
    for p in r.wg_peers.iter().flatten() {
        let id = format!("{} {}", p.iface, p.key);
        if b.wg_peers.contains(&id) {
            continue;
        }
        if !learning {
            let endpoint =
                if p.endpoint.is_empty() || p.endpoint == "(none)" { String::new() } else { format!(", endpoint {}", p.endpoint) };
            out.push(finding(
                format!("proc-wg:{id}"),
                Severity::High,
                format!(
                    "new WireGuard peer on {}: {} (allowed IPs {}{endpoint}): a new way into the VPN, unless you added it - wg show {}",
                    p.iface, p.key, p.allowed_ips, p.iface
                ),
            ));
        }
        if b.wg_peers.len() < MAX_WG_PEERS {
            b.wg_peers.insert(id);
        }
    }
    if !learning && !b.armed {
        b.armed = true;
        let more = [
            r.modules.as_ref().map(|_| format!("{} kernel modules", b.modules.len())),
            r.containers.as_ref().map(|_| format!("{} containers", b.containers.len())),
            r.wg_peers.as_ref().map(|_| format!("{} WireGuard peers", b.wg_peers.len())),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let more = if more.is_empty() { String::new() } else { format!(" and {}", more.join(", ")) };
        out.push(Finding {
            key: "proc-armed".into(),
            every: day,
            severity: Severity::Info,
            message: format!(
                "process watch learned {} outbound (program, port) pairs{more}; new ones are reported from now on",
                b.pairs.len()
            ),
            evidence: vec![],
            notify: false,
            owner: None,
            files: vec![],
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_files_and_wg_dump_are_read() {
        let config: serde_json::Value = serde_json::from_str(
            r#"{"Name":"/nextcloud-aio-mastercontainer","State":{"Running":true},"Config":{"Image":"nextcloud/all-in-one:latest"}}"#,
        )
        .unwrap();
        let host: serde_json::Value = serde_json::from_str(
            r#"{"Binds":["/var/run/docker.sock:/var/run/docker.sock:ro","nextcloud_aio_mastercontainer:/mnt/docker-aio-config","/srv/data:/data"],
                "NetworkMode":"host","PidMode":"","Privileged":false,"CapAdd":["NET_ADMIN","CAP_SYS_MODULE"],
                "Mounts":[{"Type":"bind","Source":"/etc/localtime","Target":"/etc/localtime"},{"Type":"volume","Source":"x"}]}"#,
        )
        .unwrap();
        let c = container_from_json(&config, Some(&host));
        assert_eq!(
            (c.name.as_str(), c.image.as_str(), c.running, c.privileged, c.host_network, c.host_pid),
            ("nextcloud-aio-mastercontainer", "nextcloud/all-in-one:latest", true, false, true, false)
        );
        assert_eq!(c.risky_mounts, ["/var/run/docker.sock", "/etc/localtime"]);
        assert_eq!(c.risky_caps, ["SYS_MODULE"]);
        assert_eq!(c.risks(), ["on the host's network", "mounts /var/run/docker.sock", "mounts /etc/localtime", "with CAP_SYS_MODULE"]);
        let plain =
            container_from_json(&serde_json::json!({"Name": "/web", "State": {"Running": false}, "Config": {"Image": "nginx"}}), None);
        assert!(plain.risks().is_empty() && !plain.running);
        assert!(
            risky_mount("/")
                && risky_mount("/etc/")
                && risky_mount("/run/docker.sock")
                && !risky_mount("/srv/www")
                && !risky_mount("/dev/net/tun")
        );

        let dump = "wg0\tPRIVATE\tPUBLIC\t51820\toff\nwg0\tpeerkey1=\t(none)\t203.0.113.5:4100\t10.8.0.2/32\t1700000000\t1\t2\toff\n\
                    wg0\tpeerkey2=\t(none)\t(none)\t10.8.0.3/32,fd00::3/128\t0\t0\t0\toff\nbroken line\n";
        let peers = parse_wg_dump(dump);
        assert_eq!(peers.len(), 2, "the interface line, with the private key, is dropped");
        assert_eq!(
            (peers[0].iface.as_str(), peers[0].key.as_str(), peers[0].endpoint.as_str(), peers[0].allowed_ips.as_str()),
            ("wg0", "peerkey1=", "203.0.113.5:4100", "10.8.0.2/32")
        );
        assert_eq!(parse_modules("wireguard 98304 0 - Live 0x0\nnf_tables 372736 1 nft_compat, Live 0x0\n\n"), ["wireguard", "nf_tables"]);
    }

    #[test]
    fn new_modules_containers_and_peers_after_learning() {
        let cfg = ProcCfg { learn: Dur(3600), ..Default::default() };
        let now = time::now();
        let ctr = |name: &str, host_network: bool| Container {
            name: name.into(),
            image: "img:1".into(),
            running: true,
            host_network,
            ..Default::default()
        };
        let peer =
            |key: &str| WgPeer { iface: "wg0".into(), key: key.into(), endpoint: "(none)".into(), allowed_ips: "10.8.0.2/32".into() };
        let first = ProcReport {
            scanned: now,
            available: true,
            modules: Some(vec!["wireguard".into(), "nf_tables".into()]),
            containers: Some(vec![ctr("web", false), Container { running: false, ..ctr("stopped", true) }]),
            wg_peers: Some(vec![peer("k1=")]),
            ..Default::default()
        };
        let mut b = None;
        let place = |_: IpAddr| None;
        assert!(judge(&mut b, &first, &cfg, &place).is_empty(), "learning: nothing said");
        let base = b.as_ref().unwrap();
        assert_eq!((base.modules.len(), base.containers.len(), base.wg_peers.len()), (2, 1, 1), "a stopped container isn't learned");

        let later = ProcReport {
            scanned: now + 2 * 3600 * time::SEC,
            available: true,
            modules: Some(vec!["wireguard".into(), "nf_tables".into(), "diamorphine".into()]),
            containers: Some(vec![
                ctr("web", true),
                Container { privileged: true, risky_mounts: vec!["/".into()], ..ctr("evil", false) },
                ctr("plain", false),
            ]),
            wg_peers: Some(vec![peer("k1="), peer("k2=")]),
            ..Default::default()
        };
        let f = judge(&mut b, &later, &cfg, &place);
        let got: Vec<(String, Severity)> = f.iter().map(|f| (f.key.clone(), f.severity)).collect();
        assert_eq!(
            got,
            [
                ("proc-mod:diamorphine".to_string(), Severity::High),
                ("proc-ctr-risk:web".into(), Severity::High),
                ("proc-ctr:evil".into(), Severity::High),
                ("proc-ctr:plain".into(), Severity::Warning),
                ("proc-wg:wg0 k2=".into(), Severity::High),
                ("proc-armed".into(), Severity::Info),
            ],
            "{f:#?}"
        );
        assert!(f[0].message.starts_with("kernel module diamorphine loaded, never seen before"), "{}", f[0].message);
        assert!(f[1].message.contains("container web (img:1) now runs on the host's network"), "{}", f[1].message);
        assert!(f[2].message.contains("new container evil (img:1) is running, privileged, mounts /"), "{}", f[2].message);
        assert!(f[4].message.contains("new WireGuard peer on wg0: k2= (allowed IPs 10.8.0.2/32)"), "{}", f[4].message);
        assert!(f[5].message.contains("3 kernel modules, 3 containers, 2 WireGuard peers"), "{}", f[5].message);
        // said once: the next scan with the same state is quiet
        let again = ProcReport { scanned: now + 3 * 3600 * time::SEC, ..later.clone() };
        assert!(judge(&mut b, &again, &cfg, &place).is_empty());
    }

    // (documentation addresses, which the public mirror keeps: it can't remap them in hex)
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0
   1: 0A0200C0:0016 0B6433C6:A1F2 01 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 100 0 0 10 0
   2: 0A0200C0:C350 08080808:01BB 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0 100 0 0 10 0
   3: 0A0200C0:C351 0B6433C6:115C 02 00000000:00000000 00:00000000 00000000     0        0 1004 1 0 100 0 0 10 0
";

    #[test]
    fn appimages_snaps_and_flatpaks() {
        let mountinfo = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
            30 22 0:27 / /tmp rw,nosuid,nodev shared:5 - tmpfs tmpfs rw\n\
            612 30 0:55 / /tmp/.mount_FooBar1 ro,nosuid,nodev,relatime shared:350 - fuse.Foo.AppImage Foo.AppImage ro,user_id=1000\n\
            613 30 0:56 / /tmp/my\\040dir rw shared:351 - fuse.sshfs host: rw\n";
        assert!(on_fuse(mountinfo, "/tmp/.mount_FooBar1/usr/bin/foo"), "the AppImage's own mount");
        assert!(!on_fuse(mountinfo, "/tmp/.mount_Fake/x"), "a directory merely named so, on /tmp's tmpfs");
        assert!(!on_fuse(mountinfo, "/tmp/.mount_FooBar10/x"), "a sibling with a longer name isn't inside");
        assert!(on_fuse(mountinfo, "/tmp/my dir/x"), "escaped spaces");
        assert!(!on_fuse(mountinfo, "/usr/bin/x"));
        // updated while running: Snap's and Flatpak's places are like the system's
        assert_eq!(odd_exe("/snap/firefox/5000/usr/lib/firefox/firefox (deleted)"), None);
        assert_eq!(odd_exe("/app/bin/telegram (deleted)"), None);
        assert!(odd_exe("/opt/x/y (deleted)").is_some());
        assert!(odd_exe("/tmp/.mount_FooBar1/AppRun").is_some(), "without allow_appimages, as before");
    }

    #[test]
    fn ignored_ports_never_hide_shells() {
        let cfg = ProcCfg { ignore_ports: vec![443], ignore_processes: vec!["backup".into()], ..Default::default() };
        assert!(ignored(&cfg, "firefox", 443));
        assert!(!ignored(&cfg, "bash", 443) && !ignored(&cfg, "nc", 443), "a reverse shell on 443");
        assert!(ignored(&cfg, "backup", 22) && !ignored(&cfg, "firefox", 22));
    }

    /// On a desktop (`new_outbound = false`): every new app talks; only shells, network tools
    /// and the miners' and reverse shells' ports are reported.
    #[test]
    fn desktop_reports_only_dangerous_connections() {
        let cfg = ProcCfg { new_outbound: false, learn: Dur(0), ..Default::default() };
        let conn = |process: &str, port| Conn {
            process: process.into(),
            pid: 9,
            uid: 1000,
            remote: "8.8.8.8".parse().unwrap(),
            port,
            container: None,
        };
        let report = |outbound| ProcReport { scanned: time::SEC, available: true, outbound, ..Default::default() };
        let mut b = None;
        let f =
            judge(&mut b, &report(vec![conn("steam", 27015), conn("slack", 443), conn("bash", 443), conn("xmrig", 3333)]), &cfg, &|_| None);
        let keys: Vec<&str> = f.iter().map(|f| f.key.as_str()).filter(|k| k.starts_with("proc-out:")).collect();
        assert_eq!(keys, ["proc-out:bash:443", "proc-out:xmrig:3333"]);
        assert!(f.iter().filter(|f| f.key.starts_with("proc-out:")).all(|f| f.severity == Severity::High));
    }

    #[test]
    // /proc/net fixtures as a little-endian kernel prints them (x86_64, ARM)
    #[cfg(target_endian = "little")]
    fn outbound_connections_from_proc() {
        let (conns, listening) = parse_tcp(TCP);
        assert_eq!(listening.into_iter().collect::<Vec<_>>(), vec![22]);
        let out: Vec<(u16, String, u16)> = conns.iter().map(|(lp, ip, rp, _)| (*lp, ip.to_string(), *rp)).collect();
        assert_eq!(
            out,
            vec![(22, "198.51.100.11".into(), 41458), (50000, "8.8.8.8".into(), 443), (50001, "198.51.100.11".into(), 4444)],
            "the first is a connection to sshd, not an outbound one"
        );
    }

    #[test]
    fn container_ids_from_cgroups() {
        assert_eq!(
            container_id_in("0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n"),
            Some("container 0123456789ab".into())
        );
        assert_eq!(
            container_id_in("0::/user.slice/libpod-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope"),
            Some("podman 0123456789ab".into())
        );
        assert_eq!(container_id_in("0::/system.slice/sshd.service"), None);
    }

    #[test]
    fn odd_programs() {
        assert_eq!(odd_exe("/usr/sbin/sshd"), None);
        assert_eq!(odd_exe("/usr/sbin/sshd (deleted)"), None, "replaced by an upgrade");
        assert!(odd_exe("/tmp/.x/kworker").is_some());
        assert!(odd_exe("/dev/shm/a (deleted)").unwrap().contains("deleted"));
        assert!(odd_exe("/memfd:payload (deleted)").unwrap().contains("memfd"));
        assert_eq!(odd_exe("/memfd:runc_cloned:/proc/self/exe (deleted)"), None);
        assert!(odd_exe("/home/eve/miner (deleted)").is_some());
        assert_eq!(odd_exe("/opt/app/bin/app"), None);
    }

    #[test]
    fn learns_then_reports_new_pairs() {
        let h = 3600 * time::SEC;
        let cfg = ProcCfg::default();
        let conn = |process: &str, port| Conn {
            process: process.into(),
            pid: 7,
            uid: 0,
            remote: "8.8.8.8".parse().unwrap(),
            port,
            container: None,
        };
        let report = |t: Micros, outbound: Vec<Conn>| ProcReport { scanned: t, available: true, outbound, ..Default::default() };
        let none = |_| None;
        let mut b = None;
        assert!(judge(&mut b, &report(h, vec![conn("curl", 443), conn("beam.smp", 5269)]), &cfg, &none).is_empty(), "learning");
        // a reverse shell is high even while learning
        let f = judge(&mut b, &report(2 * h, vec![conn("bash", 9001)]), &cfg, &none);
        assert!(f.len() == 1 && f[0].severity == Severity::High && f[0].message.contains("reverse shell"), "{f:?}");
        let f = judge(&mut b, &report(80 * h, vec![conn("curl", 443)]), &cfg, &none);
        assert!(f.len() == 1 && f[0].message.contains("learned 2 outbound"), "{f:?}");
        let f = judge(&mut b, &report(81 * h, vec![conn("curl", 443), conn("curl", 8080), conn("xmrig", 3333)]), &cfg, &none);
        assert_eq!(f.len(), 2, "{f:?}");
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].message.starts_with("new outbound connection: curl (pid 7, uid 0) to 8.8.8.8:8080"));
        assert_eq!(f[1].severity, Severity::High);
        assert!(judge(&mut b, &report(82 * h, vec![conn("curl", 8080)]), &cfg, &none).is_empty(), "learned after its alert");
        // the daemon's own connection is nobody's business, another program of its name is
        let own = Conn { pid: std::process::id(), ..conn("vpsfort", 7946) };
        assert!(judge(&mut b, &report(83 * h, vec![own]), &cfg, &none).is_empty(), "the daemon itself");
        let f = judge(&mut b, &report(84 * h, vec![conn("vpsfort", 7946)]), &cfg, &none);
        assert!(f.len() == 1 && f[0].message.starts_with("new outbound connection: vpsfort (pid 7"), "{f:?}");
        assert!(judge(&mut None, &ProcReport::default(), &cfg, &none).is_empty(), "no /proc: nothing");
    }

    /// A finding about a process belongs to the local user it runs as (root's to nobody):
    /// the engine limits how many such alerts one user gets sent an hour.
    #[test]
    fn findings_name_the_processes_user() {
        let cfg = ProcCfg::default();
        let odd =
            |uid| Odd { process: "x".into(), pid: 9, uid, exe: "/tmp/x".into(), why: "runs from a temporary directory", container: false };
        let conn = |uid, port| Conn { process: "nc".into(), pid: 9, uid, remote: "8.8.8.8".parse().unwrap(), port, container: None };
        let r = ProcReport {
            scanned: time::SEC,
            available: true,
            outbound: vec![conn(1000, 4444), conn(0, 4445)],
            odd: vec![odd(1000), odd(0), odd(u32::MAX)],
            ..Default::default()
        };
        let f = judge(&mut None, &r, &cfg, &|_| None);
        let owners: Vec<Option<u32>> = f.iter().map(|f| f.owner).collect();
        assert_eq!(owners, [Some(1000), None, None, Some(1000), None], "{f:?}");
        assert_eq!(f[0].files, ["/proc/9/exe"], "the program as it runs, even deleted");
    }

    #[test]
    fn a_long_deleted_path_is_still_deleted() {
        let long = format!("/home/u/{}/tool (deleted)", "d".repeat(400));
        assert!(odd_exe(&long).unwrap().contains("deleted"));
        // cut to what is shown, the reason was gone
        assert_eq!(odd_exe(&crate::event::clean(&long, 300)), None);
    }

    #[test]
    fn conntrack_says_who_opened_a_connection() {
        // (two lines as `conntrack -L -p tcp` printed them on a node, 2026-11-11)
        let text = "tcp      6 85 TIME_WAIT src=192.0.2.10 dst=203.0.113.80 sport=46438 dport=7946 src=203.0.113.80 dst=192.0.2.10 sport=7946 dport=46438 [ASSURED] mark=0 use=1\n\
                    tcp      6 431999 ESTABLISHED src=198.51.100.7 dst=192.0.2.10 sport=51234 dport=443 src=192.0.2.10 dst=198.51.100.7 sport=443 dport=51234 [ASSURED] mark=0 use=1\n\
                    tcp      6 300 ESTABLISHED src=192.0.2.10 dst=198.51.100.99 sport=443 dport=4444 src=198.51.100.99 dst=192.0.2.10 sport=4444 dport=443 [ASSURED] mark=0 use=1\n\
                    conntrack v1.4.8 (conntrack-tools): 3 flow entries have been shown.\n";
        let opened = parse_conntrack(text);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(opened.len(), 3);
        // a client of the web server on 443: its flow began at the client
        assert!(!opened.contains(&(443, ip("198.51.100.7"), 51234)));
        // a connection made from port 443 by whatever listens there: this host opened it
        assert!(opened.contains(&(443, ip("198.51.100.99"), 4444)));
        assert!(opened.contains(&(46438, ip("203.0.113.80"), 7946)));
    }
}
