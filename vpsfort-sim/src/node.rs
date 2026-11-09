//! A simulated node: its state from a decision log (what vpsfort's own `tui --actions`
//! makes of it, plus what a log doesn't carry) or from a snapshot the console saved, served
//! on a console socket the way vpsfort's `[console]` socket answers: `snapshot`, `digest`
//! (vpsfort's own renderer), `abuse 24h` / `abuse 7d` (vpsfort's own live report) and
//! `honeypots 24h` / `honeypots 7d` (vpsfort's own reader of the log).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use vpsfort::engine::{DigestData, Snapshot};
use vpsfort::time::{self, Dur, Micros, SEC};

const HOUR: Micros = 3600 * SEC;
const DAY: Micros = 24 * HOUR;
/// Abuse reports are built again after this long, like vpsfort's.
const ABUSE_FRESH: Duration = Duration::from_secs(60);

/// A node of the simulated cluster.
pub struct Node {
    pub i: usize,
    pub name: String,
    pub addr: IpAddr,
    pub backend: String,
    /// The decision log served (shifted or as it was); None: the state is a snapshot.
    pub log: Option<PathBuf>,
    pub socket: PathBuf,
    /// The log's decisions, for the trickle and the fillers.
    acts: Vec<Value>,
    state: Mutex<Value>,
    abuse: Mutex<HashMap<String, (Instant, String)>>,
    seed: Mutex<u64>,
}

/// A name and public address, for the cluster view the fillers make.
pub struct Peer {
    pub name: String,
    pub addr: IpAddr,
}

fn rnd(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *seed >> 33
}

fn ts(a: &Value) -> Micros {
    a["ts"].as_i64().unwrap_or(0)
}
fn kind(a: &Value) -> &str {
    a["kind"].as_str().unwrap_or("")
}
fn msg(a: &Value) -> &str {
    a["message"].as_str().unwrap_or("")
}
fn is_peer(a: &Value) -> bool {
    msg(a).contains("(from peer ")
}
fn evidence_len(a: &Value) -> u64 {
    a["evidence"].as_array().map_or(0, |e| e.len() as u64)
}

/// Reads a log (JSON lines, or a rotated `.gz` copy), shifted by `delta` microseconds when
/// writing it to `dst` (as plain lines, whatever the source was).
pub fn read_log(src: &Path, dst: Option<(&Path, Micros)>) -> Result<Vec<Value>> {
    let f = std::fs::File::open(src).with_context(|| format!("reading {}", src.display()))?;
    let mut text = String::new();
    if src.extension().is_some_and(|e| e == "gz") {
        flate2::read::GzDecoder::new(f).read_to_string(&mut text).with_context(|| format!("reading {} (gzip)", src.display()))?;
    } else {
        (&f).read_to_string(&mut text).with_context(|| format!("reading {}", src.display()))?;
    }
    let mut lines: Vec<Value> = text.lines().filter(|l| !l.trim().is_empty()).filter_map(|l| serde_json::from_str(l).ok()).collect();
    if let Some((dst, delta)) = dst {
        let mut out = String::with_capacity(text.len());
        for a in &mut lines {
            if ts(a) > 0 {
                a["ts"] = json!(ts(a) + delta);
            }
            if let Some(u) = a["until"].as_i64() {
                a["until"] = json!(u + delta);
            }
            out.push_str(&serde_json::to_string(a)?);
            out.push('\n');
        }
        std::fs::write(dst, out).with_context(|| format!("writing {}", dst.display()))?;
    }
    Ok(lines)
}

/// The log's last decision time, for the shift.
pub fn last_time(acts: &[Value]) -> Micros {
    acts.iter().map(ts).max().unwrap_or(0)
}

/// "... [10x fw_block, 2x fw_tripwire]" -> the counts
fn counts_of(m: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    if let Some(start) = m.rfind('[') {
        if let Some(end) = m[start..].find(']') {
            for part in m[start + 1..start + end].split(", ") {
                if let Some((n, sig)) = part.split_once("x ") {
                    if let Ok(n) = n.parse::<u64>() {
                        out.insert(sig.to_string(), n);
                    }
                }
            }
        }
    }
    out
}

fn score(m: &str, key: &str) -> f64 {
    m.split_once(&format!("{key}=")).and_then(|(_, r)| r.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()).unwrap_or(0.0)
}

/// "ban 1.2.3.4 [Germany / Hetzner Online GmbH (AS24940)] for 1h" -> the place
fn place_of(m: &str) -> Option<String> {
    let start = m.find(" [")? + 2;
    let inner = &m[start..start + m[start..].find(']')?];
    (inner.contains(" / ") || inner.contains("(AS")).then(|| inner.to_string())
}

/// An offender entry (the dashboard's scores) from a ban decided here.
fn offender(a: &Value) -> Option<Value> {
    let target = a["target"].as_str()?;
    if target.contains('/') {
        return None;
    }
    let m = msg(a);
    let top = score(m, "slow").max(score(m, "fast"));
    Some(json!({
        "ip": target, "fast": score(m, "fast"), "slow": score(m, "slow"), "danger": top, "peak": top,
        "first_seen": ts(a) - 600 * SEC, "last_seen": ts(a),
        "counts": a["signals"].as_object().map(|s| Value::Object(s.clone())).unwrap_or_else(|| json!(counts_of(m))),
        "evidence": a["evidence"].as_array().cloned().unwrap_or_default(),
        "banned_by": target, "banned_until": a["until"], "protected": null, "geo": place_of(m),
    }))
}

fn ban_of(a: &Value) -> Value {
    let m = msg(a);
    let reason = m.split_once("): ").map_or(m, |(_, r)| r);
    let origin = m.split_once("(from peer ").and_then(|(_, r)| r.split_once(')')).map(|(p, _)| p);
    let mut b = json!({ "net": a["target"], "since": ts(a), "until": a["until"], "offence": 1, "reason": reason });
    if let Some(o) = origin {
        b["origin"] = json!(o);
    }
    b
}

/// What a decision log doesn't carry, varied per node so every card of the console shows
/// something: the node's facts, the cluster as it sees it, integrity checks, resources,
/// updates, certificates. Made up, and said so in the README.
fn fill(n: &Node, v: &mut Value, peers: &[Peer], now: Micros) {
    let i = n.i;
    let uptime_h = [14.9, 19.3, 3.2, 40.1, 7.7][i % 5];
    v["version"] = json!(env!("CARGO_PKG_VERSION"));
    v["started"] = json!(now - (uptime_h * 3600.0) as i64 * SEC);
    v["mode"] = json!("enforce");
    v["backend"] = json!(n.backend);
    v["fast_threshold"] = json!(100.0);
    v["slow_threshold"] = json!(100.0);
    v["tracked_connections"] = json!(3 + i);
    v["actions_log"] = Value::Null;

    let mut hours: BTreeMap<Micros, (u64, u64)> = BTreeMap::new();
    let mut minutes: BTreeMap<Micros, (u32, u32)> = BTreeMap::new();
    for a in &n.acts {
        let t = ts(a);
        if t >= now - 7 * DAY {
            let e = hours.entry(t - t.rem_euclid(HOUR)).or_default();
            e.0 += evidence_len(a) + u64::from(kind(a) == "alert");
            e.1 += u64::from(kind(a) == "ban");
        }
        if t >= now - HOUR {
            let e = minutes.entry(t - t.rem_euclid(60 * SEC)).or_default();
            e.0 += evidence_len(a) as u32 + u32::from(kind(a) == "alert");
            e.1 += u32::from(kind(a) == "ban");
        }
    }
    v["stats"]["hours"] = Value::Array(hours.iter().map(|(h, (e, b))| json!({ "hour": h, "events": e, "bans": b })).collect());
    v["stats"]["history"] =
        Value::Array(minutes.iter().map(|(m, (e, b))| json!({ "minute": m, "events": [e, 0, 0], "bans": b })).collect());
    v["stats"]["events"] = json!({ "fw_block": 4200 + 300 * i, "fw_tripwire": 310, "ssh_auth_fail": 120 + 40 * i, "ssh_invalid_user": 88 });
    v["stats"]["records"] = json!({ "ufw": 51000 + 1000 * i, "ssh": 2100 });

    let mut seen = HashSet::new();
    let offenders: Vec<Value> = n
        .acts
        .iter()
        .rev()
        .filter(|a| kind(a) == "ban" && !is_peer(a) && ts(a) >= now - DAY)
        .filter_map(offender)
        .filter(|o| seen.insert(o["ip"].as_str().unwrap_or("").to_string()))
        .take(300)
        .collect();
    v["offenders"] = Value::Array(offenders);

    let others: Vec<&Peer> = peers.iter().filter(|p| p.name != n.name).collect();
    let peer_views: Vec<Value> = others
        .iter()
        .enumerate()
        .map(|(k, p)| {
            if i % 5 == 2 && k == 1 {
                json!({ "addr": format!("{}:7950", p.addr), "last_ok": now - 2 * HOUR, "last_error": "connect: timed out", "failing_since": now - 2 * HOUR })
            } else {
                json!({ "addr": format!("{}:7950", p.addr), "last_ok": now - (3 + k as i64) * SEC, "last_error": null, "failing_since": null })
            }
        })
        .collect();
    v["cluster"] = json!({
        "node_id": n.name, "listen": "0.0.0.0:7950", "peers": peer_views,
        "heard_from": others.iter().map(|p| (p.name.clone(), now - 5 * SEC)).collect::<BTreeMap<_, _>>(),
        "facts_known": 1532 + 40 * i, "facts_received": 9120 + 100 * i, "facts_sent": 2210, "rejected": 0, "refused_by_limit": 0,
        "key_id": "sim0000key000", "extra_key_ids": [], "key_since": now - 12 * DAY, "identity": "",
    });
    v["cron"] = json!({ "scanned": now - 24 * SEC, "learning_until": 0, "crontabs": 1, "lines": 2, "tasks": 6, "scripts": 0, "files": 124, "errors": [] });
    let infected: Vec<&str> = match i % 5 {
        1 => vec!["/var/tmp/.x/payload.elf: Unix.Trojan.Mirai-5607459-1"],
        _ => vec![],
    };
    v["av"] = json!({
        "reported": now - 5 * HOUR, "completed": now - 5 * HOUR,
        "last": { "start": now - 5 * HOUR - 20 * 60 * SEC, "end": now - 5 * HOUR, "infected": infected, "infected_count": infected.len(),
                  "scanned_files": 48213 + 1000 * i, "errors": 0, "exit": 0, "completed": true, "db_outdated": i % 5 == 3 }
    });
    v["verify"] = json!({ "last_run": now - 16 * HOUR, "checked": 7471, "mismatched": if i % 5 == 4 { 2 } else { 0 }, "suid": 14 });
    v["procwatch"] = json!({ "scanned": now - 27 * SEC, "learning_until": 0, "pairs": 2 + i, "outbound": 3 });
    v["resources"] = json!({
        "read": now - 30 * SEC,
        "disks": [ { "mount": "/", "paths": [], "size_kb": 40_000_000, "avail_kb": if i % 5 == 1 { 3_500_000 } else { 21_000_000 } },
                   { "mount": "/var/log", "paths": [], "size_kb": 10_000_000, "avail_kb": 6_200_000 } ],
        "memory": { "total_kb": 4_000_000, "avail_kb": 1_900_000 - 200_000 * (i as u64 % 5), "swap_total_kb": 1_000_000, "swap_free_kb": 990_000, "psi_some": 0.3, "psi_full": 0.0 },
        "errors": []
    });
    let dnf = n.backend == "firewalld";
    v["patches"] = json!({
        "read": now - 3 * HOUR, "upgradable": 7, "security_count": if i.is_multiple_of(2) { 2 } else { 0 },
        "security": if i.is_multiple_of(2) { vec!["openssl", "libssl3"] } else { vec![] },
        "reboot_required": dnf, "reboot_pkgs": if dnf { vec!["kernel-core"] } else { vec![] },
        "running_kernel": if dnf { "6.11.4-301.fc41" } else { "6.12.48+deb13-amd64" },
        "newest_kernel": if dnf { "6.11.8-300.fc41" } else { "6.12.48+deb13-amd64" },
        "stale": [], "errors": []
    });
    v["certs"] = match i % 5 {
        0 => {
            json!([ { "target": "cloud.example.org:443", "checked": now - 40 * 60 * SEC, "not_after": now + 4 * DAY, "not_before": now - 3 * DAY, "error": null, "names": ["cloud.example.org"], "file": false, "wrong_name": null } ])
        }
        2 => json!([
            { "target": "xmpp.example.org:5223", "checked": now - HOUR, "not_after": now + 31 * DAY, "not_before": now - 59 * DAY, "error": null, "names": ["xmpp.example.org", "conference.xmpp.example.org"], "file": false, "wrong_name": null },
            { "target": "/etc/ssl/private/dkim.pem", "checked": now - HOUR, "not_after": null, "not_before": null, "error": "openssl: unable to load certificate", "names": [], "file": true, "wrong_name": null },
        ]),
        _ => json!([]),
    };
    if i.is_multiple_of(5) {
        v["geoblock"] = json!({ "computed": now - 6 * HOUR, "what": "CN, RU and 12 ASNs", "v4": 12840, "v6": 310, "applied": true, "error": null, "countries": ["CN", "RU"], "asns": [4134, 4837, 12389] });
    }
    if i % 5 == 2 {
        v["accounts"] = json!([
            { "account": "admin", "failures": 12.5, "ips": 4, "under_attack": true },
            { "account": "support", "failures": 6.0, "ips": 3, "under_attack": true },
        ]);
    }
    v["last_lines"] = json!({ "ssh": now - 30 * SEC, "ufw": now - 2 * SEC });
    v["port_names"] = json!([[22, "ssh"], [443, "https"]]);
}

impl Node {
    /// A node whose state is its decision log. `shift`: Some(delta): the log's times moved by
    /// that much (the copy served lives in `logs`).
    #[allow(clippy::too_many_arguments)]
    pub fn from_log(
        i: usize,
        name: &str,
        addr: IpAddr,
        backend: &str,
        src: &Path,
        logs: &Path,
        socket: PathBuf,
        shift: Option<Micros>,
        filled: bool,
        peers: &[Peer],
    ) -> Result<Node> {
        // the copy served is plain lines (the source may be a rotated .gz), shifted or not
        let served = logs.join(format!("{name}.actions.jsonl"));
        let acts = read_log(src, Some((&served, shift.unwrap_or(0))))?;
        let snap = vpsfort::actions_view::load(std::slice::from_ref(&served), None)?;
        let mut v = serde_json::to_value(&snap)?;
        let node = Node {
            i,
            name: name.to_string(),
            addr,
            backend: backend.to_string(),
            log: Some(served),
            socket,
            acts,
            state: Mutex::new(Value::Null),
            abuse: Mutex::default(),
            seed: Mutex::new(7 + i as u64),
        };
        if filled {
            fill(&node, &mut v, peers, time::now());
        } else {
            v["version"] = json!(env!("CARGO_PKG_VERSION"));
            v["backend"] = json!(backend);
        }
        *node.state.lock().unwrap() = v;
        Ok(node)
    }

    /// A node whose state is a snapshot the console saved (a node's "Snapshot", or an entry
    /// of an export): served as it is, its `generated` time moved to each request's.
    pub fn from_snapshot(i: usize, name: &str, addr: IpAddr, snapshot: Value, socket: PathBuf) -> Node {
        let backend = snapshot["backend"].as_str().unwrap_or("nftables").to_string();
        Node {
            i,
            name: name.to_string(),
            addr,
            backend,
            log: None,
            socket,
            acts: vec![],
            state: Mutex::new(snapshot),
            abuse: Mutex::default(),
            seed: Mutex::new(7 + i as u64),
        }
    }

    /// A line for the start-up summary.
    pub fn describe(&self) -> String {
        let v = self.state.lock().unwrap();
        let len = |k: &str| v[k].as_array().map_or(0, |a| a.len());
        format!(
            "{}: {} ({} active bans, {} offenders, {} alerts, {} recent decisions)",
            self.name,
            match &self.log {
                Some(p) => format!("from the log {} ({} decisions)", p.display(), self.acts.len()),
                None => "from a snapshot".into(),
            },
            len("bans"),
            len("offenders"),
            len("alerts"),
            len("recent"),
        )
    }

    fn digest(&self, v: &Value, now: Micros) -> String {
        let since = now - now.rem_euclid(DAY);
        let mut d = DigestData { since, until: now, ..Default::default() };
        for a in v["recent"].as_array().into_iter().flatten().filter(|a| ts(a) >= since) {
            match kind(a) {
                "ban" if !is_peer(a) => *d.bans_by_category.entry(a["category"].as_str().unwrap_or("burst").to_string()).or_default() += 1,
                "alert" => {
                    *d.alerts_by_topic.entry(a["topic"].as_str().unwrap_or("system").to_string()).or_default() += 1;
                    if matches!(a["severity"].as_str(), Some("high") | Some("critical")) && d.attention.len() < 5 {
                        d.attention.push(msg(a).to_string());
                    }
                }
                _ => {}
            }
        }
        for o in v["offenders"].as_array().into_iter().flatten().take(10) {
            if let (Some(ip), Some(f)) = (o["ip"].as_str().and_then(|s| s.parse::<IpAddr>().ok()), o["danger"].as_f64()) {
                d.top.push((ip, f, o["banned_by"].as_str().and_then(|s| s.parse().ok()), o["geo"].as_str().map(String::from)));
            }
        }
        let snap: Snapshot = match serde_json::from_value(v.clone()) {
            Ok(s) => s,
            Err(e) => return format!("error: the state of {} doesn't read as a snapshot: {e}", self.name),
        };
        let (subject, body) = vpsfort::digest::render(&d, &snap, 14);
        format!("[{}] {subject}\n\n{body}", self.name)
    }

    fn abuse(&self, cmd: &str) -> String {
        let Some(log) = &self.log else {
            return "error: this node's state is a snapshot: no actions log to build abuse reports from".into();
        };
        let mut cache = self.abuse.lock().unwrap();
        if let Some((at, text)) = cache.get(cmd) {
            if at.elapsed() < ABUSE_FRESH {
                return text.clone();
            }
        }
        let since = vpsfort::console::abuse_window(cmd).unwrap_or(Dur(7 * 86_400));
        let text = match vpsfort::abuse::live(log, since, time::now(), self.name.clone(), vec![self.addr]) {
            Ok(r) => serde_json::to_string(&r).unwrap_or_else(|e| format!("error: {e}")),
            Err(e) => format!("error: {e:#}"),
        };
        cache.insert(cmd.to_string(), (Instant::now(), text.clone()));
        text
    }

    fn honeypots(&self, cmd: &str, since: Dur) -> String {
        let Some(log) = &self.log else {
            return "error: this node's state is a snapshot: no actions log to read honeypot hits from".into();
        };
        let mut cache = self.abuse.lock().unwrap();
        if let Some((at, text)) = cache.get(cmd) {
            if at.elapsed() < ABUSE_FRESH {
                return text.clone();
            }
        }
        let text = match vpsfort::honeypot::from_log(log, since, time::now()) {
            Ok(r) => serde_json::to_string(&r).unwrap_or_else(|e| format!("error: {e}")),
            Err(e) => format!("error: {e:#}"),
        };
        cache.insert(cmd.to_string(), (Instant::now(), text.clone()));
        text
    }

    /// A new ban (and now and then an alert) copied from the log, stamped now.
    fn trickle(&self) {
        let now = time::now();
        let mut seed = self.seed.lock().unwrap();
        let bans: Vec<&Value> = self.acts.iter().filter(|a| kind(a) == "ban" && ts(a) >= now - DAY).collect();
        let alerts: Vec<&Value> = self.acts.iter().filter(|a| kind(a) == "alert" && ts(a) > 0).collect();
        if bans.is_empty() {
            return;
        }
        let mut a = bans[(rnd(&mut seed) as usize) % bans.len()].clone();
        a["ts"] = json!(now);
        a["until"] = json!(now + HOUR + (rnd(&mut seed) % 5) as i64 * HOUR);
        let mut v = self.state.lock().unwrap();
        let push_front = |list: &mut Value, item: Value, cap: usize| {
            if let Some(arr) = list.as_array_mut() {
                arr.insert(0, item);
                arr.truncate(cap);
            }
        };
        if let Some(arr) = v["bans"].as_array_mut() {
            arr.retain(|b| b["net"] != a["target"]);
        }
        push_front(&mut v["bans"], ban_of(&a), 5000);
        if !is_peer(&a) {
            if let Some(o) = offender(&a) {
                if let Some(arr) = v["offenders"].as_array_mut() {
                    arr.retain(|x| x["ip"] != o["ip"]);
                }
                push_front(&mut v["offenders"], o, 300);
            }
        }
        v["stats"]["bans"] = json!(v["stats"]["bans"].as_u64().unwrap_or(0) + 1);
        let hour = now - now.rem_euclid(HOUR);
        if let Some(h) = v["stats"]["hours"].as_array_mut() {
            if h.last().is_none_or(|b| b["hour"].as_i64() != Some(hour)) {
                h.push(json!({ "hour": hour, "events": 0, "bans": 0 }));
            }
            if let Some(b) = h.last_mut() {
                b["bans"] = json!(b["bans"].as_u64().unwrap_or(0) + 1);
                b["events"] = json!(b["events"].as_u64().unwrap_or(0) + evidence_len(&a));
            }
        }
        push_front(&mut v["recent"], a, 500);
        if rnd(&mut seed).is_multiple_of(3) && !alerts.is_empty() {
            let mut al = alerts[(rnd(&mut seed) as usize) % alerts.len()].clone();
            al["ts"] = json!(now);
            v["stats"]["alerts"] = json!(v["stats"]["alerts"].as_u64().unwrap_or(0) + 1);
            push_front(&mut v["alerts"], al.clone(), 500);
            push_front(&mut v["recent"], al, 500);
        }
    }

    /// The node's console socket, answering like vpsfort's; a trickle thread when asked.
    pub fn start(self: Arc<Self>, trickle_secs: u64) -> Result<()> {
        let _ = std::fs::remove_file(&self.socket);
        let listener = UnixListener::bind(&self.socket).with_context(|| format!("binding {}", self.socket.display()))?;
        if trickle_secs > 0 && self.log.is_some() {
            let n = Arc::clone(&self);
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(5 + 4 * n.i as u64));
                loop {
                    n.trickle();
                    thread::sleep(Duration::from_secs(trickle_secs));
                }
            });
        }
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let n = Arc::clone(&self);
                thread::spawn(move || {
                    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut cmd = String::new();
                    let _ = (&mut s).take(4096).read_to_string(&mut cmd);
                    let reply = match vpsfort::console::read_only(cmd.trim()) {
                        None => format!(
                            "error: read-only socket: only {} (the control socket has the rest)",
                            vpsfort::console::COMMANDS.join(", ")
                        ),
                        Some("snapshot") => {
                            let mut v = n.state.lock().unwrap().clone();
                            v["generated"] = json!(time::now());
                            serde_json::to_string(&v).unwrap_or_default()
                        }
                        Some("digest") => {
                            let v = n.state.lock().unwrap().clone();
                            n.digest(&v, time::now())
                        }
                        Some(c) => match vpsfort::console::honeypots_window(c) {
                            Some(since) => n.honeypots(c, since),
                            None => n.abuse(c),
                        },
                    };
                    let _ = s.write_all(reply.as_bytes());
                });
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ban_line(t: Micros, ip: &str) -> String {
        format!("{{\"ts\":{t},\"kind\":\"ban\",\"severity\":\"high\",\"target\":\"{ip}\",\"until\":{},\"message\":\"ban {ip} [Germany / Example GmbH (AS64496)] for 1h (offence #1): burst score fast=100 slow=100 [1x fw_tripwire]\",\"evidence\":[\"10-30 13:01:12 tripwire block TCP/23\"],\"applied\":true,\"category\":\"tripwire\"}}", t + HOUR)
    }

    #[test]
    fn a_log_becomes_a_node_that_answers_like_vpsfort() {
        let dir = std::env::temp_dir().join(format!("vpsfort-sim-node-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = 1_600_000_000 * SEC;
        let src = dir.join("a.jsonl");
        std::fs::write(&src, format!("{}\n{}\n", ban_line(old, "192.0.2.1"), ban_line(old + 60 * SEC, "192.0.2.2"))).unwrap();
        let now = time::now();
        let peers = vec![
            Peer { name: "a".into(), addr: "203.0.113.1".parse().unwrap() },
            Peer { name: "b".into(), addr: "203.0.113.2".parse().unwrap() },
        ];
        let n = Node::from_log(
            0,
            "a",
            "203.0.113.1".parse().unwrap(),
            "nftables",
            &src,
            &dir,
            dir.join("a.sock"),
            Some(now - 30 * SEC - (old + 60 * SEC)),
            true,
            &peers,
        )
        .unwrap();
        let v = n.state.lock().unwrap().clone();
        assert_eq!(v["bans"].as_array().unwrap().len(), 2, "shifted to now: both bans active");
        assert_eq!(v["offenders"].as_array().unwrap().len(), 2);
        assert_eq!(v["cluster"]["peers"].as_array().unwrap().len(), 1, "the other node is a peer");
        let digest = n.digest(&v, now);
        assert!(digest.starts_with("[a] ") && digest.contains("Active bans now: 2"), "{digest}");
        let abuse: Value = serde_json::from_str(&n.abuse("abuse 24h")).unwrap();
        assert_eq!(abuse["offenders"].as_array().unwrap().len(), 2);
        assert_eq!(abuse["offenders"][0]["asn"], 64496, "the place from the message");
        n.trickle();
        let v = n.state.lock().unwrap();
        assert_eq!(v["stats"]["bans"], json!(3));
        assert_eq!(v["recent"].as_array().unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rotated copy of a log is read like the log itself, and served as plain lines.
    #[test]
    fn a_gzipped_log_is_a_node_too() {
        let dir = std::env::temp_dir().join(format!("vpsfort-sim-gz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("a.jsonl.gz");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, ban_line(time::now() - 60 * SEC, "192.0.2.1").as_bytes()).unwrap();
        std::fs::write(&src, gz.finish().unwrap()).unwrap();
        let n = Node::from_log(0, "a", "203.0.113.1".parse().unwrap(), "ufw", &src, &dir, dir.join("a.sock"), None, false, &[]).unwrap();
        assert_eq!(n.acts.len(), 1);
        assert_eq!(n.state.lock().unwrap()["bans"].as_array().unwrap().len(), 1);
        let served = std::fs::read_to_string(dir.join("a.actions.jsonl")).unwrap();
        assert!(served.starts_with('{') && served.contains("\"ts\":") && served.ends_with('\n'), "served as plain lines: {served}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_snapshot_node_has_no_abuse_report() {
        let n = Node::from_snapshot(
            0,
            "s",
            "203.0.113.9".parse().unwrap(),
            json!({ "bans": [], "backend": "ufw" }),
            PathBuf::from("/tmp/x.sock"),
        );
        assert!(n.abuse("abuse 7d").starts_with("error: this node's state is a snapshot"));
        assert_eq!(n.backend, "ufw");
    }
}
