//! The cluster in one JSON document (`/api/v1/cluster`): each node's summary, what needs
//! attention, and the nodes' bans, alerts, actions, offenders and places merged, each entry
//! naming its node.
//!
//! Everything is read from the snapshots as plain JSON, field by field, with defaults for
//! what a node's vpsfort doesn't send: nodes may run different versions.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use crate::fleet::Node;
use crate::netlist::Net;
use crate::snapshot::Snapshot;
use crate::time::{Micros, SEC};

const MIN: Micros = 60 * SEC;
const HOUR: Micros = 60 * MIN;
const DAY: Micros = 24 * HOUR;

/// Merged lists keep this many entries.
const MAX_ALERTS: usize = 500;
const MAX_ACTIONS: usize = 600;
const MAX_BANS: usize = 5000;
const MAX_OFFENDERS: usize = 400;
const MAX_ACCOUNTS: usize = 100;
/// Minutes of history in the activity chart (vpsfort keeps 180).
const HISTORY_MINUTES: i64 = 180;
/// Hours of the overview's longer charts (vpsfort keeps a week).
const HISTORY_HOURS: i64 = 7 * 24;

fn i64_at(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(Value::as_i64)
}

fn u64_at(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn f64_at(v: &Value, key: &str) -> f64 {
    v.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn list<'a>(s: &'a Snapshot, key: &str) -> &'a [Value] {
    s.value.get(key).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn section<'a>(s: &'a Snapshot, key: &str) -> Option<&'a Value> {
    s.value.get(key).filter(|v| !v.is_null())
}

/// "ok": fresh data; "stale": older data, the latest attempt failed; "down": no data at all;
/// "waiting": not asked yet.
pub fn state(n: &Node) -> &'static str {
    match (&n.snapshot, &n.error) {
        (Some(_), None) => "ok",
        (Some(_), Some(_)) => "stale",
        (None, Some(_)) => "down",
        (None, None) => "waiting",
    }
}

/// Events and bans per minute from the snapshot's history, by minute.
fn per_minute(s: &Snapshot) -> BTreeMap<Micros, (u64, u64)> {
    let mut out = BTreeMap::new();
    if let Some(h) = s.value.get("stats").and_then(|st| st.get("history")).and_then(Value::as_array) {
        for b in h {
            let Some(minute) = i64_at(b, "minute") else { continue };
            let events =
                b.get("events").and_then(Value::as_array).map_or(0, |e| e.iter().filter_map(Value::as_u64).fold(0u64, u64::saturating_add));
            out.insert(minute, (events, u64_at(b, "bans")));
        }
    }
    out
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "warning" => 2,
        "info" => 1,
        _ => 0,
    }
}

/// One node's figures for the overview.
fn summary(n: &Node, now: Micros) -> Value {
    let mut out = json!({
        "id": n.id,
        "name": n.name,
        "addr": n.addr,
        "state": state(n),
        "error": n.error,
        "fetched": n.fetched,
        "failing_since": n.failing_since,
        "latency_ms": n.latency_ms,
        "version": n.version,
    });
    let Some(s) = &n.snapshot else { return out };
    let o = out.as_object_mut().expect("an object");
    let generated = s.value.get("generated").and_then(Value::as_i64).unwrap_or(now);
    // over every ban, not only those kept
    let from_peers: usize = s.bans.iter().filter(|((origin, _), _)| origin != "local").map(|(_, n)| n).sum();
    let subnets: usize = s.bans.iter().filter(|((_, kind), _)| kind == "network").map(|(_, n)| n).sum();
    let alerts = list(s, "alerts");
    let day_alerts: Vec<&Value> = alerts.iter().filter(|a| i64_at(a, "ts").unwrap_or(0) >= now - DAY).collect();
    let serious = day_alerts.iter().filter(|a| severity_rank(str_at(a, "severity")) >= 3).count();
    let (mut events_1h, mut bans_1h) = (0u64, 0u64);
    for (minute, (e, b)) in per_minute(s) {
        if minute >= generated.saturating_sub(HOUR) {
            events_1h = events_1h.saturating_add(e);
            bans_1h = bans_1h.saturating_add(b);
        }
    }
    let copy = |key: &str| s.value.get(key).cloned().unwrap_or(Value::Null);
    o.insert("mode".into(), copy("mode"));
    o.insert("backend".into(), copy("backend"));
    o.insert("started".into(), copy("started"));
    o.insert("generated".into(), json!(generated));
    o.insert("tracked_ips".into(), copy("tracked_ips"));
    o.insert("tracked_connections".into(), copy("tracked_connections"));
    o.insert("bans".into(), json!(s.len_of("bans")));
    o.insert("bans_from_peers".into(), json!(from_peers));
    o.insert("subnet_bans".into(), json!(subnets));
    o.insert("offenders".into(), json!(s.len_of("offenders")));
    o.insert("alerts_24h".into(), json!(day_alerts.len()));
    o.insert("alerts_24h_serious".into(), json!(serious));
    o.insert("events_1h".into(), json!(events_1h));
    o.insert("bans_1h".into(), json!(bans_1h));
    o.insert(
        "stats".into(),
        json!({
            "bans": s.value.get("stats").map_or(0, |st| u64_at(st, "bans")),
            "alerts": s.value.get("stats").map_or(0, |st| u64_at(st, "alerts")),
            "records": s.value.get("stats").and_then(|st| st.get("records")).cloned().unwrap_or(json!({})),
        }),
    );
    for key in
        ["last_lines", "cluster", "certs", "resources", "patches", "verify", "cron", "procwatch", "feeds", "waf", "geoblock", "allowed"]
    {
        o.insert(key.into(), copy(key));
    }
    o.insert("av".into(), section(s, "av").and_then(|a| a.get("last")).cloned().unwrap_or(Value::Null));
    o.insert("settings".into(), settings(s));
    if let Some(x) = section(s, "exposure") {
        let listeners = x.get("listeners").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
        o.insert(
            "exposure".into(),
            json!({
                "scanned": x.get("scanned"),
                "firewall": x.get("firewall"),
                "ufw_active": x.get("ufw_active"),
                "listeners": listeners.len(),
                "open": listeners.iter().filter(|l| str_at(l, "exposure") == "allowed").count(),
                "dead_rules": x.get("dead_rules"),
            }),
        );
    }
    out
}

/// What needs the admin's attention on one node: `(level, text)`.
pub fn problems(n: &Node, now: Micros) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let since = |t: Option<Micros>| t.map(|t| format!(" since {}", crate::time::fmt_ts(t))).unwrap_or_default();
    match state(n) {
        "down" => out.push(("critical", format!("no data{}: {}", since(n.failing_since), n.error.as_deref().unwrap_or("")))),
        "stale" => out.push((
            "high",
            format!("showing data from {}: {}", n.fetched.map(crate::time::fmt_ts).unwrap_or_default(), n.error.as_deref().unwrap_or("")),
        )),
        _ => {}
    }
    let Some(s) = &n.snapshot else { return out };
    if s.value.get("mode").and_then(Value::as_str) == Some("shadow") {
        out.push(("warning", "shadow mode: bans are decided and shared, but not applied to the firewall".into()));
    }
    if let Some(n) = s.value.get("unapplied").and_then(Value::as_u64).filter(|n| *n > 0) {
        out.push((
            "high",
            format!("{n} firewall change(s) could not be applied: bans are decided but not in the kernel (tried again every 30 s)"),
        ));
    }
    if let Some(c) = section(s, "cluster") {
        for p in c.get("peers").and_then(Value::as_array).into_iter().flatten() {
            if let Some(t) = i64_at(p, "failing_since") {
                out.push((
                    "warning",
                    format!("cluster peer {} unreachable{}: {}", str_at(p, "addr"), since(Some(t)), str_at(p, "last_error")),
                ));
            }
        }
        if c.get("extra_key_ids").and_then(Value::as_array).is_some_and(|k| !k.is_empty()) {
            out.push(("info", "cluster key rotation in progress (a .next or .prev key file is present)".into()));
        }
    }
    for c in section(s, "certs").and_then(Value::as_array).into_iter().flatten() {
        let target = str_at(c, "target");
        if let Some(e) = c.get("error").and_then(Value::as_str) {
            out.push(("warning", format!("certificate {target}: {e}")));
        } else if let Some(end) = i64_at(c, "not_after") {
            // short-lived certificates (6 or 7 days) have a few days left all the time: a
            // quarter of their life is when renewal is late
            let life = i64_at(c, "not_before").map_or(90 * DAY, |b| end.saturating_sub(b));
            if end <= now {
                out.push(("high", format!("certificate {target} expired {}", crate::time::fmt_ts(end))));
            } else if end.saturating_sub(now) < (14 * DAY).min(life / 4) {
                out.push(("warning", format!("certificate {target} expires {}", crate::time::fmt_ts(end))));
            }
        }
        if let Some(w) = c.get("wrong_name").and_then(Value::as_str) {
            out.push(("warning", format!("certificate {target} doesn't name {w}")));
        }
    }
    if let Some(r) = section(s, "resources") {
        for d in r.get("disks").and_then(Value::as_array).into_iter().flatten() {
            let (size, avail) = (u64_at(d, "size_kb"), u64_at(d, "avail_kb"));
            if size > 0 && avail.saturating_mul(10) < size {
                out.push(("warning", format!("disk {}: {:.0}% free", str_at(d, "mount"), 100.0 * avail as f64 / size as f64)));
            }
        }
        if let Some(m) = r.get("memory").filter(|m| !m.is_null()) {
            let (total, avail) = (u64_at(m, "total_kb"), u64_at(m, "avail_kb"));
            if total > 0 && avail.saturating_mul(10) < total {
                out.push(("warning", format!("memory: {:.0}% available", 100.0 * avail as f64 / total as f64)));
            }
        }
    }
    if let Some(p) = section(s, "patches") {
        let security = u64_at(p, "security_count");
        if security > 0 {
            out.push(("warning", format!("{security} security update(s) pending")));
        }
        if p.get("reboot_required").and_then(Value::as_bool) == Some(true) {
            out.push(("info", "reboot required".into()));
        } else if let (Some(run), Some(new)) =
            (p.get("running_kernel").and_then(Value::as_str), p.get("newest_kernel").and_then(Value::as_str))
        {
            if run != new {
                out.push(("info", format!("kernel {new} installed, {run} running: reboot to use it")));
            }
        }
    }
    if let Some(last) = section(s, "av").and_then(|a| a.get("last")).filter(|l| !l.is_null()) {
        let infected = u64_at(last, "infected_count");
        if infected > 0 {
            out.push(("critical", format!("antivirus: {infected} infected file(s) in the last scan")));
        }
        if last.get("db_outdated").and_then(Value::as_bool) == Some(true) {
            out.push(("warning", "antivirus: signature database outdated".into()));
        }
    }
    if let Some(v) = section(s, "verify") {
        let bad = u64_at(v, "mismatched");
        if bad > 0 {
            out.push(("high", format!("{bad} package file(s) differ from their package's checksums")));
        }
    }
    for key in ["feeds", "geoblock"] {
        if let Some(e) = section(s, key).and_then(|f| f.get("error")).and_then(Value::as_str) {
            out.push(("warning", format!("{key}: {e}")));
        }
    }
    if let Some(w) = section(s, "waf") {
        for src in w.get("sources").and_then(Value::as_array).map_or(&[][..], Vec::as_slice) {
            if let Some(e) = src.get("error").and_then(Value::as_str) {
                out.push(("warning", format!("waf {}: {e}", src.get("name").and_then(Value::as_str).unwrap_or("?"))));
            }
        }
        if let Some(e) = w.get("error").and_then(Value::as_str) {
            out.push(("warning", format!("waf: {e}")));
        }
    }
    if let Some(x) = section(s, "exposure") {
        let dead = x.get("dead_rules").and_then(Value::as_array).map_or(0, Vec::len);
        if dead > 0 {
            out.push(("info", format!("{dead} firewall rule(s) open ports nothing listens on")));
        }
    }
    for e in section(s, "cron").and_then(|c| c.get("errors")).and_then(Value::as_array).into_iter().flatten().take(3) {
        out.push(("info", format!("cron watch: {}", e.as_str().unwrap_or(""))));
    }
    let serious =
        list(s, "alerts").iter().filter(|a| i64_at(a, "ts").unwrap_or(0) >= now - DAY && severity_rank(str_at(a, "severity")) >= 3).count();
    if serious > 0 {
        out.push(("warning", format!("{serious} high or critical alert(s) in the last 24 hours")));
    }
    out
}

/// What a node runs and how, for the overview's table of differences between nodes.
fn settings(s: &Snapshot) -> Value {
    let on = |key: &str| section(s, key).is_some();
    let cluster = section(s, "cluster");
    json!({
        "vpsfort": s.value.get("version").and_then(Value::as_str).filter(|v| !v.is_empty()),
        "mode": s.value.get("mode"),
        "backend": s.value.get("backend"),
        "thresholds": match (s.value.get("fast_threshold").and_then(Value::as_f64), s.value.get("slow_threshold").and_then(Value::as_f64)) {
            (Some(f), Some(sl)) => Some(format!("{f} / {sl}")),
            _ => None,
        },
        "cluster_key": cluster.map(|c| str_at(c, "key_id")).filter(|k| !k.is_empty()),
        "geo": section(s, "world").and_then(|w| w.get("geo")).and_then(Value::as_bool).unwrap_or(false),
        "feeds": on("feeds"),
        "waf": on("waf"),
        "geoblock": section(s, "geoblock").map(|g| str_at(g, "what").to_string()),
        "antivirus": on("av"),
        "patches": on("patches"),
        "verify": on("verify"),
        "procwatch": on("procwatch"),
        "cron": on("cron"),
        "sources": s.value.get("last_lines").and_then(Value::as_object).map(|m| m.len()).unwrap_or(0),
    })
}

/// Entries of list `key` from every node, each with its node's name and id.
fn merged(nodes: &[Node], key: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for n in nodes {
        let Some(s) = &n.snapshot else { continue };
        for item in list(s, key) {
            let mut item = item.clone();
            if let Some(o) = item.as_object_mut() {
                o.insert("node".into(), json!(n.name));
                o.insert("node_id".into(), json!(n.id));
            }
            out.push(item);
        }
    }
    out
}

fn newest_first(mut v: Vec<Value>, field: &str, max: usize) -> Vec<Value> {
    v.sort_by_key(|x| std::cmp::Reverse(i64_at(x, field).unwrap_or(i64::MIN)));
    v.truncate(max);
    v
}

/// Countries or networks by key, added up, with the nodes that saw each.
type Places = BTreeMap<String, (Map<String, Value>, BTreeSet<String>)>;

fn add_place(into: &mut Places, place: &Value, node: &str) {
    let key = str_at(place, "key").to_string();
    if key.is_empty() {
        return;
    }
    let (entry, on) = into.entry(key.clone()).or_insert_with(|| {
        let mut m = Map::new();
        m.insert("key".into(), json!(key));
        m.insert("name".into(), json!(str_at(place, "name")));
        m.insert("country".into(), json!(str_at(place, "country")));
        (m, BTreeSet::new())
    });
    for f in ["bans", "offenders", "events"] {
        let sum = entry.get(f).and_then(Value::as_u64).unwrap_or(0).saturating_add(u64_at(place, f));
        entry.insert(f.into(), json!(sum));
    }
    on.insert(node.to_string());
}

/// The nodes' spots (what a city-level geo database located: bans, offenders, events and
/// logins with coordinates) added up per country, city and coordinates. The page draws each
/// at its coordinates and a country's rest at its capital.
type Spots = BTreeMap<(String, String, i64, i64), Map<String, Value>>;

/// Spots kept per cluster: a city-level database gives nearly every address its own.
const SPOTS: usize = 1000;

fn add_spot(into: &mut Spots, spot: &Value) {
    let country = str_at(spot, "country");
    let (Some(lat), Some(lon)) = (spot.get("lat").and_then(Value::as_f64), spot.get("lon").and_then(Value::as_f64)) else { return };
    if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) || lat.abs() > 90.0 || lon.abs() > 180.0 {
        return;
    }
    let city: String = str_at(spot, "city").chars().take(60).collect();
    let (lat, lon) = ((lat * 100.0).round() as i64, (lon * 100.0).round() as i64);
    let entry = into.entry((country.to_string(), city.clone(), lat, lon)).or_insert_with(|| {
        let mut m = Map::new();
        m.insert("country".into(), json!(country));
        m.insert("city".into(), json!(city));
        m.insert("lat".into(), json!(lat as f64 / 100.0));
        m.insert("lon".into(), json!(lon as f64 / 100.0));
        m
    });
    for f in ["bans", "offenders", "events", "logins"] {
        let sum = entry.get(f).and_then(Value::as_u64).unwrap_or(0).saturating_add(u64_at(spot, f));
        entry.insert(f.into(), json!(sum));
    }
}

/// The most bans first (then events), at most [`SPOTS`]; what is cut off draws at its capital.
fn rank_spots(m: Spots) -> Vec<Value> {
    let mut v: Vec<Value> = m.into_values().map(Value::Object).collect();
    v.sort_by_key(|a| std::cmp::Reverse((u64_at(a, "bans"), u64_at(a, "events"), u64_at(a, "logins"))));
    v.truncate(SPOTS);
    v
}

/// The most bans first (then events), at most `max`, each with its nodes.
fn rank(m: Places, max: usize) -> Vec<Value> {
    let mut v: Vec<Value> = m
        .into_values()
        .map(|(mut e, on)| {
            e.insert("nodes".into(), json!(on));
            Value::Object(e)
        })
        .collect();
    v.sort_by_key(|a| std::cmp::Reverse((u64_at(a, "bans"), u64_at(a, "events"))));
    v.truncate(max);
    v
}

/// `[port, count]` pairs added to `into`.
fn add_ports(into: &mut BTreeMap<u64, u64>, list: Option<&Value>) {
    for p in list.and_then(Value::as_array).into_iter().flatten() {
        if let (Some(port), Some(count)) = (p.get(0).and_then(Value::as_u64), p.get(1).and_then(Value::as_u64)) {
            let c = into.entry(port).or_default();
            *c = c.saturating_add(count);
        }
    }
}

fn busiest(ports: BTreeMap<u64, u64>, max: usize) -> Vec<(u64, u64)> {
    let mut ports: Vec<(u64, u64)> = ports.into_iter().collect();
    ports.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    ports.truncate(max);
    ports
}

/// Countries, networks and ports of every node, added up; each country's own networks and
/// ports (for a country picked on the page); what each node blocks by `[geoblock]`.
fn world(nodes: &[Node]) -> Value {
    let (mut countries, mut isps) = (Places::new(), Places::new());
    let mut ports: BTreeMap<u64, u64> = BTreeMap::new();
    let mut by_country: BTreeMap<String, (Places, BTreeMap<u64, u64>)> = BTreeMap::new();
    let mut logged_in: BTreeMap<String, u64> = BTreeMap::new();
    let mut spots = Spots::new();
    let mut geoblock = Vec::new();
    // names for local ports from the nodes' configurations ("XMPP client"); the first node's wins
    let mut port_names: BTreeMap<u64, String> = BTreeMap::new();
    let (mut geo, mut unlocated) = (false, 0u64);
    for n in nodes {
        let Some(s) = &n.snapshot else { continue };
        for p in list(s, "port_names") {
            if let (Some(port), Some(name)) = (p.get(0).and_then(Value::as_u64), p.get(1).and_then(Value::as_str)) {
                port_names.entry(port).or_insert_with(|| name.chars().take(40).collect());
            }
        }
        if let Some(g) = section(s, "geoblock") {
            let codes = |key: &str| -> Vec<String> {
                g.get(key)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
                    .map(String::from)
                    .collect()
            };
            geoblock.push(json!({
                "node": n.name, "node_id": n.id,
                "what": str_at(g, "what"), "applied": g.get("applied").and_then(Value::as_bool).unwrap_or(false),
                "error": g.get("error").filter(|e| !e.is_null()),
                "countries": codes("countries"), "only_countries": codes("only_countries"),
                "asns": g.get("asns").and_then(Value::as_array).map_or(0, Vec::len),
            }));
        }
        let Some(w) = section(s, "world") else { continue };
        geo |= w.get("geo").and_then(Value::as_bool).unwrap_or(false);
        unlocated = u64_at(w, "unlocated").saturating_add(unlocated);
        for c in w.get("countries").and_then(Value::as_array).into_iter().flatten() {
            add_place(&mut countries, c, &n.name);
        }
        for c in w.get("isps").and_then(Value::as_array).into_iter().flatten() {
            add_place(&mut isps, c, &n.name);
        }
        add_ports(&mut ports, w.get("ports"));
        for (cc, detail) in w.get("by_country").and_then(Value::as_object).into_iter().flatten() {
            let (places, p) = by_country.entry(cc.clone()).or_default();
            for c in detail.get("isps").and_then(Value::as_array).into_iter().flatten() {
                add_place(places, c, &n.name);
            }
            add_ports(p, detail.get("ports"));
        }
        for (cc, count) in w.get("logged_in").and_then(Value::as_object).into_iter().flatten() {
            let c = logged_in.entry(cc.clone()).or_default();
            *c = c.saturating_add(count.as_u64().unwrap_or(0));
        }
        for sp in w.get("spots").and_then(Value::as_array).into_iter().flatten() {
            add_spot(&mut spots, sp);
        }
    }
    let countries = rank(countries, 250);
    // only the countries listed: a node's detail covers its listed ones
    let listed: BTreeSet<&str> = countries.iter().map(|c| str_at(c, "key")).collect();
    let by_country: Map<String, Value> = by_country
        .into_iter()
        .filter(|(cc, _)| listed.contains(cc.as_str()))
        .map(|(cc, (places, p))| (cc, json!({ "isps": rank(places, 50), "ports": busiest(p, 20) })))
        .collect();
    json!({
        "geo": geo,
        "unlocated": unlocated,
        "countries": countries,
        "isps": rank(isps, 150),
        "ports": busiest(ports, 40),
        "logged_in": logged_in,
        "spots": rank_spots(spots),
        "by_country": by_country,
        "geoblock": geoblock,
        "port_names": port_names,
    })
}

/// Events and bans per minute, per node, over the last [`HISTORY_MINUTES`].
fn history(nodes: &[Node], now: Micros) -> Value {
    let end = now - now.rem_euclid(MIN);
    let start = end - (HISTORY_MINUTES - 1) * MIN;
    let minutes: Vec<Micros> = (0..HISTORY_MINUTES).map(|i| start + i * MIN).collect();
    let series: Vec<Value> = nodes
        .iter()
        .filter_map(|n| {
            let s = n.snapshot.as_ref()?;
            let pm = per_minute(s);
            let events: Vec<u64> = minutes.iter().map(|m| pm.get(m).map_or(0, |x| x.0)).collect();
            let bans: Vec<u64> = minutes.iter().map(|m| pm.get(m).map_or(0, |x| x.1)).collect();
            Some(json!({ "node": n.name, "node_id": n.id, "events": events, "bans": bans }))
        })
        .collect();
    // and per hour over the last week, from vpsfort's hourly figures (since its start)
    let end_h = now - now.rem_euclid(HOUR);
    let start_h = end_h - (HISTORY_HOURS - 1) * HOUR;
    let hours: Vec<Value> = nodes
        .iter()
        .filter_map(|n| {
            let s = n.snapshot.as_ref()?;
            let mut by: BTreeMap<Micros, (u64, u64)> = BTreeMap::new();
            for b in s.value.get("stats").and_then(|st| st.get("hours")).and_then(Value::as_array).into_iter().flatten() {
                if let Some(h) = i64_at(b, "hour") {
                    by.insert(h, (u64_at(b, "events"), u64_at(b, "bans")));
                }
            }
            // a node without hourly figures (an older vpsfort) has no line here
            (!by.is_empty()).then(|| {
                let at = |i: i64| by.get(&(start_h + i * HOUR)).copied().unwrap_or((0, 0));
                json!({
                    "node": n.name, "node_id": n.id,
                    "events": (0..HISTORY_HOURS).map(|i| at(i).0).collect::<Vec<_>>(),
                    "bans": (0..HISTORY_HOURS).map(|i| at(i).1).collect::<Vec<_>>(),
                })
            })
        })
        .collect();
    json!({
        "start": start, "step": MIN, "minutes": HISTORY_MINUTES, "series": series,
        "hours": { "start": start_h, "step": HOUR, "count": HISTORY_HOURS, "series": hours },
    })
}

/// Whether two addresses or networks overlap.
fn overlaps(a: &Net, b: &Net) -> bool {
    a.contains(b.addr) || b.contains(a.addr)
}

/// Everything the nodes say about an address or network `q`: the bans covering it, the
/// decisions about it or naming it in their evidence, its scores, and whether a node trusts or
/// allows it; each entry with its node.
pub fn address(nodes: &[Node], q: &Net) -> Value {
    let net_of = |v: &Value, key: &str| str_at(v, key).parse::<Net>().ok();
    let hit = |v: &Value, key: &str| net_of(v, key).is_some_and(|n| overlaps(&n, q));
    let text = q.addr.to_string();
    let named = |v: &Value| {
        // the address itself in a line, not as the start of a longer one (192.0.2.1 in 192.0.2.10)
        let mentions = |line: &str| {
            line.match_indices(&text).any(|(i, _)| {
                let after = line[i + text.len()..].chars().next();
                !after.is_some_and(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
                    && !line[..i].chars().next_back().is_some_and(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
            })
        };
        mentions(str_at(v, "message"))
            || v.get("evidence").and_then(Value::as_array).is_some_and(|e| e.iter().filter_map(Value::as_str).any(mentions))
    };
    let bans: Vec<Value> = merged(nodes, "bans").into_iter().filter(|b| hit(b, "net")).collect();
    let mut actions: Vec<Value> =
        merged(nodes, "recent").into_iter().chain(merged(nodes, "alerts")).filter(|a| hit(a, "target") || named(a)).collect();
    // an alert is in both lists of its node
    let mut seen = BTreeSet::new();
    actions.retain(|a| seen.insert((str_at(a, "node_id").to_string(), i64_at(a, "ts"), str_at(a, "message").to_string())));
    let offenders: Vec<Value> = merged(nodes, "offenders").into_iter().filter(|o| hit(o, "ip")).collect();
    let mut trusted = Vec::new();
    for n in nodes {
        let Some(s) = &n.snapshot else { continue };
        for t in list(s, "trusted") {
            if t.get(0).and_then(Value::as_str).and_then(|a| a.parse::<Net>().ok()).is_some_and(|a| overlaps(&a, q)) {
                trusted.push(json!({ "node": n.name, "node_id": n.id, "ip": t.get(0), "since": t.get(1) }));
            }
        }
    }
    let allowed: Vec<Value> = merged(nodes, "allowed").into_iter().filter(|a| hit(a, "net")).collect();
    json!({
        "query": format!("{}{}", q.addr, if q.prefix == if q.addr.is_ipv4() { 32 } else { 128 } { String::new() } else { format!("/{}", q.prefix) }),
        "bans": newest_first(bans, "since", 500),
        "actions": newest_first(actions, "ts", 500),
        "offenders": offenders,
        "trusted": trusted,
        "allowed": allowed,
    })
}

/// The whole cluster view. `expected_version`: the vpsfort-web release every node should
/// run (`EXPECTED_VERSION`; empty: no check): a node on another gets an attention row.
pub fn cluster(nodes: &[Node], now: Micros, refresh_secs: u64, expected_version: &str) -> Value {
    let summaries: Vec<Value> = nodes.iter().map(|n| summary(n, now)).collect();
    let mut attention: Vec<Value> = Vec::new();
    for n in nodes {
        for (level, text) in problems(n, now) {
            attention.push(json!({ "node": n.name, "node_id": n.id, "level": level, "text": text }));
        }
        if !expected_version.is_empty() {
            let running = if n.addr == "local" { Some(env!("CARGO_PKG_VERSION").to_string()) } else { n.version.clone() };
            if let Some(v) = running.filter(|v| v != expected_version) {
                attention.push(json!({ "node": n.name, "node_id": n.id, "level": "info", "text": format!("vpsfort-web {v} (expected {expected_version})") }));
            }
        }
    }
    // the same cluster key everywhere: otherwise nodes drop each other's messages
    let mut keys: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in nodes {
        if let Some(k) = n.snapshot.as_ref().and_then(|s| section(s, "cluster")).map(|c| str_at(c, "key_id")).filter(|k| !k.is_empty()) {
            keys.entry(k.to_string()).or_default().push(n.name.clone());
        }
    }
    if keys.len() > 1 {
        let groups: Vec<String> = keys.iter().map(|(k, on)| format!("{k} on {}", on.join(", "))).collect();
        attention
            .push(json!({ "node": "", "node_id": "", "level": "high", "text": format!("cluster keys differ: {}", groups.join("; ")) }));
    }
    attention.sort_by_key(|a| std::cmp::Reverse(severity_rank(str_at(a, "level"))));

    let bans = merged(nodes, "bans");
    let unique: BTreeSet<&str> = bans.iter().map(|b| str_at(b, "net")).collect();
    let unique = unique.len();
    let mut offenders = merged(nodes, "offenders");
    offenders.sort_by(|a, b| f64_at(b, "danger").total_cmp(&f64_at(a, "danger")));
    offenders.truncate(MAX_OFFENDERS);
    let mut accounts = merged(nodes, "accounts");
    accounts.sort_by(|a, b| f64_at(b, "failures").total_cmp(&f64_at(a, "failures")));
    accounts.truncate(MAX_ACCOUNTS);
    let sum = |key: &str| summaries.iter().map(|s| u64_at(s, key)).fold(0u64, u64::saturating_add);
    let totals = json!({
        "nodes": nodes.len(),
        "nodes_ok": nodes.iter().filter(|n| state(n) == "ok").count(),
        "bans": sum("bans"),
        "bans_unique": unique,
        "tracked_ips": sum("tracked_ips"),
        "offenders": sum("offenders"),
        "alerts_24h": sum("alerts_24h"),
        "alerts_24h_serious": sum("alerts_24h_serious"),
        "events_1h": sum("events_1h"),
        "bans_1h": sum("bans_1h"),
    });
    json!({
        "generated": now,
        "refresh_secs": refresh_secs,
        "nodes": summaries,
        "totals": totals,
        "attention": attention,
        "alerts": newest_first(merged(nodes, "alerts"), "ts", MAX_ALERTS),
        "actions": newest_first(merged(nodes, "recent"), "ts", MAX_ACTIONS),
        "bans": newest_first(bans, "since", MAX_BANS),
        "offenders": offenders,
        "accounts": accounts,
        "world": world(nodes),
        "history": history(nodes, now),
    })
}

/// One node in full: its summary and its whole (trimmed) snapshot.
pub fn node(n: &Node, now: Micros) -> Value {
    let problems: Vec<Value> = problems(n, now).into_iter().map(|(level, text)| json!({ "level": level, "text": text })).collect();
    json!({
        "summary": summary(n, now),
        "attention": problems,
        "snapshot": n.snapshot.as_ref().map(|s| s.to_value()),
    })
}

/// What a share link's holder gets of [`address`]: the bans covering the address and the
/// decisions about it (not alerts, nor whatever merely names it in a text: those tell about
/// this host), its scores, each entry cut to the fields the page shows, with account names
/// and users' addresses withheld (`share::withhold`); nothing of what the nodes trust or
/// allow. A stranger sees what the weekly abuse report would, no more.
pub fn shared(v: Value, q: &Net) -> Value {
    let withhold = |x: &Value| Value::String(crate::share::withhold(x.as_str().unwrap_or("")));
    let lines = |x: &Value| Value::Array(x.as_array().into_iter().flatten().map(withhold).collect());
    let pick = |v: &Value, keys: &[&str], texts: &[&str], evidence: bool| -> Value {
        let mut out = Map::new();
        for k in keys {
            if let Some(x) = v.get(*k).filter(|x| !x.is_null()) {
                out.insert((*k).into(), x.clone());
            }
        }
        for k in texts {
            if let Some(x) = v.get(*k).filter(|x| x.is_string()) {
                out.insert((*k).into(), withhold(x));
            }
        }
        if evidence {
            if let Some(e) = v.get("evidence") {
                out.insert("evidence".into(), lines(e));
            }
        }
        Value::Object(out)
    };
    let items = |key: &str| v.get(key).and_then(Value::as_array).cloned().unwrap_or_default();
    let about_q = |a: &Value| str_at(a, "target").parse::<Net>().is_ok_and(|n| overlaps(&n, q));
    json!({
        "query": v.get("query").cloned().unwrap_or(Value::Null),
        "bans": items("bans").iter().map(|b| pick(b, &["net", "since", "until", "offence", "origin", "node", "node_id"], &["reason"], false)).collect::<Vec<_>>(),
        "actions": items("actions")
            .iter()
            .filter(|a| matches!(str_at(a, "kind"), "ban" | "unban") && about_q(a))
            .map(|a| pick(a, &["ts", "kind", "severity", "target", "until", "applied", "category", "node", "node_id"], &["message"], true))
            .collect::<Vec<_>>(),
        "offenders": items("offenders")
            .iter()
            .map(|o| pick(o, &["ip", "danger", "counts", "first_seen", "last_seen", "banned_by", "banned_until", "geo", "node", "node_id"], &[], true))
            .collect::<Vec<_>>(),
        "trusted": [],
        "allowed": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A share link's holder gets the bans, decisions and scores, cut to what the page shows,
    /// with names withheld; not the alerts about the host, nor what it trusts or allows.
    #[test]
    fn a_shared_page_tells_a_stranger_nothing_about_the_host() {
        let now = 1_000 * DAY;
        let snap = json!({
            "bans": [{ "net": "203.0.113.9", "since": now - MIN, "until": now + HOUR, "offence": 2, "reason": "burst score (+25) for alice@example.org" }],
            "recent": [
                { "ts": now - MIN, "kind": "ban", "severity": "high", "target": "203.0.113.9", "until": now + HOUR, "applied": true, "category": "ssh",
                  "message": "ban 203.0.113.9 for 1h (offence #2): burst score fast=100 slow=100 [5x ssh_auth_fail]",
                  "evidence": ["10-30 09:59:00 failed password for alice", "10-30 09:59:10 invalid user oracle"],
                  "accounts": ["ejabberd:alice@example.org"], "user_note": "alice, someone tried your password", "superseded": ["203.0.113.0/24"],
                  "notice": { "to": "alice@example.org", "body": "x" } },
                { "ts": now - 2 * MIN, "kind": "alert", "severity": "high", "topic": "compromise",
                  "message": "SSH login as gateway from 203.0.113.9 with a key never seen before", "evidence": [] }
            ],
            "alerts": [{ "ts": now - 3 * MIN, "kind": "alert", "severity": "warning", "target": "203.0.113.9", "message": "login as root from 203.0.113.9 failed (vsftpd)", "evidence": [] }],
            "offenders": [{ "ip": "203.0.113.9", "fast": 100.0, "slow": 100.0, "danger": 100.0, "peak": 100.0, "first_seen": now - HOUR, "last_seen": now,
                            "counts": { "ssh_auth_fail": 5 }, "evidence": ["10-30 09:59:00 failed password for alice"], "banned_by": "203.0.113.9", "banned_until": now + HOUR, "geo": "Germany / Example GmbH (AS64496)" }],
            "trusted": [["203.0.113.9", now - DAY]],
            "allowed": [{ "net": "203.0.113.0/24", "until": now + DAY, "note": "customer John's office" }],
        });
        let nodes = vec![node_with("1", "vpn", snap)];
        let q: Net = "203.0.113.9".parse().unwrap();
        let full = address(&nodes, &q);
        assert_eq!(
            (
                full["trusted"].as_array().unwrap().len(),
                full["allowed"].as_array().unwrap().len(),
                full["actions"].as_array().unwrap().len()
            ),
            (1, 1, 3)
        );
        let s = shared(full, &q);
        assert_eq!(s["query"], "203.0.113.9");
        assert!(s["trusted"].as_array().unwrap().is_empty() && s["allowed"].as_array().unwrap().is_empty());
        let b = &s["bans"][0];
        assert_eq!(b["reason"], "burst score", "no points, no addresses");
        assert_eq!(b["node"], "vpn", "names are the caller's to replace (unname_nodes)");
        let actions = s["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 1, "the ban only: no alerts, nothing that merely names the address: {actions:?}");
        let a = &actions[0];
        assert_eq!(
            a["evidence"],
            json!(["10-30 09:59:00 failed password login (account name withheld)", "10-30 09:59:10 invalid user oracle"])
        );
        for gone in ["accounts", "user_note", "notice", "superseded", "topic"] {
            assert!(a.get(gone).is_none(), "{gone} is not a stranger's business");
        }
        let o = &s["offenders"][0];
        assert_eq!(o["evidence"][0], "10-30 09:59:00 failed password login (account name withheld)");
        assert_eq!(o["geo"], "Germany / Example GmbH (AS64496)");
        assert!(o.get("fast").is_none() && o["counts"]["ssh_auth_fail"] == 5);
    }

    pub fn node_with(id: &str, name: &str, snap: Value) -> Node {
        let s = crate::snapshot::trim(&snap.to_string()).unwrap();
        Node {
            id: id.into(),
            addr: format!("{name}:7949"),
            name: name.into(),
            snapshot: Some(Arc::new(s)),
            fetched: Some(1),
            ..Default::default()
        }
    }

    #[test]
    fn merges_nodes() {
        let now = 1_000 * DAY;
        let a = node_with(
            "0",
            "xmpp",
            json!({
                "generated": now, "mode": "enforce",
                "bans": [{"net": "192.0.2.1", "since": now - 10, "until": now + HOUR, "reason": "scan"},
                         {"net": "198.51.100.0/24", "since": now - 5, "until": now + HOUR, "reason": "subnet", "origin": "vpn"}],
                "alerts": [{"ts": now - HOUR, "kind": "alert", "severity": "high", "message": "a"}],
                "recent": [{"ts": now - 3, "kind": "ban", "severity": "high", "message": "ban x"}],
                "offenders": [{"ip": "192.0.2.1", "danger": 80.0}],
                "stats": {"bans": 5, "alerts": 1, "history": [{"minute": now - now % MIN - MIN, "events": [3, 4], "bans": 1}]},
                "world": {"geo": true, "countries": [{"key": "US", "name": "United States", "bans": 1, "offenders": 2, "events": 3}], "ports": [[22, 5]],
                          "by_country": {"US": {"isps": [{"key": "AS64496", "name": "Example", "country": "US", "bans": 1, "offenders": 2, "events": 3}], "ports": [[22, 3]]},
                                         "ZZ": {"isps": [], "ports": [[1, 1]]}},
                          "spots": [{"country": "US", "city": "Ashburn", "lat": 39.04, "lon": -77.49, "bans": 1, "offenders": 2, "events": 3, "logins": 0},
                                    {"country": "US", "lat": 39.04, "lon": -77.49, "bans": 1},
                                    {"country": "us", "lat": 1, "lon": 1, "bans": 9}, {"country": "DE", "lat": 95, "lon": 1, "bans": 9}, {"country": "DE", "bans": 9}]},
                "geoblock": {"what": "CN, RU", "applied": true, "countries": ["CN", "RU", "<b>"], "asns": [1, 2]},
                "port_names": [[22, "ssh"], [5222, "XMPP client"]],
                "cluster": {"node_id": "xmpp", "key_id": "aaaa", "peers": [{"addr": "vpn:7946", "failing_since": now - HOUR, "last_error": "connect: refused"}]},
                "certs": [{"target": "example.org:443", "checked": now, "not_after": now + 3 * DAY, "not_before": now - 80 * DAY}],
            }),
        );
        let b = node_with(
            "1",
            "vpn",
            json!({
                "generated": now, "mode": "shadow",
                "bans": [{"net": "192.0.2.1", "since": now - 1, "until": now + HOUR, "reason": "from xmpp", "origin": "xmpp"}],
                "alerts": [{"ts": now - 2 * DAY, "kind": "alert", "severity": "critical", "message": "old"}],
                "offenders": [{"ip": "203.0.113.9", "danger": 95.0}],
                "world": {"countries": [{"key": "US", "name": "United States", "bans": 2, "offenders": 1, "events": 1}], "ports": [[22, 1], [443, 2]],
                          "by_country": {"US": {"isps": [{"key": "AS64496", "name": "Example", "country": "US", "bans": 2, "offenders": 0, "events": 1}], "ports": [[22, 1], [443, 2]]}},
                          "spots": [{"country": "US", "city": "Ashburn", "lat": 39.044, "lon": -77.487, "bans": 2, "logins": 1}]},
                "cluster": {"node_id": "vpn", "key_id": "bbbb", "peers": []},
                "av": {"last": {"infected_count": 2, "db_outdated": false}},
                "unapplied": 2, "apply_failures": 7,
            }),
        );
        let down = Node {
            id: "2".into(),
            addr: "tg:7949".into(),
            name: "tg:7949".into(),
            error: Some("connect: timed out".into()),
            ..Default::default()
        };
        let v = cluster(&[a, b, down], now, 10, "");
        assert_eq!(v["totals"]["nodes"], 3);
        assert_eq!(v["totals"]["nodes_ok"], 2);
        assert_eq!(v["totals"]["bans"], 3);
        assert_eq!(v["totals"]["bans_unique"], 2);
        assert_eq!(v["totals"]["alerts_24h"], 1);
        assert_eq!(v["nodes"][0]["events_1h"], 7);
        assert_eq!(v["nodes"][0]["bans_from_peers"], 1);
        assert_eq!(v["nodes"][2]["state"], "down");
        assert_eq!(v["bans"][0]["node"], "vpn", "newest first");
        assert_eq!(v["offenders"][0]["ip"], "203.0.113.9", "most dangerous first");
        assert_eq!(v["world"]["countries"][0]["bans"], 3);
        assert_eq!(v["world"]["countries"][0]["nodes"], json!(["vpn", "xmpp"]));
        assert_eq!(v["world"]["ports"][0], json!([22, 6]));
        let us = &v["world"]["by_country"]["US"];
        assert_eq!(us["isps"][0]["bans"], 3);
        assert_eq!(us["isps"][0]["nodes"], json!(["vpn", "xmpp"]));
        assert_eq!(us["ports"], json!([[22, 4], [443, 2]]));
        assert!(v["world"]["by_country"].get("ZZ").is_none(), "only listed countries");
        // a city-level database's spots: one per country, city and coordinates (to a hundredth
        // of a degree), added up across the nodes; a spot in no country or off the globe is dropped
        assert_eq!(
            v["world"]["spots"],
            json!([{"country": "US", "city": "Ashburn", "lat": 39.04, "lon": -77.49, "bans": 3, "offenders": 2, "events": 3, "logins": 1},
                   {"country": "US", "city": "", "lat": 39.04, "lon": -77.49, "bans": 1, "offenders": 0, "events": 0, "logins": 0}]),
            "{}",
            v["world"]["spots"]
        );
        let gb = &v["world"]["geoblock"];
        assert_eq!(gb.as_array().unwrap().len(), 1);
        assert_eq!(gb[0]["node"], "xmpp");
        assert_eq!(gb[0]["countries"], json!(["CN", "RU"]), "codes only");
        assert_eq!(gb[0]["asns"], 2);
        assert_eq!(v["world"]["port_names"]["5222"], "XMPP client");
        let series = &v["history"]["series"][0];
        assert_eq!(series["events"].as_array().unwrap().len(), 180);
        assert_eq!(series["events"][178], 7);
        let texts: Vec<String> =
            v["attention"].as_array().unwrap().iter().map(|a| format!("{} {} {}", a["level"], a["node"], a["text"])).collect();
        let has = |s: &str| texts.iter().any(|t| t.contains(s));
        assert!(has("\"critical\" \"tg:7949\" \"no data"), "{texts:#?}");
        assert!(has("infected"), "{texts:#?}");
        assert!(has("cluster keys differ: aaaa on xmpp; bbbb on vpn"), "{texts:#?}");
        assert!(has("shadow mode"), "{texts:#?}");
        assert!(has("\"high\" \"vpn\" \"2 firewall change(s) could not be applied"), "{texts:#?}");
        assert!(has("cluster peer vpn:7946 unreachable"), "{texts:#?}");
        assert!(has("certificate example.org:443 expires"), "{texts:#?}");
        assert!(has("1 high or critical alert(s)"), "{texts:#?}");
        assert_eq!(v["attention"][0]["level"], "critical", "worst first");
    }

    #[test]
    fn short_lived_certificates_are_fine() {
        let now = 1_000 * DAY;
        let n = node_with("0", "x", json!({"certs": [{"target": "a", "not_after": now + 2 * DAY, "not_before": now - 5 * DAY}]}));
        assert!(problems(&n, now).is_empty(), "{:?}", problems(&n, now));
    }

    #[test]
    fn a_node_on_another_release_is_pointed_out() {
        let now = 1_793_300_000 * crate::time::SEC;
        let mut a = node_with("1", "a", json!({ "generated": now, "bans": [], "stats": { "hours": [] } }));
        a.version = Some("0.3.1".into());
        let texts =
            |v: Value| v["attention"].as_array().unwrap().iter().map(|x| x["text"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert!(texts(cluster(&[a.clone()], now, 10, "0.3.4")).iter().any(|t| t == "vpsfort-web 0.3.1 (expected 0.3.4)"));
        assert!(!texts(cluster(&[a.clone()], now, 10, "0.3.1")).iter().any(|t| t.starts_with("vpsfort-web")));
        assert!(!texts(cluster(&[a], now, 10, "")).iter().any(|t| t.starts_with("vpsfort-web")), "no expectation: no row");
    }
}
