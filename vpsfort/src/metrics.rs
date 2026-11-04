//! Prometheus metrics without the web console: `[metrics] textfile` names a file the daemon
//! rewrites every `every` in the text exposition format, for node_exporter's textfile
//! collector (`--collector.textfile.directory`). The series are named as vpsfort-web's
//! `/metrics` names them, so one set of alerting rules fits both. Nothing names an attacker's
//! address or an account.

use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::engine::Snapshot;
use crate::time::{Dur, Micros, SEC};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsCfg {
    /// The file to write, e.g. `/var/lib/prometheus/node-exporter/vpsfort.prom`; empty: off.
    pub textfile: PathBuf,
    pub every: Dur,
}

impl Default for MetricsCfg {
    fn default() -> Self {
        MetricsCfg { textfile: PathBuf::new(), every: Dur(60) }
    }
}

impl MetricsCfg {
    pub fn enabled(&self) -> bool {
        !self.textfile.as_os_str().is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        if self.enabled() {
            if !self.textfile.is_absolute() {
                bail!("[metrics] textfile must be an absolute path");
            }
            if self.textfile.extension().is_none_or(|e| e != "prom") {
                bail!("[metrics] textfile must end in .prom (node_exporter reads those)");
            }
            if self.every.0 < 10 {
                bail!("[metrics] every must be at least 10s");
            }
        }
        Ok(())
    }
}

struct Out(String);

impl Out {
    fn head(&mut self, name: &str, help: &str, kind: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    fn line(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        let labels: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{}\"", escape(v))).collect();
        let labels = if labels.is_empty() { String::new() } else { format!("{{{}}}", labels.join(",")) };
        let _ = writeln!(self.0, "{name}{labels} {}", fmt(value));
    }

    fn gauge(&mut self, name: &str, help: &str, labels: &[(&str, &str)], value: f64) {
        self.head(name, help, "gauge");
        self.line(name, labels, value);
    }

    fn counter(&mut self, name: &str, help: &str, value: f64) {
        self.head(name, help, "counter");
        self.line(name, &[], value);
    }
}

fn escape(v: &str) -> String {
    v.chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '\\' => "\\\\".to_string(),
            '"' => "\\\"".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn fmt(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

fn secs(t: Micros) -> f64 {
    (t / SEC) as f64
}

/// The exposition text for one snapshot (`backend`: the enforcer's name).
pub fn render(s: &Snapshot, backend: &str) -> String {
    let mut o = Out(String::new());
    let mode = format!("{:?}", s.mode).to_lowercase();
    o.gauge("vpsfort_info", "vpsfort's mode and firewall backend.", &[("mode", &mode), ("backend", backend), ("version", &s.version)], 1.0);
    o.gauge("vpsfort_enforcing", "1 in enforce mode, 0 in shadow mode.", &[], if mode == "enforce" { 1.0 } else { 0.0 });
    o.gauge("vpsfort_started_timestamp_seconds", "When vpsfort started.", &[], secs(s.started));
    o.gauge("vpsfort_snapshot_timestamp_seconds", "When this file was written.", &[], secs(s.generated));
    o.gauge("vpsfort_tracked_addresses", "Addresses with a score.", &[], s.tracked_ips as f64);
    o.gauge("vpsfort_tracked_connections", "Client connections still in their grace time.", &[], s.tracked_connections as f64);
    o.gauge("vpsfort_offenders", "Addresses listed as offenders.", &[], s.offenders.len() as f64);
    o.head("vpsfort_active_bans", "Active bans, by origin (local or the peer that decided) and kind.", "gauge");
    let mut by: std::collections::BTreeMap<(String, &str), u32> = std::collections::BTreeMap::new();
    for b in &s.bans {
        *by.entry((b.origin.clone().unwrap_or_else(|| "local".into()), if b.net.is_host() { "address" } else { "network" }))
            .or_default() += 1;
    }
    for ((origin, kind), n) in by {
        o.line("vpsfort_active_bans", &[("origin", &origin), ("kind", kind)], n as f64);
    }
    o.counter("vpsfort_bans_total", "Bans decided since the start.", s.stats.bans as f64);
    o.counter("vpsfort_alerts_total", "Alerts raised since the start.", s.stats.alerts as f64);
    let hour = s.generated - 3600 * SEC;
    let (mut bans_hour, mut events_hour) = (0u64, 0u64);
    for m in s.stats.history.iter().filter(|m| m.minute >= hour) {
        bans_hour += u64::from(m.bans);
        events_hour += m.events.iter().map(|e| u64::from(*e)).sum::<u64>();
    }
    o.gauge("vpsfort_bans_last_hour", "Bans in the last hour.", &[], bans_hour as f64);
    o.gauge("vpsfort_events_last_hour", "Events in the last hour.", &[], events_hour as f64);
    o.head("vpsfort_records_total", "Log records read since the start, per source.", "counter");
    for (src, n) in &s.stats.records {
        o.line("vpsfort_records_total", &[("source", src.name())], *n as f64);
    }
    o.head("vpsfort_events_total", "Events scored since the start, per signal.", "counter");
    for (sig, n) in &s.stats.events {
        o.line("vpsfort_events_total", &[("signal", sig.name())], *n as f64);
    }
    o.counter("vpsfort_unattributed_lines_total", "Lines with no address to score.", s.stats.unattributed as f64);
    o.head("vpsfort_last_line_timestamp_seconds", "The newest line read, per source.", "gauge");
    for (src, t) in &s.last_lines {
        o.line("vpsfort_last_line_timestamp_seconds", &[("source", src.name())], secs(*t));
    }
    o.gauge("vpsfort_accounts_with_failures", "Accounts with failed logins lately.", &[], s.accounts.len() as f64);
    o.gauge(
        "vpsfort_accounts_under_attack",
        "Accounts under distributed guessing now.",
        &[],
        s.accounts.iter().filter(|a| a.under_attack).count() as f64,
    );
    o.gauge("vpsfort_trusted_addresses", "Addresses that logged in lately.", &[], s.trusted.len() as f64);
    o.gauge("vpsfort_operator_allowlist_entries", "Operator allowlist entries.", &[], s.allowed.len() as f64);
    o.gauge(
        "vpsfort_unapplied_changes",
        "Firewall changes the firewall program refused, waiting to be tried again.",
        &[],
        s.unapplied as f64,
    );
    o.counter("vpsfort_apply_failures_total", "Attempts to apply a firewall change that failed since the start.", s.apply_failures as f64);
    o.gauge("vpsfort_quiet", "1 while admin messages are held back (vpsfort quiet).", &[], if s.quiet.is_some() { 1.0 } else { 0.0 });
    if let Some(f) = &s.feeds {
        o.head("vpsfort_feed_networks", "Blocklist networks loaded, per family.", "gauge");
        o.line("vpsfort_feed_networks", &[("family", "ipv4")], f.v4 as f64);
        o.line("vpsfort_feed_networks", &[("family", "ipv6")], f.v6 as f64);
        o.gauge("vpsfort_feed_applied", "1 when the feeds are in the firewall.", &[], if f.applied { 1.0 } else { 0.0 });
        o.gauge("vpsfort_feed_error", "1 when the latest feed refresh failed.", &[], if f.error.is_some() { 1.0 } else { 0.0 });
        o.gauge("vpsfort_feed_refreshed_timestamp_seconds", "When the feeds were last refreshed.", &[], secs(f.refreshed));
    }
    if let Some(g) = &s.geoblock {
        o.gauge(
            "vpsfort_geoblock_applied",
            "1 when the country and network blocks are in the firewall.",
            &[],
            if g.applied { 1.0 } else { 0.0 },
        );
    }
    if let Some(c) = &s.cluster {
        o.gauge("vpsfort_cluster_info", "This node's name and key.", &[("node_id", &c.node_id), ("key_id", &c.key_id)], 1.0);
        o.head("vpsfort_cluster_peer_up", "1 when the peer took the last delivery.", "gauge");
        for p in &c.peers {
            o.line("vpsfort_cluster_peer_up", &[("peer", &p.addr)], if p.last_error.is_none() && p.last_ok.is_some() { 1.0 } else { 0.0 });
        }
        o.head(
            "vpsfort_cluster_peer_forward_secret",
            "1 when the last delivery to the peer had forward secrecy, 0 for a plain frame.",
            "gauge",
        );
        for p in &c.peers {
            if let Some(fs) = p.forward_secret {
                o.line("vpsfort_cluster_peer_forward_secret", &[("peer", &p.addr)], if fs { 1.0 } else { 0.0 });
            }
        }
        o.gauge("vpsfort_cluster_facts_known", "Facts held.", &[], c.facts_known as f64);
        o.counter("vpsfort_cluster_facts_received_total", "Facts received.", c.facts_received as f64);
        o.counter("vpsfort_cluster_facts_sent_total", "Facts sent.", c.facts_sent as f64);
        o.counter("vpsfort_cluster_rejected_total", "Messages rejected.", c.rejected as f64);
    }
    if !s.certs.is_empty() {
        o.head("vpsfort_cert_expiry_timestamp_seconds", "When the certificate expires.", "gauge");
        o.head("vpsfort_cert_error", "1 when the certificate could not be checked.", "gauge");
        o.head("vpsfort_cert_dane_mismatch", "1 when the published TLSA record doesn't match the certificate served.", "gauge");
        for c in &s.certs {
            if let Some(t) = c.not_after {
                o.line("vpsfort_cert_expiry_timestamp_seconds", &[("target", &c.target)], secs(t));
            }
            o.line("vpsfort_cert_error", &[("target", &c.target)], if c.error.is_some() { 1.0 } else { 0.0 });
            if let Some(ok) = c.dane {
                o.line("vpsfort_cert_dane_mismatch", &[("target", &c.target)], if ok { 0.0 } else { 1.0 });
            }
        }
    }
    if !s.dns.is_empty() {
        o.head("vpsfort_dns_name_ours", "1 when the name resolves to this host, 0 when it resolves elsewhere or not at all.", "gauge");
        for d in &s.dns {
            o.line("vpsfort_dns_name_ours", &[("name", &d.name)], if d.ours { 1.0 } else { 0.0 });
        }
    }
    if let Some(h) = &s.heartbeat {
        o.gauge("vpsfort_heartbeat_failures", "Heartbeat pings that failed in a row.", &[], f64::from(h.failures));
        if let Some(t) = h.last_ok {
            o.gauge("vpsfort_heartbeat_last_ok_timestamp_seconds", "When the heartbeat URL was last reached.", &[], secs(t));
        }
    }
    if let Some(r) = &s.resources {
        o.head("vpsfort_disk_free_ratio", "Free share of the filesystem.", "gauge");
        for d in &r.disks {
            o.line("vpsfort_disk_free_ratio", &[("mount", &d.mount)], d.free_percent() / 100.0);
        }
        if let Some(m) = &r.memory {
            o.gauge("vpsfort_memory_available_ratio", "Available share of memory.", &[], m.avail_percent() / 100.0);
            if let Some(p) = m.psi_full {
                o.gauge(
                    "vpsfort_memory_pressure_ratio",
                    "Share of time tasks stalled on memory (full avg300).",
                    &[("kind", "full")],
                    p / 100.0,
                );
            }
        }
        if let Some(c) = r.clock_synced {
            o.gauge("vpsfort_clock_synced", "1 when the clock is synchronised with NTP.", &[], if c { 1.0 } else { 0.0 });
        }
    }
    if let Some(p) = &s.patches {
        if let Some(n) = p.upgradable {
            o.gauge("vpsfort_updates_pending", "Pending package upgrades.", &[], n as f64);
        }
        o.gauge("vpsfort_security_updates", "Pending security upgrades.", &[], p.security_count as f64);
        o.gauge("vpsfort_reboot_required", "1 when a reboot is needed.", &[], if p.reboot_required { 1.0 } else { 0.0 });
        o.gauge(
            "vpsfort_processes_using_replaced_files",
            "Processes still running replaced programs or libraries.",
            &[],
            p.stale.len() as f64,
        );
        o.gauge("vpsfort_updates_checked_timestamp_seconds", "When the patch status was last read.", &[], secs(p.read));
    }
    if let Some(av) = &s.av {
        if let Some(last) = &av.last {
            o.gauge("vpsfort_av_infected_files", "Infected files the last scan found.", &[], last.infected_count as f64);
            o.gauge("vpsfort_av_last_scan_timestamp_seconds", "When the last scan finished.", &[], secs(av.completed));
        }
    }
    if let Some(v) = &s.verify {
        o.gauge("vpsfort_verify_checked_files", "Package files checked by the last pass.", &[], v.checked as f64);
        o.gauge("vpsfort_verify_mismatched_files", "Package files that differ from their package.", &[], v.mismatched as f64);
        o.gauge("vpsfort_verify_setuid_programs", "Set-uid and set-gid programs known.", &[], v.suid as f64);
        o.gauge("vpsfort_verify_last_run_timestamp_seconds", "When the last pass ran.", &[], secs(v.last_run));
    }
    if let Some(c) = &s.cron {
        o.gauge("vpsfort_cron_tasks", "Scheduled tasks watched.", &[], c.tasks as f64);
        o.gauge("vpsfort_cron_scripts", "Scripts they run, watched.", &[], c.scripts as f64);
        o.gauge("vpsfort_cron_files", "Other files watched.", &[], c.files as f64);
        o.gauge("vpsfort_cron_scanned_timestamp_seconds", "When the last scan ran.", &[], secs(c.scanned));
    }
    if let Some(p) = &s.procwatch {
        o.gauge("vpsfort_procwatch_pairs", "Outbound (program, port) pairs known.", &[], p.pairs as f64);
        o.gauge("vpsfort_procwatch_outbound", "Outbound connections at the last scan.", &[], p.outbound as f64);
        if let Some(n) = p.modules {
            o.gauge("vpsfort_procwatch_kernel_modules", "Kernel modules known.", &[], n as f64);
        }
        if let Some(n) = p.containers {
            o.gauge("vpsfort_procwatch_containers", "Containers known.", &[], n as f64);
        }
        if let Some(n) = p.wg_peers {
            o.gauge("vpsfort_procwatch_wireguard_peers", "WireGuard peers known.", &[], n as f64);
        }
    }
    if let Some(e) = &s.exposure {
        o.gauge(
            "vpsfort_listeners",
            "Listeners reachable from the internet.",
            &[("exposure", "public")],
            e.listeners.iter().filter(|l| l.exposure.is_exposed()).count() as f64,
        );
        o.gauge("vpsfort_firewall_dead_rules", "Allow rules with nothing listening.", &[], e.dead_rules.len() as f64);
    }
    o.0
}

/// Writes the file atomically (a temporary file renamed into place), readable by all. The
/// directory is node_exporter's, not vpsfort's: whoever writes there could put a link under
/// the temporary name, and root would write through it into any file. So the temporary file
/// is made afresh (`O_EXCL`, which never follows a link; a leftover of an interrupted write
/// goes first), and the rename replaces whatever holds the final name, a link included.
pub fn write(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("prom.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_exposition_format() {
        let cfg = std::sync::Arc::new(crate::config::Config::default());
        let e = crate::engine::Engine::new(cfg, 1_700_000_000 * SEC);
        let mut s = e.snapshot(0, 10);
        s.version = "0.4.0".into();
        s.dns = vec![crate::dnscheck::DnsStatus { name: "a\"b".into(), ours: false, ..Default::default() }];
        let text = render(&s, "nftables");
        assert!(text.starts_with("# HELP vpsfort_info vpsfort's mode and firewall backend.\n# TYPE vpsfort_info gauge\nvpsfort_info{mode=\"shadow\",backend=\"nftables\",version=\"0.4.0\"} 1\n"), "{text}");
        assert!(text.contains("\nvpsfort_enforcing 0\n") && text.contains("\nvpsfort_bans_total 0\n"), "{text}");
        assert!(text.contains("vpsfort_dns_name_ours{name=\"a\\\"b\"} 0\n"), "labels are escaped: {text}");
        assert!(text.contains("vpsfort_started_timestamp_seconds 1700000000\n"));
        assert!(!text.contains("NaN") && text.lines().all(|l| l.starts_with('#') || l.starts_with("vpsfort_")), "{text}");
        assert_eq!(fmt(0.5), "0.5");
        let cfg = MetricsCfg { textfile: "/var/lib/node_exporter/vpsfort.prom".into(), ..Default::default() };
        cfg.validate().unwrap();
        assert!(MetricsCfg { textfile: "relative.prom".into(), ..Default::default() }.validate().is_err());
        assert!(MetricsCfg { textfile: "/x/vpsfort.txt".into(), ..Default::default() }.validate().is_err());
        let d = std::env::temp_dir().join(format!("lg-metrics-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        write(&d.join("vpsfort.prom"), &text).unwrap();
        assert_eq!(std::fs::read_to_string(d.join("vpsfort.prom")).unwrap(), text);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The textfile's directory belongs to node_exporter's user: a link planted there, under
    /// the temporary name or the final one, is never written through.
    #[test]
    fn a_planted_link_is_not_written_through() {
        let d = std::env::temp_dir().join(format!("lg-metrics-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let victim = d.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, d.join("vpsfort.prom.tmp")).unwrap();
        std::os::unix::fs::symlink(&victim, d.join("vpsfort.prom")).unwrap();
        write(&d.join("vpsfort.prom"), "vpsfort_enforcing 1\n").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep", "nothing went through the links");
        assert_eq!(std::fs::read_to_string(d.join("vpsfort.prom")).unwrap(), "vpsfort_enforcing 1\n");
        assert!(std::fs::symlink_metadata(d.join("vpsfort.prom")).unwrap().file_type().is_file(), "the link is gone");
        let _ = std::fs::remove_dir_all(&d);
    }
}
