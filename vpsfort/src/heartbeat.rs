//! A dead-man's switch: vpsfort fetches a URL every few minutes, so a service outside
//! (healthchecks.io, Uptime Kuma's push monitors, a cron monitor of your own) notices when
//! the node, or the whole cluster, goes dark. Peers only cover each other. Nothing but the
//! node's address leaves the server, and the URL itself (which may hold a token) is never
//! shown whole.

use std::process::Command;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::time::{self, Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeartbeatCfg {
    /// The URL to fetch; empty: off.
    pub url: String,
    pub every: Dur,
    /// The program that fetches it (the URL is appended), as for blocklist feeds.
    pub fetch: Vec<String>,
}

impl Default for HeartbeatCfg {
    fn default() -> Self {
        HeartbeatCfg {
            url: String::new(),
            every: Dur(300),
            fetch: ["curl", "-fsS", "--max-time", "20", "-o", "/dev/null", "--proto-redir", "=https"].map(String::from).to_vec(),
        }
    }
}

impl HeartbeatCfg {
    pub fn enabled(&self) -> bool {
        !self.url.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        let local =
            self.url.starts_with("http://127.0.0.1") || self.url.starts_with("http://localhost") || self.url.starts_with("http://[::1]");
        if !self.url.starts_with("https://") && !local {
            bail!("[heartbeat] url must be https:// (a token in it would otherwise travel in clear)");
        }
        if self.every.0 < 60 {
            bail!("[heartbeat] every must be at least 60s");
        }
        if self.fetch.is_empty() {
            bail!("[heartbeat] fetch needs a program");
        }
        Ok(())
    }
}

/// The last pings, for `status` and the snapshot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HeartbeatStatus {
    /// The URL with its path cut: `https://hc-ping.com/…`.
    pub url: String,
    pub last_ok: Option<Micros>,
    pub last_error: Option<String>,
    /// Pings that failed in a row.
    pub failures: u32,
}

/// The URL without its path or query: what a status page may show.
pub fn redact(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if scheme.is_empty() {
        format!("{host}/…")
    } else {
        format!("{scheme}://{host}/…")
    }
}

/// One ping. The error names the program's complaint, never the URL.
pub fn ping(cfg: &HeartbeatCfg) -> Result<(), String> {
    let mut cmd = Command::new(&cfg.fetch[0]);
    cmd.args(&cfg.fetch[1..]).arg(&cfg.url);
    let out = crate::proc::run(cmd, None, std::time::Duration::from_secs(60)).map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let err = err.lines().next().unwrap_or("failed").replace(&cfg.url, &redact(&cfg.url));
    Err(crate::event::clean(&err, 200))
}

impl HeartbeatStatus {
    pub fn record(&mut self, cfg: &HeartbeatCfg, result: Result<(), String>, now: Micros) {
        self.url = redact(&cfg.url);
        match result {
            Ok(()) => {
                self.last_ok = Some(now);
                self.last_error = None;
                self.failures = 0;
            }
            Err(e) => {
                self.failures += 1;
                self.last_error = Some(e.replace(&cfg.url, &redact(&cfg.url)));
            }
        }
    }

    /// Whether the failures so far are worth a line in the journal: the first, then hourly.
    pub fn worth_logging(&self, cfg: &HeartbeatCfg) -> bool {
        let per_hour = (3600 / cfg.every.0.max(60)).max(1) as u32;
        self.failures == 1 || self.failures.is_multiple_of(per_hour)
    }

    pub fn summary(&self, now: Micros) -> String {
        match (&self.last_error, self.last_ok) {
            (Some(e), ok) => format!(
                "{} failing ({} in a row): {e}{}",
                self.url,
                self.failures,
                ok.map(|t| format!("; last reached {} ago", time::fmt_duration(now - t))).unwrap_or_default()
            ),
            (None, Some(t)) => format!("{} reached {} ago", self.url, time::fmt_duration(now - t)),
            (None, None) => format!("{} not tried yet", self.url),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_and_validates() {
        assert_eq!(redact("https://hc-ping.com/3f1c-secret-uuid"), "https://hc-ping.com/…");
        assert_eq!(redact("https://example.org"), "https://example.org/…");
        assert_eq!(redact("example.org/x?token=1"), "example.org/…");
        let mut cfg = HeartbeatCfg { url: "http://example.org/ping".into(), ..Default::default() };
        assert!(cfg.validate().unwrap_err().to_string().contains("https"));
        cfg.url = "https://example.org/ping".into();
        cfg.validate().unwrap();
        cfg.url = "http://127.0.0.1:9/ping".into();
        cfg.validate().unwrap();
        cfg.every = Dur(10);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn status_counts_failures_and_logs_hourly() {
        let cfg = HeartbeatCfg { url: "https://hc-ping.com/abc".into(), every: Dur(300), ..Default::default() };
        let mut st = HeartbeatStatus::default();
        st.record(&cfg, Err("curl: (7) Failed to connect https://hc-ping.com/abc".into()), 1000 * crate::time::SEC);
        assert!(st.last_error.as_deref().unwrap().contains("https://hc-ping.com/…"), "{:?}", st.last_error);
        assert!(st.worth_logging(&cfg), "the first failure");
        for _ in 0..10 {
            st.record(&cfg, Err("x".into()), 1000 * crate::time::SEC);
        }
        assert_eq!(st.failures, 11);
        assert!(!st.worth_logging(&cfg));
        st.record(&cfg, Err("x".into()), 0);
        assert!(st.worth_logging(&cfg), "the 12th: an hour of pings every 5 minutes");
        st.record(&cfg, Ok(()), 2000 * crate::time::SEC);
        assert_eq!((st.failures, st.last_error.is_none(), st.last_ok), (0, true, Some(2000 * crate::time::SEC)));
        assert!(
            st.summary(2060 * crate::time::SEC).contains("reached ") && st.summary(2060 * crate::time::SEC).contains(" ago"),
            "{}",
            st.summary(2060 * crate::time::SEC)
        );
        assert!(ping(&HeartbeatCfg { url: "https://127.0.0.1:1/x".into(), fetch: vec!["/nonexistent/curl".into()], ..Default::default() })
            .is_err());
    }
}
