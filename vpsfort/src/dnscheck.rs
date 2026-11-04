//! The host's own names: do they still resolve to this host? A record changed at the
//! registrar or the DNS provider (a hijack, or an expired domain taken over) sends users,
//! federation and mail elsewhere while the server runs on, with nothing in its logs. One
//! lookup per name an hour, through the system's resolver.

use std::net::{IpAddr, ToSocketAddrs};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::time::{self, Dur, Micros};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsCfg {
    /// Names that must resolve to one of this host's addresses; empty: off.
    pub names: Vec<String>,
    pub interval: Dur,
}

impl Default for DnsCfg {
    fn default() -> Self {
        DnsCfg { names: vec![], interval: Dur(3600) }
    }
}

impl DnsCfg {
    pub fn enabled(&self) -> bool {
        !self.names.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        for n in &self.names {
            if n.is_empty() || n.contains(|c: char| c.is_whitespace() || c == '/' || c == ':') {
                bail!("[dns] names: '{n}' is not a host name");
            }
        }
        if self.enabled() && self.interval.0 < 60 {
            bail!("[dns] interval must be at least 60s");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsStatus {
    pub name: String,
    pub checked: Micros,
    /// What the name resolves to now.
    pub addresses: Vec<IpAddr>,
    /// Whether one of them is this host's.
    pub ours: bool,
    /// The resolver's complaint (no such name, no answer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Looks `name` up and compares with this host's addresses.
pub fn check(name: &str, own: &[IpAddr]) -> DnsStatus {
    let resolved = (name, 0u16).to_socket_addrs().map(|a| a.map(|s| crate::net::normalize(s.ip())).collect::<Vec<_>>());
    judge(name, resolved.map_err(|e| e.to_string()), own, time::now())
}

pub fn judge(name: &str, resolved: Result<Vec<IpAddr>, String>, own: &[IpAddr], now: Micros) -> DnsStatus {
    let mut st = DnsStatus { name: name.into(), checked: now, ..Default::default() };
    match resolved {
        Ok(mut addrs) => {
            addrs.sort();
            addrs.dedup();
            addrs.truncate(32);
            st.ours = addrs.iter().any(|a| own.contains(a));
            if addrs.is_empty() {
                st.error = Some("no address".into());
            }
            st.addresses = addrs;
        }
        Err(e) => st.error = Some(crate::event::clean(&e, 200)),
    }
    st
}

impl DnsStatus {
    /// The alert this deserves, if any: (gate key, period, severity, message).
    pub fn concern(&self, own: &[IpAddr]) -> Option<(String, Micros, crate::engine::Severity, String)> {
        use crate::engine::Severity;
        let list = |a: &[IpAddr]| a.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", ");
        let six_hours = 6 * 3600 * time::SEC;
        if let Some(e) = &self.error {
            return Some((
                format!("dns-error:{}", self.name),
                six_hours,
                Severity::Warning,
                format!("DNS: {} doesn't resolve ({e}): clients can't reach this host by that name - dig +short {}", self.name, self.name),
            ));
        }
        if self.ours {
            return None;
        }
        Some((
            format!("dns:{}", self.name),
            six_hours,
            Severity::High,
            format!(
                "DNS: {} resolves to {}, none of them this host's address ({}): the record was changed (a hijack, a takeover of the \
                 domain?) or this host moved - dig +short {}",
                self.name,
                list(&self.addresses),
                list(own),
                self.name
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Severity;

    #[test]
    fn a_name_pointing_elsewhere_is_high_and_a_missing_one_a_warning() {
        let own: Vec<IpAddr> = vec!["203.0.113.10".parse().unwrap(), "2001:db8::10".parse().unwrap()];
        let ok = judge("example.org", Ok(vec!["2001:db8::10".parse().unwrap(), "203.0.113.10".parse().unwrap()]), &own, 1);
        assert!(ok.ours && ok.concern(&own).is_none());
        let moved = judge("example.org", Ok(vec!["198.51.100.5".parse().unwrap(), "198.51.100.5".parse().unwrap()]), &own, 1);
        assert_eq!(moved.addresses.len(), 1, "deduplicated");
        let (key, _, sev, msg) = moved.concern(&own).unwrap();
        assert_eq!((key.as_str(), sev), ("dns:example.org", Severity::High));
        assert!(msg.contains("resolves to 198.51.100.5, none of them this host's address (203.0.113.10, 2001:db8::10)"), "{msg}");
        let gone = judge("example.org", Err("failed to lookup address information: Name or service not known".into()), &own, 1);
        let (key, _, sev, msg) = gone.concern(&own).unwrap();
        assert_eq!((key.as_str(), sev), ("dns-error:example.org", Severity::Warning));
        assert!(msg.contains("doesn't resolve"), "{msg}");
        assert!(judge("x", Ok(vec![]), &own, 1).error.is_some(), "no address at all");
        assert!(DnsCfg { names: vec!["a b".into()], ..Default::default() }.validate().is_err());
        assert!(DnsCfg { names: vec!["example.org".into()], ..Default::default() }.validate().is_ok());
    }
}
