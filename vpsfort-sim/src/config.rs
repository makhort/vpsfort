//! The simulator's configuration (`vpsfort-sim.toml`): where its files go, what it listens
//! on, and the nodes with where each one's state comes from.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Where the simulator keeps what it makes: the web key, the admin's password and TOTP
    /// secret, the certificate, the nodes' sockets and shifted logs. Keep it short: Unix
    /// sockets live in it, and their paths may not exceed about 100 bytes.
    pub dir: PathBuf,
    /// The web console (HTTPS).
    pub console_listen: String,
    /// A plain-HTTP door to the same console, for a browser that can't take the self-signed
    /// certificate (an automated one); a loopback address only; empty: none.
    pub plain_http: String,
    /// The first node's agent listens on 127.0.0.1 at this port, the next ones on the ports
    /// after it.
    pub agent_port: u16,
    /// Logins ask for a one-time code too (the secret is made and printed when missing).
    pub totp: bool,
    /// The proof of work before a login, in bits (the real default is 20; 0: off).
    pub login_work: u8,
    /// How old the nodes' data may get while a page is open.
    pub refresh_secs: u64,
    /// The vpsfort-web release every node should run (`EXPECTED_VERSION`); empty: no check.
    pub expected_version: String,
    /// Shift each decision log so that it ends now (the console's windows and charts then
    /// show the log's last day as today's); off: the logs' own times.
    pub shift_to_now: bool,
    /// Every this many seconds a node whose state comes from a log gets a new ban (copied
    /// from the log, stamped now), now and then an alert too; 0: nothing moves.
    pub trickle_secs: u64,
    /// Add what a decision log doesn't carry (the cluster view, certificates, disk and
    /// memory, antivirus, updates...), varied per node, so every card has something.
    pub fill: bool,
    /// A console export (the Overview's "Export JSON"): its nodes, with their snapshots as
    /// they were, unless `[[node]]` entries are given too (those come first).
    pub export: String,
    #[serde(rename = "node")]
    pub nodes: Vec<NodeCfg>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            dir: PathBuf::from("/tmp/vpsfort-sim"),
            console_listen: "127.0.0.1:7948".into(),
            plain_http: String::new(),
            agent_port: 7960,
            totp: true,
            login_work: 8,
            refresh_secs: 10,
            expected_version: String::new(),
            shift_to_now: true,
            trickle_secs: 20,
            fill: true,
            export: String::new(),
            nodes: vec![],
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeCfg {
    pub name: String,
    /// The node's decision log (`actions.jsonl`, or a rotated `.gz` copy): its state is what
    /// vpsfort's own `tui --actions` makes of it, the abuse reports its own too.
    pub actions: String,
    /// Instead of a log: a node's snapshot as the console saves it ("Snapshot" on a node's
    /// page, or an entry of an export), used as it is.
    pub snapshot: String,
    /// The node's public address, as the abuse reports name it.
    pub address: String,
    /// The firewall backend shown ("nftables", "firewalld", "ufw").
    pub backend: String,
}

/// The example written by `--init`.
pub const EXAMPLE: &str = r#"# vpsfort-sim: a simulated cluster and its web console, from decision logs.
# Paths are relative to this file. Run:  vpsfort-sim vpsfort-sim.toml

# Where the simulator keeps what it makes (keys, the admin's files, the certificate, sockets).
# Short: Unix sockets live here.
dir = "/tmp/vpsfort-sim"
console_listen = "127.0.0.1:7948"
# A plain-HTTP door for a browser that can't take the self-signed certificate; empty: none.
plain_http = ""
agent_port = 7960
totp = true
login_work = 8
shift_to_now = true
trickle_secs = 20
fill = true
# A console export ("Export JSON" on the Overview) instead of, or besides, the nodes below.
export = ""

[[node]]
name = "node1"
actions = "logs/node1.actions.jsonl"
address = "203.0.113.10"
backend = "nftables"

[[node]]
name = "node2"
actions = "logs/node2.actions.jsonl"
address = "203.0.113.20"
backend = "nftables"

# [[node]]
# name = "node3"
# snapshot = "vpsfort-node3-snapshot.json"   # a node's Snapshot download, as it is
# address = "198.51.100.5"
"#;

impl Config {
    /// Reads the file; relative paths in it are from its directory.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: Config = toml::from_str(&text).with_context(|| format!("{}: not a simulator configuration", path.display()))?;
        let base = path.parent().filter(|p| !p.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        let abs = |p: &str| -> String {
            if p.is_empty() || Path::new(p).is_absolute() {
                p.to_string()
            } else {
                base.join(p).display().to_string()
            }
        };
        if cfg.dir.is_relative() {
            cfg.dir = base.join(&cfg.dir);
        }
        cfg.export = abs(&cfg.export);
        for n in &mut cfg.nodes {
            n.actions = abs(&n.actions);
            n.snapshot = abs(&n.snapshot);
        }
        cfg.check()?;
        Ok(cfg)
    }

    fn check(&self) -> Result<()> {
        if self.nodes.is_empty() && self.export.is_empty() {
            bail!("no nodes: add [[node]] entries (actions = \"<log>\") or export = \"<console export>\"");
        }
        for (i, n) in self.nodes.iter().enumerate() {
            if n.name.is_empty() || !vpsfort_web::node_name_ok(&n.name) {
                bail!("node {}: a name of 1-64 letters, digits, dots, dashes or underscores", i + 1);
            }
            if n.actions.is_empty() == n.snapshot.is_empty() {
                bail!("node {}: either actions = \"<log>\" or snapshot = \"<json>\"", n.name);
            }
            if self.nodes.iter().filter(|x| x.name == n.name).count() > 1 {
                bail!("node {} is listed twice", n.name);
            }
        }
        if self.console_listen.parse::<std::net::SocketAddr>().is_err() {
            bail!("console_listen: host:port, e.g. 127.0.0.1:7948");
        }
        if !self.plain_http.is_empty() {
            // the door strips TLS and the same-origin checks: it is for a browser on this machine
            match self.plain_http.parse::<std::net::SocketAddr>() {
                Ok(a) if a.ip().is_loopback() => {}
                Ok(_) => bail!("plain_http: a loopback address only (127.0.0.1:7950): it serves the console without TLS"),
                Err(_) => bail!("plain_http: host:port, or empty"),
            }
        }
        if !(2..=3600).contains(&self.refresh_secs) {
            bail!("refresh_secs: 2 to 3600");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_example_loads_and_paths_follow_the_file() {
        let dir = std::env::temp_dir().join(format!("vpsfort-sim-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vpsfort-sim.toml");
        std::fs::write(&path, EXAMPLE).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.nodes.len(), 2);
        assert!(cfg.nodes[0].actions.ends_with("logs/node1.actions.jsonl"));
        assert!(Path::new(&cfg.nodes[0].actions).is_absolute() || cfg.nodes[0].actions.starts_with(dir.to_str().unwrap()));
        assert_eq!(cfg.dir, PathBuf::from("/tmp/vpsfort-sim"));
        std::fs::write(&path, "dir = \"x\"\n[[node]]\nname = \"a\"\n").unwrap();
        assert!(Config::load(&path).unwrap_err().to_string().contains("either actions"));
        std::fs::write(&path, "nothing = 1\n").unwrap();
        assert!(Config::load(&path).is_err(), "unknown keys are refused");
        std::fs::write(&path, "plain_http = \"0.0.0.0:7950\"\n[[node]]\nname = \"a\"\nactions = \"a.jsonl\"\n").unwrap();
        assert!(Config::load(&path).unwrap_err().to_string().contains("loopback"), "the plain door stays on this machine");
        std::fs::write(&path, "plain_http = \"127.0.0.1:7950\"\n[[node]]\nname = \"a\"\nactions = \"a.jsonl\"\n").unwrap();
        assert!(Config::load(&path).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
