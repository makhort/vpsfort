//! vpsfort-sim: a simulated vpsfort cluster and its web console, from decision logs or a
//! console export, in one process. Each node answers on a console socket the way vpsfort's
//! `[console]` socket does (its snapshot from vpsfort's own log reader, its digest from
//! vpsfort's renderer, its abuse reports from vpsfort's live report); a real vpsfort-web
//! agent sits on each, and a real vpsfort-web console on the first node's socket and the
//! other nodes' agents, exactly the production layout. What the console needs (web key, the
//! admin's password and one-time secret, the certificate) is made when missing, and said.
//!
//!   vpsfort-sim --init [vpsfort-sim.toml]    writes an example configuration
//!   vpsfort-sim [vpsfort-sim.toml]           runs it

mod config;
mod node;
mod proxy;
mod state;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use vpsfort_web::agent::{self, AgentCfg};
use vpsfort_web::auth::{Auth, AuthCfg};
use vpsfort_web::console::{self, Console, ConsoleCfg};
use vpsfort_web::fleet::Fleet;
use vpsfort_web::local::Local;
use vpsfort_web::netlist::Allow;
use vpsfort_web::{digests, tls};

use config::Config;
use node::{Node, Peer};

const DEFAULT_CONFIG: &str = "vpsfort-sim.toml";
/// Unix socket paths are short on every system (104 bytes on macOS and the BSDs).
const MAX_SOCKET_PATH: usize = 100;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("--init") => init(args.get(1).map(PathBuf::from)),
        Some("-h" | "--help") => {
            println!("vpsfort-sim [config.toml]      run the simulated cluster ({DEFAULT_CONFIG} by default)\nvpsfort-sim --init [config.toml]   write an example configuration");
            Ok(())
        }
        Some(p) if p.starts_with('-') => Err(anyhow::anyhow!("unknown option {p} (--init, --help)")),
        Some(p) => run(Path::new(p)),
        None => run(Path::new(DEFAULT_CONFIG)),
    };
    if let Err(e) = result {
        eprintln!("vpsfort-sim: {e:#}");
        std::process::exit(1);
    }
}

fn init(path: Option<PathBuf>) -> Result<()> {
    let path = path.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    if path.exists() {
        bail!("{} exists already", path.display());
    }
    std::fs::write(&path, config::EXAMPLE).with_context(|| format!("writing {}", path.display()))?;
    println!("wrote {}: point its [[node]] entries at your decision logs, then run  vpsfort-sim {}", path.display(), path.display());
    Ok(())
}

/// A node to make: from a log or from a snapshot.
struct Spec {
    name: String,
    actions: Option<String>,
    snapshot: Option<Value>,
    addr: IpAddr,
    backend: String,
}

/// Documentation addresses for nodes without one.
fn default_address(i: usize) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 10 + (i as u8 % 200)))
}

fn run(config_path: &Path) -> Result<()> {
    let cfg = Config::load(config_path)?;
    println!("vpsfort-sim {} with {}", env!("CARGO_PKG_VERSION"), config_path.display());
    let (files, key) = state::prepare(&cfg.dir, cfg.totp)?;
    let socks = cfg.dir.join("sock");
    let logs = cfg.dir.join("logs");
    std::fs::create_dir_all(&socks)?;
    std::fs::create_dir_all(&logs)?;

    // the nodes: the configured ones, then the export's
    let mut specs: Vec<Spec> = Vec::new();
    for (i, n) in cfg.nodes.iter().enumerate() {
        let addr = if n.address.is_empty() {
            default_address(i)
        } else {
            n.address.parse().with_context(|| format!("node {}: address", n.name))?
        };
        let backend = if n.backend.is_empty() { "nftables".to_string() } else { n.backend.clone() };
        if !n.actions.is_empty() {
            specs.push(Spec { name: n.name.clone(), actions: Some(n.actions.clone()), snapshot: None, addr, backend });
        } else {
            let text = std::fs::read_to_string(&n.snapshot).with_context(|| format!("node {}: reading {}", n.name, n.snapshot))?;
            let v: Value = serde_json::from_str(&text).with_context(|| format!("node {}: {} is not JSON", n.name, n.snapshot))?;
            // a node's "Snapshot" download, or its "Download JSON" (summary + snapshot)
            let snap = if v.get("snapshot").is_some_and(|s| s.is_object()) { v["snapshot"].clone() } else { v };
            specs.push(Spec { name: n.name.clone(), actions: None, snapshot: Some(snap), addr, backend });
        }
    }
    if !cfg.export.is_empty() {
        let text = std::fs::read_to_string(&cfg.export).with_context(|| format!("reading the export {}", cfg.export))?;
        let v: Value = serde_json::from_str(&text).with_context(|| format!("{}: not JSON", cfg.export))?;
        let Some(list) = v["nodes"].as_array() else { bail!("{}: not a console export (no nodes)", cfg.export) };
        for n in list {
            let name = n["name"].as_str().unwrap_or("").to_string();
            if name.is_empty() || !vpsfort_web::node_name_ok(&name) || specs.iter().any(|s| s.name == name) {
                continue;
            }
            match n.get("snapshot").filter(|s| s.is_object()) {
                Some(s) => {
                    let i = specs.len();
                    let backend = s["backend"].as_str().unwrap_or("nftables").to_string();
                    specs.push(Spec { name, actions: None, snapshot: Some(s.clone()), addr: default_address(i), backend });
                }
                None => println!("export: node {name} has no snapshot in it (it was down): left out"),
            }
        }
    }
    if specs.is_empty() {
        bail!("no node to simulate");
    }
    let longest = specs.iter().map(|s| socks.join(format!("{}.sock", s.name)).as_os_str().len()).max().unwrap_or(0);
    if longest > MAX_SOCKET_PATH {
        bail!("dir = {} is too long for Unix sockets ({longest} bytes with the node names; at most {MAX_SOCKET_PATH}): use a shorter dir, e.g. /tmp/vpsfort-sim", cfg.dir.display());
    }

    let peers: Vec<Peer> = specs.iter().map(|s| Peer { name: s.name.clone(), addr: s.addr }).collect();
    let now = vpsfort::time::now();
    let mut nodes: Vec<Arc<Node>> = Vec::new();
    for (i, Spec { name, actions, snapshot, addr, backend }) in specs.into_iter().enumerate() {
        let socket = socks.join(format!("{name}.sock"));
        let node = match (actions, snapshot) {
            (Some(path), _) => {
                let shift = if cfg.shift_to_now {
                    let acts = node::read_log(Path::new(&path), None)?;
                    Some(now - 30 * vpsfort::time::SEC - node::last_time(&acts))
                } else {
                    None
                };
                Node::from_log(i, &name, addr, &backend, Path::new(&path), &logs, socket, shift, cfg.fill, &peers)?
            }
            (None, Some(snap)) => Node::from_snapshot(i, &name, addr, snap, socket),
            (None, None) => unreachable!(),
        };
        let node = Arc::new(node);
        println!("node {}", node.describe());
        Arc::clone(&node).start(cfg.trickle_secs)?;
        nodes.push(node);
    }

    // a real agent on every node but the first (the console reads that one's socket itself)
    let mut remotes = Vec::new();
    for (i, n) in nodes.iter().enumerate().skip(1) {
        let port = u16::try_from(i).ok().and_then(|i| cfg.agent_port.checked_add(i)).context("agent_port too high for this many nodes")?;
        let listen = format!("127.0.0.1:{port}");
        let addr = agent::serve(
            AgentCfg { listen, allow: Allow::Any, keys: vec![key], node: n.name.clone() },
            Arc::new(Local::new(n.socket.clone())),
        )?;
        println!("agent for {} on {addr}", n.name);
        remotes.push(addr.to_string());
    }
    let first = &nodes[0];
    let local = Arc::new(Local::new(first.socket.clone()));
    let fleet = Arc::new(Fleet::new(Some(key), Some(local), first.name.clone(), &remotes, Duration::from_secs(cfg.refresh_secs)));
    let auth = Auth::new(AuthCfg {
        password_file: files.password.clone(),
        totp_file: cfg.totp.then(|| files.totp.clone()),
        admins_dir: files.admins.clone(),
        idle: Duration::from_secs(30 * 60),
        max: Duration::from_secs(12 * 3600),
        state_dir: None,
    });
    let console_cfg = ConsoleCfg {
        listen: cfg.console_listen.clone(),
        allow: Allow::Any,
        tls: tls::server_config(files.cert.clone(), files.key.clone())?,
        metrics_token: None,
        refresh_secs: cfg.refresh_secs,
        node: first.name.clone(),
        rdap: false,
        login_work: cfg.login_work,
        tls_cert: files.cert.clone(),
        expected_version: cfg.expected_version.clone(),
        // the simulator starts afresh each run: its history and marks live in memory
        state_dir: None,
        history_days: 7,
        digest_days: 14,
    };
    let console = Arc::new(Console::new(console_cfg, auth, fleet));
    let addr = console::serve(Arc::clone(&console))?;
    digests::collect_daily(console);
    println!("console on https://{addr} (on {} with {} agent{})", first.name, remotes.len(), if remotes.len() == 1 { "" } else { "s" });
    if !cfg.plain_http.is_empty() {
        proxy::serve(&cfg.plain_http, &addr.to_string())?;
        println!("the same over plain HTTP on http://{} (for a browser that can't take the certificate)", cfg.plain_http);
    }
    println!(
        "log in as \"admin\" with the password in {}{}{}",
        files.password.display(),
        if cfg.totp { " and the one-time code" } else { " (no one-time code: totp = false)" },
        if cfg.login_work > 0 { format!("; the proof of work is {} bits", cfg.login_work) } else { String::new() }
    );
    println!("(the password is \"{}\" when the simulator made the file)", state::DEFAULT_PASSWORD);
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
