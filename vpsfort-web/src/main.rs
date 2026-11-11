use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use vpsfort_web::agent::{self, AgentCfg};
use vpsfort_web::auth::{self, Auth, AuthCfg};
use vpsfort_web::console::{self, Console, ConsoleCfg};
use vpsfort_web::fleet::{self, Fleet};
use vpsfort_web::local::Local;
use vpsfort_web::netlist::Allow;
use vpsfort_web::{envfile, say, tls, totp, wire};

/// Read-only web console for a vpsfort cluster. On every node, the agent hands that node's
/// vpsfort data (bans, alerts, health) to the consoles, sealed with the web key; on the
/// node(s) you choose, the console shows the whole cluster over HTTPS to one admin, who
/// logs in with a password and a one-time code. Nothing here can ban, unban or allow.
///
/// Every option can also come from the environment variable named after it, so config.env
/// works as the unit's EnvironmentFile.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// This node's name in the consoles [default: vpsfort's [cluster] node_id, else the host name].
    #[arg(long, env = "NODE_NAME", default_value = "", global = true)]
    node_name: String,
    /// vpsfort's read-only console socket ([console] socket in vpsfort.toml); empty on a
    /// console host without vpsfort.
    #[arg(long, env = "VPSFORT_SOCKET", default_value = "/run/vpsfort-console/console.sock", global = true, value_parser = path_or_empty)]
    vpsfort_socket: PathBuf,
    /// The web key (`keygen`), the same file on every node. Never vpsfort's cluster key: that
    /// one makes bans, and the console must not be able to.
    #[arg(long, env = "WEB_KEY_FILE", default_value = "/opt/vpsfort-web/web.key", global = true)]
    web_key_file: PathBuf,
    /// Where the agent takes the consoles' requests (`0.0.0.0:7949`); empty: no agent.
    #[arg(long, env = "AGENT_LISTEN", default_value = "", global = true)]
    agent_listen: String,
    /// The consoles' addresses or networks, separated by commas or blanks; "any" lets any
    /// address try (the web key still decides).
    #[arg(long, env = "AGENT_ALLOW", default_value = "", global = true)]
    agent_allow: String,
    /// Where the console serves HTTPS; empty: no console.
    #[arg(long, env = "CONSOLE_LISTEN", default_value = "", global = true)]
    console_listen: String,
    /// The addresses or networks the admin connects from; empty or "any": every address may
    /// see the login page.
    #[arg(long, env = "CONSOLE_ALLOW", default_value = "", global = true)]
    console_allow: String,
    /// The other nodes' agents, `host:port`, separated by commas or blanks.
    #[arg(long, env = "NODES", default_value = "", global = true)]
    nodes: String,
    /// The console's certificate chain (PEM): `gen-cert` makes a self-signed one, or use a
    /// Let's Encrypt one (read again when it changes).
    #[arg(long, env = "TLS_CERT", default_value = "/opt/vpsfort-web/tls.crt", global = true)]
    tls_cert: PathBuf,
    #[arg(long, env = "TLS_KEY", default_value = "/opt/vpsfort-web/tls.key", global = true)]
    tls_key: PathBuf,
    /// The first admin's ("admin") password hash (`passwd`).
    #[arg(long, env = "PASSWORD_FILE", default_value = "/opt/vpsfort-web/admin.password", global = true)]
    password_file: PathBuf,
    /// The other admins' password hashes and TOTP secrets (`passwd --user <name>`,
    /// `totp-setup --user <name>`): `<name>.password`, `<name>.totp`.
    #[arg(long, env = "ADMINS_DIR", default_value = "/opt/vpsfort-web/admins", global = true)]
    admins_dir: PathBuf,
    /// on: a one-time code from an authenticator app too (`totp-setup`); off: the password only.
    #[arg(long, env = "TOTP", default_value_t = true, action = clap::ArgAction::Set, value_parser = clap::builder::BoolishValueParser::new(), global = true)]
    totp: bool,
    #[arg(long, env = "TOTP_FILE", default_value = "/opt/vpsfort-web/admin.totp", global = true)]
    totp_file: PathBuf,
    /// A token (`keygen --out`) that lets Prometheus read /metrics without a login.
    #[arg(long, env = "METRICS_TOKEN_FILE", global = true)]
    metrics_token_file: Option<PathBuf>,
    /// on: the console looks up a network's abuse mailbox (RDAP, rdap.org) when an admin asks;
    /// off: the admin's browser asks rdap.org itself.
    #[arg(long, env = "RDAP_LOOKUPS", default_value_t = true, action = clap::ArgAction::Set, value_parser = clap::builder::BoolishValueParser::new(), global = true)]
    rdap_lookups: bool,
    /// Proof of work before each login: the page's JavaScript finds a hash with this many
    /// leading zero bits (20: about a second; each failure lately adds bits); 0: off.
    #[arg(long, env = "LOGIN_WORK", default_value_t = 20, global = true)]
    login_work: u8,
    /// The console asks the nodes again after this many seconds (only while someone looks).
    #[arg(long, env = "REFRESH_SECS", default_value_t = 10, global = true)]
    refresh_secs: u64,
    /// A session ends after this many minutes without a request...
    #[arg(long, env = "SESSION_IDLE_MINUTES", default_value_t = 30, global = true)]
    session_idle_minutes: u64,
    /// ...and this many hours after the login.
    #[arg(long, env = "SESSION_MAX_HOURS", default_value_t = 12, global = true)]
    session_max_hours: u64,
    /// The vpsfort-web release every node should run (e.g. "0.3.4"): a node on another is
    /// pointed out on the Overview. Nothing is downloaded. Empty: no check.
    #[arg(long, env = "EXPECTED_VERSION", default_value = "", global = true)]
    expected_version: String,
    /// Where the console keeps its attention history, the nodes' digests and the admins'
    /// marks across restarts (the unit's StateDirectory); empty: in memory only.
    #[arg(long, env = "STATE_DIR", default_value = "/var/lib/vpsfort-web", global = true, value_parser = path_or_empty)]
    state_dir: PathBuf,
    /// Days the attention history keeps a problem that went.
    #[arg(long, env = "HISTORY_DAYS", default_value_t = 7, global = true, value_parser = clap::value_parser!(u32).range(1..=3650))]
    history_days: u32,
    /// Days of each node's digests kept.
    #[arg(long, env = "DIGEST_DAYS", default_value_t = 14, global = true, value_parser = clap::value_parser!(u32).range(1..=3650))]
    digest_days: u32,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Check the settings, keys and files; ask this node's vpsfort and every agent in NODES once.
    Check,
    /// A new random key (32 bytes, base64): the web key, or a metrics token. To OUT (mode 0640,
    /// never overwritten), else to stdout.
    Keygen {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// The web key's fingerprint: the same on every node that has the same key.
    KeyId,
    /// A self-signed certificate (ECDSA P-256, five years) for the names given, to TLS_CERT and
    /// TLS_KEY; prints its fingerprint, to compare with the browser's.
    GenCert {
        /// Host names or addresses the console is reached by [default: the host name].
        #[arg(long = "name")]
        names: Vec<String>,
        /// Replace existing files.
        #[arg(long)]
        force: bool,
    },
    /// The SHA-256 fingerprint of TLS_CERT, as browsers show it.
    Fingerprint,
    /// Set an admin's password (asked twice, not shown; at least 12 characters). A new name
    /// makes a new admin, who may do all the first one may (then `totp-setup --user`).
    Passwd {
        /// Read it from the first line of stdin instead.
        #[arg(long)]
        stdin: bool,
        /// The admin: "admin" (the first), or another name (lowercase letters, digits, - and _).
        #[arg(long, default_value = auth::MAIN)]
        user: String,
    },
    /// Make an admin's TOTP secret for an authenticator app: printed as a QR code and as text.
    TotpSetup {
        /// Replace the existing secret (the app's old entry stops working).
        #[arg(long)]
        force: bool,
        #[arg(long, default_value = auth::MAIN)]
        user: String,
        /// Write the secret without asking for a code from the app first (scripts).
        #[arg(long)]
        no_confirm: bool,
    },
    /// List the admins and whether each can log in.
    Admins,
    /// An admin's passkeys (security keys, phones), as registered on the "Your account" page.
    Passkeys {
        /// The admin [default: admin].
        #[arg(long)]
        user: Option<String>,
    },
    /// Remove one of an admin's passkeys (a lost key), by the id `passkeys` shows.
    RemovePasskey {
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        id: String,
    },
    /// Remove an admin other than "admin": their files go, their sessions end at their next request.
    RemoveAdmin { user: String },
}

/// Exit status for a setting or file that keeps the service from starting; the unit doesn't
/// restart it (`RestartPreventExitStatus=78`).
const EX_CONFIG: u8 = 78;

#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

fn refuse<T>(msg: impl Into<String>) -> Result<T> {
    Err(Refused(msg.into()).into())
}

/// A path that may be empty (clap's own path parser refuses an empty value).
fn path_or_empty(s: &str) -> Result<PathBuf, std::convert::Infallible> {
    Ok(PathBuf::from(s))
}

fn list(s: &str) -> Vec<String> {
    s.split([',', ' ', '\t', '\n', ';']).filter(|x| !x.is_empty()).map(String::from).collect()
}

impl Args {
    fn key(&self) -> Result<[u8; 32]> {
        let text = fs::read_to_string(&self.web_key_file).with_context(|| {
            format!("reading WEB_KEY_FILE {} (make it with `vpsfort-web keygen --out ...`)", self.web_key_file.display())
        })?;
        wire::decode_key(&text)
    }

    /// The key, and the ones a rotation leaves next to it (`<file>.next`, `<file>.prev`):
    /// the agent accepts requests under any of them, the console sends under the first.
    /// A rotation file that isn't a key stops the start, as vpsfort's does.
    fn keys(&self) -> Result<Vec<[u8; 32]>> {
        let mut keys = vec![self.key()?];
        for ext in ["next", "prev"] {
            let p = self.web_key_file.with_extension(ext);
            if p.exists() {
                let text = fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
                keys.push(wire::decode_key(&text).with_context(|| format!("{} (a key rotation's file)", p.display()))?);
            }
        }
        Ok(keys)
    }

    fn state_dir(&self) -> Option<PathBuf> {
        (!self.state_dir.as_os_str().is_empty()).then(|| self.state_dir.clone())
    }

    fn local(&self) -> Option<Arc<Local>> {
        (!self.vpsfort_socket.as_os_str().is_empty()).then(|| Arc::new(Local::new(self.vpsfort_socket.clone())))
    }

    fn remotes(&self) -> Result<Vec<String>> {
        let nodes = list(&self.nodes);
        if let Some(bad) = nodes.iter().find(|n| n.rsplit_once(':').is_none_or(|(_, p)| p.parse::<u16>().is_err())) {
            return refuse(format!("NODES: '{bad}' must be host:port"));
        }
        Ok(nodes)
    }

    fn auth_cfg(&self) -> AuthCfg {
        AuthCfg {
            password_file: self.password_file.clone(),
            totp_file: self.totp.then(|| self.totp_file.clone()),
            admins_dir: self.admins_dir.clone(),
            idle: Duration::from_secs(self.session_idle_minutes.max(1) * 60),
            max: Duration::from_secs(self.session_max_hours.max(1) * 3600),
            state_dir: self.state_dir(),
        }
    }

    /// The running console's: its sessions and lockouts read back.
    fn auth(&self) -> Auth {
        Auth::new(self.auth_cfg())
    }

    /// For a command: the admins' files, not the running console's state.
    fn admins(&self) -> Auth {
        Auth::files(self.auth_cfg())
    }

    fn agent_allow(&self) -> Result<Allow> {
        if self.agent_allow.trim().is_empty() {
            return refuse("AGENT_ALLOW: the consoles' addresses (or \"any\": the web key alone decides)");
        }
        Allow::parse(&self.agent_allow).map_err(|e| Refused(format!("AGENT_ALLOW: {e:#}")).into())
    }

    fn validate(&self) -> Result<()> {
        if self.agent_listen.is_empty() && self.console_listen.is_empty() {
            return refuse(
                "nothing to do: set AGENT_LISTEN (this node's data for the consoles), CONSOLE_LISTEN (the web console), or both",
            );
        }
        if !self.console_listen.is_empty() && self.local().is_none() && list(&self.nodes).is_empty() {
            return refuse("CONSOLE_LISTEN without data: set VPSFORT_SOCKET, NODES, or both");
        }
        if !(2..=3600).contains(&self.refresh_secs) {
            return refuse("REFRESH_SECS: 2 to 3600");
        }
        if !self.node_name.is_empty() && !vpsfort_web::node_name_ok(&self.node_name) {
            return refuse("NODE_NAME: 1-64 letters, digits, dots, dashes or underscores");
        }
        Ok(())
    }
}

fn main() -> ExitCode {
    // config.env as the unit reads it, for the commands run by hand (the service has it already)
    let env_path = std::env::var_os("VPSFORT_WEB_CONFIG").map_or_else(|| PathBuf::from(envfile::DEFAULT_PATH), PathBuf::from);
    let env_file = if env_path.as_os_str().is_empty() { None } else { envfile::load(&env_path).map(|n| (env_path, n)) };
    let args = Args::parse();
    let result = match &args.cmd {
        None => run(&args),
        Some(Cmd::Check) => check(&args, env_file.as_ref()),
        Some(Cmd::Keygen { out }) => keygen(out.as_deref()),
        Some(Cmd::KeyId) => args.keys().map(|keys| {
            for (i, k) in keys.iter().enumerate() {
                let what = match i {
                    0 => "",
                    _ if args.web_key_file.with_extension("next").exists() && i == 1 => "  (next: a rotation in progress)",
                    _ => "  (prev: a rotation in progress)",
                };
                println!("{}{what}", wire::key_id(k));
            }
        }),
        Some(Cmd::GenCert { names, force }) => gen_cert(&args, names, *force),
        Some(Cmd::Fingerprint) => tls::file_fingerprint(&args.tls_cert).map(|f| println!("{f}")),
        Some(Cmd::Passkeys { user }) => {
            let auth = args.admins();
            let who = user.as_deref().unwrap_or(auth::MAIN);
            let list = auth.passkeys(who);
            if list.is_empty() {
                println!("{who}: no passkeys (added on the console's \"Your account\" page)");
            }
            for c in list {
                println!(
                    "{}  {:<12} {:<24} added {}  logins {}{}",
                    c.id,
                    if c.alg == -7 { "P-256" } else { "Ed25519" },
                    c.name,
                    vpsfort_web::time::fmt_ts(c.added),
                    c.logins,
                    c.last_used.map(|t| format!(", last {}", vpsfort_web::time::fmt_ts(t))).unwrap_or_default()
                );
            }
            Ok(())
        }
        Some(Cmd::RemovePasskey { user, id }) => {
            let auth = args.admins();
            let who = user.as_deref().unwrap_or(auth::MAIN);
            auth.remove_passkey(who, id).and_then(|removed| {
                if removed {
                    println!("removed; {} passkey(s) left for {who}", auth.passkeys(who).len());
                    Ok(())
                } else {
                    bail!("{who} has no passkey with that id (see `vpsfort-web passkeys --user {who}`)")
                }
            })
        }
        Some(Cmd::Passwd { stdin, user }) => passwd(&args, user, *stdin),
        Some(Cmd::TotpSetup { force, user, no_confirm }) => totp_setup(&args, user, *force, !*no_confirm),
        Some(Cmd::Admins) => admins(&args),
        Some(Cmd::RemoveAdmin { user }) => remove_admin(&args, user),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            say!("vpsfort-web: {e:#}");
            if e.downcast_ref::<Refused>().is_some() {
                ExitCode::from(EX_CONFIG)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run(args: &Args) -> Result<()> {
    args.validate()?;
    let remotes = args.remotes()?;
    let needs_key = !args.agent_listen.is_empty() || !remotes.is_empty();
    let keys = if needs_key { args.keys().map_err(|e| Refused(format!("{e:#}")))? } else { vec![] };
    let key = keys.first().copied();
    let local = args.local();
    let mut said = Vec::new();
    if !args.agent_listen.is_empty() {
        let cfg =
            AgentCfg { listen: args.agent_listen.clone(), allow: args.agent_allow()?, keys: keys.clone(), node: args.node_name.clone() };
        let local =
            local.clone().ok_or_else(|| Refused("AGENT_LISTEN needs VPSFORT_SOCKET: the agent hands out this node's data".into()))?;
        let addr = agent::serve(cfg, local)?;
        said.push(format!("agent on {addr}"));
    }
    if !args.console_listen.is_empty() {
        let tls = tls::server_config(args.tls_cert.clone(), args.tls_key.clone())
            .map_err(|e| Refused(format!("{e:#} (make a certificate with `vpsfort-web gen-cert`)")))?;
        let auth = args.auth();
        auth.check_files().map_err(|e| Refused(format!("{e:#}")))?;
        auth::warm();
        let accounts = auth.accounts();
        for a in &accounts[1..] {
            if let Err(e) = auth.check_account(a) {
                say!("vpsfort-web: admin {} can't log in: {e:#}", a.name);
            }
        }
        let metrics_token = match &args.metrics_token_file {
            Some(f) => Some(auth::read_secret(f).map_err(|e| Refused(format!("METRICS_TOKEN_FILE: {e:#}")))?).filter(|t| t.len() >= 16),
            None => None,
        };
        if args.metrics_token_file.is_some() && metrics_token.is_none() {
            return refuse("METRICS_TOKEN_FILE: at least 16 characters (make one with `vpsfort-web keygen --out ...`)");
        }
        let fleet = Arc::new(Fleet::new(key, local.clone(), args.node_name.clone(), &remotes, Duration::from_secs(args.refresh_secs)));
        let node = match &local {
            Some(l) => agent::node_name(&args.node_name, l),
            None => vpsfort_web::hostname(),
        };
        let cfg = ConsoleCfg {
            listen: args.console_listen.clone(),
            allow: Allow::parse(&args.console_allow).map_err(|e| Refused(format!("CONSOLE_ALLOW: {e:#}")))?,
            tls,
            metrics_token,
            refresh_secs: args.refresh_secs,
            node,
            rdap: args.rdap_lookups,
            login_work: args.login_work,
            tls_cert: args.tls_cert.clone(),
            expected_version: args.expected_version.trim().to_string(),
            state_dir: args.state_dir(),
            history_days: args.history_days,
            digest_days: args.digest_days,
        };
        let console = Arc::new(Console::new(cfg, auth, fleet));
        if let Some(d) = args.state_dir() {
            match fs::create_dir_all(&d).and_then(|()| fs::metadata(&d)) {
                Ok(_) => said.push(format!("state in {}", d.display())),
                Err(e) => say!("vpsfort-web: STATE_DIR {}: {e}: the history, digests and marks live in memory", d.display()),
            }
        }
        let addr = console::serve(Arc::clone(&console))?;
        vpsfort_web::digests::collect_daily(console);
        let fp = tls::file_fingerprint(&args.tls_cert).unwrap_or_default();
        said.push(format!(
            "console on https://{addr} ({} node{}, {} admin{}, {}; certificate {fp})",
            remotes.len() + usize::from(local.is_some()),
            if remotes.len() + usize::from(local.is_some()) == 1 { "" } else { "s" },
            accounts.len(),
            if accounts.len() == 1 { "" } else { "s" },
            if args.totp { "password and code" } else { "password only" },
        ));
    }
    let key_note = match keys.as_slice() {
        [] => String::new(),
        [k] => format!(", web key {}", wire::key_id(k)),
        [k, rest @ ..] => format!(
            ", web key {} (rotation: also accepting {})",
            wire::key_id(k),
            rest.iter().map(wire::key_id).collect::<Vec<_>>().join(", ")
        ),
    };
    say!("vpsfort-web {} started: {}{key_note}", env!("CARGO_PKG_VERSION"), said.join("; "));
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, Arc::clone(&stop))?;
    }
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(500));
    }
    say!("vpsfort-web stopping");
    Ok(())
}

fn check(args: &Args, env_file: Option<&(PathBuf, usize)>) -> Result<()> {
    match env_file {
        Some((path, n)) => println!("settings: {} ({n} from the file, the rest from the environment)", path.display()),
        None => println!("settings: from the environment and the options (no config.env read)"),
    }
    args.validate()?;
    let remotes = args.remotes()?;
    let mut problems = 0;
    let mut line = |ok: bool, what: String| {
        if !ok {
            problems += 1;
        }
        println!("{} {what}", if ok { "ok  " } else { "FAIL" });
    };
    let key = match args.keys() {
        Ok(keys) => {
            let k = keys[0];
            let extra = if keys.len() > 1 {
                format!("; a rotation is in progress: also accepting {}", keys[1..].iter().map(wire::key_id).collect::<Vec<_>>().join(", "))
            } else {
                String::new()
            };
            line(true, format!("web key {} (compare `vpsfort-web key-id` on the other nodes){extra}", wire::key_id(&k)));
            Some(k)
        }
        Err(e) if !args.agent_listen.is_empty() || !remotes.is_empty() => {
            line(false, format!("{e:#}"));
            None
        }
        Err(_) => None,
    };
    if let Some(local) = args.local() {
        match local.snapshot() {
            Ok(s) => {
                let mode = s.value.get("mode").and_then(|m| m.as_str()).unwrap_or("?").to_string();
                line(
                    true,
                    format!(
                        "this node's vpsfort: {mode} mode, {} active bans, as '{}'",
                        s.len_of("bans"),
                        agent::node_name(&args.node_name, &local)
                    ),
                );
            }
            Err(e) => line(false, format!("this node's vpsfort: {e:#}")),
        }
    }
    if !args.agent_listen.is_empty() {
        match args.agent_allow() {
            Ok(_) => line(true, format!("agent: AGENT_LISTEN {}, AGENT_ALLOW {}", args.agent_listen, args.agent_allow)),
            Err(e) => line(false, format!("{e:#}")),
        }
    }
    if !args.console_listen.is_empty() {
        match tls::server_config(args.tls_cert.clone(), args.tls_key.clone()) {
            Ok(_) => line(
                true,
                format!("certificate {}: {}", args.tls_cert.display(), tls::file_fingerprint(&args.tls_cert).unwrap_or_default()),
            ),
            Err(e) => line(false, format!("certificate: {e:#}")),
        }
        let auth = args.admins();
        for a in auth.accounts() {
            match auth.check_account(&a) {
                Ok(()) => {
                    let keys = auth.passkeys(&a.name).len();
                    let keys = if keys > 0 { format!(", {keys} passkey(s)") } else { String::new() };
                    line(
                        true,
                        format!("admin {}: password{}{keys}", a.name, if args.totp { " and one-time code" } else { " only (TOTP=off)" }),
                    )
                }
                Err(e) => line(false, format!("admin {}: {e:#}", a.name)),
            }
        }
        if let Err(e) = Allow::parse(&args.console_allow) {
            line(false, format!("CONSOLE_ALLOW: {e:#}"));
        }
        match args.state_dir() {
            Some(d) => {
                let writable = fs::create_dir_all(&d).is_ok() && fs::metadata(&d).is_ok_and(|m| !m.permissions().readonly());
                line(
                    writable,
                    format!(
                        "STATE_DIR {}: the attention history ({} days), the nodes' digests ({} days), the marks, the share links, the lockouts and the sessions survive a restart there{}",
                        d.display(),
                        args.history_days,
                        args.digest_days,
                        if writable { "" } else { " (not writable: they would live in memory)" }
                    ),
                );
            }
            None => line(true, "STATE_DIR empty: the attention history, digests, marks, share links, lockouts and sessions live in memory (a restart forgets them)".into()),
        }
        if args.login_work > 0 {
            let d = args.login_work.min(vpsfort_web::work::MAX_DIFFICULTY);
            let t = vpsfort_web::work::time_solve(d);
            line(true, format!("proof of work before a login: {d} bits, solved here in {:.1} s (a phone takes a few times longer; each failure lately doubles it)", t.as_secs_f64()));
        } else {
            line(true, "proof of work before a login: off (LOGIN_WORK=0)".into());
        }
        for addr in &remotes {
            let Some(key) = &key else { break };
            match fleet::fetch(addr, key, wire::Want::Snapshot) {
                Ok(r) => match (&r.error, &r.snapshot) {
                    (None, Some(_)) => line(true, format!("node {addr}: '{}', vpsfort-web {}", r.node, r.version)),
                    (e, _) => line(false, format!("node {addr} ('{}'): its vpsfort: {}", r.node, e.as_deref().unwrap_or("no data"))),
                },
                Err(e) => line(false, format!("node {addr}: {e:#}")),
            }
        }
    }
    if problems > 0 {
        bail!("{problems} problem(s)");
    }
    Ok(())
}

/// Writes a secret file: mode 0640, the group of its directory (`/opt/vpsfort-web` is
/// root:vpsfort-web, so the service may read it), replaced atomically; an existing file only
/// with `force`.
fn write_secret(path: &Path, content: &str, mode: u32, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!("{} exists already (--force replaces it)", path.display());
    }
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".{}.tmp", path.file_name().context("no file name")?.to_string_lossy()));
    let _ = fs::remove_file(&tmp);
    let mut f =
        OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(content.as_bytes())?;
    // the mode asked for, whatever the umask of the shell this runs in: under 077 the service
    // (the group) could not read its own secrets, under 002 others could change them
    f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(mode))?;
    f.sync_all()?;
    if let Ok(gid) = fs::metadata(dir).map(|m| m.gid()) {
        // as root; another user's file keeps its own group
        let _ = std::os::unix::fs::fchown(&f, None, Some(gid));
    }
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn keygen(out: Option<&Path>) -> Result<()> {
    let key = wire::generate_key();
    match out {
        Some(p) => {
            write_secret(p, &format!("{key}\n"), 0o640, false)?;
            eprintln!("written to {} (fingerprint {})", p.display(), wire::key_id(&wire::decode_key(&key)?));
        }
        None => println!("{key}"),
    }
    Ok(())
}

fn gen_cert(args: &Args, names: &[String], force: bool) -> Result<()> {
    let names = if names.is_empty() { vec![vpsfort_web::hostname()] } else { names.to_vec() };
    if !force && (args.tls_cert.exists() || args.tls_key.exists()) {
        bail!("{} or {} exists already (--force replaces them)", args.tls_cert.display(), args.tls_key.display());
    }
    let (cert, key, fp) = tls::self_signed(&names)?;
    write_secret(&args.tls_key, &key, 0o640, true)?;
    write_secret(&args.tls_cert, &cert, 0o644, true)?;
    println!("certificate for {} in {}", names.join(", "), args.tls_cert.display());
    println!("SHA-256 fingerprint (compare it with the browser's when it asks to trust the certificate):");
    println!("  {fp}");
    Ok(())
}

/// Reads a line from the terminal without showing it.
fn ask_hidden(prompt: &str) -> Result<String> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty").context("no terminal: use --stdin")?;
    use std::os::fd::AsRawFd;
    let fd = tty.as_raw_fd();
    // SAFETY: termios is plain data, filled by tcgetattr before use; fd is open for the call.
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
        bail!("not a terminal: use --stdin");
    }
    let saved = term;
    term.c_lflag &= !libc::ECHO;
    term.c_lflag |= libc::ECHONL;
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    let mut w = &tty;
    let _ = write!(w, "{prompt}");
    let _ = w.flush();
    let mut line = String::new();
    let read = std::io::BufReader::new(&tty).read_line(&mut line);
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    read?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Admin `user`'s files, refused for a name that can't be one.
fn account(args: &Args, user: &str) -> Result<auth::Account> {
    args.admins()
        .account(user)
        .with_context(|| format!("'{user}' can't be an admin's name: 1-32 lowercase letters, digits, - and _, starting with a letter"))
}

/// `ADMINS_DIR`, made the first time like `/opt/vpsfort-web`: root's, its group's (the
/// service's) to read.
fn admins_dir(args: &Args) -> Result<()> {
    let dir = &args.admins_dir;
    if dir.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new().mode(0o750).create(dir).with_context(|| format!("creating {}", dir.display()))?;
    if let Some(gid) = dir.parent().and_then(|p| fs::metadata(p).ok()).map(|m| m.gid()) {
        let _ = std::os::unix::fs::chown(dir, None, Some(gid));
    }
    Ok(())
}

fn admins(args: &Args) -> Result<()> {
    let auth = args.admins();
    for a in auth.accounts() {
        let state = match auth.check_account(&a) {
            Ok(()) => "can log in".to_string(),
            Err(e) => format!("can't log in: {e:#}"),
        };
        println!("{:<20} {state}", a.name);
    }
    Ok(())
}

fn remove_admin(args: &Args, user: &str) -> Result<()> {
    let a = account(args, user)?;
    if a.name == auth::MAIN {
        bail!("\"admin\" stays: change its password with `passwd`, or its codes with `totp-setup --force`");
    }
    if !a.password_file.exists() {
        bail!("no admin {user}");
    }
    let totp = args.admins_dir.join(format!("{user}.totp"));
    let old_passkeys = a.legacy_passkeys.clone().unwrap_or_else(|| a.passkeys_file.clone());
    for f in [&a.password_file, &totp, &a.passkeys_file, &old_passkeys] {
        match fs::remove_file(f) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", f.display())),
        }
    }
    println!("admin {user} removed (their sessions end at their next request)");
    Ok(())
}

fn passwd(args: &Args, user: &str, stdin: bool) -> Result<()> {
    let a = account(args, user)?;
    let password = if stdin {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    } else {
        let first = ask_hidden(&format!("New console password for {}: ", a.name))?;
        if ask_hidden("Again: ")? != first {
            bail!("the two differ: nothing changed");
        }
        first
    };
    if password.chars().count() < auth::MIN_PASSWORD {
        bail!("at least {} characters", auth::MIN_PASSWORD);
    }
    if password.len() > 1024 {
        bail!("at most 1024 bytes");
    }
    if a.name != auth::MAIN {
        admins_dir(args)?;
    }
    let new = !a.password_file.exists();
    write_secret(&a.password_file, &format!("{}\n", auth::hash_password(&password)?), 0o640, true)?;
    println!("password of {} set in {} (this admin's sessions end at their next request)", a.name, a.password_file.display());
    if new && a.name != auth::MAIN && args.totp {
        println!("next: the one-time codes:  vpsfort-web totp-setup --user {}", a.name);
    }
    Ok(())
}

fn totp_setup(args: &Args, user: &str, force: bool, confirm: bool) -> Result<()> {
    let a = account(args, user)?;
    if a.name != auth::MAIN && !a.password_file.exists() {
        bail!("no admin {user} yet: set their password first (`passwd --user {user}`)");
    }
    let file = if a.name == auth::MAIN { args.totp_file.clone() } else { args.admins_dir.join(format!("{user}.totp")) };
    // before anything is shown: a secret the admin scanned must never be refused afterwards
    if file.exists() && !force {
        bail!("{} exists already (--force replaces it)", file.display());
    }
    let mut secret = [0u8; 20];
    wire::getrandom(&mut secret)?;
    let name = if args.node_name.is_empty() { vpsfort_web::hostname() } else { args.node_name.clone() };
    let uri = totp::uri(&secret, "vpsfort-web", &format!("{}@{name}", a.name));
    let qr = qrcode::QrCode::new(uri.as_bytes()).context("QR code")?;
    let image = qr
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Light)
        .light_color(qrcode::render::unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build();
    println!("Scan this with an authenticator app (Aegis, 2FAS, FreeOTP, a password manager, ...):\n\n{image}\n");
    println!("or add it by its link:   {uri}");
    println!("   (without a label:     {})", totp::bare_uri(&secret));
    let grouped: Vec<String> = totp::base32(&secret).as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    println!("or type the secret:      {}  (time-based, SHA-1, 6 digits, 30 seconds)", grouped.join(" "));
    if confirm {
        // the secret is kept only once the app shows it works: a failed scan leaves nothing
        // behind that no app has, and the old secret (with --force) stays until then
        println!();
        let mut ok = false;
        for left in (0..3).rev() {
            let code = ask_hidden("The code the app shows now (to confirm the setup worked): ")
                .map_err(|e| anyhow::anyhow!("{e:#} (no terminal to ask on: --no-confirm writes the secret without the check)"))?;
            let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            if totp::verify(&secret, code.trim(), unix, 0).is_some() {
                ok = true;
                break;
            }
            if left > 0 {
                println!(
                    "that isn't this secret's current code ({left} more {}): check the app's entry, and the clock",
                    if left == 1 { "try" } else { "tries" }
                );
            }
        }
        if !ok {
            bail!("no matching code: nothing written (the app's entry, if any, is for a secret that doesn't exist; run this again)");
        }
    }
    write_secret(&file, &format!("{}\n", totp::base32(&secret)), 0o640, force)?;
    println!("secret written to {}{}", file.display(), if confirm { " (the app's code matched)" } else { "" });
    if !args.totp {
        println!("(TOTP=off in config.env: logins ask for the password only until it is on)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_socket_means_no_local_vpsfort() {
        // a console host without vpsfort: `VPSFORT_SOCKET=` in config.env
        let args = Args::try_parse_from(["vpsfort-web", "--vpsfort-socket", "", "check"]).unwrap();
        assert!(args.local().is_none());
        let args = Args::try_parse_from(["vpsfort-web", "check"]).unwrap();
        assert_eq!(args.vpsfort_socket, PathBuf::from("/run/vpsfort-console/console.sock"));
    }
}
