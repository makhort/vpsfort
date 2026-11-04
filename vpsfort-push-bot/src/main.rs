use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{parser::ValueSource, CommandFactory, FromArgMatches, Parser, Subcommand};

use vpsfort_push_bot::bot::{self, Bot, Refused};
use vpsfort_push_bot::logger;
use vpsfort_push_bot::push::{Kind, Priority, Push};
use vpsfort_push_bot::redact::{self, Pseudonyms};

/// Push bot delivering vpsfort's admin alerts and daily digest to ntfy, Gotify or a webhook,
/// with XMPP account names and the servers' addresses replaced, and the weekly abuse report
/// as a file encrypted to the admin's OpenPGP key.
///
/// Every option can also come from the environment variable named after it, so config.env
/// works as the unit's EnvironmentFile.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// The service: ntfy, gotify or webhook.
    #[arg(long, env = "PUSH_KIND", default_value = "ntfy", global = true)]
    kind: String,
    /// ntfy: the topic's URL (https://ntfy.example.org/vpsfort); Gotify: the server's URL;
    /// webhook: the URL to POST to. https, or http to localhost.
    #[arg(long, env = "PUSH_URL", default_value = "", global = true)]
    url: String,
    /// The access token (ntfy: an access token, or the password with PUSH_USER; Gotify: the
    /// application token; webhook: sent as a Bearer token). Prefer the environment variable or
    /// --token-file: a command-line argument is visible to every user in `ps`.
    #[arg(long, env = "PUSH_TOKEN", hide_env_values = true, global = true)]
    token: Option<String>,
    /// File holding the token (trailing newline ignored).
    #[arg(long, env = "PUSH_TOKEN_FILE", conflicts_with = "token", global = true)]
    token_file: Option<PathBuf>,
    /// ntfy with user and password instead of an access token: the user (the password is
    /// PUSH_TOKEN).
    #[arg(long, env = "PUSH_USER", default_value = "", global = true)]
    user: String,
    /// vpsfort's messages and files for the admin (vpsfort's `[notify] push_outbox` and the
    /// abuse report's ABUSE_REPORT_PUSH_OUTBOX).
    #[arg(long, env = "OUTBOX_DIR", default_value = "/opt/vpsfort-push-bot/outbox", global = true)]
    outbox_dir: PathBuf,
    /// Days a file may wait to be sent before it is deleted unsent.
    #[arg(long, env = "OUTBOX_MAX_DAYS", default_value_t = 7, global = true)]
    outbox_max_days: u32,
    /// Hours an alert may wait (bot down, the service out of reach) before it is dropped unsent.
    #[arg(long, env = "ALERT_MAX_HOURS", default_value_t = 24, global = true)]
    alert_max_hours: u32,
    /// The XMPP domains, separated by commas or blanks: a bare user name in an alert
    /// (`ejabberd:alice`) is taken as on the first one. Every address in alerts is replaced.
    #[arg(long, env = "XMPP_DOMAINS", default_value = "", global = true)]
    xmpp_domains: String,
    /// The servers' own addresses and host names, replaced by their node ids in alerts:
    /// `xmpp=192.0.2.10,example.org; vpn=198.51.100.20` (subdomains included).
    #[arg(long, env = "SERVER_NAMES", default_value = "", global = true)]
    server_names: String,
    /// The admin's OpenPGP public key (armored or binary, v4: RSA or Curve25519). Files go out
    /// encrypted to it, as a whole; without it they aren't sent.
    #[arg(long, env = "OPENPGP_KEY", global = true)]
    openpgp_key: Option<PathBuf>,
    /// The pseudonym key; made on first start.
    #[arg(long, env = "PSEUDONYM_KEY", default_value = "/opt/vpsfort-push-bot/pseudonym.key", global = true)]
    pseudonym_key: PathBuf,
    /// Log to bot.log here (else to stderr).
    #[arg(long, env = "LOG_DIR", default_value = "/var/log/vpsfort-push-bot", global = true)]
    log_dir: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Check the settings, the token file, the OpenPGP key and the outbox, sending nothing.
    Check,
    /// Send one test message (and nothing else) to the service.
    SendTest,
    /// Print the pseudonym of each account as alerts show it (reads the key file).
    Pseudonym {
        #[arg(required = true)]
        accounts: Vec<String>,
    },
}

impl Args {
    fn token(&self) -> Result<Option<String>> {
        let token = match &self.token_file {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?
                    .trim_end_matches(['\r', '\n'])
                    .to_string(),
            ),
            None => self.token.clone(),
        };
        Ok(token.filter(|t| !t.is_empty()))
    }

    fn pseudonyms(&self, create: bool) -> Result<Pseudonyms> {
        let domains = redact::parse_domains(&self.xmpp_domains);
        let r =
            if create { Pseudonyms::load_or_create(&self.pseudonym_key, domains) } else { Pseudonyms::load(&self.pseudonym_key, domains) };
        r.map_err(|e| Refused(format!("pseudonym key: {e}")).into())
    }

    fn push(&self) -> Result<Push> {
        let kind = Kind::parse(&self.kind).map_err(|e| Refused(format!("PUSH_KIND: {e}")))?;
        if self.url.trim().is_empty() {
            bail!(Refused("PUSH_URL is not set".into()));
        }
        let token = self.token()?;
        if token.is_none() && kind == Kind::Gotify {
            bail!(Refused("Gotify needs an application token in PUSH_TOKEN".into()));
        }
        let user = (!self.user.trim().is_empty()).then(|| self.user.trim().to_string());
        Push::new(kind, self.url.trim(), token, user).map_err(|e| Refused(format!("PUSH_URL: {e}")).into())
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e:#}");
            if e.is::<Refused>() {
                ExitCode::from(Refused::EXIT_CODE)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run() -> Result<()> {
    let matches = Args::command().get_matches();
    let token_on_command_line = matches.value_source("token") == Some(ValueSource::CommandLine);
    let args = Args::from_arg_matches(&matches)?;
    match &args.cmd {
        None => logger::init(&args.log_dir),
        Some(_) => logger::init_stderr(),
    }
    if token_on_command_line {
        log::warn!("--token on the command line is visible in `ps`; use PUSH_TOKEN or --token-file");
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;

    if let Some(Cmd::Pseudonym { accounts }) = &args.cmd {
        let names = args.pseudonyms(false)?;
        for a in accounts {
            println!("{a} {}", names.tag(a));
        }
        return Ok(());
    }
    if args.alert_max_hours == 0 || args.outbox_max_days == 0 {
        bail!(Refused("ALERT_MAX_HOURS and OUTBOX_MAX_DAYS must be at least 1".into()));
    }
    let push = args.push()?;
    let servers = vpsfort_push_bot::servers::ServerNames::parse(&args.server_names).map_err(|e| Refused(format!("SERVER_NAMES: {e}")))?;
    if servers.is_empty() {
        log::warn!("SERVER_NAMES is not set: the servers' addresses and host names in alerts go to {} as they are", push.kind.name());
    }
    let recipient = match &args.openpgp_key {
        Some(path) => {
            let r = vpsfort_push_bot::seal::Recipient::load(path, chrono::Utc::now().timestamp() as u32)
                .map_err(|e| Refused(format!("OPENPGP_KEY {e}")))?;
            log::info!("files are encrypted to OpenPGP key {}", r.pretty_fingerprint());
            Some(r)
        }
        None => {
            log::warn!("OPENPGP_KEY is not set: files (the weekly abuse report) are not sent, they go out encrypted only");
            None
        }
    };
    if push.kind == Kind::Gotify {
        log::info!("Gotify takes no attachments: files (the weekly abuse report) stay on the server, the admin is told once a day");
    }
    let cfg = bot::Config {
        outbox: args.outbox_dir.clone(),
        outbox_max_age: Duration::from_secs(u64::from(args.outbox_max_days) * 86400),
        alert_max_age: Duration::from_secs(u64::from(args.alert_max_hours) * 3600),
        servers,
        recipient,
    };
    match &args.cmd {
        Some(Cmd::Check) => {
            // the one-off commands run as root: the key the service makes must stay the bot's
            let _ = args.pseudonyms(false).map_err(|e| log::warn!("{e:#} (the service makes it on its first start)"));
            match vpsfort_push_bot::outbox::writable(&cfg.outbox) {
                Ok(()) => println!("outbox {}: writable", cfg.outbox.display()),
                Err(e) => println!("outbox {}: {e} (as this user; the service runs as vpsfort-push-bot)", cfg.outbox.display()),
            }
            println!(
                "{}: {} (token: {}); files: {}",
                push.kind.name(),
                args.url.trim(),
                if args.token()?.is_some() { "set" } else { "none" },
                match (&cfg.recipient, push.kind.takes_files()) {
                    (_, false) => "not taken by this service".to_string(),
                    (Some(r), true) => format!("encrypted to {}", r.pretty_fingerprint()),
                    (None, true) => "not sent (no OPENPGP_KEY)".to_string(),
                }
            );
            println!("settings OK (nothing sent: `send-test` sends one message)");
            Ok(())
        }
        Some(Cmd::SendTest) => runtime.block_on(async {
            let text =
                "vpsfort-push-bot test\n\n[Info] a test message from vpsfort-push-bot; the real ones look like this: \"quotes\", → ⚠ ✓";
            let (subject, bodies) = bot::pieces(text);
            for b in &bodies {
                push.send_message(&subject, b, Priority::of(text)).await.map_err(|e| anyhow::anyhow!("{}: {e}", push.kind.name()))?;
            }
            println!("sent one test message to {}", push.kind.name());
            Ok(())
        }),
        Some(Cmd::Pseudonym { .. }) => unreachable!(),
        None => {
            let names = args.pseudonyms(true)?;
            log::info!("vpsfort-push-bot {} to {}; outbox {}", env!("CARGO_PKG_VERSION"), push.kind.name(), cfg.outbox.display());
            runtime.block_on(bot::run(Bot::new(push, cfg, names)))
        }
    }
}
