//! The web console: HTTPS (TLS 1.3) for one admin, the page and its JSON API, read only.
//!
//! | path | what |
//! |---|---|
//! | `/` | the page (it asks for the login itself); `/world.json` the Map tab's countries and capitals |
//! | `POST /api/login`, `POST /api/logout` | `{"password": ..., "code": ...}`; a session cookie |
//! | `/api/v1/session` | whether this browser is logged in (the only API path that needs no session) |
//! | `/api/v1/cluster` | everything below in one document (the page's refresh) |
//! | `/api/v1/{overview,attention,alerts,actions,bans,offenders,accounts,world,history}` | parts of it |
//! | `/api/v1/nodes`, `/api/v1/nodes/<id>`, `/api/v1/nodes/<id>/digest` | the nodes; one node's whole snapshot; its digest so far |
//! | `/api/v1/abuse/{24h,7d}`, `/api/v1/nodes/<id>/abuse/{24h,7d}` | the abuse report of every node merged, or of one, per provider |
//! | `/api/v1/address/<address or network>` | what every node says about it |
//! | `/api/v1/honeypots/{24h,7d}` | every node's honeypot hits of the window, from their actions logs |
//! | `/api/v1/rdap/<address>` | its network's abuse mailbox (RDAP); `"fallback": true` when the page should ask itself |
//! | `/api/v1/sessions`, `POST /api/v1/sessions/end-others` | this admin's sessions; end the others |
//! | `/metrics` | Prometheus' text format (a session, or `Authorization: Bearer` with `METRICS_TOKEN_FILE`) |

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::auth::{self, Auth, Login};
use crate::fleet::Fleet;
use crate::http::{self, ReadError, Request, Response};
use crate::netlist::{normalize, Allow};
use crate::say;

const MAX_CONNECTIONS: usize = 64;
/// A browser opens up to six connections to a site.
const MAX_PER_SOURCE: usize = 12;
/// To finish the TLS handshake, then each request (or to wait for the next one)...
const HANDSHAKE: Duration = Duration::from_secs(10);
const REQUEST: Duration = Duration::from_secs(30);
/// ...and a whole connection, however busy: a browser opens a new one. Without it a few
/// addresses could hold every slot by sending a byte every 29 seconds.
const CONNECTION: Duration = Duration::from_secs(10 * 60);
const MAX_REQUESTS: usize = 1000;

const INDEX: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const CORE_JS: &str = include_str!("../web/core.js");
const DOM_JS: &str = include_str!("../web/dom.js");
const WORK_JS: &str = include_str!("../web/work.js");
const APP_CSS: &str = include_str!("../web/app.css");
const ICON: &str = include_str!("../web/icon.svg");
/// The Map tab's countries (Natural Earth, public domain) and capitals (vpsfort's): public data.
const WORLD: &str = include_str!("../web/world.json");

/// `connect-src` names RDAP's servers: when the console can't look up an abuse mailbox, the
/// page asks rdap.org itself, which sends it on to the registry (Brazil's own for its
/// addresses, which LACNIC hands them to).
const CSP: &str = "default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self' data:; \
                   connect-src 'self' https://rdap.org https://*.arin.net https://*.ripe.net https://*.apnic.net \
                   https://*.lacnic.net https://*.afrinic.net https://rdap.registro.br; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub struct ConsoleCfg {
    pub listen: String,
    pub allow: Allow,
    pub tls: Arc<rustls::ServerConfig>,
    /// `METRICS_TOKEN_FILE`'s token, for Prometheus.
    pub metrics_token: Option<String>,
    pub refresh_secs: u64,
    /// This node's name, shown on the login page.
    pub node: String,
    /// Whether the console looks up abuse mailboxes itself (`RDAP_LOOKUPS`).
    pub rdap: bool,
    /// The proof of work's base difficulty (`LOGIN_WORK`; 0 off).
    pub login_work: u8,
    /// The certificate file (`TLS_CERT`), for the health check's expiry date.
    pub tls_cert: std::path::PathBuf,
    /// The vpsfort-web release every node should run (`EXPECTED_VERSION`; empty: no check).
    pub expected_version: String,
    /// Where the history, the digests and the marks are kept (`STATE_DIR`); None: in memory.
    pub state_dir: Option<std::path::PathBuf>,
    /// Days the attention history keeps a problem that went (`HISTORY_DAYS`).
    pub history_days: u32,
    /// Days of digests kept per node (`DIGEST_DAYS`).
    pub digest_days: u32,
}

pub struct Console {
    pub cfg: ConsoleCfg,
    pub auth: Auth,
    pub fleet: Arc<Fleet>,
    pub rdap: crate::rdap::Rdap,
    /// Proof of work before a login (`LOGIN_WORK`).
    pub work: crate::work::Work,
    /// Addresses whose failed TLS handshakes were logged lately (scanners try often).
    tls_logged: Mutex<HashMap<IpAddr, Instant>>,
    /// What needed attention lately (a week).
    pub history: crate::history::History,
    /// The nodes' daily digests (two weeks).
    pub digests: crate::digests::Digests,
    /// Share links to an address's page (signed with a key of the console's own).
    pub share: crate::share::Share,
    /// The admins' marks: abuse reports mailed, problems seen.
    pub marks: crate::marks::Marks,
    /// Passkey challenges handed out (registration and login).
    pub challenges: crate::webauthn::Challenges,
    /// How often one address may open shared pages.
    shared_pace: crate::share::Pace,
}

impl Console {
    pub fn new(cfg: ConsoleCfg, auth: Auth, fleet: Arc<Fleet>) -> Self {
        let rdap = crate::rdap::Rdap::new(cfg.rdap);
        let work = crate::work::Work::new(cfg.login_work);
        let dir = cfg.state_dir.clone();
        let (history_days, digest_days) = (cfg.history_days, cfg.digest_days);
        let share = crate::share::Share::new(dir.as_deref());
        Console {
            cfg,
            auth,
            fleet,
            rdap,
            work,
            tls_logged: Mutex::default(),
            history: crate::history::History::new(dir.as_deref()).keep_days(history_days),
            digests: crate::digests::Digests::new(dir.as_deref()).keep_days(digest_days),
            share,
            marks: crate::marks::Marks::new(dir.as_deref()),
            challenges: Default::default(),
            shared_pace: Default::default(),
        }
    }
}

/// A response is given the time of a request, and beyond it a second for each of these
/// bytes: a client that reads its answer a few bytes at a time holds a connection no longer
/// than one that sends its request that way.
const WRITE_FLOOR: usize = 16 * 1024;

/// A TCP stream whose reads share one deadline (set per request), and whose writes another
/// (set per response).
struct Timed {
    s: TcpStream,
    until: Instant,
    write_until: Instant,
}

/// When a response of `len` bytes must have gone out.
fn write_deadline(len: usize) -> Instant {
    Instant::now() + (REQUEST + Duration::from_secs((len / WRITE_FLOOR) as u64)).min(CONNECTION)
}

/// What a source's connections are counted by: its address, or for IPv6 its /64 (one
/// customer's network: counted by address, it would have 2^64 times the limit).
fn source(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(a) => {
            let s = a.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "too slow"));
        }
        self.s.set_read_timeout(Some(left))?;
        self.s.read(buf)
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let left = self.write_until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "too slow"));
        }
        self.s.set_write_timeout(Some(left.min(REQUEST)))?;
        self.s.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.s.flush()
    }
}

/// Starts the console's listener thread; returns the address it listens on.
pub fn serve(console: Arc<Console>) -> Result<SocketAddr> {
    let listener = TcpListener::bind(&console.cfg.listen).with_context(|| format!("binding CONSOLE_LISTEN {}", console.cfg.listen))?;
    let addr = listener.local_addr()?;
    let active = Arc::new(AtomicUsize::new(0));
    let per_source: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::default();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(s) = stream else { continue };
            let Ok(ip) = s.peer_addr().map(|a| normalize(a.ip())) else { continue };
            if !console.cfg.allow.admits(ip) {
                say!("console: refused connection from {ip}: not in CONSOLE_ALLOW");
                continue;
            }
            if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                continue;
            }
            let from = source(ip);
            {
                let mut open = per_source.lock().unwrap_or_else(|e| e.into_inner());
                let n = open.entry(from).or_default();
                if *n >= MAX_PER_SOURCE {
                    continue;
                }
                *n += 1;
            }
            active.fetch_add(1, Ordering::Relaxed);
            let (console, active, per_source) = (Arc::clone(&console), Arc::clone(&active), Arc::clone(&per_source));
            std::thread::spawn(move || {
                connection(&console, s, ip);
                let mut open = per_source.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(n) = open.get_mut(&from) {
                    *n -= 1;
                    if *n == 0 {
                        open.remove(&from);
                    }
                }
                active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    Ok(addr)
}

fn connection(console: &Console, s: TcpStream, ip: IpAddr) {
    let _ = s.set_write_timeout(Some(REQUEST));
    let Ok(conn) = rustls::ServerConnection::new(Arc::clone(&console.cfg.tls)) else { return };
    let handshake = Instant::now() + HANDSHAKE;
    let mut tls = rustls::StreamOwned::new(conn, Timed { s, until: handshake, write_until: handshake });
    while tls.conn.is_handshaking() {
        if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
            log_tls_failure(console, ip, &e);
            return;
        }
    }
    let mut reader = BufReader::new(tls);
    let ends = Instant::now() + CONNECTION;
    for _ in 0..MAX_REQUESTS {
        reader.get_mut().sock.until = (Instant::now() + REQUEST).min(ends);
        if Instant::now() >= ends {
            break;
        }
        let req = match http::read_request(&mut reader) {
            Ok(r) => r,
            Err(ReadError::Closed) | Err(ReadError::Io(_)) => break,
            Err(ReadError::Bad(status, why)) => {
                reader.get_mut().sock.write_until = write_deadline(0);
                let _ = http::write_response(reader.get_mut(), headers(Response::error(status, why)), false, false, false);
                break;
            }
        };
        let keep = req.keep_alive;
        let head = req.method == "HEAD";
        let gzip = http::takes_gzip(&req);
        let resp = headers(handle(console, &req, ip));
        reader.get_mut().sock.write_until = write_deadline(resp.body.len());
        if http::write_response(reader.get_mut(), resp, keep, head, gzip).is_err() || !keep {
            break;
        }
    }
    let tls = reader.get_mut();
    tls.sock.write_until = Instant::now() + Duration::from_secs(5);
    tls.conn.send_close_notify();
    let _ = tls.conn.complete_io(&mut tls.sock);
}

fn log_tls_failure(console: &Console, ip: IpAddr, e: &std::io::Error) {
    let mut logged = console.tls_logged.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    // at the size where nothing more is taken, not one above it: there neither this nor the
    // insert below would ever run again, and no failed handshake would be logged until a restart
    if logged.len() >= 1000 {
        logged.retain(|_, t| now - *t < Duration::from_secs(3600));
    }
    if logged.len() < 1000 && logged.get(&ip).is_none_or(|t| now - *t >= Duration::from_secs(3600)) {
        logged.insert(ip, now);
        say!("console: TLS handshake with {ip} failed: {e}");
    }
}

/// Headers every answer carries: no caching, no framing, no other origins.
fn headers(resp: Response) -> Response {
    resp.with("Content-Security-Policy", CSP)
        .with("Strict-Transport-Security", "max-age=31536000")
        .with("X-Content-Type-Options", "nosniff")
        .with("X-Frame-Options", "DENY")
        .with("Referrer-Policy", "no-referrer")
        .with("Cross-Origin-Opener-Policy", "same-origin")
        .with("Cross-Origin-Resource-Policy", "same-origin")
        .with("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        .with("Cache-Control", "no-store")
}

fn session_token(req: &Request) -> Option<&str> {
    req.header("cookie").and_then(auth::cookie_value)
}

/// The admin logged in with this request's cookie.
fn user(console: &Console, req: &Request) -> Option<String> {
    session_token(req).and_then(|t| console.auth.session(t))
}

fn logged_in(console: &Console, req: &Request) -> bool {
    user(console, req).is_some()
}

use crate::auth::same;

/// A request a page of this console sent: same origin when the browser says where it came from.
fn same_origin(req: &Request) -> bool {
    if req.header("sec-fetch-site").is_some_and(|s| s == "cross-site" || s == "same-site") {
        return false;
    }
    match (req.header("origin"), req.header("host")) {
        (Some(origin), Some(host)) => origin == format!("https://{host}"),
        (Some(_), None) => false,
        (None, _) => true,
    }
}

fn handle(console: &Console, req: &Request, ip: IpAddr) -> Response {
    let read = req.method == "GET" || req.method == "HEAD";
    match (req.method.as_str(), req.path.as_str()) {
        (_, "/" | "/index.html") if read => Response::new(200, "text/html; charset=utf-8", INDEX.into()),
        (_, "/app.js") if read => Response::new(200, "text/javascript; charset=utf-8", APP_JS.into()),
        (_, "/core.js") if read => Response::new(200, "text/javascript; charset=utf-8", CORE_JS.into()),
        (_, "/dom.js") if read => Response::new(200, "text/javascript; charset=utf-8", DOM_JS.into()),
        (_, "/work.js") if read => Response::new(200, "text/javascript; charset=utf-8", WORK_JS.into()),
        (_, "/app.css") if read => Response::new(200, "text/css; charset=utf-8", APP_CSS.into()),
        (_, "/icon.svg" | "/favicon.ico") if read => Response::new(200, "image/svg+xml", ICON.into()),
        (_, "/world.json") if read => Response::new(200, "application/json", WORLD.into()),
        ("POST", "/api/login") => login(console, req, ip),
        // a share link's data: the token stands for the login, for that address only
        (_, p) if read && p.starts_with("/api/v1/address/") && req.param("share").is_some() => shared_address(console, req, p, ip),
        ("POST", "/api/v1/share") => share_link(console, req),
        ("POST", "/api/v1/share/end") => {
            if !same_origin(req) {
                return Response::error(403, "not from this console's page");
            }
            let Some(who) = user(console, req) else { return Response::error(401, "log in first") };
            let Ok(v) = serde_json::from_slice::<Value>(&req.body) else { return Response::error(400, "not JSON") };
            let id = v["id"].as_str().unwrap_or("");
            if console.share.end(id) {
                say!("{who} ended share link {id}");
                Response::json(200, &json!({ "ok": true }))
            } else {
                Response::error(404, "no such share link, or it was ended already")
            }
        }
        ("POST", "/api/logout") => {
            if !same_origin(req) {
                return Response::error(403, "not from this console's page");
            }
            if let Some(t) = session_token(req) {
                console.auth.logout(t);
            }
            Response::json(200, &json!({ "ok": true }))
                .with("Set-Cookie", format!("{}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0", auth::COOKIE))
        }
        ("POST", "/api/v1/passkeys/begin" | "/api/v1/passkeys/finish" | "/api/v1/passkeys/remove") => {
            if !same_origin(req) {
                return Response::error(403, "not from this console's page");
            }
            let Some(who) = user(console, req) else { return Response::error(401, "log in first") };
            passkeys(console, req, &who)
        }
        ("POST", "/api/v1/marks") => {
            if !same_origin(req) {
                return Response::error(403, "not from this console's page");
            }
            if !logged_in(console, req) {
                return Response::error(401, "log in first");
            }
            let Ok(v) = serde_json::from_slice::<Value>(&req.body) else { return Response::error(400, "not JSON") };
            match console.marks.set(v) {
                Ok(()) => Response::json(200, &json!({ "ok": true })),
                Err(e) => Response::error(400, e),
            }
        }
        ("POST", "/api/v1/sessions/end-others") => {
            if !same_origin(req) {
                return Response::error(403, "not from this console's page");
            }
            match session_token(req).filter(|t| console.auth.session(t).is_some()) {
                Some(t) => Response::json(200, &json!({ "ended": console.auth.end_others(t) })),
                None => Response::error(401, "log in first"),
            }
        }
        (_, "/api/v1/session") if read => {
            let user = user(console, req);
            let about = session_token(req).filter(|_| user.is_some()).and_then(|t| console.auth.about(t));
            Response::json(
                200,
                &json!({
                    "logged_in": user.is_some(),
                    "user": user,
                    "session": about.as_ref().map(|a| &a.0),
                    "previous": about.as_ref().map(|a| &a.1),
                    "totp": console.auth.cfg.totp_file.is_some(),
                    // the sessions, lockouts and login records survive a restart (STATE_DIR)
                    "kept": console.auth.kept(),
                    // the account named has passkeys: a request to answer with one, instead of the code
                    "passkey": (user.is_none()).then(|| {
                        let who = auth::login_name(req.param("user").unwrap_or(""));
                        let creds = console.auth.passkeys(who);
                        let rp = crate::webauthn::rp_id(req.header("host").unwrap_or(""))?;
                        (!creds.is_empty()).then(|| console.challenges.issue(who, crate::webauthn::Purpose::Login).ok()).flatten()
                            .map(|c| crate::webauthn::request_options(&c, &rp, &creds))
                    }).flatten(),
                    "node": console.cfg.node,
                    "version": env!("CARGO_PKG_VERSION"),
                    // a challenge for the login form, at the difficulty this address and the
                    // account named (?user=) have earned
                    "work": (user.is_none() && console.work.enabled()).then(|| {
                        let who = auth::login_name(req.param("user").unwrap_or(""));
                        let (by_ip, by_account, all) = console.auth.failures_lately(ip, who);
                        console.work.issue(console.work.difficulty(by_ip, by_account, all), ip, who)
                    }),
                }),
            )
        }
        (_, "/metrics") if read => {
            let bearer = req.header("authorization").and_then(|a| a.strip_prefix("Bearer ")).map(str::trim);
            let token_ok = match (&console.cfg.metrics_token, bearer) {
                (Some(want), Some(got)) => same(want.as_bytes(), got.as_bytes()),
                _ => false,
            };
            if !token_ok && !logged_in(console, req) {
                return Response::error(401, "log in, or send the metrics token").with("WWW-Authenticate", "Bearer");
            }
            let nodes = console.fleet.view();
            let ours = crate::metrics::Console {
                logins: std::array::from_fn(|i| console.auth.logins[i].load(std::sync::atomic::Ordering::Relaxed)),
                sessions: console.auth.sessions(),
            };
            let text = crate::metrics::render(&nodes, crate::time::now(), Some(ours));
            Response::new(200, "text/plain; version=0.0.4; charset=utf-8", text.into())
        }
        (_, p) if p.starts_with("/api/v1/") && read => {
            if !same_origin(req) {
                return Response::error(403, "not from this console's page");
            }
            if !logged_in(console, req) {
                return Response::error(401, "log in first");
            }
            api(console, req, &p["/api/v1/".len()..])
        }
        (
            _,
            "/" | "/index.html" | "/app.js" | "/core.js" | "/dom.js" | "/work.js" | "/app.css" | "/icon.svg" | "/favicon.ico"
            | "/world.json" | "/metrics",
        ) => Response::error(405, "GET only").with("Allow", "GET, HEAD"),
        (_, p) if p.starts_with("/api/") => Response::error(404, "no such API path"),
        (m, p) => {
            if !logged_in(console, req) {
                say!("console: unknown path from {ip}: {m} {}", p.chars().take(200).collect::<String>());
            }
            Response::error(404, "not found")
        }
    }
}

/// The console's own health, for the Account page: what `vpsfort-web check` prints.
fn check(console: &Console, nodes: &[crate::fleet::Node]) -> Value {
    let now = crate::time::now();
    let cert = crate::tls::validity(&console.cfg.tls_cert);
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "node": console.cfg.node,
        "certificate": {
            "file": console.cfg.tls_cert.display().to_string(),
            "fingerprint": crate::tls::file_fingerprint(&console.cfg.tls_cert).ok(),
            "not_before": cert.map(|c| c.0),
            "not_after": cert.map(|c| c.1),
            "days_left": cert.map(|c| (c.1 - now) / (86_400 * crate::time::SEC)),
        },
        "web_key": console.fleet.key_id(),
        "admins": console.auth.accounts().len(),
        "totp": console.auth.cfg.totp_file.is_some(),
        "login_work": console.cfg.login_work,
        "rdap": console.cfg.rdap,
        "refresh_secs": console.cfg.refresh_secs,
        "sessions": console.auth.sessions(),
        "expected_version": console.cfg.expected_version,
        "nodes": nodes.iter().map(|n| json!({
            "id": n.id, "name": n.name, "addr": n.addr, "state": crate::aggregate::state(n), "version": n.version, "error": n.error,
        })).collect::<Vec<_>>(),
    })
}

/// `POST /api/v1/share {"net": ..., "hours": ...}`: a link to that address's page without a
/// login, for the admin logged in here.
fn share_link(console: &Console, req: &Request) -> Response {
    if !same_origin(req) {
        return Response::error(403, "not from this console's page");
    }
    let Some(who) = user(console, req) else { return Response::error(401, "log in first") };
    let Ok(v) = serde_json::from_slice::<Value>(&req.body) else { return Response::error(400, "not JSON") };
    let Ok(net) = v["net"].as_str().unwrap_or("").parse::<crate::netlist::Net>() else {
        return Response::error(400, "not an address or network");
    };
    let hours = v["hours"].as_u64().unwrap_or(24).clamp(1, crate::share::MAX_HOURS);
    let net = net.to_string();
    let (token, expires) = console.share.token(&net, hours, crate::time::now(), &who);
    say!("{who} made a share link for {net} ({hours} h)");
    Response::json(200, &json!({ "net": net, "token": token, "expires": expires, "path": format!("/#/share/{net}?t={token}") }))
}

/// The address's data for a share link's holder: a stranger (see `share`). Refusals are
/// logged with the address first, like the login's: vpsfort bans one that keeps trying.
fn shared_address(console: &Console, req: &Request, path: &str, ip: IpAddr) -> Response {
    let now = Instant::now();
    if let Err(refused) = console.shared_pace.allow(ip, now) {
        // once per window, not once per request: a loop would fill the journal
        if refused.first {
            say!("share link refused from {ip}: more than {} requests a minute", crate::share::PACE);
        }
        return Response::error(429, "too many requests for shared pages from this address: wait a minute")
            .with("Retry-After", refused.wait.as_secs().max(1).to_string());
    }
    let q = &path["/api/v1/address/".len()..];
    let Ok(net) = q.parse::<crate::netlist::Net>() else { return Response::error(400, "not an address or network") };
    if let Err(e) = console.share.check(&net.to_string(), req.param("share").unwrap_or(""), crate::time::now()) {
        say!("share link refused from {ip}: {e} ({})", net);
        return Response::error(403, e);
    }
    let nodes = console.fleet.view();
    let names: Vec<(String, String)> = nodes.iter().map(|n| (n.name.clone(), n.id.clone())).collect();
    let mut v = crate::aggregate::shared(crate::aggregate::address(&nodes, &net), &net);
    unname_nodes(&mut v, &names);
    Response::json(200, &v)
}

/// The nodes numbered, not named, in what a share link's holder gets: node names are the
/// admin's (the abuse texts name servers by address only). A `node` field becomes "node 2",
/// and a name inside a text ("from peer vpn") the same.
pub fn unname_nodes(v: &mut Value, names: &[(String, String)]) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                if k == "node" || k == "origin" {
                    if let Some(name) = x.as_str().filter(|n| !n.is_empty()) {
                        // a name the console doesn't go by (a peer not in NODES, a node known
                        // by its address so far) is a node's name all the same
                        *x = Value::String(match names.iter().find(|(n, _)| n == name) {
                            Some((_, id)) => format!("node {id}"),
                            None => "another node".to_string(),
                        });
                    }
                } else {
                    unname_nodes(x, names);
                }
            }
        }
        Value::Array(list) => list.iter_mut().for_each(|x| unname_nodes(x, names)),
        Value::String(s) => {
            for (name, id) in names {
                if !name.is_empty() && s.contains(name.as_str()) {
                    *s = replace_word(s, name, &format!("node {id}"));
                }
            }
            // "(from peer vpn)" in a ban's text, whoever the peer is
            const FROM: &str = "(from peer ";
            if let Some(at) = s.find(FROM) {
                let name_at = at + FROM.len();
                if let Some(len) = s[name_at..].find(')') {
                    if !s[name_at..name_at + len].starts_with("node ") {
                        s.replace_range(name_at..name_at + len, "another node");
                    }
                }
            }
        }
        _ => {}
    }
}

/// `from` replaced by `to` where it stands as a word (not inside another, as "vpn" in "openvpn").
fn replace_word(text: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let word = |c: char| c.is_alphanumeric() || c == '_' || c == '-';
    while let Some(i) = rest.find(from) {
        let before = rest[..i].chars().next_back().is_none_or(|c| !word(c) && c != '.');
        // "vpn." ends a sentence; "vpn.example.org" is a host name
        let mut tail = rest[i + from.len()..].chars();
        let after = match tail.next() {
            None => true,
            Some('.') => !tail.next().is_some_and(word),
            Some(c) => !word(c),
        };
        out.push_str(&rest[..i]);
        out.push_str(if before && after { to } else { from });
        rest = &rest[i + from.len()..];
    }
    out.push_str(rest);
    out
}

fn login(console: &Console, req: &Request, ip: IpAddr) -> Response {
    if !same_origin(req) {
        return Response::error(403, "not from this console's page");
    }
    if !req.header("content-type").is_some_and(|c| c.split(';').next().is_some_and(|t| t.trim() == "application/json")) {
        return Response::error(415, "JSON only");
    }
    let body: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return Response::error(400, "not JSON"),
    };
    let user = body.get("user").and_then(Value::as_str).unwrap_or("").trim();
    let password = body.get("password").and_then(Value::as_str).unwrap_or("");
    let code = body.get("code").and_then(Value::as_str).unwrap_or("");
    if console.work.enabled() {
        // the proof of work first: without it no Argon2 is run for the request
        let who = auth::login_name(user);
        let (by_ip, by_account, all) = console.auth.failures_lately(ip, who);
        let need = console.work.difficulty(by_ip, by_account, all);
        let answer = body.get("work").cloned().and_then(|w| serde_json::from_value::<crate::work::Answer>(w).ok());
        let checked = match &answer {
            Some(a) => console.work.verify(a, need, ip, who),
            None => Err("no proof of work"),
        };
        if let Err(why) = checked {
            say!("login refused from {ip}: {why}");
            return Response::json(428, &json!({ "error": why, "work": console.work.issue(need, ip, who) }));
        }
    }
    // a passkey's answer instead of the code: its challenge must be one this console issued
    // to that account lately (taken back here, whatever comes of the login)
    let second = match body.get("passkey").filter(|p| p.is_object()) {
        Some(p) => {
            let who = auth::login_name(user);
            let challenge = p["challenge"].as_str().unwrap_or("").to_string();
            if !console.challenges.take(&challenge, who, crate::webauthn::Purpose::Login) {
                say!("login refused from {ip}: the passkey's challenge is not one issued to this account lately");
                return Response::error(401, "the passkey's challenge expired: try again");
            }
            let field = |k: &str| crate::webauthn::decode(p[k].as_str().unwrap_or(""));
            let host = req.header("host").unwrap_or("");
            match (field("clientDataJSON"), field("authenticatorData"), field("signature"), crate::webauthn::rp_id(host)) {
                (Ok(client_data), Ok(auth_data), Ok(signature), Some(rp_id)) => auth::Second::Passkey(auth::Assertion {
                    id: p["id"].as_str().unwrap_or("").to_string(),
                    client_data,
                    auth_data,
                    signature,
                    challenge,
                    rp_id,
                    origin: crate::webauthn::origin(host),
                }),
                _ => {
                    return Response::error(
                        400,
                        "a passkey's answer needs clientDataJSON, authenticatorData and signature (base64url), at a host name",
                    )
                }
            }
        }
        None => auth::Second::Code(code.to_string()),
    };
    match console.auth.login_with(ip, user, password, second) {
        Ok(Login::Ok(token)) => {
            console.auth.set_agent(&token, req.header("user-agent").unwrap_or(""));
            Response::json(200, &json!({ "ok": true }))
                .with("Set-Cookie", format!("{}={token}; Path=/; Secure; HttpOnly; SameSite=Strict", auth::COOKIE))
        }
        Ok(Login::Wrong) => Response::error(401, "wrong account, password or code"),
        Ok(Login::NeedsPassword) => Response::json(
            401,
            &json!({ "error": "this passkey didn't check your fingerprint or PIN: type the password too, then use it again", "needs_password": true }),
        ),
        Ok(Login::Locked(left)) => {
            Response::error(429, &format!("too many failed logins from this address: wait {} minutes", left.as_secs().div_ceil(60)))
                .with("Retry-After", left.as_secs().to_string())
        }
        Err(e) => {
            say!("console: login impossible: {e:#}");
            Response::error(503, "the console can't check logins: see its log (journalctl -u vpsfort-web)")
        }
    }
}

/// Registration and removal of the logged-in admin's passkeys (`/api/v1/passkeys/...`).
fn passkeys(console: &Console, req: &Request, who: &str) -> Response {
    let body: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return Response::error(400, "not JSON"),
    };
    let host = req.header("host").unwrap_or("");
    let Some(rp) = crate::webauthn::rp_id(host) else {
        return Response::error(400, "passkeys need the console reached by a host name (or localhost through a tunnel), not an address");
    };
    match req.path.as_str() {
        "/api/v1/passkeys/begin" => {
            // before the browser makes (and keeps) a passkey the console then couldn't store
            if let Err(e) = console.auth.passkeys_writable(who) {
                say!("console: passkeys can't be stored: {e:#}");
                return Response::error(503, &format!("{e:#}"));
            }
            let creds = console.auth.passkeys(who);
            if creds.len() >= crate::webauthn::MAX_PER_ADMIN {
                return Response::error(400, &format!("at most {} passkeys per admin: remove one first", crate::webauthn::MAX_PER_ADMIN));
            }
            match console.challenges.issue(who, crate::webauthn::Purpose::Register) {
                Ok(c) => Response::json(200, &crate::webauthn::creation_options(&c, &rp, who, &creds)),
                Err(e) => Response::error(503, &format!("{e:#}")),
            }
        }
        "/api/v1/passkeys/finish" => {
            let challenge = body["challenge"].as_str().unwrap_or("").to_string();
            if !console.challenges.take(&challenge, who, crate::webauthn::Purpose::Register) {
                return Response::error(400, "the registration's challenge expired: begin again");
            }
            let field = |k: &str| crate::webauthn::decode(body[k].as_str().unwrap_or(""));
            let (Ok(client_data), Ok(attestation)) = (field("clientDataJSON"), field("attestationObject")) else {
                return Response::error(400, "clientDataJSON and attestationObject (base64url) are needed");
            };
            let name = body["name"].as_str().unwrap_or("");
            match crate::webauthn::finish_registration(
                &rp,
                &crate::webauthn::origin(host),
                &challenge,
                &client_data,
                &attestation,
                name,
                crate::time::now(),
            )
            .and_then(|c| {
                let view = crate::webauthn::view(&c);
                console.auth.add_passkey(who, c).map(|()| view)
            }) {
                Ok(view) => {
                    say!("passkey added for {who}: {}", view["name"]);
                    Response::json(200, &json!({ "ok": true, "passkey": view }))
                }
                Err(e) => Response::error(400, &format!("{e:#}")),
            }
        }
        _ => {
            let id = body["id"].as_str().unwrap_or("");
            match console.auth.remove_passkey(who, id) {
                Ok(true) => {
                    say!("passkey removed for {who}");
                    Response::json(200, &json!({ "ok": true }))
                }
                Ok(false) => Response::error(404, "no such passkey"),
                Err(e) => Response::error(500, &format!("{e:#}")),
            }
        }
    }
}

fn api(console: &Console, req: &Request, rest: &str) -> Response {
    let now = crate::time::now();
    // the console's own matters first: they don't ask the nodes
    if rest == "sessions" {
        let list = session_token(req).map(|t| console.auth.list(t)).unwrap_or_default();
        return Response::json(200, &json!({ "sessions": list }));
    }
    if rest == "passkeys" {
        let list: Vec<Value> =
            user(console, req).map(|u| console.auth.passkeys(&u).iter().map(crate::webauthn::view).collect()).unwrap_or_default();
        let rp = crate::webauthn::rp_id(req.header("host").unwrap_or(""));
        return Response::json(200, &json!({ "passkeys": list, "rp_id": rp, "max": crate::webauthn::MAX_PER_ADMIN }));
    }
    if rest == "share" {
        return Response::json(200, &json!({ "links": console.share.list(crate::time::now()), "kept": console.cfg.state_dir.is_some() }));
    }
    if rest == "marks" {
        return Response::json(200, &json!({ "marks": console.marks.get(), "kept": console.cfg.state_dir.is_some() }));
    }
    if let Some(ip) = rest.strip_prefix("rdap/") {
        let Ok(ip) = ip.parse::<IpAddr>() else { return Response::error(400, "not an address") };
        return match console.rdap.lookup(crate::netlist::normalize(ip)) {
            Ok(c) => Response::json(200, &json!({ "abuse": c.abuse, "network": c.network, "via": "console" })),
            // the page asks rdap.org itself then
            Err(e) => Response::json(502, &json!({ "error": e, "fallback": true })),
        };
    }
    let nodes = console.fleet.view();
    if rest == "attention/history" {
        return Response::json(200, &json!({ "problems": console.history.list() }));
    }
    if rest == "check" {
        return Response::json(200, &check(console, &nodes));
    }
    if rest == "export" {
        let all = crate::aggregate::cluster(&nodes, now, console.cfg.refresh_secs, &console.cfg.expected_version);
        let export = json!({
            "generated": now,
            "console": env!("CARGO_PKG_VERSION"),
            "node": console.cfg.node,
            "cluster": all,
            "nodes": nodes.iter().map(|n| json!({
                "id": n.id, "name": n.name, "addr": n.addr, "version": n.version, "state": crate::aggregate::state(n),
                "snapshot": n.snapshot.as_ref().map(|s| s.to_value()),
            })).collect::<Vec<_>>(),
        });
        return Response::json(200, &export)
            .with("Content-Disposition", format!("attachment; filename=\"vpsfort-cluster-{}.json\"", now / crate::time::SEC));
    }
    if let Some(q) = rest.strip_prefix("address/") {
        return match q.parse::<crate::netlist::Net>() {
            Ok(net) => Response::json(200, &crate::aggregate::address(&nodes, &net)),
            Err(_) => Response::error(400, "not an address or network"),
        };
    }
    let abuse = |want: Option<crate::wire::Want>, only: Option<&str>| match want {
        Some(want) => match console.fleet.abuse(want, only) {
            Ok(r) => Response::json(200, &serde_json::to_value(r).unwrap_or_default()),
            Err(e) => Response::error(404, &format!("{e:#}")),
        },
        None => Response::error(404, "abuse reports are of 24h or 7d"),
    };
    if let Some(window) = rest.strip_prefix("honeypots/") {
        return match crate::wire::Want::honeypots(window).map(|want| console.fleet.honeypots(want)) {
            Some(Ok(json)) => Response::new(200, "application/json", json.to_vec()),
            Some(Err(e)) => Response::error(404, &format!("{e:#}")),
            None => Response::error(404, "honeypot hits are of 24h or 7d"),
        };
    }
    if let Some(window) = rest.strip_prefix("abuse/") {
        return abuse(crate::wire::Want::abuse(window), None);
    }
    if let Some(node) = rest.strip_prefix("nodes/") {
        if let Some((id, window)) = node.split_once("/abuse/") {
            return abuse(crate::wire::Want::abuse(window), Some(id));
        }
        if let Some(id) = node.strip_suffix("/digests") {
            let Some(n) = nodes.iter().find(|n| n.id == id) else { return Response::error(404, "no such node") };
            return Response::json(200, &json!({ "node": n.name, "digests": console.digests.list(&n.id) }));
        }
        let (id, digest) = match node.strip_suffix("/digest") {
            Some(id) => (id, true),
            None => (node, false),
        };
        let Some(n) = nodes.iter().find(|n| n.id == id) else { return Response::error(404, "no such node") };
        if digest {
            return match console.fleet.digest(&n.id) {
                Ok(text) => {
                    // today's so far, kept with the archive until the day's last copy replaces it
                    console.digests.keep(&n.id, &crate::digests::day_of(now), &text);
                    Response::json(200, &json!({ "node": n.name, "text": text }))
                }
                Err(e) => Response::error(502, &format!("{e:#}")),
            };
        }
        return Response::json(200, &crate::aggregate::node(n, now));
    }
    let all = crate::aggregate::cluster(&nodes, now, console.cfg.refresh_secs, &console.cfg.expected_version);
    if let Some(att) = all["attention"].as_array() {
        console.history.observe(att, now);
    }
    let part = |keys: &[&str]| {
        let mut out = serde_json::Map::new();
        out.insert("generated".into(), all["generated"].clone());
        for k in keys {
            out.insert((*k).into(), all[*k].clone());
        }
        Response::json(200, &Value::Object(out))
    };
    match rest {
        // the page asks for what its tab shows (`?only=alerts,history`), and always for what its
        // header needs
        "cluster" if req.param("only").is_some() => {
            let mut keys = vec!["refresh_secs", "nodes", "totals", "attention"];
            keys.extend(
                req.param("only")
                    .unwrap_or("")
                    .split(',')
                    .filter(|k| ["alerts", "actions", "bans", "offenders", "accounts", "world", "history"].contains(k)),
            );
            part(&keys)
        }
        "cluster" => Response::json(200, &all),
        "overview" => part(&["nodes", "totals", "attention"]),
        "nodes" => part(&["nodes"]),
        "attention" | "alerts" | "actions" | "bans" | "offenders" | "accounts" | "world" | "history" => part(&[rest]),
        _ => Response::error(404, "no such API path"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A share link's holder sees the nodes numbered, in fields and in texts alike.
    #[test]
    fn shared_answers_name_no_node() {
        let names = vec![("vpn".to_string(), "1".to_string()), ("xmpp".to_string(), "2".to_string())];
        let mut v = json!({
            "bans": [{ "node": "vpn", "node_id": "1", "origin": "xmpp", "reason": "ban 192.0.2.1 for 1h (from peer xmpp): burst" }],
            "actions": [{ "node": "xmpp", "message": "openvpn restarted; peer vpn said so; vpn-gw too; vpn." }],
        });
        unname_nodes(&mut v, &names);
        assert_eq!(v["bans"][0]["node"], "node 1");
        assert_eq!(v["bans"][0]["origin"], "node 2");
        assert_eq!(v["bans"][0]["reason"], "ban 192.0.2.1 for 1h (from peer node 2): burst");
        assert_eq!(v["actions"][0]["message"], "openvpn restarted; peer node 1 said so; vpn-gw too; node 1.", "only whole words");
    }

    fn req(headers: &[(&str, &str)]) -> Request {
        Request {
            method: "POST".into(),
            path: "/api/login".into(),
            query: String::new(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: vec![],
            keep_alive: true,
        }
    }

    #[test]
    fn origins() {
        assert!(same_origin(&req(&[("host", "c.example.org:7948"), ("origin", "https://c.example.org:7948")])));
        assert!(same_origin(&req(&[("host", "c.example.org:7948")])), "no Origin: not a browser's cross-site request");
        assert!(!same_origin(&req(&[("host", "c.example.org:7948"), ("origin", "https://evil.example")])));
        assert!(!same_origin(&req(&[("host", "c.example.org:7948"), ("origin", "http://c.example.org:7948")])));
        assert!(!same_origin(&req(&[("host", "c"), ("sec-fetch-site", "cross-site")])));
        assert!(same_origin(&req(&[("host", "c"), ("sec-fetch-site", "same-origin")])));
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"abc", b"ab"));
    }
}
