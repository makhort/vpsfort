//! Tripwire listeners (`[ports] honeypot`): vpsfort accepts TCP connections on ports nobody
//! legitimate uses, never sends a byte, and closes each after reading what the sender says
//! first (`[ports] honeypot_capture` bytes, within [`CAPTURE_WAIT`]; 0 closes at once). A
//! connection is only accepted after the TCP handshake, which a forged source address can't
//! complete (the server's SYN-ACK goes to the real owner of the address), so unlike a blocked
//! SYN in the firewall log, a hit here names its sender for certain; what it sent (a Telnet
//! login, an HTTP request, a protocol banner) says what it was after, and goes into the
//! evidence and the abuse report.
//!
//! On a port named in `[ports] honeypot_prompts` (off by default) the listener does speak,
//! but only fixed lines: the prompts a Telnet, FTP, SMTP, POP3 or IMAP server shows, each
//! followed by a read of the reply, so clients that wait for the server (Telnet bots, FTP and
//! mail scanners) hand over the login they try instead of showing as `sent nothing`; for SSH,
//! the server's identification line alone, which makes the client send its own (`SSH-2.0-
//! libssh_0.9.6`: the tool), the one thing it says before the key exchange a honeypot can't
//! follow. Nothing the client sends is parsed or answered: the same lines go out whatever
//! arrives.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::engine::Action;
use crate::time::{Dur, Micros};

/// The fixed lines a `[ports] honeypot_prompts` port shows, in the role of this server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Prompts {
    Telnet,
    Ftp,
    Smtp,
    Pop3,
    Imap,
    Ssh,
}

impl Prompts {
    pub const ALL: [Prompts; 6] = [Prompts::Telnet, Prompts::Ftp, Prompts::Smtp, Prompts::Pop3, Prompts::Imap, Prompts::Ssh];

    /// Its name in the configuration and the evidence.
    pub fn name(self) -> &'static str {
        match self {
            Prompts::Telnet => "telnet",
            Prompts::Ftp => "ftp",
            Prompts::Smtp => "smtp",
            Prompts::Pop3 => "pop3",
            Prompts::Imap => "imap",
            Prompts::Ssh => "ssh",
        }
    }

    /// What the evidence calls what was shown: prompts, or SSH's one banner.
    fn what(self) -> &'static str {
        match self {
            Prompts::Ssh => "banner",
            _ => "prompts",
        }
    }

    /// The greeting sent unless `[ports] honeypot_banners` names another: a real server's
    /// line as its distribution package writes it, so the port passes for the service it
    /// isn't. A greeting that names no known software gets the honeypot marked and skipped by
    /// a scanner with many addresses, while a connection dropped after a familiar one looks
    /// like a network fault, to be tried again from another address.
    pub fn default_banner(self) -> &'static str {
        match self {
            // the issue line a Debian login shows before its prompt
            Prompts::Telnet => "Debian GNU/Linux 12",
            Prompts::Ftp => "220 (vsFTPd 3.0.3)",
            Prompts::Smtp => "220 mail ESMTP Postfix (Debian/GNU)",
            Prompts::Pop3 => "+OK Dovecot (Debian) ready.",
            Prompts::Imap => {
                "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN AUTH=LOGIN] Dovecot (Debian) ready."
            }
            Prompts::Ssh => "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u5",
        }
    }

    /// What a greeting of this protocol must start with to be one a client takes (RFC 4253's
    /// identification line, the FTP and SMTP `220` reply, POP3's `+OK`, IMAP's untagged `OK`;
    /// a Telnet issue line is free text).
    fn banner_prefix(self) -> &'static str {
        match self {
            Prompts::Telnet => "",
            Prompts::Ftp | Prompts::Smtp => "220",
            Prompts::Pop3 => "+OK",
            Prompts::Imap => "* OK",
            Prompts::Ssh => "SSH-2.0-",
        }
    }

    /// Whether `banner` can be sent as this protocol's greeting: its prefix, then something
    /// (SSH: a software token, with comments after a space), printable ASCII, at most 253
    /// characters before the line end.
    pub fn valid_banner(self, banner: &str) -> bool {
        let Some(rest) = banner.strip_prefix(self.banner_prefix()) else { return false };
        let token_ok = match self {
            Prompts::Ssh => !rest.is_empty() && !rest.starts_with(' '),
            Prompts::Telnet => true,
            _ => rest.is_empty() || rest.starts_with(' '),
        };
        token_ok && banner.len() <= 253 && banner.bytes().all(|b| (0x20..=0x7e).contains(&b))
    }

    /// The bytes the greeting goes out as: with its line end, and for Telnet the way a
    /// telnetd shows it: its option negotiation first ([`TELNET_OPTIONS`]), then the issue
    /// line with blank lines around it and the prompt after it.
    fn first_line(self, banner: &str) -> Vec<u8> {
        match self {
            Prompts::Telnet => [TELNET_OPTIONS, format!("\r\n{banner}\r\n\r\nlogin: ").as_bytes()].concat(),
            _ => format!("{banner}\r\n").into_bytes(),
        }
    }

    /// The lines sent, in turn: after each, the reply is read up to its line end. `first` is
    /// the greeting ([`Prompts::first_line`]); the rest are the server's next replies, as the
    /// software the greeting names writes them.
    fn lines(self, first: &[u8]) -> Vec<&[u8]> {
        match self {
            // the identification string every client answers with its own before anything
            // else; what follows (its KEXINIT) is binary and is not read
            Prompts::Ssh => vec![first],
            // the login name, then the password
            Prompts::Telnet => vec![first, b"Password: "],
            // `USER x`, then `PASS y`
            Prompts::Ftp => vec![first, b"331 Please specify the password.\r\n"],
            // `EHLO`, then what the client is here for (`AUTH LOGIN`, `MAIL FROM:`)
            Prompts::Smtp => vec![first, b"250 mail\r\n"],
            // `USER x`, then `PASS y`
            Prompts::Pop3 => vec![first, b"+OK\r\n"],
            // `a1 LOGIN user pass` in one line
            Prompts::Imap => vec![first],
        }
    }
}

/// Which honeypot ports show prompts, and the greeting each protocol opens with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prompting {
    pub by_port: BTreeMap<u16, Prompts>,
    /// Each protocol's greeting, without its line end (validated with
    /// [`Prompts::valid_banner`]); a protocol left out greets with its default.
    pub banners: BTreeMap<Prompts, String>,
}

impl Prompting {
    /// A port's prompts, if it has any, with their greeting as it goes out.
    fn script(&self, port: u16) -> Option<(Prompts, Arc<Vec<u8>>)> {
        let p = *self.by_port.get(&port)?;
        Some((p, Arc::new(p.first_line(self.banners.get(&p).map_or(p.default_banner(), String::as_str)))))
    }
}

/// One completed handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub ip: IpAddr,
    pub port: u16,
    /// What the sender wrote first, at most the configured capture (empty: nothing within
    /// [`CAPTURE_WAIT`], or capturing is off). With prompts: its replies, one after the
    /// other, without the prompts.
    pub sent: Vec<u8>,
    /// The prompts the port showed, if any.
    pub prompts: Option<Prompts>,
}

/// A source is reported once a minute per port, however often it connects.
const REPEAT_AFTER: Duration = Duration::from_secs(60);
/// Sources remembered per port for that (real addresses only, but a botnet has many).
const MAX_SOURCES: usize = 10_000;
/// How long a connection is held for the sender's first bytes. Scanners that complete a
/// handshake write at once (Mirai's Telnet login, an HTTP request) or wait for a banner
/// that never comes.
pub const CAPTURE_WAIT: Duration = Duration::from_secs(3);
/// How long a prompted connection is held in all: a bot types its login within seconds of
/// each prompt; one that doesn't is closed and counted all the same.
pub const PROMPT_WAIT: Duration = Duration::from_secs(10);
/// The most `[ports] honeypot_capture` can ask for.
pub const MAX_CAPTURE: usize = 4096;
/// Connections read at the same time (one thread each); beyond that a connection is closed
/// without a read.
const MAX_READING: usize = 64;
/// Characters of the captured bytes shown in an evidence line.
const SHOWN: usize = 120;
/// Characters of one HTTP field (request line, host, user agent) shown.
const SHOWN_FIELD: usize = 60;

/// Reads up to `capture` bytes within [`CAPTURE_WAIT`], without ever writing.
fn read_first(mut s: TcpStream, capture: usize) -> Vec<u8> {
    let deadline = Instant::now() + CAPTURE_WAIT;
    let mut out = vec![0u8; capture];
    let mut n = 0;
    while n < capture {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || s.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match s.read(&mut out[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    out.truncate(n);
    out
}

/// What BusyBox's telnetd sends before any text, and what a Telnet bot waits for before it
/// reads for a prompt: `IAC DO ECHO`, `IAC DO NAWS`, `IAC WILL ECHO`, `IAC WILL SGA`. Nine
/// of the first ten Telnet connections to a honeypot node sat silent at a greeting without it.
const TELNET_OPTIONS: &[u8] = b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03";

/// Removes the Telnet option negotiation a client sends back (`IAC WONT ECHO`, a window
/// size `IAC SB NAWS ... IAC SE`) from `buf`, leaving the text; a sequence cut short at the
/// end, still arriving, is left for the next read. `IAC IAC` is a literal 0xff.
fn strip_telnet_options(buf: &mut Vec<u8>) -> usize {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        if buf[i] != 0xff {
            out.push(buf[i]);
            i += 1;
            continue;
        }
        match buf.get(i + 1) {
            None => break, // an IAC alone: the rest comes with the next read
            Some(0xff) => {
                out.push(0xff);
                i += 2;
            }
            // subnegotiation, up to IAC SE
            Some(0xfa) => match buf[i + 2..].windows(2).position(|w| w == [0xff, 0xf0]) {
                Some(end) => i += 2 + end + 2,
                None => break,
            },
            // WILL, WONT, DO, DONT: one option byte
            Some(0xfb..=0xfe) => {
                if i + 2 >= buf.len() {
                    break;
                }
                i += 3;
            }
            // the other commands (NOP, GA, ...): the two bytes
            Some(_) => i += 2,
        }
    }
    let tail = buf.split_off(i);
    *buf = out;
    buf.extend(&tail);
    tail.len()
}

/// Appends the sender's next line (up to and including its `\n`, or whatever arrives before
/// the deadline or the capture is full) to `out`, first from `pending`: what the last read
/// brought beyond its line (a bot sends its login and password in one packet, before the
/// password prompt). With `telnet`, the client's option negotiation is dropped on the way.
/// False when the connection is over or silent: no further prompt then.
fn read_line(s: &mut TcpStream, deadline: Instant, capture: usize, out: &mut Vec<u8>, pending: &mut Vec<u8>, telnet: bool) -> bool {
    let mut buf = [0u8; 256];
    // bytes at pending's end that are a Telnet sequence cut short: they wait for the next read
    let mut hold = if telnet { strip_telnet_options(pending) } else { 0 };
    loop {
        if pending.len() <= hold {
            if out.len() >= capture {
                // the capture is full: what the sender wrote is kept, but no further prompt is worth it
                return false;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || s.set_read_timeout(Some(left)).is_err() {
                return false;
            }
            match s.read(&mut buf) {
                Ok(0) | Err(_) => return false,
                Ok(k) => pending.extend_from_slice(&buf[..k]),
            }
            if telnet {
                hold = strip_telnet_options(pending);
            }
            continue; // negotiation alone so far: the text is still to come
        }
        let room = capture - out.len();
        if room == 0 {
            return false;
        }
        // a line ends at its `\n` when it is text; a binary reply (a TLS client hello after an
        // FTP greeting, with a 0x0a byte somewhere inside) is read whole, to the capture or
        // the deadline
        let text = &pending[..pending.len() - hold];
        let line_end = text
            .iter()
            .position(|&b| b == b'\n')
            .filter(|&i| text[..i].iter().all(|&b| matches!(b, b'\r' | b'\t' | 0x20..=0x7e | 0x80..)))
            .map(|i| i + 1);
        let take = line_end.unwrap_or(text.len()).min(room);
        out.extend(pending.drain(..take));
        if line_end == Some(take) {
            return true;
        }
    }
}

/// Shows the prompts, one by one, reading the reply to each; returns the replies. The same
/// lines go out whatever the client sends, within [`PROMPT_WAIT`] and `capture` bytes in all.
fn converse(mut s: TcpStream, capture: usize, prompts: Prompts, first: &[u8]) -> Vec<u8> {
    let deadline = Instant::now() + PROMPT_WAIT;
    let (mut out, mut pending) = (Vec::new(), Vec::new());
    for line in prompts.lines(first) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || s.set_write_timeout(Some(left)).is_err() || s.write_all(line).is_err() || s.flush().is_err() {
            break;
        }
        if !read_line(&mut s, deadline, capture, &mut out, &mut pending, prompts == Prompts::Telnet) {
            break;
        }
    }
    // what came after the last line asked for (SSH's binary key exchange) isn't kept
    out
}

/// Bytes as plain ASCII: printable characters as they are, `\r`, `\n`, `\t`, `\"` and `\\`
/// escaped, anything else as `\xNN`, cut to `max` characters.
fn ascii(bytes: &[u8], max: usize) -> String {
    let mut text = String::new();
    for &b in bytes {
        let piece = match b {
            b'\r' => "\\r".to_string(),
            b'\n' => "\\n".to_string(),
            b'\t' => "\\t".to_string(),
            b'"' => "\\\"".to_string(),
            b'\\' => "\\\\".to_string(),
            0x20..=0x7e => (b as char).to_string(),
            _ => format!("\\x{b:02x}"),
        };
        if text.len() + piece.len() > max {
            text.push('…');
            break;
        }
        text.push_str(&piece);
    }
    text
}

/// What an HTTP request is shown by.
struct HttpRequest<'a> {
    request: &'a [u8],
    host: Option<&'a [u8]>,
    agent: Option<&'a [u8]>,
}

/// The request line, `Host` and `User-Agent` of what looks like an HTTP request: a method in
/// capitals, a target and `HTTP/` on the first line.
fn http_request(sent: &[u8]) -> Option<HttpRequest<'_>> {
    let mut lines = sent.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let request = lines.next()?;
    let mut words = request.split(|&b| b == b' ');
    let (method, target, version) = (words.next()?, words.next()?, words.next()?);
    if method.is_empty()
        || method.len() > 12
        || !method.iter().all(u8::is_ascii_uppercase)
        || target.is_empty()
        || !version.starts_with(b"HTTP/")
    {
        return None;
    }
    let (mut host, mut agent) = (None, None);
    for l in lines.take_while(|l| !l.is_empty()) {
        let Some(colon) = l.iter().position(|&b| b == b':') else { continue };
        let value = l[colon + 1..].strip_prefix(b" ").unwrap_or(&l[colon + 1..]);
        if l[..colon].eq_ignore_ascii_case(b"host") {
            host.get_or_insert(value);
        } else if l[..colon].eq_ignore_ascii_case(b"user-agent") {
            agent.get_or_insert(value);
        }
    }
    Some(HttpRequest { request, host, agent })
}

/// The captured bytes as one line of plain ASCII (see [`ascii`]), cut to [`SHOWN`]
/// characters; an HTTP request by its request line, host and user agent; the replies to
/// prompts named as such. The abuse report quotes it after "connected to our decoy service
/// on port ... and".
pub fn describe(sent: &[u8], prompts: Option<Prompts>) -> String {
    match (prompts, sent.is_empty()) {
        (Some(p), true) => return format!("sent nothing to the {} {}", p.name(), p.what()),
        (Some(p), false) => {
            // a reply that is another protocol's opening (TLS tried after the greeting) is
            // named too; not what the prompt asks for (a client's banner after SSH's, Telnet's
            // own negotiation), which would say nothing
            let name = protocol(sent)
                .filter(|&n| !matches!((p, n), (Prompts::Ssh, "an SSH client banner") | (Prompts::Telnet, "Telnet option negotiation")));
            let what = name.map_or_else(|| format!("{} bytes", sent.len()), |name| format!("{name} ({} bytes)", sent.len()));
            return format!("answered the {} {} with {what}: \"{}\"", p.name(), p.what(), ascii(sent, SHOWN));
        }
        (None, true) => return "sent nothing".to_string(),
        (None, false) => {}
    }
    if let Some(HttpRequest { request, host, agent }) = http_request(sent) {
        let mut text = format!("sent HTTP request \"{}\"", ascii(request, SHOWN_FIELD));
        if let Some(h) = host {
            text += &format!(" for host \"{}\"", ascii(h, SHOWN_FIELD));
        }
        match agent {
            Some(a) => text += &format!(" with user agent \"{}\"", ascii(a, SHOWN_FIELD)),
            None => text += " without a user agent",
        }
        return format!("{text} ({} bytes)", sent.len());
    }
    match protocol(sent) {
        Some(what) => format!("sent {what} ({} bytes): \"{}\"", sent.len(), ascii(sent, SHOWN)),
        None => format!("sent {} bytes: \"{}\"", sent.len(), ascii(sent, SHOWN)),
    }
}

/// What the first bytes of a connection are, for the protocols scanners open with (the
/// client speaks first in each), so the evidence says "an SMB2 negotiate" before the hex. By
/// the fixed bytes of each protocol's opening message: a length that matches, a magic string,
/// a version. Nothing is answered; a capture cut short still names its protocol.
fn protocol(s: &[u8]) -> Option<&'static str> {
    let n = s.len();
    let at = |i: usize| s.get(i).copied();
    let be16 = |i: usize| Some(u16::from_be_bytes([at(i)?, at(i + 1)?]) as usize);
    let be32 = |i: usize| Some(u32::from_be_bytes([at(i)?, at(i + 1)?, at(i + 2)?, at(i + 3)?]));
    let le32 = |i: usize| Some(u32::from_le_bytes([at(i)?, at(i + 1)?, at(i + 2)?, at(i + 3)?]));
    let has = |needle: &[u8]| s.windows(needle.len()).any(|w| w == needle);
    // a length field that is the whole message, or more than was captured
    let whole = |len: Option<usize>| len.is_some_and(|l| l >= n && l <= MAX_CAPTURE * 4);
    let first_line = s.split(|&b| b == b'\n').next().unwrap_or(s);
    Some(if s.starts_with(b"SSH-") {
        "an SSH client banner"
    } else if s.starts_with(b"RFB 0") {
        "a VNC client version"
    } else if first_line.strip_suffix(b"\r").unwrap_or(first_line).ends_with(b" SIP/2.0") {
        "a SIP request"
    } else if s.starts_with(b"AMQP") {
        "an AMQP protocol header"
    } else if s.starts_with(b"CNXN") {
        "an ADB connect"
    } else if s.starts_with(b"JRMI") {
        "a Java RMI handshake"
    } else if (s.starts_with(b"*") && has(b"\r\n$"))
        || [&b"INFO"[..], b"PING", b"CONFIG ", b"AUTH ", b"EVAL "].iter().any(|c| s.starts_with(c))
    {
        "a Redis command"
    } else if s.starts_with(b"stats") || s.starts_with(b"version\r\n") {
        "a memcached command"
    } else if at(0) == Some(0xff) {
        "Telnet option negotiation"
    } else if at(0) == Some(0x16) && at(1) == Some(0x03) && at(2).is_some_and(|v| v <= 0x03) && at(5) == Some(0x01) {
        "a TLS client hello"
    } else if at(0) == Some(0x12) && at(1) == Some(0x01) && whole(be16(2)) {
        "an MS SQL (TDS) pre-login"
    } else if at(0) == Some(0) && n >= 8 && &s[4..8] == b"\xfeSMB" {
        if at(16) == Some(0) && at(17) == Some(0) {
            "an SMB2 negotiate"
        } else {
            "an SMB2 request"
        }
    } else if at(0) == Some(0) && n >= 9 && &s[4..8] == b"\xffSMB" {
        if at(8) == Some(0x72) {
            "an SMB1 negotiate"
        } else {
            "an SMB1 request"
        }
    } else if at(0) == Some(3) && at(1) == Some(0) && whole(be16(2)) && at(5) == Some(0xe0) {
        if has(b"mstshash") {
            "an RDP connection request"
        } else {
            "a TPKT connection request (RDP or Siemens S7)"
        }
    } else if be32(0) == Some(8) && be32(4) == Some(80_877_103) {
        "a PostgreSQL SSL request"
    } else if be32(0).is_some_and(|l| (8..=10_000).contains(&l)) && n >= 8 && s[4..8] == [0, 3, 0, 0] {
        "a PostgreSQL startup message"
    } else if le32(0).is_some_and(|l| l >= 16) && le32(12).is_some_and(|op| [2004, 2010, 2011, 2013].contains(&op)) {
        "a MongoDB query"
    } else if at(0) == Some(5) && n >= 3 && at(1) == Some((n - 2) as u8) {
        "a SOCKS5 greeting"
    } else if at(0) == Some(4) && (at(1) == Some(1) || at(1) == Some(2)) && n >= 9 {
        "a SOCKS4 connect"
    } else if at(0) == Some(0x10) && (has(b"\x00\x04MQTT") || has(b"\x00\x06MQIsdp")) {
        "an MQTT connect"
    } else if n >= 8 && s[2..4] == [0, 0] && be16(4) == Some(n - 6) && (1..=0x7f).contains(&s[7]) {
        "a Modbus request"
    } else if at(0) == Some(0x30) && n >= 7 && s[2..7].windows(3).any(|w| w[0] == 0x02 && w[1] == 0x01) && s[..12.min(n)].contains(&0x60) {
        "an LDAP bind request"
    } else if n >= 16 && at(0).is_some_and(|b| b & 0x80 != 0) && s[8..12] == [0, 0, 0, 0] && s[12..16] == [0, 0, 0, 2] {
        "an RPC call (rpcbind or NFS)"
    } else if at(4) == Some(1) && whole(be16(0)) && has(b"CONNECT_DATA") {
        "an Oracle TNS connect"
    } else if be16(2) == Some(1) && be32(4) == Some(0x1a2b_3c4d) {
        "a PPTP control connection request"
    } else {
        return None;
    })
}

/// Binds `port` on every address: IPv6 with IPv4 mapped where the system allows, else IPv4,
/// and IPv4 as well where IPv6 sockets don't take it (`net.ipv6.bindv6only = 1`).
fn bind(port: u16) -> std::io::Result<Vec<TcpListener>> {
    let mut out = Vec::new();
    let v6 = TcpListener::bind(("::", port));
    if let Ok(l) = v6 {
        out.push(l);
    }
    match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => out.push(l),
        // taken by the dual-stack IPv6 socket above: fine
        Err(e) if out.is_empty() => return Err(e),
        Err(_) => {}
    }
    Ok(out)
}

fn serve(
    listener: TcpListener,
    port: u16,
    capture: usize,
    script: Option<(Prompts, Arc<Vec<u8>>)>,
    on_hit: Arc<dyn Fn(Hit) -> bool + Send + Sync>,
    reading: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let mut seen: HashMap<IpAddr, Instant> = HashMap::new();
        for stream in listener.incoming() {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let Ok(s) = stream else {
                // e.g. out of file descriptors: don't spin
                thread::sleep(Duration::from_millis(100));
                continue;
            };
            let peer = s.peer_addr().ok().map(|a| crate::net::normalize(a.ip()));
            let Some(ip) = peer else { continue };
            let now = Instant::now();
            if seen.get(&ip).is_some_and(|t| now.duration_since(*t) < REPEAT_AFTER) {
                continue; // (closed without a read: a repeat within the minute)
            }
            if seen.len() >= MAX_SOURCES {
                seen.retain(|_, t| now.duration_since(*t) < REPEAT_AFTER);
            }
            if seen.len() < MAX_SOURCES {
                seen.insert(ip, now);
            }
            // with capturing off (or too many connections being read already) the connection
            // is closed before anything else: nothing is sent, not even a prompt
            if capture == 0 || reading.load(Ordering::Relaxed) >= MAX_READING {
                drop(s);
                if !on_hit(Hit { ip, port, sent: vec![], prompts: None }) {
                    return;
                }
                continue;
            }
            reading.fetch_add(1, Ordering::Relaxed);
            let (on_hit, reading, stop, script) = (Arc::clone(&on_hit), Arc::clone(&reading), Arc::clone(&stop), script.clone());
            thread::spawn(move || {
                let prompts = script.as_ref().map(|(p, _)| *p);
                let sent = match &script {
                    Some((p, first)) => converse(s, capture, *p, first),
                    None => read_first(s, capture),
                };
                reading.fetch_sub(1, Ordering::Relaxed);
                if !on_hit(Hit { ip, port, sent, prompts }) {
                    stop.store(true, Ordering::Relaxed);
                }
            });
        }
    });
}

/// Starts a listener for each port, reading up to `capture` bytes of each connection (0:
/// none), showing the prompts of the ports that have them; `on_hit` is called from their
/// threads (false stops them). Returns the ports that could not be opened, with why.
pub fn start(
    ports: &[u16],
    capture: usize,
    prompting: &Prompting,
    on_hit: impl Fn(Hit) -> bool + Send + Sync + 'static,
    stop: Arc<AtomicBool>,
) -> Vec<String> {
    let on_hit: Arc<dyn Fn(Hit) -> bool + Send + Sync> = Arc::new(on_hit);
    let reading = Arc::new(AtomicUsize::new(0));
    let capture = capture.min(MAX_CAPTURE);
    let mut errors = Vec::new();
    for &port in ports {
        match bind(port) {
            Ok(listeners) => {
                for l in listeners {
                    serve(l, port, capture, prompting.script(port), Arc::clone(&on_hit), Arc::clone(&reading), Arc::clone(&stop));
                }
            }
            Err(e) => errors.push(format!("honeypot port {port}/tcp: cannot listen: {e}")),
        }
    }
    errors
}

/// Bans one answer of [`from_log`] holds, the newest: a week of a busy honeypot node's.
pub const MAX_LOG_HITS: usize = 10_000;

/// This node's honeypot hits of a window, from its actions log: what the console's Honeypots
/// tab shows (`honeypots 24h` and `honeypots 7d` on the console socket). The list of latest
/// decisions in the snapshot is too short for it: it keeps 100 across a restart.
#[derive(Debug, Serialize)]
pub struct LogHits {
    pub from: Micros,
    pub to: Micros,
    /// Bans with a hit in the window, also those beyond `hits`.
    pub total: usize,
    /// Those bans, the newest first.
    pub hits: Vec<Action>,
}

/// Whether an evidence line is a hit on a honeypot port or the decoy site: by what the line
/// starts with after its time (and a network ban's member address), since what follows is
/// what a stranger chose.
fn is_hit_line(line: &str) -> bool {
    let mut text = line;
    let mut parts = line.splitn(3, ' ');
    if let (Some(d), Some(t), Some(rest)) = (parts.next(), parts.next(), parts.next()) {
        if d.len() == 5 && d.as_bytes()[2] == b'-' && t.len() == 8 && t.as_bytes()[2] == b':' {
            text = rest;
        }
    }
    if let Some((member, rest)) = text.split_once(' ') {
        if member.parse::<IpAddr>().is_ok() {
            text = rest;
        }
    }
    ["connected to honeypot ", "decoy_request: ", "decoy_request_json: "].iter().any(|p| text.starts_with(p))
}

/// A ban taken over from a peer: it repeats the evidence of the node that caught the source.
fn is_peers_ban(a: &Action) -> bool {
    a.category.as_deref() == Some("from peers") || a.message.contains(" (from peer ")
}

fn newest(hits: &mut Vec<Action>, keep: usize) {
    hits.sort_by_key(|a| std::cmp::Reverse(a.ts));
    hits.truncate(keep);
}

fn collect_hits(path: &Path, from: Micros, keep: usize) -> anyhow::Result<(usize, Vec<Action>)> {
    let (mut total, mut hits) = (0, Vec::new());
    crate::abuse::for_each_ban(path, from, |mut a| {
        if is_peers_ban(&a) || !a.evidence.iter().any(|l| is_hit_line(l)) {
            return;
        }
        total += 1;
        // what the tab has no use for
        a.notice = None;
        a.user_note = None;
        a.signals.clear();
        hits.push(a);
        if hits.len() >= keep.saturating_mul(2) {
            newest(&mut hits, keep);
        }
    })?;
    newest(&mut hits, keep);
    Ok((total, hits))
}

/// The honeypot hits this node decided on in the `since` window up to `now`, from the actions
/// log at `path` and its rotated copies. Peers' copies of a ban are left out: the node that
/// caught the source has it.
pub fn from_log(path: &Path, since: Dur, now: Micros) -> anyhow::Result<LogHits> {
    let from = crate::abuse::window_start(now, since);
    let (total, hits) = collect_hits(path, from, MAX_LOG_HITS)?;
    Ok(LogHits { from, to: now, total, hits })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    fn silent() -> Prompting {
        Prompting::default()
    }

    fn prompting(port: u16, p: Prompts) -> Prompting {
        Prompting { by_port: [(port, p)].into_iter().collect(), ..Default::default() }
    }

    /// Needs to bind 127.0.0.1 (run outside a sandbox that forbids it).
    #[test]
    fn a_connection_is_a_hit_once_a_minute() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        let errors = start(&[port], 0, &silent(), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false)));
        assert!(errors.is_empty(), "{errors:?}");
        for _ in 0..3 {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            // closed by the other side without a word
            let mut buf = [0u8; 8];
            assert_eq!(s.read(&mut buf).unwrap_or(0), 0);
        }
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(hit, Hit { ip: "127.0.0.1".parse().unwrap(), port, sent: vec![], prompts: None });
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "repeats within a minute are one hit");
        let taken = start(&[port], 0, &silent(), |_| true, Arc::new(AtomicBool::new(false)));
        assert!(taken[0].contains("cannot listen"), "{taken:?}");
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn what_the_sender_wrote_first_is_captured_and_nothing_is_sent() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        let errors = start(&[port], 16, &silent(), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false)));
        assert!(errors.is_empty(), "{errors:?}");
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut buf = [0u8; 8];
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "closed without a word once the capture is full");
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(hit.sent, b"GET / HTTP/1.1\r\n", "at most the capture");
        assert_eq!(describe(&hit.sent, None), "sent HTTP request \"GET / HTTP/1.1\" without a user agent (16 bytes)");
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn prompts_are_shown_in_turn_and_the_replies_kept() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        let errors = start(&[port], 64, &prompting(port, Prompts::Telnet), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false)));
        assert!(errors.is_empty(), "{errors:?}");
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(
            &buf[..n],
            b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\nDebian GNU/Linux 12\r\n\r\nlogin: ",
            "telnetd's negotiation, then the issue line"
        );
        // the bot answers the negotiation (WONT ECHO, its window size), then types; the
        // negotiation is left out of what is kept
        s.write_all(b"\xff\xfc\x01\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0").unwrap();
        thread::sleep(Duration::from_millis(50));
        s.write_all(b"root\r\n").unwrap();
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"Password: ");
        // the password comes in two pieces, a negotiation command cut between them too
        s.write_all(b"xc35\xff").unwrap();
        thread::sleep(Duration::from_millis(50));
        s.write_all(b"\xfe\x0111\r\n").unwrap();
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "closed after the last reply");
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(hit.sent, b"root\r\nxc3511\r\n", "the replies, without the prompts or the negotiation");
        assert_eq!(hit.prompts, Some(Prompts::Telnet));
        assert_eq!(describe(&hit.sent, hit.prompts), "answered the telnet prompts with 14 bytes: \"root\\r\\nxc3511\\r\\n\"");
    }

    #[test]
    fn telnet_option_negotiation_is_stripped_and_a_cut_sequence_waits() {
        let strip = |b: &[u8]| {
            let mut v = b.to_vec();
            strip_telnet_options(&mut v);
            v
        };
        assert_eq!(strip(b"\xff\xfc\x01root\r\n"), b"root\r\n");
        assert_eq!(strip(b"\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0admin\xff\xfd\x03\r\n"), b"admin\r\n");
        assert_eq!(strip(b"a\xff\xffb"), b"a\xffb", "IAC IAC is a literal 0xff");
        assert_eq!(strip(b"\xff\xf1x"), b"x", "a bare command is two bytes");
        // cut short: the tail waits for the next read
        assert_eq!(strip(b"root\xff"), b"root\xff");
        assert_eq!(strip(b"root\xff\xfd"), b"root\xff\xfd");
        assert_eq!(strip(b"\xff\xfa\x1f\x00"), b"\xff\xfa\x1f\x00");
        assert_eq!(strip(b""), b"");
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn a_bot_that_answers_both_prompts_at_once_loses_nothing() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(
            start(&[port], 64, &prompting(port, Prompts::Telnet), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false))).is_empty()
        );
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap();
        assert!(buf[..n].ends_with(b"login: "));
        // login and password in one packet, before the password prompt
        s.write_all(b"admin\r\nadmin\r\n").unwrap();
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"Password: ");
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "closed after the last reply");
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(hit.sent, b"admin\r\nadmin\r\n", "the second line isn't lost");
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn a_silent_client_gets_the_first_prompt_only_and_the_capture_bounds_the_replies() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        let errors = start(&[port], 8, &prompting(port, Prompts::Ftp), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false)));
        assert!(errors.is_empty(), "{errors:?}");
        // a client that hangs up at the banner
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"220 (vsFTPd 3.0.3)\r\n");
        drop(s);
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((hit.sent.as_slice(), hit.prompts), (&b""[..], Some(Prompts::Ftp)));
        assert_eq!(describe(&hit.sent, hit.prompts), "sent nothing to the ftp prompts");
        // another source (the first is a repeat within the minute): a long first reply
        // fills the capture, and the second prompt isn't shown
        let (tx2, rx2) = std::sync::mpsc::channel();
        let port2 = free_port();
        assert!(
            start(&[port2], 8, &prompting(port2, Prompts::Ftp), move |h| tx2.send(h).is_ok(), Arc::new(AtomicBool::new(false))).is_empty()
        );
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port2)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"220 (vsFTPd 3.0.3)\r\n");
        s.write_all(b"USER anonymous\r\n").unwrap();
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "closed: the capture is full");
        let hit = rx2.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(hit.sent, b"USER ano");
    }

    #[test]
    fn captured_bytes_are_shown_as_plain_ascii() {
        assert_eq!(describe(b"", None), "sent nothing");
        assert_eq!(describe(b"root\r\n\x1b[2J\"q\\\0", None), "sent 14 bytes: \"root\\r\\n\\x1b[2J\\\"q\\\\\\x00\"");
        let long = describe(&[b'A'; 500], None);
        assert!(long.starts_with("sent 500 bytes: \"AAAA") && long.ends_with("A…\""), "{long}");
        assert!(long.chars().count() < 150, "{long}");
        // nothing a terminal or a report could act on survives
        assert!(describe(b"\x1b]52;c;ZXZpbA==\x07\xff\n", None).chars().all(|c| !c.is_control()));
        assert!(describe(b"\x1b]52;c;ZXZpbA==\x07\xff\n", Some(Prompts::Imap)).chars().all(|c| !c.is_control()));
    }

    #[test]
    fn an_http_request_is_shown_by_its_request_line_host_and_user_agent() {
        let req =
            b"GET /.env HTTP/1.1\r\nHost: 203.0.113.9\r\nUser-Agent: Mozilla/5.0 (Nuclei - Open-source project)\r\nAccept: */*\r\n\r\n";
        assert_eq!(
            describe(req, None),
            format!(
                "sent HTTP request \"GET /.env HTTP/1.1\" for host \"203.0.113.9\" with user agent \"Mozilla/5.0 (Nuclei - Open-source project)\" ({} bytes)",
                req.len()
            )
        );
        // header names in any case, no Host, no User-Agent
        let boa = b"POST /boaform/admin/formLogin HTTP/1.0\r\nuser-agent: curl/8.0\r\n\r\n";
        assert_eq!(
            describe(boa, None),
            format!("sent HTTP request \"POST /boaform/admin/formLogin HTTP/1.0\" with user agent \"curl/8.0\" ({} bytes)", boa.len())
        );
        assert_eq!(describe(b"GET / HTTP/1.1\r\n\r\n", None), "sent HTTP request \"GET / HTTP/1.1\" without a user agent (18 bytes)");
        // the capture may end inside the headers: what is there is shown
        let cut = b"GET / HTTP/1.1\r\nHost: a.example\r\nUser-Ag";
        assert_eq!(
            describe(cut, None),
            format!("sent HTTP request \"GET / HTTP/1.1\" for host \"a.example\" without a user agent ({} bytes)", cut.len())
        );
        // long fields are cut, and escaped like everything else
        let long =
            describe(format!("GET /{} HTTP/1.1\r\nHost: x\r\nUser-Agent: \x1b]52;evil\x07\"\r\n\r\n", "a".repeat(200)).as_bytes(), None);
        assert!(
            long.starts_with("sent HTTP request \"GET /aaaa")
                && long.contains("a…\" for host \"x\" with user agent \"\\x1b]52;evil\\x07\\\"\""),
            "{long}"
        );
        assert!(long.chars().all(|c| !c.is_control()));
        // not HTTP: a lower-case method, a Telnet login, a TLS hello, binary
        assert_eq!(describe(b"get / HTTP/1.1\r\n", None), "sent 16 bytes: \"get / HTTP/1.1\\r\\n\"");
        assert_eq!(describe(b"root\r\n1234\r\n", None), "sent 12 bytes: \"root\\r\\n1234\\r\\n\"");
        assert!(describe(b"\x16\x03\x01\x00\xa5\x01\x00", None).starts_with("sent a TLS client hello (7 bytes): \"\\x16\\x03\\x01"));
        assert_eq!(describe(b"GET HTTP/1.1\r\n", None), "sent 14 bytes: \"GET HTTP/1.1\\r\\n\"", "no target");
    }

    #[test]
    fn the_protocols_scanners_open_with_are_named() {
        // the description up to its " (N bytes)"
        let name = |b: &[u8]| {
            let d = describe(b, None);
            let cut = d.match_indices(" (").find(|(i, _)| d[i + 2..].starts_with(|c: char| c.is_ascii_digit())).map_or(d.len(), |(i, _)| i);
            d[..cut].to_string()
        };
        // the three seen on the honeypot node on its first night
        let tds = b"\x12\x01\x00\x29\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x04\xff\x0c\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(tds.len(), 41);
        assert_eq!(name(tds), "sent an MS SQL (TDS) pre-login");
        assert!(
            describe(tds, None).starts_with("sent an MS SQL (TDS) pre-login (41 bytes): \"\\x12\\x01\\x00)"),
            "{}",
            describe(tds, None)
        );
        let mut smb2 =
            b"\x00\x00\x00\xae\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        smb2.resize(178, 0);
        assert_eq!(name(&smb2), "sent an SMB2 negotiate");
        let mut smb2_other = smb2.clone();
        smb2_other[16] = 0x05;
        assert_eq!(name(&smb2_other), "sent an SMB2 request");
        assert_eq!(name(b"SSH-2.0-Go\r\n"), "sent an SSH client banner");
        // the rest, by their opening bytes
        assert_eq!(name(b"\x00\x00\x00\x2f\xffSMBr\x00\x00\x00\x00\x18\x01\x28\x00"), "sent an SMB1 negotiate");
        assert_eq!(name(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"), "sent a TLS client hello");
        assert_eq!(
            name(b"\x03\x00\x00\x2b\x26\xe0\x00\x00\x00\x00\x00Cookie: mstshash=admin\r\n\x01\x00\x08\x00\x03\x00\x00\x00"),
            "sent an RDP connection request"
        );
        assert_eq!(
            name(b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a"),
            "sent a TPKT connection request (RDP or Siemens S7)"
        );
        assert_eq!(name(b"\x00\x00\x00\x08\x04\xd2\x16\x2f"), "sent a PostgreSQL SSL request");
        assert_eq!(
            name(b"\x00\x00\x00\x21\x00\x03\x00\x00user\x00postgres\x00database\x00postgres\x00\x00"),
            "sent a PostgreSQL startup message"
        );
        assert_eq!(name(b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"), "sent a MongoDB query");
        assert_eq!(name(b"*1\r\n$4\r\nINFO\r\n"), "sent a Redis command");
        assert_eq!(name(b"INFO\r\n"), "sent a Redis command");
        assert_eq!(name(b"stats\r\n"), "sent a memcached command");
        assert_eq!(name(b"\x05\x02\x00\x02"), "sent a SOCKS5 greeting");
        assert_eq!(name(b"\x04\x01\x00\x50\xcb\x00\x71\x01\x00"), "sent a SOCKS4 connect");
        assert_eq!(name(b"\x10\x1a\x00\x04MQTT\x04\x02\x00\x3c\x00\x0emqtt-explorer"), "sent an MQTT connect");
        assert_eq!(name(b"AMQP\x00\x00\x09\x01"), "sent an AMQP protocol header");
        assert_eq!(name(b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00"), "sent an ADB connect");
        assert_eq!(name(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"), "sent a Modbus request");
        assert_eq!(name(b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"), "sent an LDAP bind request");
        assert_eq!(
            name(b"\x80\x00\x00\x28\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x03"),
            "sent an RPC call (rpcbind or NFS)"
        );
        assert_eq!(name(b"\x00\x3e\x00\x00\x01\x00\x00\x00\x01\x3a(CONNECT_DATA=(SERVICE_NAME=XE))"), "sent an Oracle TNS connect");
        assert_eq!(name(b"\x00\x9c\x00\x01\x1a\x2b\x3c\x4d\x00\x01\x00\x00"), "sent a PPTP control connection request");
        assert_eq!(name(b"RFB 003.008\n"), "sent a VNC client version");
        assert_eq!(name(b"OPTIONS sip:100@203.0.113.9 SIP/2.0\r\nVia: SIP/2.0/TCP x\r\n"), "sent a SIP request");
        assert_eq!(name(b"JRMI\x00\x02\x4b"), "sent a Java RMI handshake");
        assert_eq!(name(b"\xff\xfd\x01\xff\xfb\x1f"), "sent Telnet option negotiation");
        // not one of them: the plain form, as before
        assert_eq!(describe(b"root\r\n1234\r\n", None), "sent 12 bytes: \"root\\r\\n1234\\r\\n\"");
        assert_eq!(describe(b"\x01\x02\x03", None), "sent 3 bytes: \"\\x01\\x02\\x03\"");
        // HTTP keeps its own wording
        assert!(describe(b"GET / HTTP/1.1\r\n\r\n", None).starts_with("sent HTTP request"));
    }

    #[test]
    fn hits_come_from_the_log_without_the_peers_copies() {
        let dir = std::env::temp_dir().join(format!("vpsfort-hits-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("actions.jsonl");
        let now = crate::time::now();
        let hour = 3600 * crate::time::SEC;
        let ban = |ago: i64, ip: &str, message: &str, category: &str, line: &str| {
            serde_json::json!({
                "ts": now - ago * hour, "kind": "ban", "severity": "high", "target": ip, "until": now + hour, "message": message,
                "evidence": [line], "applied": true, "category": category, "user_note": "for the user",
            })
            .to_string()
        };
        let trap = "11-09 02:33:57 connected to honeypot TCP/3389, sent nothing";
        let site = r#"11-09 02:33:57 decoy_request: "GET / HTTP/1.0" 404 146 "-" "-""#;
        let lines = [
            ban(1, "203.0.113.1", "ban 203.0.113.1 for 14d", "tripwire", trap),
            ban(2, "203.0.113.2", "ban 203.0.113.2 for 14d", "custom", site),
            ban(3, "203.0.113.3", "ban 203.0.113.3 for 14d (from peer node1): burst", "from peers", trap),
            ban(4, "203.0.113.4", "ban 203.0.113.4 for 1h", "ssh", "11-09 02:33:57 invalid user oracle"),
            // a line that only names a honeypot further on: what a stranger typed
            ban(5, "203.0.113.5", "ban 203.0.113.5 for 1h", "ssh", "11-09 02:33:57 invalid user connected to honeypot TCP/1, sent nothing"),
            ban(30, "203.0.113.6", "ban 203.0.113.6 for 14d", "tripwire", trap),
            // a network ban's lines name the member first
            ban(
                6,
                "203.0.113.0/24",
                "ban 203.0.113.0/24 for 7d",
                "subnet",
                "11-09 02:33:57 203.0.113.7 connected to honeypot TCP/23, sent nothing",
            ),
        ];
        std::fs::write(&log, lines.join("\n") + "\n").unwrap();
        let day = from_log(&log, Dur(86_400), now).unwrap();
        let targets: Vec<String> = day.hits.iter().filter_map(|a| a.target.map(|t| t.to_string())).collect();
        assert_eq!(targets, ["203.0.113.1", "203.0.113.2", "203.0.113.0/24"], "the newest first, in the window, no peer's copy");
        assert_eq!((day.total, day.to, day.from), (3, now, now - 24 * hour));
        assert_eq!(day.hits[0].user_note, None, "what the tab has no use for is left out");
        assert_eq!(from_log(&log, Dur(7 * 86_400), now).unwrap().total, 4, "the older one is within a week");
        // more than one answer holds: the newest, and the count of all
        let (total, hits) = collect_hits(&log, now - 24 * hour, 2).unwrap();
        assert_eq!((total, hits.len(), hits[1].target.map(|t| t.to_string())), (3, 2, Some("203.0.113.2".to_string())));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(from_log(&log, Dur(86_400), now).is_err(), "no log: said, not an empty list");
    }

    #[test]
    fn prompt_names_round_trip_the_configuration() {
        for p in Prompts::ALL {
            let toml = format!("p = \"{}\"", p.name());
            let back: BTreeMap<String, Prompts> = toml::from_str(&toml).unwrap();
            assert_eq!(back["p"], p);
        }
        // SSH: the configured identification line alone, answered with the client's
        assert_eq!(Prompts::Ssh.lines(b"SSH-2.0-x\r\n"), [&b"SSH-2.0-x\r\n"[..]]);
        assert_eq!(
            describe(b"SSH-2.0-libssh_0.9.6\r\n", Some(Prompts::Ssh)),
            "answered the ssh banner with 22 bytes: \"SSH-2.0-libssh_0.9.6\\r\\n\""
        );
        assert_eq!(describe(b"", Some(Prompts::Ssh)), "sent nothing to the ssh banner");
        assert!(toml::from_str::<BTreeMap<String, Prompts>>("p = \"http\"").is_err(), "no HTTP: the plain capture keeps the request");
        // every default greeting is a real server's and valid for its protocol; a banner
        // must be one a client takes
        for p in Prompts::ALL {
            assert!(p.valid_banner(p.default_banner()), "{p:?}");
            assert!(!p.valid_banner("hello\r\n"), "{p:?}: no line end inside");
            assert!(!p.valid_banner(&"x".repeat(254)), "{p:?}: too long");
        }
        assert!(Prompts::Ssh.default_banner().starts_with("SSH-2.0-OpenSSH_"));
        assert!(Prompts::Ssh.valid_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.11"));
        for bad in ["SSH-1.99-OpenSSH_9.2", "OpenSSH_9.2", "SSH-2.0-", "SSH-2.0- x", "SSH-2.0-x\tx", "SSH-2.0-é"] {
            assert!(!Prompts::Ssh.valid_banner(bad), "{bad:?}");
        }
        assert!(Prompts::Ftp.valid_banner("220 ProFTPD Server (Debian) [::ffff:203.0.113.9]") && Prompts::Ftp.valid_banner("220"));
        assert!(!Prompts::Ftp.valid_banner("2200 x") && !Prompts::Ftp.valid_banner("+OK"));
        assert!(Prompts::Smtp.valid_banner("220 mx.example.org ESMTP Exim 4.96") && !Prompts::Smtp.valid_banner("250 ok"));
        assert!(Prompts::Pop3.valid_banner("+OK POP3 ready") && !Prompts::Pop3.valid_banner("-ERR"));
        assert!(Prompts::Imap.valid_banner("* OK IMAP4rev1 ready") && !Prompts::Imap.valid_banner("* BYE"));
        assert!(Prompts::Telnet.valid_banner("Ubuntu 22.04.4 LTS") && Prompts::Telnet.valid_banner(""));
        // the greeting goes out with its line end; Telnet's the way a login shows it
        assert_eq!(Prompts::Ftp.first_line("220 x"), b"220 x\r\n");
        assert_eq!(Prompts::Telnet.first_line("Ubuntu 22.04.4 LTS"), [TELNET_OPTIONS, b"\r\nUbuntu 22.04.4 LTS\r\n\r\nlogin: "].concat());
        let own = Prompting { by_port: BTreeMap::new(), banners: [(Prompts::Ftp, "220 ProFTPD Server".to_string())].into_iter().collect() };
        let own = Prompting { by_port: [(21, Prompts::Ftp), (110, Prompts::Pop3)].into_iter().collect(), ..own };
        assert_eq!(own.script(21).map(|(p, f)| (p, f.to_vec())), Some((Prompts::Ftp, b"220 ProFTPD Server\r\n".to_vec())));
        let pop = own.script(110).unwrap();
        assert_eq!((pop.0, pop.1.as_slice()), (Prompts::Pop3, &b"+OK Dovecot (Debian) ready.\r\n"[..]), "the others keep their defaults");
        assert_eq!(own.script(22), None, "no prompts on this port");
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn a_binary_reply_to_a_prompt_is_read_whole_and_named() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(
            start(&[port], 512, &prompting(port, Prompts::Ftp), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false))).is_empty()
        );
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"220 (vsFTPd 3.0.3)\r\n");
        // a TLS client hello, 0x0a bytes inside it, as a scanner sends after the greeting
        let mut hello = b"\x16\x03\x01\x01\x0a\x01\x00\x01\x06\x03\x03".to_vec();
        hello.extend((0..260).map(|i| (i % 23) as u8));
        s.write_all(&hello).unwrap();
        drop(s);
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(hit.sent, hello, "not cut at the first 0x0a");
        assert!(
            describe(&hit.sent, hit.prompts).starts_with("answered the ftp prompts with a TLS client hello (271 bytes): \"\\x16\\x03\\x01"),
            "{}",
            describe(&hit.sent, hit.prompts)
        );
        // text still ends at its line, with Telnet's negotiation bytes before it allowed
        assert_eq!(
            describe(b"\xff\xfc\x01root\r\n", Some(Prompts::Telnet)),
            "answered the telnet prompts with 9 bytes: \"\\xff\\xfc\\x01root\\r\\n\""
        );
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn the_ssh_banner_is_sent_and_the_clients_kept_without_its_key_exchange() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        let prompting = Prompting {
            banners: [(Prompts::Ssh, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.11".to_string())].into_iter().collect(),
            ..prompting(port, Prompts::Ssh)
        };
        assert!(start(&[port], 64, &prompting, move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false))).is_empty());
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.11\r\n");
        // the client's identification, and its KEXINIT right behind it
        s.write_all(b"SSH-2.0-Go\r\n\x00\x00\x04\x14\x0a\x14\xff\xfe").unwrap();
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "closed after the banner line");
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((hit.sent.as_slice(), hit.prompts), (&b"SSH-2.0-Go\r\n"[..], Some(Prompts::Ssh)));
        assert_eq!(describe(&hit.sent, hit.prompts), "answered the ssh banner with 12 bytes: \"SSH-2.0-Go\\r\\n\"");
    }
}
