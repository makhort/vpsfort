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
//! follow; VNC's version line likewise; for MySQL, a server's first packet, which brings out
//! the client's login. Nothing the client sends acts on what goes out: the same lines go out
//! whatever arrives, but for the second line of POP3 and FTP, which depends on the first word
//! of the reply, and IMAP's answer to `CAPABILITY`, which repeats the client's tag
//! ([`Prompts::reply_to`]).

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
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
    Vnc,
    Mysql,
}

impl Prompts {
    pub const ALL: [Prompts; 8] =
        [Prompts::Telnet, Prompts::Ftp, Prompts::Smtp, Prompts::Pop3, Prompts::Imap, Prompts::Ssh, Prompts::Vnc, Prompts::Mysql];

    /// Its name in the configuration and the evidence.
    pub fn name(self) -> &'static str {
        match self {
            Prompts::Telnet => "telnet",
            Prompts::Ftp => "ftp",
            Prompts::Smtp => "smtp",
            Prompts::Pop3 => "pop3",
            Prompts::Imap => "imap",
            Prompts::Ssh => "ssh",
            Prompts::Vnc => "vnc",
            Prompts::Mysql => "mysql",
        }
    }

    /// What the evidence calls what was shown: prompts, or the one line or packet of the
    /// protocols that show only that.
    fn what(self) -> &'static str {
        match self {
            Prompts::Ssh | Prompts::Vnc => "banner",
            Prompts::Mysql => "greeting",
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
            // what TigerVNC, x11vnc and QEMU all send
            Prompts::Vnc => "RFB 003.008",
            // Debian 12's server, as `SELECT VERSION()` shows it, with the `5.5.5-` MariaDB 10
            // puts before it in the greeting
            Prompts::Mysql => "5.5.5-10.11.19-MariaDB-0+deb12u1",
        }
    }

    /// What a greeting of this protocol must start with to be one a client takes (RFC 4253's
    /// identification line, the FTP and SMTP `220` reply, POP3's `+OK`, IMAP's untagged `OK`,
    /// RFC 6143's `RFB `; a Telnet issue line is free text, a MySQL version is checked below).
    fn banner_prefix(self) -> &'static str {
        match self {
            Prompts::Telnet | Prompts::Mysql => "",
            Prompts::Ftp | Prompts::Smtp => "220",
            Prompts::Pop3 => "+OK",
            Prompts::Imap => "* OK",
            Prompts::Ssh => "SSH-2.0-",
            Prompts::Vnc => "RFB ",
        }
    }

    /// Whether `banner` can be sent as this protocol's greeting: its prefix, then something
    /// (SSH: a software token, with comments after a space; VNC: exactly `ddd.ddd`, which is
    /// all a client and a scanner accept; MySQL: a version number), printable ASCII, at most
    /// 253 characters before the line end.
    pub fn valid_banner(self, banner: &str) -> bool {
        let Some(rest) = banner.strip_prefix(self.banner_prefix()) else { return false };
        let token_ok = match self {
            Prompts::Ssh => !rest.is_empty() && !rest.starts_with(' '),
            Prompts::Telnet => true,
            Prompts::Vnc => {
                matches!(rest.as_bytes(), [a, b, c, b'.', d, e, f] if [a, b, c, d, e, f].iter().all(|x| x.is_ascii_digit()))
            }
            Prompts::Mysql => rest.starts_with(|c: char| c.is_ascii_digit()),
            _ => rest.is_empty() || rest.starts_with(' '),
        };
        token_ok && banner.len() <= 253 && banner.bytes().all(|b| (0x20..=0x7e).contains(&b))
    }

    /// The bytes the greeting goes out as, built for each connection: with its line end, for
    /// Telnet the way a telnetd shows it: its option negotiation first ([`TELNET_OPTIONS`]),
    /// then the issue line with blank lines around it and the prompt after it; for MySQL the
    /// server's first packet, around the version ([`mysql_greeting`]).
    fn first_line(self, banner: &str) -> Vec<u8> {
        match self {
            Prompts::Telnet => [TELNET_OPTIONS, format!("\r\n{banner}\r\n\r\nlogin: ").as_bytes()].concat(),
            Prompts::Vnc => format!("{banner}\n").into_bytes(), // RFC 6143: a bare line feed
            Prompts::Mysql => mysql_greeting(banner),
            _ => format!("{banner}\r\n").into_bytes(),
        }
    }

    /// What goes out in place of `line`, given what the client has said so far: `line`, except
    /// for the reply of POP3, FTP and IMAP to the first thing said; `None` ends the
    /// conversation. A real server refuses anything but a command it knows, and scanners test
    /// for that: fingerprintx sends a bogus command and takes the port for POP3 only if `-ERR`
    /// comes back. So only `USER` gets the reply that brings out the password, and the first
    /// word is all that is looked at. IMAP answers `CAPABILITY` alone ([`imap_capability`]).
    fn reply_to<'a>(self, line: &'a [u8], said: &[u8]) -> Option<Cow<'a, [u8]>> {
        if said.is_empty() {
            return Some(line.into());
        }
        if self == Prompts::Imap {
            return imap_capability(line, said).map(Cow::Owned);
        }
        let user = said.split(u8::is_ascii_whitespace).next().is_some_and(|w| w.eq_ignore_ascii_case(b"USER"));
        let reply: &[u8] = match self {
            Prompts::Pop3 if !user => b"-ERR Unknown command.\r\n", // Dovecot's words, as the greeting's
            // vsftpd's words before a login, also to `AUTH TLS` when it has no TLS configured
            Prompts::Ftp if !user => b"530 Please login with USER and PASS.\r\n",
            _ => line,
        };
        Some(reply.into())
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
            // `a1 LOGIN user pass` in one line, perhaps after `a1 CAPABILITY`; the second entry
            // isn't a line but the list [`Prompts::reply_to`] answers that with
            Prompts::Imap => vec![first, imap_capabilities(first)],
            // the client's version line; the security types that would come next are not sent
            Prompts::Vnc => vec![first],
            // the client's login: the account by name, the password as a salted hash
            Prompts::Mysql => vec![first],
        }
    }
}

/// What an IMAP server lists when a greeting set in `[ports] honeypot_banners` lists nothing.
const IMAP_CAPABILITIES: &[u8] = b"IMAP4rev1 AUTH=PLAIN AUTH=LOGIN";

/// The capabilities an IMAP greeting lists (`* OK [CAPABILITY ...] ...`). A server's answer to
/// `CAPABILITY` is the same list.
fn imap_capabilities(greeting: &[u8]) -> &[u8] {
    const CODE: &[u8] = b"[CAPABILITY ";
    greeting
        .windows(CODE.len())
        .position(|w| w == CODE)
        .map(|at| &greeting[at + CODE.len()..])
        .and_then(|rest| rest.iter().position(|&b| b == b']').map(|end| &rest[..end]))
        .unwrap_or(IMAP_CAPABILITIES)
}

/// A server's answer to `<tag> CAPABILITY`, in Dovecot's words: the list, then the client's
/// tag at the start of the next line, which is what fingerprintx looks for. `None` for
/// anything else, and for a tag RFC 3501 wouldn't take: the tag is the only thing a client
/// says that ever goes back out.
fn imap_capability(capabilities: &[u8], said: &[u8]) -> Option<Vec<u8>> {
    let mut words = said.split(u8::is_ascii_whitespace).filter(|word| !word.is_empty());
    let (tag, command) = (words.next()?, words.next()?);
    let tag_ok = tag.len() <= 64 && tag.iter().all(|b| b.is_ascii_graphic() && !b"(){%*\"\\+".contains(b));
    if !tag_ok || !command.eq_ignore_ascii_case(b"CAPABILITY") || words.next().is_some() {
        return None;
    }
    let ok = b" OK Pre-login capabilities listed, post-login capabilities have more.\r\n";
    Some([&b"* CAPABILITY "[..], capabilities, b"\r\n", tag, ok].concat())
}

/// `N` bytes from the system. If it has none to give the bytes stay zero: this is only a
/// greeting's salt, not worth stopping a listener for.
fn random_bytes<const N: usize>() -> [u8; N] {
    use chacha20poly1305::aead::{rand_core::RngCore, OsRng};
    let mut bytes = [0u8; N];
    let _ = OsRng.try_fill_bytes(&mut bytes);
    bytes
}

/// The connection number of the last MySQL greeting. A server numbers its connections from
/// its start; this starts where one that has been up for a while would be.
static MYSQL_CONNECTION: AtomicU32 = AtomicU32::new(0);

/// A server's first packet (protocol 10) for `version`: the client answers it with its login.
/// The salt and the connection number change with every connection, as on a real server; the
/// same ones twice would show two addresses of a scanner that they met one fake. TLS isn't
/// offered, as a Debian package's default server doesn't, so the login comes in the clear.
fn mysql_greeting(version: &str) -> Vec<u8> {
    let start = 1 + u32::from_le_bytes(random_bytes()) % 90_000;
    let _ = MYSQL_CONNECTION.compare_exchange(0, start, Ordering::Relaxed, Ordering::Relaxed);
    let connection = MYSQL_CONNECTION.fetch_add(1, Ordering::Relaxed);
    // printable, as a server's own
    let salt = random_bytes::<20>().map(|b| 33 + b % 94);
    // MariaDB leaves CLIENT_MYSQL off and says what else it can do where MySQL has filler
    let maria = version.contains("MariaDB");
    let capabilities_low: u16 = if maria { 0xf7fe } else { 0xf7ff };
    let capabilities_maria: [u8; 4] = if maria { [0x1d, 0, 0, 0] } else { [0; 4] };
    let mut body = vec![10];
    body.extend_from_slice(version.as_bytes());
    body.push(0);
    body.extend_from_slice(&connection.to_le_bytes());
    body.extend_from_slice(&salt[..8]);
    body.push(0);
    body.extend_from_slice(&capabilities_low.to_le_bytes());
    body.push(45); // utf8mb4_general_ci
    body.extend_from_slice(&2u16.to_le_bytes()); // autocommit
    body.extend_from_slice(&0x81ffu16.to_le_bytes());
    body.push(salt.len() as u8 + 1);
    body.extend_from_slice(&[0; 6]);
    body.extend_from_slice(&capabilities_maria);
    body.extend_from_slice(&salt[8..]);
    body.push(0);
    body.extend_from_slice(b"mysql_native_password\0");
    let mut packet = (body.len() as u32).to_le_bytes()[..3].to_vec();
    packet.push(0); // the packet's sequence number
    packet.extend_from_slice(&body);
    packet
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
    /// A port's prompts, if it has any, with the greeting they open with.
    fn script(&self, port: u16) -> Option<(Prompts, Arc<str>)> {
        let p = *self.by_port.get(&port)?;
        Some((p, Arc::from(self.banners.get(&p).map_or(p.default_banner(), String::as_str))))
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
const MAX_SOURCES: usize = 2_000;
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
    // a hit waits in the daemon's queue with what was read, not with the whole capture's
    // room (4 KB at most, times the thousands of hits a flood queues)
    out.shrink_to_fit();
    out
}

/// What BusyBox's telnetd sends before any text, and what a Telnet bot waits for before it
/// reads for a prompt: `IAC DO ECHO`, `IAC DO NAWS`, `IAC WILL ECHO`, `IAC WILL SGA`. Nine
/// of the first ten Telnet connections to a honeypot node sat silent at a greeting without it.
const TELNET_OPTIONS: &[u8] = b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03";

/// The longest Telnet subnegotiation waited for: a window size is 9 bytes, a terminal type or
/// an environment a few dozen.
const TELNET_SUBNEGOTIATION: usize = 256;

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
                // one that doesn't end isn't negotiation: its bytes are text, which the capture
                // bounds. Left to wait for their end, they would pile up (and be gone through
                // again at every read) for as long as the client sent them.
                None if buf.len() - i > TELNET_SUBNEGOTIATION => {
                    out.extend_from_slice(&buf[i..]);
                    i = buf.len();
                }
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

/// Appends what a client answers a MySQL greeting with to `out`: the one packet its header
/// announces when that is a login (the packet numbered 1), else what the first read brings
/// (a TLS client hello, an HTTP request). Within the deadline and the capture.
fn read_mysql_answer(s: &mut TcpStream, deadline: Instant, capture: usize, out: &mut Vec<u8>) {
    let mut buf = [0u8; 512];
    while out.len() < capture {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || s.set_read_timeout(Some(left)).is_err() {
            return;
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(k) => out.extend_from_slice(&buf[..k.min(capture - out.len())]),
        }
        if let [a, b, c, number, ..] = out[..] {
            if number != 1 || out.len() >= 4 + u32::from_le_bytes([a, b, c, 0]) as usize {
                return;
            }
        }
    }
}

/// Shows the prompts, one by one, reading the reply to each; returns the replies. The same
/// lines go out whatever the client sends ([`Prompts::reply_to`] has the exceptions), within
/// [`PROMPT_WAIT`] and `capture` bytes in all.
fn converse(mut s: TcpStream, capture: usize, prompts: Prompts, banner: &str) -> Vec<u8> {
    let deadline = Instant::now() + PROMPT_WAIT;
    let first = prompts.first_line(banner);
    let (mut out, mut pending) = (Vec::new(), Vec::new());
    for line in prompts.lines(&first) {
        let Some(line) = prompts.reply_to(line, &out) else { break };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || s.set_write_timeout(Some(left)).is_err() || s.write_all(&line).is_err() || s.flush().is_err() {
            break;
        }
        if prompts == Prompts::Mysql {
            read_mysql_answer(&mut s, deadline, capture, &mut out);
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
    /// The method its JSON-RPC body calls, if it has one ([`rpc_method`]).
    rpc: Option<&'a [u8]>,
}

/// The method a JSON-RPC body calls (`{"jsonrpc":"2.0","method":"eth_accounts"}`): what a
/// probe of a cryptocurrency node's RPC port is after, which its request line, a bare
/// `POST /`, doesn't say. A plain name or nothing: the name is what a stranger chose.
fn rpc_method(body: &[u8]) -> Option<&[u8]> {
    const KEY: &[u8] = b"\"method\"";
    let after = body.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let name = body[after..].trim_ascii_start().strip_prefix(b":")?.trim_ascii_start().strip_prefix(b"\"")?;
    let name = &name[..name.iter().position(|&b| b == b'"')?];
    let plain = !name.is_empty() && name.len() <= 64 && name.iter().all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(b));
    plain.then_some(name)
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
    // what follows the blank line, whichever line ends the client uses
    let body = (0..sent.len()).find_map(|i| match &sent[i..] {
        [b'\n', b'\n', body @ ..] | [b'\n', b'\r', b'\n', body @ ..] => Some(body),
        _ => None,
    });
    Some(HttpRequest { request, host, agent, rpc: body.and_then(rpc_method) })
}

/// The captured bytes as one line of plain ASCII (see [`ascii`]), cut to [`SHOWN`]
/// characters; an HTTP request by its request line, the method its JSON-RPC body calls, its
/// host and user agent; the replies to
/// prompts named as such. The abuse report quotes it after "connected to our decoy service
/// on port ... and".
pub fn describe(sent: &[u8], prompts: Option<Prompts>) -> String {
    match (prompts, sent.is_empty()) {
        (Some(p), true) => return format!("sent nothing to the {} {}", p.name(), p.what()),
        (Some(p), false) => {
            if let Some(user) = mysql_login_user(sent).filter(|_| p == Prompts::Mysql) {
                let (user, after) = (ascii(user, SHOWN_FIELD), ascii(&sent[MYSQL_NAME_AT..], SHOWN));
                return format!("answered the mysql greeting with a login as \"{user}\" ({} bytes): \"{after}\"", sent.len());
            }
            // a reply that is another protocol's opening (TLS tried after the greeting) is
            // named too; not what the prompt asks for (a client's banner after SSH's or
            // VNC's, Telnet's own negotiation), which would say nothing
            let name = protocol(sent).filter(|&n| {
                !matches!(
                    (p, n),
                    (Prompts::Ssh, "an SSH client banner")
                        | (Prompts::Vnc, "a VNC client version")
                        | (Prompts::Telnet, "Telnet option negotiation")
                )
            });
            let what = name.map_or_else(|| format!("{} bytes", sent.len()), |name| format!("{name} ({} bytes)", sent.len()));
            return format!("answered the {} {} with {what}: \"{}\"", p.name(), p.what(), ascii(sent, SHOWN));
        }
        (None, true) => return "sent nothing".to_string(),
        (None, false) => {}
    }
    if let Some(HttpRequest { request, host, agent, rpc }) = http_request(sent) {
        let mut text = format!("sent HTTP request \"{}\"", ascii(request, SHOWN_FIELD));
        if let Some(m) = rpc {
            text += &format!(" calling \"{}\"", ascii(m, SHOWN_FIELD));
        }
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

/// Where the account name starts in a MySQL login: after the packet's header and the fixed
/// fields (capabilities, largest packet, character set, filler). The account is the one thing
/// in it that says anything, and the filler's zeros would use up an evidence line before it.
const MYSQL_NAME_AT: usize = 4 + 32;

/// The account a MySQL client logs in as, if `s` is a login: the packet numbered 1, the 4.1
/// protocol's flag, the name up to its zero byte (or to the end of a capture cut short).
fn mysql_login_user(s: &[u8]) -> Option<&[u8]> {
    if s.get(3) != Some(&1) || s.get(5)? & 0x02 == 0 {
        return None;
    }
    let rest = s.get(MYSQL_NAME_AT..).filter(|r| !r.is_empty())?;
    rest.split(|&b| b == 0).next()
}

/// Whether the bytes open an LDAP bind: a BER sequence, a message ID of up to 4 bytes (a
/// client picks its size: scanners often send 4), then the bind request's tag.
fn is_ldap_bind(s: &[u8]) -> bool {
    if s.first() != Some(&0x30) {
        return false;
    }
    // the sequence's length: one byte, or 0x81..=0x84 and that many more
    let id_at = match s.get(1) {
        Some(0..=0x7f) => 2,
        Some(l @ 0x81..=0x84) => 2 + usize::from(l - 0x80),
        _ => return false,
    };
    let (Some(0x02), Some(&size @ 1..=4)) = (s.get(id_at), s.get(id_at + 1)) else { return false };
    s.get(id_at + 2 + usize::from(size)) == Some(&0x60)
}

/// What the first bytes of a connection are, for the protocols scanners open with (the
/// client speaks first in each), so the evidence says "an SMB2 negotiate" before the hex. By
/// the fixed bytes of each protocol's opening message: a length that matches, a magic string,
/// a version. Nothing is answered; a capture cut short still names its protocol.
fn protocol(s: &[u8]) -> Option<&'static str> {
    let n = s.len();
    let at = |i: usize| s.get(i).copied();
    let be16 = |i: usize| Some(u16::from_be_bytes([at(i)?, at(i + 1)?]) as usize);
    let le16 = |i: usize| Some(u16::from_le_bytes([at(i)?, at(i + 1)?]) as usize);
    let be32 = |i: usize| Some(u32::from_be_bytes([at(i)?, at(i + 1)?, at(i + 2)?, at(i + 3)?]));
    let le32 = |i: usize| Some(u32::from_le_bytes([at(i)?, at(i + 1)?, at(i + 2)?, at(i + 3)?]));
    let has = |needle: &[u8]| s.windows(needle.len()).any(|w| w == needle);
    // a length field that is the whole message, or more than was captured
    let whole = |len: Option<usize>| len.is_some_and(|l| l >= n && l <= MAX_CAPTURE * 4);
    let first_line = s.split(|&b| b == b'\n').next().unwrap_or(s);
    let first_line = first_line.strip_suffix(b"\r").unwrap_or(first_line);
    // how an FTP client asks for TLS: the same first word as a Redis login
    let ftp_tls = [&b"AUTH TLS"[..], b"AUTH SSL", b"AUTH TLS-C", b"AUTH TLS-P"].contains(&first_line);
    Some(if s.starts_with(b"SSH-") {
        "an SSH client banner"
    } else if s.starts_with(b"RFB 0") {
        "a VNC client version"
    } else if first_line.ends_with(b" SIP/2.0") {
        "a SIP request"
    } else if s.starts_with(b"AMQP") {
        "an AMQP protocol header"
    } else if s.starts_with(b"CNXN") {
        "an ADB connect"
    } else if s.starts_with(b"JRMI") {
        "a Java RMI handshake"
    } else if (s.starts_with(b"*") && has(b"\r\n$"))
        || (!ftp_tls && [&b"INFO"[..], b"PING", b"CONFIG ", b"AUTH ", b"EVAL "].iter().any(|c| s.starts_with(c)))
        || first_line == b"info"
        || first_line == b"ping"
    {
        "a Redis command"
    } else if s.starts_with(b"stats") || s.starts_with(b"version\r\n") {
        "a memcached command"
    } else if at(0) == Some(0xff) && at(1).is_some_and(|command| (0xf0..=0xfe).contains(&command)) {
        // the byte after IAC is what says Telnet: other protocols open with 0xff too (DVRs on 34567)
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
    } else if at(0) == Some(0x81) && at(1) == Some(0) && at(4) == Some(0x20) && whole(be16(2).map(|l| l + 4)) {
        // port 139's opening before SMB: the header, then the called name's length (always 32)
        "a NetBIOS session request"
    } else if at(0) == Some(3) && at(1) == Some(0) && whole(be16(2)) && at(5) == Some(0xe0) {
        // by its cookie, or without one by the RDP negotiation request right after the header
        if has(b"mstshash") || s.get(11..15) == Some(b"\x01\x00\x08\x00") {
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
    } else if s.starts_with(b"\x05\x00\x0b") && whole(le16(8)) {
        "a DCE/RPC bind"
    } else if at(0) == Some(1) && at(1) == Some(1) && be16(4) == Some(8) && be16(8).is_some_and(|role| (1..=3).contains(&role)) {
        "a FastCGI request"
    } else if s.get(1..7) == Some(b"\x02index") {
        "a MikroTik Winbox request"
    } else if at(0) == Some(5) && n >= 3 && at(1) == Some((n - 2) as u8) {
        "a SOCKS5 greeting"
    } else if at(0) == Some(4) && (at(1) == Some(1) || at(1) == Some(2)) && n >= 9 {
        "a SOCKS4 connect"
    } else if at(0) == Some(0x10) && (has(b"\x00\x04MQTT") || has(b"\x00\x06MQIsdp")) {
        "an MQTT connect"
    } else if n >= 8 && s[2..4] == [0, 0] && be16(4) == Some(n - 6) && (1..=0x7f).contains(&s[7]) {
        "a Modbus request"
    } else if is_ldap_bind(s) {
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
    script: Option<(Prompts, Arc<str>)>,
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
                    Some((p, banner)) => converse(s, capture, *p, banner),
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

    /// A subnegotiation that never ends was held for more, read after read, and grew for as
    /// long as the client sent it: megabytes a connection, gone through again at every read.
    #[test]
    fn an_endless_telnet_subnegotiation_is_text_not_a_wait() {
        let mut v = [&b"\xff\xfa\x18"[..], &[b'A'; 300]].concat();
        assert_eq!(strip_telnet_options(&mut v), 0, "nothing is left waiting");
        assert_eq!(v.len(), 303, "its bytes are text, for the capture to bound");
        // a short one cut by the read still waits for its end
        let mut v = b"root\xff\xfa\x1f\x00\x50".to_vec();
        assert_eq!(strip_telnet_options(&mut v), 5);
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn an_endless_telnet_subnegotiation_fills_the_capture_and_ends() {
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
        let began = Instant::now();
        let flood = [&b"\xff\xfa\x18"[..], &[b'A'; 4000]].concat();
        let _ = s.write_all(&flood);
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(hit.sent.len(), 64, "the capture, not what the client cared to send");
        assert!(began.elapsed() < PROMPT_WAIT, "closed when the capture is full, not at the deadline");
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
        // the RDP negotiation request without a cookie, all five seen on 3389 on the honeypot node
        assert_eq!(name(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"), "sent an RDP connection request");
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
        assert_eq!(name(b"info\n"), "sent a Redis command");
        assert_eq!(name(b"ping\r\n"), "sent a Redis command");
        assert_eq!(name(b"AUTH hunter2\r\n"), "sent a Redis command");
        // an FTP client asking for TLS, seen after the honeypot's FTP greeting
        assert_eq!(describe(b"AUTH TLS\r\n", None), "sent 10 bytes: \"AUTH TLS\\r\\n\"");
        assert_eq!(
            describe(b"AUTH TLS\r\nAUTH SSL\r\n", Some(Prompts::Ftp)),
            "answered the ftp prompts with 20 bytes: \"AUTH TLS\\r\\nAUTH SSL\\r\\n\""
        );
        let netbios = b"\x81\x00\x00D CKFDENECFDEFFCFGEFFCCACACACACACA\x00 CKFDENECEDEMEJEFEOFECACACACACAAA\x00";
        assert_eq!(netbios.len(), 72);
        assert_eq!(name(netbios), "sent a NetBIOS session request");
        assert_eq!(name(&netbios[..40]), "sent a NetBIOS session request", "cut by the capture");
        assert!(!name(b"\x81\x00\x00\x01 xy").contains("NetBIOS"), "a length shorter than what came");
        assert_eq!(describe(b"information\n", None), "sent 12 bytes: \"information\\n\"", "lower case: only the whole command");
        assert_eq!(name(b"stats\r\n"), "sent a memcached command");
        // as seen on the honeypot node
        let mut dce = b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00".to_vec();
        dce.resize(72, 0);
        assert_eq!(name(&dce), "sent a DCE/RPC bind");
        let fcgi = b"\x01\x01\xe6\x0a\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x04\xe6\x0a\x00\x00\x00\x00";
        assert_eq!(name(fcgi), "sent a FastCGI request");
        assert_eq!(name(b"\x13\x02index\x00\x00\x00\x00\x00\x00\x00\xff\xed\x00\x00\x00\x00\x00"), "sent a MikroTik Winbox request");
        assert_eq!(name(b"\x05\x02\x00\x02"), "sent a SOCKS5 greeting");
        assert_eq!(name(b"\x04\x01\x00\x50\xcb\x00\x71\x01\x00"), "sent a SOCKS4 connect");
        assert_eq!(name(b"\x10\x1a\x00\x04MQTT\x04\x02\x00\x3c\x00\x0emqtt-explorer"), "sent an MQTT connect");
        assert_eq!(name(b"AMQP\x00\x00\x09\x01"), "sent an AMQP protocol header");
        assert_eq!(name(b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00"), "sent an ADB connect");
        assert_eq!(name(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"), "sent a Modbus request");
        assert_eq!(name(b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"), "sent an LDAP bind request");
        // as fingerprintx sends it: a 4-byte message ID, seen on the honeypot node
        let ldap = b"0:\x02\x04\x19\x00\xe7\xf8`2\x02\x01\x03\x04\x17cn=pcvueuuqtafriifthgjz\x80\x14pcvueuuqtafriifthgjz";
        assert_eq!(ldap.len(), 60);
        assert_eq!(name(ldap), "sent an LDAP bind request");
        // the sequence's length in the long form
        assert_eq!(name(b"\x30\x81\x0c\x02\x02\x00\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"), "sent an LDAP bind request");
        // the same start, but not a bind (a search); and cut short
        assert!(!is_ldap_bind(b"\x30\x0c\x02\x01\x01\x63\x07\x60\x60"));
        assert!(!is_ldap_bind(b"\x30\x0c\x02\x04\x19"));
        assert!(!is_ldap_bind(b"\x30\x0c\x02\x05\x00\x00\x00\x00\x00\x60"), "an ID larger than LDAP allows");
        assert!(!is_ldap_bind(b"\x30"));
        assert!(!is_ldap_bind(b""));
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
        assert!(!name(b"\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x03").contains("Telnet"), "a DVR's opening");
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
        assert_eq!(own.script(21).map(|(p, b)| (p, b.to_string())), Some((Prompts::Ftp, "220 ProFTPD Server".to_string())));
        let pop = own.script(110).unwrap();
        assert_eq!((pop.0, &*pop.1), (Prompts::Pop3, "+OK Dovecot (Debian) ready."), "the others keep their defaults");
        assert_eq!(own.script(22), None, "no prompts on this port");
        // VNC: exactly what a client takes, sent with a bare line feed
        assert_eq!(Prompts::Vnc.first_line(Prompts::Vnc.default_banner()), b"RFB 003.008\n");
        assert!(Prompts::Vnc.valid_banner("RFB 003.003") && Prompts::Vnc.valid_banner("RFB 005.000"));
        for bad in ["RFB 3.8", "RFB 003.008 x", "RFB 003-008", "RFB 00a.008", "003.008"] {
            assert!(!Prompts::Vnc.valid_banner(bad), "{bad:?}");
        }
        // MySQL: a version number
        assert!(Prompts::Mysql.valid_banner("5.7.44-log") && Prompts::Mysql.valid_banner("8.0.43"));
        assert!(!Prompts::Mysql.valid_banner("MariaDB") && !Prompts::Mysql.valid_banner(""));
    }

    /// The parts of a MySQL greeting a client or a scanner reads.
    struct Greeting {
        version: Vec<u8>,
        connection: u32,
        salt: Vec<u8>,
        capabilities_low: u16,
        plugin: Vec<u8>,
    }

    fn parse_greeting(packet: &[u8]) -> Greeting {
        let length = u32::from_le_bytes([packet[0], packet[1], packet[2], 0]) as usize;
        assert_eq!(packet.len(), 4 + length, "the header says the packet's size");
        assert_eq!(packet[3], 0, "the first packet of a connection");
        assert_eq!(packet[4], 10, "protocol 10");
        // fingerprintx: 4 header bytes read as a little-endian 25..=4096, 35 bytes at least,
        // and a zero 13 bytes after the version's
        let header = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert!((25..=4096).contains(&header) && packet.len() >= 35, "{header}");
        let end = 5 + packet[5..].iter().position(|&b| b == 0).unwrap();
        assert_eq!(packet[end + 13], 0, "the filler after the salt's first part");
        // Nmap: `^.\0\0\0\x0a` before the version: the length has to fit one byte
        assert!(packet[..4][1..] == [0, 0, 0]);
        let at = end + 1;
        let connection = u32::from_le_bytes(packet[at..at + 4].try_into().unwrap());
        let mut salt = packet[at + 4..at + 12].to_vec();
        let capabilities_low = u16::from_le_bytes(packet[at + 13..at + 15].try_into().unwrap());
        assert_eq!(capabilities_low & 0x0800, 0, "no TLS offered: the login comes in the clear");
        assert_eq!(packet[at + 15], 45, "the character set");
        assert_eq!(packet[at + 18..at + 20], [0xff, 0x81], "capabilities' upper part");
        assert_eq!(usize::from(packet[at + 20]), 21, "the salt's length, with its zero");
        let second = at + 21 + 10;
        salt.extend_from_slice(&packet[second..second + 12]);
        assert_eq!(packet[second + 12], 0);
        let plugin = packet[second + 13..packet.len() - 1].to_vec();
        assert_eq!(packet[packet.len() - 1], 0);
        Greeting { version: packet[5..end].to_vec(), connection, salt, capabilities_low, plugin }
    }

    #[test]
    fn a_mysql_greeting_is_what_clients_and_scanners_read_and_never_the_same_twice() {
        let (one, two) = (mysql_greeting(Prompts::Mysql.default_banner()), mysql_greeting(Prompts::Mysql.default_banner()));
        let (a, b) = (parse_greeting(&one), parse_greeting(&two));
        assert_eq!(a.version, b"5.5.5-10.11.19-MariaDB-0+deb12u1");
        assert_eq!(a.plugin, b"mysql_native_password");
        assert_eq!(a.capabilities_low & 1, 0, "MariaDB leaves CLIENT_MYSQL off");
        assert_eq!(a.salt.len(), 20);
        assert!(a.salt.iter().chain(&b.salt).all(|c| (33..=126).contains(c)), "printable, as a server's");
        assert_ne!(a.salt, b.salt, "a fresh salt each time");
        assert!(b.connection > a.connection, "the connections are counted");
        // another server's version: MySQL's flags
        let mysql = parse_greeting(&mysql_greeting("5.7.44-log"));
        assert_eq!((mysql.version.as_slice(), mysql.capabilities_low & 1), (&b"5.7.44-log"[..], 1));
    }

    /// A login as a client writes it: the 4.1 protocol, then its name, its hash, its plugin.
    fn mysql_login(user: &[u8]) -> Vec<u8> {
        let mut body = 0x0003_a685u32.to_le_bytes().to_vec(); // includes CLIENT_PROTOCOL_41
        body.extend_from_slice(&0x0100_0000u32.to_le_bytes());
        body.push(45);
        body.extend_from_slice(&[0; 23]);
        body.extend_from_slice(user);
        body.push(0);
        body.push(20);
        body.extend_from_slice(&[0xab; 20]);
        body.extend_from_slice(b"mysql_native_password\0");
        let mut packet = (body.len() as u32).to_le_bytes()[..3].to_vec();
        packet.push(1);
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn a_mysql_login_is_shown_by_its_account() {
        let login = mysql_login(b"root");
        assert!(
            describe(&login, Some(Prompts::Mysql)).starts_with(&format!(
                "answered the mysql greeting with a login as \"root\" ({} bytes): \"root\\x00\\x14\\xab",
                login.len()
            )),
            "{}",
            describe(&login, Some(Prompts::Mysql))
        );
        // what a stranger chose can't act on a terminal or a report
        let odd = describe(&mysql_login(b"\x1b]52;c;x\x07\"root"), Some(Prompts::Mysql));
        assert!(odd.contains("a login as \"\\x1b]52;c;x\\x07\\\"root\"") && odd.chars().all(|c| !c.is_control()), "{odd}");
        // a capture that ends inside the name still has what arrived
        assert!(describe(&mysql_login(b"administrator")[..40], Some(Prompts::Mysql)).contains("a login as \"admi\""));
        // not a login: the plain form, named when it is another protocol's opening
        assert_eq!(describe(b"\r\n", Some(Prompts::Mysql)), "answered the mysql greeting with 2 bytes: \"\\r\\n\"");
        assert!(describe(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc", Some(Prompts::Mysql))
            .starts_with("answered the mysql greeting with a TLS client hello"));
        assert_eq!(mysql_login_user(&mysql_login(b"root")[..36]), None, "the name hasn't arrived");
        let mut old = mysql_login(b"root");
        old[5] &= !0x02;
        assert_eq!(mysql_login_user(&old), None, "not the 4.1 protocol: the name is elsewhere");
        assert_eq!(describe(b"", Some(Prompts::Mysql)), "sent nothing to the mysql greeting");
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn a_mysql_login_ends_the_conversation_at_its_packets_end() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(
            start(&[port], 512, &prompting(port, Prompts::Mysql), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false))).is_empty()
        );
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(parse_greeting(&buf[..n]).version, Prompts::Mysql.default_banner().as_bytes());
        // the login in two pieces, and a command behind it that is no part of it
        let login = mysql_login(b"root");
        let started = Instant::now();
        s.write_all(&login[..20]).unwrap();
        thread::sleep(Duration::from_millis(50));
        s.write_all(&login[20..]).unwrap();
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "closed after the login");
        assert!(started.elapsed() < Duration::from_secs(5), "not held to the deadline: {:?}", started.elapsed());
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((hit.sent.as_slice(), hit.prompts), (login.as_slice(), Some(Prompts::Mysql)));
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn the_vnc_banner_is_sent_and_the_clients_version_kept() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(
            start(&[port], 64, &prompting(port, Prompts::Vnc), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false))).is_empty()
        );
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"RFB 003.008\n", "the 12 bytes clients and scanners insist on");
        s.write_all(b"RFB 003.008\n").unwrap();
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "closed after the client's version");
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((hit.sent.as_slice(), hit.prompts), (&b"RFB 003.008\n"[..], Some(Prompts::Vnc)));
        assert_eq!(describe(&hit.sent, hit.prompts), "answered the vnc banner with 12 bytes: \"RFB 003.008\\n\"");
        assert_eq!(describe(b"", Some(Prompts::Vnc)), "sent nothing to the vnc banner");
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn ftp_refuses_what_comes_before_a_login() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(
            start(&[port], 64, &prompting(port, Prompts::Ftp), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false))).is_empty()
        );
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"220 (vsFTPd 3.0.3)\r\n");
        // both lines in one packet, as seen on the honeypot node
        s.write_all(b"AUTH TLS\r\nQUIT\r\n").unwrap();
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"530 Please login with USER and PASS.\r\n");
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap().sent, b"AUTH TLS\r\nQUIT\r\n");
        // a login still gets its password prompt, in any case
        for user in [&b"USER root\r\n"[..], b"user root\r\n"] {
            assert_eq!(reply(Prompts::Ftp, b"331 Please specify the password.\r\n", user), b"331 Please specify the password.\r\n");
        }
        assert_eq!(reply(Prompts::Ftp, b"220 x\r\n", b""), b"220 x\r\n", "the greeting comes first");
    }

    #[test]
    fn an_rpc_call_is_shown_by_the_method_it_calls() {
        let post =
            |body: &str| format!("POST / HTTP/1.1\r\nHost: example.org:8545\r\nUser-Agent: Go-http-client/1.1\r\n\r\n{body}").into_bytes();
        let shown = |body: &str| describe(&post(body), None);
        let eth = r#"{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}"#;
        assert_eq!(
            shown(eth),
            format!(
                "sent HTTP request \"POST / HTTP/1.1\" calling \"eth_accounts\" for host \"example.org:8545\" with user agent \"Go-http-client/1.1\" ({} bytes)",
                post(eth).len()
            )
        );
        for (body, method) in [
            (r#"{"jsonrpc":"1.0","id":"x","method":"getblockchaininfo","params":[]}"#, "getblockchaininfo"),
            ("{ \"method\" :\n \"get_info\" }", "get_info"),
            (r#"[{"method":"getVersion"},{"method":"getSlot"}]"#, "getVersion"),
            (r#"{"method":"tools/list"}"#, "tools/list"),
        ] {
            assert!(shown(body).contains(&format!(" calling \"{method}\" for host")), "{}", shown(body));
        }
        // no method, or none worth trusting: the request is shown as before
        for body in [
            "",
            "user=admin&pass=admin",
            r#"{"id":1}"#,
            r#"{"method":""}"#,
            r#"{"method":"two words"}"#,
            r#"{"method":"eth_acc"#,
            r#"{"method":1}"#,
            "{\"method\":\"a\x1b[2Jb\"}",
        ] {
            assert!(!shown(body).contains(" calling "), "{body:?}: {}", shown(body));
        }
        assert!(!shown(&format!(r#"{{"method":"{}"}}"#, "a".repeat(65))).contains(" calling "), "too long");
        // a header is not the body, and bare line feeds end the headers too
        assert!(!describe(b"POST / HTTP/1.1\r\nX-A: \"method\":\"x\"\r\n\r\n{}", None).contains(" calling "));
        assert!(describe(b"POST / HTTP/1.0\nHost: a\n\n{\"method\":\"x\"}", None).contains(" calling \"x\""));
        // no HTTP around it: not a call
        assert!(!describe(br#"{"method":"x"}"#, None).contains(" calling "));
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn an_rpc_body_sent_after_its_headers_is_kept() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(start(&[port], 512, &silent(), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false))).is_empty());
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(b"POST / HTTP/1.1\r\nHost: example.org\r\nContent-Length: 25\r\n\r\n").unwrap();
        s.flush().unwrap();
        thread::sleep(Duration::from_millis(100));
        s.write_all(br#"{"method":"eth_accounts"}"#).unwrap();
        drop(s);
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(describe(&hit.sent, None).contains(" calling \"eth_accounts\""), "{}", describe(&hit.sent, None));
    }

    fn reply(p: Prompts, line: &[u8], said: &[u8]) -> Vec<u8> {
        p.reply_to(line, said).unwrap().into_owned()
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn imap_answers_capability_with_the_clients_tag_and_keeps_the_login_after_it() {
        // writes each of `sends` after reading what the listener has said; what it heard, what
        // it heard after the last write (nothing if the connection just closed), and the hit
        let run = |sends: &[&[u8]]| {
            let port = free_port();
            let (tx, rx) = std::sync::mpsc::channel();
            assert!(start(&[port], 256, &prompting(port, Prompts::Imap), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false)))
                .is_empty());
            let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut heard = Vec::new();
            let mut buf = [0u8; 512];
            for said in sends {
                let n = s.read(&mut buf).unwrap();
                heard.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                s.write_all(said).unwrap();
            }
            let n = s.read(&mut buf).unwrap_or(0);
            let last = String::from_utf8_lossy(&buf[..n]).into_owned();
            drop(s);
            (heard, last, rx.recv_timeout(Duration::from_secs(5)).unwrap())
        };
        let list = "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN AUTH=LOGIN";
        // what fingerprintx reads: `* OK` first, then two lines, `* CAPABILITY` and its own tag
        let (heard, last, hit) = run(&[b"7FYWU8I4 CAPABILITY\r\n"]);
        assert!(heard[0].starts_with("* OK") && heard[0].contains(list), "{heard:?}");
        let answer: Vec<&str> = last.split("\r\n").collect();
        assert_eq!(answer[0], format!("* CAPABILITY {list}"));
        assert_eq!(answer[1], "7FYWU8I4 OK Pre-login capabilities listed, post-login capabilities have more.");
        assert_eq!(answer[2], "");
        assert_eq!(hit.sent, b"7FYWU8I4 CAPABILITY\r\n");
        // a client that asks first still hands over its login, then the connection ends
        let (heard, last, hit) = run(&[b"a1 capability\r\n", b"a2 LOGIN root 1234\r\n"]);
        assert!(heard[1].starts_with("* CAPABILITY ") && heard[1].contains("\r\na1 OK "), "{heard:?}");
        assert_eq!(last, "");
        assert_eq!(hit.sent, b"a1 capability\r\na2 LOGIN root 1234\r\n");
        // the login in the same packet is kept too
        let (_, last, hit) = run(&[b"a1 CAPABILITY\r\na2 LOGIN root 1234\r\n"]);
        assert!(last.starts_with("* CAPABILITY "), "{last:?}");
        assert_eq!(hit.sent, b"a1 CAPABILITY\r\na2 LOGIN root 1234\r\n");
        // anything else ends it at once, as before
        let (_, last, hit) = run(&[b"a1 LOGIN root 1234\r\n"]);
        assert_eq!(last, "");
        assert_eq!(hit.sent, b"a1 LOGIN root 1234\r\n");
    }

    #[test]
    fn imap_answers_only_a_well_formed_capability_and_repeats_its_greetings_list() {
        let ok = b"a1 OK Pre-login capabilities listed, post-login capabilities have more.\r\n";
        assert_eq!(imap_capability(b"X", b"a1 CAPABILITY\r\n").unwrap(), [&b"* CAPABILITY X\r\n"[..], ok].concat());
        assert_eq!(imap_capability(b"X", b"a1\tCapability\n").unwrap(), [&b"* CAPABILITY X\r\n"[..], ok].concat());
        let long = format!("{} CAPABILITY\r\n", "a".repeat(65));
        for said in [
            &b"CAPABILITY\r\n"[..],
            b"\r\n",
            b"a1 NOOP\r\n",
            b"a1 CAPABILITY now\r\n",
            b"+ CAPABILITY\r\n",
            b"a* CAPABILITY\r\n",
            b"a\"1 CAPABILITY\r\n",
            b"\x16\x03\x01 CAPABILITY\r\n",
            long.as_bytes(),
        ] {
            assert_eq!(imap_capability(b"X", said), None, "{}", String::from_utf8_lossy(said));
        }
        // nothing a tag can hold starts another line
        let answer = imap_capability(b"X", b"a]b. CAPABILITY\r\n").unwrap();
        assert_eq!(answer.iter().filter(|&&b| b == b'\n').count(), 2);

        assert_eq!(imap_capabilities(b"* OK [CAPABILITY IMAP4rev1 IDLE] ready\r\n"), b"IMAP4rev1 IDLE");
        assert_eq!(imap_capabilities(b"* OK IMAP4rev1 ready\r\n"), IMAP_CAPABILITIES);
        assert_eq!(imap_capabilities(b"* OK [CAPABILITY cut short\r\n"), IMAP_CAPABILITIES);
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn pop3_refuses_what_it_doesnt_know_and_takes_a_login() {
        let run = |sends: &[&[u8]]| {
            let port = free_port();
            let (tx, rx) = std::sync::mpsc::channel();
            assert!(start(&[port], 64, &prompting(port, Prompts::Pop3), move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false)))
                .is_empty());
            let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut heard = Vec::new();
            for said in sends {
                let mut buf = [0u8; 128];
                let n = s.read(&mut buf).unwrap();
                heard.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                s.write_all(said).unwrap();
            }
            if sends.len() == 1 {
                let mut buf = [0u8; 128];
                let n = s.read(&mut buf).unwrap();
                heard.push(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
            drop(s);
            (heard, rx.recv_timeout(Duration::from_secs(5)).unwrap())
        };
        // what fingerprintx does: the greeting must start +OK, the bogus command's answer -ERR
        let (heard, hit) = run(&[b"Not a command \r\n"]);
        assert!(heard[0].starts_with("+OK"), "{heard:?}");
        assert_eq!(heard[1], "-ERR Unknown command.\r\n");
        assert_eq!(hit.sent, b"Not a command \r\n");
        // a login still comes out whole, in any case
        for user in [&b"USER root\r\n"[..], b"user root\r\n"] {
            let (heard, hit) = run(&[user, b"PASS 1234\r\n"]);
            assert_eq!(heard[1], "+OK\r\n", "{heard:?}");
            assert_eq!(hit.sent, [user, b"PASS 1234\r\n"].concat());
        }
        // only the first word counts, and only for POP3
        assert_eq!(reply(Prompts::Pop3, b"+OK\r\n", b"USERNAME x\r\n"), b"-ERR Unknown command.\r\n");
        assert_eq!(reply(Prompts::Pop3, b"+OK Dovecot\r\n", b""), b"+OK Dovecot\r\n", "the greeting comes first");
        assert_eq!(reply(Prompts::Smtp, b"250 mail\r\n", b"Not a command\r\n"), b"250 mail\r\n");
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
