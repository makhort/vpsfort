//! Tripwire listeners (`[ports] honeypot`): vpsfort accepts TCP connections on ports nobody
//! legitimate uses, never sends a byte, and closes each after reading what the sender says
//! first (`[ports] honeypot_capture` bytes, within [`CAPTURE_WAIT`]; 0 closes at once). A
//! connection is only accepted after the TCP handshake, which a forged source address can't
//! complete (the server's SYN-ACK goes to the real owner of the address), so unlike a blocked
//! SYN in the firewall log, a hit here names its sender for certain; what it sent (a Telnet
//! login, an HTTP request, a protocol banner) says what it was after, and goes into the
//! evidence and the abuse report.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// One completed handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub ip: IpAddr,
    pub port: u16,
    /// What the sender wrote first, at most the configured capture (empty: nothing within
    /// [`CAPTURE_WAIT`], or capturing is off).
    pub sent: Vec<u8>,
}

/// A source is reported once a minute per port, however often it connects.
const REPEAT_AFTER: Duration = Duration::from_secs(60);
/// Sources remembered per port for that (real addresses only, but a botnet has many).
const MAX_SOURCES: usize = 10_000;
/// How long a connection is held for the sender's first bytes. Scanners that complete a
/// handshake write at once (Mirai's Telnet login, an HTTP request) or wait for a banner
/// that never comes.
pub const CAPTURE_WAIT: Duration = Duration::from_secs(3);
/// The most `[ports] honeypot_capture` can ask for.
pub const MAX_CAPTURE: usize = 4096;
/// Connections read at the same time (one thread each); beyond that a connection is closed
/// at once, as with capturing off, so a flood can't hold threads or sockets.
const MAX_READING: usize = 64;
/// Characters of the captured bytes shown in an evidence line.
const SHOWN: usize = 120;

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

/// The captured bytes as one line of plain ASCII: printable characters as they are, `\r`,
/// `\n`, `\t`, `\"` and `\\` escaped, anything else as `\xNN`, cut to [`SHOWN`] characters.
pub fn describe(sent: &[u8]) -> String {
    if sent.is_empty() {
        return "sent nothing".to_string();
    }
    let mut text = String::new();
    for &b in sent {
        let piece = match b {
            b'\r' => "\\r".to_string(),
            b'\n' => "\\n".to_string(),
            b'\t' => "\\t".to_string(),
            b'"' => "\\\"".to_string(),
            b'\\' => "\\\\".to_string(),
            0x20..=0x7e => (b as char).to_string(),
            _ => format!("\\x{b:02x}"),
        };
        if text.len() + piece.len() > SHOWN {
            text.push('…');
            break;
        }
        text.push_str(&piece);
    }
    format!("sent {} bytes: \"{text}\"", sent.len())
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
            // nothing is ever sent; with capturing off (or too many connections being read
            // already) the connection is closed before anything else
            if capture == 0 || reading.load(Ordering::Relaxed) >= MAX_READING {
                drop(s);
                if !on_hit(Hit { ip, port, sent: vec![] }) {
                    return;
                }
                continue;
            }
            reading.fetch_add(1, Ordering::Relaxed);
            let (on_hit, reading, stop) = (Arc::clone(&on_hit), Arc::clone(&reading), Arc::clone(&stop));
            thread::spawn(move || {
                let sent = read_first(s, capture);
                reading.fetch_sub(1, Ordering::Relaxed);
                if !on_hit(Hit { ip, port, sent }) {
                    stop.store(true, Ordering::Relaxed);
                }
            });
        }
    });
}

/// Starts a listener for each port, reading up to `capture` bytes of each connection (0:
/// none); `on_hit` is called from their threads (false stops them). Returns the ports that
/// could not be opened, with why.
pub fn start(ports: &[u16], capture: usize, on_hit: impl Fn(Hit) -> bool + Send + Sync + 'static, stop: Arc<AtomicBool>) -> Vec<String> {
    let on_hit: Arc<dyn Fn(Hit) -> bool + Send + Sync> = Arc::new(on_hit);
    let reading = Arc::new(AtomicUsize::new(0));
    let capture = capture.min(MAX_CAPTURE);
    let mut errors = Vec::new();
    for &port in ports {
        match bind(port) {
            Ok(listeners) => {
                for l in listeners {
                    serve(l, port, capture, Arc::clone(&on_hit), Arc::clone(&reading), Arc::clone(&stop));
                }
            }
            Err(e) => errors.push(format!("honeypot port {port}/tcp: cannot listen: {e}")),
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    /// Needs to bind 127.0.0.1 (run outside a sandbox that forbids it).
    #[test]
    fn a_connection_is_a_hit_once_a_minute() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        let errors = start(&[port], 0, move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false)));
        assert!(errors.is_empty(), "{errors:?}");
        for _ in 0..3 {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            // closed by the other side without a word
            let mut buf = [0u8; 8];
            assert_eq!(s.read(&mut buf).unwrap_or(0), 0);
        }
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(hit, Hit { ip: "127.0.0.1".parse().unwrap(), port, sent: vec![] });
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "repeats within a minute are one hit");
        let taken = start(&[port], 0, |_| true, Arc::new(AtomicBool::new(false)));
        assert!(taken[0].contains("cannot listen"), "{taken:?}");
    }

    /// Needs to bind 127.0.0.1 too.
    #[test]
    fn what_the_sender_wrote_first_is_captured_and_nothing_is_sent() {
        let port = free_port();
        let (tx, rx) = std::sync::mpsc::channel();
        let errors = start(&[port], 16, move |h| tx.send(h).is_ok(), Arc::new(AtomicBool::new(false)));
        assert!(errors.is_empty(), "{errors:?}");
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        std::io::Write::write_all(&mut s, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut buf = [0u8; 8];
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "closed without a word once the capture is full");
        let hit = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(hit.sent, b"GET / HTTP/1.1\r\n", "at most the capture");
        assert_eq!(describe(&hit.sent), "sent 16 bytes: \"GET / HTTP/1.1\\r\\n\"");
    }

    #[test]
    fn captured_bytes_are_shown_as_plain_ascii() {
        assert_eq!(describe(b""), "sent nothing");
        assert_eq!(describe(b"root\r\n\x1b[2J\"q\\\0"), "sent 14 bytes: \"root\\r\\n\\x1b[2J\\\"q\\\\\\x00\"");
        let long = describe(&[b'A'; 500]);
        assert!(long.starts_with("sent 500 bytes: \"AAAA") && long.ends_with("A…\""), "{long}");
        assert!(long.chars().count() < 150, "{long}");
        // nothing a terminal or a report could act on survives
        assert!(describe(b"\x1b]52;c;ZXZpbA==\x07\xff\n").chars().all(|c| !c.is_control()));
    }
}
