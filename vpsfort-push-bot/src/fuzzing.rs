//! What the fuzz targets in `fuzz/` run (`cargo +nightly fuzz run alert_text`, ...). Each
//! takes input the bot doesn't control: vpsfort's outbox files (log text attackers wrote
//! into), the admin's OpenPGP key file, the `SERVER_NAMES` setting. None of it may panic or
//! hang, and what leaves for the service keeps the bot's promises, checked here with rules of
//! their own rather than the code under test: no account address, no configured server
//! address or host name, messages within the service's limits.
//! `tests/fuzz_smoke.rs` runs the same functions on stable, so `cargo test` keeps them working.

use std::net::IpAddr;

use crate::outbox;
use crate::redact::{parse_domains, Pseudonyms};
use crate::seal::Recipient;
use crate::servers::ServerNames;

/// The servers of the fuzzed setup (documentation addresses only).
pub const SERVERS: &str = "xmpp=192.0.2.10,2001:db8::10,example.org; vpn=198.51.100.20; tg=203.0.113.30,relay.example.net";
const V4: &[&str] = &["192.0.2.10", "198.51.100.20", "203.0.113.30"];
const V6: &[&str] = &["2001:db8::10"];
const HOSTS: &[&str] = &["example.org", "relay.example.net"];
/// A fixed "now" for the key checks: Unix time in 2026.
pub const NOW: u32 = 1_780_000_000;

/// `s` from about `at` bytes on (a character boundary at or before it).
fn from(s: &str, at: usize) -> &str {
    let mut k = at.min(s.len());
    while !s.is_char_boundary(k) {
        k -= 1;
    }
    &s[k..]
}

/// The start of a long text, for an assertion message.
fn short(s: &str) -> String {
    let mut t: String = s.chars().take(300).collect();
    if t.len() < s.len() {
        t.push('…');
    }
    t
}

/// What XMPP forbids in an account's local part (RFC 7622), besides blanks and controls.
fn local_char(c: char) -> bool {
    !c.is_whitespace() && !c.is_control() && !"\"&'/:<>@".contains(c)
}

fn domain_char(c: char) -> bool {
    c.is_alphanumeric() || c == '.' || c == '-'
}

fn host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// No `local@domain` is left: before every `@` there is no account name (account characters
/// back to a blank, without the brackets that open it), or after it no domain with a letter
/// or digit.
fn assert_no_accounts(out: &str) {
    for (i, _) in out.match_indices('@') {
        let local: String = out[..i].chars().rev().take_while(|&c| local_char(c)).collect::<Vec<_>>().into_iter().rev().collect();
        let name = local.trim_start_matches(['(', '[', '{']);
        let domain: String = out[i + 1..].chars().take_while(|&c| domain_char(c)).collect();
        assert!(
            !(!name.is_empty() && domain.trim_end_matches(['.', '-']).chars().any(char::is_alphanumeric)),
            "an address is left at byte {i}: {:?}",
            short(from(out, i.saturating_sub(40)))
        );
    }
    for (i, m) in out.match_indices("ejabberd:") {
        let rest = &out[i + m.len()..];
        let name: String = rest.chars().take_while(|&c| local_char(c)).collect();
        let name = name.trim_start_matches(['(', '[', '{']).trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}']);
        assert!(
            name.is_empty() || crate::redact::pseudonym_after_openers(rest).is_some(),
            "an ejabberd: name is left at byte {i}: {:?}",
            short(from(out, i))
        );
    }
}

/// The maximal runs of ASCII bytes in `class`.
fn runs(text: &str, class: impl Fn(u8) -> bool) -> Vec<&str> {
    let b = text.as_bytes();
    let mut v = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !class(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && class(b[i]) {
            i += 1;
        }
        v.push(&text[start..i]);
    }
    v
}

/// None of `v4`, `v6` or `hosts` is left. In a run of address characters: a run that is a
/// valid address must not be one of them (nor spell one of the IPv4 ones in its last 32
/// bits); in a run that is none, no piece between separators may be one. A host name must
/// not be left on its own (not part of a longer name).
fn assert_no_servers(out: &str, v4: &[IpAddr], v6: &[IpAddr], hosts: &[String]) {
    let ours = |c: &str| {
        c.parse::<IpAddr>()
            .ok()
            .map(|ip| match ip {
                IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
                v4 => v4,
            })
            .filter(|ip| v6.contains(ip) || v4.contains(ip))
    };
    let check = |run: &str| {
        let whole = run.trim_matches('.');
        if whole.parse::<IpAddr>().is_ok() {
            let tail = whole.rsplit_once(':').map_or("", |(_, t)| t);
            assert!(ours(whole).is_none() && ours(tail).is_none(), "server address in {whole} is left: {:?}", short(out));
            return;
        }
        let b = run.as_bytes();
        let sep = |k: usize| b[k] == b':' || b[k] == b'.';
        for start in (0..b.len()).filter(|&k| k == 0 || sep(k - 1)) {
            for end in (start + 1..=b.len().min(start + 45)).filter(|&k| k == b.len() || sep(k)) {
                assert!(ours(&run[start..end]).is_none(), "server address {} is left: {:?}", &run[start..end], short(out));
            }
        }
    };
    for run in runs(out, |c| c.is_ascii_hexdigit() || c == b':' || c == b'.').into_iter().filter(|r| r.contains(':')) {
        check(run);
    }
    for run in runs(out, |c| c.is_ascii_digit() || c == b'.') {
        check(run);
    }
    let lower = out.to_ascii_lowercase();
    for host in hosts {
        for (k, _) in lower.match_indices(host.as_str()) {
            let before = lower[..k].chars().next_back();
            let mut after = lower[k + host.len()..].chars();
            let (a1, a2) = (after.next(), after.next());
            let whole_left = before.is_none_or(|c| !host_char(c) || c == '.');
            let whole_right = a1.is_none_or(|c| !host_char(c)) && !(a1 == Some('.') && a2.is_some_and(host_char));
            assert!(!(whole_left && whole_right), "host name {host} is left at byte {k}: {:?}", short(from(out, k)));
        }
    }
}

fn setup() -> (Pseudonyms, ServerNames) {
    (Pseudonyms::new([7; 32], parse_domains("example.org")), ServerNames::parse(SERVERS).expect("the fuzzed setup"))
}

/// An outbox file, as vpsfort writes it (or anything else): what the bot makes of it for
/// the service, and the promises about it: nothing of the accounts or servers left, a title
/// and bodies within the limits, no control characters but line breaks and tabs.
pub fn alert(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let body = outbox::parse_message(&text).unwrap_or_else(|| text.to_string());
    let (names, servers) = setup();
    let once = crate::redact::sanitize(&names, &servers, &body);
    assert_eq!(crate::redact::sanitize(&names, &servers, &once), once, "a second pass changes it: something was left to replace");
    assert_no_accounts(&once);
    let v4: Vec<IpAddr> = V4.iter().map(|a| a.parse().unwrap()).collect();
    let v6: Vec<IpAddr> = V6.iter().map(|a| a.parse().unwrap()).collect();
    let hosts: Vec<String> = HOSTS.iter().map(|h| h.to_string()).collect();
    assert_no_servers(&once, &v4, &v6, &hosts);
    let (subject, bodies) = crate::bot::pieces(&once);
    assert!(!subject.is_empty() && subject.chars().count() <= 250 && !subject.contains('\n'));
    assert!(!bodies.is_empty(), "an alert always gives a message");
    for b in &bodies {
        assert!(b.chars().count() <= crate::push::MESSAGE_LIMIT, "{} characters", b.chars().count());
        assert!(b.chars().all(|c| c == '\n' || c == '\t' || !c.is_control()), "a control character: {:?}", short(b));
    }
    let _ = crate::push::Priority::of(&once);
}

/// The admin's key file: whatever is taken as a key must also encrypt.
pub fn openpgp_key(data: &[u8]) {
    if let Ok(r) = Recipient::parse(data, NOW) {
        assert_eq!(r.fingerprint.len(), 40, "{}", r.fingerprint);
        let _ = r.pretty_fingerprint();
        r.check(NOW).expect("taken at NOW, so usable at NOW");
        let sealed = r.seal(b"report".to_vec(), NOW).expect("a key that was taken must encrypt");
        assert!(!sealed.windows(6).any(|w| w == b"report"), "nothing in clear");
        let _ = r.check(u32::MAX);
    }
}

/// `SERVER_NAMES` and a text, separated by the first NUL byte: a list that is taken works on
/// any text, and leaves none of its addresses or names in it.
pub fn server_names(data: &[u8]) {
    let (spec, text) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &b""[..]),
    };
    let (spec, text) = (String::from_utf8_lossy(spec), String::from_utf8_lossy(text));
    let Ok(servers) = ServerNames::parse(&spec) else { return };
    let once = servers.replace(&text);
    // what the list names, read the plain way
    let (mut v4, mut v6, mut hosts) = (Vec::new(), Vec::new(), Vec::new());
    for entry in spec.split([';', '\n']) {
        let Some((_, items)) = entry.split_once('=') else { continue };
        for item in items.split([',', ' ']).map(str::trim).filter(|i| !i.is_empty()) {
            match item.trim_matches(['[', ']']).parse::<IpAddr>() {
                Ok(IpAddr::V6(a)) if a.to_ipv4_mapped().is_none() => v6.push(IpAddr::V6(a)),
                Ok(IpAddr::V6(a)) => v4.push(IpAddr::V4(a.to_ipv4_mapped().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED))),
                Ok(ip) => v4.push(ip),
                Err(_) => hosts.push(item.trim_matches('.').to_ascii_lowercase()),
            }
        }
    }
    // A node id may be a label of a listed name ("tg=...; vpn=tg.example.com"): replacing
    // one name can then make another. Not a leak, but no fixed point either, so those lists
    // are checked for crashes only.
    let nodes: Vec<String> =
        spec.split([';', '\n']).filter_map(|e| e.split_once('=')).map(|(n, _)| n.trim().to_ascii_lowercase()).collect();
    if hosts.iter().any(|h| nodes.iter().any(|n| h.contains(n.as_str()))) {
        return;
    }
    assert_eq!(servers.replace(&once), once, "a second pass changes it");
    assert_no_servers(&once, &v4, &v6, &hosts);
}
