//! A link to one address's page that needs no login: for handing the evidence about an
//! address to its hosting provider. The link carries a token: the address and an expiry,
//! signed with the web key (or, on a console without one, a key made at start). It opens
//! nothing but that address's data (`/api/v1/address/<net>?share=<token>`), stays read-only
//! like everything here, and ends when it expires: at most a week.
//!
//! Whoever holds the link is a stranger to this cluster: the page shows what the weekly
//! abuse report would, no more. Account names, users' addresses and the admin's notes are
//! withheld ([`withhold`], the abuse report's own wording), alerts about the host and what
//! it trusts or allows are left out (`aggregate::shared`), the nodes are numbered, not named,
//! and one address may ask a few times a minute ([`Pace`]): guessing a token (128 bits) is
//! hopeless anyway, and vpsfort bans an address that keeps trying (the refusals are logged
//! for it).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::time::{Micros, SEC};

/// A link lasts at most this long.
pub const MAX_HOURS: u64 = 7 * 24;

/// A link made, as the account page lists it: nothing in it opens the page (the token's
/// signature is not kept, only its first bytes as the id).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub id: String,
    pub net: String,
    pub by: String,
    pub made: Micros,
    pub expires: Micros,
    /// Ended early by an admin: refused from then on.
    #[serde(default)]
    pub ended: bool,
}

/// Links remembered at most.
const MAX_LINKS: usize = 1000;

pub struct Share {
    key: [u8; 32],
    /// The links made (in `STATE_DIR/share-links.json` across restarts), so an admin can see
    /// them and end one early.
    links: Mutex<Vec<Link>>,
    path: Option<PathBuf>,
}

impl Share {
    pub fn new(web_key: Option<[u8; 32]>, dir: Option<&Path>) -> Share {
        let key = web_key.unwrap_or_else(|| {
            let mut k = [0u8; 32];
            let _ = crate::wire::getrandom(&mut k);
            k
        });
        let path = dir.map(|d| d.join("share-links.json"));
        let links: Vec<Link> =
            path.as_deref().and_then(crate::store::load).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
        Share { key, links: Mutex::new(links), path }
    }

    fn save(&self, links: &[Link]) {
        if let Some(p) = &self.path {
            if let Ok(v) = serde_json::to_value(links) {
                crate::store::save(p, &v);
            }
        }
    }

    /// The links made that haven't expired, newest first.
    pub fn list(&self, now: Micros) -> Vec<Link> {
        let mut links = self.links.lock().unwrap_or_else(|e| e.into_inner());
        links.retain(|l| l.expires > now);
        let mut out = links.clone();
        out.sort_by_key(|l| std::cmp::Reverse(l.made));
        out
    }

    /// Ends a link early (by its id); false when there is no such link.
    pub fn end(&self, id: &str) -> bool {
        let mut links = self.links.lock().unwrap_or_else(|e| e.into_inner());
        let Some(l) = links.iter_mut().find(|l| l.id == id && !l.ended) else { return false };
        l.ended = true;
        self.save(&links);
        true
    }

    /// A token's id: the first bytes of its signature.
    fn id_of(token: &str) -> &str {
        let mac = token.split_once('.').map_or(token, |(_, m)| m);
        &mac[..mac.len().min(12)]
    }

    fn mac(&self, net: &str, expires: i64) -> String {
        let mut m = Hmac::<Sha256>::new_from_slice(&self.key).expect("any key length");
        m.update(b"share\0");
        m.update(net.as_bytes());
        m.update(b"\0");
        m.update(&expires.to_be_bytes());
        crate::wire::hex(&m.finalize().into_bytes()[..16])
    }

    /// A token for `net`'s page, good for `hours` (capped at a week) from `now`, made by
    /// admin `by` (remembered, so it can be listed and ended).
    pub fn token(&self, net: &str, hours: u64, now: Micros, by: &str) -> (String, Micros) {
        let expires = now / SEC + (hours.clamp(1, MAX_HOURS) * 3600) as i64;
        let token = format!("{expires}.{}", self.mac(net, expires));
        let mut links = self.links.lock().unwrap_or_else(|e| e.into_inner());
        links.retain(|l| l.expires > now);
        if links.len() >= MAX_LINKS {
            links.remove(0);
        }
        links.push(Link {
            id: Share::id_of(&token).to_string(),
            net: net.to_string(),
            by: by.to_string(),
            made: now,
            expires: expires * SEC,
            ended: false,
        });
        self.save(&links);
        (token, expires * SEC)
    }

    /// Whether `token` opens `net`'s page now.
    pub fn check(&self, net: &str, token: &str, now: Micros) -> Result<(), &'static str> {
        if token.len() > 64 || net.len() > 64 {
            return Err("not a share link");
        }
        let Some((expires, mac)) = token.split_once('.') else { return Err("not a share link") };
        let Ok(expires) = expires.parse::<i64>() else { return Err("not a share link") };
        if !crate::auth::same(self.mac(net, expires).as_bytes(), mac.as_bytes()) {
            return Err("not a share link of this console");
        }
        if expires * SEC < now {
            return Err("this share link has expired");
        }
        if self.links.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|l| l.ended && l.id == Share::id_of(token)) {
            return Err("this share link was ended");
        }
        Ok(())
    }
}

/// Requests to the shared endpoint from one address within a minute; beyond, 429.
pub const PACE: u32 = 30;
const PACE_WINDOW: Duration = Duration::from_secs(60);
const PACE_TRACKED: usize = 10_000;

/// How often one address may ask for a shared page: a link's holder opening it and letting
/// it refresh is a few requests a minute; a loop (or a token guesser) is not.
#[derive(Default)]
pub struct Pace {
    seen: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl Pace {
    /// Counts a request from `ip`; `Err(wait)` when it is over the pace, with how long until
    /// the window ends.
    pub fn allow(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.len() >= PACE_TRACKED && !seen.contains_key(&ip) {
            seen.retain(|_, (since, _)| now.duration_since(*since) < PACE_WINDOW);
        }
        let e = seen.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= PACE_WINDOW {
            *e = (now, 0);
        }
        e.1 += 1;
        if e.1 > PACE {
            return Err(PACE_WINDOW.saturating_sub(now.duration_since(e.0)));
        }
        Ok(())
    }
}

/// A text as a stranger may see it: an evidence line (`10-12 14:03:11 failed password for
/// alice`, with or without the stamp, or a network member's `192.0.2.9 ...` before it), a
/// ban's reason or message. Account names are withheld as vpsfort's weekly abuse report
/// withholds them (its wording, so the two agree), anything with an `@` becomes `[account]`,
/// internal points (` (+25)`) go, and so do control characters.
pub fn withhold(text: &str) -> String {
    let text: String = text.chars().filter(|c| !c.is_control()).collect();
    // "MM-DD HH:MM:SS rest", as evidence lines are stamped
    let mut parts = text.splitn(3, ' ');
    if let (Some(d), Some(t), Some(rest)) = (parts.next(), parts.next(), parts.next()) {
        let stamp = d.len() == 5 && d.as_bytes()[2] == b'-' && t.len() == 8 && t.as_bytes()[2] == b':';
        if stamp {
            return format!("{d} {t} {}", withhold_line(rest));
        }
    }
    withhold_line(&text)
}

fn withhold_line(text: &str) -> String {
    // a network ban's lines name the member first
    if let Some((ip, rest)) = text.split_once(' ').filter(|(ip, _)| ip.parse::<IpAddr>().is_ok()) {
        return format!("{ip} {}", withhold_line(rest));
    }
    let cut = |s: &str, at: &str| s.find(at).map(|i| s[..i].to_string());
    let t = if text.contains("canary account") {
        if text.starts_with("login to canary account") {
            "logged in to a decoy account (credentials that are never used legitimately)".to_string()
        } else if text.starts_with("registration of") {
            "tried to register a decoy account name".to_string()
        } else {
            "login attempt on a decoy account (password guessing)".to_string()
        }
    } else if let Some(rest) = text.strip_prefix("failed ") {
        match rest.split_once(" for invalid user ") {
            Some((method, user)) => format!("failed {method} login as non-existent user {user}"),
            None => format!("failed {} login (account name withheld)", rest.split(" for ").next().unwrap_or(rest)),
        }
    } else if text.starts_with("user ") && text.contains(" not allowed") {
        "login attempt as a user that may not log in (name withheld)".to_string()
    } else if text.starts_with("gave up authenticating as ") {
        "gave up authenticating (account name withheld)".to_string()
    } else if text.starts_with("nextcloud login failed for ") {
        "failed Nextcloud login (account name withheld)".to_string()
    } else if text.starts_with("registered account ") {
        "registered an account".to_string()
    } else if let Some(rest) = text.strip_prefix("login as ") {
        // an alert's wording: "login as root from 203.0.113.9 failed (vsftpd) for eve"
        format!(
            "login (account name withheld){}",
            rest.find(" from ").map(|i| cut(&rest[i..], " for ").unwrap_or(rest[i..].to_string())).unwrap_or_default()
        )
    } else if let Some(c) = cut(text, " (+") {
        c
    } else {
        text.to_string()
    };
    let words: Vec<String> = t.split(' ').map(|w| if w.contains('@') { "[account]".to_string() } else { w.to_string() }).collect();
    words.join(" ").chars().take(300).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strangers_see_what_the_abuse_report_shows() {
        assert_eq!(withhold("10-12 14:03:11 failed password for alice"), "10-12 14:03:11 failed password login (account name withheld)");
        assert_eq!(withhold("failed publickey for invalid user oracle"), "failed publickey login as non-existent user oracle");
        assert_eq!(withhold("192.0.2.9 failed password for alice"), "192.0.2.9 failed password login (account name withheld)");
        assert_eq!(
            withhold("user root not allowed because not listed in AllowUsers"),
            "login attempt as a user that may not log in (name withheld)"
        );
        assert_eq!(withhold("login attempt on canary account test"), "login attempt on a decoy account (password guessing)");
        assert_eq!(withhold("xmpp auth failed for alice@example.org (+25)"), "xmpp auth failed for [account]");
        assert_eq!(
            withhold("login as root from 203.0.113.9 failed (vsftpd) for eve"),
            "login (account name withheld) from 203.0.113.9 failed (vsftpd)"
        );
        assert_eq!(withhold("tripwire block TCP/23\u{1b}[0m"), "tripwire block TCP/23[0m", "no control characters");
        assert_eq!(
            withhold("ban 203.0.113.9 for 1h (offence #1): burst score fast=100 slow=100 [5x ssh_auth_fail]"),
            "ban 203.0.113.9 for 1h (offence #1): burst score fast=100 slow=100 [5x ssh_auth_fail]"
        );
    }

    #[test]
    fn a_few_requests_a_minute_per_address() {
        let p = Pace::default();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let other: IpAddr = "203.0.113.10".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..PACE {
            assert_eq!(p.allow(ip, t0), Ok(()));
        }
        let wait = p.allow(ip, t0 + Duration::from_secs(10)).unwrap_err();
        assert!(wait > Duration::from_secs(40) && wait <= Duration::from_secs(50), "{wait:?}");
        assert_eq!(p.allow(other, t0), Ok(()), "another address isn't held back");
        assert_eq!(p.allow(ip, t0 + Duration::from_secs(61)), Ok(()), "the next minute");
    }

    #[test]
    fn a_token_opens_its_address_until_it_expires() {
        let s = Share::new(Some([7u8; 32]), None);
        let now = 1_793_300_000 * SEC;
        let (t, expires) = s.token("192.0.2.1", 2, now, "admin");
        assert_eq!(expires, now + 2 * 3600 * SEC);
        assert_eq!(s.check("192.0.2.1", &t, now), Ok(()));
        assert_eq!(s.check("192.0.2.1", &t, now + 3 * 3600 * SEC), Err("this share link has expired"));
        assert!(s.check("192.0.2.2", &t, now).is_err(), "another address");
        assert!(Share::new(Some([8u8; 32]), None).check("192.0.2.1", &t, now).is_err(), "another console");
        let mut forged = t.clone();
        forged.replace_range(..1, "9");
        assert!(s.check("192.0.2.1", &forged, now).is_err(), "a later expiry is a different signature");
        assert!(s.check("192.0.2.1", "x", now).is_err());
        let (week, _) = s.token("192.0.2.1", 1000, now, "admin");
        assert_eq!(s.check("192.0.2.1", &week, now + (MAX_HOURS as i64) * 3600 * SEC - SEC), Ok(()), "capped at a week");
        assert!(s.check("192.0.2.1", &week, now + (MAX_HOURS as i64 + 1) * 3600 * SEC).is_err());
        assert_ne!(
            Share::new(None, None).token("a", 1, now, "admin").0,
            Share::new(None, None).token("a", 1, now, "admin").0,
            "no web key: a random one"
        );
        // listed, ended early, and kept across a restart
        let d = std::env::temp_dir().join(format!("lgw-share-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let s = Share::new(Some([7u8; 32]), Some(&d));
        let (t, _) = s.token("192.0.2.1", 24, now, "alice");
        let (t2, _) = s.token("192.0.2.2", 1, now + SEC, "bob");
        let list = s.list(now);
        assert_eq!(list.len(), 2);
        assert_eq!((list[0].net.as_str(), list[0].by.as_str(), list[0].ended), ("192.0.2.2", "bob", false));
        assert!(s.check("192.0.2.1", &t, now).is_ok());
        assert!(s.end(&list[1].id));
        assert!(!s.end(&list[1].id), "ended once");
        assert_eq!(s.check("192.0.2.1", &t, now), Err("this share link was ended"));
        assert!(s.check("192.0.2.2", &t2, now).is_ok(), "the other link still works");
        let again = Share::new(Some([7u8; 32]), Some(&d));
        assert_eq!(again.check("192.0.2.1", &t, now), Err("this share link was ended"), "read back");
        assert_eq!(again.list(now + 2 * 3600 * SEC).len(), 1, "the expired one is gone from the list");
        let _ = std::fs::remove_dir_all(&d);
    }
}
