//! Proof of work before a login: the page must find a nonce such that
//! `SHA-256(challenge ‖ nonce)` starts with `difficulty` zero bits. A guess then costs the
//! guesser a second or so of CPU, not the console (checking is one hash); the lockouts in
//! `auth.rs` stay alongside. The difficulty ramps with failures: the address's, the account's
//! and everyone's, so a distributed guesser (many addresses, one account) pays more with every
//! try, and the admin who mistyped once barely notices.
//!
//! A challenge is 16 random bytes, the difficulty, when it expires, and an HMAC under a key
//! made at start (a restart only means a fresh challenge) over those and the address and
//! account it was issued to: one solved for another account, or from another address, is not
//! this one's. Each works once: the salts used are kept until their challenge would have
//! expired anyway. Nothing is kept for a challenge handed out and never used, so asking for
//! them costs the console nothing (a flood of `GET /api/v1/session` can't fill anything or
//! cancel other admins' challenges).

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::time::{self, Micros, SEC};

/// A challenge is good for this long (the page solves while the admin types).
const VALID: Micros = 5 * 60 * SEC;
/// Salts used lately, remembered against replays until they expire; beyond this the oldest
/// go (each was solved: a flood of solved logins is the lockouts' business).
const MAX_USED: usize = 50_000;
/// Never beyond this: 2^28 hashes is minutes on a phone.
pub const MAX_DIFFICULTY: u8 = 28;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Challenge {
    /// 16 random bytes, hex.
    pub salt: String,
    pub difficulty: u8,
    /// Microseconds since the epoch.
    pub expires: Micros,
    /// HMAC-SHA-256 of the three, hex.
    pub mac: String,
}

/// What the admin sends back: the challenge and the nonce found.
#[derive(Clone, Debug, Deserialize)]
pub struct Answer {
    pub salt: String,
    pub difficulty: u8,
    pub expires: Micros,
    pub mac: String,
    pub nonce: String,
}

/// The salts used: in order of expiry, and as a set.
#[derive(Default)]
struct Used {
    order: VecDeque<(Micros, String)>,
    set: HashSet<String>,
}

pub struct Work {
    /// The base difficulty (`LOGIN_WORK`); 0: no proof of work.
    pub base: u8,
    key: [u8; 32],
    /// Salts used, oldest first, with when their challenge expires (then they are forgotten).
    used: Mutex<Used>,
}

/// Whether `hash` starts with `bits` zero bits.
fn leading_zero_bits(hash: &[u8], bits: u8) -> bool {
    let mut left = u32::from(bits);
    for b in hash {
        if left == 0 {
            return true;
        }
        if left >= 8 {
            if *b != 0 {
                return false;
            }
            left -= 8;
        } else {
            return b >> (8 - left) == 0;
        }
    }
    left == 0
}

impl Work {
    pub fn new(base: u8) -> Self {
        let mut key = [0u8; 32];
        // without randomness the console doesn't start anyway (sessions need it)
        let _ = crate::wire::getrandom(&mut key);
        Work { base: base.min(MAX_DIFFICULTY), key, used: Mutex::default() }
    }

    pub fn enabled(&self) -> bool {
        self.base > 0
    }

    /// The challenge's MAC, over what it is and whom it is for.
    fn mac(&self, salt: &str, difficulty: u8, expires: Micros, ip: IpAddr, user: &str) -> String {
        let mut m = Hmac::<Sha256>::new_from_slice(&self.key).expect("any key length");
        m.update(salt.as_bytes());
        m.update(&[difficulty]);
        m.update(&expires.to_be_bytes());
        m.update(ip.to_string().as_bytes());
        m.update(&[0]);
        m.update(user.as_bytes());
        crate::wire::hex(&m.finalize().into_bytes())
    }

    /// The difficulty for a login attempt, from the base and the failures lately: the
    /// address's (each one adds a bit, up to 6: 64× the work), the account's from anywhere (one
    /// bit per 3, up to 4), and everyone's in the window (one bit per 50, up to 3).
    pub fn difficulty(&self, ip_failures: u32, account_failures: u32, all_failures: u32) -> u8 {
        if self.base == 0 {
            return 0;
        }
        let extra = ip_failures.min(6) + (account_failures / 3).min(4) + (all_failures / 50).min(3);
        (u32::from(self.base) + extra).min(u32::from(MAX_DIFFICULTY)) as u8
    }

    /// A new challenge at `difficulty` for a login from `ip` as `user` ("" is "admin", as the
    /// login takes it).
    pub fn issue(&self, difficulty: u8, ip: IpAddr, user: &str) -> Challenge {
        let mut raw = [0u8; 16];
        let _ = crate::wire::getrandom(&mut raw);
        let salt = crate::wire::hex(&raw);
        let expires = time::now() + VALID;
        Challenge { mac: self.mac(&salt, difficulty, expires, ip, user), salt, difficulty, expires }
    }

    /// Checks an answer from `ip` for `user`: issued to them by this console, not expired, not
    /// used before, and solved at least at `min_difficulty` (the difficulty the attempt
    /// deserves now: a challenge issued easier, before the failures that raised it, isn't
    /// enough). Uses the challenge up.
    pub fn verify(&self, a: &Answer, min_difficulty: u8, ip: IpAddr, user: &str) -> Result<(), &'static str> {
        if !self.enabled() {
            return Ok(());
        }
        if a.salt.len() != 32 || a.nonce.len() > 64 || a.mac.len() != 64 {
            return Err("no proof of work");
        }
        if !crate::auth::same(self.mac(&a.salt, a.difficulty, a.expires, ip, user).as_bytes(), a.mac.as_bytes()) {
            return Err("the proof of work is not this console's, or not for this account and address");
        }
        if a.expires < time::now() {
            return Err("the proof of work has expired: try again");
        }
        if a.difficulty < min_difficulty {
            return Err("more work is needed now: try again");
        }
        let mut h = Sha256::new();
        h.update(a.salt.as_bytes());
        h.update(a.nonce.as_bytes());
        if !leading_zero_bits(&h.finalize(), a.difficulty) {
            return Err("the proof of work is wrong");
        }
        // last: a wrong answer doesn't use the challenge up
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        let now = time::now();
        while used.order.front().is_some_and(|(e, _)| *e < now || used.order.len() > MAX_USED) {
            let (_, old) = used.order.pop_front().expect("not empty");
            used.set.remove(&old);
        }
        if !used.set.insert(a.salt.clone()) {
            return Err("the proof of work was used already: try again");
        }
        used.order.push_back((a.expires, a.salt.clone()));
        Ok(())
    }
}

/// Solves a challenge (the tests, and `vpsfort-web check` to time the difficulty).
pub fn solve(salt: &str, difficulty: u8) -> String {
    for n in 0u64.. {
        let nonce = n.to_string();
        let mut h = Sha256::new();
        h.update(salt.as_bytes());
        h.update(nonce.as_bytes());
        if leading_zero_bits(&h.finalize(), difficulty) {
            return nonce;
        }
    }
    unreachable!()
}

/// How long one solve takes here, for `check`.
pub fn time_solve(difficulty: u8) -> Duration {
    let start = Instant::now();
    solve("timing", difficulty);
    start.elapsed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(c: &Challenge, nonce: &str) -> Answer {
        Answer { salt: c.salt.clone(), difficulty: c.difficulty, expires: c.expires, mac: c.mac.clone(), nonce: nonce.into() }
    }

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

    #[test]
    fn solved_once() {
        let w = Work::new(8);
        let c = w.issue(8, IP, "admin");
        let nonce = solve(&c.salt, 8);
        // a nonce that doesn't solve it: picked by checking, since one in 256 would by chance
        let solves = |n: &str| {
            let mut h = Sha256::new();
            h.update(c.salt.as_bytes());
            h.update(n.as_bytes());
            leading_zero_bits(&h.finalize(), 8)
        };
        let wrong = (0u32..).map(|n| format!("x{n}")).find(|n| !solves(n)).unwrap();
        assert_eq!(w.verify(&answer(&c, &wrong), 8, IP, "admin"), Err("the proof of work is wrong"));
        assert_eq!(w.verify(&answer(&c, &nonce), 8, IP, "admin"), Ok(()));
        assert_eq!(w.verify(&answer(&c, &nonce), 8, IP, "admin"), Err("the proof of work was used already: try again"));
        // forged, expired, too easy, another console's
        let c2 = w.issue(8, IP, "admin");
        let n2 = solve(&c2.salt, 8);
        let mut easy = answer(&c2, &n2);
        easy.difficulty = 2;
        assert!(w.verify(&easy, 8, IP, "admin").unwrap_err().contains("not this console's"), "the difficulty is signed");
        assert_eq!(w.verify(&answer(&c2, &n2), 12, IP, "admin"), Err("more work is needed now: try again"));
        let mut old = w.issue(8, IP, "admin");
        old.expires = 1;
        old.mac = w.mac(&old.salt, 8, 1, IP, "admin");
        assert!(w.verify(&answer(&old, &solve(&old.salt, 8)), 8, IP, "admin").unwrap_err().contains("expired"));
        assert!(Work::new(8).verify(&answer(&c2, &n2), 8, IP, "admin").unwrap_err().contains("not this console's"));
        assert_eq!(Work::new(0).verify(&answer(&c2, ""), 0, IP, "admin"), Ok(()), "off: nothing asked");
    }

    /// A challenge is for the address and account it was issued to: one solved at the base
    /// difficulty for an account with no failures can't be spent on the account under attack,
    /// nor from another address.
    #[test]
    fn bound_to_account_and_address() {
        let w = Work::new(8);
        let c = w.issue(8, IP, "nobody");
        let n = solve(&c.salt, 8);
        assert!(w.verify(&answer(&c, &n), 8, IP, "admin").unwrap_err().contains("not for this account"));
        let other = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 2));
        assert!(w.verify(&answer(&c, &n), 8, other, "nobody").unwrap_err().contains("not for this account"));
        assert_eq!(w.verify(&answer(&c, &n), 8, IP, "nobody"), Ok(()));
    }

    /// Unused challenges cost nothing: a flood of them fills no table and cancels no one's.
    #[test]
    fn unused_challenges_are_free() {
        let w = Work::new(4);
        let mine = w.issue(4, IP, "admin");
        for _ in 0..1000 {
            w.issue(4, IP, "x");
        }
        assert_eq!(w.used.lock().unwrap().order.len(), 0);
        assert_eq!(w.verify(&answer(&mine, &solve(&mine.salt, 4)), 4, IP, "admin"), Ok(()), "still good after the flood");
    }

    #[test]
    fn difficulty_ramps_with_failures() {
        let w = Work::new(20);
        assert_eq!(w.difficulty(0, 0, 0), 20);
        assert_eq!(w.difficulty(1, 1, 1), 21, "one mistake: twice the work");
        assert_eq!(w.difficulty(3, 3, 0), 24);
        assert_eq!(w.difficulty(100, 100, 1000), 28, "capped: 6 + 4 + 3 bits");
        assert_eq!(w.difficulty(0, 9, 0), 23, "the account's failures from anywhere count");
        assert_eq!(Work::new(0).difficulty(5, 5, 5), 0);
        assert_eq!(Work::new(40).base, MAX_DIFFICULTY);
    }

    #[test]
    fn zero_bits() {
        assert!(leading_zero_bits(&[0, 0, 0xff], 16));
        assert!(leading_zero_bits(&[0, 0x0f], 12));
        assert!(!leading_zero_bits(&[0, 0x1f], 12));
        assert!(leading_zero_bits(&[0xff], 0));
    }
}
