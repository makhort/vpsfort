//! Enforcement against a real kernel: the nftables backend with the real `nft`, as root.
//! Every other enforcement test uses a stand-in `nft`; this one checks that the rulesets
//! vpsfort writes are what the kernel takes, that a ban's timeout lives in the kernel, that
//! feeds load, and that a deleted table is rebuilt with the bans still active. CI runs it on
//! its Linux runners (`.github/workflows/vpsfort.yml`); by hand:
//!
//!     cargo test --test real_nft --no-run     # then the printed binary, as root:
//!     sudo VPSFORT_REAL_NFT=1 target/debug/deps/real_nft-* --ignored
//!
//! It uses a table of its own (`inet vpsfort_ci`) and deletes it when done.

use std::process::Command;

use vpsfort::config::Config;
use vpsfort::enforce::{Enforcer, Kind};
use vpsfort::engine::{Action, ActionKind, Ban, Severity};
use vpsfort::time::{self, SEC};

const TABLE: &str = "vpsfort_ci";

fn nft(args: &[&str]) -> String {
    let out = Command::new("nft").args(args).output().expect("nft runs");
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

fn set(name: &str) -> String {
    nft(&["list", "set", "inet", TABLE, name])
}

/// Whether the set's listing holds `elem` with time left in the kernel. nft prints an element
/// as `<elem> expires <left>` or, with its own timeout named, `<elem> timeout <t> expires <left>`.
fn timed(listing: &str, elem: &str) -> bool {
    listing
        .split(['{', ',', '}'])
        .map(str::trim)
        .any(|e| e.strip_prefix(elem).is_some_and(|rest| rest.starts_with(' ') && rest.split_whitespace().any(|w| w == "expires")))
}

/// Deletes the test's table when the test ends, however it ends.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new("nft").args(["delete", "table", "inet", TABLE]).output();
    }
}

fn change(kind: ActionKind, net: &str, secs: i64) -> Action {
    let now = time::now();
    Action {
        ts: now,
        kind,
        severity: Severity::Info,
        target: Some(net.parse().unwrap()),
        until: Some(now + secs * SEC),
        message: format!("{kind:?} {net} (real_nft test)"),
        evidence: vec![],
        superseded: vec![],
        applied: false,
        topic: None,
        accounts: vec![],
        user_note: None,
        notice: None,
        category: None,
        signals: Default::default(),
    }
}

#[test]
fn a_listed_element_is_timed_in_either_spelling() {
    let old = "elements = { 198.51.100.7 timeout 59m59s expires 59m58s940ms, 203.0.113.0/24 timeout 1h59m59s expires 1h59m58s982ms }";
    assert!(timed(old, "198.51.100.7") && timed(old, "203.0.113.0/24"));
    let new = "elements = { 198.51.100.7 expires 59m58s, 2001:db8::7 expires 9m }";
    assert!(timed(new, "198.51.100.7") && timed(new, "2001:db8::7"));
    assert!(!timed(new, "198.51.100.70") && !timed(new, "198.51.100") && !timed("elements = { 198.51.100.7 }", "198.51.100.7"));
}

#[test]
#[ignore = "needs root and nftables: VPSFORT_REAL_NFT=1, as root"]
fn bans_feeds_and_healing_on_a_real_kernel() {
    if std::env::var("VPSFORT_REAL_NFT").as_deref() != Ok("1") {
        eprintln!("real_nft: skipped (VPSFORT_REAL_NFT=1 as root runs it)");
        return;
    }
    let cfg = Config::from_toml(&format!(
        "mode = \"enforce\"\n[enforce]\nbackend = \"nft\"\nnft_table = \"{TABLE}\"\n\
         [ports]\nwhitelist = [\"51820/udp\"]\n\
         [[ratelimit]]\nports = [\"2222/tcp\"]\nrate = \"6/minute\"\nburst = 6\n"
    ))
    .unwrap();
    let _cleanup = Cleanup;
    let e = Enforcer::new(&cfg, &[]);
    assert_eq!(e.kind, Kind::Nft, "the nftables setup was refused: {:?}", e.nft_error);
    assert!(e.trip_error.is_none(), "the kernel tripwire rules were refused: {:?}", e.trip_error);
    let table = nft(&["list", "table", "inet", TABLE]);
    for want in ["chain bans", "chain rl", "set ban4", "set ban6", "set feed4", "set oper4", "set geo4", "set tripseen4", "51820"] {
        assert!(table.contains(want), "{want} missing from the table the kernel holds:\n{table}");
    }

    // bans, with their time left in the kernel; an unban removes one
    let mut ban = change(ActionKind::Ban, "198.51.100.7", 3600);
    e.apply(&mut ban).unwrap();
    assert!(ban.applied);
    let mut ban6 = change(ActionKind::Ban, "2001:db8::7", 3600);
    e.apply(&mut ban6).unwrap();
    let mut subnet = change(ActionKind::Ban, "203.0.113.0/24", 7200);
    e.apply(&mut subnet).unwrap();
    let ban4 = set("ban4");
    assert!(timed(&ban4, "198.51.100.7") && timed(&ban4, "203.0.113.0/24"), "{ban4}");
    assert!(timed(&set("ban6"), "2001:db8::7"), "{}", set("ban6"));
    let mut allow = change(ActionKind::Allow, "192.0.2.9", 600);
    e.apply(&mut allow).unwrap();
    assert!(timed(&set("oper4"), "192.0.2.9"), "{}", set("oper4"));
    let mut unban = change(ActionKind::Unban, "198.51.100.7", 0);
    e.apply(&mut unban).unwrap();
    assert!(unban.applied && !set("ban4").contains("198.51.100.7"), "{}", set("ban4"));
    let again = e.apply(&mut change(ActionKind::Unban, "198.51.100.7", 0));
    assert!(again.is_ok(), "an element already gone is fine, but nft's answer wasn't read as that: {again:?}");

    // a blocklist feed
    let feed: vpsfort::net::Net = "198.18.0.0/15".parse().unwrap();
    assert!(e.load_feeds(&[feed]).unwrap());
    assert!(set("feed4").contains("198.18.0.0/15"), "{}", set("feed4"));

    // the table deleted (as `nft flush ruleset` does): noticed and rebuilt with what is still active
    nft(&["delete", "table", "inet", TABLE]);
    assert!(!e.table_present());
    let now = time::now();
    let bans = [
        Ban {
            net: "203.0.113.0/24".parse().unwrap(),
            since: now - 60 * SEC,
            until: now + 600 * SEC,
            offence: 1,
            reason: "ci".into(),
            origin: None,
            inner: vec![],
        },
        Ban {
            net: "2001:db8::7".parse().unwrap(),
            since: now - 60 * SEC,
            until: now + 600 * SEC,
            offence: 1,
            reason: "ci".into(),
            origin: None,
            inner: vec![],
        },
    ];
    let msg = e.heal(&bans, &[], &[feed], &[], &[], now).expect("the table was missing");
    assert!(msg.contains("rebuilt it and restored 2 bans"), "{msg}");
    assert!(e.table_present());
    assert!(timed(&set("ban4"), "203.0.113.0/24") && timed(&set("ban6"), "2001:db8::7"), "{}{}", set("ban4"), set("ban6"));
    assert!(set("feed4").contains("198.18.0.0/15"));
    assert!(e.restore(&bans, now).is_empty(), "elements there already are no failure");
}
