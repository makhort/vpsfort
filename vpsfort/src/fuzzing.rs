//! What the fuzz targets in `fuzz/` run (`cargo +nightly fuzz run records`). They feed
//! arbitrary input to the code that reads log lines: attackers shape those lines (the user
//! names they try, request paths, client banners, certificate names), so none of it may
//! panic, hang or grow without bound. `tests/fuzz_smoke.rs` runs the same functions on
//! stable over the sample logs and generated input, so `cargo test` keeps them working.

use std::sync::Arc;

use crate::config::Config;
use crate::pipeline::Pipeline;
use crate::record::{self, YearGuess};
use crate::time::SEC;

/// The configuration the targets use: every source on, so every parser is reached, and
/// patterns of your own and every app's built-in ones on any line no built-in parser reads
/// (journal exports and syslog text carry no sender fields, so they apply).
pub fn config() -> Arc<Config> {
    let apps: Vec<String> = crate::parse::apps::APPS.iter().map(|a| format!("\"{}\"", a.name)).collect();
    let mut cfg = Config::from_toml(&format!(
        r#"
        [sources]
        apps = [{}]
        [[patterns]]
        name = "auth"
        identifier = "fuzz"
        uid = 0
        regex = '(?:failed|refused) (?:login|auth)[^\[]*\[(?P<ip>[0-9A-Fa-f.:]+)\](?: user=(?P<user>\S+))?'
        [[patterns]]
        name = "probe"
        unit = "fuzz.service"
        kind = "probe"
        weight = 40
        regex = '^(?P<ip>\S+) .*"GET /\.(?:env|git)'
        [[patterns]]
        name = "login"
        identifier = "fuzz"
        uid = 0
        kind = "success"
        regex = 'accepted (?P<user>\S+) from (?P<ip>\S+)'
        "#,
        apps.join(", ")
    ))
    .expect("valid fuzzing config");
    cfg.sources.nextcloud_aio = true;
    cfg.sources.services = vec!["vpsfort-xmpp-bot.service".into(), "ejabberd.service".into()];
    Arc::new(cfg)
}

/// Lines in any format vpsfort reads (`journalctl -o json`, short syslog, Nextcloud's JSON
/// log), through the parsers and the decision engine, then a day of time for the
/// parsers' and the engine's timers.
pub fn records(cfg: &Arc<Config>, data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let mut pipe = Pipeline::new(Arc::clone(cfg), 0);
    let mut years = YearGuess::new(2026);
    let mut last = 0;
    for line in text.lines() {
        let rec = if line.starts_with('{') { record::parse_journal_json(line).0 } else { record::parse_syslog_line(line, &mut years) };
        let Some(rec) = rec.or_else(|| record::parse_nextcloud_line(line)) else { continue };
        pipe.tick(rec.ts);
        pipe.feed(&rec);
        last = last.max(rec.ts);
        // the pieces the pipeline calls only for some sources, on any message
        let _ = crate::parse::kernel::parse_oom(&rec.msg);
        let _ = crate::parse::systemd::parse(&rec.msg);
        let _ = crate::abuse::sanitize(&rec.msg);
        for ident in ["su", "sudo"] {
            let _ = crate::parse::privilege::parse(ident, &rec.msg);
        }
        for ident in ["login", "useradd", "usermod", "gpasswd", "passwd"] {
            let _ = crate::parse::auth::pam(ident, &rec.msg);
        }
        let _ = crate::parse::auth::audit(&rec.msg, &["*".to_string()]);
        let _ = crate::patches::parse_apt_simulation(&rec.msg);
        let _ = crate::procwatch::odd_exe(&rec.msg);
        let _ = crate::feeds::parse_asns(&rec.msg);
    }
    pipe.tick(last.saturating_add(86_400 * SEC));
    let _ = pipe.snapshot(10);
    waf(&text);
}

/// What `[waf]` sources give out (a WAF's API answer, a file another program writes) in
/// every format: whatever it holds, a parse ends, with decisions or an error.
/// A decision log (`actions.jsonl`) through what reads it back: the dashboard's log view and
/// the live abuse report. Peers' and older versions' lines, and a damaged rotated copy, must
/// never panic it.
pub fn actions_log(data: &[u8]) {
    let mut actions = Vec::new();
    let _ = record::for_each_action_line(data, |line| {
        if let Ok(a) = serde_json::from_str::<crate::engine::Action>(line) {
            actions.push(a);
        }
    });
    let filter = crate::abuse::Filter { only: vec![], min_events: 1 };
    let mut c = crate::abuse::Collector::new(&filter, 20, 50);
    for a in &actions {
        c.add(a);
    }
    let _ = crate::abuse::live_of(c, 0, 1_800_000_000 * SEC, "host".into(), vec![]);
    let _ = crate::actions_view::build(vec![actions], None);
}

/// A decision log's hourly index (`logindex`) as an attacker or a damaged disk may leave it,
/// against a log: whatever it says, a reader is sent to the start of a line of the hour
/// asked, or to the start of the log, never into a line or past the end. The input is the
/// index's text, a NUL, then the log.
pub fn log_index(data: &[u8]) {
    let split = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    let index = String::from_utf8_lossy(&data[..split]);
    let log = &data[(split + 1).min(data.len())..];
    let Some((_, entries)) = crate::logindex::parse(&index) else { return };
    let len = log.len() as u64;
    let mut froms = vec![0, 1, i64::MAX, 1_793_300_000 * SEC];
    froms.extend(entries.iter().flat_map(|(h, _)| [*h, h + 1, h - 1]));
    for from in froms {
        let mut cur = std::io::Cursor::new(log);
        if let Some(off) = crate::logindex::offset_within(&mut cur, len, &entries, from) {
            assert!(off <= len, "offset {off} beyond the log ({len} bytes)");
            assert!(off == 0 || log[off as usize - 1] == b'\n', "offset {off} inside a line");
            // and what follows reads as log lines
            let _ = record::for_each_action_line(&log[off as usize..], |_| {});
        }
    }
}

pub fn waf(text: &str) {
    use crate::waf::{Format, WafSource};
    let base = WafSource { name: "fuzz".into(), file: Some("/dev/null".into()), ..Default::default() };
    let sources = [
        WafSource { format: Format::Plain, ..base.clone() },
        WafSource { format: Format::Crowdsec, ..base.clone() },
        WafSource {
            format: Format::Json,
            items: "result.items".into(),
            duration_field: "ttl".into(),
            until_field: "meta.until".into(),
            reason_field: "comment".into(),
            ..base.clone()
        },
        WafSource { format: Format::Csv, ip_field: "2".into(), duration_field: "ttl".into(), header: true, ..base.clone() },
        WafSource { format: Format::Regex, pattern: r"(?P<ip>\S+) (?P<duration>\S+) (?P<reason>.*)".into(), ..base },
    ];
    for s in &sources {
        if let Ok(mut p) = crate::waf::parse(s, text, 1_790_000_000 * SEC) {
            crate::waf::filter(s, &mut p);
            let _ = crate::waf::by_net(&p.decisions);
        }
    }
}
