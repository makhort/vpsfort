//! Tamper evidence for the actions log: once a day, each node hashes the previous UTC day's
//! lines of `actions.jsonl` and shares the hash with its peers as a fact, which they keep
//! (`vpsfort log-digests`). A root intruder who edits the log on the node can't edit the
//! copies of the hash the peers hold: `vpsfort log-digest --day D` on the node, compared with
//! what a peer prints, tells whether that day's log is still what it was.

use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result};
use sha2::Digest;

use crate::time::{self, Micros, SEC};

/// The UTC day of a time, `YYYY-MM-DD`.
pub fn day_of(ts: Micros) -> String {
    time::fmt_ts(ts)[..10].to_string()
}

/// The day before `now`'s.
pub fn yesterday(now: Micros) -> String {
    day_of(now - 86_400 * SEC)
}

/// Whether `s` is a day as [`day_of`] writes it.
pub fn is_day(s: &str) -> bool {
    s.len() == 10 && s.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 { b == b'-' } else { b.is_ascii_digit() })
}

/// The `ts` field of an actions log line (the first field vpsfort writes), without parsing
/// the whole line.
fn line_ts(line: &str) -> Option<Micros> {
    let rest = line.strip_prefix("{\"ts\":")?;
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-')?;
    rest[..end].parse().ok()
}

/// SHA-256 over the log's lines of `day` (each with its newline, in file order, the rotated
/// copies oldest first), and how many there were. A day with no lines hashes to the hash of
/// nothing, with 0 lines.
/// The number in a rotated copy's name (`actions.jsonl.12.gz`: 12); 0 for the live log, and
/// for a copy named another way (by date), which then keeps the order of its name.
fn rotation(log: &Path, file: &Path) -> (u64, std::path::PathBuf) {
    let rest = file.to_string_lossy()[log.to_string_lossy().len().min(file.to_string_lossy().len())..].to_string();
    let n = rest.trim_start_matches('.').split('.').next().and_then(|n| n.parse().ok()).unwrap_or(0);
    (n, file.to_path_buf())
}

pub fn hash_day(path: &Path, day: &str) -> Result<(String, u64)> {
    let mut files = crate::abuse::log_files(path, 0);
    // oldest first: the rotated copies from the highest number down (`.10.gz` before
    // `.9.gz`, which their names as text don't give), then the live log
    files.sort_by_key(|f| std::cmp::Reverse(rotation(path, f)));
    let mut hasher = sha2::Sha256::new();
    let mut lines = 0u64;
    for f in files {
        let file = std::fs::File::open(&f).with_context(|| format!("opening {}", f.display()))?;
        let gz = f.extension().is_some_and(|e| e == "gz");
        let reader: Box<dyn Read> = if gz { Box::new(flate2::read::GzDecoder::new(file)) } else { Box::new(file) };
        let mut reader = BufReader::new(reader);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n = crate::record::read_line_capped(&mut reader, &mut buf, 1 << 20).with_context(|| format!("reading {}", f.display()))?;
            if n == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&buf);
            let line = line.trim_end_matches(['\n', '\r']);
            if line_ts(line).is_some_and(|ts| day_of(ts) == day) {
                hasher.update(line.as_bytes());
                hasher.update(b"\n");
                lines += 1;
            }
        }
    }
    Ok((hasher.finalize().iter().map(|b| format!("{b:02x}")).collect(), lines))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_one_days_lines_across_rotated_copies() {
        let d = std::env::temp_dir().join(format!("lg-logdigest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let day1 = 1_700_000_000 * SEC; // 2023-11-14 22:13:20 UTC
        let day2 = day1 + 86_400 * SEC;
        let line = |ts: Micros, n: u32| format!("{{\"ts\":{ts},\"kind\":\"ban\",\"message\":\"m{n}\"}}\n");
        // the rotated copy holds the older lines, the live log the newer ones
        std::fs::write(d.join("actions.jsonl.1"), line(day1, 1) + &line(day1 + SEC, 2)).unwrap();
        std::fs::write(d.join("actions.jsonl"), line(day1 + 2 * SEC, 3) + &line(day2, 4) + "not json\n").unwrap();
        let (h, n) = hash_day(&d.join("actions.jsonl"), &day_of(day1)).unwrap();
        assert_eq!(n, 3);
        let mut expect = sha2::Sha256::new();
        for i in 0..3u32 {
            expect.update(line(day1 + i64::from(i) * SEC, i + 1).as_bytes());
        }
        assert_eq!(h, expect.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>());
        let (h2, n2) = hash_day(&d.join("actions.jsonl"), &day_of(day2)).unwrap();
        assert_eq!(n2, 1);
        assert_ne!(h, h2);
        assert_eq!(hash_day(&d.join("actions.jsonl"), "2001-01-01").unwrap().1, 0);
        assert_eq!(day_of(day1), "2023-11-14");
        assert_eq!(yesterday(day2 + 3600 * SEC), "2023-11-14");
        assert!(is_day("2026-11-03") && !is_day("2026-11-3") && !is_day("2026/11/03"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rotated_copies_are_read_by_number() {
        let log = Path::new("/var/log/vpsfort/actions.jsonl");
        let mut files: Vec<std::path::PathBuf> =
            ["actions.jsonl", "actions.jsonl.1", "actions.jsonl.2.gz", "actions.jsonl.9.gz", "actions.jsonl.10.gz", "actions.jsonl.11.gz"]
                .iter()
                .map(|n| log.with_file_name(n))
                .collect();
        files.sort_by_key(|f| std::cmp::Reverse(rotation(log, f)));
        let names: Vec<String> = files.iter().map(|f| f.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(
            names,
            ["actions.jsonl.11.gz", "actions.jsonl.10.gz", "actions.jsonl.9.gz", "actions.jsonl.2.gz", "actions.jsonl.1", "actions.jsonl"]
        );
    }
}
