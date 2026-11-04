//! An hourly index beside the decision log (`actions.jsonl.index`): for each hour that has
//! a decision, the byte offset of its first line. The console asks for the last day or week
//! out of a log that may hold months; with the index a reader starts at the window instead
//! of parsing everything before it.
//!
//! The index is advisory. Its header names the log file it belongs to (the inode); after a
//! rotation that creates a new file the daemon starts a fresh index, and a reader ignores an
//! index whose file isn't the log's. An entry is used only if the line at its offset really
//! starts a decision of that hour, so a truncated or rewritten log can't send a reader into
//! the middle of a line: it then reads from the start, as without an index.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::time::{Micros, SEC};

const HOUR: Micros = 3600 * SEC;
const HEADER: &str = "vpsfort-index 1";

/// The index path of a log.
pub fn path_of(log: &Path) -> PathBuf {
    let mut s = log.as_os_str().to_owned();
    s.push(".index");
    PathBuf::from(s)
}

fn inode(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.ino())
}

/// At most this many entries are read from an index (a year of hours is 8,760): a huge or
/// forged one costs a reader nothing more.
const MAX_ENTRIES: usize = 100_000;

/// An index's text: the inode it names and its entries (hour, offset), in order. None when
/// it isn't an index of this format; entries out of order end the list (what follows can't be
/// trusted, and a reader needs them ascending).
pub fn parse(text: &str) -> Option<(u64, Vec<(Micros, u64)>)> {
    let mut lines = text.lines();
    let ino = lines.next()?.strip_prefix(HEADER)?.trim().parse::<u64>().ok()?;
    let mut out: Vec<(Micros, u64)> = Vec::new();
    for line in lines.take(MAX_ENTRIES) {
        let Some((h, o)) = line.split_once(' ') else { break };
        let (Ok(h), Ok(o)) = (h.parse::<Micros>(), o.parse::<u64>()) else { break };
        if h <= 0 || h.rem_euclid(HOUR) != 0 || out.last().is_some_and(|(lh, lo)| h <= *lh || o < *lo) {
            break;
        }
        out.push((h, o));
    }
    Some((ino, out))
}

/// The entries of an index that belongs to `log`: (hour, offset), as written.
fn entries(log: &Path) -> Option<Vec<(Micros, u64)>> {
    let text = std::fs::read_to_string(path_of(log)).ok()?;
    let (ino, entries) = parse(&text)?;
    (inode(log)? == ino).then_some(entries)
}

/// Whether a decision of `hour` starts at `offset` of `log` (`len` bytes long).
fn starts_hour(log: &mut (impl Read + Seek), offset: u64, hour: Micros, len: u64) -> bool {
    if offset > len || log.seek(SeekFrom::Start(offset)).is_err() {
        return false;
    }
    // a line starts there: the byte before is a newline (or it is the start of the log)
    if offset > 0 {
        let mut before = [0u8; 1];
        if log.seek(SeekFrom::Start(offset - 1)).is_err() || log.read_exact(&mut before).is_err() || before[0] != b'\n' {
            return false;
        }
    }
    let mut head = [0u8; 200];
    let n = log.read(&mut head).unwrap_or(0);
    let head = String::from_utf8_lossy(&head[..n]);
    if !head.starts_with('{') {
        return false;
    }
    // `{"ts":1793364189457747,...`: the time is the first field the daemon writes
    let Some(rest) = head.split_once("\"ts\":").map(|(_, r)| r) else { return false };
    let ts: Micros = match rest.split(|c: char| !c.is_ascii_digit()).next().and_then(|d| d.parse().ok()) {
        Some(t) => t,
        None => return false,
    };
    ts - ts.rem_euclid(HOUR) == hour
}

/// Where a reader of `log` may start for decisions from `from` on: the offset of the hour
/// `from` falls in (or the latest hour before it), when the index has one that checks out.
/// None: read from the start.
pub fn offset_for(log: &Path, from: Micros) -> Option<u64> {
    let all = entries(log)?;
    let mut file = File::open(log).ok()?;
    let len = file.metadata().ok()?.len();
    offset_within(&mut file, len, &all, from)
}

/// `offset_for` on an open log of `len` bytes with the index's entries: the latest hour at
/// or before `from` whose entry checks out, then earlier ones if that one is stale.
pub fn offset_within(log: &mut (impl Read + Seek), len: u64, entries: &[(Micros, u64)], from: Micros) -> Option<u64> {
    let at = entries.iter().rposition(|(h, _)| *h <= from)?;
    entries[..=at].iter().rev().find(|(h, o)| starts_hour(log, *o, *h, len)).map(|(_, o)| *o)
}

/// The daemon's side: appends an entry when a decision starts a new hour.
pub struct Index {
    file: File,
    last_hour: Micros,
    /// The last offset noted: one below it means the log was truncated in place.
    last_offset: u64,
}

impl Index {
    /// Opens (or starts) the index of `log`, which must exist already.
    pub fn open(log: &Path) -> std::io::Result<Index> {
        let ino = inode(log).ok_or_else(|| std::io::Error::other("the log isn't there"))?;
        let path = path_of(log);
        let len = std::fs::metadata(log).map(|m| m.len()).unwrap_or(0);
        // an index of this very file, whose entries all lie within it, carries on; else fresh
        let kept = entries(log).filter(|e| e.iter().all(|(_, o)| *o <= len));
        let (last_hour, last_offset) = kept.as_ref().and_then(|e| e.last().copied()).unwrap_or((0, 0));
        let file = OpenOptions::new().create(true).append(true).mode(0o640).open(&path)?;
        let mut ix = Index { file, last_hour, last_offset };
        if kept.is_none() {
            ix.start_over(ino)?;
        }
        Ok(ix)
    }

    /// A fresh index for the log file `ino`.
    fn start_over(&mut self, ino: u64) -> std::io::Result<()> {
        self.file.set_len(0)?;
        writeln!(self.file, "{HEADER} {ino}")?;
        self.last_hour = 0;
        self.last_offset = 0;
        Ok(())
    }

    /// A decision at `ts` was written at `offset` of `log`.
    pub fn note(&mut self, log: &Path, ts: Micros, offset: u64) {
        if ts <= 0 {
            return;
        }
        // The log was truncated in place (logrotate's copytruncate keeps its inode): the
        // entries so far point into the old content, and offsets must stay ascending for a
        // reader; the index starts over with this very file's.
        if offset < self.last_offset {
            match inode(log) {
                Some(ino) if self.start_over(ino).is_ok() => {}
                _ => return,
            }
        }
        let hour = ts - ts.rem_euclid(HOUR);
        if hour > self.last_hour && writeln!(self.file, "{hour} {offset}").is_ok() {
            self.last_hour = hour;
            self.last_offset = offset;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(ts: Micros) -> String {
        format!("{{\"ts\":{ts},\"kind\":\"ban\",\"severity\":\"high\",\"target\":\"192.0.2.1\",\"message\":\"ban\"}}\n")
    }

    /// Writes decisions at the given times through the index, as the daemon does.
    fn log_with(dir: &Path, times: &[Micros]) -> PathBuf {
        let log = dir.join("actions.jsonl");
        let mut f = OpenOptions::new().create(true).append(true).open(&log).unwrap();
        let mut ix = Index::open(&log).unwrap();
        for t in times {
            let off = f.metadata().unwrap().len();
            f.write_all(line(*t).as_bytes()).unwrap();
            ix.note(&log, *t, off);
        }
        log
    }

    #[test]
    fn a_reader_starts_at_the_hour() {
        let dir = tempdir();
        let h = 1_793_300_000 * SEC;
        let h0 = h - h.rem_euclid(HOUR);
        let times = [h0 + 5 * SEC, h0 + 70 * SEC, h0 + HOUR + SEC, h0 + HOUR + 9 * SEC, h0 + 3 * HOUR];
        let log = log_with(&dir, &times);
        let text = std::fs::read_to_string(path_of(&log)).unwrap();
        assert_eq!(text.lines().count(), 4, "a header and one entry per hour with decisions: {text}");
        let second = line(times[0]).len() as u64 + line(times[1]).len() as u64;
        assert_eq!(offset_for(&log, h0 + HOUR), Some(second));
        assert_eq!(offset_for(&log, h0 + HOUR + 30 * 60 * SEC), Some(second), "within the hour: its start");
        assert_eq!(offset_for(&log, h0 + 2 * HOUR), Some(second), "an hour without decisions: the hour before");
        assert_eq!(offset_for(&log, h0 - SEC), None, "before the first entry: from the start");
        assert_eq!(offset_for(&log, h0), Some(0));
        // the offset is the start of a line of that hour: what `for_each_ban` reads from there
        let mut f = File::open(&log).unwrap();
        f.seek(SeekFrom::Start(second)).unwrap();
        let mut rest = String::new();
        f.read_to_string(&mut rest).unwrap();
        assert_eq!(rest.lines().count(), 3);
        assert!(rest.starts_with(&format!("{{\"ts\":{}", times[2])));
        drop(dir);
    }

    /// After a rotation the log is a new file: its old index is not used and is replaced.
    #[test]
    fn a_rotated_log_gets_a_fresh_index() {
        let dir = tempdir();
        let h = 1_793_300_000 * SEC;
        let log = log_with(&dir, &[h, h + HOUR]);
        assert!(offset_for(&log, h + HOUR).is_some());
        std::fs::rename(&log, dir.join("actions.jsonl.1")).unwrap();
        std::fs::write(&log, line(h + 2 * HOUR)).unwrap();
        assert_eq!(offset_for(&log, h + HOUR), None, "another file's index");
        let mut ix = Index::open(&log).unwrap();
        ix.note(&log, h + 3 * HOUR, line(h + 2 * HOUR).len() as u64);
        let text = std::fs::read_to_string(path_of(&log)).unwrap();
        assert_eq!(text.lines().count(), 2, "fresh: a header and the new entry: {text}");
        drop(dir);
    }

    /// logrotate's copytruncate empties the log in place while the daemon runs: the index
    /// it keeps open starts over at the first decision after, so a reader of the new content
    /// still finds its hours (instead of entries out of order, which a reader drops).
    #[test]
    fn the_index_starts_over_when_the_log_is_truncated_in_place() {
        let dir = tempdir();
        let h = 1_793_300_000 * SEC;
        let h0 = h - h.rem_euclid(HOUR);
        let log = dir.join("actions.jsonl");
        let mut f = OpenOptions::new().create(true).append(true).open(&log).unwrap();
        let mut ix = Index::open(&log).unwrap();
        for t in [h0, h0 + HOUR, h0 + 2 * HOUR] {
            let off = f.metadata().unwrap().len();
            f.write_all(line(t).as_bytes()).unwrap();
            ix.note(&log, t, off);
        }
        // copytruncate: the same file (inode), emptied; the daemon's descriptor appends at 0
        f.set_len(0).unwrap();
        for t in [h0 + 5 * HOUR, h0 + 6 * HOUR] {
            let off = f.metadata().unwrap().len();
            f.write_all(line(t).as_bytes()).unwrap();
            ix.note(&log, t, off);
        }
        let text = std::fs::read_to_string(path_of(&log)).unwrap();
        assert_eq!(text.lines().count(), 3, "a header and the two hours since the truncation: {text}");
        assert_eq!(offset_for(&log, h0 + 6 * HOUR), Some(line(h0 + 5 * HOUR).len() as u64));
        assert_eq!(offset_for(&log, h0 + 5 * HOUR), Some(0));
        drop(dir);
    }

    /// A forged or damaged index never sends a reader into a line or past the end.
    #[test]
    fn a_bad_index_is_not_followed() {
        let h = 1_793_300_000 * SEC;
        let h0 = h - h.rem_euclid(HOUR);
        let log = format!("{}{}", line(h0 + SEC), line(h0 + HOUR));
        let len = log.len() as u64;
        let second = line(h0 + SEC).len() as u64;
        let mut cur = std::io::Cursor::new(log.clone().into_bytes());
        let check = |entries: &[(Micros, u64)], from: Micros| {
            offset_within(&mut std::io::Cursor::new(log.clone().into_bytes()), len, entries, from)
        };
        assert_eq!(check(&[(h0, 0), (h0 + HOUR, second)], h0 + HOUR), Some(second), "a good one");
        assert_eq!(check(&[(h0, 0), (h0 + HOUR, second + 3)], h0 + HOUR), Some(0), "inside a line: the entry before");
        assert_eq!(check(&[(h0, 7), (h0 + HOUR, len + 1000)], h0 + HOUR), None, "past the end, inside a line: from the start");
        assert_eq!(check(&[(h0 + HOUR, 0)], h0 + HOUR), None, "the wrong hour");
        assert!(!starts_hour(&mut cur, u64::MAX, h0, len));
        let (ino, e) = parse(&format!("{HEADER} 5\n{h0} 0\n{} {second}\n{} 1\nx y\n", h0 + HOUR, h0 + 2 * HOUR)).unwrap();
        assert_eq!((ino, e.len()), (5, 2), "entries stop where the offsets go backwards");
        assert!(parse("not an index\n1 2\n").is_none());
        assert_eq!(parse(&format!("{HEADER} 1\n{} 5\n", h0 + 7)).unwrap().1, vec![], "an hour must be whole");
    }

    /// A log truncated in place (copytruncate) keeps its inode: entries that no longer start
    /// a line of their hour are skipped, so a reader is never sent into the middle of one.
    #[test]
    fn a_truncated_log_is_read_from_the_start() {
        let dir = tempdir();
        let h = 1_793_300_000 * SEC;
        let log = log_with(&dir, &[h, h + HOUR, h + 2 * HOUR]);
        std::fs::write(&log, line(h + 5 * HOUR)).unwrap();
        assert_eq!(offset_for(&log, h + 2 * HOUR), None);
        let ix = Index::open(&log).unwrap();
        assert_eq!(ix.last_hour, 0, "entries beyond the file: started over");
        drop(dir);
    }

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("vpsfort-index-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
