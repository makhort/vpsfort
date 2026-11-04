//! A copy of the decision log on a peer (`[cluster] mirror_to`): every line written to
//! `actions.jsonl` goes to one direct peer at the next sync, which appends it to
//! `<mirror_dir>/<origin>.jsonl` (rotated once, at `mirror_max_mb`). The daily hashes
//! (`logdigest`) prove an edit of the log on the node; the mirror keeps the lines
//! themselves, so what a wiped node decided is still somewhere. Lines wait in memory for
//! the sync (bounded: a flood drops the rest and says how many), and a peer down for longer
//! than an hour misses a batch, which the mirror marks as a gap.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cluster::FactBody;
use crate::time::{self, Micros};

/// Most lines, and bytes, in one batch (a fact; a frame holds at most 1 MB).
pub const MAX_BATCH_LINES: usize = 1000;
pub const MAX_BATCH_BYTES: usize = 256 * 1024;
/// A line longer than this is cut (a ban's line with its evidence is a few KB).
pub const MAX_LINE: usize = 16 * 1024;

/// Lines written since the last sync, waiting for the mirror.
#[derive(Default)]
pub struct Buffer {
    lines: Vec<String>,
    bytes: usize,
    /// Lines that didn't fit since the last batch.
    dropped: u64,
}

impl Buffer {
    pub fn push(&mut self, line: &str) {
        if self.lines.len() >= MAX_BATCH_LINES || self.bytes + line.len() > MAX_BATCH_BYTES {
            self.dropped += 1;
            return;
        }
        let line: String = line.chars().take(MAX_LINE).collect();
        self.bytes += line.len();
        self.lines.push(line);
    }

    /// The next batch as a fact for `to`, numbered `batch`; None while nothing waits.
    pub fn take(&mut self, to: &str, batch: u64) -> Option<FactBody> {
        if self.lines.is_empty() && self.dropped == 0 {
            return None;
        }
        self.bytes = 0;
        Some(FactBody::LogLines {
            to: to.to_string(),
            batch,
            dropped: std::mem::take(&mut self.dropped),
            lines: std::mem::take(&mut self.lines),
        })
    }

    pub fn waiting(&self) -> usize {
        self.lines.len()
    }
}

/// What this node holds of a peer's log.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MirrorView {
    /// Lines appended since vpsfort started.
    pub lines: u64,
    /// The file's size now.
    pub bytes: u64,
    pub last: Micros,
    /// Batches missed (a peer down for an hour, or lines it had to drop) since the start.
    pub gaps: u32,
    pub last_batch: u64,
}

/// A node name fit for a file name.
fn node_ok(n: &str) -> bool {
    (1..=64).contains(&n.len()) && !n.starts_with('.') && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

pub fn file_of(dir: &Path, origin: &str) -> PathBuf {
    dir.join(format!("{origin}.jsonl"))
}

/// A batch as a peer sent it.
pub struct Batch<'a> {
    pub origin: &'a str,
    pub batch: u64,
    pub dropped: u64,
    pub lines: &'a [String],
}

/// Appends a batch from its origin to the origin's mirror file, with a marker line where
/// batches are missing or the origin dropped lines; `view` is updated (its `last_batch`
/// tells gaps).
pub fn append(dir: &Path, b: &Batch, max_bytes: u64, now: Micros, view: &mut MirrorView) -> Result<()> {
    let Batch { origin, batch, dropped, lines } = *b;
    if !node_ok(origin) {
        bail!("node name unfit for a file name");
    }
    if dir.as_os_str().is_empty() {
        bail!("[cluster] mirror_dir is empty");
    }
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let path = file_of(dir, origin);
    let incoming: usize = lines.iter().map(|l| l.len() + 1).sum();
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    if size > 0 && size + incoming as u64 > max_bytes {
        // rotate once: the previous copy goes, the current one becomes it
        std::fs::rename(&path, path.with_extension("jsonl.1")).with_context(|| format!("rotating {}", path.display()))?;
    }
    let mut f =
        std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&path).with_context(|| path.display().to_string())?;
    let mut markers = Vec::new();
    if view.last_batch != 0 && batch != view.last_batch + 1 {
        view.gaps += 1;
        markers.push(format!(
            "{{\"mirror\":\"gap\",\"ts\":{now},\"after_batch\":{},\"batch\":{batch},\"note\":\"batches missing: the mirror was unreachable, or vpsfort there restarted\"}}",
            view.last_batch
        ));
    }
    if dropped > 0 {
        view.gaps += 1;
        markers.push(format!(
            "{{\"mirror\":\"dropped\",\"ts\":{now},\"lines\":{dropped},\"note\":\"the origin had more lines than a batch holds\"}}"
        ));
    }
    for m in &markers {
        writeln!(f, "{m}")?;
    }
    for l in lines {
        // one record per line, whatever a peer sends
        writeln!(f, "{}", l.replace(['\n', '\r'], " "))?;
    }
    f.flush()?;
    view.lines += lines.len() as u64;
    view.bytes = f.metadata().map(|m| m.len()).unwrap_or(0);
    view.last = now;
    view.last_batch = batch;
    Ok(())
}

/// The mirror files held: (origin, bytes of both copies, last written).
pub fn held(dir: &Path) -> BTreeMap<String, (u64, Micros)> {
    let mut out = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(origin) = name.strip_suffix(".jsonl").or_else(|| name.strip_suffix(".jsonl.1")) else { continue };
        let Ok(m) = e.metadata() else { continue };
        let modified = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_micros() as Micros);
        let entry = out.entry(origin.to_string()).or_insert((0, 0));
        entry.0 += m.len();
        entry.1 = entry.1.max(modified);
    }
    out
}

/// For `vpsfort mirror`: one line per peer mirrored here.
pub fn describe(dir: &Path) -> Vec<String> {
    held(dir)
        .into_iter()
        .map(|(origin, (bytes, last))| {
            format!(
                "{origin}: {} ({}), last line {}",
                file_of(dir, &origin).display(),
                human(bytes),
                if last == 0 { "never".into() } else { time::fmt_ts(last) }
            )
        })
        .collect()
}

fn human(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{} KB", b >> 10),
        b => format!("{b} B"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches_are_bounded_and_numbered() {
        let mut b = Buffer::default();
        assert!(b.take("x", 1).is_none());
        for i in 0..MAX_BATCH_LINES + 5 {
            b.push(&format!("{{\"n\":{i}}}"));
        }
        assert_eq!(b.waiting(), MAX_BATCH_LINES);
        let Some(FactBody::LogLines { to, batch, dropped, lines }) = b.take("peer", 7) else { panic!() };
        assert_eq!((to.as_str(), batch, dropped, lines.len()), ("peer", 7, 5, MAX_BATCH_LINES));
        assert!(b.take("peer", 8).is_none(), "emptied");
        b.push(&"x".repeat(MAX_LINE + 10));
        let Some(FactBody::LogLines { lines, .. }) = b.take("peer", 8) else { panic!() };
        assert_eq!(lines[0].len(), MAX_LINE, "a long line is cut");
    }

    #[test]
    fn appends_marks_gaps_and_rotates() {
        let d = std::env::temp_dir().join(format!("lg-mirror-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mut v = MirrorView::default();
        let now = 1_700_000_000 * time::SEC;
        let first = ["{\"a\":1}".to_string(), "{\"b\":2}\nextra".to_string()];
        append(&d, &Batch { origin: "vpn", batch: 1, dropped: 0, lines: &first }, 1 << 20, now, &mut v).unwrap();
        let text = std::fs::read_to_string(d.join("vpn.jsonl")).unwrap();
        assert_eq!(text, "{\"a\":1}\n{\"b\":2} extra\n");
        assert_eq!((v.lines, v.gaps, v.last_batch), (2, 0, 1));
        // batch 3 after 1: a gap, and dropped lines
        append(&d, &Batch { origin: "vpn", batch: 3, dropped: 4, lines: &["{\"c\":3}".to_string()] }, 1 << 20, now + time::SEC, &mut v)
            .unwrap();
        let text = std::fs::read_to_string(d.join("vpn.jsonl")).unwrap();
        assert!(text.contains("\"mirror\":\"gap\"") && text.contains("\"after_batch\":1,\"batch\":3"), "{text}");
        assert!(text.contains("\"mirror\":\"dropped\",\"ts\":1700000001000000,\"lines\":4"), "{text}");
        assert_eq!(v.gaps, 2);
        // rotation at the size limit: the file becomes .1, a new one starts
        let before = std::fs::metadata(d.join("vpn.jsonl")).unwrap().len();
        append(
            &d,
            &Batch { origin: "vpn", batch: 4, dropped: 0, lines: &["{\"d\":4}".to_string()] },
            before + 2,
            now + 2 * time::SEC,
            &mut v,
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(d.join("vpn.jsonl")).unwrap(), "{\"d\":4}\n");
        assert_eq!(std::fs::metadata(d.join("vpn.jsonl.1")).unwrap().len(), before);
        let held = held(&d);
        assert_eq!(held["vpn"].0, before + "{\"d\":4}\n".len() as u64);
        assert!(describe(&d)[0].starts_with("vpn: "));
        // names a peer can't use for a path
        assert!(append(&d, &Batch { origin: "../x", batch: 1, dropped: 0, lines: &[] }, 1 << 20, now, &mut MirrorView::default()).is_err());
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&d);
    }

    use std::os::unix::fs::PermissionsExt;
}
