//! The nodes' daily digests, the last two weeks of them, in the console's memory: the
//! admins' mailbox is otherwise the only copy. A day's text is taken when the digest is
//! shown, and once a day near the end of it (UTC) for every node: the console's only
//! traffic to the nodes while nobody looks. With a `STATE_DIR`, they are written there
//! (`digests.json`) and read back at start.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::time::{self, Micros, SEC};

/// Days kept per node.
pub const KEEP_DAYS: usize = 14;
/// A day's digest is taken this many minutes before the UTC day ends.
const BEFORE_MIDNIGHT: i64 = 15;

pub struct Digests {
    /// Per node id: (day, text), oldest first.
    inner: Mutex<HashMap<String, VecDeque<(String, String)>>>,
    path: Option<PathBuf>,
    keep: usize,
}

impl Default for Digests {
    fn default() -> Self {
        Digests { inner: Mutex::default(), path: None, keep: KEEP_DAYS }
    }
}

/// The UTC day of a time, `YYYY-MM-DD`.
pub fn day_of(t: Micros) -> String {
    let (y, m, d) = time::ymd(t);
    format!("{y:04}-{m:02}-{d:02}")
}

impl Digests {
    /// With a directory, the digests read from `digests.json` there, and written back at
    /// every change.
    pub fn new(dir: Option<&std::path::Path>) -> Self {
        let path = dir.map(|d| d.join("digests.json"));
        let loaded: HashMap<String, VecDeque<(String, String)>> =
            path.as_deref().and_then(crate::store::load).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
        Digests { inner: Mutex::new(loaded), path, keep: KEEP_DAYS }
    }

    /// Keeps `days` per node instead of 14.
    pub fn keep_days(mut self, days: u32) -> Self {
        self.keep = days.clamp(1, 3650) as usize;
        self
    }

    /// `text` is `day`'s digest of node `id` as it stands (a later copy of the same day
    /// replaces the earlier).
    pub fn keep(&self, id: &str, day: &str, text: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let days = inner.entry(id.to_string()).or_default();
        match days.iter_mut().find(|(d, _)| d == day) {
            Some((_, t)) => *t = text.to_string(),
            None => {
                days.push_back((day.to_string(), text.to_string()));
                while days.len() > self.keep {
                    days.pop_front();
                }
            }
        }
        if let Some(p) = &self.path {
            if let Ok(v) = serde_json::to_value(&*inner) {
                crate::store::save(p, &v);
            }
        }
    }

    /// Node `id`'s digests, the latest day first.
    pub fn list(&self, id: &str) -> Value {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let days =
            inner.get(id).map(|d| d.iter().rev().map(|(day, text)| json!({ "day": day, "text": text })).collect()).unwrap_or_default();
        Value::Array(days)
    }
}

/// Keeps every node's digest once a day, shortly before the UTC day ends.
pub fn collect_daily(console: Arc<crate::console::Console>) {
    thread::spawn(move || {
        let mut done = String::new();
        loop {
            thread::sleep(Duration::from_secs(300));
            let now = time::now();
            let minute_of_day = (now / (60 * SEC)).rem_euclid(24 * 60);
            let day = day_of(now);
            if minute_of_day < 24 * 60 - BEFORE_MIDNIGHT || done == day {
                continue;
            }
            for n in console.fleet.view() {
                if let Ok(text) = console.fleet.digest(&n.id) {
                    console.digests.keep(&n.id, &day, &text);
                }
            }
            done = day;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_weeks_per_node_latest_first() {
        let d = Digests::default();
        for i in 0..20 {
            d.keep("1", &format!("2026-10-{:02}", i + 1), &format!("day {i}"));
        }
        d.keep("1", "2026-10-20", "day 19 again");
        let l = d.list("1");
        let l = l.as_array().unwrap();
        assert_eq!(l.len(), KEEP_DAYS);
        assert_eq!(l[0]["day"], "2026-10-20");
        assert_eq!(l[0]["text"], "day 19 again", "the same day is replaced");
        assert_eq!(l[KEEP_DAYS - 1]["day"], "2026-10-07");
        assert_eq!(d.list("2").as_array().unwrap().len(), 0);
        assert_eq!(day_of(1_793_364_189 * SEC), "2026-10-30");
        let dir = std::env::temp_dir().join(format!("lgw-digests-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let kept = Digests::new(Some(&dir));
        kept.keep("1", "2026-10-30", "the day");
        assert_eq!(Digests::new(Some(&dir)).list("1")[0]["text"], "the day", "read back after a restart");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
