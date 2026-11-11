//! What needed attention lately: every problem the Overview listed, with when it appeared
//! and when it went, kept for a week. In memory, like the sessions: a restart forgets it.
//!
//! A problem is its level and text; a count in the text ("3 high or critical alert(s)") is
//! left out of the identity, so a changing count is one problem, not a new one each time.
//! With a `STATE_DIR`, the list is written there whenever it changes and read back at start.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::time::{Micros, SEC};

/// A problem that went is kept this long after (`HISTORY_DAYS`, 7 by default).
const KEEP: Micros = 7 * 86_400 * SEC;
/// Problems kept at most (a flapping node could otherwise fill the memory).
const MAX: usize = 2000;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Problem {
    pub level: String,
    pub text: String,
    pub nodes: Vec<String>,
    pub first: Micros,
    pub last: Micros,
    pub gone: Option<Micros>,
}

/// The text without its count: "3 high or critical alert(s) in..." -> "high or critical
/// alert(s) in..."; a count is a number before a "(s)" word, as the page reads it too.
pub fn without_count(text: &str) -> String {
    let words: Vec<&str> = text.split(' ').collect();
    let count = words.iter().position(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_digit()));
    match count {
        Some(i) if words[i..].iter().any(|w| w.ends_with("(s)")) => {
            words.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, w)| *w).collect::<Vec<_>>().join(" ")
        }
        _ => text.to_string(),
    }
}

pub struct History {
    inner: Mutex<Vec<Problem>>,
    path: Option<PathBuf>,
    keep: Micros,
}

impl Default for History {
    fn default() -> Self {
        History { inner: Mutex::default(), path: None, keep: KEEP }
    }
}

impl History {
    /// With a directory, the history read from `attention-history.json` there, and written
    /// back whenever it changes.
    pub fn new(dir: Option<&std::path::Path>) -> Self {
        let path = dir.map(|d| d.join("attention-history.json"));
        let loaded: Vec<Problem> =
            path.as_deref().and_then(crate::store::load).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
        History { inner: Mutex::new(loaded), path, keep: KEEP }
    }

    /// Keeps problems that went for `days` instead of 7.
    pub fn keep_days(mut self, days: u32) -> Self {
        self.keep = Micros::from(days.clamp(1, 3650)) * 86_400 * SEC;
        self
    }

    /// The Overview's attention list as it stands now.
    pub fn observe(&self, attention: &[Value], now: Micros) {
        let mut list = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = list.clone();
        let mut present: HashSet<(String, String)> = HashSet::new();
        // the open problems by what they are (the latest of each): looking through the list
        // for every row took seconds, under the lock, once a node listed thousands
        let mut open: HashMap<(String, String), usize> =
            list.iter().enumerate().filter(|(_, p)| p.gone.is_none()).map(|(i, p)| ((p.level.clone(), p.text.clone()), i)).collect();
        for a in attention {
            let level = a["level"].as_str().unwrap_or("").to_string();
            let text = without_count(a["text"].as_str().unwrap_or(""));
            let node = a["node"].as_str().unwrap_or("").to_string();
            let key = (level, text);
            match open.get(&key) {
                Some(&i) => {
                    let p = &mut list[i];
                    p.last = now;
                    if !node.is_empty() && !p.nodes.contains(&node) {
                        p.nodes.push(node);
                    }
                }
                None => {
                    open.insert(key.clone(), list.len());
                    list.push(Problem {
                        level: key.0.clone(),
                        text: key.1.clone(),
                        nodes: if node.is_empty() { vec![] } else { vec![node] },
                        first: now,
                        last: now,
                        gone: None,
                    });
                }
            }
            present.insert(key);
        }
        for p in list.iter_mut() {
            if p.gone.is_none() && !present.contains(&(p.level.clone(), p.text.clone())) {
                p.gone = Some(now);
            }
        }
        list.retain(|p| p.gone.is_none_or(|g| now - g < self.keep));
        if list.len() > MAX {
            let extra = list.len() - MAX;
            list.drain(..extra);
        }
        if let Some(p) = &self.path {
            if *list != before {
                if let Ok(v) = serde_json::to_value(&*list) {
                    crate::store::save(p, &v);
                }
            }
        }
    }

    /// Every problem kept, the latest first.
    pub fn list(&self) -> Value {
        let list = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<&Problem> = list.iter().collect();
        out.sort_by_key(|p| std::cmp::Reverse((p.gone.unwrap_or(i64::MAX), p.last)));
        Value::Array(
            out.iter()
                .map(|p| json!({ "level": p.level, "text": p.text, "nodes": p.nodes, "first": p.first, "last": p.last, "gone": p.gone }))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn att(level: &str, node: &str, text: &str) -> Value {
        json!({ "level": level, "node": node, "node_id": "1", "text": text })
    }

    #[test]
    fn problems_appear_merge_and_go() {
        let h = History::default();
        let t0 = 1_793_300_000 * SEC;
        h.observe(
            &[
                att("warning", "a", "3 high or critical alert(s) in the last 24 hours"),
                att("critical", "b", "antivirus: 1 infected file(s) in the last scan"),
            ],
            t0,
        );
        h.observe(
            &[
                att("warning", "a", "5 high or critical alert(s) in the last 24 hours"),
                att("warning", "b", "1 high or critical alert(s) in the last 24 hours"),
            ],
            t0 + 60 * SEC,
        );
        let l = h.list();
        assert_eq!(l.as_array().unwrap().len(), 2, "a changed count is the same problem: {l}");
        let alerts = l.as_array().unwrap().iter().find(|p| p["level"] == "warning").unwrap();
        assert_eq!(alerts["text"], "high or critical alert(s) in the last 24 hours");
        assert_eq!(alerts["nodes"], json!(["a", "b"]));
        assert_eq!(alerts["last"], json!(t0 + 60 * SEC));
        assert!(alerts["gone"].is_null());
        let av = l.as_array().unwrap().iter().find(|p| p["level"] == "critical").unwrap();
        assert_eq!(av["gone"], json!(t0 + 60 * SEC), "not listed any more: gone");
        // back again later: a new entry, the old one stays until it ages out
        h.observe(&[att("critical", "b", "antivirus: 2 infected file(s) in the last scan")], t0 + 120 * SEC);
        assert_eq!(h.list().as_array().unwrap().iter().filter(|p| p["level"] == "critical").count(), 2);
        h.observe(&[], t0 + 200 * SEC);
        assert!(h.list().as_array().unwrap().iter().all(|p| !p["gone"].is_null()), "nothing listed: all gone");
        h.observe(&[], t0 + 200 * SEC + KEEP + SEC);
        assert_eq!(h.list().as_array().unwrap().len(), 0, "all gone for a week: forgotten");
    }

    #[test]
    fn kept_on_disk() {
        let d = std::env::temp_dir().join(format!("lgw-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let h = History::new(Some(&d));
        let t0 = 1_793_300_000 * SEC;
        h.observe(&[att("critical", "b", "antivirus: 1 infected file(s) in the last scan")], t0);
        let again = History::new(Some(&d));
        assert_eq!(again.list().as_array().unwrap().len(), 1, "read back after a restart");
        again.observe(&[], t0 + SEC);
        assert!(!History::new(Some(&d)).list()[0]["gone"].is_null(), "and written when it changes");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn counts_only_before_plural_words() {
        assert_eq!(without_count("disk /: 9% free"), "disk /: 9% free");
        assert_eq!(without_count("2 security update(s) pending"), "security update(s) pending");
        assert_eq!(
            without_count("cluster peer 203.0.113.20:7950 unreachable since 2026-10-30"),
            "cluster peer 203.0.113.20:7950 unreachable since 2026-10-30"
        );
    }
}
