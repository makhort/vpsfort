//! Honeypot hits in the console. Each node's vpsfort reads them from its actions log
//! (`honeypots 24h` / `honeypots 7d` on its console socket): the bans it decided itself whose
//! evidence is a hit on a honeypot port or the decoy site, so they last as long as the log
//! and a peer's copy of a ban isn't among them. Here they are checked, marked with their node
//! and merged, the newest first.
//!
//! What a node sends is shown as text only; still, long or odd strings are cut here.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::abuse::{clean, net_ok};
use crate::time::Micros;

/// Hits taken from one node (vpsfort sends its newest 10,000).
const MAX_NODE_HITS: usize = 10_000;
/// Hits sent to the page, of all the nodes together.
const MAX_HITS: usize = 10_000;
/// Evidence lines kept per ban: vpsfort keeps 8 per address, and a network ban lists its
/// members' too.
const MAX_LINES: usize = 200;
/// Evidence lines taken from one node in all: its 10,000 bans carry a few each. A node that
/// sent 200 for every ban would have the console hold 800 MB of them.
const MAX_NODE_LINES: usize = 50_000;

#[derive(Deserialize)]
struct NodeReport {
    #[serde(default)]
    total: usize,
    #[serde(default)]
    hits: Vec<Hit>,
}

/// One ban with a honeypot hit in its evidence: the fields of a decision the page shows.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Hit {
    #[serde(default)]
    pub ts: Micros,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Micros>,
    #[serde(default)]
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_id: String,
}

/// One node's hits, checked.
#[derive(Clone, Debug)]
pub struct Parsed {
    /// Bans with a hit in the window, also those not sent.
    pub total: usize,
    pub hits: Vec<Hit>,
}

/// Reads a node's hits (vpsfort's JSON).
pub fn parse(text: &str) -> Result<Parsed> {
    let r: NodeReport = serde_json::from_str(text).context("not a list of honeypot hits")?;
    let (mut hits, mut valid, mut lines) = (Vec::new(), 0usize, 0usize);
    for mut h in r.hits.into_iter().take(MAX_NODE_HITS) {
        if !net_ok(&h.target) {
            continue;
        }
        valid += 1;
        if lines >= MAX_NODE_LINES {
            continue; // counted, not kept: they come the newest first
        }
        h.kind = clean(&h.kind, 20);
        h.severity = clean(&h.severity, 20);
        h.category = h.category.map(|c| clean(&c, 40));
        h.message = clean(&h.message, 500);
        h.evidence.truncate(MAX_LINES.min(MAX_NODE_LINES - lines));
        lines += h.evidence.len();
        for l in &mut h.evidence {
            *l = clean(l, 400);
        }
        // only the console says which node it is
        h.node.clear();
        h.node_id.clear();
        hits.push(h);
    }
    Ok(Parsed { total: r.total.max(valid), hits })
}

/// How asking one node went.
#[derive(Clone, Debug, Serialize)]
pub struct NodeState {
    pub node: String,
    pub node_id: String,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Every node's hits of a window.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub window: String,
    pub generated: Micros,
    /// Bans with a hit, also those not sent.
    pub total: usize,
    /// The newest first.
    pub hits: Vec<Hit>,
    pub nodes: Vec<NodeState>,
}

/// One report of what each node (id, name) answered.
pub fn merge(window: &str, parts: Vec<(String, String, Result<Parsed, String>)>, now: Micros) -> Report {
    let (mut hits, mut nodes, mut total) = (Vec::new(), Vec::new(), 0usize);
    for (id, name, got) in parts {
        match got {
            Ok(p) => {
                total = total.saturating_add(p.total);
                nodes.push(NodeState { node: name.clone(), node_id: id.clone(), total: p.total, error: None });
                hits.extend(p.hits.into_iter().map(|mut h| {
                    h.node.clone_from(&name);
                    h.node_id.clone_from(&id);
                    h
                }));
            }
            Err(e) => nodes.push(NodeState { node: name, node_id: id, total: 0, error: Some(clean(&e, 300)) }),
        }
    }
    hits.sort_by_key(|h: &Hit| std::cmp::Reverse(h.ts));
    hits.truncate(MAX_HITS);
    Report { window: window.to_string(), generated: now, total, hits, nodes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_marked_and_merged_the_newest_first() {
        let node = |ts: i64, target: &str| {
            format!(
                r#"{{"from":1,"to":9,"total":7,"hits":[{{"ts":{ts},"kind":"ban","severity":"high","target":"{target}","until":99,"applied":true,
                   "category":"tripwire","message":"ban\u001b[2J x","evidence":["11-09 02:33:57 connected to honeypot TCP/23, sent nothing","\u001b]52;evil"],
                   "node":"forged","node_id":"9","notice":{{"x":1}}}}]}}"#
            )
        };
        let a = parse(&node(5, "203.0.113.1")).unwrap();
        let b = parse(&node(8, "203.0.113.0/24")).unwrap();
        assert_eq!((a.total, a.hits.len(), a.hits[0].node.as_str()), (7, 1, ""), "the node's own say about its name is dropped");
        assert_eq!(a.hits[0].message, "ban[2J x", "no control characters");
        assert!(a.hits[0].evidence[1].chars().all(|c| !c.is_control()));
        let r = merge(
            "24h",
            vec![("0".into(), "a".into(), Ok(a)), ("1".into(), "b".into(), Ok(b)), ("2".into(), "c".into(), Err("older".into()))],
            10,
        );
        assert_eq!((r.window.as_str(), r.generated, r.total), ("24h", 10, 14));
        let order: Vec<(&str, &str, &str)> = r.hits.iter().map(|h| (h.node.as_str(), h.node_id.as_str(), h.target.as_str())).collect();
        assert_eq!(order, [("b", "1", "203.0.113.0/24"), ("a", "0", "203.0.113.1")]);
        assert_eq!((r.nodes[2].node.as_str(), r.nodes[2].error.as_deref()), ("c", Some("older")));
        // what the page reads of a decision is there
        let v = serde_json::to_value(&r).unwrap();
        for k in ["ts", "kind", "severity", "target", "until", "applied", "category", "message", "evidence", "node", "node_id"] {
            assert!(v["hits"][0].get(k).is_some(), "{k}");
        }
    }

    #[test]
    fn a_network_bans_many_lines_are_kept() {
        let lines: Vec<String> =
            (0..60).map(|i| format!(r#""11-09 02:33:{i:02} 192.0.2.{i} connected to honeypot TCP/23, sent nothing""#)).collect();
        let p = parse(&format!(r#"{{"hits":[{{"ts":1,"target":"192.0.2.0/24","evidence":[{}]}}]}}"#, lines.join(","))).unwrap();
        assert_eq!(p.hits[0].evidence.len(), 60);
    }

    #[test]
    fn a_nodes_evidence_lines_are_bounded_in_all() {
        let lines: Vec<String> =
            (0..MAX_LINES).map(|i| format!(r#""192.0.2.{} connected to honeypot TCP/23, sent nothing""#, i % 250)).collect();
        let hit = |ts: usize| format!(r#"{{"ts":{ts},"target":"192.0.2.0/24","evidence":[{}]}}"#, lines.join(","));
        let many: Vec<String> = (0..300).rev().map(hit).collect();
        let p = parse(&format!(r#"{{"hits":[{}]}}"#, many.join(","))).unwrap();
        assert_eq!(p.hits.iter().map(|h| h.evidence.len()).sum::<usize>(), MAX_NODE_LINES);
        assert_eq!((p.hits.len(), p.hits[0].ts, p.total), (MAX_NODE_LINES / MAX_LINES, 299, 300), "the newest are kept, all are counted");
    }

    #[test]
    fn what_cannot_be_a_hit_is_left_out() {
        assert!(parse("not json").is_err());
        assert_eq!(parse("{}").unwrap().hits.len(), 0);
        let p = parse(r#"{"total":0,"hits":[{"ts":1,"target":"<script>"},{"ts":2,"target":"192.0.2.1"}]}"#).unwrap();
        assert_eq!((p.total, p.hits.len(), p.hits[0].ts), (1, 1, 2), "the count is at least what came");
        let many: Vec<String> = (0..12_000).map(|i| format!(r#"{{"ts":{i},"target":"192.0.2.1"}}"#)).collect();
        let p = parse(&format!(r#"{{"hits":[{}]}}"#, many.join(","))).unwrap();
        assert_eq!(p.hits.len(), MAX_NODE_HITS);
        let lots = |id: &str| (id.to_string(), id.to_string(), Ok(Parsed { total: p.total, hits: p.hits.clone() }));
        let r = merge("7d", vec![lots("0"), lots("1")], 0);
        assert_eq!((r.hits.len(), r.total), (MAX_HITS, 2 * MAX_NODE_HITS), "the page gets a bound, and the true count");
    }
}
