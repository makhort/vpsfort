//! nftables rulesets of the host's own (Debian's `nftables.conf`, a hand-written table),
//! read for the exposure watch as `nft -j` prints them: the filter chains on the input hook
//! in priority order, each followed like the kernel does (rules in order, jumps and gotos,
//! the chain's policy), so a listener is "allowed by nftables" or "blocked by nftables"
//! instead of "nftables rules not read". A match this reader doesn't know makes an accept
//! count and a drop not, so exposure is over- rather than under-reported, as with iptables.
//! An `accept` ends one base chain only: a packet is let in when no base chain drops it.

use std::collections::HashMap;

use serde_json::Value;

use crate::event::Proto;
use crate::exposure::{internal_interface, sources, Accepted};

/// Most chains followed (base chains and the ones they jump to).
const MAX_CHAINS: usize = 64;

#[derive(Debug, Default, Clone)]
pub struct NftRule {
    /// tcp or udp; None for every protocol.
    proto: Option<Proto>,
    /// ICMP and the like: never a listener's.
    other_proto: bool,
    /// Destination ports and ranges; empty for every port.
    ports: Vec<(u16, u16)>,
    /// IPv4 only (`ip saddr`, `meta nfproto ipv4`) or IPv6 only; None for both.
    v4: Option<bool>,
    verdict: Verdict,
    /// A rate limit on the way: it acts on some connection attempts only.
    limit: bool,
    /// Doesn't concern new connections from anywhere to a public address: ignored.
    skip: bool,
    /// Has a match this reader doesn't know.
    unsure: bool,
    /// Only for these sources.
    from: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq)]
enum Verdict {
    #[default]
    None,
    Accept,
    Drop,
    Jump(String),
    Goto(String),
    Return,
}

#[derive(Debug, Clone)]
pub struct NftChain {
    pub family: String,
    pub table: String,
    pub name: String,
    /// Base chains: the hook's priority; None for a chain jumped to.
    pub priority: Option<i64>,
    pub policy_drop: bool,
    /// `nft` couldn't list it (an odd name): it counts as filtering, and is passed through.
    pub unreadable: bool,
    rules: Vec<NftRule>,
}

/// The input-hook filter chains and the chains they reach, by (family, table, name).
#[derive(Debug, Default)]
pub struct NftRules {
    chains: HashMap<(String, String, String), NftChain>,
    /// The base chains in priority order (lower first, as the kernel runs them).
    base: Vec<(String, String, String)>,
}

/// The base chains `nft -j list chains` names: input-hook filter chains other than the
/// `filter` tables iptables-nft keeps for iptables, with (family, table, name, priority,
/// drops by default).
pub fn base_chains(json: &str) -> Vec<(String, String, String, i64, bool)> {
    let Ok(v) = serde_json::from_str::<Value>(json) else { return vec![] };
    let items = v["nftables"].as_array().map(Vec::as_slice).unwrap_or_default();
    let mut out: Vec<_> = items
        .iter()
        .filter_map(|item| {
            let c = &item["chain"];
            let field = |k: &str| c[k].as_str();
            let (family, table) = (field("family")?, field("table")?);
            if field("hook")? != "input" || field("type")? != "filter" || (matches!(family, "ip" | "ip6") && table == "filter") {
                return None;
            }
            Some((
                family.to_string(),
                table.to_string(),
                field("name")?.to_string(),
                c["prio"].as_i64().unwrap_or(0),
                field("policy") == Some("drop"),
            ))
        })
        .collect();
    out.sort_by_key(|c| c.3);
    out
}

/// A table or chain name safe to hand back to nft, which reads its arguments as one command
/// line: a name with blanks, quotes or `;` (or one starting with `-`) is never passed on.
pub fn plain_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('-') && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

impl NftRules {
    /// Builds the rules from `nft -j list chains` and, for each chain needed, `list` giving
    /// `nft -j list chain <family> <table> <name>` (None: not readable).
    pub fn read(chains_json: &str, mut list: impl FnMut(&str, &str, &str) -> Option<String>) -> NftRules {
        let mut rules = NftRules::default();
        let mut queue: Vec<(String, String, String, Option<i64>, bool)> =
            base_chains(chains_json).into_iter().map(|(f, t, n, p, d)| (f, t, n, Some(p), d)).collect();
        let mut i = 0;
        while i < queue.len() && rules.chains.len() < MAX_CHAINS {
            let (family, table, name, priority, policy_drop) = queue[i].clone();
            i += 1;
            let key = (family.clone(), table.clone(), name.clone());
            if rules.chains.contains_key(&key) {
                continue;
            }
            let ok = [&family, &table, &name].iter().all(|n| plain_name(n));
            let parsed = if ok { list(&family, &table, &name).map(|t| parse_chain(&t, &name)) } else { None };
            let (rules_of, unreadable) = match parsed {
                Some(r) => (r, false),
                None => (vec![], true),
            };
            for r in &rules_of {
                if let Verdict::Jump(t) | Verdict::Goto(t) = &r.verdict {
                    queue.push((family.clone(), table.clone(), t.clone(), None, false));
                }
            }
            rules.chains.insert(key.clone(), NftChain { family, table, name, priority, policy_drop, unreadable, rules: rules_of });
            if priority.is_some() {
                rules.base.push(key);
            }
        }
        rules
    }

    /// Whether anything filters: a base chain that drops by default, or a rule reached that
    /// drops new connections from everyone (not only some sources or rates).
    pub fn filters(&self) -> bool {
        self.base.iter().filter_map(|k| self.chains.get(k)).any(|c| c.policy_drop || c.unreadable)
            || self.reachable().iter().any(|r| r.verdict == Verdict::Drop && r.from.is_none() && !r.skip && !r.limit && !r.unsure)
    }

    pub fn is_empty(&self) -> bool {
        self.base.is_empty()
    }

    /// Every rule of the base chains and the chains they reach.
    fn reachable(&self) -> Vec<&NftRule> {
        self.chains.values().flat_map(|c| c.rules.iter()).collect()
    }

    /// For a port closed to everyone: the accept rules reached that let some sources in.
    pub fn accepts_some(&self, proto: Proto, port: u16, v4: bool) -> Option<String> {
        let rules: Vec<&NftRule> = self
            .reachable()
            .into_iter()
            .filter(|r| r.verdict == Verdict::Accept && r.from.is_some() && r.matches_port(proto, port, v4))
            .collect();
        let what = rules.first()?.what().unwrap_or_else(|| "all".into());
        Some(format!("accept {what} from {}", sources(rules.iter().filter_map(|r| r.from.as_deref()))))
    }

    /// The rule letting a new connection from anywhere to `port` in, for IPv4 (`v4`) or
    /// IPv6: None when a base chain drops it.
    pub(crate) fn accepts(&self, proto: Proto, port: u16, v4: bool) -> Option<Accepted> {
        let (mut limited, mut first): (bool, Option<(String, bool)>) = (false, None);
        for key in &self.base {
            let Some(chain) = self.chains.get(key) else { continue };
            if !family_fits(&chain.family, v4) {
                continue;
            }
            let base = chain_label(chain);
            match self.walk(key, proto, port, v4, None, 0, &mut limited, &base) {
                Some(Some(acc)) => first.get_or_insert(acc),
                Some(None) => return None,
                None if chain.policy_drop => return None,
                None => continue,
            };
        }
        let (rule, range) = first.unwrap_or_else(|| ("policy accept".into(), false));
        Some(Accepted { rule, limited, range })
    }

    /// Some(Some((label, through a range))): accepted; Some(None): dropped; None: through the
    /// chain (return, or its end).
    #[allow(clippy::too_many_arguments)]
    fn walk<'a>(
        &'a self,
        key: &(String, String, String),
        proto: Proto,
        port: u16,
        v4: bool,
        outer: Option<&'a NftRule>,
        depth: u8,
        limited: &mut bool,
        base: &str,
    ) -> Option<Option<(String, bool)>> {
        if depth > 10 {
            return None;
        }
        let chain = self.chains.get(key)?;
        for r in chain.rules.iter().filter(|r| r.matches(proto, port, v4)) {
            let spec = if r.proto.is_some() { Some(r) } else { outer };
            match &r.verdict {
                Verdict::Accept => {
                    *limited |= r.limit;
                    let via = if chain.priority.is_some() { String::new() } else { format!(" via {}", chain.name) };
                    let what = spec.and_then(NftRule::what).unwrap_or_else(|| "all".into());
                    return Some(Some((format!("accept {what} ({base}){via}"), spec.is_some_and(|s| s.by_range(port)))));
                }
                Verdict::Drop if r.limit || r.unsure => *limited |= r.limit,
                Verdict::Drop => return Some(None),
                Verdict::Return => return None,
                Verdict::Jump(t) | Verdict::Goto(t) => {
                    let target = (key.0.clone(), key.1.clone(), t.clone());
                    match self.walk(&target, proto, port, v4, spec, depth + 1, limited, base) {
                        Some(v) => return Some(v),
                        None if matches!(r.verdict, Verdict::Goto(_)) => return None,
                        None => {}
                    }
                }
                Verdict::None => {}
            }
        }
        None
    }
}

/// "inet filter input": where a rule sits.
fn chain_label(c: &NftChain) -> String {
    format!("{} {} {}", c.family, c.table, c.name)
}

fn family_fits(family: &str, v4: bool) -> bool {
    match family {
        "ip" => v4,
        "ip6" => !v4,
        _ => true,
    }
}

impl NftRule {
    fn matches(&self, proto: Proto, port: u16, v4: bool) -> bool {
        self.from.is_none() && self.matches_port(proto, port, v4)
    }

    fn matches_port(&self, proto: Proto, port: u16, v4: bool) -> bool {
        !self.skip
            && !self.other_proto
            && self.v4.is_none_or(|f| f == v4)
            && self.proto.is_none_or(|p| p == proto)
            && (self.ports.is_empty() || self.ports.iter().any(|(lo, hi)| (*lo..=*hi).contains(&port)))
    }

    fn what(&self) -> Option<String> {
        let proto = match self.proto? {
            Proto::Udp => "udp",
            _ => "tcp",
        };
        let ports: Vec<String> = self.ports.iter().map(|(lo, hi)| if lo == hi { lo.to_string() } else { format!("{lo}-{hi}") }).collect();
        Some(if ports.is_empty() { proto.to_string() } else { format!("{}/{proto}", ports.join(",")) })
    }

    fn by_range(&self, port: u16) -> bool {
        let hit = |single: bool| self.ports.iter().any(|(lo, hi)| (lo == hi) == single && (*lo..=*hi).contains(&port));
        !hit(true) && hit(false)
    }
}

/// The rules of one chain from `nft -j list chain ...`; verdict maps (`tcp dport vmap { 22 :
/// accept }`) become one rule per entry.
pub fn parse_chain(json: &str, chain: &str) -> Vec<NftRule> {
    let Ok(v) = serde_json::from_str::<Value>(json) else { return vec![] };
    let items = v["nftables"].as_array().map(Vec::as_slice).unwrap_or_default();
    let mut out = Vec::new();
    for item in items {
        let r = &item["rule"];
        if r["chain"].as_str() != Some(chain) {
            continue;
        }
        let exprs = r["expr"].as_array().map(Vec::as_slice).unwrap_or_default();
        out.extend(parse_exprs(exprs));
    }
    out
}

fn parse_exprs(exprs: &[Value]) -> Vec<NftRule> {
    let mut rule = NftRule::default();
    let mut vmap: Vec<(Vec<(u16, u16)>, Verdict)> = Vec::new();
    for e in exprs {
        if let Some(m) = e.get("match") {
            match_expr(&mut rule, m);
        } else if e.get("limit").is_some() {
            rule.limit = true;
        } else if e.get("accept").is_some() {
            rule.verdict = Verdict::Accept;
        } else if e.get("drop").is_some() || e.get("reject").is_some() {
            rule.verdict = Verdict::Drop;
        } else if e.get("return").is_some() {
            rule.verdict = Verdict::Return;
        } else if let Some(t) = e["jump"]["target"].as_str() {
            rule.verdict = Verdict::Jump(t.to_string());
        } else if let Some(t) = e["goto"]["target"].as_str() {
            rule.verdict = Verdict::Goto(t.to_string());
        } else if let Some(vm) = e.get("vmap") {
            // `tcp dport vmap { 22 : accept, 80 : jump web }`
            let key_is_dport = vm["key"]["payload"]["field"].as_str() == Some("dport");
            if let Some(proto) = vm["key"]["payload"]["protocol"].as_str() {
                set_proto(&mut rule, proto);
            }
            let entries = vm["data"]["set"].as_array().map(Vec::as_slice).unwrap_or_default();
            for pair in entries {
                let (Some(k), Some(v)) = (pair.get(0), pair.get(1)) else { continue };
                let verdict = if v.get("accept").is_some() {
                    Verdict::Accept
                } else if v.get("drop").is_some() || v.get("reject").is_some() {
                    Verdict::Drop
                } else if let Some(t) = v["jump"]["target"].as_str() {
                    Verdict::Jump(t.to_string())
                } else if let Some(t) = v["goto"]["target"].as_str() {
                    Verdict::Goto(t.to_string())
                } else {
                    continue;
                };
                match (key_is_dport, port_value(k)) {
                    (true, Some(ports)) => vmap.push((ports, verdict)),
                    _ => rule.unsure = true,
                }
            }
        } else if e.get("meter").is_some() {
            // a rate per source inside: the verdict applies to some packets only
            rule.limit = true;
        } else if e.get("counter").is_some() || e.get("log").is_some() || e.get("notrack").is_some() {
            // says nothing about what gets in
        } else {
            rule.unsure = true;
        }
    }
    if vmap.is_empty() {
        return vec![rule];
    }
    vmap.into_iter().map(|(ports, verdict)| NftRule { ports, verdict, ..rule.clone() }).collect()
}

fn set_proto(rule: &mut NftRule, proto: &str) {
    match proto {
        "tcp" | "6" => rule.proto = Some(Proto::Tcp),
        "udp" | "17" => rule.proto = Some(Proto::Udp),
        _ => rule.other_proto = true,
    }
}

/// A port, a set of ports and ranges, or a range, as the right side of a match.
fn port_value(v: &Value) -> Option<Vec<(u16, u16)>> {
    let one = |v: &Value| -> Option<(u16, u16)> {
        if let Some(n) = v.as_u64() {
            return u16::try_from(n).ok().map(|p| (p, p));
        }
        let r = v["range"].as_array()?;
        Some((u16::try_from(r.first()?.as_u64()?).ok()?, u16::try_from(r.get(1)?.as_u64()?).ok()?))
    };
    if let Some(set) = v["set"].as_array() {
        return set.iter().map(one).collect();
    }
    one(v).map(|p| vec![p])
}

/// A `match` expression: what it says about the rule.
fn match_expr(rule: &mut NftRule, m: &Value) {
    let negated = m["op"].as_str() == Some("!=");
    let (left, right) = (&m["left"], &m["right"]);
    let right_strings = || -> Vec<String> {
        match right {
            Value::String(s) => vec![s.clone()],
            Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            v => v["set"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default(),
        }
    };
    if let Some(p) = left.get("payload") {
        let (proto, field) = (p["protocol"].as_str().unwrap_or(""), p["field"].as_str().unwrap_or(""));
        match (proto, field) {
            ("tcp" | "udp" | "th" | "sctp" | "dccp", "dport") => {
                if proto != "th" {
                    set_proto(rule, proto);
                }
                match (negated, port_value(right)) {
                    (false, Some(ports)) => rule.ports = ports,
                    _ => rule.unsure = true,
                }
            }
            ("tcp" | "udp" | "th" | "sctp" | "dccp", "sport") => rule.skip = true,
            ("ip", "protocol") | ("ip6", "nexthdr") => {
                rule.v4 = Some(proto == "ip");
                if negated {
                    rule.unsure = true;
                } else {
                    for p in right_strings() {
                        set_proto(rule, &p);
                    }
                    if right_strings().iter().any(|p| p == "tcp") && right_strings().iter().any(|p| p == "udp") {
                        rule.proto = None;
                    }
                }
            }
            ("ip" | "ip6", "saddr") => {
                rule.v4 = Some(proto == "ip");
                if negated {
                    rule.unsure = true;
                } else {
                    rule.from = Some(match right {
                        Value::String(s) => s.clone(),
                        v if v.get("prefix").is_some() => {
                            format!("{}/{}", v["prefix"]["addr"].as_str().unwrap_or("?"), v["prefix"]["len"].as_u64().unwrap_or(0))
                        }
                        v if v.get("set").is_some() => format!("{} sources", v["set"].as_array().map_or(0, Vec::len)),
                        _ => "some sources".into(),
                    });
                }
            }
            ("ip" | "ip6", "daddr") => {
                rule.v4 = Some(proto == "ip");
                // to loopback: not a public address's traffic (a private one may be where a
                // cloud host's public address is NATed to)
                let loopback = matches!(right.as_str(), Some(s) if s.starts_with("127.") || s == "::1");
                if loopback && !negated {
                    rule.skip = true;
                } else {
                    rule.unsure = true;
                }
            }
            ("tcp", "flags") => {
                // `tcp flags syn` is a new connection; anything else is odd
                // (`tcp flags != syn` is everything but one)
                if negated || !(right_strings().iter().any(|f| f == "syn") || right["&"].is_array() || right.as_str() == Some("syn")) {
                    rule.unsure = true;
                }
            }
            _ => rule.unsure = true,
        }
        return;
    }
    if let Some(key) = left["meta"]["key"].as_str() {
        match key {
            "l4proto" => {
                if negated {
                    rule.unsure = true;
                } else {
                    let protos = right_strings();
                    if protos.iter().any(|p| p == "tcp") && protos.iter().any(|p| p == "udp") {
                        rule.proto = None;
                    } else {
                        for p in &protos {
                            set_proto(rule, p);
                        }
                    }
                }
            }
            "nfproto" => match (negated, right.as_str()) {
                (false, Some("ipv4")) => rule.v4 = Some(true),
                (false, Some("ipv6")) => rule.v4 = Some(false),
                _ => rule.unsure = true,
            },
            "iifname" | "iif" | "iifgroup" | "iiftype" => {
                let names = right_strings();
                if !negated && !names.is_empty() && names.iter().all(|n| internal_interface(n)) {
                    rule.skip = true;
                } else if negated || names.iter().any(|n| internal_interface(n)) {
                    rule.unsure = true;
                }
            }
            "oifname" | "oif" => rule.skip = true,
            _ => rule.unsure = true,
        }
        return;
    }
    if let Some(key) = left["ct"]["key"].as_str() {
        match key {
            "state" => {
                let states = right_strings();
                let new = states.iter().any(|s| s == "new");
                if negated {
                    rule.unsure = true;
                } else if !new {
                    rule.skip = true;
                }
            }
            "status" | "direction" | "mark" | "zone" | "label" => rule.unsure = true,
            _ => rule.unsure = true,
        }
        return;
    }
    if left.get("fib").is_some() {
        // `fib daddr type local` is this host's traffic (fine); anything else is odd
        let local = right.as_str() == Some("local") && !negated;
        if !local {
            rule.unsure = true;
        }
        return;
    }
    rule.unsure = true;
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAINS: &str = r#"{"nftables":[{"metainfo":{}},
      {"chain":{"family":"inet","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
      {"chain":{"family":"inet","table":"filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
      {"chain":{"family":"inet","table":"filter","name":"web","handle":3}},
      {"chain":{"family":"inet","table":"vpsfort","name":"bans","handle":4,"type":"filter","hook":"prerouting","prio":-151,"policy":"accept"}},
      {"chain":{"family":"ip","table":"filter","name":"INPUT","handle":5,"type":"filter","hook":"input","prio":0,"policy":"accept"}},
      {"chain":{"family":"ip","table":"early","name":"guard","handle":6,"type":"filter","hook":"input","prio":-10,"policy":"accept"}}
    ]}"#;

    fn input() -> String {
        // Debian's nftables.conf style: lo, established, ssh, web through a jump, a rate-limited
        // port, a source-limited port, a UDP range, a vmap, an unknown match on a drop
        r#"{"nftables":[{"metainfo":{}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"accept":null}]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":11,"expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":12,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},{"limit":{"rate":10,"per":"minute"}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":13,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[80,443]}}},{"jump":{"target":"web"}}]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":14,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"203.0.113.0","len":24}}}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":7946}},{"accept":null}]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":15,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[50000,50100]}}},{"accept":null}]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":16,"expr":[{"vmap":{"key":{"payload":{"protocol":"tcp","field":"dport"}},"data":{"set":[[5222,{"accept":null}],[3306,{"drop":null}]]}}}]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":17,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},{"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":7}},{"drop":null}]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":18,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},{"accept":null}]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":19,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv6"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":9000}},{"accept":null}]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":20,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":25}},{"reject":{"type":"tcp reset"}}]}}
        ]}"#.to_string()
    }

    fn web() -> String {
        r#"{"nftables":[{"rule":{"family":"inet","table":"filter","chain":"web","handle":30,"expr":[{"counter":{}},{"accept":null}]}}]}"#
            .into()
    }

    fn guard() -> String {
        // an earlier base chain that drops one port for everyone, and returns otherwise
        r#"{"nftables":[{"rule":{"family":"ip","table":"early","chain":"guard","handle":40,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":5222}},{"drop":null}]}}]}"#.into()
    }

    fn rules() -> NftRules {
        NftRules::read(CHAINS, |family, table, name| match (family, table, name) {
            ("inet", "filter", "input") => Some(input()),
            ("inet", "filter", "web") => Some(web()),
            ("ip", "early", "guard") => Some(guard()),
            _ => None,
        })
    }

    #[test]
    fn base_chains_are_input_filters_in_priority_order() {
        let b = base_chains(CHAINS);
        let names: Vec<&str> = b.iter().map(|c| c.2.as_str()).collect();
        assert_eq!(names, ["guard", "input"], "forward, prerouting and iptables-nft's INPUT left out; priority order");
        assert!(b[1].4 && !b[0].4);
        assert!(plain_name("input") && !plain_name("in put") && !plain_name("-x") && !plain_name("a;b"));
    }

    #[test]
    fn rules_read_like_the_kernel() {
        let r = rules();
        assert!(r.filters());
        let acc = |rule: &str, limited, range| Some(Accepted { rule: rule.into(), limited, range });
        assert_eq!(r.accepts(Proto::Tcp, 22, true), acc("accept 22/tcp (inet filter input)", true, false), "rate-limited");
        assert_eq!(r.accepts(Proto::Tcp, 443, true), acc("accept 80,443/tcp (inet filter input) via web", false, false));
        assert_eq!(r.accepts(Proto::Udp, 50050, true), acc("accept 50000-50100/udp (inet filter input)", false, true), "a range: dynamic");
        assert_eq!(r.accepts(Proto::Udp, 443, true), None, "the web rule is tcp only");
        assert_eq!(r.accepts(Proto::Tcp, 7946, true), None, "from some sources only");
        assert_eq!(r.accepts_some(Proto::Tcp, 7946, true).as_deref(), Some("accept 7946/tcp from 203.0.113.0/24"));
        assert_eq!(r.accepts(Proto::Tcp, 5222, true), None, "the earlier base chain drops it for IPv4");
        assert_eq!(r.accepts(Proto::Tcp, 5222, false), acc("accept 5222/tcp (inet filter input)", false, false), "the vmap, for IPv6");
        assert_eq!(r.accepts(Proto::Tcp, 3306, true), None, "the vmap drops it");
        assert_eq!(r.accepts(Proto::Tcp, 25, true), None, "rejected");
        assert_eq!(
            r.accepts(Proto::Tcp, 8443, true).map(|a| a.rule),
            Some("accept 8443/tcp (inet filter input)".into()),
            "the unsure drop doesn't count"
        );
        assert_eq!(r.accepts(Proto::Tcp, 9000, true), None, "IPv6 only");
        assert!(r.accepts(Proto::Tcp, 9000, false).is_some());
        assert_eq!(r.accepts(Proto::Tcp, 8080, true), None, "the policy drops it; lo and established rules don't count");
    }

    #[test]
    fn an_accepting_table_with_no_rules_does_not_filter() {
        let chains = r#"{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}}]}"#;
        let r = NftRules::read(chains, |_, _, _| Some(r#"{"nftables":[]}"#.into()));
        assert!(!r.filters() && !r.is_empty());
        assert_eq!(r.accepts(Proto::Tcp, 22, true).map(|a| a.rule), Some("policy accept".into()));
        // a chain that can't be read counts as filtering
        let r = NftRules::read(chains, |_, _, _| None);
        assert!(r.filters());
        assert!(r.accepts(Proto::Tcp, 22, true).is_some(), "and is passed through: the listener counts as reachable");
    }
}
