// What the page works out (core.js).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  abuseRows, abuseText, abuseSubject, mailto, parseRdap, plainEmail, csv, linkify, parseHash, queryFor, applyQuery,
  drift, niceMax, duration, mergePlaces, reportedSources, brief, browserName, groupAttention, reoffended, viewTitle, mapMarkers,
} from "../core.js";

const T = 1793000000000000; // 2026-10-26 07:33 UTC (vpsfort's microseconds)
const source = (net, events, extra = {}) => ({
  net, first: T, last: T + 60e6, bans: 1, events, activity: "SSH probing / login attempts", members: [],
  evidence: [{ ts: T, server: "vpn", to: "192.0.2.1", text: "failed password login (account name withheld)" }], omitted: 0, ...extra,
});
const report = {
  window: "7d", from: T - 7 * 86400e6, to: T,
  providers: [
    { key: "AS64500", asn: 64500, name: "Example Net", countries: [["NL", "Netherlands"]], sources: [source("198.51.100.7", 5), source("198.51.100.8", 1)] },
    { key: "unknown", asn: null, name: null, countries: [], sources: [source("203.0.113.9", 4)] },
  ],
};

test("abuse rows: worth, search, already mailed", () => {
  const f = { q: "", worth: true, fresh: false };
  let rows = abuseRows(report, f);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0].sources.map((x) => x.net), ["198.51.100.7"], "one line isn't worth a mail");
  assert.equal(rows[0].events, 5, "added up again");
  rows = abuseRows(report, { ...f, q: "netherlands" });
  assert.deepEqual(rows.map((p) => p.key), ["AS64500"]);
  const marked = { AS64500: { at: Date.now() - 86400000, sources: ["198.51.100.7"] }, old: { at: Date.now() - 90 * 86400000, sources: ["203.0.113.9"] } };
  assert.deepEqual([...reportedSources(marked)], ["198.51.100.7"], "marks older than 30 days are over");
  rows = abuseRows(report, { ...f, fresh: true }, marked);
  assert.deepEqual(rows.map((p) => p.key), ["unknown"]);
});

test("the e-mail text, and the mailto link that fits", () => {
  const p = report.providers[0];
  const text = abuseText(p, report);
  assert.match(text, /^Hello,\n/);
  assert.match(text, /in your network \(Example Net, AS64500\) attacked our servers/);
  assert.match(text, /\(to 192\.0\.2\.1\) failed password login/);
  assert.ok(!text.includes("vpn"), "never a node's name");
  assert.match(abuseText(p, report, 1), /\.\.\. and 1 more source: all of them are in the attached file/);
  assert.equal(abuseSubject(p, report), "Abuse from your network (AS64500): 2 sources, 2026-10-19 to 2026-10-26");
  const all = mailto(["abuse@example.net"], p, report);
  assert.equal(all.cut, 0);
  assert.ok(all.url.startsWith("mailto:abuse%40example.net?subject=Abuse%20from"));
  const short = mailto(["abuse@example.net"], p, report, 900);
  assert.equal(short.cut, 1, "the second source left for the attached file");
  assert.ok(short.url.length <= 900 || short.cut === p.sources.length - 1);
});

test("RDAP answers: only plain mailboxes", () => {
  const ok = parseRdap({ handle: "NET-1", name: "EXAMPLE", entities: [{ roles: ["registrant"], entities: [{ roles: ["abuse"], vcardArray: ["vcard", [["email", {}, "text", "Abuse@Example.net"]]] }] }] });
  assert.deepEqual(ok, { abuse: ["abuse@example.net"], network: "EXAMPLE, NET-1" });
  const evil = parseRdap({ name: "X\nTo: someone@else", entities: [{ roles: ["abuse"], vcardArray: ["vcard", [["email", {}, "text", "a@b.example\nBcc: x@y.z"], ["email", {}, "text", "ok@isp.example"]]] }] });
  assert.deepEqual(evil.abuse, ["ok@isp.example"]);
  assert.ok(!evil.network.includes("\n"));
  assert.equal(plainEmail("x@y"), null);
  assert.equal(parseRdap(null), null);
  const deep = { entities: [] };
  let at = deep;
  for (let i = 0; i < 50; i++) { const e = { entities: [] }; at.entities.push(e); at = e; }
  assert.deepEqual(parseRdap(deep).abuse, [], "deep nesting stops");
});

test("CSV: quoted, and no formulas from strangers", () => {
  assert.equal(csv([["a", 'say "hi"', "x,y"], ["=cmd|' /C calc'!A0", "+1", "-2", "@SUM(A1)", "line\nbreak"]]),
    'a,"say ""hi""","x,y"\r\n\'=cmd|\' /C calc\'!A0,\'+1,\'-2,\'@SUM(A1),"line\nbreak"\r\n');
});

test("addresses in text", () => {
  const parts = linkify("ban 192.0.2.5 at 10:15:30 for 2001:db8::/32; not 300.1.1.1 or x10.0.0.1 or 192.0.2.50x");
  assert.deepEqual(parts.filter((p) => p.addr).map((p) => p.addr), ["192.0.2.5", "2001:db8::/32"]);
  assert.equal(parts.map((p) => p.text || p.addr).join(""), "ban 192.0.2.5 at 10:15:30 for 2001:db8::/32; not 300.1.1.1 or x10.0.0.1 or 192.0.2.50x");
  assert.deepEqual(linkify("[2001:db8::5]:22 fe80::1").filter((p) => p.addr).map((p) => p.addr), ["2001:db8::5", "fe80::1"]);
});

test("links carry the filters that differ", () => {
  const defaults = { level: "all", q: "", group: false, selected: "" };
  const f = { level: "high", q: "ssh x", group: true, selected: "DE" };
  const qs = queryFor(f, defaults);
  assert.equal(qs, "?level=high&q=ssh+x&group=1");
  const { parts, query } = parseHash(`#/alerts${qs}`);
  assert.deepEqual(parts, ["alerts"]);
  const back = applyQuery({ ...defaults }, defaults, { ...query, evil: "x", selected: "FR" });
  assert.deepEqual(back, { level: "high", q: "ssh x", group: true, selected: "" });
  assert.equal(queryFor(defaults, defaults), "");
  assert.deepEqual(parseHash("#/address/192.0.2.0/24").parts, ["address", "192.0.2.0", "24"]);
});

test("settings that differ between nodes", () => {
  const rows = [{ id: "0", values: { mode: "enforce", v: "0.3.0" } }, { id: "1", values: { mode: "enforce", v: "0.3.0" } }, { id: "2", values: { mode: "shadow", v: "0.3.0" } }];
  const d = drift(rows, ["mode", "v"]);
  assert.deepEqual([...d.mode.differ], ["2"]);
  assert.equal(d.mode.common, "enforce");
  assert.equal(d.v.differ.size, 0);
  const two = drift([{ id: "a", values: { v: "1" } }, { id: "b", values: { v: "2" } }], ["v"]);
  assert.deepEqual([...two.v.differ], ["a", "b"], "no majority: both marked");
});

test("a node card's problem in brief", () => {
  assert.equal(brief("no data since 2026-10-29 00:24:24 UTC: connecting to 203.0.113.5:7949: Connection refused (os error 61)"), "no data: connection refused");
  assert.equal(brief("no data since 2026-10-29 00:24:24 UTC: its vpsfort: no console socket"), "no data: no console socket");
  assert.equal(brief("1 security update(s) pending"), "1 security update(s) pending");
  assert.equal(brief("x".repeat(100)).length, 89);
});

test("a browser's name from its User-Agent", () => {
  assert.equal(browserName("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.7977.167 Safari/537.36"), "Chrome 152 on macOS");
  assert.equal(browserName("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"), "Firefox 128 on Linux");
  assert.equal(browserName("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"), "Safari 17 on iOS");
  // full version strings, as Edge sends them (a reduced "12.194.0.0" is shaped like an IPv4 address)
  assert.equal(browserName("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.92 Safari/537.36 Edg/130.0.2849.68"), "Edge 130 on Windows");
  assert.equal(browserName("curl/8.7.1"), "curl/8.7.1");
});

test("the same problem on several nodes is one entry", () => {
  const att = [
    { level: "critical", node: "a", node_id: "0", text: "antivirus: 1 infected file(s)" },
    { level: "critical", node: "b", node_id: "1", text: "antivirus: 1 infected file(s)" },
    { level: "high", node: "", node_id: "", text: "cluster keys differ" },
    { level: "warning", node: "a", node_id: "0", text: "antivirus: 1 infected file(s)" },
  ];
  const g = groupAttention(att);
  assert.equal(g.length, 3, "a different level is another entry");
  assert.deepEqual(g[0].nodes.map((n) => n.node), ["a", "b"]);
  assert.deepEqual(g[1].nodes, [], "a cluster-wide one has no node");
});

test("the same problem with different counts is one entry with the counts", () => {
  const att = [
    { level: "warning", node: "a", node_id: "0", text: "3 high or critical alert(s) in the last 24 hours" },
    { level: "warning", node: "b", node_id: "1", text: "1 high or critical alert(s) in the last 24 hours" },
    { level: "warning", node: "a", node_id: "0", text: "2 security update(s) pending" },
    { level: "warning", node: "b", node_id: "1", text: "2 security update(s) pending" },
    { level: "critical", node: "a", node_id: "0", text: "antivirus: 1 infected file(s) in the last scan" },
    { level: "critical", node: "b", node_id: "1", text: "antivirus: 2 infected file(s) in the last scan" },
    { level: "warning", node: "a", node_id: "0", text: "disk /: 9% free" },
    { level: "warning", node: "b", node_id: "1", text: "disk /: 4% free" },
  ];
  const g = groupAttention(att);
  assert.equal(g.length, 5, "a count mid-sentence merges too; a percentage is not a count");
  assert.equal(g[2].text, "antivirus: infected file(s) in the last scan");
  assert.deepEqual(g[2].nodes.map((n) => n.count), [1, 2]);
  assert.deepEqual(g.slice(3).map((x) => x.text), ["disk /: 9% free", "disk /: 4% free"]);
  assert.equal(g[0].text, "high or critical alert(s) in the last 24 hours");
  assert.deepEqual(g[0].nodes.map((n) => [n.node, n.count]), [["a", 3], ["b", 1]]);
  assert.equal(g[1].text, "2 security update(s) pending", "the same count everywhere: the text keeps it");
  assert.deepEqual(g[1].nodes.map((n) => n.count), [null, null]);
});

test("a mailed network seen again is marked re-offended", () => {
  const p = { key: "AS1", sources: [{ net: "192.0.2.1", last: 1_700_000_000_000_000 }, { net: "192.0.2.2", last: 1_700_000_900_000_000 }] };
  assert.equal(reoffended(p, {}), null, "never mailed");
  assert.equal(reoffended(p, { AS1: { at: 1_700_000_950_000, sources: [] } }), null, "nothing since the mark");
  assert.deepEqual(reoffended(p, { AS1: { at: 1_700_000_500_000, sources: [] } }), { count: 1, since: 1_700_000_500_000 });
  assert.equal(viewTitle("#/alerts?level=high&q=ssh"), "alerts · level=high q=ssh");
  assert.equal(viewTitle("#/overview"), "overview");
  assert.equal(viewTitle(""), "overview");
});

test("small helpers", () => {
  assert.equal(niceMax(7), 8);
  assert.equal(niceMax(130), 200);
  assert.equal(duration(90061000), "1d 1h");
  assert.equal(duration(61000), "1m");
  const m = mergePlaces([{ key: "DE", name: "Germany", bans: 2, nodes: ["a"] }, { key: "DE", name: "Germany", bans: 3, nodes: ["b", "a"] }]);
  assert.deepEqual(m.map((x) => [x.bans, x.nodes]), [[5, ["a", "b"]]]);
});

const { mergeAcross, decisionKey, alertKey, snapshotDiff, buckets, sparkPath, newSince } = await import("../core.js");

test("the same decision on four nodes is one row", () => {
  const rows = [
    { ts: 40, node: "node1", node_id: "0", kind: "ban", target: "11.183.70.179", message: "ban 11.183.70.179 for 59m55s (from peer xmpp): burst score fast=100 slow=100 [1x fw_tripwire]" },
    { ts: 39, node: "vpn", node_id: "1", kind: "ban", target: "11.183.70.179", message: "ban 11.183.70.179 for 59m54s (from peer xmpp): burst score fast=100 slow=100 [1x fw_tripwire]" },
    { ts: 35, node: "xmpp", node_id: "2", kind: "ban", target: "11.183.70.179", message: "ban 11.183.70.179 [China / Chinanet (AS4134)] for 1h (offence #1): burst score fast=100 slow=100 [1x fw_tripwire]" },
    { ts: 30, node: "xmpp", node_id: "2", kind: "unban", target: "11.183.70.179", message: "unban 11.183.70.179: ban expired" },
  ];
  const m = mergeAcross(rows, decisionKey);
  assert.equal(m.length, 2, "the ban once, the unban once");
  assert.equal(m[0].count, 3);
  assert.deepEqual(m[0].nodes.map((n) => n.node), ["node1", "vpn", "xmpp"]);
  assert.equal(m[0].ts, 40, "the newest keeps its time");
  assert.equal(m[0].first, 35);
  assert.equal(m[1].count, 1);
});

test("repeated alerts within a minute are one row", () => {
  const rows = [60e6 * 10 + 5e6, 60e6 * 10 + 3e6, 60e6 * 10 + 1e6, 60e6 * 9 + 50e6].map((ts, i) => ({ ts, node: i < 3 ? "a" : "b", node_id: i < 3 ? "0" : "1", severity: "info", message: "su to ejabberd by root" }));
  const m = mergeAcross(rows, alertKey);
  assert.equal(m.length, 2, "minute 10 and minute 9");
  assert.equal(m[0].count, 3);
  assert.equal(m[1].nodes[0].node, "b");
});

test("what changed on a node since its last snapshot", () => {
  const before = { generated: 100, bans: [{ net: "a" }, { net: "b" }], alerts: [{ ts: 90 }], exposure: { listeners: [{ key: { addr: "0.0.0.0", port: 22 } }] } };
  const after = { generated: 200, bans: [{ net: "b" }, { net: "c" }, { net: "d" }], alerts: [{ ts: 150 }, { ts: 90 }], exposure: { listeners: [{ key: { addr: "0.0.0.0", port: 22 } }, { key: { addr: "0.0.0.0", port: 7949 } }] } };
  assert.deepEqual(snapshotDiff(before, after), ["+2 bans", "−1 ban", "1 new alert", "new listener on 0.0.0.0:7949"]);
  assert.deepEqual(snapshotDiff(after, after), []);
  assert.deepEqual(snapshotDiff(null, after), []);
});

test("sparkline buckets and path", () => {
  assert.deepEqual(buckets([1, 2, 3, 4, 5, 6, 7, 8], 2, 3), [12, 21], "the last 6 values, in threes");
  assert.deepEqual(buckets([1, 2], 5, 2), [3], "fewer than asked: what there is");
  assert.equal(sparkPath([0, 0], 10, 4), "M0.0,3.5L10.0,3.5", "flat at the bottom");
  assert.equal(sparkPath([5], 10, 4), "");
  assert.match(sparkPath([0, 2, 1], 20, 10), /^M0\.0,9\.5L10\.0,0\.5L20\.0,5\.0$/);
});

test("new since the last look", () => {
  const rows = [{ ts: 50 }, { ts: 30 }, { since: 10 }];
  const n = newSince(rows, 20);
  assert.equal(n.count, 2);
  assert.ok(n.isNew(rows[0]) && !n.isNew(rows[2]));
  assert.equal(newSince(rows, 0).count, 3, "no last look: everything is new");
});

test("map markers at a spot's coordinates, the rest of the country at its capital", () => {
  const capitals = { DE: [52.52, 13.4], FR: [48.86, 2.35], AU: [-35.28, 149.13] };
  const world = {
    countries: [{ key: "DE", name: "Germany", bans: 3, offenders: 5, events: 9 }, { key: "FR", name: "France", bans: 2, offenders: 2, events: 2 }, { key: "ZZ", name: "Nowhere", bans: 2, offenders: 2, events: 2 }],
    logged_in: { DE: 1, AU: 2 },
    spots: [
      { country: "DE", city: "Nuremberg", lat: 49.45, lon: 11.08, bans: 2, offenders: 4, events: 8, logins: 1 },
      { country: "FR", city: "Lyon", lat: 45.76, lon: 4.84, bans: 2, offenders: 1, events: 1, logins: 0 },
      { country: "ZZ", lat: 10, lon: 20, bans: 1 },
      { country: "DE", city: "Nowhere", lat: 95, lon: 0, bans: 1 },
    ],
  };
  const { markers, off } = mapMarkers(world, capitals, "bans");
  assert.deepEqual(markers.map((m) => [m.name, m.lat, m.lon, m.value, m.logins, m.spot]), [
    ["Germany, Nuremberg", 49.45, 11.08, 2, 1, true],
    ["France, Lyon", 45.76, 4.84, 2, 0, true],
    ["Germany", 52.52, 13.4, 1, 0, false],
    ["Nowhere", 10, 20, 1, 0, true],
    ["AU", -35.28, 149.13, 0, 2, false],
  ], "no marker at Paris: Lyon has all of France's bans; a spot off the globe is dropped");
  assert.equal(off, 1, "the rest of ZZ has no capital");
  // another metric: the spots' own share of it
  const o = mapMarkers(world, capitals, "offenders");
  assert.deepEqual(o.markers.filter((m) => m.key === "DE").map((m) => [m.name, m.value]), [["Germany, Nuremberg", 4], ["Germany", 1]]);
  // a node without coordinates (or an older one): everything at the capitals, as before
  const old = mapMarkers({ countries: world.countries, logged_in: world.logged_in }, capitals, "bans");
  assert.deepEqual(old.markers.map((m) => [m.key, m.value, m.logins]), [["DE", 3, 1], ["FR", 2, 0], ["AU", 0, 2]]);
  assert.equal(old.off, 2);
});
