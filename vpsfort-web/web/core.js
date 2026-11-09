// vpsfort console: what the page works out, apart from the page itself, so it can be tested
// without a browser (`node --test web/tests`). Nothing here touches the DOM.

export const ms = (t) => t / 1000;

export function duration(msecs) {
  let sec = Math.max(0, Math.round(msecs / 1000));
  const d = Math.floor(sec / 86400); sec -= d * 86400;
  const hr = Math.floor(sec / 3600); sec -= hr * 3600;
  const m = Math.floor(sec / 60); sec -= m * 60;
  if (d) return hr ? `${d}d ${hr}h` : `${d}d`;
  if (hr) return m ? `${hr}h ${m}m` : `${hr}h`;
  if (m) return `${m}m`;
  return `${sec}s`;
}

export function compact(n) {
  if (n >= 1e6) return `${+(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${+(n / 1e3).toFixed(1)}K`;
  return String(n);
}

export function matches(q, ...fields) {
  if (!q) return true;
  const needle = q.toLowerCase();
  return fields.some((f) => f !== null && f !== undefined && String(f).toLowerCase().includes(needle));
}

// A round top for the axis whose half is a whole number too (counts have no halves).
export function niceMax(v) {
  v = Math.max(2, v);
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const k of p === 1 ? [2, 4, 6, 8, 10] : [1, 2, 4, 5, 6, 8, 10]) if (k * p >= v) return k * p;
  return 10 * p;
}

// Places of several lists added up by key (a network spanning the countries picked).
export function mergePlaces(list) {
  const by = new Map();
  for (const p of list) {
    const e = by.get(p.key) || { key: p.key, name: p.name, country: p.country, bans: 0, offenders: 0, events: 0, nodes: [] };
    e.bans += p.bans || 0; e.offenders += p.offenders || 0; e.events += p.events || 0;
    e.nodes = [...new Set([...e.nodes, ...(p.nodes || [])])].sort();
    by.set(p.key, e);
  }
  return [...by.values()];
}

export function mergePorts(lists) {
  const by = new Map();
  for (const l of lists) for (const [port, n] of l || []) by.set(port, (by.get(port) || 0) + n);
  return [...by.entries()];
}

// What the weekly report leaves out: one blocked packet isn't worth a mail.
export const WORTH = 3;

// How long a source counts as reported after its provider was marked mailed.
export const REPORTED_DAYS = 30;

// The sources reported lately (`reported`: provider key -> {at, sources}), as a set.
export function reportedSources(reported, now = Date.now()) {
  const out = new Set();
  for (const r of Object.values(reported || {})) {
    if (r && now - r.at < REPORTED_DAYS * 86400000) for (const n of r.sources || []) out.add(n);
  }
  return out;
}

// The sources worth showing and the providers left with any, added up again. `f.fresh` leaves
// out the sources reported lately (`reported`, as above).
export function abuseRows(report, f, reported = {}, now = Date.now()) {
  const out = [];
  const done = f.fresh ? reportedSources(reported, now) : new Set();
  for (const p of report.providers || []) {
    const country = p.countries.map(([c, n]) => `${c} ${n}`).join(" ");
    const sources = p.sources.filter((x) => (!f.worth || x.events >= WORTH) && !done.has(x.net)
      && matches(f.q, p.name, p.key, country, x.net, x.activity, (x.members || []).join(" ")));
    if (!sources.length) continue;
    const sum = (k) => sources.reduce((a, x) => a + (x[k] || 0), 0);
    out.push({ ...p, sources, bans: sum("bans"), events: sum("events"), first: Math.min(...sources.map((x) => x.first)), last: Math.max(...sources.map((x) => x.last)) });
  }
  return out;
}

// A network marked mailed whose sources were seen again after the mark: how many, and since
// when (the mark's time). `marks`: provider key -> {at (ms), sources}; `p.sources[].last` in µs.
export function reoffended(p, marks) {
  const r = (marks || {})[p.key];
  if (!r) return null;
  const again = (p.sources || []).filter((x) => ms(x.last) > r.at).length;
  return again ? { count: again, since: r.at } : null;
}

// A saved view's title from its hash: the tab and what differs from the defaults
// ("alerts · level=high q=ssh").
export function viewTitle(hash) {
  const [path, query] = (hash || "").replace(/^#\//, "").split("?");
  const parts = decodeURIComponent(query || "").split("&").filter(Boolean).map((kv) => kv.replace("=", "="));
  return `${path || "overview"}${parts.length ? ` · ${parts.join(" ")}` : ""}`;
}

export const utc = (t) => `${new Date(ms(t)).toISOString().slice(0, 19).replace("T", " ")} UTC`;

export const providerName = (p) => p.name || (p.asn ? `AS${p.asn}` : "Unknown network");

// One provider's part as an e-mail to its abuse desk, like the weekly report's: the
// attacked servers by their public address, never by the nodes' names. `limit`: only the first
// sources (a mailto: link can't carry much), saying how many more the attached file has.
export function abuseText(p, report, limit = Infinity) {
  const n = p.sources.length;
  const lines = [
    "Hello,",
    "",
    `the following ${n === 1 ? "address" : `${n} addresses or networks`} in your network (${providerName(p)}${p.asn && p.name ? `, AS${p.asn}` : ""}) attacked our servers`,
    `between ${utc(report.from)} and ${utc(report.to)}. Please investigate and stop the abuse.`,
    "The evidence is taken from our server logs (firewall and the attacked services); all times",
    "are UTC and account names are withheld.",
  ];
  for (const x of p.sources.slice(0, limit)) {
    lines.push("", "--------------------------------------------------------------------------");
    lines.push(`Source: ${x.net}${x.country_name ? `   [${x.country_name}]` : ""}`);
    lines.push(`Seen: ${utc(x.first)} - ${utc(x.last)} (${x.bans} incident${x.bans === 1 ? "" : "s"})`);
    lines.push(`Activity: ${x.activity || "malicious activity"}`);
    if ((x.members || []).length) lines.push(`Addresses involved: ${x.members.join(", ")}`);
    if ((x.evidence || []).length) {
      lines.push("Log excerpt:");
      for (const l of x.evidence) lines.push(`  ${utc(l.ts)}  ${l.to ? `(to ${l.to}) ` : ""}${l.text}`);
      if (x.omitted) lines.push(`  ... and ${x.omitted} more`);
    }
  }
  if (n > limit) lines.push("", `... and ${n - limit} more source${n - limit === 1 ? "" : "s"}: all of them are in the attached file.`);
  return `${lines.join("\n")}\n`;
}

export function abuseSubject(p, report) {
  const n = p.sources.length;
  const day = (t) => utc(t).slice(0, 10);
  return `Abuse from your network${p.asn ? ` (AS${p.asn})` : ""}: ${n} source${n === 1 ? "" : "s"}, ${day(report.from)} to ${day(report.to)}`;
}

// A mailto: link to the provider's abuse desk with the report in it, as many sources as fit in
// `max` characters (mail programs cut long links): {url, cut} (sources left out).
export function mailto(addresses, p, report, max = 6000) {
  const subject = encodeURIComponent(abuseSubject(p, report));
  const to = addresses.map(encodeURIComponent).join(",");
  for (let limit = p.sources.length; ; limit--) {
    const url = `mailto:${to}?subject=${subject}&body=${encodeURIComponent(abuseText(p, report, limit))}`;
    if (url.length <= max || limit <= 1) return { url, cut: p.sources.length - limit };
  }
}

// ------------------------------------------------------------------ RDAP

// RDAP data is written by the network's owner, who may be the attacker: only plain e-mail
// addresses are taken, as by the console (src/rdap.rs) and vpsfort's weekly report.
export function plainEmail(e) {
  if (typeof e !== "string") return null;
  e = e.trim().toLowerCase();
  const ok = e.length <= 100 && e.split("@").length === 2 && !e.startsWith("@") && e.includes(".") && /^[a-z0-9@._+-]+$/.test(e);
  return ok ? e : null;
}

// The abuse mailboxes and the network's name in an RDAP answer (parsed JSON).
export function parseRdap(v) {
  if (!v || typeof v !== "object") return null;
  const abuse = [];
  const walk = (o, depth) => {
    if (depth > 8) return;
    for (const e of Array.isArray(o.entities) ? o.entities : []) {
      if (!e || typeof e !== "object") continue;
      if (Array.isArray(e.roles) && e.roles.includes("abuse") && Array.isArray(e.vcardArray) && Array.isArray(e.vcardArray[1])) {
        for (const item of e.vcardArray[1]) {
          const m = Array.isArray(item) && item[0] === "email" ? plainEmail(item[3]) : null;
          if (m && !abuse.includes(m)) abuse.push(m);
        }
      }
      walk(e, depth + 1);
    }
  };
  walk(v, 0);
  const name = typeof v.name === "string" ? v.name : "";
  const handle = typeof v.handle === "string" ? v.handle : "";
  const network = (name && handle ? `${name}, ${handle}` : name || handle).replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, 100);
  return { abuse: abuse.slice(0, 5), network };
}

// ------------------------------------------------------------------ exports, links

// CSV (RFC 4180), safe to open in a spreadsheet: what came from strangers (log lines, network
// names) can't become a formula.
export function csv(rows) {
  const cell = (v) => {
    let t = v === null || v === undefined ? "" : String(v);
    if (/^[=+\-@\t\r]/.test(t)) t = `'${t}`;
    return /[",\r\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
  };
  return rows.map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

const IPV4 = String.raw`(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?:\/(?:3[0-2]|[12]?\d))?`;
// IPv6 loosely here, checked by v6ok
const IPV6 = String.raw`[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?:\/\d{1,3})?`;
const ADDRESS = new RegExp(`(?<![\\w.:/])(?:${IPV4}|${IPV6})(?![\\w.:])`, "g");

function v6ok(a) {
  const [addr, prefix] = a.split("/");
  if (prefix !== undefined && !(Number(prefix) <= 128)) return false;
  const halves = addr.split("::");
  if (halves.length > 2) return false;
  const groups = (h) => (h === "" ? [] : h.split(":"));
  const all = halves.flatMap(groups);
  if (all.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  return halves.length === 2 ? all.length <= 7 : all.length === 8;
}

// Text split into plain pieces and addresses (with their networks): [{text} | {addr}].
export function linkify(text) {
  text = String(text);
  const out = [];
  let at = 0;
  for (const m of text.matchAll(ADDRESS)) {
    if (m[0].includes(":") && !v6ok(m[0])) continue;
    if (m.index > at) out.push({ text: text.slice(at, m.index) });
    out.push({ addr: m[0] });
    at = m.index + m[0].length;
  }
  if (at < text.length) out.push({ text: text.slice(at) });
  return out;
}

// "#/alerts?level=high&q=ssh" as {parts: ["alerts"], query: {level: "high", q: "ssh"}}.
export function parseHash(hash) {
  const [path, qs] = String(hash).replace(/^#\/?/, "").split("?");
  const parts = path.split("/").filter((p, i) => p !== "" || i === 0).map((p) => { try { return decodeURIComponent(p); } catch (_) { return p; } });
  const query = {};
  for (const [k, v] of new URLSearchParams(qs || "")) query[k] = v;
  return { parts, query };
}

// A view's filters as a query string: only what differs from their defaults ("" when none).
export function queryFor(filters, defaults) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(filters || {})) {
    if (k === "selected" || v === (defaults || {})[k]) continue;
    q.set(k, typeof v === "boolean" ? (v ? "1" : "0") : String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

// Applies a query to a view's filters, each value as its default's type; unknown keys are left out.
export function applyQuery(filters, defaults, query) {
  for (const [k, v] of Object.entries(query || {})) {
    if (!(k in (defaults || {})) || k === "selected") continue;
    const d = defaults[k];
    if (typeof d === "boolean") filters[k] = v === "1" || v === "true";
    else if (typeof d === "string") filters[k] = v.slice(0, 200);
  }
  return filters;
}

// A problem's first clause, for a node card (the whole text is on hover and on the node's
// page): "no data since 2026-10-29 00:24:24 UTC: connecting to 203.0.113.5:7949: Connection
// refused (os error 61)" becomes "no data: connection refused".
export function brief(text) {
  const m = String(text).match(/^no data since \S+ \S+ UTC: (?:.*: )?(.+?)(?: \(os error \d+\))?$/);
  if (m) return `no data: ${m[1].charAt(0).toLowerCase()}${m[1].slice(1)}`;
  return text.length > 90 ? `${text.slice(0, 88)}…` : text;
}

// A browser and its system from a User-Agent, as people name them: "Chrome 152 on macOS". The
// whole string stays on hover.
export function browserName(ua) {
  ua = String(ua);
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /CrOS/.test(ua) ? "ChromeOS" : /Linux/.test(ua) ? "Linux" : "";
  const take = (re) => { const m = ua.match(re); return m ? `${m[1]} ${m[2].split(".")[0]}` : null; };
  const browser = take(/(Firefox)\/(\d+)/) || take(/(Edg)e?\/(\d+)/)?.replace("Edg", "Edge") || take(/(OPR)\/(\d+)/)?.replace("OPR", "Opera")
    || take(/(Chrome)\/(\d+)/) || (/Safari\//.test(ua) && take(/(Version)\/(\d+)/)?.replace("Version", "Safari")) || null;
  if (!browser && !os) return ua.slice(0, 40);
  return [browser, os].filter(Boolean).join(" on ");
}

// "Needs attention" entries with the same level and text (several nodes with the same problem)
// as one, with every node that has it; the order of first appearance stays.
export function groupAttention(att) {
  const out = [];
  const by = new Map();
  for (const a of att) {
    // "3 high or critical alert(s) ..." is the same problem as "1 high or critical alert(s) ...",
    // "antivirus: 2 infected file(s) ..." as "antivirus: 1 infected file(s) ...": one entry, each
    // node's count beside its chip. A count is a number before a "(s)" word (a "9% free" isn't).
    const m = /^(.*?)(\d+) ([^,.;:]*?\(s\))(.*)$/.exec(a.text);
    const base = m ? `${m[1]}${m[3]}${m[4]}` : a.text;
    const key = `${a.level}|${base}`;
    let g = by.get(key);
    if (!g) { g = { level: a.level, text: a.text, base, nodes: [] }; by.set(key, g); out.push(g); }
    if (a.node && !g.nodes.some((n) => n.node_id === a.node_id)) g.nodes.push({ node: a.node, node_id: a.node_id, count: m ? Number(m[2]) : null });
  }
  for (const g of out) {
    // the text keeps its count when every node has the same; else the counts go to the chips
    const counts = g.nodes.map((n) => n.count);
    if (counts.length > 1 && counts.some((c) => c !== counts[0])) g.text = g.base;
    else for (const n of g.nodes) n.count = null;
    delete g.base;
  }
  return out;
}

// For each setting, the value most nodes have, and which nodes differ: {key: {common, differ: Set}}
// (all of them when no value has a majority).
export function drift(rows, keys) {
  const out = {};
  for (const k of keys) {
    const counts = new Map();
    for (const r of rows) {
      const v = JSON.stringify(r.values[k] ?? null);
      counts.set(v, (counts.get(v) || 0) + 1);
    }
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const common = sorted[0];
    // no value most nodes share (two nodes, two values): every node differs
    const tie = sorted.length > 1 && sorted[1][1] === common[1];
    const differ = new Set(rows.filter((r) => counts.size > 1 && (tie || JSON.stringify(r.values[k] ?? null) !== common[0])).map((r) => r.id));
    out[k] = { common: common ? JSON.parse(common[0]) : null, differ };
  }
  return out;
}

// ------------------------------------------------------------------ merging across nodes

// The same decision on several nodes (a peer's ban relayed to each) as one row with every
// node: the key is the kind, the target and the message with the "(from peer X)" part and
// the per-node duration left out; the first (newest) entry keeps its time and text.
export function mergeAcross(rows, keyOf) {
  const out = [];
  const by = new Map();
  for (const r of rows) {
    const k = keyOf(r);
    const g = by.get(k);
    if (g) {
      if (!g.nodes.some((n) => n.node_id === r.node_id)) g.nodes.push({ node: r.node, node_id: r.node_id });
      g.count += 1;
      g.first = Math.min(g.first, r.ts || 0);
    } else {
      const g2 = { ...r, nodes: [{ node: r.node, node_id: r.node_id }], count: 1, first: r.ts || 0 };
      by.set(k, g2);
      out.push(g2);
    }
  }
  return out;
}

// What makes a decision the same one on another node: its kind and target, and its message
// without the node-specific parts ("for 59m55s" counts down per node; "(from peer xmpp)" names
// where it came from; the geo label is only on the deciding node).
export function decisionKey(a) {
  const msg = String(a.message || "")
    .replace(/ \[[^\]]*\]/g, "")
    .replace(/ for \d+[hms][\dhms]*/g, "")
    .replace(/ \(from peer [^)]*\)/g, "")
    .replace(/ \(offence #\d+\)/g, "");
  return `${a.kind}|${a.target || ""}|${msg}`;
}

// The same alert on several nodes, or the same one repeated on one node within a minute
// (ten "su to ejabberd by root" from one cron run): one row, with the count.
export function alertKey(a) {
  const minute = Math.floor((a.ts || 0) / 60e6);
  return `${a.severity}|${a.topic || ""}|${a.message}|${minute}`;
}

// ------------------------------------------------------------------ what changed on a node

// A short line on what differs between a node's previous snapshot and its current one: bans
// and listeners come and go, alerts arrive. Empty when nothing of that changed.
export function snapshotDiff(before, after) {
  if (!before || !after) return [];
  const keys = (list, k) => new Set((list || []).map((x) => x[k]));
  const added = (a, b) => [...a].filter((x) => !b.has(x)).length;
  const out = [];
  const bansB = keys(before.bans, "net"), bansA = keys(after.bans, "net");
  const plus = added(bansA, bansB), minus = added(bansB, bansA);
  if (plus) out.push(`+${plus} ban${plus === 1 ? "" : "s"}`);
  if (minus) out.push(`−${minus} ban${minus === 1 ? "" : "s"}`);
  const alerts = (after.alerts || []).filter((a) => (a.ts || 0) > (before.generated || 0)).length;
  if (alerts) out.push(`${alerts} new alert${alerts === 1 ? "" : "s"}`);
  const where = (l) => `${(l.key || {}).addr}:${(l.key || {}).port}`;
  const lB = new Set(((before.exposure || {}).listeners || []).map(where)), lA = new Set(((after.exposure || {}).listeners || []).map(where));
  const newL = [...lA].filter((x) => !lB.has(x)), goneL = [...lB].filter((x) => !lA.has(x));
  if (newL.length) out.push(`new listener${newL.length === 1 ? "" : "s"} on ${newL.join(", ")}`);
  if (goneL.length) out.push(`listener${goneL.length === 1 ? "" : "s"} gone: ${goneL.join(", ")}`);
  return out;
}

// ------------------------------------------------------------------ map

// What the map draws, the most of `metric` (bans, offenders or events) first: each spot a
// city-level geo database located (world.spots: its share of a country's figures and of the
// addresses that logged in), then each country's rest at its capital (capitals[cc] =
// [lat, lon]). A spot's name is "Country, City". `off` is the rest of the countries whose
// capital is unknown. Nodes without coordinates (or older ones) send no spots, so everything
// of theirs is at the capitals.
export function mapMarkers(world, capitals, metric) {
  const rest = new Map((world.countries || []).map((c) => [c.key, { key: c.key, name: c.name || c.key, value: c[metric] || 0, logins: 0 }]));
  for (const [cc, n] of Object.entries(world.logged_in || {})) {
    if (!rest.has(cc)) rest.set(cc, { key: cc, name: cc, value: 0, logins: 0 });
    rest.get(cc).logins += n;
  }
  const markers = [];
  for (const sp of world.spots || []) {
    const value = sp[metric] || 0, logins = sp.logins || 0;
    if (!(value > 0 || logins > 0) || !(Math.abs(sp.lat) <= 90 && Math.abs(sp.lon) <= 180)) continue;
    const r = rest.get(sp.country);
    if (r) {
      r.value = Math.max(0, r.value - value);
      r.logins = Math.max(0, r.logins - logins);
    }
    const country = r ? r.name : sp.country;
    markers.push({ key: sp.country, name: sp.city ? `${country}, ${sp.city}` : country, city: sp.city || "", lat: sp.lat, lon: sp.lon, value, logins, spot: true });
  }
  let off = 0;
  for (const r of rest.values()) {
    if (!(r.value > 0 || r.logins > 0)) continue;
    const cap = capitals[r.key];
    if (!cap) { off += r.value; continue; }
    markers.push({ key: r.key, name: r.name, city: "", lat: cap[0], lon: cap[1], value: r.value, logins: r.logins, spot: false });
  }
  markers.sort((a, b) => b.value - a.value || b.logins - a.logins || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return { markers, off };
}

// ------------------------------------------------------------------ sparklines

// The last `n` values of a per-minute series, summed per bucket of `every` minutes.
export function buckets(values, n, every) {
  const v = values || [];
  const out = [];
  for (let i = Math.max(0, v.length - n * every); i < v.length; i += every) {
    out.push(v.slice(i, i + every).reduce((a, b) => a + b, 0));
  }
  return out;
}

// An SVG path for `values` in a w×h box (0 at the bottom; a flat line when all are 0).
export function sparkPath(values, w, h) {
  const n = values.length;
  if (n < 2) return "";
  const max = Math.max(1, ...values);
  const x = (i) => ((i * w) / (n - 1)).toFixed(1);
  const y = (v) => (h - (v / max) * (h - 1) - 0.5).toFixed(1);
  return values.map((v, i) => `${i ? "L" : "M"}${x(i)},${y(v)}`).join("");
}

// ------------------------------------------------------------------ seen marks

// Entries newer than `since` (the admin's last look, microseconds): their count, and whether
// a given one is new.
export function newSince(rows, since) {
  const s = since || 0;
  return { count: rows.filter((r) => (r.ts || r.since || 0) > s).length, isNew: (r) => (r.ts || r.since || 0) > s };
}

// A honeypot's evidence line: `11-09 01:07:00 connected to honeypot TCP/445, sent an SMB2
// negotiate (178 bytes): "..."`, or the decoy web site's `11-09 01:23:02 decoy_request: "GET /
// HTTP/1.1" 404 118 "-" "zgrab/0.x"`; a network ban's lines name the member after the time.
// Lines written before the capture existed stop after the port.
const TRAP_LINE = /^(?:\d\d-\d\d \d\d:\d\d:\d\d )?(?:([0-9A-Fa-f.:]+) )?(?:connected to honeypot (TCP\/\d+)(?:, (.*))?|decoy_request(?:_json)?: (.*))$/;

// A ban a node took over from a peer: `ban 203.0.113.9 [...] for 14d (from peer node1): ...`.
const FROM_PEER = /\(from peer ([^)]+)\)/;

// Where a ban's message places its target: `ban 203.0.113.9 [Germany, Berlin / Hetzner Online
// GmbH (AS24940)] for 14d ...`, or only `[Germany]` or `[Hetzner Online GmbH (AS24940)]`, or
// nothing (no geo database, an older log). Only the bracket right after the target: the later
// `[1x tripwire_connect]` is what the source did.
export function banPlace(message) {
  const m = /^ban \S+ \[([^\]]*)\]/.exec(message || "");
  if (!m) return { place: "", network: "" };
  const inner = m[1];
  const cut = inner.indexOf(" / ");
  if (cut >= 0) return { place: inner.slice(0, cut), network: inner.slice(cut + 3) };
  return inner.endsWith(")") ? { place: "", network: inner } : { place: inner, network: "" };
}

// The decisions whose evidence came from a honeypot port or the decoy site, one row per
// evidence line, with the scanner's address, the port and what it sent. A ban the peers took
// over carries the same evidence on each of them: one row, the deciding node's (its own row
// when there is one, else a copy put under the origin's name), so the hits are counted and
// filtered by the node that caught them. The same hit from the log and from the latest
// decisions is one row too.
export function trapHits(actions, nodes) {
  const idOf = new Map((nodes || []).map((n) => [n.name, n.id]));
  const rows = new Map();
  for (const a of actions) {
    const peer = FROM_PEER.exec(a.message || "");
    const copy = Boolean(peer) || a.category === "from peers";
    const node = peer ? peer[1] : a.node;
    const node_id = peer ? (idOf.has(peer[1]) ? idOf.get(peer[1]) : peer[1]) : a.node_id;
    for (const l of a.evidence || []) {
      const m = TRAP_LINE.exec(l);
      if (!m) continue;
      const addr = m[1] || a.target;
      const key = `${node}:${addr}:${l}`;
      const have = rows.get(key);
      if (have && (!have.copy || copy)) continue;
      rows.set(key, { ...a, ...banPlace(a.message), node, node_id, copy, addr, port: m[2] || "web", sent: m[3] || m[4] || "not recorded", line: l, key });
    }
  }
  return [...rows.values()];
}
