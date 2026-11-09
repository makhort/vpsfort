// vpsfort console: one page, no libraries. Everything shown comes from the nodes (log lines,
// account names, peers' messages), so it only ever goes into the page as text (textContent,
// createTextNode), never as HTML. The parts: dom.js builds and patches the page, core.js works
// things out (tested with `node --test web/tests`), this file has the views.

import { SVG, on, h, s, patch, livePart } from "/dom.js";
import {
  ms, duration, compact, matches, niceMax, mergePlaces, mergePorts, WORTH, abuseRows, utc, providerName, abuseText,
  mailto, parseRdap, csv, linkify, parseHash, queryFor, applyQuery, drift, REPORTED_DAYS, brief, browserName, groupAttention, reoffended, viewTitle,
  mergeAcross, decisionKey, alertKey, snapshotDiff, buckets, sparkPath, newSince, mapMarkers, trapHits,
} from "/core.js";

(() => {
  const app = document.getElementById("app");
  // Per browser: the theme, notifications, marks, pins, columns (and the filters, below).
  const pref = (k, fallback) => { try { return localStorage.getItem(k) ?? fallback; } catch (_) { return fallback; } };
  const setPref = (k, v) => { try { localStorage.setItem(k, v); } catch (_) { /* no storage */ } };
  // base64url <-> bytes, for passkeys (WebAuthn hands out and takes ArrayBuffers)
  const b64ToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - (s.length % 4)) % 4), "=")), (c) => c.charCodeAt(0)).buffer;
  const bufToB64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const passkeysPossible = () => Boolean(window.PublicKeyCredential && navigator.credentials && (location.hostname === "localhost" || !/^[\d.]+$|^\[/.test(location.hostname)));
  const state = {
    session: null,
    data: null,
    error: null,
    loading: false,
    updated: 0,
    paused: false,
    timer: null,
    every: 0,
    view: null,
    route: [],
    node: {},
    digest: {},
    abuse: {},
    honeypots: {},
    address: {},
    mailbox: {},
    sessions: null,
    // what an action on a card of the Account page failed with, until its next try
    cardNote: {},
    // the console's own matters (Account page), the attention history, the digest archives
    check: null,
    history: null,
    digests: {},
    // a share link's view: {net, token}; no login, no other page
    shared: null,
    again: false,
    lastApi: Date.now(),
    open: new Set(),
    sort: {},
    // the admin's last look (per browser): rows newer than it are marked
    lastLook: Number(pref("lgw-last-look", "0")) || 0,
    previous: {},
    scrolls: {},
    down: 0,
    hidden: (() => { try { return JSON.parse(pref("lgw-columns", "{}")); } catch (_) { return {}; } })(),
    seen: (() => { try { return JSON.parse(pref("lgw-seen", "{}")); } catch (_) { return {}; } })(),
    pins: (() => { try { return JSON.parse(pref("lgw-pins", "[]")); } catch (_) { return []; } })(),
    filters: {
      overview: { range: "3h" },
      alerts: { level: "all", node: "", q: "", merge: true },
      bans: { node: "", q: "", group: false },
      honeypots: { window: "24h", node: "", kind: "", q: "" },
      offenders: { node: "", q: "" },
      activity: { kind: "", node: "", q: "", merge: true },
      world: { q: "", selected: "", all: false, allNets: false, allPorts: false },
      map: { metric: "bans", europe: false },
      abuse: { window: "24h", q: "", worth: true, fresh: false, todo: false },
    },
  };
  // the filters as they start: a link carries only what differs
  const DEFAULTS = JSON.parse(JSON.stringify(state.filters));

  const THEMES = ["auto", "light", "dark"];
  function applyTheme() {
    const t = pref("lgw-theme", "auto");
    if (t === "auto") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = t;
  }
  applyTheme();

  // The filters and settings, kept per browser (not the searches: those are for the moment).
  const KEPT = "lgw-filters";
  try {
    const kept = JSON.parse(localStorage.getItem(KEPT) || "{}");
    for (const [view, f] of Object.entries(kept)) {
      if (!state.filters[view] || typeof f !== "object") continue;
      for (const [k, v] of Object.entries(f)) if (k in state.filters[view] && typeof v === typeof state.filters[view][k]) state.filters[view][k] = v;
    }
  } catch (_) { /* no storage, or something else in it */ }

  function keepFilters() {
    const out = {};
    for (const [view, f] of Object.entries(state.filters)) out[view] = Object.fromEntries(Object.entries(f).filter(([k]) => k !== "q" && k !== "selected"));
    try { localStorage.setItem(KEPT, JSON.stringify(out)); } catch (_) { /* no storage */ }
  }

  // ------------------------------------------------------------------ DOM helpers

  // ------------------------------------------------------------------ formatting

  const dayFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const yearFmt = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const hmFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
  const dateFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });
  const dayFmtShort = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  const nf = new Intl.NumberFormat();

  // vpsfort's times are microseconds since 1970; 0 or missing means "never" (an unset field),
  // and a time before 2000 can only be that too
  const unset = (t) => !t || t < 946_684_800_000_000;

  function when(t) {
    if (unset(t)) return t === null || t === undefined ? "" : "never";
    const d = new Date(ms(t));
    const today = new Date();
    if (d.toDateString() === today.toDateString()) return timeFmt.format(d);
    return d.getFullYear() === today.getFullYear() ? dayFmt.format(d) : yearFmt.format(d);
  }

  function ago(t) {
    if (unset(t)) return t === null || t === undefined ? "" : "never";
    const diff = Date.now() - ms(t);
    return diff >= 0 ? `${duration(diff)} ago` : `in ${duration(-diff)}`;
  }

  // How long a ban has left: "ended 5m ago" for one whose end has passed but is still listed
  // (the node's clock, or a snapshot older than the ban).
  function left(t) {
    if (unset(t)) return "";
    const diff = ms(t) - Date.now();
    return diff > 0 ? duration(diff) : `ended ${duration(-diff)} ago`;
  }
  const ended = (b) => !unset(b.until) && ms(b.until) <= Date.now();

  const num = (n) => (n === null || n === undefined || Number.isNaN(n) ? "–" : nf.format(n));

  // Tables show how long ago, the exact time on hover (today's as a time, older with the date).
  function timeCell(t) {
    if (unset(t)) return h("span", null, when(t));
    const d = new Date(ms(t));
    const diff = Date.now() - ms(t);
    const text = diff >= 0 && diff < 86400000 ? `${when(t)} (${ago(t)})` : when(t);
    return h("span", { class: "nowrap", title: d.toString() }, text);
  }

  // ------------------------------------------------------------------ status, chips

  const LEVELS = { critical: "Critical", high: "High", warning: "Warning", info: "Info", good: "OK" };

  function icon(level) {
    const a = { viewBox: "0 0 16 16", fill: "none", stroke: "currentColor", "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" };
    if (level === "critical") return s("svg", a, s("circle", { cx: 8, cy: 8, r: 6.2 }), s("path", { d: "M5.8 5.8l4.4 4.4M10.2 5.8l-4.4 4.4" }));
    if (level === "high" || level === "warning") return s("svg", a, s("path", { d: "M8 2.2l6.2 11H1.8z" }), s("path", { d: "M8 6.5v3M8 11.4v.1" }));
    if (level === "good") return s("svg", a, s("circle", { cx: 8, cy: 8, r: 6.2 }), s("path", { d: "M5.3 8.2l1.9 1.9 3.6-3.8" }));
    return s("svg", a, s("circle", { cx: 8, cy: 8, r: 6.2 }), s("path", { d: "M8 7.3v3.6M8 5.2v.1" }));
  }

  function status(level, label) {
    const lv = LEVELS[level] ? level : "info";
    const text = label || LEVELS[lv];
    // a long one (an error, the infected files) wraps like text; a short one never breaks
    return h("span", { class: `status ${lv}${text.length > 40 ? " long" : ""}` }, icon(lv), text);
  }

  const STATES = { ok: ["good", "Up"], stale: ["warning", "Stale"], down: ["critical", "Down"], waiting: ["info", "Waiting"] };
  const nodeState = (st) => status(...(STATES[st] || STATES.waiting));

  function nodeKey(id) {
    const nodes = (state.data && state.data.nodes) || [];
    const i = nodes.findIndex((n) => n.id === id);
    return i >= 0 && i < 8 ? `var(--s${i + 1})` : "var(--axis)";
  }

  // Every node, or "all N" when they all see it: shorter than four names.
  function nodeChips(names) {
    const list = names || [];
    const total = (state.data && state.data.nodes || []).length;
    if (total > 2 && list.length === total) return h("span", { class: "chip", title: list.join(", ") }, `all ${total}`);
    return list.map((n) => [h("span", { class: "chip" }, n), " "]);
  }

  function nodeChip(name, id) {
    return h("a", { class: "chip node", key: nodeKey(id), href: `#/nodes/${encodeURIComponent(id)}`, onclick: (e) => e.stopPropagation() }, name || "?");
  }

  // The same chip without the link, where a click means something else (a header that picks).
  function plainChip(name, id) {
    return h("span", { class: "chip node", key: nodeKey(id) }, name || "?");
  }

  // ------------------------------------------------------------------ API

  class LoginNeeded extends Error {}

  // A request that doesn't answer in `opts.timeout` ms (30 s) fails, so a stuck one never
  // holds up the refreshes.
  async function api(path, opts = {}) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), opts.timeout || 30000);
    let res, body = {};
    try {
      res = await fetch(path, {
        method: opts.method || "GET", credentials: "same-origin", cache: "no-store", signal: ctl.signal,
        headers: { Accept: "application/json", ...(opts.body ? { "Content-Type": "application/json" } : {}) },
        body: opts.body,
      });
      try { body = await res.json(); } catch (_) { /* not JSON */ }
    } catch (e) {
      throw new Error(e.name === "AbortError" ? "the console didn't answer in time" : `the console can't be reached (${e.message})`);
    } finally {
      clearTimeout(timer);
    }
    if (res.status === 401 && path.startsWith("/api/v1/")) {
      stop();
      login("Your session ended: log in again.");
      throw new LoginNeeded();
    }
    if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
    // a request counts as the session's activity
    state.lastApi = Date.now();
    return body;
  }

  // ------------------------------------------------------------------ login

  function login(message) {
    state.view = null;
    const session = state.session || {};
    const err = h("div", { class: "err", role: "alert" }, message || "");
    let remembered = "";
    try { remembered = localStorage.getItem("lgw-user") || ""; } catch (_) { /* no storage */ }
    const user = h("input", { type: "text", id: "user", autocomplete: "username", autocapitalize: "none", spellcheck: "false", value: remembered, placeholder: "admin" });
    const pw = h("input", { type: "password", id: "pw", autocomplete: "current-password", required: true });
    const code = session.totp === false ? null : h("input", { class: "code", id: "code", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: "6", required: true, placeholder: "123456" });
    const btn = h("button", { class: "btn primary", type: "submit" }, "Log in");
    const note = h("div", { class: "muted work-note", role: "status" });
    // The proof of work (src/work.rs): a challenge for the account typed, solved in a worker
    // while the admin types; the console refuses a login without it, or with one made too easy
    // before failures raised the difficulty, with 428 and a fresh challenge.
    const work = { challenge: session.work || null, solved: null, solving: null, worker: null, user: "", passkey: session.passkey || null };
    // the passkey's answer, when the admin chose one instead of typing the code
    let passkeyAnswer = null;
    const KEY_LABEL = "Log in with a passkey";
    const keyBtn = h("button", { class: "btn", type: "button", hidden: !(work.passkey && passkeysPossible()), title: "A passkey that checks your fingerprint or PIN logs you in on its own; one that doesn't stands in for the one-time code beside the password" }, KEY_LABEL);
    // what the passkey step still needs, under its button
    const keyNote = h("div", { class: "muted work-note", role: "status" });
    // the passkey is the login: neither the password nor the code is asked for with it
    const afterPasskey = () => {
      pw.required = false;
      keyNote.textContent = "";
      form.requestSubmit();
    };
    const usePasskey = async () => {
      if (!work.passkey) return;
      // answered already: only the password is missing
      if (passkeyAnswer) { afterPasskey(); return; }
      try {
        const opts = work.passkey;
        const cred = await navigator.credentials.get({ publicKey: {
          challenge: b64ToBuf(opts.challenge), rpId: opts.rpId, timeout: opts.timeout, userVerification: opts.userVerification,
          allowCredentials: (opts.allowCredentials || []).map((c) => ({ type: "public-key", id: b64ToBuf(c.id) })),
        } });
        passkeyAnswer = { id: cred.id, challenge: opts.challenge, clientDataJSON: bufToB64(cred.response.clientDataJSON), authenticatorData: bufToB64(cred.response.authenticatorData), signature: bufToB64(cred.response.signature) };
        keyBtn.textContent = "Passkey ready";
        err.textContent = "";
        if (code) { code.required = false; code.value = ""; code.placeholder = "not needed"; }
        afterPasskey();
      } catch (ex) {
        err.textContent = ex.name === "NotAllowedError" ? "passkey: the browser didn't use one (cancelled, timed out, or none for this console here)" : `passkey: ${ex.message}`;
      }
    };
    on(keyBtn, "click", usePasskey);
    const solve = (challenge) => new Promise((resolve, reject) => {
      if (work.worker) work.worker.terminate();
      if (typeof Worker === "undefined" || !crypto.subtle) { reject(new Error("this browser can't do the proof of work (no Web Worker or WebCrypto)")); return; }
      const w = (work.worker = new Worker("/work.js"));
      const started = Date.now();
      w.onmessage = (ev) => {
        if (ev.data.progress) { note.textContent = `preparing the login: ${compact(ev.data.progress)} tries, ${Math.round((Date.now() - started) / 1000)} s…`; return; }
        note.textContent = "";
        resolve({ ...challenge, nonce: ev.data.nonce });
      };
      w.onerror = (ev) => reject(new Error(`the proof of work failed: ${ev.message}`));
      w.postMessage({ salt: challenge.salt, difficulty: challenge.difficulty });
    });
    // A challenge for the account named (each has its own difficulty), solved as the admin
    // types: `given` is one the console just sent (after a refusal); `again` asks for a fresh one.
    const prepare = async ({ given = null, again = false } = {}) => {
      const who = user.value.trim().toLowerCase() || "admin";
      if (!given && !again && work.solving && work.user === who) return work.solving;
      work.user = who;
      work.solved = null;
      work.solving = (async () => {
        let c = given;
        if (!c) {
          const ses = await (await fetch(`/api/v1/session?user=${encodeURIComponent(who)}`, { credentials: "same-origin", cache: "no-store" })).json();
          c = ses.work;
          // a passkey's answer waiting to be sent stays (this may be the login asking for its
          // proof of work); a fresh start, or another account, begins again
          if (again || !passkeyAnswer) {
            work.passkey = ses.passkey || null;
            passkeyAnswer = null;
            keyBtn.hidden = !(work.passkey && passkeysPossible());
            keyBtn.textContent = KEY_LABEL;
            pw.required = true;
            if (code) { code.required = true; code.placeholder = "123456"; }
          }
        }
        if (!c) return null;
        return (work.solved = await solve(c));
      })();
      work.solving.catch(() => {});
      return work.solving;
    };
    if (session.work) prepare();
    on(user, "change", () => prepare({ again: true }));
    const form = h("form", {
      class: "card login",
      onsubmit: async (e) => {
        e.preventDefault();
        btn.disabled = true;
        err.textContent = "";
        try {
          const attempt = async (proof) => {
            const res = await fetch("/api/login", {
              method: "POST", credentials: "same-origin",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ user: user.value.trim().toLowerCase(), password: pw.value, code: code ? code.value.trim() : "", passkey: passkeyAnswer, work: proof }),
            });
            return [res, await res.json().catch(() => ({}))];
          };
          let [res, body] = await attempt(await prepare());
          if (res.status === 428 && body.work) {
            // the challenge was used, expired or is too easy now: solve the one given and try once more
            note.textContent = "more work is needed now…";
            [res, body] = await attempt(await prepare({ given: body.work }));
          }
          // a failure raised the difficulty: the next try needs a fresh challenge
          if (!res.ok) {
            passkeyAnswer = null;
            prepare({ again: true });
            // a key without a fingerprint or PIN: the password goes with it
            keyNote.textContent = body.needs_password ? "Type your password, then use the passkey again." : "";
            if (body.needs_password) pw.focus();
            throw new Error(body.error || `${res.status} ${res.statusText}`);
          }
          pw.value = "";
          try { localStorage.setItem("lgw-user", user.value.trim().toLowerCase()); } catch (_) { /* no storage */ }
          state.session = await api("/api/v1/session");
          start();
        } catch (ex) {
          err.textContent = ex.message;
          if (code) code.value = "";
          btn.disabled = false;
        }
      },
    },
      h("div", { class: "brand" }, h("img", { src: "/icon.svg", alt: "" }), "vpsfort console"),
      h("p", null, session.node ? `Cluster console on ${session.node}` : "Cluster console"),
      h("label", { for: "user" }, "Account"), user,
      h("label", { for: "pw" }, "Password"), pw,
      code && h("label", { for: "code" }, "One-time code"), code,
      btn, keyBtn, keyNote, note, err);
    app.replaceChildren(h("div", { class: "login-wrap" }, form));
    (remembered ? pw : user).focus();
  }

  // ------------------------------------------------------------------ shell

  const TABS = [["overview", "Overview"], ["alerts", "Alerts"], ["bans", "Bans"], ["honeypots", "Honeypots"], ["offenders", "Offenders"], ["activity", "Activity"], ["world", "World"], ["map", "Map"], ["abuse", "Abuse"]];
  let shell = null;

  function buildShell() {
    const nav = h("nav", { class: "tabs", "aria-label": "Sections" }, TABS.map(([k, label]) => h("a", { href: `#/${k}`, "data-tab": k }, label)));
    const pill = h("span", { class: "pill" });
    const spin = h("span", { class: "spin", title: "asking the nodes" });
    const updated = h("span", { class: "nowrap updated" });
    const who = h("a", { class: "nowrap who", href: "#/account", title: "your sessions and settings" }, (state.session && state.session.user) || "");
    const theme = h("button", { class: "btn small icon", type: "button", onclick: () => { const t = pref("lgw-theme", "auto"); setPref("lgw-theme", THEMES[(THEMES.indexOf(t) + 1) % THEMES.length]); applyTheme(); header(); } });
    const bell = h("button", { class: "btn small icon", type: "button", onclick: toggleNotify });
    // the session's end, the first login's news: above every tab
    const notice = h("div", { class: "notice-area" });
    // an address or network typed here opens its page; anything else searches the tab
    const go = h("input", { type: "search", class: "go", placeholder: "Address…", "aria-label": "Go to an address", onkeydown: (e) => {
      if (e.key !== "Enter") return;
      const q = e.target.value.trim();
      if (!q) return;
      if (linkify(q).some((p) => p.addr === q)) { location.hash = `#/address/${q}`; e.target.value = ""; return; }
      const box = shell && shell.main.querySelector('input[type="search"]');
      if (box) { box.value = q; box.dispatchEvent(new Event("input")); box.focus(); } else { state.filters.offenders.q = q; location.hash = "#/offenders"; }
      e.target.value = "";
    } });
    const pause = h("button", { class: "btn small", type: "button", onclick: () => { state.paused = !state.paused; header(); if (!state.paused) refresh(); } });
    // this tab with its filters, kept in this browser: one click back to "xmpp, high, last day"
    const views = h("details", { class: "columns views" }, h("summary", { class: "btn small icon", title: "Saved views: this tab with its filters, kept in this browser", "aria-label": "Saved views" }, icons.pin()), h("div", { class: "menu" }));
    // which colour is which node, where the chips are
    const legend = h("ul", { class: "legend node-legend", "aria-label": "Nodes" });
    // an icon: the header is crowded on a phone
    const out = h("button", {
      class: "btn small icon", type: "button", title: "Log out", "aria-label": "Log out",
      onclick: async () => {
        stop();
        try { await fetch("/api/logout", { method: "POST", credentials: "same-origin" }); } catch (_) { /* offline */ }
        state.data = null;
        login("Logged out.");
      },
    }, s("svg", { viewBox: "0 0 16 16", width: 15, height: 15, fill: "none", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" },
      s("path", { d: "M6.5 2.5H3.5a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h3" }), s("path", { d: "M10 5l3 3-3 3" }), s("path", { d: "M13 8H6.5" })));
    const main = h("main", { id: "main" });
    const top = h("header", { class: "top" },
      h("a", { class: "brand", href: "#/overview" }, h("img", { src: "/icon.svg", alt: "" }), "vpsfort"),
      nav,
      h("div", { class: "top-right" }, go, views, spin, pill, updated, pause, bell, theme, who, out));
    app.replaceChildren(top, legend, notice, main);
    shell = { nav, pill, spin, updated, pause, main, theme, bell, notice, go, views, legend };
  }

  // The header's icons (inline SVG: the same on every system, unlike text glyphs).
  // saved views: the tab and its filters, kept in this browser ("lgw-views": [{hash, title}])
  function savedViews() {
    try { return JSON.parse(pref("lgw-views", "[]")); } catch (_) { return []; }
  }
  function saveView(hash) {
    const list = savedViews().filter((v) => v.hash !== hash);
    list.unshift({ hash, title: viewTitle(hash) });
    setPref("lgw-views", JSON.stringify(list.slice(0, 20)));
  }
  function forgetView(hash) {
    setPref("lgw-views", JSON.stringify(savedViews().filter((v) => v.hash !== hash)));
  }

  const iconSvg = (...paths) => s("svg", { viewBox: "0 0 16 16", width: 15, height: 15, fill: "none", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" }, ...paths);
  const icons = {
    pin: () => iconSvg(s("path", { d: "M8 2.5l1.6 3.3 3.6.5-2.6 2.5.6 3.6L8 10.7l-3.2 1.7.6-3.6-2.6-2.5 3.6-.5z" })),
    // half-filled circle: as the system
    auto: () => iconSvg(s("circle", { cx: 8, cy: 8, r: 5.5 }), s("path", { d: "M8 2.5v11A5.5 5.5 0 0 0 8 2.5z", fill: "currentColor", stroke: "none" })),
    light: () => iconSvg(s("circle", { cx: 8, cy: 8, r: 3 }), s("path", { d: "M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4" })),
    dark: () => iconSvg(s("path", { d: "M13 10.2A5.5 5.5 0 0 1 5.8 3a5.5 5.5 0 1 0 7.2 7.2z" })),
    bellOn: () => iconSvg(s("path", { d: "M4 11V7a4 4 0 0 1 8 0v4l1 1.5H3z" }), s("path", { d: "M6.5 13.5a1.5 1.5 0 0 0 3 0" })),
    bellOff: () => iconSvg(s("path", { d: "M4 11V7a4 4 0 0 1 8 0v4l1 1.5H3z" }), s("path", { d: "M6.5 13.5a1.5 1.5 0 0 0 3 0" }), s("path", { d: "M2.5 2.5l11 11" })),
  };

  function header() {
    if (!shell) return;
    const d = state.data;
    shell.spin.classList.toggle("on", state.loading);
    shell.pause.textContent = state.paused ? "Resume" : "Pause";
    shell.pause.title = state.paused ? "Resume refreshes" : "Pause refreshes";
    if (d) {
      const t = d.totals;
      const down = t.nodes - t.nodes_ok;
      shell.pill.replaceChildren(status(down ? (t.nodes_ok ? "warning" : "critical") : "good", `${t.nodes_ok}/${t.nodes} nodes up`));
    }
    shell.updated.textContent = state.updated ? `updated ${timeFmt.format(new Date(state.updated))}${state.held ? " · held while text is selected" : ""}` : "";
    const stale = state.updated && Date.now() - state.updated > 3 * Math.max(5, state.every || 10) * 1000;
    shell.updated.classList.toggle("stale", Boolean(stale));
    shell.updated.title = stale ? "No fresh data for a while: see the banner below" : "";
    // what needs attention, in the tab's title too (seen from another tab)
    const n = d ? (d.attention || []).filter((a) => a.level === "critical" || a.level === "high").length : 0;
    document.title = n ? `(${n}) vpsfort console` : "vpsfort console";
    const t = pref("lgw-theme", "auto");
    shell.theme.replaceChildren(icons[t]());
    shell.theme.title = `Colours: ${t === "auto" ? "as the system's" : t} (click for ${THEMES[(THEMES.indexOf(t) + 1) % THEMES.length]})`;
    const on = notifying();
    shell.bell.replaceChildren(on ? icons.bellOn() : icons.bellOff());
    shell.bell.title = on ? "Notifications on: new critical problems while this page is open (click to stop)" : "Notify me of new critical problems while this page is open";
    shell.bell.setAttribute("aria-pressed", String(on));
    notices();
    // the saved views, with their removal
    const saved = savedViews();
    const here = location.hash || "#/overview";
    patch(shell.views.querySelector(".menu"), [
      h("button", { class: "btn small", type: "button", disabled: saved.some((v) => v.hash === here), onclick: () => { saveView(here); header(); } }, `Save this view: ${viewTitle(here)}`),
      ...saved.map((v) => h("div", { class: "view" }, h("a", { href: v.hash, onclick: () => { shell.views.open = false; } }, v.title),
        h("button", { class: "linklike", type: "button", title: "Forget this view", "aria-label": `Forget ${v.title}`, onclick: () => { forgetView(v.hash); header(); } }, "×"))),
      saved.length ? null : h("div", { class: "muted" }, "No saved views yet."),
    ]);
    // the nodes' colours, on the tabs that show node chips (several nodes only)
    const chips = ["alerts", "bans", "offenders", "activity", "abuse", "address"].includes(state.route[0]);
    const nodes = (d && d.nodes) || [];
    patch(shell.legend, chips && nodes.length > 1 && pref("lgw-legend", "1") === "1"
      ? [...nodes.map((n) => h("li", null, h("span", { class: "key", key: nodeKey(n.id) }), h("a", { href: `#/nodes/${n.id}` }, n.name))),
        h("li", { class: "hide" }, h("button", { class: "btn small", type: "button", title: "Hide the legend (the Account page brings it back)", onclick: () => { setPref("lgw-legend", "0"); header(); } }, "hide"))]
      : []);
    for (const a of shell.nav.querySelectorAll("a")) {
      if (a.dataset.tab === state.route[0]) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
  }

  function stop() {
    if (state.timer) clearInterval(state.timer);
    state.timer = null;
    state.every = 0;
    shell = null;
  }

  function schedule() {
    const base = Math.max(5, (state.data && state.data.refresh_secs) || 10);
    const every = state.down ? Math.min(60, base * 2 ** Math.min(3, state.down - 1)) : base;
    if (state.timer && every === state.every) return;
    if (state.timer) clearInterval(state.timer);
    state.every = every;
    state.timer = setInterval(() => {
      if (document.hidden || state.paused) return;
      // the page stays still while the reader selects text in it (to copy)
      state.held = selecting();
      if (state.held) header();
      else refresh();
    }, every * 1000);
  }

  function selecting() {
    const sel = window.getSelection();
    return Boolean(shell && sel && !sel.isCollapsed && shell.main.contains(sel.anchorNode));
  }

  // Leaving (or hiding) the page marks the admin's last look: what comes after is "new".
  const markLook = () => { if (state.updated) setPref("lgw-last-look", String(state.updated * 1000)); };
  document.addEventListener("visibilitychange", () => { if (document.hidden) markLook(); });
  window.addEventListener("pagehide", markLook);
  // Back to a tab left a while: fresh data at once, not at the next tick.
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && shell && !state.paused && Date.now() - state.updated > Math.max(5, state.every || 10) * 1000) refresh();
  });

  // "/" goes to the page's search box, as on many sites; Escape leaves it.
  // Keys: "/" the tab's search, "g" the address box, 1-8 the tabs, j/k the next/previous row
  // (Enter opens it), "?" this list. Not while typing, never with a modifier.
  const KEYS = [["/", "search this tab"], ["g", "go to an address"], ["1–8", "the tabs, in order"], ["j / k", "next / previous row"], ["Enter", "open the row"], ["Esc", "leave a box"], ["?", "these keys"]];
  document.addEventListener("keydown", (e) => {
    const t = e.target;
    const typing = t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement || (t && t.isContentEditable);
    if (e.key === "Escape" && t instanceof HTMLInputElement && t.type === "search") { t.blur(); return; }
    if (typing || e.ctrlKey || e.metaKey || e.altKey || !shell || state.shared) return;
    if (e.key === "/") {
      const box = shell.main.querySelector('input[type="search"]');
      if (box) { e.preventDefault(); box.focus(); box.select(); }
    } else if (e.key === "g") {
      e.preventDefault();
      shell.go.focus();
    } else if (/^[1-8]$/.test(e.key) && TABS[Number(e.key) - 1]) {
      location.hash = `#/${TABS[Number(e.key) - 1][0]}`;
    } else if (e.key === "j" || e.key === "k") {
      const rows = [...shell.main.querySelectorAll('tr[tabindex="0"]')];
      if (!rows.length) return;
      e.preventDefault();
      const at = rows.indexOf(document.activeElement);
      const next = e.key === "j" ? Math.min(rows.length - 1, at + 1) : Math.max(0, at - 1);
      rows[next].focus();
      rows[next].scrollIntoView({ block: "nearest" });
    } else if (e.key === "?") {
      state.keysShown = !state.keysShown;
      notices();
    }
  });

  // What each tab shows besides the header's figures: a refresh asks for that only.
  const NEEDS = { overview: ["alerts", "history"], alerts: ["alerts"], activity: ["actions"], bans: ["bans"], honeypots: ["actions"], offenders: ["offenders", "accounts"], world: ["world"], map: ["world"] };
  const ready = (...parts) => Boolean(state.data) && parts.every((p) => p in state.data);

  async function refresh() {
    if (!shell) return;
    if (state.loading) { state.again = true; return; }
    state.loading = true;
    header();
    try {
      // what the other tabs had stays, to show at once when they open (and is asked again then)
      const fresh = await api(`/api/v1/cluster?only=${(NEEDS[state.route[0]] || []).join(",")}`);
      state.data = Object.assign({}, state.data, fresh);
      state.error = null;
      state.updated = Date.now();
      if (state.route[0] === "nodes") await loadNode(state.route[1]);
      if (state.route[0] === "address") await loadAddress(addressOf(state.route));
      if (state.route[0] === "account") await loadSessions();
      notify();
      state.down = 0;
    } catch (e) {
      if (e instanceof LoginNeeded) return;
      state.error = e.message;
      // the console unreachable (restart, a VPN exit change): try again with backoff, up to a minute
      state.down = (state.down || 0) + 1;
    } finally {
      state.loading = false;
    }
    schedule();
    header();
    update();
    if (state.again) { state.again = false; refresh(); }
  }

  async function loadNode(id) {
    try {
      const got = await api(`/api/v1/nodes/${encodeURIComponent(id)}`);
      // the snapshot before this one, for "what changed" (only a different one)
      const old = state.node[id] && state.node[id].snapshot;
      if (old && got.snapshot && old.generated !== got.snapshot.generated) state.previous[id] = old;
      state.node[id] = got;
    } catch (e) {
      if (e instanceof LoginNeeded) throw e;
      state.node[id] = { error: e.message };
    }
  }

  function start() {
    loadMarks();
    buildShell();
    window.onhashchange = route;
    route();
    refresh();
  }

  const VIEWS = { overview: viewOverview, alerts: viewAlerts, bans: viewBans, honeypots: viewHoneypots, offenders: viewOffenders, activity: viewActivity, world: viewWorld, map: viewMap, abuse: viewAbuse, nodes: viewNode, address: viewAddress, account: viewAccount };

  // An address page's address: a network's "/" splits the hash's path.
  const addressOf = (parts) => parts.slice(1).join("/");

  function route() {
    if (!shell) return;
    const { parts, query } = parseHash(location.hash);
    if (!VIEWS[parts[0]]) parts.splice(0, parts.length, "overview");
    // a link's filters (#/alerts?level=high&q=ssh)
    if (state.filters[parts[0]]) applyQuery(state.filters[parts[0]], DEFAULTS[parts[0]], query);
    // the scroll position of each tab, restored when it comes back (opened rows stay in state.open)
    if (state.route && state.route.length) state.scrolls[state.route.join("/")] = window.scrollY;
    state.route = parts;
    shell.main.replaceChildren();
    state.view = VIEWS[parts[0]](shell.main, parts[0] === "address" ? addressOf(parts) : parts[1]);
    header();
    update();
    window.scrollTo(0, state.scrolls[parts.join("/")] || 0);
    // the tab's data at once, not at the next tick
    if (state.data) refresh();
  }

  // The address bar follows the filters, so a link shows another admin the same.
  function syncUrl() {
    const view = state.route[0];
    if (!state.filters[view]) return;
    const path = location.hash.split("?")[0] || `#/${view}`;
    const want = `${path}${queryFor(state.filters[view], DEFAULTS[view])}`;
    if (want !== location.hash) history.replaceState(null, "", want);
  }

  function update() {
    // a share link's page has no shell: just its view
    if (state.shared) { if (state.view) state.view.update(); return; }
    if (!state.view || !shell) return;
    state.view.update();
    keepFilters();
    syncUrl();
  }

  let resizing = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizing);
    resizing = setTimeout(update, 150);
  });

  // ------------------------------------------------------------------ building blocks

  function banner(root) {
    if (!state.error) return;
    const age = state.updated ? duration(Date.now() - state.updated) : null;
    root.appendChild(h("div", { class: "error-banner", role: "alert" }, status("warning", state.down > 1 ? "Reconnecting" : "Can't refresh"),
      h("span", null, state.error, age ? ` · showing data ${age} old` : "", state.down > 1 ? ` · trying again every ${state.every}s` : ""),
      h("button", { class: "btn small", type: "button", onclick: () => { state.down = 0; refresh(); } }, "Try now")));
  }

  function card(title, extra, ...body) {
    return h("section", { class: "card section" }, h("header", null, h("h2", null, title), h("span", { class: "grow" }), extra), ...body);
  }

  function nodeOptions(selected) {
    const nodes = (state.data && state.data.nodes) || [];
    return [h("option", { value: "" }, "All nodes"), ...nodes.map((n) => h("option", { value: n.id, selected: n.id === selected }, n.name))];
  }

  // A sortable table. cols: {label, sort?: row => value, cell: row => node, cls?}. Rows with a
  // `detail` function expand on click; what is open survives refreshes (by `key`).
  function table(name, cols, rows, opts = {}) {
    // a column that is there only sometimes (a peers' Error column when one has an error) is null;
    // and the admin may have hidden some (the column chooser, kept per browser)
    const hidden = hiddenColumns(name);
    cols = cols.filter(Boolean).filter((c) => !hidden.includes(c.label));
    const sort = state.sort[name] || opts.sort || null;
    let list = rows;
    if (sort) {
      const col = cols.find((c) => c.label === sort.col);
      if (col && col.sort) {
        list = rows.slice().sort((a, b) => {
          const x = col.sort(a), y = col.sort(b);
          const r = x < y ? -1 : x > y ? 1 : 0;
          return sort.asc ? r : -r;
        });
      }
    }
    const limit = opts.limit || 500;
    const shown = list.slice(0, limit);
    const head = h("tr", null, cols.map((c) => {
      const sorted = sort && sort.col === c.label;
      return h("th", {
        class: [c.cls, c.sort ? "sortable" : "", sorted ? "sorted" : "", sorted && sort.asc ? "asc" : ""].filter(Boolean).join(" "),
        scope: "col",
        onclick: c.sort ? () => { state.sort[name] = { col: c.label, asc: sorted ? !sort.asc : false }; update(); } : null,
      }, c.label);
    }));
    const body = h("tbody");
    for (const r of shown) {
      const key = opts.key ? `${name}:${opts.key(r)}` : null;
      const picked = opts.picked && opts.picked(r);
      const cls = [opts.detail || opts.pick ? "clickable" : "", picked ? "picked" : "", opts.rowClass ? opts.rowClass(r) : ""].filter(Boolean).join(" ");
      // an expandable row shows a chevron before its first cell
      const chevron = opts.detail ? h("span", { class: "chev", "aria-hidden": "true" }) : null;
      const tr = h("tr", { class: cls || null, "data-k": key, role: opts.detail ? "button" : null },
        cols.map((c, i) => h("td", { class: [c.cls, i === 0 && opts.detail ? "first" : ""].filter(Boolean).join(" ") || null, "data-label": c.short || c.label || null }, i === 0 ? chevron : null, c.cell(r))));
      body.appendChild(tr);
      if (opts.pick) {
        tr.tabIndex = 0;
        tr.setAttribute("aria-selected", picked ? "true" : "false");
        on(tr, "click", () => opts.pick(r));
        on(tr, "keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); opts.pick(r); } });
      }
      if (opts.detail) {
        tr.tabIndex = 0;
        tr.setAttribute("aria-expanded", state.open.has(key) ? "true" : "false");
        // a click that ends a text selection in the row isn't a toggle
        const toggle = () => { if (String(window.getSelection() || "")) return; if (state.open.has(key)) state.open.delete(key); else state.open.add(key); update(); };
        on(tr, "click", toggle);
        on(tr, "keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
        if (state.open.has(key)) body.appendChild(h("tr", { class: "detail", "data-k": key && `${key}:detail` }, h("td", { colspan: cols.length }, opts.detail(r))));
      }
    }
    const out = [h("div", { class: "table-wrap" }, h("table", null, h("thead", null, head), body))];
    if (!rows.length) out.push(h("div", { class: "empty" }, opts.empty || "Nothing to show."));
    else if (list.length > shown.length) out.push(h("div", { class: "more" }, `Showing ${num(shown.length)} of ${num(list.length)}: narrow it down with the filter.`));
    return out;
  }

  function evidence(lines) {
    return lines && lines.length ? h("ul", { class: "evidence" }, lines.map((l) => h("li", null, linked(l)))) : null;
  }

  // An address or network that opens its page (what every node says about it).
  function addrLink(a) {
    if (state.shared) return h("span", { class: "mono addr" }, a);
    return h("a", { class: "mono addr", href: `#/address/${a}`, title: "everything the nodes know about it", onclick: (e) => e.stopPropagation() }, a);
  }

  // Text with the addresses in it as links.
  const linked = (text) => linkify(text || "").map((p) => (p.addr ? addrLink(p.addr) : p.text));

  // What a cell shows, as text (for CSV).
  function textOf(v) {
    if (v === null || v === undefined || v === false) return "";
    if (Array.isArray(v)) return v.map(textOf).join("");
    return v instanceof Node ? v.textContent : String(v);
  }

  function saveFile(name, type, text) {
    const a = h("a", { href: URL.createObjectURL(new Blob([text], { type })), download: name });
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  const stamp = () => new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");

  // CSV and JSON of a table's rows as filtered (all of them, not only those shown). A column's
  // `csv` gives its value, else what its cell shows.
  // Which columns a table shows, kept per browser: a checkbox per column in a small menu.
  // Columns off unless the admin chose otherwise: the Offenders' Place wraps a lot and the
  // row's details (and the Address page) have it.
  const HIDDEN_BY_DEFAULT = { offenders: ["Place"] };
  const hiddenColumns = (name) => state.hidden[name] || HIDDEN_BY_DEFAULT[name] || [];

  function columnChooser(name, cols) {
    const all = cols.filter(Boolean);
    const hidden = hiddenColumns(name);
    const toggle = (label, on) => {
      const next = on ? hidden.filter((l) => l !== label) : [...hidden, label];
      state.hidden[name] = next;
      setPref("lgw-columns", JSON.stringify(state.hidden));
      update();
    };
    return h("details", { class: "columns" }, h("summary", { class: "btn small" }, `Columns${hidden.length ? ` (${all.length - hidden.length})` : ""}`),
      h("div", { class: "menu" }, all.filter((c) => c.label).map((c) => h("label", null,
        h("input", { type: "checkbox", checked: !hidden.includes(c.label), onchange: (e) => toggle(c.label, e.target.checked) }), c.label))));
  }

  function tableExport(name, cols, rows) {
    const toCsv = () => csv([cols.map((c) => c.label), ...rows.map((r) => cols.map((c) => (c.csv ? c.csv(r) : textOf(c.cell(r)))))]);
    return [
      h("button", { class: "btn small", type: "button", title: "these rows as CSV (a spreadsheet)", onclick: () => saveFile(`vpsfort-${name}-${stamp()}.csv`, "text/csv;charset=utf-8", toCsv()) }, "CSV"),
      h("button", { class: "btn small", type: "button", title: "these rows as the API gives them", onclick: () => saveFile(`vpsfort-${name}-${stamp()}.json`, "application/json", JSON.stringify(rows, null, 2)) }, "JSON"),
    ];
  }

  function kv(pairs) {
    return h("dl", { class: "kv" }, pairs.filter((p) => p && p[1] !== null && p[1] !== undefined && p[1] !== "").map(([k, v]) => [h("dt", null, k), h("dd", null, v)]));
  }

  function meter(pct, warnAt, critAt) {
    const p = Math.max(0, Math.min(100, pct || 0));
    const cls = critAt !== undefined && p >= critAt ? "fill crit" : warnAt !== undefined && p >= warnAt ? "fill warn" : "fill";
    return h("span", { class: "meter" }, h("span", { class: "track" }, h("span", { class: cls, width: `${p}%` })), h("span", { class: "num" }, `${Math.round(p)}%`));
  }

  function barCell(value, max) {
    const p = max > 0 ? (100 * value) / max : 0;
    return h("span", { class: "bar-cell" }, h("span", { class: "bar", width: `${Math.max(1, p * 0.75)}%` }), h("span", { class: "num" }, num(value)));
  }

  function filterRow(...kids) {
    return h("div", { class: "filters" }, ...kids);
  }

  function search(value, placeholder, oninput) {
    return h("input", { type: "search", value, placeholder, "aria-label": placeholder, oninput: (e) => oninput(e.target.value) });
  }

  function select(options, onchange, label) {
    return h("select", { "aria-label": label, onchange: (e) => onchange(e.target.value) }, options);
  }

  // ------------------------------------------------------------------ chart

  // Lines per node over time, with a crosshair that reads every node at the pointer's minute.
  function lineChart(series, start, step, opts = {}) {
    const width = Math.max(320, (opts.width || 800));
    const height = opts.height || 180;
    // redrawn only when what it shows changes
    const wrap = h("div", { class: "chart", "data-sig": JSON.stringify([series.map((sr) => [sr.name, sr.color, sr.values]), start, step, width, height]) });
    const m = { l: 44, r: 14, t: 10, b: 24 };
    const n = series.length ? series[0].values.length : 0;
    const max = Math.max(1, ...series.flatMap((x) => x.values));
    const nice = niceMax(max);
    const x = (i) => m.l + (n <= 1 ? 0 : (i * (width - m.l - m.r)) / (n - 1));
    const y = (v) => m.t + (height - m.t - m.b) * (1 - v / nice);
    const svg = s("svg", { viewBox: `0 0 ${width} ${height}`, width, height, role: "img", "aria-label": opts.label || "chart", tabindex: "0" });
    for (const t of [0, nice / 2, nice]) {
      svg.appendChild(s("line", { class: t === 0 ? "baseline" : "gridline", x1: m.l, x2: width - m.r, y1: y(t), y2: y(t) }));
      svg.appendChild(s("text", { class: "tick", x: m.l - 6, y: y(t) + 4, "text-anchor": "end" }, compact(t)));
    }
    for (let i = 0; i < n; i++) {
      const t = start + i * step;
      const label = (opts.tick || minuteTicks)(t);
      if (label) svg.appendChild(s("text", { class: "tick", x: x(i), y: height - 6, "text-anchor": "middle" }, label));
    }
    for (const sr of series) {
      const d = sr.values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
      svg.appendChild(s("path", { class: "series", d, paint: sr.color }));
    }
    const cross = s("line", { class: "crosshair", y1: m.t, y2: height - m.b, visibility: "hidden" });
    const dots = series.map((sr) => s("circle", { class: "dot", r: 4, fillPaint: sr.color, visibility: "hidden" }));
    svg.appendChild(cross);
    dots.forEach((d) => svg.appendChild(d));
    const tip = h("div", { class: "tooltip hidden", role: "status" });
    let at = -1;
    const show = (i, clientX, clientY) => {
      if (i < 0 || i >= n) return;
      at = i;
      cross.setAttribute("x1", x(i)); cross.setAttribute("x2", x(i)); cross.setAttribute("visibility", "visible");
      series.forEach((sr, k) => { dots[k].setAttribute("cx", x(i)); dots[k].setAttribute("cy", y(sr.values[i])); dots[k].setAttribute("visibility", "visible"); });
      const rows = series.map((sr) => ({ sr, v: sr.values[i] })).sort((a, b) => b.v - a.v);
      tip.replaceChildren(h("div", { class: "when" }, hmFmt.format(new Date(ms(start + i * step)))),
        ...rows.map(({ sr, v }) => h("div", { class: "row" }, h("span", { class: "key", key: sr.color }), h("strong", null, num(v)), h("span", null, sr.name))));
      tip.classList.remove("hidden");
      const r = svg.getBoundingClientRect();
      const px = clientX !== undefined ? clientX : r.left + (x(i) / width) * r.width;
      const py = clientY !== undefined ? clientY : r.top + r.height / 3;
      const tw = tip.offsetWidth;
      tip.style.left = `${px + 14 + tw > window.innerWidth ? px - tw - 14 : px + 14}px`;
      tip.style.top = `${Math.max(8, py - 20)}px`;
    };
    const hide = () => {
      at = -1;
      cross.setAttribute("visibility", "hidden");
      dots.forEach((d) => d.setAttribute("visibility", "hidden"));
      tip.classList.add("hidden");
    };
    svg.addEventListener("pointermove", (e) => {
      const r = svg.getBoundingClientRect();
      const px = ((e.clientX - r.left) / r.width) * width;
      show(Math.round(((px - m.l) / (width - m.l - m.r)) * (n - 1)), e.clientX, e.clientY);
    });
    svg.addEventListener("pointerleave", hide);
    svg.addEventListener("blur", hide);
    svg.addEventListener("keydown", (e) => {
      if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        e.preventDefault();
        show(Math.max(0, Math.min(n - 1, (at < 0 ? n - 1 : at) + (e.key === "ArrowLeft" ? -1 : 1))));
      } else if (e.key === "Escape") hide();
    });
    if (series.length > 1) {
      wrap.appendChild(h("ul", { class: "legend" }, series.map((sr) => h("li", null, h("span", { class: "key", key: sr.color }), sr.name))));
    }
    wrap.appendChild(svg);
    wrap.appendChild(tip);
    return wrap;
  }

  // The nodes' series (8 at most: more nodes fold into "Other").
  // Axis labels: every half hour (3 hours), every 3 hours (a day), each midnight (a week).
  const minuteTicks = (t) => (Math.round(ms(t) / 60000) % 30 === 0 ? hmFmt.format(new Date(ms(t))) : null);
  const hourTicks = (t) => (new Date(ms(t)).getHours() % 3 === 0 ? hmFmt.format(new Date(ms(t))) : null);
  const dayTicks = (t) => (new Date(ms(t)).getHours() === 0 ? dateFmt.format(new Date(ms(t))) : null);

  // The overview's chart ranges: the history to draw from, how many points, labels, table rows.
  const RANGES = {
    "3h": { label: "3 hours", per: "per minute", hours: false, tick: minuteTicks, group: 10, groupLabel: "per 10 minutes" },
    "24h": { label: "24 hours", per: "per hour", hours: true, points: 24, tick: hourTicks, group: 1, groupLabel: "per hour" },
    "7d": { label: "7 days", per: "per hour", hours: true, points: 168, tick: dayTicks, group: 6, groupLabel: "per 6 hours" },
  };

  function nodeSeries(field, range = RANGES["3h"]) {
    const all = state.data.history;
    const hist = range.hours ? all.hours || { series: [] } : all;
    const list = hist.series.map((sr) => ({ name: sr.node, color: nodeKey(sr.node_id), values: range.points ? sr[field].slice(-range.points) : sr[field] }));
    if (list.length <= 8) return list;
    const other = { name: "Other nodes", color: "var(--axis)", values: list[7].values.map(() => 0) };
    for (const sr of list.slice(7)) sr.values.forEach((v, i) => { other.values[i] += v; });
    return [...list.slice(0, 7), other];
  }

  // The chart's numbers as a table, for reading without the chart.
  function chartTable(series, start, step, group = 10, groupLabel = "per 10 minutes") {
    const n = series.length ? series[0].values.length : 0;
    const rows = [];
    for (let i = 0; i < n; i += group) {
      rows.push({ t: start + i * step, v: series.map((sr) => sr.values.slice(i, i + group).reduce((a, b) => a + b, 0)) });
    }
    const at = (t) => (step >= 3600e6 ? dayFmtShort.format(new Date(ms(t))) : hmFmt.format(new Date(ms(t))));
    return h("details", null, h("summary", { class: "muted" }, `As a table (${groupLabel})`),
      h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, "From"), series.map((sr) => h("th", { class: "num" }, sr.name)))),
        h("tbody", null, rows.reverse().map((r) => h("tr", null, h("td", null, at(r.t)), r.v.map((v) => h("td", { class: "num" }, num(v)))))))));
  }

  // ------------------------------------------------------------------ overview

  function viewOverview(root) {
    return {
      update: livePart(root, (body) => {
        body.appendChild(h("div", { class: "page-head" }, h("h1", null, "Overview"), h("span", { class: "sub" }, "the whole cluster: what needs attention, activity, every node"),
          h("button", { class: "btn small", type: "button", title: "Everything the console has now, as one JSON file: the merged view and each node's whole snapshot (for a ticket, or `vpsfort tui --file` on a node's part)", onclick: exportCluster }, "Export JSON")));
        banner(body);
        lastLoginNote(body);
        const d = state.data;
        if (!ready("alerts", "history")) { body.appendChild(h("div", { class: "empty" }, "Asking the nodes…")); return; }
        const t = d.totals;
        // a sparkline of the last 3 hours (per 5 minutes) under a tile, from the history
        const sum = (field) => { const all = d.history.series.map((sr) => sr[field]); return all.length ? all[0].map((_, i) => all.reduce((a, sr) => a + (sr[i] || 0), 0)) : []; };
        const spark = (field) => { const v = buckets(sum(field), 36, 5); return v.length > 1 ? s("svg", { class: "spark", viewBox: "0 0 120 24", width: 120, height: 24, "aria-hidden": "true" }, s("path", { d: sparkPath(v, 120, 24) })) : null; };
        const tile = (label, value, note, trend) => h("div", { class: "card tile" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value), note ? h("div", { class: "note" }, note) : null, trend || null);
        body.appendChild(h("div", { class: "tiles" },
          tile("Nodes up", `${t.nodes_ok}/${t.nodes}`, t.nodes - t.nodes_ok ? `${t.nodes - t.nodes_ok} without fresh data` : "all answering"),
          tile("Active bans", num(t.bans), `${num(t.bans_unique)} distinct addresses or networks`),
          tile("Bans, last hour", num(t.bans_1h), "last 3 hours, per 5 min", spark("bans")),
          tile("Events, last hour", num(t.events_1h), "last 3 hours, per 5 min", spark("events")),
          tile("Alerts, 24 hours", num(t.alerts_24h), `${num(t.alerts_24h_serious)} high or critical`),
          tile("Tracked addresses", num(t.tracked_ips), `${num(t.offenders)} offenders listed`)));

        const att = d.attention || [];
        // "seen": a click dims a problem (kept in this browser); it comes back if it goes and returns
        const seenKey = (a) => `${a.level}|${a.text}`;
        const grouped = groupAttention(att);
        const unseen = grouped.filter((a) => !state.seen[seenKey(a)]).length;
        // marks older than 30 days go, so the store doesn't grow with every problem ever seen
        const markSeen = (a, on) => {
          if (on) state.seen[seenKey(a)] = Date.now(); else delete state.seen[seenKey(a)];
          for (const [k, t] of Object.entries(state.seen)) if (Date.now() - t > 30 * 86400000) delete state.seen[k];
          setPref("lgw-seen", JSON.stringify(state.seen));
          saveMarks();
          update();
        };
        body.appendChild(card("Needs attention", h("span", { class: "muted" }, att.length ? `${num(unseen)} unseen of ${grouped.length}` : "",
          unseen < grouped.length && grouped.length ? h("button", { class: "btn small", type: "button", onclick: () => { for (const a of grouped) delete state.seen[seenKey(a)]; setPref("lgw-seen", JSON.stringify(state.seen)); update(); } }, "Show all") : null),
          att.length
            ? h("ul", { class: "attention" }, grouped.map((a) => h("li", { class: state.seen[seenKey(a)] ? "seen" : null, title: state.seen[seenKey(a)] ? "seen: click to bring it back" : "click when seen" }, status(a.level),
              h("span", { class: "nodes" }, a.nodes.length ? a.nodes.map((n) => [nodeChip(n.node, n.node_id), n.count ? h("span", { class: "count", title: `${num(n.count)} on ${n.node}` }, num(n.count)) : null, " "]) : h("span", { class: "muted" }, "cluster")),
              h("span", { class: "text", onclick: () => markSeen(a, !state.seen[seenKey(a)]) }, a.text))))
            : h("div", { class: "empty" }, status("good", "Nothing needs attention."))));
        body.appendChild(historyCard());

        const width = Math.min(1400, (shell.main.clientWidth || 900) - 34);
        const f = state.filters.overview;
        const range = RANGES[f.range] || RANGES["3h"];
        const hist = range.hours ? d.history.hours || { series: [] } : d.history;
        const events = nodeSeries("events", range), bans = nodeSeries("bans", range);
        // a range's first point: the history's end minus its points
        const start = range.points ? hist.start + (hist.count - range.points) * hist.step : hist.start;
        const rangeSeg = h("div", { class: "segmented", role: "group", "aria-label": "Range" },
          Object.entries(RANGES).map(([k, r]) => h("button", { type: "button", "aria-pressed": String(k === f.range), onclick: () => { f.range = k; update(); } }, r.label)));
        body.appendChild(card(`Activity, last ${range.label}`, h("span", { class: "chart-head" }, h("span", { class: "muted" }, `${range.per}, by node`), rangeSeg),
          h("div", { class: "body" },
            events.length ? [
              h("div", { class: "chart-title" }, "Events"),
              lineChart(events, start, hist.step, { width, height: 190, tick: range.tick, label: `Events ${range.per} by node` }),
              h("div", { class: "chart-title" }, "Bans"),
              lineChart(bans, start, hist.step, { width, height: 120, tick: range.tick, label: `Bans ${range.per} by node` }),
              chartTable(events, start, hist.step, range.group, range.groupLabel),
              range.hours ? h("div", { class: "muted small-note" }, "Hourly figures since each node's vpsfort started (it keeps a week).") : null,
            ] : h("div", { class: "empty" }, range.hours ? "No node's vpsfort keeps hourly figures yet (vpsfort 0.3.0 from 2026-10-28 on)." : "No figures yet."))));

        const order = d.nodes.slice().sort((a, b) => Number(state.pins.includes(b.id)) - Number(state.pins.includes(a.id)));
        body.appendChild(h("div", { class: "grid cols-3 section" }, order.map((n) => nodeCard(n, att.filter((a) => a.node_id === n.id)))));
        const differences = driftCard(d.nodes);
        if (differences) body.appendChild(differences);

        const alerts = d.alerts.slice(0, 8);
        body.appendChild(card("Latest alerts", h("a", { href: "#/alerts" }, "All alerts"),
          h("div", { class: "body flush" }, table("overview-alerts", alertCols(), alerts, { key: (a) => `${a.node_id}:${a.ts}:${a.message}`, detail: actionDetail, empty: "No alerts." }))));
      }),
    };
  }

  // The problems of the last 7 days as the console saw them come and go (its memory).
  function historyCard() {
    const hist = state.history;
    const open = state.historyOpen;
    const load = async () => {
      state.history = { loading: true };
      try { state.history = await api("/api/v1/attention/history"); } catch (e) { if (e instanceof LoginNeeded) return; state.history = { error: e.message }; }
      update();
    };
    const list = hist && hist.problems ? hist.problems.filter((p) => p.gone) : [];
    return card("Attention history", h("span", { class: "muted" }, open && hist && hist.problems ? `${num(list.length)} gone in the last 7 days · ` : "",
      h("button", { class: "btn small", type: "button", onclick: () => { state.historyOpen = !open; if (!open && !hist) load(); else update(); } }, open ? "Hide" : "Show"),
      open ? [" ", h("button", { class: "btn small", type: "button", disabled: hist && hist.loading, onclick: load }, "Again")] : null),
      !open ? h("div", { class: "empty" }, "What needed attention and went away, with when: the console remembers a week (a restart forgets).")
        : hist && hist.error ? h("div", { class: "empty" }, hist.error)
        : !hist || hist.loading ? h("div", { class: "empty" }, "Asking…")
        : h("div", { class: "body flush" }, table("attention-history", [
          { label: "Level", sort: (p) => SEV[p.level] || 0, cell: (p) => status(p.level) },
          { label: "Nodes", cell: (p) => (p.nodes.length ? nodeChips(p.nodes) : h("span", { class: "muted" }, "cluster")) },
          { label: "Problem", cls: "msg", cell: (p) => p.text },
          { label: "Appeared", sort: (p) => p.first, cell: (p) => timeCell(p.first) },
          { label: "Lasted", cls: "num", sort: (p) => p.last - p.first, cell: (p) => duration(Math.max(60000, ms(p.last) - ms(p.first))) },
          { label: "Gone", sort: (p) => p.gone, cell: (p) => timeCell(p.gone) },
        ], list, { key: (p) => `${p.level}:${p.text}:${p.first}`, sort: { col: "Gone", asc: false }, empty: "Nothing went away in the last 7 days." })));
  }

  async function exportCluster() {
    try {
      const got = await api("/api/v1/export");
      saveFile(`vpsfort-cluster-${stamp()}.json`, "application/json", JSON.stringify(got, null, 2));
    } catch (e) {
      if (!(e instanceof LoginNeeded)) alert(e.message);
    }
  }

  function nodeCard(n, problems) {
    const fact = (k, v, note) => h("div", { class: "fact" }, h("div", { class: "v" }, v), h("div", { class: "k" }, k, note ? h("span", { class: "muted" }, ` · ${note}`) : null));
    const has = n.mode !== undefined;
    return h("article", { class: "card node-card" },
      h("header", null, h("span", { class: "key-line", key: nodeKey(n.id), "aria-hidden": "true" }), h("a", { class: "name", href: `#/nodes/${encodeURIComponent(n.id)}` }, n.name),
        h("button", { class: `pin${state.pins.includes(n.id) ? " on" : ""}`, type: "button", title: state.pins.includes(n.id) ? "Unpin" : "Pin to the top", "aria-pressed": String(state.pins.includes(n.id)), onclick: () => { state.pins = state.pins.includes(n.id) ? state.pins.filter((x) => x !== n.id) : [...state.pins, n.id]; setPref("lgw-pins", JSON.stringify(state.pins)); update(); } }, "★"),
        h("span", { class: "grow" }), nodeState(n.state)),
      h("div", { class: "body" },
        has ? h("div", { class: "facts" },
          fact("Active bans", num(n.bans), n.bans_from_peers ? `${num(n.bans_from_peers)} from peers` : null),
          fact("Offenders", num(n.offenders)),
          fact("Tracked", num(n.tracked_ips)),
          fact("Alerts 24h", num(n.alerts_24h), n.alerts_24h_serious ? `${n.alerts_24h_serious} serious` : null),
          fact("Events 1h", num(n.events_1h)),
          fact("Bans 1h", num(n.bans_1h))) : h("div", { class: "muted" }, n.state === "waiting" ? "Not asked yet." : "No data from this node."),
        has ? h("div", { class: "meta" },
          h("span", { class: "chip" }, n.mode === "enforce" ? "enforce" : n.mode || "?"),
          n.backend ? h("span", { class: "chip" }, n.backend) : null,
          n.started ? h("span", { class: "chip", title: `started ${when(n.started)}` }, `up ${duration(Date.now() - ms(n.started))}`) : null,
          n.cluster ? h("span", { class: "chip", title: "cluster key fingerprint" }, `key ${n.cluster.key_id || "?"}`) : null) : null,
        problems.length ? h("div", { class: "problem", title: problems.map((p) => p.text).join("\n") }, status(problems[0].level), " ", brief(problems[0].text), problems.length > 1 ? h("span", { class: "muted" }, ` (+${problems.length - 1} more)`) : null) : null),
      // the address is the title already when the node has no name of its own
      h("footer", null, h("span", null, n.addr === "local" ? "this node" : n.addr === n.name ? "" : n.addr), h("span", null, n.fetched ? `data ${ago(n.fetched)}` : "")));
  }


  // ------------------------------------------------------------------ alerts & activity

  // The nodes a merged row came from, or the one node.
  const nodesCell = (a) => (a.nodes && a.nodes.length > 1 ? a.nodes.map((n) => [nodeChip(n.node, n.node_id), " "]) : nodeChip(a.node, a.node_id));
  const nodesCsv = (a) => (a.nodes ? a.nodes.map((n) => n.node).join(" ") : a.node);
  const countCell = (a) => (a.count > 1 ? h("span", { class: "chip count-chip", title: `${a.count} times: the same on ${a.nodes.length} node${a.nodes.length === 1 ? "" : "s"}` }, `×${a.count}`) : null);

  function alertCols() {
    return [
      { label: "Time", sort: (a) => a.ts, cell: (a) => [timeCell(a.ts), " ", countCell(a)], csv: (a) => utc(a.ts) },
      { label: "Node", sort: (a) => a.node, cell: nodesCell, csv: nodesCsv },
      { label: "Severity", sort: (a) => SEV[a.severity] || 0, cell: (a) => status(a.severity), csv: (a) => a.severity },
      { label: "Topic", sort: (a) => a.topic || "", cell: (a) => (a.topic ? a.topic.replace(/_/g, " ") : "") },
      { label: "Message", cls: "msg", cell: (a) => linked(a.message) },
    ];
  }

  const SEV = { info: 1, warning: 2, high: 3, critical: 4 };

  function actionDetail(a) {
    return h("div", null,
      kv([
        ["When", a.ts ? new Date(ms(a.ts)).toString() : null],
        ["Target", a.target ? addrLink(a.target) : null],
        ["Until", a.until ? `${when(a.until)} (${left(a.until)})` : null],
        ["Applied", a.kind === "ban" || a.kind === "unban" ? (a.applied ? "yes" : "no (shadow mode)") : null],
        ["Category", a.category],
        ["Accounts", a.accounts && a.accounts.length ? a.accounts.join(", ") : null],
        ["Replaced", a.superseded && a.superseded.length ? a.superseded.join(", ") : null],
        ["For the user", a.user_note],
      ]),
      a.evidence && a.evidence.length ? [h("h3", null, "Evidence"), evidence(a.evidence)] : null);
  }

  function viewAlerts(root) {
    const f = state.filters.alerts;
    const count = h("span", { class: "count" });
    const exp = h("span", { class: "export" });
    const nodeSel = select(nodeOptions(f.node), (v) => { f.node = v; update(); }, "Node");
    root.append(
      h("div", { class: "page-head" }, h("h1", null, "Alerts"), h("span", { class: "sub" }, "the latest from every node, newest first")),
      filterRow(
        select([["all", "All severities"], ["warning", "Warning and worse"], ["high", "High and critical"], ["critical", "Critical"]].map(([v, l]) => h("option", { value: v, selected: v === f.level }, l)), (v) => { f.level = v; update(); }, "Severity"),
        nodeSel,
        search(f.q, "Search messages, accounts, addresses", (v) => { f.q = v; update(); }),
        h("label", { title: "The same alert on several nodes, or repeated within a minute, as one row" }, h("input", { type: "checkbox", checked: f.merge, onchange: (e) => { f.merge = e.target.checked; update(); } }), "Merge repeats"),
        columnChooser("alerts", alertCols()), count, exp));
    const body = h("section", { class: "card" });
    root.appendChild(body);
    return {
      update() {
        patch(nodeSel, nodeOptions(f.node));
        const d = state.data;
        if (!ready("alerts")) return;
        const min = { all: 0, warning: 2, high: 3, critical: 4 }[f.level];
        let rows = d.alerts.filter((a) => (SEV[a.severity] || 0) >= min && (!f.node || a.node_id === f.node) && matches(f.q, a.message, a.target, (a.accounts || []).join(" "), a.topic, (a.evidence || []).join(" ")));
        const all = rows.length;
        if (f.merge) rows = mergeAcross(rows, alertKey);
        const fresh = newSince(rows, state.lastLook);
        count.textContent = `${num(rows.length)} alert${rows.length === 1 ? "" : "s"}${f.merge && rows.length < all ? ` (${num(all)} entries)` : ""}${fresh.count ? `, ${num(fresh.count)} new` : ""}`;
        patch(exp, tableExport("alerts", alertCols(), rows));
        patch(body, table("alerts", alertCols(), rows, { key: (a) => `${a.node_id}:${a.ts}:${a.message}`, detail: actionDetail, empty: "No alerts match.", rowClass: (a) => `sev-${a.severity}${fresh.isNew(a) ? " fresh" : ""}` }));
      },
    };
  }

  function viewActivity(root) {
    const f = state.filters.activity;
    const count = h("span", { class: "count" });
    const exp = h("span", { class: "export" });
    const nodeSel = select(nodeOptions(f.node), (v) => { f.node = v; update(); }, "Node");
    const body = h("section", { class: "card" });
    const cols = [
      { label: "Time", sort: (a) => a.ts, cell: (a) => [timeCell(a.ts), " ", countCell(a)], csv: (a) => utc(a.ts) },
      { label: "Node", sort: (a) => a.node, cell: nodesCell, csv: nodesCsv },
      { label: "Decision", sort: (a) => a.kind, cell: (a) => a.kind },
      { label: "Severity", sort: (a) => SEV[a.severity] || 0, cell: (a) => status(a.severity), csv: (a) => a.severity },
      { label: "Message", cls: "msg", cell: (a) => linked(a.message) },
    ];
    root.append(
      h("div", { class: "page-head" }, h("h1", null, "Activity"), h("span", { class: "sub" }, "every node's latest decisions: bans, unbans, alerts, allowlist changes")),
      filterRow(
        select([["", "All decisions"], ["ban", "Bans"], ["unban", "Unbans"], ["alert", "Alerts"], ["allow", "Allowed"], ["disallow", "Disallowed"]].map(([v, l]) => h("option", { value: v, selected: v === f.kind }, l)), (v) => { f.kind = v; update(); }, "Kind"),
        nodeSel,
        search(f.q, "Search", (v) => { f.q = v; update(); }),
        h("label", { title: "The same decision on several nodes (a peer's ban relayed to each) as one row" }, h("input", { type: "checkbox", checked: f.merge, onchange: (e) => { f.merge = e.target.checked; update(); } }), "Merge across nodes"),
        columnChooser("activity", cols), count, exp));
    root.appendChild(body);
    return {
      update() {
        patch(nodeSel, nodeOptions(f.node));
        const d = state.data;
        if (!ready("actions")) return;
        let rows = d.actions.filter((a) => (!f.kind || a.kind === f.kind) && (!f.node || a.node_id === f.node) && matches(f.q, a.message, a.target, a.category));
        const all = rows.length;
        if (f.merge) rows = mergeAcross(rows, decisionKey);
        const fresh = newSince(rows, state.lastLook);
        count.textContent = `${num(rows.length)} decision${rows.length === 1 ? "" : "s"}${f.merge && rows.length < all ? ` (${num(all)} entries)` : ""}${fresh.count ? `, ${num(fresh.count)} new` : ""}`;
        patch(exp, tableExport("activity", cols, rows));
        patch(body, table("activity", cols, rows, { key: (a) => `${a.node_id}:${a.ts}:${a.message}`, detail: actionDetail, empty: "Nothing matches.", rowClass: (a) => `sev-${a.severity}${fresh.isNew(a) ? " fresh" : ""}` }));
      },
    };
  }

  // ------------------------------------------------------------------ bans

  function viewBans(root) {
    const f = state.filters.bans;
    const count = h("span", { class: "count" });
    const exp = h("span", { class: "export" });
    const nodeSel = select(nodeOptions(f.node), (v) => { f.node = v; update(); }, "Node");
    const body = h("section", { class: "card" });
    const origin = (b) => (b.origin ? `from ${b.origin}` : "here");
    const cols = [
      { label: "Address or network", short: "Address", sort: (b) => b.net, cell: (b) => addrLink(b.net) },
      { label: "Node", sort: (b) => b.node, cell: (b) => nodeChip(b.node, b.node_id) },
      { label: "Decided", cls: "nowrap", sort: (b) => origin(b), cell: origin },
      { label: "Since", sort: (b) => b.since, cell: (b) => timeCell(b.since), csv: (b) => utc(b.since) },
      { label: "Left", cls: "num", sort: (b) => b.until, cell: (b) => h("span", { class: ended(b) ? "muted" : null }, left(b.until)), csv: (b) => utc(b.until) },
      { label: "Offence", cls: "num", sort: (b) => b.offence || 0, cell: (b) => (b.offence ? `#${b.offence}` : "") },
      { label: "Reason", cls: "msg", cell: (b) => b.reason },
    ];
    const grouped = [
      { label: "Address or network", sort: (g) => g.net, cell: (g) => addrLink(g.net) },
      { label: "Nodes", sort: (g) => g.bans.length, cell: (g) => g.bans.map((b) => [nodeChip(b.node, b.node_id), " "]), csv: (g) => g.bans.map((b) => b.node).join(" ") },
      { label: "First", sort: (g) => g.since, cell: (g) => timeCell(g.since), csv: (g) => utc(g.since) },
      { label: "Longest left", cls: "num", sort: (g) => g.until, cell: (g) => left(g.until), csv: (g) => utc(g.until) },
      { label: "Reason", cls: "msg", cell: (g) => g.bans.find((b) => !b.origin)?.reason || g.bans[0].reason },
    ];
    root.append(
      h("div", { class: "page-head" }, h("h1", null, "Bans"), h("span", { class: "sub" }, "in force on each node now")),
      filterRow(nodeSel, search(f.q, "Search addresses, networks, reasons", (v) => { f.q = v; update(); }),
        h("label", null, h("input", { type: "checkbox", checked: f.group, onchange: (e) => { f.group = e.target.checked; update(); } }), "One row per address"),
        columnChooser("bans", cols), count, exp));
    root.appendChild(body);
    return {
      update() {
        patch(nodeSel, nodeOptions(f.node));
        const d = state.data;
        if (!ready("bans")) return;
        const rows = d.bans.filter((b) => (!f.node || b.node_id === f.node) && matches(f.q, b.net, b.reason, b.origin));
        const total = d.totals.bans;
        if (f.group) {
          const by = new Map();
          for (const b of rows) {
            const g = by.get(b.net) || { net: b.net, bans: [], since: b.since, until: b.until };
            g.bans.push(b);
            g.since = Math.min(g.since, b.since);
            g.until = Math.max(g.until, b.until);
            by.set(b.net, g);
          }
          const groups = [...by.values()];
          count.textContent = `${num(groups.length)} addresses or networks`;
          patch(exp, tableExport("bans", grouped, groups));
          patch(body, table("bans-grouped", grouped, groups, { sort: { col: "First", asc: false }, empty: "No bans match." }));
        } else {
          count.textContent = `${num(rows.length)} ban${rows.length === 1 ? "" : "s"}${rows.length < total && !f.q && !f.node ? ` (the newest of ${num(total)})` : ""}`;
          patch(exp, tableExport("bans", cols, rows));
          patch(body, table("bans", cols, rows, { limit: 1000, empty: "No bans match." }));
        }
      },
    };
  }

  // ------------------------------------------------------------------ honeypots

  // How long a node's hits from its log are shown before they are asked again; what the
  // latest decisions add in between comes with every refresh.
  const HONEYPOTS_EVERY = 60 * 1000;
  const HONEYPOT_WINDOWS = { "24h": 86400e6, "7d": 7 * 86400e6 };

  async function loadHoneypots(win) {
    const cur = state.honeypots[win];
    if (cur && (cur.loading || Date.now() - cur.at < HONEYPOTS_EVERY)) return;
    state.honeypots[win] = { ...(cur || {}), loading: true };
    try {
      // the nodes read their actions logs first
      state.honeypots[win] = { data: await api(`/api/v1/honeypots/${win}`, { timeout: 150000 }), at: Date.now() };
    } catch (e) {
      if (e instanceof LoginNeeded) return;
      state.honeypots[win] = { data: cur && cur.data, error: e.message, at: Date.now() };
    }
    update();
  }

  function viewHoneypots(root) {
    const f = state.filters.honeypots;
    const count = h("span", { class: "count" });
    const exp = h("span", { class: "export" });
    const nodeSel = select(nodeOptions(f.node), (v) => { f.node = v; update(); }, "Node");
    const ports = h("div", { class: "chips ports" });
    const notes = h("div", { class: "trap-notes muted" });
    const q = search(f.q, "Search addresses, places, networks, ports, what was sent", (v) => { f.q = v; update(); });
    const kindSel = select([["", "Ports and decoy sites"], ["ports", "Honeypot ports"], ["web", "Decoy sites"]].map(([v, l]) => h("option", { value: v, selected: v === f.kind }, l)), (v) => { f.kind = v; update(); }, "Kind");
    // a chip narrows the table to its port (the decoy sites to their kind); the same chip again widens it
    const pick = (p) => {
      if (p === "web") {
        f.kind = f.kind === "web" ? "" : "web";
        kindSel.value = f.kind;
      } else {
        f.q = f.q.trim() === p ? "" : p;
        q.value = f.q;
      }
      update();
    };
    const picked = (p) => (p === "web" ? f.kind === "web" : f.q.trim() === p);
    const body = h("section", { class: "card" });
    const cols = [
      { label: "Time", sort: (r) => r.hit_ts, cell: (r) => timeCell(r.hit_ts), csv: (r) => utc(r.hit_ts) },
      { label: "Node", sort: (r) => r.node, cell: (r) => nodeChip(r.node, r.node_id) },
      { label: "Address", sort: (r) => r.addr, cell: (r) => addrLink(r.addr), csv: (r) => r.addr },
      { label: "Place", sort: (r) => r.place, cell: (r) => r.place },
      { label: "Network", sort: (r) => r.network, cell: (r) => r.network },
      { label: "Port", cls: "nowrap", sort: (r) => (r.port === "web" ? 0 : Number(r.port.slice(4))), cell: (r) => (r.port === "web" ? "decoy site" : r.port) },
      { label: "What it sent", cls: "msg", cell: (r) => h("span", { class: "mono" }, r.sent), csv: (r) => r.sent },
      { label: "Decision", cls: "nowrap", sort: (r) => r.kind, cell: (r) => (r.kind === "ban" && r.until ? `ban, ${left(r.until)}${ended(r) ? "" : " left"}` : r.kind), csv: (r) => r.kind },
    ];
    root.append(
      h("div", { class: "page-head" }, h("h1", null, "Honeypots"), h("span", { class: "sub" }, "what connected to the honeypot ports and the decoy sites, and what it sent")),
      filterRow(
        select(WINDOWS.map(([v, l]) => h("option", { value: v, selected: v === f.window }, l)), (v) => { f.window = v; update(); }, "Period"),
        kindSel,
        nodeSel,
        q,
        columnChooser("honeypots", cols), count, exp),
      notes,
      ports);
    root.appendChild(body);
    return {
      update() {
        patch(nodeSel, nodeOptions(f.node));
        const d = state.data;
        if (!ready("actions")) return;
        loadHoneypots(f.window);
        const log = state.honeypots[f.window] || { loading: true };
        // the logs, asked every minute, and the latest decisions, which come with every refresh
        const since = Date.now() * 1000 - HONEYPOT_WINDOWS[f.window];
        const all = trapHits([...((log.data && log.data.hits) || []), ...d.actions.filter((a) => a.ts >= since)], d.nodes).filter((r) => r.hit_ts >= since);
        // a port typed whole ("23", "TCP/23") is that port, not every port it is a prefix of
        const portQ = /^(?:tcp\/)?(\d+)$/i.exec((f.q || "").trim());
        const hit = (r) => (portQ ? r.port === `TCP/${portQ[1]}` : matches(f.q, r.addr, r.target, r.port, r.place, r.network, r.sent));
        const rows = all.filter((r) => (!f.node || r.node_id === f.node) && (!f.kind || (f.kind === "web") === (r.port === "web")) && hit(r));
        const by = new Map();
        for (const r of all.filter((r) => !f.node || r.node_id === f.node)) by.set(r.port, (by.get(r.port) || 0) + 1);
        const top = [...by.entries()].sort((a, b) => b[1] - a[1]);
        patch(ports, top.map(([p, n]) => h("button", { type: "button", class: `chip${picked(p) ? " on" : ""}`, "data-k": p, title: `${num(n)} hit${n === 1 ? "" : "s"}: click to show only these`, "aria-pressed": picked(p) ? "true" : "false", onclick: () => pick(p) }, p === "web" ? "decoy site" : p, " ", h("b", null, num(n)))));
        const fresh = newSince(rows, state.lastLook);
        const period = WINDOWS.find(([v]) => v === f.window)[1].toLowerCase();
        count.textContent = `${num(rows.length)} hit${rows.length === 1 ? "" : "s"}${fresh.count ? `, ${num(fresh.count)} new` : ""} in the ${period}${log.loading ? ", reading the nodes' logs…" : ""}`;
        const trouble = [
          log.error ? `The nodes' logs couldn't be read (${log.error}): only their latest decisions are shown.` : null,
          log.data && log.data.total > log.data.hits.length ? `The newest ${num(log.data.hits.length)} of ${num(log.data.total)} bans with a hit are shown.` : null,
          ...((log.data && log.data.nodes) || []).filter((n) => n.error && (!f.node || n.node_id === f.node)).map((n) => `${n.node}: only its latest decisions (${n.error}).`),
        ].filter(Boolean);
        patch(notes, trouble.map((t) => h("div", null, t)));
        patch(exp, tableExport("honeypots", cols, rows));
        patch(body, table("honeypots", cols, rows, { key: (r) => r.key, detail: actionDetail, sort: { col: "Time", asc: false }, limit: 1000, empty: log.loading && !all.length ? "Reading the nodes' logs…" : all.length ? "Nothing matches." : "No honeypot hit in this period. Honeypot ports and the decoy site are set up per node ([ports] honeypot, [sources] apps = [\"decoy\"]).", rowClass: (r) => (fresh.isNew(r) ? "fresh" : "") }));
      },
    };
  }

  // ------------------------------------------------------------------ offenders

  function viewOffenders(root) {
    const f = state.filters.offenders;
    const count = h("span", { class: "count" });
    const exp = h("span", { class: "export" });
    const nodeSel = select(nodeOptions(f.node), (v) => { f.node = v; update(); }, "Node");
    const body = h("section", { class: "card" });
    const accounts = h("div");
    const signals = (o) => Object.entries(o.counts || {}).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => `${v}× ${k}`).join(", ");
    const cols = [
      { label: "Address", sort: (o) => o.ip, cell: (o) => addrLink(o.ip) },
      { label: "Node", sort: (o) => o.node, cell: (o) => nodeChip(o.node, o.node_id) },
      { label: "Danger", sort: (o) => o.danger, cell: (o) => meter(o.danger, 60, 100), csv: (o) => Math.round(o.danger) },
      { label: "Last seen", sort: (o) => o.last_seen, cell: (o) => timeCell(o.last_seen), csv: (o) => utc(o.last_seen) },
      { label: "Signals", cell: signals },
      { label: "Place", sort: (o) => o.geo || "", cell: (o) => o.geo || "" },
      { label: "State", sort: (o) => (o.banned_by ? 2 : o.protected ? 1 : 0), cell: (o) => (o.banned_by ? `banned (${o.banned_by})` : o.protected ? `protected: ${o.protected}` : "") },
    ];
    const detail = (o) => h("div", null,
      kv([["Scores", `fast ${o.fast.toFixed(1)}, slow ${o.slow.toFixed(1)} (peak ${(o.peak || 0).toFixed(0)})`], ["First seen", when(o.first_seen)], ["Banned until", o.banned_until ? when(o.banned_until) : null],
        ["Signals", Object.entries(o.counts || {}).map(([k, v]) => `${v}× ${k}`).join(", ")]]),
      o.evidence && o.evidence.length ? [h("h3", null, "Evidence"), evidence(o.evidence)] : null);
    const acols = [
      { label: "Account", sort: (a) => a.account, cell: (a) => h("span", { class: "mono" }, a.account) },
      { label: "Node", sort: (a) => a.node, cell: (a) => nodeChip(a.node, a.node_id) },
      { label: "Failures", cls: "num", sort: (a) => a.failures, cell: (a) => a.failures.toFixed(1) },
      { label: "Addresses", cls: "num", sort: (a) => a.ips, cell: (a) => num(a.ips) },
      { label: "Under attack", sort: (a) => (a.under_attack ? 1 : 0), cell: (a) => (a.under_attack ? status("high", "yes") : "") },
    ];
    root.append(
      h("div", { class: "page-head" }, h("h1", null, "Offenders"), h("span", { class: "sub" }, "addresses with the highest scores on each node")),
      filterRow(nodeSel, search(f.q, "Search addresses, places, signals", (v) => { f.q = v; update(); }), columnChooser("offenders", cols), count, exp));
    root.append(body, accounts);
    return {
      update() {
        patch(nodeSel, nodeOptions(f.node));
        const d = state.data;
        if (!ready("offenders", "accounts")) return;
        const rows = d.offenders.filter((o) => (!f.node || o.node_id === f.node) && matches(f.q, o.ip, o.geo, Object.keys(o.counts || {}).join(" "), o.banned_by));
        count.textContent = `${num(rows.length)} address${rows.length === 1 ? "" : "es"}`;
        patch(exp, tableExport("offenders", cols, rows));
        patch(body, table("offenders", cols, rows, { key: (o) => `${o.node_id}:${o.ip}`, detail, empty: "No offenders match." }));
        const acc = d.accounts.filter((a) => !f.node || a.node_id === f.node);
        patch(accounts, acc.length ? card("Accounts with failed logins", null, h("div", { class: "body flush" }, table("accounts", acols, acc))) : "");
      },
    };
  }

  // ------------------------------------------------------------------ world

  function viewWorld(root, arg) {
    const f = state.filters.world;
    if (arg) { f.selected = arg.toUpperCase(); f.q = ""; }
    const clear = h("span", { class: "picked-now" });
    root.append(
      h("div", { class: "page-head" }, h("h1", null, "World"), h("span", { class: "sub" }, "where the trouble comes from, all nodes added up")),
      filterRow(search(f.q, "Search countries, networks", (v) => { f.q = v; f.selected = ""; update(); }), clear,
        h("span", { class: "count" }, "Pick a country for its networks and ports")));
    // bars: one event isn't a flood: the scale is at least 10
    const placeCols = (keyLabel, max) => [
      { label: keyLabel, sort: (p) => p.name || p.key, cell: (p) => h("span", null, p.name || p.key, p.key && p.name && p.key !== p.name ? h("span", { class: "muted" }, ` ${p.key}`) : null) },
      { label: "Bans", sort: (p) => p.bans, cell: (p) => barCell(p.bans, Math.max(10, max)) },
      { label: "Offenders", cls: "num", sort: (p) => p.offenders, cell: (p) => num(p.offenders) },
      { label: "Events", cls: "num", sort: (p) => p.events, cell: (p) => num(p.events) },
      { label: "Nodes", cls: "nodes", cell: (p) => nodeChips(p.nodes), csv: (p) => (p.nodes || []).join(" ") },
    ];
    return {
      update: livePart(root, (body) => {
        const d = state.data;
        if (!ready("world")) return;
        const w = d.world;
        const by = w.by_country || {};
        if (!w.geo) body.appendChild(h("div", { class: "error-banner" }, status("info", "No geo database"), "No node has [geo] set up: countries and networks are unknown. Ports are still counted."));
        const countries = w.countries.filter((p) => f.selected ? true : matches(f.q, p.name, p.key));
        // the countries whose networks and ports are shown: the one picked, else those the search finds
        const chosen = f.selected ? w.countries.filter((p) => p.key === f.selected) : f.q ? countries : [];
        const codes = chosen.map((p) => p.key);
        const what = chosen.length === 1 ? chosen[0].name || chosen[0].key : `${chosen.length} countries`;
        let nets, ports, note = null;
        if (codes.length) {
          const known = codes.filter((cc) => by[cc]);
          nets = known.length ? mergePlaces(known.flatMap((cc) => by[cc].isps)) : w.isps.filter((p) => codes.includes(p.country));
          ports = mergePorts(known.map((cc) => by[cc].ports));
          if (!known.length) note = "These nodes don't report ports per country (an older vpsfort).";
        } else {
          const name = (cc) => (w.countries.find((c) => c.key === cc) || {}).name;
          nets = w.isps.filter((p) => matches(f.q, p.name, p.key, p.country, name(p.country)));
          ports = w.ports;
        }
        // the picked country in the filter row: a chip with its figures, and the way back
        patch(clear, f.selected && chosen[0] ? [
          h("span", { class: "chip picked-chip" }, `${what} · ${num(chosen[0].bans)} bans · ${num(nets.length)} networks · ${num(ports.length)} ports`),
          h("a", { class: "btn small", href: `#/map`, title: "this country on the map" }, "Map"),
          h("button", { class: "btn small", type: "button", onclick: () => { f.selected = ""; f.all = false; f.allNets = false; f.allPorts = false; location.hash = "#/world"; update(); } }, `Show all, not only ${what}`),
        ] : "");
        const maxC = Math.max(0, ...countries.map((p) => p.bans));
        const maxI = Math.max(0, ...nets.map((p) => p.bans));
        const maxP = Math.max(0, ...ports.map((p) => p[1]));
        const names = w.port_names || {};
        const pick = (p) => { f.selected = f.selected === p.key ? "" : p.key; f.allNets = false; f.allPorts = false; update(); if (f.selected) window.scrollTo({ top: 0, behavior: "smooth" }); };
        // the list shows the top 15 unless asked for all, or searched: a hundred rows pushed
        // everything else off the screen
        const FOLD = 15;
        const sorted = countries.slice().sort((a, b) => b.bans - a.bans);
        const shown = f.all || f.q || (f.selected && sorted.findIndex((p) => p.key === f.selected) >= FOLD) ? countries : sorted.slice(0, FOLD);
        const picker = card("Countries", h("span", { class: "muted" }, w.unlocated ? `${num(w.unlocated)} offenders unlocated` : ""),
          h("div", { class: "body flush scrolls" }, table("countries", placeCols("Country", maxC), shown, { sort: { col: "Bans", asc: false }, pick, picked: (p) => codes.includes(p.key) })),
          countries.length > shown.length ? h("div", { class: "more" }, h("button", { class: "btn small", type: "button", onclick: () => { f.all = true; update(); } }, `Show all ${num(countries.length)} countries`)) : null);
        // networks and ports fold too: a big country's networks ran a screen long, a port scan
        // lists hundreds of ports; the top rows show, "Show all" or a search opens the rest
        const NETS = 10, PORTS = 10;
        const netsSorted = nets.slice().sort((a, b) => b.bans - a.bans || b.events - a.events);
        const netsShown = f.allNets || f.q ? nets : netsSorted.slice(0, NETS);
        const portsSorted = ports.slice().sort((a, b) => b[1] - a[1]);
        const portsShown = f.allPorts ? ports : portsSorted.slice(0, PORTS);
        const more = (hidden, label, flag) => (hidden > 0 ? h("div", { class: "more" }, h("button", { class: "btn small", type: "button", onclick: () => { f[flag] = true; update(); } }, label)) : null);
        const about = h("div", { class: "world-about" },
          card(codes.length ? `Networks in ${what}` : "Networks", h("span", { class: "muted" }, nets.length > netsShown.length ? `top ${netsShown.length} of ${num(nets.length)}` : `${num(nets.length)}`),
            h("div", { class: "body flush scrolls half" }, table("isps", placeCols("Network", maxI), netsShown, { sort: { col: "Bans", asc: false }, empty: codes.length ? "No networks reported for it." : "Nothing matches." })),
            more(nets.length - netsShown.length, `Show all ${num(nets.length)} networks`, "allNets")),
          card(codes.length ? `Busiest ports: ${what}` : "Busiest ports", h("span", { class: "muted" }, ports.length > portsShown.length ? `top ${portsShown.length} of ${num(ports.length)} · ` : "", "events per local port, recent activity weighted"),
            h("div", { class: "body flush scrolls half" }, table("ports", [
              { label: "Port", sort: (p) => p[0], cell: (p) => h("span", null, h("span", { class: "mono" }, p[0]), names[p[0]] ? h("span", { class: "muted" }, ` ${names[p[0]]}`) : null) },
              { label: "Events", sort: (p) => p[1], cell: (p) => barCell(p[1], Math.max(10, maxP)) },
            ], portsShown, { sort: { col: "Events", asc: false }, empty: note || "No events on any port." })),
            more(ports.length - portsShown.length, `Show all ${num(ports.length)} ports`, "allPorts")));
        // a picked country's cards first on a phone (the picker is long); the picker first otherwise
        body.appendChild(h("div", { class: `grid cols-2 world${f.selected ? " picked" : ""}` }, picker, about));
      }),
    };
  }


  // ------------------------------------------------------------------ map

  // Natural Earth's countries and vpsfort's capitals (/world.json), fetched and projected once.
  let worldMap = null;
  function loadWorld() {
    if (!worldMap) {
      worldMap = fetch("/world.json", { credentials: "same-origin" })
        .then((r) => { if (!r.ok) throw new Error(`the map didn't load (${r.status})`); return r.json(); })
        .then(prepareWorld);
      worldMap.catch(() => { worldMap = null; });
    }
    return worldMap;
  }

  // Equal Earth (Šavrič, Patterson, Jenny 2018): areas true to size, the continents' shapes kept.
  function project(lon, lat) {
    const A1 = 1.340264, A2 = -0.081106, A3 = 0.000893, A4 = 0.003796, M = Math.sqrt(3) / 2;
    const lam = (lon * Math.PI) / 180;
    const th = Math.asin(M * Math.sin((lat * Math.PI) / 180));
    const t2 = th * th, t6 = t2 * t2 * t2;
    const x = (2 * Math.sqrt(3) * lam * Math.cos(th)) / (3 * (9 * A4 * t6 * t2 + 7 * A3 * t6 + 3 * A2 * t2 + A1));
    const y = th * (A4 * t6 * t2 + A3 * t6 + A2 * t2 + A1);
    return [x * 100, -y * 100];
  }

  function line(points) {
    return points.map(([lon, lat], i) => { const [x, y] = project(lon, lat); return `${i ? "L" : "M"}${x.toFixed(2)} ${y.toFixed(2)}`; }).join("");
  }

  // Rings come as tenths of a degree, the first point whole, then the steps.
  function prepareWorld(doc) {
    const countries = doc.c.map(([iso, name, rings]) => {
      const d = rings.map((r) => {
        const pts = [[r[0] / 10, r[1] / 10]];
        let lon = r[0], lat = r[1];
        for (let i = 2; i < r.length; i += 2) { lon += r[i]; lat += r[i + 1]; pts.push([lon / 10, lat / 10]); }
        return `${line(pts)}Z`;
      }).join("");
      return { iso, name, d };
    });
    const edge = [];
    for (let lat = -90; lat <= 90; lat += 2) edge.push([180, lat]);
    for (let lat = 90; lat >= -90; lat -= 2) edge.push([-180, lat]);
    const grid = [];
    for (let lon = -150; lon <= 150; lon += 30) { const m = []; for (let lat = -80; lat <= 80; lat += 4) m.push([lon, lat]); grid.push(line(m)); }
    for (let lat = -60; lat <= 60; lat += 30) { const p = []; for (let lon = -180; lon <= 180; lon += 4) p.push([lon, lat]); grid.push(line(p)); }
    return { countries, sphere: `${line(edge)}Z`, graticule: grid.join(""), capitals: doc.cap || {} };
  }

  // The part shown, in map units: the world but Antarctica, or Europe (the TUI's "z").
  function mapBox(europe) {
    const [w, e, so, n] = europe ? [-25, 45, 34, 71] : [-180, 180, -58, 84];
    let x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
    for (let i = 0; i <= 40; i++) {
      const lon = w + ((e - w) * i) / 40, lat = so + ((n - so) * i) / 40;
      for (const [x, y] of [project(lon, so), project(lon, n), project(w, lat), project(e, lat)]) {
        x0 = Math.min(x0, x); x1 = Math.max(x1, x); y0 = Math.min(y0, y); y1 = Math.max(y1, y);
      }
    }
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
  }

  const METRICS = { bans: "active bans", offenders: "offenders", events: "events" };

  function viewMap(root) {
    const f = state.filters.map;
    const controls = h("div", { class: "filters" });
    root.append(h("div", { class: "page-head" }, h("h1", null, "Map"), h("span", { class: "sub" }, "every node's bans and logins, at their coordinates where a node's geo database is a city-level one, else at the country's capital")), controls);
    let world = null, failed = null;
    loadWorld().then((w) => { world = w; update(); }, (e) => { failed = e.message; update(); });
    const seg = (label, options, value, set) => h("div", { class: "segmented", role: "group", "aria-label": label },
      options.map(([v, l]) => h("button", { type: "button", "aria-pressed": String(v === value), onclick: () => { set(v); update(); } }, l)));
    const render = livePart(root, (body) => {
      banner(body);
      const d = state.data;
      if (failed) { body.appendChild(h("div", { class: "error-banner" }, status("warning", "No map"), failed)); return; }
      if (!ready("world") || !world) { body.appendChild(h("div", { class: "empty" }, ready("world") ? "Drawing the map…" : "Asking the nodes…")); return; }
      drawMap(body, d, world, f);
    });
    return {
      update() {
        patch(controls, [
          seg("Markers", Object.entries(METRICS).map(([k, l]) => [k, l[0].toUpperCase() + l.slice(1)]), f.metric, (v) => { f.metric = v; }),
          seg("Area", [[false, "World"], [true, "Europe"]], f.europe, (v) => { f.europe = v; })]);
        render();
      },
    };
  }

  function drawMap(body, d, world, f) {
    const w = d.world;
    if (!w.geo) body.appendChild(h("div", { class: "error-banner" }, status("info", "No geo database"), "No node has [geo] set up: nothing to place on the map but what [geoblock] blocks."));
    const places = new Map(w.countries.map((c) => [c.key, c]));
    const gb = w.geoblock || [];
    const blockedOn = (cc) => gb.filter((g) => g.countries.includes(cc) || (g.only_countries.length > 0 && !g.only_countries.includes(cc)));
    const box = mapBox(f.europe);
    const width = Math.max(320, Math.min(1400, (shell.main.clientWidth || 900) - 34));
    const height = Math.round((width * box.h) / box.w);
    const k = box.w / width; // map units per pixel
    const svg = s("svg", { class: "worldmap", viewBox: `${box.x} ${box.y} ${box.w} ${box.h}`, width, height, role: "img",
      "aria-label": `Map of ${METRICS[f.metric]} by country; the World tab has them as a table` });
    const hatch = 6 * k;
    svg.appendChild(s("defs", null, s("pattern", { id: "lgw-hatch", patternUnits: "userSpaceOnUse", width: hatch, height: hatch, patternTransform: "rotate(45)" },
      s("rect", { class: "hatch-bg", width: hatch, height: hatch }), s("line", { class: "hatch-line", x1: 0, y1: 0, x2: 0, y2: hatch, "stroke-width": 1.6 * k }))));
    svg.appendChild(s("path", { class: "sphere", d: world.sphere }));
    svg.appendChild(s("path", { class: "graticule", d: world.graticule }));

    const tip = h("div", { class: "tooltip hidden", role: "status" });
    // `spot`: a marker a city-level database placed ("Germany, Nuremberg"): its own figures,
    // then the country's
    const show = (cc, name, e, spot) => {
      const p = places.get(cc) || {};
      const users = (w.logged_in || {})[cc] || 0;
      const blocked = blockedOn(cc);
      const row = (key, value, label) => h("div", { class: "row" }, key, h("strong", null, value), h("span", null, label));
      const here = spot ? [
        spot.value ? row(h("span", { class: "mark ban" }, "▲"), num(spot.value), `${METRICS[f.metric]} here`) : null,
        spot.logins ? row(h("span", { class: "mark login" }, "●"), num(spot.logins), "logged in here, last hour") : null,
        h("div", { class: "note" }, `${p.name || cc}: ${num(p.bans || 0)} active bans, ${num(p.offenders || 0)} offenders, ${num(p.events || 0)} events`),
      ] : [
        row(h("span", { class: "mark ban" }, "▲"), num(p.bans || 0), "active bans"),
        row(h("span", { class: "mark" }), num(p.offenders || 0), "offenders"),
        row(h("span", { class: "mark" }), num(p.events || 0), "events"),
        users ? row(h("span", { class: "mark login" }, "●"), num(users), "logged in, last hour") : null,
      ];
      tip.replaceChildren(...[
        h("div", { class: "when" }, name || p.name || cc, cc ? ` ${cc}` : ""),
        ...here,
        blocked.length ? h("div", { class: "note" }, "Blocked by [geoblock] on ", blocked.map((g) => `${g.node}${g.applied ? "" : " (not applied)"}`).join(", ")) : null,
        p.nodes && p.nodes.length ? h("div", { class: "note" }, `Seen by ${p.nodes.join(", ")}`) : null,
        cc && places.has(cc) ? h("div", { class: "note muted" }, "Click: its networks and ports") : null,
      ].filter(Boolean));
      tip.classList.remove("hidden");
      const tw = tip.offsetWidth, th = tip.offsetHeight;
      tip.style.left = `${e.clientX + 16 + tw > window.innerWidth ? e.clientX - tw - 16 : e.clientX + 16}px`;
      tip.style.top = `${Math.max(8, Math.min(window.innerHeight - th - 8, e.clientY - 12))}px`;
    };
    const hide = () => tip.classList.add("hidden");
    const open = (cc) => { if (cc && places.has(cc)) location.hash = `#/world/${cc}`; };

    const land = s("g");
    for (const c of world.countries) {
      const blocked = c.iso && blockedOn(c.iso).length > 0;
      const path = s("path", { class: `land${blocked ? " blocked" : ""}${c.iso && places.has(c.iso) ? " seen" : ""}`, d: c.d });
      path.addEventListener("pointermove", (e) => { path.classList.add("hot"); show(c.iso, c.name, e); });
      path.addEventListener("pointerleave", () => { path.classList.remove("hot"); hide(); });
      path.addEventListener("click", () => open(c.iso));
      land.appendChild(path);
    }
    svg.appendChild(land);

    // ▲ sized by the metric (area grows with it) and ● addresses that logged in, one marker
    // per place: where a city-level database put them, the rest at the capitals
    const metric = f.metric;
    const { markers, off: offTotal } = mapMarkers(w, world.capitals, metric);
    const max = Math.max(1, ...markers.map((m) => m.value));
    const maxU = Math.max(1, ...markers.map((m) => m.logins));
    const size = (v) => (3.5 + 11 * Math.sqrt(v / max)) * k;
    const marks = s("g");
    for (const m of markers) {
      const [x, y] = project(m.lon, m.lat);
      const spot = m.spot ? m : null;
      const r = m.value > 0 ? size(m.value) : 0;
      if (m.value > 0) {
        const tri = s("path", { class: "ban", d: `M${x} ${y - r}L${x + r * 0.866} ${y + r * 0.5}L${x - r * 0.866} ${y + r * 0.5}Z` });
        tri.addEventListener("pointermove", (e) => show(m.key, m.name, e, spot));
        tri.addEventListener("pointerleave", hide);
        tri.addEventListener("click", () => open(m.key));
        marks.appendChild(tri);
      }
      if (m.logins > 0) {
        const ru = (2.5 + 6 * Math.sqrt(m.logins / maxU)) * k;
        // left of the triangle: its label goes to the right
        const dx = r > 0 ? -(r * 0.866 + ru + 1.5 * k) : 0;
        const dot = s("circle", { class: "login", cx: x + dx, cy: y, r: ru });
        dot.addEventListener("pointermove", (e) => show(m.key, m.name, e, spot));
        dot.addEventListener("pointerleave", hide);
        marks.appendChild(dot);
      }
    }
    svg.appendChild(marks);

    // labels for the most, one per country (its biggest marker), right of the marker (else
    // left), none over another
    const taken = [];
    const labelled = new Set();
    const labels = s("g", { class: "labels" });
    const font = 11 * k;
    for (const m of markers.filter((m) => m.value > 0 && !labelled.has(m.key) && labelled.add(m.key)).slice(0, f.europe ? 30 : 14)) {
      const [x, y] = project(m.lon, m.lat);
      if (x < box.x || x > box.x + box.w || y < box.y || y > box.y + box.h) continue;
      const r = size(m.value);
      const wText = font * 1.35;
      for (const [lx, anchor] of [[x + r * 0.9 + 2 * k, "start"], [x - r * 0.9 - 2 * k, "end"]]) {
        const x0 = anchor === "start" ? lx : lx - wText;
        const b = [x0, y - font * 0.7, x0 + wText, y + font * 0.4];
        if (taken.some((t) => b[0] < t[2] && b[2] > t[0] && b[1] < t[3] && b[3] > t[1])) continue;
        taken.push(b);
        labels.appendChild(s("text", { class: "label", x: lx, y: y + font * 0.35, "text-anchor": anchor, "font-size": font, "stroke-width": 3 * k }, m.key));
        break;
      }
    }
    svg.appendChild(labels);

    const marked = new Set(markers.filter((m) => m.value > 0).map((m) => m.key));
    const total = markers.reduce((a, m) => a + m.value, 0);
    const logged = markers.reduce((a, m) => a + m.logins, 0);
    const blockedNodes = gb.filter((g) => g.countries.length || g.only_countries.length);
    body.appendChild(h("section", { class: "card" },
      h("header", null, h("h2", null, `${num(total)} ${METRICS[metric]} in ${num(marked.size)} ${marked.size === 1 ? "country" : "countries"}`),
        offTotal ? h("span", { class: "muted" }, `+${num(offTotal)} where no capital is known`) : null, h("span", { class: "grow" })),
      // redrawn only when what it shows changes (the tooltip and the hover stay)
      h("div", { class: "map-wrap", "data-sig": JSON.stringify([w.countries, w.logged_in, w.spots, gb, f.metric, f.europe, width]) }, svg, tip),
      h("ul", { class: "legend map-legend" },
        h("li", null, h("span", { class: "mark ban" }, "▲"), `${METRICS[metric]} (bigger: more)`),
        d.nodes.some((n) => n.mode !== undefined) ? h("li", null, h("span", { class: "mark login" }, "●"), `${num(logged)} logged in during the last hour`) : null,
        h("li", null, h("span", { class: "swatch blocked" }), blockedNodes.length ? `blocked by [geoblock] on ${blockedNodes.map((g) => g.node).join(", ")}` : "blocked by [geoblock]: no node blocks countries"),
        h("li", { class: "muted attribution" }, "Countries: Natural Earth"))));

    const top = w.countries.filter((c) => marked.has(c.key)).sort((a, b) => b[metric] - a[metric]).slice(0, 12);
    if (top.length) {
      body.appendChild(card(`Most ${METRICS[metric]}`, h("a", { href: "#/world" }, "All countries"),
        h("div", { class: "body chips" }, top.map((c) => h("a", { class: "chip", href: `#/world/${c.key}`, title: c.name }, `${c.key} ${num(c[metric])}`)))));
    }
    if (gb.length) {
      body.appendChild(card("Blocked countries and networks", null, h("div", { class: "body flush" }, table("geoblock", [
        { label: "Node", cell: (g) => nodeChip(g.node, g.node_id) },
        { label: "Blocks", cls: "msg", cell: (g) => g.what || "" },
        { label: "State", cell: (g) => (g.error ? status("warning", g.error) : g.applied ? status("good", "in force") : status("info", "not applied (shadow mode or the backend)")) },
      ], gb))));
    }
  }

  // ------------------------------------------------------------------ one node

  function viewNode(root, id) {
    return {
      update: livePart(root, (body) => {
        banner(body);
        const d = state.data;
        const summary = d && d.nodes.find((n) => n.id === id);
        if (!summary) { body.appendChild(h("div", { class: "empty" }, d ? "No such node." : "Asking the nodes…")); return; }
        const detail = state.node[id];
        const snap = (detail && detail.snapshot) || {};
        const others = d.nodes.filter((n) => n.id !== id);
        body.appendChild(h("div", { class: "page-head" },
          h("h1", null, summary.name), nodeState(summary.state),
          h("span", { class: "sub" }, summary.addr === "local" ? "this node" : summary.addr),
          others.length ? h("span", { class: "sub" }, "· other nodes: ", others.map((n) => [nodeChip(n.name, n.id), " "])) : null));
        if (detail && detail.error) body.appendChild(h("div", { class: "error-banner" }, status("warning", "Can't read this node"), detail.error));
        const changes = snapshotDiff(state.previous[id], snap);
        if (changes.length) body.appendChild(h("div", { class: "notice" }, status("info", "Since the last snapshot"), h("span", null, `${when(state.previous[id].generated)}: ${changes.join(", ")}`)));
        const att = (detail && detail.attention) || [];
        if (att.length) body.appendChild(card("Needs attention", null, h("ul", { class: "attention" }, att.map((a) => h("li", null, status(a.level), h("span"), h("span", { class: "text" }, a.text))))));
        const grid = h("div", { class: "grid cols-2" });
        body.appendChild(grid);

        const stats = snap.stats || {};
        grid.appendChild(card("vpsfort", null, h("div", { class: "body" }, kv([
          ["Mode", snap.mode ? (snap.mode === "enforce" ? "enforce" : `${snap.mode}: bans are not applied`) : null],
          ["Firewall", snap.backend],
          ["Started", snap.started ? `${when(snap.started)} (up ${duration(Date.now() - ms(snap.started))})` : null],
          ["Data from", snap.generated ? `${when(snap.generated)} (${ago(snap.generated)})` : null],
          ["Tracked addresses", num(snap.tracked_ips)],
          ["Connections in grace", snap.tracked_connections !== undefined ? num(snap.tracked_connections) : null],
          ["Bans since start", stats.bans !== undefined ? num(stats.bans) : null],
          ["Alerts since start", stats.alerts !== undefined ? num(stats.alerts) : null],
          ["Thresholds", snap.fast_threshold ? `fast ${snap.fast_threshold}, slow ${snap.slow_threshold}` : null],
          ["vpsfort-web", summary.version || (summary.addr === "local" ? "this console" : null)],
          ["Answer time", summary.latency_ms !== null && summary.latency_ms !== undefined ? `${summary.latency_ms} ms` : null],
        ]))));

        const lines = Object.entries(snap.last_lines || {});
        const records = stats.records || {};
        grid.appendChild(card("Log sources", null, h("div", { class: "body flush" }, table(`sources-${id}`, [
          { label: "Source", sort: (r) => r[0], cell: (r) => r[0] },
          { label: "Newest line", sort: (r) => r[1], cell: (r) => h("span", { title: when(r[1]) }, ago(r[1])) },
          { label: "Lines read", cls: "num", sort: (r) => records[r[0]] || 0, cell: (r) => num(records[r[0]] || 0) },
        ], lines, { empty: "No lines read yet." }))));

        if (snap.cluster) grid.appendChild(clusterCard(snap.cluster, id));
        if (snap.certs && snap.certs.length) grid.appendChild(card("Certificates", null, h("div", { class: "body flush" }, table(`certs-${id}`, [
          { label: "Certificate", sort: (c) => c.target, cell: (c) => h("span", { class: "mono" }, c.target) },
          { label: "Expires", sort: (c) => c.not_after || 0, cell: (c) => (c.error ? status("warning", c.error) : c.not_after ? h("span", { title: when(c.not_after) }, left(c.not_after)) : "") },
          { label: "Names", cell: (c) => (c.names || []).join(", ") },
        ], snap.certs))));
        if (snap.resources) grid.appendChild(resourcesCard(snap.resources));
        if (snap.patches) grid.appendChild(patchesCard(snap.patches));
        const integrity = integrityCard(snap);
        if (integrity) grid.appendChild(integrity);
        const waf = snap.waf;
        const wafBans = waf ? (waf.sources || []).reduce((n, s) => n + (s.banned || 0), 0) : 0;
        const wafList = waf ? (waf.list_v4 || 0) + (waf.list_v6 || 0) : 0;
        const wafErrors = waf ? (waf.sources || []).filter((s) => s.error).map((s) => `${s.name}: ${s.error}`).concat(waf.error ? [waf.error] : []) : [];
        if (snap.feeds || snap.geoblock || waf) grid.appendChild(card("Blocklists", null, h("div", { class: "body" }, kv([
          ["Feeds", snap.feeds ? `${num(snap.feeds.v4)} IPv4 and ${num(snap.feeds.v6)} IPv6 networks, ${snap.feeds.applied ? "in the firewall" : "not applied"}, refreshed ${ago(snap.feeds.refreshed)}` : null],
          ["Feed error", snap.feeds && snap.feeds.error],
          ["WAF decisions", waf ? `${(waf.sources || []).map((s) => s.name).join(", ")}: ${num(wafBans)} bans${wafList ? `, ${num(wafList)} listed networks${waf.applied ? "" : " (not applied)"}` : ""}, read ${ago(waf.refreshed)}` : null],
          ["WAF error", wafErrors.length ? wafErrors.join("; ") : null],
          ["Country/network blocking", snap.geoblock ? `${snap.geoblock.what}: ${num(snap.geoblock.v4)} IPv4 and ${num(snap.geoblock.v6)} IPv6 networks, ${snap.geoblock.applied ? "in the firewall" : "not applied"}` : null],
          ["Blocking error", snap.geoblock && snap.geoblock.error],
        ]))));
        if (snap.exposure) body.appendChild(exposureCard(snap.exposure, id));
        const allowed = snap.allowed || [];
        if (allowed.length || (snap.trusted || []).length || (snap.allow_hosts || []).length) {
          body.appendChild(card("Allowed and trusted", null, h("div", { class: "body" },
            allowed.length ? [h("h3", null, "Operator allowlist"), ...table(`allowed-${id}`, [
              { label: "Network", sort: (a) => a.net, cell: (a) => h("span", { class: "mono" }, a.net) },
              { label: "Left", sort: (a) => a.until, cell: (a) => left(a.until) },
              { label: "Note", cls: "msg", cell: (a) => a.note },
            ], allowed)] : null,
            (snap.trusted || []).length ? [h("h3", null, "Trusted (logged in lately)"), h("div", { class: "mono" }, snap.trusted.slice(0, 100).map((t) => `${t[0]} `))] : null,
            (snap.allow_hosts || []).length ? [h("h3", null, "[allowlist] hosts resolve to"), h("div", { class: "mono" }, snap.allow_hosts.join(" "))] : null)));
        }
        if ((snap.patterns || []).length) body.appendChild(card("Patterns", null, h("div", { class: "body flush" }, table(`patterns-${id}`, [
          { label: "Reads", cell: (p) => p.from },
          { label: "Kind", cell: (p) => p.kind },
          { label: "Points", cls: "num", cell: (p) => num(p.weight) },
          { label: "Addresses", cls: "num", sort: (p) => p.addresses, cell: (p) => num(p.addresses) },
        ], snap.patterns))));

        const digest = state.digest[id];
        const past = state.digests[id];
        const pick = (past && past.pick) || "";
        const shown = past && past.digests && pick ? past.digests.find((x) => x.day === pick) : null;
        body.appendChild(card("Today's digest so far", h("span", null,
          h("button", { class: "btn small", type: "button", onclick: () => loadDigest(id) }, digest ? "Again" : "Show"), " ",
          h("button", { class: "btn small", type: "button", title: "The last two weeks' digests of this node, as the console kept them", onclick: () => loadDigests(id) }, past && past.digests ? "Past days again" : "Past days"), " ",
          h("button", { class: "btn small", type: "button", disabled: !detail || !detail.snapshot, title: "This page's data: the summary, the problems and the whole snapshot", onclick: () => download(summary.name, detail) }, "Download JSON"), " ",
          h("button", { class: "btn small", type: "button", disabled: !detail || !detail.snapshot, title: "The snapshot alone, as `vpsfort tui --file` reads it", onclick: () => download(`${summary.name}-snapshot`, detail.snapshot) }, "Snapshot")),
        digest ? (digest.error ? h("div", { class: "empty" }, status("warning", digest.error)) : h("pre", { class: "digest" }, digest.text)) : h("div", { class: "empty" }, "The daily summary vpsfort sends the admins, as it stands now."),
        past ? (past.error ? h("div", { class: "empty" }, status("warning", past.error))
          : !past.digests ? h("div", { class: "empty" }, "Asking…")
          : !past.digests.length ? h("div", { class: "empty" }, "No day kept yet: the console keeps each day's digest when it is shown here, and every node's shortly before midnight UTC, for two weeks.")
          : [h("div", { class: "filters" }, h("span", { class: "muted" }, "Past days:"), select(past.digests.map((x) => h("option", { value: x.day, selected: x.day === (pick || past.digests[0].day) }, x.day)), (v) => { past.pick = v; update(); }, "Day")),
            h("pre", { class: "digest" }, (shown || past.digests[0]).text)]) : null));

        body.appendChild(abuseCard(id));
      }),
    };
  }

  async function loadDigests(id) {
    state.digests[id] = { pick: (state.digests[id] || {}).pick };
    update();
    try {
      const got = await api(`/api/v1/nodes/${encodeURIComponent(id)}/digests`);
      state.digests[id] = { digests: got.digests, pick: state.digests[id].pick };
    } catch (e) {
      if (e instanceof LoginNeeded) return;
      state.digests[id] = { error: e.message };
    }
    update();
  }

  async function loadDigest(id) {
    state.digest[id] = { text: "…" };
    update();
    try {
      state.digest[id] = await api(`/api/v1/nodes/${encodeURIComponent(id)}/digest`);
    } catch (e) {
      if (e instanceof LoginNeeded) return;
      state.digest[id] = { error: e.message };
    }
    update();
  }

  function download(name, detail) {
    saveFile(`vpsfort-${name}-${stamp()}.json`, "application/json", JSON.stringify(detail, null, 2));
  }

  // ------------------------------------------------------------------ abuse reports

  const WINDOWS = [["24h", "Last 24 hours"], ["7d", "Last 7 days"]];
  // Reports are built from a week of each node's actions log: asked again only this often
  // (and on "Again"), not on every refresh.
  const ABUSE_EVERY = 5 * 60 * 1000;

  // The reports of `scope` ("all", or a node's id) for both windows, asked when missing or old.
  function wantAbuse(scope, force) {
    for (const [win] of WINDOWS) loadAbuse(scope, win, force);
  }

  async function loadAbuse(scope, win, force) {
    const k = `${scope}:${win}`;
    const cur = state.abuse[k];
    if (cur && (cur.loading || (!force && Date.now() - cur.at < ABUSE_EVERY))) return;
    state.abuse[k] = { ...(cur || {}), loading: true };
    const path = scope === "all" ? `/api/v1/abuse/${win}` : `/api/v1/nodes/${encodeURIComponent(scope)}/abuse/${win}`;
    try {
      // the nodes read a week of their actions logs first
      state.abuse[k] = { data: await api(path, { timeout: 150000 }), at: Date.now() };
    } catch (e) {
      if (e instanceof LoginNeeded) return;
      state.abuse[k] = { data: cur && cur.data, error: e.message, at: Date.now() };
    }
    update();
  }

  // What the export buttons last did, shown a few seconds: {key, text}.
  let exported = null;

  function exportNote(key, text) {
    exported = { key, text };
    update();
    setTimeout(() => { if (exported && exported.key === key && exported.text === text) { exported = null; update(); } }, 3000);
  }

  // The provider's e-mail text to the clipboard; where the browser refuses, its text opened
  // and selected instead, for copying by hand.
  async function copyProvider(p, report, scope) {
    const key = `${scope}:${report.window}:${p.key}`;
    try {
      await navigator.clipboard.writeText(abuseText(p, report));
      exportNote(key, "Copied");
    } catch (_) {
      state.open.add(`abuse-${scope}-${report.window}:${p.key}`);
      state.open.add(`abuse-text:${key}`);
      exportNote(key, "See below");
      const pre = document.querySelector(`pre[data-text="${CSS.escape(key)}"]`);
      if (pre) window.getSelection().selectAllChildren(pre);
    }
  }

  function saveProvider(p, report, scope, note = true) {
    const name = (p.asn ? `AS${p.asn}` : providerName(p)).replace(/[^A-Za-z0-9.-]+/g, "-").slice(0, 60);
    saveFile(`abuse-${name}-${report.window}-${new Date(ms(report.to)).toISOString().slice(0, 10)}.txt`, "text/plain;charset=utf-8", abuseText(p, report));
    if (note) exportNote(`${scope}:${report.window}:${p.key}`, "Saved");
  }

  // ---------------- abuse mailboxes (RDAP)

  const RDAP_KEEP = 7 * 86400000;
  function rdapCache() {
    try { return JSON.parse(localStorage.getItem("lgw-rdap") || "{}"); } catch (_) { return {}; }
  }

  // The abuse mailbox of `ip`'s network: asked by the console, else (it can't, or isn't
  // allowed to) by this browser from rdap.org, which sends it on to the registry. Kept a week
  // in this browser.
  async function lookupRdap(ip) {
    const cache = rdapCache();
    if (cache[ip] && Date.now() - cache[ip].at < RDAP_KEEP) return cache[ip];
    let got;
    try {
      got = { ...(await api(`/api/v1/rdap/${ip}`, { timeout: 60000 })), via: "console" };
    } catch (e) {
      if (e instanceof LoginNeeded || /not a public address/.test(e.message)) throw e;
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 30000);
      try {
        const res = await fetch(`https://rdap.org/ip/${ip}`, { headers: { Accept: "application/rdap+json" }, credentials: "omit", referrerPolicy: "no-referrer", signal: ctl.signal });
        if (!res.ok) throw new Error(res.status === 404 ? "no registry knows it" : `RDAP answered ${res.status}`);
        got = { ...parseRdap(await res.json()), via: "browser" };
      } catch (b) {
        throw new Error(`the console: ${e.message}; this browser: ${b.name === "AbortError" ? "no answer in time" : b.message}`);
      } finally {
        clearTimeout(timer);
      }
    }
    got.at = Date.now();
    const keep = Object.fromEntries(Object.entries(cache).filter(([, v]) => Date.now() - v.at < RDAP_KEEP).slice(-500));
    keep[ip] = got;
    setPref("lgw-rdap", JSON.stringify(keep));
    return got;
  }

  // A provider's network is asked about by its first source's address.
  const lookupIp = (p) => (p.sources[0] ? p.sources[0].net.split("/")[0] : "");

  async function findMailbox(p) {
    const m = (state.mailbox[p.key] = { busy: true });
    update();
    try { Object.assign(m, await lookupRdap(lookupIp(p))); } catch (e) { if (e instanceof LoginNeeded) return; m.error = e.message; }
    m.busy = false;
    update();
    return m;
  }

  // Opens the mail program with the e-mail to the provider's abuse desk; a long report goes in
  // part (the link can't carry it all) and is saved as a .txt to attach.
  async function mailProvider(p, report, scope) {
    const key = `${scope}:${report.window}:${p.key}`;
    const m = state.mailbox[p.key] && state.mailbox[p.key].abuse ? state.mailbox[p.key] : await findMailbox(p);
    if (!m || !m.abuse || !m.abuse.length) { exportNote(key, m && m.error ? "No lookup" : "No mailbox"); return; }
    const { url, cut } = mailto(m.abuse, p, report);
    if (cut) saveProvider(p, report, scope, false);
    const a = h("a", { href: url });
    a.click();
    exportNote(key, cut ? "Mail + .txt" : "Mail opened");
  }

  // ---------------- marked mailed (kept in this browser)

  function reportedMarks() {
    try { return JSON.parse(localStorage.getItem("lgw-reported") || "{}"); } catch (_) { return {}; }
  }

  function markReported(p, on) {
    const marks = reportedMarks();
    if (on) marks[p.key] = { at: Date.now(), name: providerName(p), sources: p.sources.map((x) => x.net) };
    else delete marks[p.key];
    for (const [k, v] of Object.entries(marks)) if (Date.now() - v.at > 4 * REPORTED_DAYS * 86400000) delete marks[k];
    setPref("lgw-reported", JSON.stringify(marks));
    saveMarks();
    update();
  }

  // The marks (reports mailed, problems seen) also live on the console, shared by every
  // admin and browser and kept across its restarts: what it holds wins at the start, and
  // every change goes back to it.
  state.marksKept = false;
  async function loadMarks() {
    try {
      const got = await api("/api/v1/marks");
      state.marksKept = Boolean(got.kept);
      const m = got.marks || {};
      if (m.reported && typeof m.reported === "object") setPref("lgw-reported", JSON.stringify(m.reported));
      if (m.seen && typeof m.seen === "object") { state.seen = m.seen; setPref("lgw-seen", JSON.stringify(m.seen)); }
    } catch (_) { /* an older console, or not logged in: this browser's marks stand */ }
  }
  function saveMarks() {
    const body = JSON.stringify({ reported: reportedMarks(), seen: state.seen || {} });
    api("/api/v1/marks", { method: "POST", body }).catch(() => {});
  }

  // Copy, .txt and Mail for one provider's row; they don't open the row, and say for a moment
  // what they did in their own label.
  function exportButtons(p, report, scope) {
    const key = `${scope}:${report.window}:${p.key}`;
    const did = exported && exported.key === key ? exported.text : null;
    const quiet = { onkeydown: (e) => e.stopPropagation() };
    const m = state.mailbox[p.key];
    return h("span", { class: "export" },
      h("button", { class: "btn small", type: "button", title: "The e-mail to this network's abuse desk, to paste", ...quiet, onclick: (e) => { e.stopPropagation(); copyProvider(p, report, scope); } }, did === "Copied" || did === "See below" ? did : "Copy"),
      h("button", { class: "btn small", type: "button", title: "The same text as a .txt file", ...quiet, onclick: (e) => { e.stopPropagation(); saveProvider(p, report, scope); } }, did === "Saved" ? "Saved" : ".txt"),
      h("button", {
        class: "btn small", type: "button", disabled: Boolean(m && m.busy), ...quiet,
        title: m && m.abuse ? `To ${m.abuse.join(", ") || "nobody: RDAP gives no abuse mailbox"}` : "Look up the abuse mailbox (RDAP) and open the e-mail in your mail program",
        onclick: (e) => { e.stopPropagation(); mailProvider(p, report, scope); },
      }, m && m.busy ? "Asking…" : did && !["Copied", "See below", "Saved"].includes(did) ? did : "Mail"));
  }

  // "seen again: 2 sources" after a report: the mail changed nothing (or not yet).
  function reoffendedChip(p) {
    const r = reoffended(p, reportedMarks());
    if (!r) return null;
    return h("span", { class: "chip warn", title: `${r.count} of its sources banned again after it was marked mailed (${when(r.since * 1000)})` }, `seen again: ${num(r.count)}`);
  }

  // "mailed 3 days ago", with its undo.
  function reportedChip(p) {
    const r = reportedMarks()[p.key];
    if (!r) return null;
    return h("span", { class: "chip reported", title: `Marked mailed ${when(r.at * 1000)} in this browser; its ${r.sources.length} sources count as reported for ${REPORTED_DAYS} days` }, `mailed ${ago(r.at * 1000)}`);
  }

  function providerDetail(p, report, scope) {
    const key = `${scope}:${report.window}:${p.key}`;
    const tk = `abuse-text:${key}`;
    const asText = state.open.has(tk);
    const text = abuseText(p, report);
    return h("div", { class: "abuse-detail" },
      h("div", { class: "actions" },
        h("button", { class: "btn small", type: "button", onclick: (e) => { e.stopPropagation(); if (asText) state.open.delete(tk); else state.open.add(tk); update(); } }, asText ? "As a list" : "As e-mail text"),
        h("button", { class: "btn small", type: "button", onclick: (e) => { e.stopPropagation(); markReported(p, !reportedMarks()[p.key]); } }, reportedMarks()[p.key] ? "Unmark mailed" : "Mark mailed"),
        reportedChip(p),
        mailboxLine(p)),
      asText ? h("pre", { class: "digest", "data-text": key }, text) : p.sources.slice(0, 200).map((x) => h("div", { class: "abuse-source" },
        h("div", { class: "head" },
          addrLink(x.net),
          x.country_name ? h("span", { class: "muted" }, x.country_name) : null,
          h("span", { class: "muted", title: `${utc(x.first)} - ${utc(x.last)}` }, `${when(x.first)} – ${when(x.last)}`),
          h("span", null, `${num(x.bans)} ban${x.bans === 1 ? "" : "s"}, ${num(x.events)} log line${x.events === 1 ? "" : "s"}`),
          scope === "all" ? (x.nodes || []).map((n) => h("span", { class: "chip" }, n)) : null),
        h("div", { class: "activity" }, x.activity),
        (x.members || []).length ? h("div", { class: "mono small" }, `Addresses: ${x.members.join(", ")}`) : null,
        (x.evidence || []).length ? h("ul", { class: "evidence" },
          x.evidence.map((l) => h("li", null, h("span", { class: "muted nowrap", title: utc(l.ts) }, when(l.ts)), " ",
            scope === "all" && l.server ? h("span", { class: "chip" }, l.server) : null, " ", linked(l.text))),
          x.omitted ? h("li", { class: "muted" }, `… and ${num(x.omitted)} more`) : null) : null)),
      !asText && p.sources.length > 200 ? h("div", { class: "more" }, `The first 200 of ${num(p.sources.length)} sources; the text has them all.`) : null);
  }

  // The provider's abuse mailbox, once looked up, or the button that looks it up.
  function mailboxLine(p) {
    const m = state.mailbox[p.key] || (rdapCache()[lookupIp(p)] ? (state.mailbox[p.key] = { ...rdapCache()[lookupIp(p)] }) : null);
    if (!m) return h("button", { class: "btn small", type: "button", onclick: (e) => { e.stopPropagation(); findMailbox(p); } }, "Look up the abuse mailbox");
    if (m.busy) return h("span", { class: "muted" }, "Asking RDAP…");
    if (m.error) return h("span", { class: "muted", title: m.error }, `No mailbox found: ${m.error}`);
    return h("span", { class: "mailbox" }, m.abuse.length ? `Abuse mailbox: ${m.abuse.join(", ")}` : "RDAP gives no abuse mailbox",
      h("span", { class: "muted" }, ` · ${m.network || "?"} (RDAP via ${m.via === "browser" ? "this browser" : "the console"})`));
  }

  // The merged report as CSV: one line per source.
  function abuseCsv(rows, r) {
    const lines = [["network", "asn", "countries", "source", "country", "first_seen_utc", "last_seen_utc", "bans", "log_lines", "nodes", "activity", "abuse_mailbox"]];
    for (const p of rows) {
      const m = state.mailbox[p.key];
      for (const x of p.sources) {
        lines.push([providerName(p), p.asn || "", p.countries.map((c) => c[0]).join(" "), x.net, x.country || "", utc(x.first), utc(x.last), x.bans, x.events, (x.nodes || []).join(" "), x.activity, m && m.abuse ? m.abuse.join(" ") : ""]);
      }
    }
    saveFile(`vpsfort-abuse-${r.window}-${stamp()}.csv`, "text/csv;charset=utf-8", csv(lines));
  }

  // The report of `scope` as the page shows it: the windows, a filter, one row per provider.
  function abuseReport(scope) {
    const f = state.filters.abuse;
    wantAbuse(scope, false);
    const got = (win) => state.abuse[`${scope}:${win}`] || { loading: true };
    const cur = got(f.window);
    const seg = h("div", { class: "segmented", role: "group", "aria-label": "Period" }, WINDOWS.map(([win, label]) => {
      const g = got(win);
      const n = g.data ? abuseRows(g.data, f, reportedMarks()).length : null;
      return h("button", { type: "button", "aria-pressed": String(win === f.window), onclick: () => { f.window = win; update(); } },
        label, n !== null ? h("span", { class: "count-in" }, num(n)) : null);
    }));
    const controls = filterRow(seg,
      h("input", { type: "search", value: f.q, placeholder: "Search networks, addresses, activity", "aria-label": "Search", oninput: (e) => { f.q = e.target.value; update(); } }),
      h("label", null, h("input", { type: "checkbox", checked: f.worth, onchange: (e) => { f.worth = e.target.checked; update(); } }), `Only sources with ${WORTH}+ log lines`),
      h("label", { title: `Sources of networks marked mailed in this browser in the last ${REPORTED_DAYS} days` }, h("input", { type: "checkbox", checked: f.fresh, onchange: (e) => { f.fresh = e.target.checked; update(); } }), "Hide those already mailed"),
      h("label", { title: "The checklist: networks not yet mailed, most bans first, with just Copy, Mail and Mark" }, h("input", { type: "checkbox", checked: f.todo, onchange: (e) => { f.todo = e.target.checked; if (f.todo) f.fresh = true; update(); } }), "To send"),
      h("button", { class: "btn small", type: "button", disabled: cur.loading, onclick: () => wantAbuse(scope, true) }, cur.loading ? "Asking…" : "Again"),
      h("span", { class: "count" }, cur.at ? `built ${timeFmt.format(new Date(cur.at))}` : ""));
    const out = [controls];
    const r = cur.data;
    if (cur.error) out.push(h("div", { class: "error-banner" }, status("warning", "No report"), cur.error));
    if (!r) { out.push(h("div", { class: "empty" }, cur.loading ? "The nodes are building their reports from their actions logs…" : "No report.")); return out; }
    const missing = r.nodes.filter((n) => n.error);
    if (missing.length) out.push(h("div", { class: "error-banner" }, status("info", missing.length === r.nodes.length ? "No node answered" : "Without"), missing.map((n) => `${n.name}: ${n.error}`).join("; ")));
    const beyond = r.nodes.reduce((a, n) => a + n.beyond, 0);
    const rows = abuseRows(r, f, reportedMarks());
    const sources = rows.reduce((a, p) => a + p.sources.length, 0);
    controls.appendChild(h("button", { class: "btn small", type: "button", title: "one line per source, as filtered", onclick: () => abuseCsv(rows, r) }, "CSV"));
    if (!r.to) {
      // no node answered: there is no period to speak of
      out.push(...table(`abuse-${scope}-${r.window}`, [], [], { empty: "No report: no node answered." }));
      return out;
    }
    out.push(h("p", { class: "muted abuse-sum" },
      `${num(rows.length)} network${rows.length === 1 ? "" : "s"}, ${num(sources)} source${sources === 1 ? "" : "s"} banned ${utc(r.from)} to ${utc(r.to)}`,
      f.worth && sources < r.sources ? ` (${num(r.sources - sources)} more with fewer log lines or not matching)` : "",
      beyond ? `; ${num(beyond)} less persistent sources left out by the nodes` : ""));
    const mark = (p) => h("button", { class: "btn small", type: "button", onclick: (e) => { e.stopPropagation(); markReported(p, true); } }, "Mark mailed");
    const cols = f.todo ? [
      { label: "Network", sort: (p) => providerName(p).toLowerCase(), cell: (p) => h("span", null, providerName(p), p.asn && p.name ? h("span", { class: "muted" }, ` AS${p.asn}`) : null), csv: (p) => providerName(p) },
      { label: "Sources", cls: "num", sort: (p) => p.sources.length, cell: (p) => num(p.sources.length) },
      { label: "Bans", cls: "num", sort: (p) => p.bans, cell: (p) => num(p.bans) },
      { label: "Send", cell: (p) => [exportButtons(p, r, scope), " ", mark(p)] },
    ] : [
      { label: "Network", sort: (p) => providerName(p).toLowerCase(), cell: (p) => h("span", null, providerName(p), p.asn && p.name ? h("span", { class: "muted" }, ` AS${p.asn}`) : null, " ", reportedChip(p), " ", reoffendedChip(p)), csv: (p) => providerName(p) },
      { label: "Country", sort: (p) => (p.countries[0] || [""])[0], cell: (p) => h("span", { title: p.countries.map((c) => c[1]).join(", ") }, p.countries.map((c) => c[0]).join(" ")) },
      { label: "Sources", cls: "num", sort: (p) => p.sources.length, cell: (p) => num(p.sources.length) },
      { label: "Bans", cls: "num", sort: (p) => p.bans, cell: (p) => num(p.bans) },
      { label: "Log lines", cls: "num", sort: (p) => p.events, cell: (p) => num(p.events) },
      scope === "all" ? { label: "Nodes", cell: (p) => p.nodes.map((n) => [h("span", { class: "chip" }, n), " "]) } : null,
      { label: "Last seen", sort: (p) => p.last, cell: (p) => timeCell(p.last) },
      { label: "Export", cell: (p) => exportButtons(p, r, scope) },
    ].filter(Boolean);
    out.push(...table(`abuse-${scope}-${r.window}`, cols, rows, { key: (p) => p.key, sort: { col: "Bans", asc: false }, detail: (p) => providerDetail(p, r, scope), empty: "Nothing banned in this period matches." }));
    return out;
  }

  function viewAbuse(root) {
    root.append(h("div", { class: "page-head" }, h("h1", null, "Abuse"), h("span", { class: "sub" }, "every node's bans of the period, merged, one entry per network owner: what to send each abuse desk")));
    const body = h("section", { class: "card abuse" });
    root.appendChild(body);
    return { update() { patch(body, abuseReport("all")); } };
  }

  function abuseCard(id) {
    return h("section", { class: "card section abuse" }, h("header", null, h("h2", null, "Abuse report"), h("span", { class: "grow" }),
      h("a", { href: "#/abuse" }, "All nodes merged")), abuseReport(id));
  }

  function clusterCard(c, id) {
    const peers = c.peers || [];
    const heard = Object.entries(c.heard_from || {});
    return card("Cluster", h("span", { class: "muted mono" }, c.key_id ? `key ${c.key_id}${(c.extra_key_ids || []).length ? ` (+${c.extra_key_ids.join(", ")})` : ""}` : ""), h("div", { class: "body" },
      kv([
        ["Node name", c.node_id],
        ["Listens on", c.listen || "nothing (send-only)"],
        ["Facts", `${num(c.facts_known)} held, ${num(c.facts_received)} received, ${num(c.facts_sent)} sent`],
        ["Refused", c.rejected || c.refused_by_limit ? `${num(c.rejected)} messages or facts, ${num(c.refused_by_limit || 0)} beyond peer_accept` : null],
        ["Key installed", c.key_since ? `${when(c.key_since)} (${ago(c.key_since)})` : null],
      ]),
      peers.length ? [h("h3", null, "Peers"), ...table(`peers-${id}`, [
        { label: "Peer", sort: (p) => p.addr, cell: (p) => h("span", { class: "mono" }, p.addr) },
        { label: "State", sort: (p) => (p.failing_since ? 0 : 1), cell: (p) => (p.failing_since ? status("warning", `failing ${ago(p.failing_since)}`) : p.last_ok ? status("good", "delivering") : status("info", "not yet")) },
        { label: "Last delivery", sort: (p) => p.last_ok || 0, cell: (p) => (p.last_ok ? ago(p.last_ok) : "") },
        peers.some((p) => p.last_error) ? { label: "Error", cls: "msg", cell: (p) => p.last_error || "" } : null,
      ], peers)] : null,
      // peers talk every few seconds: a quarter of an hour of silence is late, two hours is lost
      heard.length ? [h("h3", null, "Heard from"), h("div", null, heard.map(([n, t]) => {
        const silent = Date.now() - ms(t);
        const cls = silent > 2 * 3600000 ? "chip lost" : silent > 15 * 60000 ? "chip late" : "chip";
        return h("span", { class: cls, title: `${when(t)}${cls === "chip" ? "" : " · nothing since"}` }, `${n} · ${ago(t)}`);
      }).flatMap((x) => [x, " "]))] : null));
  }

  // kB as people read sizes: 880 MB, 21.4 GB
  function size(kb) {
    if (kb >= 1048576) return `${(kb / 1048576).toFixed(kb >= 10485760 ? 0 : 1)} GB`;
    if (kb >= 1024) return `${Math.round(kb / 1024)} MB`;
    return `${kb} kB`;
  }

  // One line of the disk and memory card: what, how full, how much is left.
  function usageRow(label, total, avail, extra, warnAt, critAt) {
    const used = total > 0 ? Math.max(0, Math.min(100, 100 - (100 * avail) / total)) : 0;
    const cls = used >= critAt ? "fill crit" : used >= warnAt ? "fill warn" : "fill";
    return [
      h("div", { class: "what" }, label),
      h("div", { class: "track", role: "meter", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": String(Math.round(used)), "aria-label": "used" },
        h("div", { class: cls, width: `${used}%` })),
      h("div", { class: "pct" }, `${Math.round(used)}%`),
      h("div", { class: "detail" }, `${size(avail)} free of ${size(total)}${extra || ""}`),
    ];
  }

  function resourcesCard(r) {
    const m = r.memory;
    const rows = (r.disks || []).map((dk) => usageRow(h("span", { class: "mono", title: (dk.paths || []).join(", ") }, dk.mount), dk.size_kb, dk.avail_kb, "", 80, 90));
    if (m) {
      const psi = m.psi_full ? ` · stalled ${m.psi_full.toFixed(1)}% of the time` : "";
      rows.push(usageRow("Memory", m.total_kb, m.avail_kb, psi, 85, 95));
      if (m.swap_total_kb) rows.push(usageRow("Swap", m.swap_total_kb, m.swap_free_kb, "", 50, 80));
    }
    return card("Disk and memory", h("span", { class: "muted" }, r.read ? `read ${ago(r.read)}` : ""), h("div", { class: "body" },
      rows.length ? h("div", { class: "usage" }, rows) : h("div", { class: "muted" }, "Nothing measured."),
      (r.errors || []).map((e) => h("div", { class: "muted" }, e))));
  }

  function patchesCard(p) {
    return card("Updates", h("span", { class: "muted" }, p.read ? `checked ${ago(p.read)}` : ""), h("div", { class: "body" }, kv([
      ["Pending", p.upgradable !== null && p.upgradable !== undefined ? num(p.upgradable) : null],
      ["Security", p.security_count ? h("span", null, status("warning", `${p.security_count} pending`), " ", h("span", { class: "muted" }, (p.security || []).join(", "))) : "none pending"],
      ["Reboot", p.reboot_required ? status("info", `required${(p.reboot_pkgs || []).length ? ` (${p.reboot_pkgs.join(", ")})` : ""}`) : "not required"],
      ["Kernel", p.running_kernel ? (p.newest_kernel && p.newest_kernel !== p.running_kernel ? `${p.running_kernel} running, ${p.newest_kernel} installed` : p.running_kernel) : null],
      ["Using replaced files", (p.stale || []).length ? p.stale.map((x) => `${x.process} (${x.pids})`).join(", ") : null],
    ])));
  }

  function integrityCard(snap) {
    const pairs = [];
    if (snap.cron) pairs.push(["Cron watch", `${num(snap.cron.tasks)} tasks, ${num(snap.cron.scripts)} scripts, scanned ${ago(snap.cron.scanned)}${(snap.cron.errors || []).length ? `; ${snap.cron.errors.join("; ")}` : ""}`]);
    const last = snap.av && snap.av.last;
    if (last) {
      // the first few infected files here, all of them in the tooltip
      const infected = last.infected || [];
      const shown = infected.slice(0, 3).join(", ") + (infected.length > 3 ? ` (+${infected.length - 3} more)` : "");
      pairs.push(["Antivirus", last.infected_count ? h("span", { title: infected.join("\n") }, status("critical", `${last.infected_count} infected: ${shown}`)) : `clean, ${last.scanned_files ? `${num(last.scanned_files)} files, ` : ""}finished ${ago(last.end)}${last.db_outdated ? " (signatures outdated)" : ""}`]);
    }
    if (snap.verify) pairs.push(["Package files", snap.verify.mismatched ? status("high", `${snap.verify.mismatched} differ from their checksums`) : `${num(snap.verify.checked)} match, ${num(snap.verify.suid)} set-uid programs, checked ${ago(snap.verify.last_run)}`]);
    if (snap.procwatch) pairs.push(["Outbound connections", `${num(snap.procwatch.pairs)} program/destination pairs learned, scanned ${ago(snap.procwatch.scanned)}`]);
    return pairs.length ? card("Integrity", null, h("div", { class: "body" }, kv(pairs))) : null;
  }

  function exposureCard(x, id) {
    const ls = x.listeners || [];
    const where = (l) => {
      const k = l.key || {};
      const a = String(k.addr || "");
      return `${a.includes(":") ? `[${a}]` : a}:${k.port}/${k.proto || "tcp"}`;
    };
    const order = { allowed: 0, firewalled: 1, local: 2 };
    return card("Listening services", h("span", { class: "muted" }, `${x.firewall || (x.ufw_active ? "ufw" : "no firewall read")}, scanned ${ago(x.scanned)}`), h("div", { class: "body flush" },
      table(`listeners-${id}`, [
        { label: "Listens on", sort: (l) => where(l), cell: (l) => h("span", { class: "mono" }, where(l)) },
        { label: "Program", sort: (l) => l.process, cell: (l) => l.process },
        { label: "Reachable", sort: (l) => order[l.exposure] ?? 3, cell: (l) => (l.exposure === "allowed" ? `from the internet${l.limited ? " (rate-limited)" : ""}` : l.exposure === "firewalled" ? "firewalled" : "this host only") },
        { label: "Rule", cell: (l) => [l.rule || "", l.honeypot ? " honeypot" : "", l.dynamic ? " port range" : ""].join("") },
      ], ls, { sort: { col: "Reachable", asc: true } }),
      (x.dead_rules || []).length ? h("div", { class: "more" }, `Rules for ports nothing listens on: ${x.dead_rules.join(", ")}`) : null));
  }

  // ------------------------------------------------------------------ session notices, notifications

  // What the admin should know about the session, above every tab: its end coming (it ends
  // `SESSION_MAX_HOURS` after the login, or after `SESSION_IDLE_MINUTES` without a request,
  // which only happens while refreshes are paused or the tab is hidden).
  function notices() {
    if (!shell) return;
    const out = [];
    const ses = state.session && state.session.session;
    if (ses) {
      const now = Date.now();
      const ends = ms(ses.ends);
      if (ends - now < 10 * 60000) {
        out.push(h("div", { class: "notice warn", role: "status" }, status("warning", "Session"),
          `This session ends at ${timeFmt.format(new Date(ends))}, ${Math.round((ses.ends / 1000 - ses.created / 1000) / 3600000)} hours after the login, however busy: log in again then.`,
          h("a", { class: "btn small", href: "#/account" }, "Sessions")));
      }
      const idleLeft = state.lastApi + ses.idle_secs * 1000 - now;
      if (state.paused && idleLeft < 3 * 60000) {
        out.push(h("div", { class: "notice warn", role: "status" }, status("warning", "Session"),
          idleLeft > 0 ? `Refreshes are paused: this session ends in ${duration(idleLeft)} without a request.` : "This session has probably ended (paused too long).",
          h("button", { class: "btn small", type: "button", onclick: async () => { try { state.session = await api("/api/v1/session"); } catch (_) { /* login page */ } header(); } }, "Stay logged in")));
      }
    }
    if (state.keysShown) {
      out.push(h("div", { class: "notice", role: "status" }, status("info", "Keys"),
        h("span", { class: "keys" }, KEYS.map(([k, what]) => h("span", null, h("kbd", null, k), ` ${what}`))),
        h("button", { class: "btn small", type: "button", onclick: () => { state.keysShown = false; notices(); } }, "OK")));
    }
    patch(shell.notice, out);
  }
  setInterval(() => notices(), 20000);

  // After a login: when this admin logged in before, and the failed attempts since (shown on the
  // overview until dismissed).
  function lastLoginNote(body) {
    const prev = state.session && state.session.previous;
    if (!prev || state.loginNoted) return;
    const failed = prev.failed_since || 0;
    const text = prev.at ? `Your last login: ${when(prev.at)} (${ago(prev.at)}) from ${prev.ip}.` : "Your first login since the console started.";
    const since = prev.at ? "since then" : "since the console started";
    body.appendChild(h("div", { class: `notice ${failed ? "warn" : ""}`, role: "status" },
      status(failed ? "warning" : "info", failed ? "Failed logins" : "Last login"),
      text, failed ? ` ${failed} failed attempt${failed === 1 ? "" : "s"} at this account ${since}. If that wasn't you, see Sessions.` : "",
      h("a", { href: "#/account" }, "Sessions"),
      h("button", { class: "btn small", type: "button", onclick: () => { state.loginNoted = true; update(); } }, "OK")));
  }

  // Browser notifications of new critical problems, while a console tab is open (opt-in).
  const notifying = () => pref("lgw-notify", "0") === "1" && typeof Notification !== "undefined" && Notification.permission === "granted";
  let seen = null;

  async function toggleNotify() {
    if (typeof Notification === "undefined") { alert("This browser can't show notifications."); return; }
    if (notifying()) setPref("lgw-notify", "0");
    else {
      const p = Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
      if (p === "granted") setPref("lgw-notify", "1");
      else alert("The browser doesn't allow notifications for this page (its site settings can).");
    }
    header();
  }

  function notify() {
    const att = (state.data && state.data.attention) || [];
    const now = new Set(att.filter((a) => a.level === "critical").map((a) => `${a.node_id}|${a.text}`));
    // what is there at the start isn't news
    if (seen && notifying()) {
      for (const a of att) {
        const k = `${a.node_id}|${a.text}`;
        if (a.level === "critical" && !seen.has(k)) {
          const n = new Notification(`vpsfort: ${a.node || "cluster"}`, { body: a.text, tag: k });
          n.onclick = () => { window.focus(); location.hash = a.node_id ? `#/nodes/${a.node_id}` : "#/overview"; };
        }
      }
    }
    seen = now;
  }

  // ------------------------------------------------------------------ settings across nodes

  const DRIFT = [
    ["vpsfort", "vpsfort"], ["web", "vpsfort-web"], ["mode", "Mode"], ["backend", "Firewall"], ["thresholds", "Thresholds (fast / slow)"],
    ["cluster_key", "Cluster key"], ["geo", "Geo database"], ["feeds", "Feeds"], ["waf", "WAF decisions"], ["geoblock", "Country blocking"],
    ["antivirus", "Antivirus"], ["patches", "Update check"], ["verify", "Package check"], ["procwatch", "Process watch"], ["cron", "Cron watch"], ["sources", "Log sources"],
  ];

  // What each node runs and how, side by side; what differs from most nodes is marked.
  // Two nodes picked in the header: only those, and only the rows that differ between them.
  let compare = [];
  function driftCard(nodes) {
    const picked = compare.filter((id) => nodes.some((n) => n.id === id));
    const rows = nodes.filter((n) => n.settings && (picked.length < 2 || picked.includes(n.id))).map((n) => ({
      id: n.id, name: n.name,
      values: { ...n.settings, web: n.addr === "local" ? (state.session && state.session.version) || "this console" : n.version || null },
    }));
    if (rows.length < 2) return null;
    const keys = DRIFT.map(([k]) => k);
    const d = drift(rows, keys);
    const shown = (k, v) => {
      // a vpsfort that doesn't send its version (a build from before the first release)
      if (k === "vpsfort" && (v === null || v === undefined || v === "")) return h("span", { class: "muted", title: "this vpsfort doesn't say its version" }, "not reported");
      return v === true ? "on" : v === false ? "off" : v === null || v === undefined || v === "" ? "–" : String(v);
    };
    const differing = keys.filter((k) => d[k].differ.size).length;
    const two = picked.length === 2;
    const shownKeys = two ? DRIFT.filter(([k]) => d[k].differ.size) : DRIFT;
    const pickNode = (id) => { compare = compare.includes(id) ? compare.filter((x) => x !== id) : [...compare.slice(-1), id]; update(); };
    return card("Nodes side by side", h("span", { class: "chart-head" },
      h("span", { class: "muted" }, two ? `${shownKeys.length} setting${shownKeys.length === 1 ? "" : "s"} differ between these two` : differing ? `${differing} setting${differing === 1 ? "" : "s"} differ` : "the same everywhere"),
      two ? h("button", { class: "btn small", type: "button", onclick: () => { compare = []; update(); } }, "All nodes") : h("span", { class: "muted small-note" }, "click two nodes to compare them")),
      h("div", { class: "body flush" }, h("div", { class: "table-wrap" }, h("table", { class: "drift" },
        h("thead", null, h("tr", null, h("th", null, ""), rows.map((r) => h("th", { class: compare.includes(r.id) ? "chosen" : null }, h("button", { class: "bare", type: "button", "aria-pressed": String(compare.includes(r.id)), title: compare.includes(r.id) ? "chosen: click to drop it" : "click to compare this node with another (its page: the node's card above)", onclick: () => pickNode(r.id) }, plainChip(r.name, r.id)))))),
        h("tbody", null, shownKeys.map(([k, label]) => h("tr", { class: d[k].differ.size ? "differs" : null },
          h("th", { scope: "row" }, label),
          rows.map((r) => h("td", { class: d[k].differ.has(r.id) ? "odd" : null, "data-label": r.name, title: d[k].differ.has(r.id) ? `most nodes: ${textOf(shown(k, d[k].common))}` : null }, shown(k, r.values[k]))))))),
        two && !shownKeys.length ? h("div", { class: "empty" }, "These two are set up the same.") : null)));
  }

  // ------------------------------------------------------------------ one address

  async function loadAddress(q) {
    if (!q) return;
    try {
      const share = state.shared ? `?share=${encodeURIComponent(state.shared.token)}` : "";
      state.address[q] = { data: await api(`/api/v1/address/${q}${share}`), at: Date.now() };
    } catch (e) {
      if (e instanceof LoginNeeded) throw e;
      state.address[q] = { error: e.message, at: Date.now() };
    }
  }

  // The abuse report's entries for an address: the source itself, the network it is in, or a
  // network's member.
  function abuseFor(q) {
    const r = state.abuse["all:7d"] && state.abuse["all:7d"].data;
    if (!r) return [];
    const ip = q.split("/")[0];
    const out = [];
    for (const p of r.providers || []) {
      for (const x of p.sources) {
        if (x.net === q || x.net.split("/")[0] === ip || (x.members || []).includes(ip) || (x.net.includes("/") && v4Within(ip, x.net))) out.push({ p, x });
      }
    }
    return out;
  }

  function v4Within(ip, net) {
    const [base, bits] = net.split("/");
    const n = (a) => a.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) || !/^\d+\.\d+\.\d+\.\d+$/.test(base)) return false;
    const size = 2 ** (32 - Number(bits));
    return Math.floor(n(ip) / size) === Math.floor(n(base) / size);
  }

  function viewAddress(root, q) {
    root.append(h("div", { class: "page-head" }, h("h1", { class: "addr-title" }, q || "?"), h("span", { class: "sub" }, state.shared ? "what every node of this cluster says about this address now (a read-only share)" : "what every node says about this address now")));
    const body = h("div");
    root.appendChild(body);
    loadAddress(q).then(update, () => {});
    if (!state.shared) loadAbuse("all", "7d", false);
    const look = { busy: false, got: null, error: null };
    // a link to this page that needs no login (signed, at most a week), for the provider
    const share = { busy: false, got: null, error: null, hours: 24 };
    return {
      update() {
        const a = state.address[q];
        const out = [];
        banner({ appendChild: (n) => out.push(n) });
        if (!a) { patch(body, h("div", { class: "empty" }, "Asking the nodes…")); return; }
        if (a.error) { patch(body, h("div", { class: "error-banner" }, status("warning", "Can't ask"), a.error)); return; }
        const d = a.data;
        const place = (d.offenders.find((o) => o.geo) || {}).geo;
        const ip = q.split("/")[0];
        out.push(h("div", { class: "filters" },
          place ? h("span", { class: "chip" }, place) : null,
          state.shared ? null : h("button", {
            class: "btn small", type: "button", disabled: look.busy,
            onclick: async () => {
              look.busy = true; look.error = null; update();
              try { look.got = await lookupRdap(ip); } catch (e) { if (e instanceof LoginNeeded) return; look.error = e.message; }
              look.busy = false; update();
            },
          }, look.busy ? "Asking RDAP…" : "Who runs this network?"),
          look.got ? h("span", null, look.got.network || "?", " · abuse: ", look.got.abuse.length ? look.got.abuse.join(", ") : "no mailbox given", h("span", { class: "muted" }, ` (RDAP, asked by ${look.got.via === "browser" ? "this browser" : "the console"})`)) : null,
          look.error ? h("span", { class: "muted" }, look.error) : null,
          state.shared ? null : h("a", { href: `#/abuse?q=${encodeURIComponent(ip)}&worth=0` }, "Find it on Abuse"),
          state.shared ? null : h("span", { class: "share" },
            select([["24", "24 hours"], ["72", "3 days"], ["168", "a week"]].map(([v, t]) => h("option", { value: v, selected: Number(v) === share.hours }, t)), (v) => { share.hours = Number(v); }, "The share link lasts"),
            h("button", {
              class: "btn small", type: "button", disabled: share.busy, title: "A link to this page that needs no login: this address only, read-only, until it expires",
              onclick: async () => {
                share.busy = true; share.error = null; update();
                try { share.got = await api("/api/v1/share", { method: "POST", body: JSON.stringify({ net: q, hours: share.hours }) }); } catch (e) { if (e instanceof LoginNeeded) return; share.error = e.message; }
                share.busy = false; update();
              },
            }, share.busy ? "Making…" : "Share link"),
            share.got ? [h("input", { type: "text", readonly: true, class: "share-url", value: `${location.origin}${share.got.path}`, onfocus: (e) => e.target.select() }),
              h("button", { class: "btn small", type: "button", onclick: (e) => { navigator.clipboard.writeText(`${location.origin}${share.got.path}`).then(() => { e.target.textContent = "Copied"; }, () => {}); } }, "Copy"),
              h("span", { class: "muted" }, ` until ${when(share.got.expires)}`)] : null,
            share.error ? h("span", { class: "muted" }, share.error) : null)));
        const nothing = !d.bans.length && !d.actions.length && !d.offenders.length && !d.trusted.length && !d.allowed.length;
        if (nothing) out.push(h("div", { class: "card" }, h("div", { class: "empty" }, "No node knows this address now: bans end, and decisions and scores are kept for a while only (the actions log has them all: `vpsfort abuse-report --ip`).")));
        if (d.bans.length) out.push(card("Bans in force", h("span", { class: "muted" }, `${d.bans.length}`), h("div", { class: "body flush" }, table(`addr-bans`, [
          { label: "Address or network", sort: (b) => b.net, cell: (b) => addrLink(b.net) },
          { label: "Node", sort: (b) => b.node, cell: (b) => nodeChip(b.node, b.node_id) },
          { label: "Decided", cls: "nowrap", cell: (b) => (b.origin ? `from ${b.origin}` : "here") },
          { label: "Since", sort: (b) => b.since, cell: (b) => timeCell(b.since) },
          { label: "Left", cls: "num", sort: (b) => b.until, cell: (b) => h("span", { class: ended(b) ? "muted" : null }, left(b.until)) },
          { label: "Reason", cls: "msg", cell: (b) => b.reason },
        ], d.bans))));
        if (d.offenders.length) out.push(card("Scores", null, h("div", { class: "body flush" }, table("addr-scores", [
          { label: "Node", cell: (o) => nodeChip(o.node, o.node_id) },
          { label: "Danger", sort: (o) => o.danger, cell: (o) => meter(o.danger, 60, 100) },
          { label: "Signals", cell: (o) => Object.entries(o.counts || {}).map(([k, v]) => `${v}× ${k}`).join(", ") },
          { label: "First seen", cell: (o) => timeCell(o.first_seen) },
          { label: "Last seen", cell: (o) => timeCell(o.last_seen) },
        ], d.offenders, { key: (o) => `${o.node_id}:${o.ip}`, detail: (o) => evidence(o.evidence) }))));
        if (d.actions.length) out.push(card("Decisions and alerts", h("span", { class: "muted" }, "the nodes' latest, naming it"), h("div", { class: "body flush" }, table("addr-actions", [
          { label: "Time", sort: (x) => x.ts, cell: (x) => timeCell(x.ts) },
          { label: "Node", cell: (x) => nodeChip(x.node, x.node_id) },
          { label: "Decision", cell: (x) => x.kind },
          { label: "Severity", sort: (x) => SEV[x.severity] || 0, cell: (x) => status(x.severity) },
          { label: "Message", cls: "msg", cell: (x) => linked(x.message) },
        ], d.actions, { key: (x) => `${x.node_id}:${x.ts}:${x.message}`, detail: actionDetail }))));
        const abuse = abuseFor(q);
        const ab = state.abuse["all:7d"];
        if (!state.shared) out.push(card("Abuse report, last 7 days", h("a", { href: `#/abuse?q=${encodeURIComponent(ip)}&window=7d&worth=0` }, "On Abuse"),
          abuse.length ? h("div", { class: "body" }, abuse.map(({ p, x }) => h("div", { class: "abuse-source" },
            h("div", { class: "head" }, addrLink(x.net), h("span", null, providerName(p), p.asn && p.name ? h("span", { class: "muted" }, ` AS${p.asn}`) : null),
              (x.nodes || []).map((n) => h("span", { class: "chip" }, n)),
              h("span", null, `${num(x.bans)} ban${x.bans === 1 ? "" : "s"}, ${num(x.events)} log lines`), exportButtons(p, ab.data, "all")),
            h("div", { class: "activity" }, x.activity))))
            : h("div", { class: "empty" }, ab && ab.data ? "Not in the report of the last 7 days." : ab && ab.error ? ab.error : "Asking the nodes for their reports…")));
        if (d.trusted.length || d.allowed.length) out.push(card("Trusted and allowed", null, h("div", { class: "body" }, kv([
          ["Trusted (logged in lately)", d.trusted.length ? d.trusted.map((t) => `${t.node} (${ago(t.since)})`).join(", ") : null],
          ["Operator allowlist", d.allowed.length ? d.allowed.map((x) => `${x.node}: ${x.net}${x.note ? ` (${x.note})` : ""}`).join("; ") : null],
        ]))));
        patch(body, out);
      },
    };
  }

  // ------------------------------------------------------------------ your account

  async function loadSessions() {
    try {
      state.sessions = (await api("/api/v1/sessions")).sessions;
      state.session = await api("/api/v1/session");
    } catch (e) {
      if (e instanceof LoginNeeded) throw e;
      state.sessions = { error: e.message };
    }
  }

  async function loadCheck() {
    try { state.check = await api("/api/v1/check"); } catch (e) { if (e instanceof LoginNeeded) throw e; state.check = { error: e.message }; }
  }

  // What `vpsfort-web check` prints, for the page: the certificate, the key, the admins, the nodes.
  function checkCard() {
    const c = state.check;
    if (!c) return card("Console health", null, h("div", { class: "empty" }, "Asking…"));
    if (c.error) return card("Console health", null, h("div", { class: "empty" }, c.error));
    const cert = c.certificate || {};
    const days = cert.days_left;
    const certText = cert.not_after ? h("span", null, days < 14 ? status(days < 3 ? "critical" : "warning", `expires in ${days} day${days === 1 ? "" : "s"}`) : `expires ${when(cert.not_after)} (in ${days} days)`, cert.fingerprint ? h("span", { class: "muted" }, ` · ${cert.fingerprint.slice(0, 23)}…`) : null) : h("span", null, status("warning", "can't read its dates"), ` ${cert.file}`);
    const up = c.nodes.filter((n) => n.state === "ok").length;
    return card("Console health", h("button", { class: "btn small", type: "button", onclick: async () => { state.check = null; update(); await loadCheck(); update(); } }, "Again"), h("div", { class: "body" }, kv([
      ["vpsfort-web", `${c.version} on ${c.node}${c.expected_version ? ` (expected everywhere: ${c.expected_version})` : ""}`],
      ["Certificate", certText],
      ["Web key", c.web_key ? h("span", { class: "mono" }, c.web_key) : h("span", { class: "muted" }, "none (no agents)")],
      ["Admins", `${c.admins}, ${c.totp ? "password and one-time code" : "password only (TOTP=off)"}`],
      ["Login", `${c.login_work ? `proof of work ${c.login_work} bits` : "no proof of work"} · ${c.sessions} session${c.sessions === 1 ? "" : "s"} open`],
      ["Nodes", h("span", null, status(up === c.nodes.length ? "good" : up ? "warning" : "critical", `${up}/${c.nodes.length} answering`), " ",
        c.nodes.map((n) => h("span", { class: `chip${n.state === "ok" ? "" : " warn"}`, title: n.error || n.addr }, `${n.name}${n.version ? ` ${n.version}` : ""}`)))],
      ["Lookups", `RDAP by ${c.rdap ? "the console" : "the browser"} · nodes asked every ${c.refresh_secs}s while a page is open`],
    ])));
  }

  // The admin's passkeys: registered here (navigator.credentials.create), checked at the login.
  async function loadPasskeys() {
    try { state.passkeys = await api("/api/v1/passkeys"); } catch (e) { state.passkeys = { error: e.message }; }
  }
  async function addPasskey() {
    const name = window.prompt("A name for this passkey (the key or the phone it lives on):", "");
    if (name === null) return;
    const opts = await api("/api/v1/passkeys/begin", { method: "POST", body: "{}" });
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: b64ToBuf(opts.challenge), rp: opts.rp, user: { id: b64ToBuf(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
      pubKeyCredParams: opts.pubKeyCredParams, excludeCredentials: (opts.excludeCredentials || []).map((c) => ({ type: "public-key", id: b64ToBuf(c.id) })),
      authenticatorSelection: opts.authenticatorSelection, attestation: opts.attestation, timeout: opts.timeout,
    } });
    try {
      await api("/api/v1/passkeys/finish", { method: "POST", body: JSON.stringify({
        name, challenge: opts.challenge, id: cred.id, clientDataJSON: bufToB64(cred.response.clientDataJSON), attestationObject: bufToB64(cred.response.attestationObject),
      }) });
    } catch (e) {
      if (e instanceof LoginNeeded) throw e;
      // the browser has made and kept its half already
      throw new Error(`The console didn't keep the passkey: ${e.message}. Your browser or password manager saved one for ${opts.rp.id} that the console doesn't know: delete it there, then add it again.`);
    }
  }
  async function loadShares() {
    try { state.shares = await api("/api/v1/share"); } catch (e) { state.shares = { error: e.message }; }
  }
  function sharesCard(update) {
    const s = state.shares || {};
    const list = Array.isArray(s.links) ? s.links : [];
    let note = s.kept ? "Kept across restarts (STATE_DIR). An ended link is refused from then on." : "The console has no STATE_DIR: these live in memory, and a restart forgets which were made.";
    // what went wrong stays on the card until the next try (the card is drawn again at once)
    const failed = state.cardNote.shares;
    const act = async (fn) => { state.cardNote.shares = null; try { await fn(); } catch (e) { if (e instanceof LoginNeeded) return; state.cardNote.shares = e.message; } await loadShares(); update(); };
    return card("Share links", h("span", { class: "muted" }, `${list.filter((x) => !x.ended).length} open`),
      h("div", { class: "body flush" },
        s.error ? h("div", { class: "empty" }, s.error) : table("shares", [
          { label: "Address", cell: (x) => addrLink(x.net) },
          { label: "Made by", cell: (x) => x.by },
          { label: "Made", sort: (x) => x.made, cell: (x) => timeCell(x.made) },
          { label: "Expires", sort: (x) => x.expires, cell: (x) => timeCell(x.expires) },
          { label: "", cls: "act", cell: (x) => (x.ended ? h("span", { class: "chip" }, "ended") : h("button", { class: "btn small", type: "button", onclick: () => { if (window.confirm(`End the share link for ${x.net} now?`)) act(() => api("/api/v1/share/end", { method: "POST", body: JSON.stringify({ id: x.id }) })); } }, "End")) },
        ], list, { key: (x) => x.id, empty: "No share links made (an address's page makes one)." }),
        failed ? h("div", { class: "error-banner card-error", role: "alert" }, status("warning", "Not done"), failed) : null,
        h("p", { class: "muted small-note" }, note)));
  }

  function passkeysCard(update) {
    const p = state.passkeys || {};
    const list = Array.isArray(p.passkeys) ? p.passkeys : [];
    let note = "";
    if (!passkeysPossible()) note = "Passkeys need the console reached by a host name (or localhost through an SSH tunnel), in a browser that supports them.";
    else if (p.rp_id) note = `Registered for ${p.rp_id}. A passkey that checks your fingerprint, face or PIN logs you in on its own; a security key without a PIN stands in for the one-time code beside the password. The password with the code keeps working.`;
    const failed = state.cardNote.passkeys;
    const act = async (fn) => {
      state.cardNote.passkeys = null;
      try { await fn(); } catch (e) {
        if (e instanceof LoginNeeded) return;
        // the browser's own refusals (cancelled, timed out) by their names
        state.cardNote.passkeys = e.name === "NotAllowedError" ? "The browser didn't make a passkey (cancelled, or it timed out)." : e.name === "InvalidStateError" ? "This authenticator already holds a passkey for this account." : e.message;
      }
      await loadPasskeys(); update();
    };
    return card("Passkeys", h("button", { class: "btn small", type: "button", disabled: !passkeysPossible() || list.length >= (p.max || 10), onclick: () => act(addPasskey) }, "Add a passkey"),
      h("div", { class: "body flush" },
        p.error ? h("div", { class: "empty" }, p.error) : table("passkeys", [
          { label: "Name", cell: (x) => x.name },
          { label: "Kind", cell: (x) => x.alg },
          { label: "Added", sort: (x) => x.added, cell: (x) => timeCell(x.added) },
          { label: "Logins", cls: "num", sort: (x) => x.logins || 0, cell: (x) => num(x.logins || 0) },
          { label: "Last used", sort: (x) => x.last_used || 0, cell: (x) => (x.last_used ? timeCell(x.last_used) : h("span", { class: "muted" }, "not yet")) },
          { label: "", cls: "act", cell: (x) => h("button", { class: "btn small", type: "button", onclick: () => { if (window.confirm(`Remove the passkey "${x.name}"?`)) act(() => api("/api/v1/passkeys/remove", { method: "POST", body: JSON.stringify({ id: x.id }) })); } }, "Remove") },
        ], list, { key: (x) => x.id, empty: "No passkeys yet: the one-time code is the second factor." }),
        failed ? h("div", { class: "error-banner card-error", role: "alert" }, status("warning", "Not done"), failed) : null,
        h("p", { class: "muted small-note" }, note)));
  }

  function viewAccount(root) {
    root.append(h("div", { class: "page-head" }, h("h1", null, (state.session && state.session.user) || "You"), h("span", { class: "sub" }, "your sessions, passkeys, the console's health and this browser's settings")));
    const body = h("div");
    root.appendChild(body);
    let ended = null;
    loadSessions().then(update, () => {});
    loadCheck().then(update, () => {});
    loadPasskeys().then(update, () => {});
    loadShares().then(update, () => {});
    return {
      update() {
        const ses = state.session && state.session.session;
        const prev = state.session && state.session.previous;
        const list = Array.isArray(state.sessions) ? state.sessions : [];
        const others = list.filter((x) => !x.current).length;
        patch(body, [
          h("div", { class: "grid cols-2" },
            card("This session", null, h("div", { class: "body" }, ses ? kv([
              ["Account", ses.user], ["From", ses.ip], ["Browser", ses.agent ? h("span", { title: ses.agent }, browserName(ses.agent)) : "–"],
              ["Logged in", `${when(ses.created)} (${ago(ses.created)})`],
              ["Ends", `${when(ses.ends)} at the latest, or after ${Math.round(ses.idle_secs / 60)} minutes without a request`],
            ]) : "–")),
            card("Before this login", null, h("div", { class: "body" }, prev ? kv([
              ["Last login", prev.at ? `${when(prev.at)} (${ago(prev.at)}) from ${prev.ip}` : "none since the console started"],
              ["Failed logins at this account since", String(prev.failed_since || 0)],
            ]) : "–", h("p", { class: "muted small-note" }, state.session && state.session.kept ? "Kept across restarts (STATE_DIR); the journal has every login." : "The console keeps these in memory: a restart forgets them (the journal has every login).")))),
          card("Your sessions", h("span", null,
            ended !== null ? h("span", { class: "muted" }, `${ended} ended `) : null,
            h("button", {
              class: "btn small", type: "button", disabled: !others,
              onclick: async () => {
                try { ended = (await api("/api/v1/sessions/end-others", { method: "POST", body: "{}" })).ended; } catch (e) { if (e instanceof LoginNeeded) return; ended = e.message; }
                await loadSessions();
                update();
              },
            }, "Log out the others")),
            h("div", { class: "body flush" }, state.sessions && state.sessions.error ? h("div", { class: "empty" }, state.sessions.error) : table("sessions", [
              { label: "", cell: (x) => (x.current ? h("span", { class: "chip" }, "this one") : "") },
              { label: "From", cell: (x) => x.ip },
              { label: "Browser", cls: "msg", cell: (x) => (x.agent ? h("span", { title: x.agent }, browserName(x.agent)) : "–") },
              { label: "Logged in", sort: (x) => x.created, cell: (x) => timeCell(x.created) },
              { label: "Last request", sort: (x) => x.last, cell: (x) => timeCell(x.last) },
              { label: "Ends", sort: (x) => x.ends, cell: (x) => timeCell(x.ends) },
            ], list, { key: (x) => x.id, empty: "Asking…" }))),
          passkeysCard(update),
          sharesCard(update),
          card("This browser", null, h("div", { class: "body" }, kv([
            ["Colours", h("span", { class: "segmented", role: "group" }, THEMES.map((t) => h("button", { type: "button", "aria-pressed": String(pref("lgw-theme", "auto") === t), onclick: () => { setPref("lgw-theme", t); applyTheme(); header(); update(); } }, t === "auto" ? "As the system" : t[0].toUpperCase() + t.slice(1))))],
            ["Notifications", h("span", null, notifying() ? "on: new critical problems, while a console tab is open " : "off ", h("button", { class: "btn small", type: "button", onclick: async () => { await toggleNotify(); update(); } }, notifying() ? "Turn off" : "Turn on"))],
            ["Abuse reports marked mailed", `${Object.keys(reportedMarks()).length} networks (${state.marksKept ? "kept by the console, for every admin and browser" : "kept in this browser; the console has no STATE_DIR"})`],
            ["Node legend", h("span", null, pref("lgw-legend", "1") === "1" ? "shown under the header on the tabs with node chips " : "hidden ", h("button", { class: "btn small", type: "button", onclick: () => { setPref("lgw-legend", pref("lgw-legend", "1") === "1" ? "0" : "1"); header(); update(); } }, pref("lgw-legend", "1") === "1" ? "Hide" : "Show"))],
            ["Saved views", savedViews().length ? h("span", { class: "saved-views" }, savedViews().map((v) => h("span", { class: "chip" }, h("a", { href: v.hash }, v.title), " ", h("button", { class: "linklike", type: "button", title: "Forget", onclick: () => { forgetView(v.hash); header(); update(); } }, "×")))) : h("span", { class: "muted" }, "none: the star in the header saves the tab you are on with its filters")],
            ["Keys", h("span", { class: "keys" }, KEYS.map(([k, what]) => h("span", { class: "key-item" }, h("kbd", null, k), ` ${what}`)))],
          ]))),
          checkCard(),
        ]);
      },
    };
  }

  // ------------------------------------------------------------------ start

  // A share link (#/share/<address>?t=<token>): that address's page, nothing else, no login.
  function sharedStart(net, token) {
    state.shared = { net, token };
    const main = h("main", { id: "main" });
    app.replaceChildren(h("header", { class: "top" }, h("span", { class: "brand" }, h("img", { src: "/icon.svg", alt: "" }), "vpsfort"),
      h("span", { class: "muted" }, "a shared, read-only view")), main);
    state.view = viewAddress(main, net);
    const again = async () => { await loadAddress(net).catch(() => {}); state.view.update(); };
    setInterval(again, 60000);
  }

  (async () => {
    const shared = /^#\/share\/([^?]+)\?t=([^&]+)$/.exec(location.hash);
    if (shared) { sharedStart(decodeURIComponent(shared[1]), shared[2]); return; }
    try {
      state.session = await (await fetch("/api/v1/session", { credentials: "same-origin", cache: "no-store" })).json();
    } catch (e) {
      app.replaceChildren(h("div", { class: "login-wrap" }, h("div", { class: "card login" }, h("div", { class: "brand" }, "vpsfort console"), h("p", null, `The console doesn't answer: ${e.message}`))));
      return;
    }
    if (state.session.logged_in) start();
    else login();
  })();
})();
