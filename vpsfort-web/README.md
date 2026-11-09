# vpsfort-web

A read-only web console for a vpsfort cluster: every node's bans, alerts, decisions,
offenders, countries and networks, cluster peers, certificates, disks, updates and integrity
checks on one HTTPS page, with what needs attention first, and every node's abuse report of the
last day or week, split per network owner and ready to mail. For one admin or a few, all equal.
`/metrics` gives the same in Prometheus' format for Grafana.

It **only reads**. Nothing in it can ban, unban, allow or change a setting: those stay on the
servers, over SSH, as `vpsfort unban …` and the TUI.

```
 every node                                              the console's node
 ┌────────────────────────────────────┐                  ┌──────────────────────────────────────────┐
 │ vpsfort ── console socket ──► agent│ ◄── TCP 7949 ───│ console ── HTTPS 7948 (TLS 1.3) ──► browser│
 │ (root)      read-only, 0660   vpsfort-web             vpsfort-web       password + one-time code │
 └────────────────────────────────────┘   request sealed │ + its own node's vpsfort (socket)        │
                                          with the web    └──────────────────────────────────────────┘
                                          key; reply under
                                          a fresh X25519 key
```

One binary, two roles, each switched on by a setting: the **agent** (`AGENT_LISTEN`, on every
node) hands its node's vpsfort data to the consoles; the **console** (`CONSOLE_LISTEN`, on the
node or nodes you choose) asks the agents in `NODES` and its own vpsfort, and serves the page.

## Contents

1. [Security design](#security-design)
2. [Setup](#setup)
3. [Settings (`/opt/vpsfort-web/config.env`)](#settings-optvpsfort-webconfigenv)
4. [Commands](#commands)
5. [The page](#the-page)
6. [API](#api)
   - [Prometheus and Grafana](#prometheus-and-grafana)
7. [Files](#files)
8. [Install from a release bundle](#install-from-a-release-bundle)
9. [Install from a package](#install-from-a-package)
10. [Development](#development)
11. [Verified](#verified)
12. [Not yet verified](#not-yet-verified)

## Security design

**Its own key, never the cluster key.** vpsfort's cluster key lets its holder ban, unban,
allowlist and trust addresses on every node. A web console is the part of a system most exposed
to the network, so it must not hold that key: the agents and the console share a separate
**web key** (32 random bytes, `vpsfort-web keygen`), and a stolen web key reads status data,
nothing more. It cannot forge cluster facts, and the console can't ask an agent for anything but
reading (`snapshot`, `digest`, `abuse_24h`, `abuse_7d`). An agent says what it answers; the console
asks older agents for snapshots and digests only (an agent refuses a request it can't read, and
vpsfort bans an address that sends many of those).

**The agent protocol** (`src/wire.rs`), one request and one reply per TCP connection:

- The request is sealed with XChaCha20-Poly1305 under the web key (as the cluster's messages
  are), with its time (refused beyond 5 minutes of clock difference), a random id (refused if
  seen again) and a fresh X25519 public key.
- The reply is sealed under a key derived (HKDF-SHA-256) from a second fresh X25519 key and the
  console's, with the web key as salt and the request id and both public keys bound in. Only a
  holder of the web key can make or read it, it answers that one request only, and **once both
  fresh keys are gone nobody can read a recorded reply, even with the web key** (forward
  secrecy). The cluster's own link does the same since its key exchange (vpsfort's README,
  "Cluster"); snapshots name accounts and addresses.
- Frames are bounded (4 KB requests, 16 MB compressed replies, 64 MB uncompressed); an agent
  takes 8 connections at once, 2 per address, 10 seconds for a whole request, and only from
  `AGENT_ALLOW`. Memory follows what is kept: long lists (every active ban of a flood) are cut
  to their newest few thousand while parsing, their full lengths kept.

**The console:**

- **HTTPS, TLS 1.3 only** (rustls with ring), with a self-signed certificate made at install
  (compare its fingerprint with the browser's once) or a Let's Encrypt one (read again when it
  changes). Older clients (TLS 1.2 only) are refused.
- **Admins, two factors each:** `admin` and any others you add, all equal (no roles). Each has a
  password (Argon2id, `passwd [--user NAME]`) and a one-time code from an authenticator app (TOTP,
  RFC 6238, `totp-setup [--user NAME]` shows a QR code); each code works once, and only for its
  admin. `TOTP=off` leaves the passwords alone. **Or a passkey** (WebAuthn: a security key, the
  phone's, the browser's keychain), registered on the "Your account" page (up to 10 per admin,
  kept in `STATE_DIR/passkeys/<admin>.passkeys`, `vpsfort-web passkeys` and `remove-passkey` on the
  server): the login page offers "Log in with a passkey" for an account that has one. A passkey that
  checked its holder (a fingerprint, a face, the key's PIN: the user-verification flag) is the login
  on its own, without the password or the code; one that was only touched (a security key without a
  PIN) stands in for the code beside the password, and the page says so. A password that is given
  must still be right. The console checks the answer itself (`src/webauthn.rs`): the challenge it issued
  for that account, the origin, the site's hash and the user-presence flag in the authenticator
  data, the signature (ECDSA P-256 or Ed25519, with ring) and a signature counter that must grow
  (a cloned key is refused). Attestation is not checked (the key is the admin's own). Passkeys need
  the console reached by a host name, not an address: `localhost` through an SSH tunnel works. Every attempt costs the same Argon2 check (one at a
  time), whichever factor is wrong and also for an account that doesn't exist, and the answer
  doesn't say which. Five failures from an address within 15 minutes lock it out for 15 minutes,
  and vpsfort bans it (below); ten failures at one account from anywhere lock the account for 15
  minutes, except for addresses it was logged in to from (the admin's own) and for a login with
  the account's current one-time code (a guesser can't produce one), so a guesser spread over many
  addresses is stopped without locking the admin out, even from a new address. With `TOTP=off`
  the lock holds for every unknown address.
- **Proof of work before each login** (`LOGIN_WORK`, default 20 bits; `0` off): the page's
  JavaScript (`web/work.js`, in a Web Worker, plain SHA-256) must find a nonce such that
  `SHA-256(challenge ‖ nonce)` starts with that many zero bits, about 2^20 hashes, and the console
  checks it with one hash before any Argon2 runs. That's under a second on a laptop and a few on a
  phone, solved while you type; a guesser pays it for every guess. The difficulty ramps with
  failures lately (15 minutes): each failure from the address adds a bit (up to 6: 64× the work),
  every 3 failures at the account from anywhere adds one (up to 4), every 50 failures from everyone
  adds one (up to 3), capped at 28 bits. A challenge is signed by the console (a key made at start),
  good for 5 minutes, works once, and one solved before the difficulty rose is refused (428 with a
  fresh challenge: the page solves it and tries once more). A challenge is for the address and
  account it was issued to (both in its signature), so one solved cheaply for an account with no
  failures can't be spent on the one under attack; nothing is kept for challenges handed out and
  not used, so asking for them costs the console nothing. `vpsfort-web check` times a solve.
  Nothing fingerprints the browser and no cookie is set for it: Mullvad or Tor are treated like
  anyone else; a browser without JavaScript or Web Workers can't log in, which was true already.
- **Sessions** are named by a random 256-bit cookie
  `__Host-lgw` (Secure, HttpOnly, SameSite=Strict); 30 idle minutes or 12 hours end one, and so
  does removing its admin (`remove-admin`), at its next request. 8 per admin, 64 in all. An admin
  sees their own sessions (address, browser, times) and can end the others; after a login the page
  says when that admin last logged in, from where, and how many failed attempts at the account came
  since. The sessions (as the cookies' digests), these records, the lockouts and the failure
  counters are written to `STATE_DIR` and read back at start, so a restart (an upgrade, or a crash
  an attacker provokes) neither resets a lockout nor logs every admin out; without a `STATE_DIR`
  they live in memory.
- **Read only**, and only for this site's pages: the API answers GET; login and logout take
  JSON (a form from another site can't send it) and check `Origin`; requests another site's page
  makes (`Origin`, `Sec-Fetch-Site`) are refused.
- **The page** is a few files compiled into the binary (`web/`: `app.js` the views, `dom.js`
  building and patching the page, `core.js` what it works out), no libraries, nothing from other
  hosts. `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; ...`,
  no inline script, no framing, `no-store`; `connect-src` adds RDAP's servers (rdap.org and the
  five registries) for the abuse-mailbox lookup below. Everything a node sends (log lines, account names, a
  peer's notices) goes into the page as text (`textContent`), never as HTML.
- **A small HTTP parser** of its own (`src/http.rs`): no chunked bodies, no proxy requests, no
  folded headers, one Host and one Content-Length, 16 KB of headers, 8 KB bodies; anything else is
  refused and the connection closed. 64 connections at once, 12 per address, 30 seconds per request
  and 10 minutes per connection however busy (a few addresses can't hold every slot by sending a
  byte every 29 seconds). `CONSOLE_ALLOW` drops other addresses before TLS.

**Privilege separation.** vpsfort runs as root; vpsfort-web as its own system user, under a
sandboxed unit (`ProtectSystem=strict`, no capabilities, `MemoryDenyWriteExecute`, 128 MB at
most), writing only its own state (`STATE_DIR`, the admins' passkeys among it). It reaches vpsfort only through vpsfort's **console socket**
(`[console]` in vpsfort.toml): root's directory, mode 0750, group `vpsfort-web`, which answers
`snapshot`, `digest` and `abuse 24h` / `abuse 7d` and refuses every other command before the daemon
sees it. The control socket, the cluster key and vpsfort's state stay root's.

**What a break-in would give.** The console broken into: everything the page shows, read only;
the web key. An agent's node broken into: the web key, and with it the power to show the console
false data (what a node reports is displayed, never acted on: the console has nothing to act
with). Neither gives a ban, an unban or the cluster key.

**vpsfort watches it.** vpsfort-web writes to the journal: `login failed from <address>: …`
(with the account tried, if it can be one: nothing else a stranger types reaches the log),
`console: unknown path from <address>: GET /.env`, refused connections, agent requests without the
web key. With `[sources] apps = ["vpsfort-web"]` vpsfort scores them (25 points a failed login,
40 a probe for secrets, 20 a refused connection) and bans the address like any other attacker,
on every node through the cluster.

## Setup

On every node of the cluster (the console's too):

1. Install it (from a release bundle, below, or `./deploy/deploy.sh <host>` from a checkout). The
   first run puts `/opt/vpsfort-web/config.env` in place and creates the user `vpsfort-web`.
2. The **web key**, once, on one node, then the same file to every other node's
   `/opt/vpsfort-web/web.key`:
   ```bash
   /opt/vpsfort-web/vpsfort-web keygen --out /opt/vpsfort-web/web.key
   /opt/vpsfort-web/vpsfort-web key-id     # the same fingerprint on every node
   ```
3. vpsfort's console socket, in `/etc/vpsfort/vpsfort.toml`, then `systemctl restart vpsfort`:
   ```toml
   [console]
   socket = "/run/vpsfort-console/console.sock"
   group = "vpsfort-web"
   ```
   And in `[sources]`, `apps = ["vpsfort-web"]` (with your other apps) to ban password guessers.
4. In `config.env`: `AGENT_LISTEN=0.0.0.0:7949`, and `AGENT_ALLOW` the console node's address.
   Open the port to that address only:
   `ufw allow from 203.0.113.10 to any port 7949 proto tcp` (firewalld:
   `firewall-cmd --permanent --zone=public --add-rich-rule='rule family=ipv4 source address=203.0.113.10 port port=7949 protocol=tcp accept'`).
   The console's own node needs no agent: the console reads that node's vpsfort through
   `VPSFORT_SOCKET`, so `AGENT_LISTEN` stays empty there and 7949 needs no rule.

On the console's node, also:

5. In `config.env`: `CONSOLE_LISTEN`, and `NODES` the other nodes' agents
   (`vpn.example.org:7949, 198.51.100.20:7949`). Either:
   - `CONSOLE_LISTEN=127.0.0.1:7948`, reached through SSH:
     `ssh -L 7948:127.0.0.1:7948 <host>`, then `https://127.0.0.1:7948` (a hardened SSH gateway
     needs `PermitOpen 127.0.0.1:7948` for its user); or
   - `CONSOLE_LISTEN=0.0.0.0:7948` with `CONSOLE_ALLOW` the networks you work from, and the port
     opened to them in the firewall. vpsfort's exposure watch reports the new listener once.
6. The admin's login:
   ```bash
   /opt/vpsfort-web/vpsfort-web passwd        # asked twice, not shown; 12 characters at least
   /opt/vpsfort-web/vpsfort-web totp-setup    # scan the QR code, or add the otpauth:// link
   ```
   It then asks for the code the app shows and writes the secret only when it matches: if the
   scan didn't take, nothing is written and you run it again.
   More admins, the same way, each with their own password and codes (they log in with their name
   in "Account"; `admin` is the default):
   ```bash
   /opt/vpsfort-web/vpsfort-web passwd --user alice
   /opt/vpsfort-web/vpsfort-web totp-setup --user alice   # alice scans it with her own app
   /opt/vpsfort-web/vpsfort-web admins                    # who can log in
   /opt/vpsfort-web/vpsfort-web remove-admin alice        # her sessions end at once
   ```
   No restart needed: the console reads the files at each login.
7. `bash /opt/vpsfort-web/install.sh` again (a package install: `dpkg-reconfigure vpsfort-web`, or
   `dnf reinstall` the rpm; it starts nothing, so finish with `systemctl enable --now vpsfort-web`): it sets the files' owners and modes, makes the
   self-signed certificate if there is none, and starts the service once nothing is missing
   (until then it lists what is). Check it:
   ```bash
   /opt/vpsfort-web/vpsfort-web check     # reads config.env itself, as the unit does
   ```
   `check` reads every file and asks this node's vpsfort and every agent in `NODES` once.
8. Open the console. The browser warns about the self-signed certificate once: compare the
   SHA-256 fingerprint it shows with `vpsfort-web fingerprint` (install.sh prints it too) before
   you accept it.

**A console without vpsfort** (a host that only aggregates the nodes and serves the page):
`VPSFORT_SOCKET=`, `CONSOLE_LISTEN` and `NODES`, no agent, and skip step 3. Every node shown is
then an agent's. One thing is missing there: with no vpsfort on that host, nothing bans password
guessers at its console from the journal; the lockout above still applies, so keep `CONSOLE_ALLOW`
narrow (or the console on 127.0.0.1 behind SSH). Two consoles: both in each agent's
`AGENT_ALLOW`. A node without the console: `CONSOLE_LISTEN=` (the default).

## Settings (`/opt/vpsfort-web/config.env`)

| variable | default | meaning |
|---|---|---|
| `NODE_NAME` | vpsfort's `[cluster] node_id`, else the host name | this node's name in the console |
| `VPSFORT_SOCKET` | `/run/vpsfort-console/console.sock` | vpsfort's `[console] socket`; empty without vpsfort |
| `WEB_KEY_FILE` | `/opt/vpsfort-web/web.key` | the web key, the same on every node |
| `AGENT_LISTEN` | empty (no agent) | where the consoles ask for this node's data, e.g. `0.0.0.0:7949` |
| `AGENT_ALLOW` | required with an agent | the consoles' addresses or networks; `any`: the web key alone decides |
| `CONSOLE_LISTEN` | empty (no console) | where the console serves HTTPS, e.g. `127.0.0.1:7948` |
| `CONSOLE_ALLOW` | empty: every address | addresses or networks that may reach the login page |
| `NODES` | empty | the other nodes' agents, `host:port`, separated by commas or blanks |
| `TLS_CERT`, `TLS_KEY` | `/opt/vpsfort-web/tls.crt`, `tls.key` | PEM certificate chain and key; read again when they change |
| `LOGIN_WORK` | `20` | bits of proof of work before a login (ramps with failures; `0`: off) |
| `RDAP_LOOKUPS` | `on` | the console looks up abuse mailboxes (rdap.org, HTTPS with the system's CA bundle) when an admin asks; `off`, or when it can't get out, the admin's browser asks rdap.org itself |
| `PASSWORD_FILE` | `/opt/vpsfort-web/admin.password` | `admin`'s Argon2id hash (`passwd`) |
| `TOTP`, `TOTP_FILE` | `on`, `/opt/vpsfort-web/admin.totp` | one-time codes for every admin (`off`: passwords only); `admin`'s secret (`totp-setup`) |
| `ADMINS_DIR` | `/opt/vpsfort-web/admins` | the other admins: `<name>.password`, `<name>.totp` (`passwd --user`, `totp-setup --user`) |
| `METRICS_TOKEN_FILE` | unset | a token that reads `/metrics` without a login (Prometheus) |
| `REFRESH_SECS` | 10 | how old the nodes' data may get while a page is open |
| `SESSION_IDLE_MINUTES`, `SESSION_MAX_HOURS` | 30, 12 | when a session ends |
| `EXPECTED_VERSION` | unset | the vpsfort-web release every node should run (`0.5.0`): a node on another gets a row on the Overview. Nothing is downloaded or checked online |
| `STATE_DIR` | `/var/lib/vpsfort-web` | where the attention history, the nodes' digests, the admins' marks, the share links, the lockouts and failure counters, and the sessions are kept across restarts (the unit's `StateDirectory`); empty: in memory only (a restart then forgets the lockouts and logs every admin out) |
| `HISTORY_DAYS`, `DIGEST_DAYS` | 7, 14 | how long the attention history keeps a problem that went, and how many days of each node's digests are kept |

The console asks the nodes only while someone looks (a page open, a Prometheus scrape): an
idle console sends nothing. A slow node's answer shows with the next refresh; one that doesn't
answer shows as down, with the reason and its last data, and is asked less and less often (twice
the wait after each failure, up to a minute) until it answers again. The page asks for what its
tab shows (`/api/v1/cluster?only=...`), not the whole cluster document every time.

## Commands

```
vpsfort-web                  run (the unit does)
vpsfort-web check            settings, files, this node's vpsfort and every agent, once
vpsfort-web keygen [--out F] a new web key (or metrics token); F mode 0640, never overwritten
vpsfort-web key-id           the web key's fingerprint (and a rotation's .next/.prev keys)
vpsfort-web gen-cert --name console.example.org --name 203.0.113.10 [--force]
vpsfort-web fingerprint      the certificate's SHA-256 fingerprint, as browsers show it
vpsfort-web passwd [--user NAME] [--stdin]       an admin's password (a new NAME: a new admin)
vpsfort-web totp-setup [--user NAME] [--force] [--no-confirm]
                              their one-time codes' secret: a QR code, the otpauth:// link (also
                              without a label, for password managers) and the secret in groups;
                              written only after a code from the app matches, so a failed scan
                              leaves nothing behind (--no-confirm writes at once, for scripts)
vpsfort-web admins                               the admins, and whether each can log in
vpsfort-web remove-admin NAME                    remove one (not admin): files gone, sessions end
vpsfort-web passkeys [--user NAME]               an admin's passkeys (registered on the "Your account" page)
vpsfort-web remove-passkey --user NAME --id ID   remove one (a lost key)
```

**Rotating the web key** (`deploy/rotate-web-key.sh`, as vpsfort's `rotate-cluster-key.sh`): the
agent also answers requests sealed under `<WEB_KEY_FILE>.next` and `.prev`, while the console
sends with `WEB_KEY_FILE`, so the key changes in three rounds without a moment in which the
console can't ask an agent: `start` (the new key as `.next` on every node), `switch` (it becomes
the key, the old one `.prev`), `finish` (the old one goes). Each round copies the files over SFTP
and prints the command to paste into a root shell on each node, which checks them, installs the
key and restarts vpsfort-web; `key-id` and `check` show a rotation in progress. Share links made
before `switch` end with it (they are signed with the key).

## The page

- **Overview:** nodes up, active bans (and how many distinct addresses), bans and events in the
  last hour, alerts in 24 hours, tracked addresses; **Needs attention** (a node without data, a
  failing cluster peer, differing cluster keys, shadow mode, a certificate running out, a full
  disk, security updates, infected files, changed package files, feed errors...); events and
  bans per minute over three hours, per node (also as a table); a card per node.
- **Alerts, Activity** (every decision), **Bans** (per node, or one row per address with the
  nodes that ban it), **Honeypots** (what connected to the nodes' honeypot ports and decoy web
  sites and what it sent, one row per hit with the port and the bytes or request in words, a
  count per port whose chips narrow the table to that port on a click, filters for ports or
  decoy sites: the honeypot nodes' catch without opening each
  address), **Offenders** (scores, evidence, accounts with failed logins): filters,
  sorting, details on click, a column chooser (kept per browser), CSV and JSON. On Alerts and
  Activity, **Merge** folds the same alert or decision on several nodes (a peer's ban relayed to
  each; a cron's ten `su` lines within a minute) into one row with every node and a ×N count; rows
  carry their severity as a left edge, and rows newer than your last look are tinted, with their
  count in the header ("12 new").
- **World:** countries, networks and ports, all nodes added up. Every list folds: the Countries
  picker shows the top 15, a country's Networks and Busiest ports the top 10 each (a big country
  has dozens of networks; a port scan lists hundreds of ports), with "Show all N" under each and
  the full lists on a search; each scrolls inside its card, so picking a country shows its
  networks and ports side by side with the picker on a desktop, and above it on a phone, with the
  country's figures as a chip in the filter row and a link to the map.
- **Map:** the TUI's map, drawn properly. Countries from Natural Earth (public domain) in the Equal
  Earth projection, the whole world or Europe. ▲ sized by active bans, offenders or events, at
  the addresses' coordinates where a node's geo database is a city-level one (one marker per
  place, "Germany, Nuremberg" on hover) and at the country's capital for the rest (the free
  databases name only the country; a node without coordinates, or an older one, draws as
  before); ● where addresses logged in during the last hour; countries `[geoblock]` blocks
  hatched, with the nodes that block them and whether it is in force. Hover for the figures; a
  click opens the country on World. `web/world.json` is made by `scripts/world-map.py`.
- **An address's page** (`#/address/<address or network>`; every address or network shown is a
  link, also inside log lines and messages): the bans covering it on every node, its scores, the
  decisions and alerts naming it, whether a node trusts or allows it, its entry in the last week's
  abuse report, and who runs its network (RDAP).
- **Abuse:** every node's abuse report merged (**To send** turns it into the checklist: networks
  not yet mailed, most bans first, with Copy, Mail and Mark mailed on each row and nothing else), for the last 24 hours or the last 7 days (each
  button shows how many networks it has), one row per network owner (by AS number, else by name):
  its countries, sources, bans, log lines, the nodes that banned them and when last seen. A click
  opens its sources: what each did, in the words of the weekly report, and its first log lines
  marked with the node they hit. **Copy** puts that network's part on the clipboard as an e-mail
  to its abuse desk ("Hello, the following addresses in your network ... attacked our servers"),
  **.txt** saves it as a file, **Mail** looks up the network's abuse mailbox (RDAP) and opens the
  e-mail in your mail program, addressed and with a subject (a report too long for a mail link goes
  in part, the rest saved as a .txt to attach). The text names the attacked servers by their public
  address, never by the nodes' names. The mailbox lookup: the console asks rdap.org (one a second,
  kept a day, following a registry's redirects only to public host names); if it can't (`RDAP_LOOKUPS=off`, no way out from its host) the page asks rdap.org
  itself, which then learns the address asked about and the admin's address. The console follows a
  registry's redirects only to rdap.org and the five registries (`*.arin.net`, `*.ripe.net`,
  `*.apnic.net`, `*.lacnic.net`, `*.afrinic.net`), and only to their public addresses. Only plain
  e-mail addresses are taken from RDAP (the network's owner writes it, and may be the attacker). **Mark
  mailed** remembers a network as reported, shown on its row; "Hide those already
  mailed" leaves out its sources for 30 days. The marks (mailed networks, problems seen) are kept
  by the console in `STATE_DIR`, so every admin and browser sees the same and a restart keeps them;
  this browser's copy stands in while the console has none. **CSV**: one line per source. Sources with fewer than
  3 log lines are left out unless you ask, as in the weekly report. Each node builds its report from its actions log when asked (vpsfort keeps
  it a minute, the console too); the page asks again every 5 minutes or on "Again".
- **A node's page** starts with what changed since the console's previous snapshot of it ("+3
  bans, 1 new alert, new listener on 0.0.0.0:7949"), then vpsfort's mode and figures, log sources, the cluster as that node sees it
  (peers, facts, key), certificates, disk and memory, updates, cron, antivirus and package checks,
  listening services, blocklists, the allowlists, patterns, today's digest so far, that node's
  abuse report (as on Abuse), and its whole snapshot as JSON.

- **Overview** also has sparklines under the bans and events tiles (the last 3 hours), the
  activity charts over 3 hours (per minute), 24 hours or 7 days (per hour, from vpsfort's hourly
  figures since its start), node cards you can **pin** to the top (★, per browser), **Needs
  attention** as a queue (click a problem once seen: it dims, "3 unseen of 8" in the header), and
  **Nodes side by side**: each node's vpsfort and vpsfort-web versions, mode, firewall,
  thresholds, cluster key and which watches are on, the cells that differ from most nodes marked;
  click two nodes to see only what differs between those two.
- **Your account** (your name in the header): this session, the login before it, your sessions
  with "Log out the others", your passkeys (add one: the browser asks the security key or the
  phone; remove one), this browser's settings (colours, notifications, the node legend, the
  saved views, the keys), and **Console health**: what `vpsfort-web check` prints, on the page:
  the certificate's expiry (a warning under 14 days), the web key's id, the admins, the proof of
  work, the sessions open, every node's state and vpsfort-web version.
- **Attention history** (Overview, under Needs attention): the problems of the last 7 days as the
  console saw them appear and go, with how long each lasted. Kept in `STATE_DIR`
  (`/var/lib/vpsfort-web`, the unit's `StateDirectory`), so a restart keeps it; with `STATE_DIR`
  empty, in memory. A changing count ("3 high or critical alert(s)") is one problem.
- **A node's digests:** "Past days" on a node's page shows the last two weeks' digests as the
  console kept them (each day's when it was shown, and every node's 15 minutes before midnight UTC:
  the console's only traffic to the nodes while nobody looks), in `STATE_DIR` across restarts. **Snapshot** saves the node's
  snapshot alone, as `vpsfort tui --file` reads it; **Export JSON** on the Overview saves
  everything the console has (the merged view and every node's snapshot) for a ticket.
- **Share links** (an address's page): "Share link" makes a link to that page that needs no
  login, for handing the evidence to the address's hosting provider: it opens that address's data
  only, read-only like everything here, and ends when it expires (24 hours, 3 days or a week; a
  week at most). Its holder is a stranger to the cluster and sees what the weekly abuse report
  would, no more: the bans covering the address, the ban and unban decisions about it with their
  evidence, and its scores. Account names are withheld as the abuse report withholds them
  ("failed password login (account name withheld)"), anything with an `@` becomes `[account]`,
  internal points go, and the alerts about the host, the users notified, the admin's notes, and
  what the nodes trust or allow are left out altogether; the nodes are numbered, not named, in
  fields and texts alike; no abuse report, no RDAP, no other page, every link plain text. One
  address may open shared pages 30 times a minute (429 beyond); a wrong, expired or hammering
  request is logged with the address first (`share link refused from …`), and vpsfort's
  `vpsfort_web_share` pattern bans an address that keeps trying. The link carries the address
  and its expiry, signed with the web key (on a console without one, a key made at start: its
  links end with a restart). The links made are listed on the account page (who made it, for
  which address, until when; in `STATE_DIR` across restarts), and any admin can **end one
  early** there: it is refused from then on. Making and ending one is logged.
- **Re-offended:** a network marked mailed whose sources were banned again after the mark shows
  "seen again: N" on Abuse, so you can tell which reports worked.
- **Saved views:** ★ in the header saves the tab you are on with its filters ("alerts · level=high
  q=ssh"), in this browser; the same menu lists them for one click back.
- **Keys:** `/` the tab's search, `g` the address box, `1`–`8` the tabs, `j`/`k` the next and
  previous row, `Enter` opens it, `Esc` leaves a box, `?` shows the list. Never while typing.
- **The node legend** under the header (on the tabs with node chips) says which colour is which
  node; "hide" there, and the Account page brings it back.
- **Times:** a table cell shows the time (today's as a time, this year's with the day, older
  with the year) and, within a day, how long ago; the full date is in the tooltip.
- **Every table** of the Alerts, Activity, Bans and Offenders tabs exports as CSV or JSON (the rows
  as filtered, all of them). CSV cells that would start a spreadsheet formula (`=`, `+`, `-`, `@`)
  get a `'` first: log lines and network names come from strangers.

The page refreshes in place: only what changed is redrawn, so the scroll position, rows opened,
text selected and the focus stay, and charts and the map are redrawn only when their data
changes. While text in the page is selected, refreshes wait ("held" in the header) so it can be
copied. A tab left in the background asks again when shown; data older than three refreshes shows
in red in the header; the tab's title counts what needs attention (high or critical). Filters and
settings (not searches) are remembered in the browser. `/` jumps to the page's search box.
The header's search box takes an address or network and opens its page, or searches the open
tab. Each tab keeps its scroll position and opened rows while you look at another. If the console
stops answering, the page says so with how old its data is, tries again with backoff (up to a
minute) and offers "Try now". Printing a page (an abuse report, a node) gives black on white
without the header or buttons. A tab's filters are in its address (`#/alerts?level=high&q=ssh`), so a link shows another admin
the same. 🔔 in the header turns on browser notifications of new critical problems while a console
tab is open; ◐ picks light, dark or the system's colours. On a phone, tables turn into cards.

## API

JSON over HTTPS, GET, with the session cookie (log in with `POST /api/login`
`{"user": "admin", "password": "...", "code": "123456", "work": {...}}`, `Content-Type:
application/json`; without `user`: admin; `work` is the challenge from `/api/v1/session?user=…`
with the `nonce` found, see "Proof of work" above; without it, or with one too easy for the
failures since, 428 and a fresh challenge).

| path | |
|---|---|
| `/api/v1/session` | `{"logged_in": …, "user": …, "totp": …, "node": …, "work": {"salt", "difficulty", "expires", "mac"}}` (needs no session; `?user=NAME` for that account's difficulty) |
| `/world.json` | the Map tab's countries and capitals (public data, needs no session) |
| `/api/v1/cluster` | everything below in one document; `?only=alerts,history` only those parts (and `nodes`, `totals`, `attention`, `refresh_secs`) |
| `/api/v1/overview` | `nodes`, `totals`, `attention` |
| `/api/v1/{attention,alerts,actions,bans,offenders,accounts,world,history,nodes}` | one part; list entries carry `node` and `node_id`; `world` also has `by_country` (each country's networks and ports), `geoblock` (what each node blocks) and `port_names` |
| `/api/v1/nodes/<id>` | one node: its summary, what needs attention, its whole snapshot (`_cut` gives the full length of lists cut short) |
| `/api/v1/nodes/<id>/digest` | `{"text": …}`: that node's digest so far |
| `/api/v1/nodes/<id>/digests` | `{"digests": [{"day", "text"}, …]}`: the last 14 days' digests of that node the console kept (each day's when shown, and every node's 15 minutes before midnight UTC) |
| `/api/v1/attention/history` | `{"problems": [{"level", "text", "nodes", "first", "last", "gone"}, …]}`: what needed attention in the last 7 days, with when it appeared and went (`gone` null: still there); a count in the text is left out, so a changing count is one problem |
| `/api/v1/check` | the console's own health: version, certificate (fingerprint, `not_after`, `days_left`), web key id, admins, TOTP, proof of work, sessions, every node's state and version |
| `/api/v1/export` | everything as one JSON file (a download): the cluster document and each node's whole snapshot (`vpsfort tui --file` reads a node's `snapshot`) |
| `POST /api/v1/share` | `{"net": …, "hours": 1–168}` → `{"path": "/#/share/<net>?t=<token>", "expires": …}`: a link to that address's page that needs no login (see below) |
| `/api/v1/share` | the share links made that haven't expired (`id`, `net`, `by`, `made`, `expires`, `ended`); `POST /api/v1/share/end` with an `id` ends one early |
| `/api/v1/address/<net>?share=<token>` | the address's data for a share link's holder: that address only, until the link expires |
| `/api/v1/abuse/{24h,7d}` | every node's abuse report merged: `nodes` (each with `sources`, or `error`), `sources`, `providers` (`key`, `asn`, `name`, `countries`, `bans`, `events`, `first`, `last`, `nodes`, `sources` with `activity`, `evidence`, `omitted`, `members`) |
| `/api/v1/nodes/<id>/abuse/{24h,7d}` | the same for one node |
| `/api/v1/address/<address or network>` | `bans`, `actions`, `offenders`, `trusted`, `allowed` naming it or overlapping it, each with its node |
| `/api/v1/rdap/<address>` | `{"abuse": [...], "network": ...}`; 502 with `"fallback": true` when the console can't look up |
| `/api/v1/sessions` | this admin's sessions; `POST /api/v1/sessions/end-others` ends the others |
| `/api/v1/marks` | the admins' marks (networks marked mailed, problems seen) as the page keeps them, and `kept`: whether the console stores them; `POST` replaces them (an object, 256 KB at most) |
| `/api/v1/passkeys` | this admin's passkeys (`id`, `name`, `added`, `alg`, `logins` and `last_used` as the console counted them, `sign_count`: the authenticator's own counter, 0 for passkeys that sync) and the relying party id; `POST /api/v1/passkeys/begin` gives the registration options, `/finish` takes the browser's answer (`challenge`, `id`, `clientDataJSON`, `attestationObject`, `name`), `/remove` an `id`. At the login, `/api/v1/session?user=NAME` carries `passkey` (the request options) for an account that has one, and `POST /api/login` takes `passkey: {id, challenge, clientDataJSON, authenticatorData, signature}` instead of `code` |
| `/metrics` | Prometheus' text format |

Times are microseconds since 1970 (UTC), as in vpsfort. Node ids are `0` for this node and
`1`, `2`, ... for the entries of `NODES`.

### Prometheus and Grafana

```bash
/opt/vpsfort-web/vpsfort-web keygen --out /opt/vpsfort-web/metrics.token   # then METRICS_TOKEN_FILE=... and restart
```

```yaml
scrape_configs:
  - job_name: vpsfort
    scheme: https
    scrape_interval: 60s
    authorization: { credentials_file: /etc/prometheus/vpsfort.token }
    tls_config: { ca_file: /etc/prometheus/vpsfort-web.crt }   # the self-signed certificate
    static_configs: [{ targets: ["console.example.org:7948"] }]
rule_files: [vpsfort-rules.yml]   # deploy/prometheus-rules.yml: node down, data stale, critical attention, ban spike, infected files, changed package files, disk, memory, certificates, peers, updates
```

`deploy/prometheus-rules.yml` holds alerting rules for every series above with thresholds to
start from; every series carries the node's name in `node`.

Everything the console shows, per node (`node` label), in about 110 families:

| area | series |
|---|---|
| the console's view | `vpsfort_up`, `vpsfort_data_age_seconds`, `vpsfort_fetch_duration_seconds`, `vpsfort_web_agent_info{version}`, `vpsfort_attention{level}` (the overview's "needs attention", for alert rules) |
| vpsfort | `vpsfort_info{mode,backend}`, `vpsfort_enforcing`, `vpsfort_started_timestamp_seconds`, `vpsfort_snapshot_timestamp_seconds`, `vpsfort_tracked_addresses`, `vpsfort_tracked_connections`, `vpsfort_unapplied_changes`, `vpsfort_apply_failures_total`, `vpsfort_ban_threshold{window}`, `vpsfort_offenders`, `vpsfort_last_line_timestamp_seconds{source}` |
| bans, alerts, events | `vpsfort_active_bans{origin,kind}` (every ban counted: `origin` local or the peer that decided it, `kind` address or network), `vpsfort_bans_total`, `vpsfort_alerts_total`, `vpsfort_bans_last_hour`, `vpsfort_events_last_hour`, `vpsfort_alerts_last_day{severity}`, `vpsfort_records_total{source}`, `vpsfort_events_total{signal}`, `vpsfort_unattributed_lines_total`, `vpsfort_hidden_addresses_total` |
| accounts and trust | `vpsfort_accounts_with_failures`, `vpsfort_accounts_under_attack`, `vpsfort_trusted_addresses`, `vpsfort_operator_allowlist_entries` |
| places | `vpsfort_country_{active_bans,offenders,events}{country}`, `vpsfort_network_{active_bans,offenders,events}{asn,name,country}`, `vpsfort_port_events{port}`, `vpsfort_logged_in_addresses{country}`, `vpsfort_offenders_unlocated` |
| blocking | `vpsfort_geoblock_networks{family}`, `vpsfort_geoblock_applied`, `vpsfort_geoblock_error`, `vpsfort_geoblock_asns`, `vpsfort_geoblock_country{country,list}`, `vpsfort_feed_networks{family}`, `vpsfort_feed_applied`, `vpsfort_feed_error`, `vpsfort_feed_refreshed_timestamp_seconds`, `vpsfort_feed_skipped_entries`, `vpsfort_feed_asns`, `vpsfort_feed_source_{entries,error}{url}` |
| cluster | `vpsfort_cluster_info{node_id,key_id}`, `vpsfort_cluster_key_installed_timestamp_seconds`, `vpsfort_cluster_rotation_keys`, `vpsfort_cluster_peer_up{peer}`, `vpsfort_cluster_peer_last_ok_timestamp_seconds{peer}`, `vpsfort_cluster_peer_failing_since_timestamp_seconds{peer}`, `vpsfort_cluster_heard_from_timestamp_seconds{from}`, `vpsfort_cluster_facts_known`, `vpsfort_cluster_facts_{received,sent}_total`, `vpsfort_cluster_rejected_total`, `vpsfort_cluster_refused_by_limit_total` |
| host | `vpsfort_cert_{expiry,start,checked}_timestamp_seconds{target}`, `vpsfort_cert_error{target}`, `vpsfort_cert_wrong_name{target}`, `vpsfort_disk_{size,available}_bytes{mount}`, `vpsfort_disk_free_ratio{mount}`, `vpsfort_memory_{total,available}_bytes`, `vpsfort_memory_available_ratio`, `vpsfort_swap_{total,free}_bytes`, `vpsfort_memory_pressure_ratio{kind}`, `vpsfort_updates_pending`, `vpsfort_security_updates`, `vpsfort_reboot_required`, `vpsfort_kernel_outdated`, `vpsfort_processes_using_replaced_files`, `vpsfort_updates_checked_timestamp_seconds` |
| integrity | `vpsfort_av_{infected_files,scanned_files,errors}`, `vpsfort_av_signatures_outdated`, `vpsfort_av_scan_completed`, `vpsfort_av_last_scan_timestamp_seconds`, `vpsfort_verify_{checked_files,mismatched_files,setuid_programs}`, `vpsfort_verify_last_run_timestamp_seconds`, `vpsfort_cron_{tasks,scripts,files,errors}`, `vpsfort_cron_scanned_timestamp_seconds`, `vpsfort_procwatch_{pairs,outbound}` |
| exposure | `vpsfort_listeners{exposure}`, `vpsfort_public_listener{proto,port,process}`, `vpsfort_firewall_dead_rules`, `vpsfort_ufw_active` |
| patterns | `vpsfort_pattern_{lines,matches,unaddressed}_total{pattern,kind}`, `vpsfort_pattern_addresses{pattern,kind}` |
| the console | `vpsfort_web_logins_total{result}` (ok, failed, locked_out), `vpsfort_web_sessions`, `vpsfort_web_nodes` |

No series names an attacker's address or an account (personal data, and unbounded); countries,
networks, ports, peers and the rest are bounded by vpsfort's own caps. A family appears when the
node has that part (`[feeds]`, `[antivirus]`, ... switched on). Rules to start from:
`vpsfort_up == 0`, `vpsfort_attention{level=~"critical|high"} > 0`,
`vpsfort_cluster_peer_up == 0`, `increase(vpsfort_web_logins_total{result="failed"}[15m]) > 3`,
`vpsfort_cert_expiry_timestamp_seconds - time() < 7 * 86400`.

## Files

| path | owner, mode | |
|---|---|---|
| `/opt/vpsfort-web/vpsfort-web` | root 0755 | the binary (`.prev`: the rollback one) |
| `/opt/vpsfort-web/config.env` | root:vpsfort-web 0640 | settings |
| `/opt/vpsfort-web/web.key` | root:vpsfort-web 0640 | the web key |
| `/opt/vpsfort-web/tls.crt`, `tls.key` | 0644, root:vpsfort-web 0640 | the console's certificate |
| `/opt/vpsfort-web/admin.password`, `admin.totp` | root:vpsfort-web 0640 | `admin`'s login |
| `/opt/vpsfort-web/admins/` | root:vpsfort-web 0750, files 0640 | the other admins' logins |
| `/etc/systemd/system/vpsfort-web.service` | root 0644 | the unit |
| `/run/vpsfort-console/console.sock` | root:vpsfort-web 0660 | vpsfort's console socket (vpsfort makes it) |
| `/var/lib/vpsfort-web/passkeys/<admin>.passkeys` | vpsfort-web 0600 | the admins' passkeys: public keys, written by the console at registration (the directory of the passwords is root's, and the unit may write nowhere else). With `STATE_DIR=` empty they go beside the password file, which the console must then be able to write. A file beside the password file is still read while the state directory has none for that admin |
| `/var/lib/vpsfort-web/` (`STATE_DIR`) | vpsfort-web 0700 | `attention-history.json`, `digests.json`, `marks.json`, `share-links.json`, `lockouts.json`, `sessions.json` (the cookies' digests only): the console's own state across restarts |

Logs: `journalctl -u vpsfort-web`.

## Install from a release bundle

Every version tag `vpsfort-web-v<version>` gets its bundle, `vpsfort-web-<version>-<commit>-<arch>.zip`
for each architecture (`x86_64-linux-musl`, `aarch64-linux-musl` for arm64,
`armv7-linux-musleabihf` for 32-bit ARMv7), as an asset of the tag's GitHub Release (see
"Releases" in the [repository README](../README.md#deployment)). Take the one for the server's
architecture (`uname -m`) and check it:

```bash
arch=x86_64-linux-musl     # the server's: aarch64-linux-musl (arm64), armv7-linux-musleabihf (32-bit ARM)
gh release download vpsfort-web-v0.6.3 --repo makhort/vpsfort --pattern "*-$arch.zip*"   # the zip, its .sha256 and .sigstore.json
sha256sum -c vpsfort-web-*-$arch.zip.sha256          # the download is intact (macOS: shasum -a 256 -c)
gh attestation verify vpsfort-web-*-$arch.zip --repo makhort/vpsfort --source-ref refs/tags/vpsfort-web-v0.6.3
```

Then on the server:

```bash
unzip vpsfort-web-*-$arch.zip && cd vpsfort-web-*-$arch
sudo ./install.sh            # or as root; again after editing config.env
sudo ./install.sh rollback   # back to the previous version
```

## Install from a package

The same release has a package per architecture, for the distribution's package manager instead of `install.sh`: `vpsfort-web_<version>-1_<arch>.deb` (`amd64`, `arm64`, `armhf`; Debian, Ubuntu and their derivatives) `vpsfort-web-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`, `armv7hl`; Fedora, RHEL and its rebuilds) and `vpsfort-web-<version>-r0.<arch>.apk` (`x86_64`, `aarch64`, `armv7`; Alpine, with OpenRC: below), each with its `.sha256` and `.sigstore.json`, downloaded and verified as the bundle above (`--pattern "*.deb*"`, `"*.rpm*"` or `"*.apk*"`). CI keeps them for every commit as workflow artifacts, and `scripts/package.sh` builds them locally (`cargo install cargo-deb cargo-generate-rpm --locked` once, and python3 for the `.apk`, which `scripts/apk.py` at the repository's root writes; none needs dpkg, rpm or apk-tools, so it runs on macOS too; `--target aarch64-unknown-linux-musl` or `armv7-unknown-linux-musleabihf` for the ARM ones). Or from the signed apt and dnf repository on GitHub Pages, once it is set up (the repository README, "Deployment"), where `apt upgrade` and `dnf upgrade` then bring new versions.

```bash
sudo apt install ./vpsfort-web_0.6.3-1_amd64.deb     # Fedora, RHEL:  sudo dnf install ./vpsfort-web-0.6.3-1.x86_64.rpm
sudoedit /opt/vpsfort-web/config.env                 # the first install put the template there; then the keys, password, codes ("Setup")
sudo dpkg-reconfigure vpsfort-web                    # rpm: sudo dnf reinstall ./vpsfort-web-*.rpm  (step 7: owners, modes, the certificate)
/opt/vpsfort-web/vpsfort-web check && sudo systemctl enable --now vpsfort-web
```

The package puts the same files in the same places as `install.sh` (`/opt/vpsfort-web` with the binary and `config.env.example`, the user `vpsfort-web`), except the unit, which is in `/usr/lib/systemd/system`. Its post-install step does what `install.sh` does apart from copying files: the user, `config.env` from the template the first time, the owners and modes, the self-signed certificate once `CONSOLE_LISTEN` is set; and it lists what is still missing (the to-do list of "Setup"). `dpkg-reconfigure vpsfort-web` (rpm: `dnf reinstall`) runs that step again, as "`bash install.sh` again" does for the bundle. `apt remove vpsfort-web` (`dnf remove`) stops the service and keeps `/opt/vpsfort-web`; `apt purge` removes it with the keys, password and certificate (rpm: by hand).

**Nothing starts on its own.** The first install puts the template in place and prints what to fill in; you enable the service once it is filled in. An upgrade keeps the config and restarts the service only if it was running and the config is filled in. **Over a bundle or `deploy.sh` install** the package takes over: the config, state and keys stay; the bundle's unit in `/etc/systemd/system` (it would shadow the package's) and its rollback files go, and the service is enabled again on the package's unit if it was (vpsfort's integrity watch reports the removed unit as a warning once). **Replacing the config:** when a terminal is there, the install asks whether to replace the config with the new template (the old one kept with the suffix `.old`); Enter, a timeout of a minute, no terminal or `DEBIAN_FRONTEND=noninteractive` keep it. `VPSFORT_PACKAGE_CONFIG=replace` (or `keep`) answers without asking: `sudo VPSFORT_PACKAGE_CONFIG=replace apt install ./<file>.deb`. **Rollback** is installing the previous version's package (`apt install ./<old>.deb --allow-downgrades`, `dnf downgrade ./<old>.rpm`): there is no `.prev` file.

**Alpine (apk, OpenRC):** `apk add --allow-untrusted ./vpsfort-web-<version>-r0.x86_64.apk` puts the same files in the same places, with the OpenRC script `/etc/init.d/vpsfort-web` instead of the unit: the settings exported from `config.env` as `EnvironmentFile=` does, `STATE_DIR` `/var/lib/vpsfort-web` (the console's own, mode 0700) unless `config.env` says otherwise, the console's own messages in `/var/log/vpsfort-web/console.log`, supervised by `supervise-daemon` and started again 5 seconds after a crash; systemd's sandboxing has no equivalent there. The package is unsigned, hence `--allow-untrusted`: `sha256sum -c` and the attestation verify it. Its install scripts are POSIX sh and do what the post-install step above does: the user, `config.env` from the template the first time, the owners and modes; an upgrade restarts a running console. Then `rc-update add vpsfort-web default && rc-service vpsfort-web start`. `apk del vpsfort-web` stops it and keeps `/opt/vpsfort-web` and the state. Not yet run on an Alpine host: CI installs the package in an Alpine container.

## Development

```bash
./scripts/ci.sh              # fmt, clippy -D warnings, tests, cargo audit, static musl build
./deploy/deploy.sh <host>    # ci.sh, then the files over SFTP and the command for a root shell
```

`node --test web/tests/*.test.mjs` (in `ci.sh` when Node is installed) tests the page's patching against a
small fake DOM, the proof of work's SHA-256 against the standard's vectors and the console's check, and the abuse e-mail, mail links, RDAP parsing, CSV, address links and link
filters. `tests/end_to_end.rs` runs an agent and a console against a fake vpsfort socket and logs in
over TLS like a browser (it listens on 127.0.0.1 and a Unix socket). The fuzz targets in
`fuzz/` (`cargo +nightly fuzz run http_request`, `agent_request`, `snapshot`, `abuse_report`) cover what strangers
and key holders send; `tests/fuzz_smoke.rs` runs them over their seeds on stable.

## Verified

**On the Mac**, beyond the tests above: runs against snapshots made from real decision logs,
through real TLS and the agent protocol, with the page looked at in a browser (light and dark;
phone, tablet and desktop widths; keyboard only), and two reviews of the rendered page with the
fixes they named. Abuse reports built by vpsfort from a copy of real actions logs and merged
from two fake nodes through a real agent, per-provider Copy and .txt, several admins (also
against a console without vpsfort), the in-place refresh; the address page, Mail with RDAP (the
console's lookup and the browser's fallback both asked rdap.org for real addresses), mailed
marks, CSV/JSON exports, links with filters, sessions, the 7-day charts, the table of
differences; the proof of work and the account lockout through the demo (a wrong password
raised the difficulty from 20 to 21 bits, the next login solved it and got in; 20 bits took
0.7 s in the browser, 22 bits 2.4 s) and in the end-to-end test; the no-JavaScript notice
rendered from its markup.

**On the real cluster** (since 2026-10-27; five nodes, all but one
through their agents): the unit under systemd's sandboxing, vpsfort's real console socket,
`install.sh`, a browser reaching the console without a tunnel with its self-signed certificate;
every node's alerts and bans on one page; a node's stale state during its agent's restart, the
"since the last snapshot" line as its data came back, the filters above the tables.

**Reviewed** (2026-10-29): an audit of the whole crate (the proof of work first): six fixes,
each with a test, listed in the commit `vpsfort-web: audit fixes`; the rest of what was read
(the HTTP parser, the agent protocol, sessions, the page's handling of what nodes send, the
unit's sandbox, the installer's modes) found sound. A second audit the same day, after the
page's changes: two small fixes (a locked account's files were read for any login attempt at
it, now only for one carrying something shaped like a code; the page's "seen" marks are pruned
after 30 days). Known and accepted: someone holding an account's TOTP secret but not its
password can keep failing at a locked account (the lock is for password guessers; the secret is
the larger loss); `/api/v1/session?user=NAME` shows a raised difficulty for a name under
attack, which says the name is being tried, not that it exists.

**Found by these runs**, fixed the same day: `check` misread an `AGENT_ALLOW` list with blanks
when `config.env` was sourced in a shell (the commands now read the file themselves, as systemd
does); the installer's new system user raised high alerts in vpsfort (the installers now
announce the account files); an empty console socket setting was refused; on the real cluster
the Bans, Offenders and Activity tabs had their heading and filters below the table.

## Not yet verified

Covered by tests, not yet seen on a server:

- a Let's Encrypt certificate's reload, and Prometheus scraping the metrics;
- vpsfort building a week's abuse report under its unit's memory limit;
- agents of mixed versions;
- browser notifications firing, and RDAP from a server's sandboxed unit;
- a phone's proof-of-work solve time;
- the ARM builds on a server;
- the map's markers at coordinates, from a node with a city-level geo database;
- passkeys with a real security key or phone (the checks run against a fake authenticator's answers in the tests), `STATE_DIR` on a server (the history, digests, marks, share links, lockouts and sessions read back after a restart), ending a share link early, `HISTORY_DAYS`/`DIGEST_DAYS` other than the defaults, and a web key rotation between real nodes.
