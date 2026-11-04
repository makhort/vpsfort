# vpsfort-sim

A simulated vpsfort cluster and its web console, in one process, from real decision logs
or a console export. For trying the console without servers, for screenshots, for working on
the page against a cluster's worth of data, and for showing it around.

What runs:

- **A node per decision log** (`actions.jsonl`): its state is what vpsfort's own log reader
  (`tui --actions`) makes of the log (the bans active at its end, the decisions, the alerts,
  the countries and networks), its digest comes from vpsfort's digest renderer, and its
  abuse reports from vpsfort's live report builder, so the console sees exactly what a
  daemon's `[console]` socket would answer. A log is shifted so that it ends now (`shift_to_now`),
  and every `trickle_secs` a new ban (now and then an alert) copied from it, stamped now, keeps
  the page's "new since your last look" paths busy.
- **A node per snapshot** the console saved ("Snapshot" or "Download JSON" on a node's page,
  or the nodes of an "Export JSON" of the whole cluster): served as it is. No abuse reports
  (they need a log); the digest is rendered from the snapshot.
- **A real vpsfort-web agent** on every node but the first, and **a real vpsfort-web
  console** on the first node's socket and the other nodes' agents: the production layout,
  with the real login (password, one-time code, proof of work), sessions, share links, exports.

What a decision log doesn't carry (the cluster as the node sees it, certificates, disk and
memory, antivirus, package and cron checks, updates, listeners) is **made up** when `fill = true`
(the default), varied per node so every card of the console shows something: an infected file
here, a failing peer there, a full disk, a certificate about to expire. Don't take those for
real; the bans, offenders, alerts, countries and abuse reports are the log's.

## Run

```bash
cargo build --release
./target/release/vpsfort-sim --init            # writes vpsfort-sim.toml: an example to edit
./target/release/vpsfort-sim vpsfort-sim.toml
```

The first run makes what the console needs and says so: the web key, the admin's password
(`vpsfort-sim` for the account `admin`), the one-time secret (printed as an `otpauth://` link
for an authenticator app, and the current code, which a real console never prints), and a
self-signed certificate for 127.0.0.1 and localhost. Files that exist are kept; delete one to
have it made again. Then it prints each node, the agents, the console's address and how to
log in. Open `https://127.0.0.1:7948` and accept the certificate (its fingerprint is printed).

## Configuration

```toml
dir = "/tmp/vpsfort-sim"        # keys, the admin's files, the certificate, sockets, shifted logs (keep it short; made 0700, and refused if others can reach it)
console_listen = "127.0.0.1:7948"
plain_http = ""                  # e.g. "127.0.0.1:7950": the same console over plain HTTP, for a browser that can't take the certificate (loopback only)
agent_port = 7960                # the agents: 127.0.0.1:7960, 7961, ... (the first node needs none)
totp = true                      # logins ask for a one-time code (the secret is made and printed)
login_work = 8                   # proof-of-work bits before a login (the real default is 20; 0: off)
refresh_secs = 10
expected_version = ""            # EXPECTED_VERSION: a node on another vpsfort-web release is pointed out
shift_to_now = true
trickle_secs = 20                # 0: nothing moves
fill = true                      # the made-up cards (see above)
export = ""                      # a console export: its nodes, besides the ones below

[[node]]
name = "node1"
actions = "logs/node1.actions.jsonl"   # relative to this file
address = "203.0.113.10"         # the public address the abuse reports name
backend = "nftables"

[[node]]
name = "node2"
snapshot = "vpsfort-node2-snapshot.json"        # a snapshot instead of a log
```

Nodes are numbered in the order given, the export's after the `[[node]]` entries; the first
one hosts the console. A node of the export without a snapshot (it was down when exported)
is left out, and said.

The `plain_http` door rewrites each request's `Host`, `Origin` and `Referer` to the console's
own and drops the HSTS header on the way back, so the page's login works over `http://127.0.0.1`
(browsers treat that address as secure). It is for automation; use HTTPS otherwise.

## What it is not

Nothing is enforced: there is no firewall, no journal, no cluster traffic between the nodes.
The nodes don't talk to each other; a peer's ban in a log stays a line in that log. The
console's own behaviour (sessions, lockouts, share links, the attention history, the digest
archive) is the real one, in the real code.
