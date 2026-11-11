# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.7.0 - 2026-11-11

The Honeypots tab for a node of a hundred ports: a filter by service type, folded port chips, the last 3 hours. Its answer is built once and kept, within the service's memory. A click on a new row acknowledges it. And the fixes of an audit of the whole console: share links are signed with a key of the console's own, so links made before this version are refused.

- The Honeypots tab filters by service type (SSH, Telnet, Mail, VNC, Databases, Crypto and so on, with each one's hits), and its search finds them too. A service narrows the table and the port chips with it.
- The tab's port chips are folded to two rows, with a button that opens all of them in a box that scrolls: the honeypot node template has 92 ports now. A chip in use stays in sight while they are folded, and the service and the open list are kept in the page's address, so a saved view has them.
- The tab offers the last 3 hours as well, as the Overview's Activity does.
- The Honeypots tab's answer is built once per period and kept a minute (ten seconds while a node hasn't answered), by one request at a time, straight to JSON. Every request used to copy each node's hits, merge them and build the answer twice over in memory: two tabs asking for a week of a busy honeypot node at once could take the service past its 128 MB.
- A node's hits are kept with at most 50,000 evidence lines in all, the newest first; the rest are counted, as the page says.
- A click on a row marked new (Honeypots, Alerts, Activity) opens it and acknowledges it: the mark goes from that row at once and the "new" count drops, where it used to stay until the page was loaded again. The acknowledgment is kept in the browser until the next look makes the row old anyway.
- A share link's page asked at the rate limit made the console stop: the refusal was read twice, and the second reading could find none (a panic, which ends the service). Anyone holding a link, or guessing at one, could do it.
- Share links are signed with a key of the console's own (`STATE_DIR/share.key`), not the web key every node holds: a node broken into could make links to any address's page. Links made before this version are refused; a link must also be among those listed, so one ended early stays ended.
- An admin whose TOTP secret file is empty or shorter than 16 bytes can't log in (the codes of an empty secret are anyone's to compute). The last code used is kept across restarts, so a code seen once can't be used again after a crash. A changed password ends that admin's sessions at their next request. A full table of locked names still counts failures for a new name.
- A response has a deadline as a request has (a client that doesn't read used to hold one of the 64 connections for as long as it liked), and IPv6 clients are counted per /64.
- RDAP lookups have 40 seconds in all, three addresses a name, and never go to carrier NAT, benchmark or reserved ranges. A node's digest is cut at 256 KiB and its error text at 500 characters; the attention list holds 60 rows of 300 characters. An agent remembers a request's id for as long as the request is valid.
- A shared page names no node, a peer's name in a text included ("another node").
- The page: a link with a filter value no control offers no longer leaves a tab broken in that browser (the tab's filters go back to their defaults, and a tab that can't be drawn says so while the others work); `#/constructor` and a stray `%` in a link are plain text; a time no date holds is "unknown time"; CSV cells holding `;` or a tab are quoted; a shared page whose link ended stops asking (each refusal counted towards a ban of its reader); the address in a request's path is an address. The policy lets the page ask Brazil's registry (`rdap.registro.br`).
- `deploy.sh` and `rotate-web-key.sh` refuse a staging copy holding anything but regular files, as vpsfort's do; on Alpine the service's log file is made for its user; a secret file is written at its mode whatever the umask.
- A node's reply is read as it is unpacked, one reply at a time: up to 64 MB each used to be unpacked whole and then read into a second copy, for every node asked at once, in a service limited to 128 MB.

## 0.6.6 - 2026-11-09

The Honeypots tab counts each hit once, at its own time, and names what reached a decoy site in another protocol.

- The Honeypots tab counts a hit once when an address's ban and the network ban that followed both list it.
- Its Time column says when the hit was, not when the ban listing it was taken: a network ban gathers hits from hours before. A hit older than the period chosen is left out.
- A decoy site's rows name what a client sent when it spoke another protocol to a web port (a TLS client hello, an MS SQL pre-login, an OpenVPN client reset), before the bytes the web server logged.

## 0.6.5 - 2026-11-09

Where the honeypots' visitors come from.

- The Honeypots tab has Place and Network columns, from what each ban's message says of its target, and its search covers them: a botnet's addresses in one country on several providers show at a glance.

## 0.6.4 - 2026-11-09

The Honeypots tab reads the nodes' actions logs.

- The Honeypots tab shows the last 24 hours or 7 days, read from each node's actions log (`/api/v1/honeypots/{24h,7d}`, every minute), with what the latest decisions add in between. It could only see the latest decisions held in memory, of which a restart leaves 100 per node, and the console's 600 were mostly the peers' copies. A node that can't answer (its vpsfort or vpsfort-web is older) is named, and shows its latest decisions as before. Needs the vpsfort with the `honeypots` commands on each node.
- Hit lines from before the capture existed (`connected to honeypot TCP/23` with nothing after it) are shown too, as "not recorded". A network ban's hits name the member that made them.

## 0.6.3 - 2026-11-09

The Honeypots tab's chips and search.

- The Honeypots tab's search takes a port typed whole (`23`, `TCP/23`) as that port, not as every port it is a prefix of (2375, 2376).
- A click on one of the tab's port chips narrows the table to that port (the decoy sites' chip to the decoy sites), and a second click widens it again; the chip shows which is on.

## 0.6.2 - 2026-11-09

A fix checked in the simulator against the honeypot node's export.

- The Honeypots tab puts each hit under the node that caught it. A ban the peers took over carries the honeypot's evidence on every node, and the tab kept whichever copy came first, so hits were counted under the peers and the honeypot node's own filter showed a few. The deciding node's row is kept; where only the peers' copies are among the latest decisions, the hit is shown under the origin's name. A ban whose end has passed reads "ban, ended 12m ago", not "... ago left".

## 0.6.1 - 2026-11-09

A fix found on the console.

- The Honeypots tab asks the console for the nodes' decisions when it opens: it showed nothing, since the page fetches only the parts its open tab names and the new tab named none.

## 0.6.0 - 2026-11-09

A Honeypots tab.

- A **Honeypots** tab: the nodes' decisions whose evidence came from a honeypot port (`[ports] honeypot`) or the decoy web site (`[sources] apps = ["decoy"]`), one row per hit with the node, the address, the port and what the scanner sent, the hits counted per port, filters for node, ports or decoy sites, and a search over what was sent. Before, each honeypot catch meant the Bans tab, the address's page and the row of its decision.

## 0.5.1 - 2026-11-06

Fixes.

- The package's question whether to replace `config.env` is asked on the terminal itself, so it shows under dnf too: dnf held it back with the install's output, and the install looked hung for the question's minute before keeping the config.

## 0.5.0 - 2026-11-05

First public release.

- A read-only HTTPS console for the whole cluster: nodes, bans, scores, alerts, history, digests, maps at city coordinates, health, saved views.
- Agents on the nodes read the daemon's console socket and talk to the console over a web key of their own, never the cluster key.
- Admin sign-in with a password and an optional one-time code, or with a passkey alone; lockouts, sessions and passkeys survive a restart; share links that show what the abuse report shows, no more.
- Exports, Prometheus metrics with alerting rules, a web key rotation script.
