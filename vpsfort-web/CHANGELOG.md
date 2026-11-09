# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
