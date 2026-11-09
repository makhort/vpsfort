# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
