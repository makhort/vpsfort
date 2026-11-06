# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.6.1 - 2026-11-06

Fixes.

- Upgrades no longer raise a high integrity alert for the new config template: the .deb/.rpm, bundle and Alpine installers announce `vpsfort.toml.new` before writing it (the package also a replaced config and its `vpsfort.toml.old` copy).
- The package's question whether to replace the config is asked on the terminal itself, so it shows under dnf too: dnf held it back with the install's output, and the install looked hung for the question's minute before keeping the config.
- `sysctl-audit`'s fix names the `key = value` line that keeps a setting after a reboot in `/etc/sysctl.d/90-hardening.conf`; it read as if the `sysctl -w` command went there, where it is ignored at boot.
- The TUI's Overview labels the running process's decision count "This run" (it said "In all", which read as if the state had been lost after a restart).

## 0.6.0 - 2026-11-05

First public release.

- Follows the systemd journal (or a syslog text file) for sshd, ejabberd, the firewall's log, Nextcloud and twenty-odd common services, with patterns of your own for the rest.
- Scores every remote address by its behaviour, with decaying scores, a ban ladder, subnet and account analysis, and bans in nftables, firewalld, ufw, iptables or ipset within seconds; whole countries and networks by the offline geo database.
- Kernel tripwires and honeypot ports, which keep what the scanner sent for the evidence.
- Host watches: su and sudo, scheduled tasks, package files and set-uid programs, outbound connections and odd processes, nftables rulesets, listeners, patch status, PAM and audit records, changed files scanned by ClamAV or YARA.
- An encrypted cluster link between nodes: shared bans and suspicion reports, per-node signing, a decision log mirrored to a peer.
- Alerts, a daily digest and a weekly abuse report through file outboxes, for the bots and the web console; a read-only console socket; Prometheus metrics.
- A TUI dashboard, `explain`, baselines, a self-audit, an sshd audit, a canary lockout warning.
- Release bundles and .deb, .rpm and .apk packages for x86_64, aarch64 and armv7; OpenRC scripts for Alpine.
