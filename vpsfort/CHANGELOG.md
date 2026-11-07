# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.6.2 - 2026-11-07

Fixes found on the VPN node and in the Fedora node's first upgrade from the repository.

- `sysctl-audit` and the hourly reading also read what the next boot sets, from the sysctl.d files as systemd-sysctl reads them. Each of these is now a problem of its own: a good value the files set back at boot, named with its file and line (Ubuntu's `kernel.sysrq = 176`); lines boot skips, such as a pasted `sysctl -w` command, with the `sed` that fixes them; hardening only `/etc/sysctl.conf` holds where systemd doesn't read it (Debian 13); and `fs.suid_dumpable` under apport, which sets it to 2 at every start. Before, a fix applied with `sysctl -w` alone looked done until the next reboot.
- `sysctl-audit --conf` prints the `key = value` lines for `/etc/sysctl.d/90-hardening.conf` that keep every watched sysctl at a good value, never weaker than it is now: `vpsfort sysctl-audit --conf | tee -a /etc/sysctl.d/90-hardening.conf && sysctl --system`.
- When a sysctl problem is told as fixed and no sysctl.d file keeps the fix, the message says that the next reboot undoes it.
- Upgrades (package and `install.sh`) no longer print the peers' cluster-port rules that are already in place, with firewalld's `ALREADY_ENABLED` warning or ufw's "Skipping adding existing rule" for each: only a rule that is added is shown. firewalld is reloaded only when its running rules lack one, so an upgrade with nothing to add no longer drops the runtime bans until the restart.

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
