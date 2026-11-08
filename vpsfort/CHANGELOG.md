# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.7.0 - 2026-11-08

Honeypots that bring out the login a bot tries, a decoy web site, and the README's recipe for dedicated honeypot nodes in a cluster.

- `[ports] honeypot_prompts = { "2323/tcp" = "telnet", "21/tcp" = "ftp", "25/tcp" = "smtp" }` (also `pop3`, `imap`, `ssh`; off by default) makes those honeypot ports show a server's fixed prompts and read the reply to each, so clients that wait for the server (Telnet bots, FTP and mail scanners) hand over the login they try instead of showing as `sent nothing`: the evidence reads `answered the telnet prompts with 14 bytes: "root\r\nxc3511\r\n"`. `ssh` sends an sshd's identification line alone, which most scanners wait for before sending their own (a day's report showed four of five SSH hits silent): `answered the ssh banner with 22 bytes: "SSH-2.0-libssh_0.9.6\r\n"`. Every greeting is a real server's line (OpenSSH, vsftpd, Postfix, Dovecot, Debian's issue line), since a scanner that meets an unknown banner marks the host and moves its other addresses on; `honeypot_banners = { ssh = "...", ftp = "..." }` names the software and version each port is to pass for. Nothing the client sends is parsed or answered. No HTTP, on purpose (the README says why).
- A honeypot's captured HTTP request is described by its request line, host and user agent (`sent HTTP request "GET /.env HTTP/1.1" for host "..." with user agent "..." (212 bytes)`) instead of its first 120 bytes.
- A Telnet, FTP, POP3 or SMTP bot that sends its login and password in one packet, before the password prompt, loses neither: the honeypot keeps what a read brought beyond the line it asked for, for the next prompt's reply. (The second line was dropped, and the second prompt waited for nothing.)
- The README's Caddy decoy block uses a certificate file with `default_sni` and `fallback_sni` instead of `tls internal { on_demand }`, which let any client have Caddy mint certificates and gave a client that sends no name none, so a scanner's TLS request by address went unlogged. The lighttpd block no longer lists the modules Debian loads already (a module listed twice stops lighttpd) and says what each real site's block must set back; Apache's notes `a2enmod ssl`.
- `[sources] apps = ["decoy"]` reads the log of a catch-all web site that nothing points at (`decoy.log` next to nginx's, Apache's, lighttpd's or Caddy's logs): every request there is a scanner's, so one request bans (`decoy_request`, `decoy_request_json`, 100 points) with the server's own log line as evidence. The README has the server blocks for nginx, Apache, Caddy and lighttpd.
- README: "Dedicated honeypot nodes", how one or more nodes that serve nothing feed their bans to the cluster, and what to limit them to with `peer_accept`.

Found on the servers.

- `sysctl-audit` warns that apport will set `fs.suid_dumpable` back only where apport starts at boot. It looked at `kernel.core_pattern`, which still names apport after `systemctl disable --now apport` on Ubuntu 22.04: apport is an init.d script there, and `--now` disabled it without stopping it. The advice is now `systemctl disable apport && systemctl stop apport`.
- `sysctl-audit` and the hourly reading read ufw's own sysctl file (`IPT_SYSCTL` in `/etc/default/ufw`, `/etc/ufw/sysctl.conf` as shipped) where ufw is enabled. ufw applies it at every start and reload, after the sysctl.d files, and it sets `log_martians` to 0, so a line in `90-hardening.conf` and `sysctl --system` held only until ufw next started. The audit and `--conf` now name the line in that file to change.
- The clock warning no longer fires at a boot. The first reading came before timesyncd's first NTP answer, warned at once and was kept for an hour, so a healthy host could report an unsynchronised clock. A clock now has to stay unsynchronised for 15 minutes, and is asked about every minute in the meantime.

Found by the tenth audit (2026-11-07), which asked what a compromised service's user, and an attacker outside, can do against vpsfort.

- The weekly abuse report is handed to the bots without writing through a link. The bot's user, who writes in the outbox too, could put a link under the predictable temporary name and have root write the report into, and give it, any file the unit may write. The file is now made by `mktemp` under a random name, given to the bot only once it is root's own, and a directory under the final name is reported, not written into.
- Messages for the admin bot are signed in their names: `alert-<time>-<n>-<signature>.msg`, the keyed hash of name and text under root's `/var/lib/vpsfort/botbox.key` (made at the first start). The fallback sends a file plain only when its signature matches; a file the bot's user put under one of vpsfort's names is deleted instead, with a high `system` alert. Messages written before the upgrade go out as before; `notify-test --bot` uses the same key. The bots match `alert-*.msg` as before.
- A login excuses only so much. An address that authenticated to a service was never banned for failures on that service, so anyone with an account there could guess the others' passwords from the same address, unbanned. `[allowlist] trust_limit` (4) bans it anyway at that many ban thresholds of points; 0 keeps the old behaviour. The ban's reason says "past what a login excuses".
- With firewalld and ufw, whose own rules accept established traffic before vpsfort's, a ban now also ends the address's open connections (`conntrack -D --orig-src`; the path in `[enforce] conntrack`): a brute force over one kept-alive HTTP or IMAP connection went on until that connection closed. Without conntrack-tools, a warning at start says so. nftables and iptables needed nothing: they drop whatever the connection's state.
- journald's own word that it dropped a unit's lines for its rate limit (`Suppressed 1431 messages from sshd.service`, `Missed N kernel messages`) is read and raised as a `system` alert, high for a unit vpsfort reads: the logins and attacks in the dropped lines went unseen, which a flood of connections brings about. The alert names the fix.
- Changed-file scans run ClamAV and YARA in a transient service sandboxed like `vpsfort-avscan.service` (read-only but its cache, no network, no new privileges, reading the only capability). They ran as plain root: a hole in a scanner's parser, on a file an attacker planted where the integrity watches look, gave root.
- The README's new section "A compromised service" says what a service's user can and can't do to vpsfort.

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
