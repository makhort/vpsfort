# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.8.0 - 2026-11-11

A second day on a honeypot node: IMAP answers `CAPABILITY`, RPC probes show the method they call, the honeypot template opens 37 more ports. Then the fixes of two audits (the honeypots and what another user on the same host can do to vpsfort; a re-read of the whole of vpsfort) and of a re-read of the parsers. Defaults that change: `openvpn_hmac` and `openvpn_tls` score 0, `[[ratelimit]]` counts IPv6 sources per /64, and a login from inside a subnet shields it from a subnet ban only up to twice what a ban needs.

- A honeypot's IMAP prompt answers `CAPABILITY` as Dovecot does, with the list its greeting shows and the client's tag, and reads one more line for the login. The connection used to close there, so fingerprintx took the port for something other than IMAP, and a client that asks before it logs in (curl does) never got to its login.
- `AUTH TLS` and `AUTH SSL` are no longer called a Redis command in a honeypot's evidence: they are how an FTP client asks for TLS.
- A NetBIOS session request, the opening on port 139 before SMB, is named in a honeypot's evidence.
- An HTTP request to a honeypot port with a JSON-RPC body shows the method it calls (`sent HTTP request "POST / HTTP/1.1" calling "eth_accounts" ...`): on a cryptocurrency node's RPC port the request line says nothing else.
- A first byte of 0xFF no longer makes a capture "Telnet option negotiation" unless a Telnet command follows it: DVRs on port 34567 open the same way.
- The honeypot node template listens on 37 more ports, chosen from what five nodes' firewalls saw: SIP, DVRs and cameras, more VNC displays, LDAPS, CouchDB, Solr, etcd, AI services and cryptocurrency nodes. With sshd that is 100 open ports, about as many as one host should show.
- Process watch leaves out vpsfort's own connections. A connection to a cluster peer that a scan happened to catch warned of a "new outbound connection" from vpsfort. Another program that takes the name is still reported.
- journald's notice of the lines it dropped (`Suppressed 1431 messages from sshd.service`) was never read on a live host: vpsfort took it for a line of the system manager's and asked for PID 1, which journald isn't. It is now told by journald's own transport (`driver`), which also keeps a local user's `logger -t systemd-journald` from raising the alert.
- A Telnet honeypot held a subnegotiation that never ended for as long as the client kept sending, going through all of it again at every read: a few dozen such connections cost megabytes each, of a service limited to 128 MB, and a processor for ten seconds. One longer than 256 bytes is now text, which the capture bounds.
- The copies of running programs made for the scanners take at most four times `scan_max_mb` per scan in all: 200 programs of 100 MB each, which any user can start from `/tmp`, would have been 20 GB on the state's disk. Copies left by a scan that vpsfort was stopped in are removed at the next one, and the list of the files being scanned is root's alone (0600).
- `/var/lib/vpsfort` is mode 0700 and `/var/log/vpsfort` 0750 under systemd (as the state directory was on Alpine, whose log directory follows): the scan results and the lists of scanned files were readable by every local user.
- firewalld's entry files are written in the control socket's directory, root's own, not in `/tmp`: without systemd's private `/tmp` (OpenRC) another user could take a file's predictable name first and make the batch fail.
- The README's "A compromised service" says what a local user without a service can and can't do.
- A followed log's line longer than 64 KB was cut, and what followed in it was then read as a line of its own: text a client chose (a path, a user agent), in a log whose lines ban addresses. The reader's position now moves past the whole line, and the rest of one still being written is dropped when it comes.
- The SSH audit opened what sshd is told to read in a user's home (`authorized_keys`) as any file: a pipe there held the audit forever, a link to a terminal made it the daemon's own. It opens regular files only, without blocking, as the cron watch does.
- With `[cluster] share` holding `log_digests`, the previous day's actions log was read, hashed and sent to the peers again every minute, all day: the day remembered was compared with the wrong date. Once a day now, and a failed attempt waits an hour.
- A forged SYN to a `ufw limit` port no longer counts against an address that is logged in (it could be banned past `trust_limit` that way): `[UFW LIMIT BLOCK]` is treated as the other blocked packets are.
- Out-of-memory alerts are one an hour per program, for eight programs an hour, and one for all the others: a local user who makes the kernel kill processes of names of their own choosing got a High alert per kill, each remembered for eight days. Facts refused for their signature are one alert a day per peer they came through, not per name written in them.
- Bounds where someone else decides how much there is: the addresses remembered for the ban ladder (200,000, those banned longest ago go first), the addresses trusted after a login (100,000), a blocklist's lines (500,000 read) and a WAF source's decisions (250,000) while they are read and not after, a watched pattern's matches in a directory of a user's (10,000, counted as they come), the entries of a bot's outbox one sweep reads (10,000), a honeypot port's memory of recent sources (2,000) and of what one hit sent (what was read, not the capture's whole room). A peer's report about an address written as `::ffff:10.0.0.5` is judged as 10.0.0.5, and doesn't add an address to a full table.
- A bot's files stuck in its outbox are reported in one message, once an hour at most (the bot's user decides how many there are; each was a High message to every admin), and the files the cron watch can't read are named three at a time, the rest in one message.
- The console and control sockets read a command within 3 seconds in all (a client sending a byte at a time held everyone else's commands), and a report from the actions log is counted until its answer is written (a client that didn't read its answers could start any number of them).
- After `firewall-cmd --reload` the blocklists and the WAF list are loaded again with the bans, not at their next refresh (a day later by default). A rule with `tcp flags != syn` or a `meter` is no longer read as closing a port (exposure watch).
- A fallback to plain frames with a peer that doesn't answer key exchanges (`forward_secrecy = "prefer"`) ends after ten minutes as documented: each delivery used to start it anew, so one dropped answer left that peer without forward secrecy for good.
- `nan` and `inf` are refused as thresholds and weights, a ladder step of 0 and a duration beyond 100 years given as a number too. The digest's event counts are right after a restart (they stayed at zero until the new process had counted past the old one's totals). `log-digest` reads rotated copies by their number (`.10.gz` before `.9.gz`). A program vpsfort stops for taking too long is stopped with what it started. `verify` knows the push bot's outbox.
- `deploy.sh` and `rotate-cluster-key.sh`: the command pasted into the root shell refuses a staging copy holding anything but regular files. A link left there by the SSH user passed the hash check through its target, which could be changed before `install.sh` ran as root.
- The package's `postinst` enables the units again when the config is replaced by the template during a takeover of a bundle install (the daemon was gone after the next reboot). `vpsfort-avscan` writes its log with awk (BusyBox's sed has no `-u`) and asks systemctl only where there is one; the abuse report's unit may write the push bot's outbox, and a directory planted under a leftover's name no longer stops the report. `scripts/ci.sh` stops at a bundled config that doesn't parse.
- **OpenVPN: `openvpn_hmac` and `openvpn_tls` score 0 by default** (they were 40 and 20). An OpenVPN server usually listens on UDP, where one packet with any source address its sender writes makes each of these lines: three packets banned whatever address they named. They are still counted (the Patterns tab); a server on TCP gives them points with `[sources.app_weights]`.
- ProFTPD's failed logins are counted against the address in brackets, not the name before it: that name is what the address resolves to, the client's own DNS, and a name made of digits read as another address. An Exim relay refusal whose HELO name reads like the rest of the line (possible with `helo_accept_junk_hosts`) counts against nobody instead of the address written there.
- A login from inside a subnet keeps it from a subnet ban only until it shows twice what a ban needs (six bad addresses by default): one account, where anyone can register one, and one login kept a whole /64 or /24 of attacking addresses open. A subnet whose ban ended is banned again for what comes from it after that, not for the scores its addresses still have: each such ban was a step up the ladder without one new line.
- The "possible compromise" alert is raised for an address that is trusted for the service too, unless the account has logged in from its network before: the login that earned the trust may have been to an account of the attacker's own.
- An address remembers 8 accounts as the targets of its failed logins, names of 64 bytes at most (32 of 200 characters each, for every address of a botnet, were more than the service's memory). A ban put back when a wider one ends isn't, if its address is allowlisted, a peer's or this host's by then.
- Cluster: facts are sent, and applied, in the order they were made (after a full sync a restarted node could apply a ban after the unban that had lifted it); one node's relayed messages take half of the hour's at most, so the others' still go out; a peer's log digest is kept for a day that is over and at most 8 days back, and a node not heard of doesn't push out a known one's.
- An unban the firewall program refused is tried again like any other change (with nftables any failure counted as "already gone", and the address stayed banned in the kernel). After one answer slower than 10 seconds the changes of the next half minute wait for the retry, which itself takes 30 seconds a round at most: a firewall program that hangs used to hold the main loop for its timeout per change, until the watchdog restarted the daemon.
- `[[ratelimit]]` counts IPv6 sources per /64 (a host with a /64 had a new allowance with every address it picked); an nft that doesn't take that rule gets the per-address ones as before, and vpsfort says so.
- Exposure watch: ufw rules for one interface, for one of the host's addresses, for `Anywhere` and for the common app profiles (`OpenSSH`, `Nginx Full`, ...) are read (ports they open showed as blocked), iptables-save's long form of `--syn` (`--tcp-flags FIN,SYN,RST,ACK SYN`) is a new connection, and a DROP for one destination address closes nothing for the others.
- The set-uid search reads at most 500,000 entries of directories that aren't root's alone (users' and shared ones) and the rest in full: millions of files in `/tmp` or a home stopped it before `/usr`, and the programs it hadn't reached counted as gone. A search that stops keeps what was known.
- A scan of changed files whose scanner failed says so in its own line, and a file without a finding isn't "clean" then. A program's path is judged whole (a deleted program with a path longer than 300 characters wasn't reported), and runc's memory copy is excused for root only.
- Log lines waiting for the main loop are bounded by their size (24 MB), those held back at start too; the cron and integrity watch scans every five seconds at most, however often a user touches a watched directory; patterns' matches are counted as they are read here as well.
- `vpsfort allow` for a network that is allowed already sets its new end (nftables kept the old one: the entry is replaced now).
- A name in `[procwatch] ignore_processes` counts for a program whose file is root's and writable by root alone. A process names itself, so anything a user started under a listed name (`backup`, `firefox`) went unreported, connections and odd programs alike.
- The cron and integrity watch keeps a file's hash under the identity of the file it read, taken from the open file: a user who swapped the directory above their script while it was scanned had another file's hash kept for it, and the script in place wasn't read again.
- The set-uid search says so (and keeps what it knew) when it leaves the rest of one huge directory of a user's out, not only when it reaches the next one.
- README: PostgreSQL's `log_hostname` stays off for `[sources] apps = ["postgresql"]`.
- `[[ratelimit]]`: a source's entry ends a minute after its last connection (a rate per second), ten minutes (per minute) or two hours (per hour), where nft takes the rule (1.0.2 with kernel 5.15 and 1.1.3 with 6.12 do, IPv6 by /64 included). All entries used to last two hours, so 65,536 forged sources left a limit off for everyone new for that long.
- The process watch asks conntrack (where conntrack-tools is installed) who opened a connection from a port that also listens: a program listening on a port can connect out from it, and those connections counted as its clients'.
- The ufw backend compares the deny rules carrying vpsfort's comment with the bans it holds, at start: a ban ufw had refused was never put in after a restart, and an unban it had refused left the address denied for good.
- With the firewalld backend, a whitelisted port that firewalld doesn't open to everyone is a `system` warning: vpsfort's zone accepts it from banned addresses, so it was open to them and closed to the rest.
- The log says about how much memory the loaded geo database takes; one that takes more than half of the unit's limit is a `system` warning.
- An unban of an address the kernel has already let go is done, whichever way nft says so: "element does not exist" is how it answers for the ban sets, not only the kernel's "No such file or directory". With the retry of refused unbans above, such an unban would have been tried again every 30 seconds with a high alert. Found by CI's run against a real kernel.
- rustix 1.1.6, for RUSTSEC-2026-0486 (its xattr functions, which vpsfort doesn't call). The layout tests give each daemon a cluster port below the range the kernel hands out: one asked from the kernel could be taken again before the daemon bound it, which failed a test now and then.

## 0.7.8 - 2026-11-09

What a day on a honeypot node showed: VNC and MySQL prompts, a real FTP refusal, more openings named.

- A honeypot's POP3 prompt refuses what it doesn't know, as a real server does: after anything but `USER` it answers Dovecot's `-ERR Unknown command.` instead of `+OK`. fingerprintx, which the honeypot node's visitors run, sends a bogus command and takes a port for POP3 only if `-ERR` comes back, so `+OK` to anything marked the port as not being what it claimed.
- An LDAP bind is named whatever the size of its message ID: fingerprintx's 4-byte ID left one as raw bytes.
- Two more honeypot prompts for clients that wait for the server, after a day on a honeypot node where half the VNC and four of five MySQL connections sat silent. `vnc` sends the `RFB 003.008` version line and keeps the client's. `mysql` sends a server's first packet (by default Debian 12's MariaDB; `honeypot_banners` names another version), with a new salt and connection number each time and no offer of TLS, and the evidence names the account the client logs in as.
- A honeypot's FTP prompt refuses what comes before a login with vsftpd's `530 Please login with USER and PASS.`: only `USER` gets the `331` that brings out the password. `AUTH TLS` was answered `331`, which no vsftpd does.
- More openings are named in a honeypot's evidence: an RDP connection request without a cookie (every TPKT request seen on 3389 was one), lowercase `info` and `ping` to Redis, a DCE/RPC bind, a FastCGI request and a MikroTik Winbox request.
- The honeypot node template shows prompts on 587 (SMTP), 3306 (MySQL), 5900 and 5901 (VNC) as well.

## 0.7.7 - 2026-11-09

The honeypot hits for the console, from the actions log.

- The console socket answers `honeypots 24h` and `honeypots 7d`: the bans this node decided on a hit on a honeypot port or the decoy site, from the actions log and its rotated copies (the newest 10,000), without the peers' copies. The web console's Honeypots tab reads them: it could only see the latest decisions kept in memory, of which a restart leaves 100, about two hours of a honeypot node's.

## 0.7.6 - 2026-11-09

What the honeypot node's first Telnet connections showed.

- The Telnet greeting opens the way a telnetd does, with its option negotiation (`IAC DO ECHO`, `IAC DO NAWS`, `IAC WILL ECHO`, `IAC WILL SGA`, as BusyBox sends them) before the issue line and `login:`: nine of the first ten Telnet connections to a honeypot node sat silent at a greeting without it, since a bot waits for that exchange before it reads for a prompt. The bot's own negotiation replies are left out of the evidence, which keeps the login it types.

## 0.7.5 - 2026-11-09

A fix found on the honeypot node's peers.

- Evidence shared with the peers and quoted in the abuse report keeps a honeypot's captured bytes: a word holding an `@` is withheld as an account only when it looks like one (`alice@example.org`), not when it is a quoted capture, whose `\xfeSMB@` turned a whole SMB2 negotiate into `[account]` on the peers.

## 0.7.4 - 2026-11-09

Fixes found on the Fedora node and the honeypot node.

- A reply to a honeypot's prompts that isn't text is read whole, not to a line end: a scanner that answered the FTP greeting with a TLS client hello was kept to the first 0x0a byte inside it (96 of 271 bytes). Such a reply is named like a plain capture: `answered the ftp prompts with a TLS client hello (271 bytes): "..."`.
- A program running from a temporary or deleted file is scanned from a copy vpsfort makes of it, not from `/proc/<pid>/exe` itself. Following that link takes ptrace access to the process, which vpsfort has and the scanners' sandbox hasn't, so every such scan ended in `YARA: could not open file` (ClamAV read it through `clamd` alone, not through `clamscan`). The copy also stays when the process exits while ClamAV runs; a process gone before the scan starts reads `not scanned: the process has exited`. The scan's record counts a file no scanner could read as not scanned (`scanned 0 of 1 changed files`).

## 0.7.3 - 2026-11-09

Found on the honeypot node's first night.

- A honeypot's capture is named by its protocol before the bytes, for the openings scanners send: `sent an SMB2 negotiate (178 bytes): "\x00\x00\x00\xae\xfeSMB..."`, an MS SQL pre-login, a TLS client hello, an RDP connection request, PostgreSQL, MongoDB, Redis, memcached, SOCKS, MQTT, AMQP, ADB, Modbus, LDAP, RPC, Oracle, PPTP, VNC, SIP, Java RMI, an SSH client banner. Recognised by each protocol's fixed opening bytes; nothing is answered. (Found on the honeypot node, where a night's evidence was hex to decode by hand.)

## 0.7.2 - 2026-11-09

Found on the first dedicated honeypot node.

- The exposure watch reads ufw rules that name several ports (`ufw allow 21,22,23/tcp`, ranges inside a list too), and rules whose target is wider than `ufw status`'s column, where one space is left before the action. Each port of such a rule is a rule of its own in the Exposure tab, named with its list (`ALLOW 2323/tcp (of 21,22,23,25,110,143,2222,2323/tcp)`), and a dead one is named the same way. Before, every honeypot opened with one such rule showed as "blocked by ufw", and `ALLOW OUT` rules passed for incoming ones.
- The README's nginx decoy recipe removes Debian's default site (a second `default_server` on port 80 fails `nginx -t`), makes the certificate's directory, and reloads nginx, which creates `decoy.log` at once.
- A config template for a dedicated honeypot node, `vpsfort-honeypot.toml` (`install.sh --template honeypot`; a `-dnf` variant too): 55 honeypot ports with their prompts and the ufw rules that open them, the decoy site's log, enforce mode from the start, a `7d`/`30d` ban ladder, the blocklist feeds and country blocking off (a honeypot wants the bad networks to connect), and the `peer_accept` line for the other nodes.
- The decoy site's evidence starts at the request (`decoy_request: "GET / HTTP/1.1" 404 181 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."`): the address and time, which the ban has anyway, no longer use up the 120 characters before the user agent. Any `[[patterns]]` regex can do the same with a group named `show`. The abuse report describes such bans as requests to our decoy web site.

## 0.7.1 - 2026-11-08

A fix found on the servers during the upgrade to 0.7.0.

- A node that restarts no longer delivers its peers' alerts and digests a second time. What a node has seen lived only in memory, and the peers resend what they hold at every full sync, for `notice_ttl` (a day), so an upgrade flooded the bot chat with the last day's messages (`[node1] vpsfort daily digest (relayed 14h33m late)`). The notices delivered are now kept in the state file. Those that came while the node was down are still delivered, late, as before. A new node takes the notices created since its first start, and the first start after this upgrade those since the old version last saved its state.

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
