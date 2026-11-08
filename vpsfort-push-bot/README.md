# vpsfort-push-bot

A send-only bot that brings vpsfort's admin messages (the alerts, the daily digest and the
weekly abuse report) to a push service you run or trust, or to any webhook:

- **ntfy** (<https://ntfy.sh>, or a server of your own): a message per alert, the report as
  an attachment;
- **Gotify** (a server of your own): a message per alert; it takes no attachments, so files
  stay on the server and the admin is told once a day;
- **a webhook**: a JSON `POST` per alert and per file, with a Bearer token.

None of these encrypts end to end: the service's server reads what the bot sends. So, as on
Telegram (`vpsfort-tg-bot`, whose code this bot shares), **account names become pseudonyms
and the servers appear only by their node ids**, and **files go out only OpenPGP-encrypted**
to the admin's key, or not at all. It does for push services what `vpsfort-tg-bot` does
for Telegram on vpsfort's side, through the same kind of outbox, and nothing else: it reads
nothing back, takes no orders for the servers, and runs as its own user
`vpsfort-push-bot`.

vpsfort feeds it only when `[notify] push_outbox` is set. Without it, nothing changes. It
can run next to the other bots, on any node; on a relay node (vpsfort's
`deploy/vpsfort-tg.toml`), the XMPP server never connects to the service.

## Contents

1. [What it sends](#what-it-sends)
2. [What the service sees](#what-the-service-sees)
3. [How vpsfort and the bot meet](#how-vpsfort-and-the-bot-meet)
4. [Install from a release bundle](#install-from-a-release-bundle)
5. [Install from a package](#install-from-a-package)
6. [Setup](#setup)
7. [Settings](#settings)
8. [Retention and what the bot keeps](#retention-and-what-the-bot-keeps)
9. [Build and test](#build-and-test)

## What it sends

| From vpsfort | ntfy | Gotify | webhook |
|---|---|---|---|
| an alert or the digest (`alert-*.msg`) | a message: the subject as the title, the text as the message; longer ones in pieces of 4000 characters (the later ones marked "continued"); the priority from vpsfort's severity (`[High]` 4, `[Critical]` 5) | the same, priorities 8 and 10 | `{"kind": "alert", "subject", "text", "priority"}` |
| the weekly abuse report (`abuse-report-<date>.txt`), or any other file | a `PUT` with the file encrypted to `OPENPGP_KEY`, named `report-<date>.txt.pgp`, a fixed caption | not sent: the file waits on the server, a message once a day says so | `{"kind": "file", "name", "caption", "content_base64"}` (encrypted) |
| alerts older than `ALERT_MAX_HOURS` (24) when the bot gets to them | dropped, and one message says how many | | |
| an alert the service refuses for good (400, 413, ...) | dropped with a note, so it can't hold up the alerts after it | | |

A refused token (401, 403) stops the bot with exit 78, which the unit doesn't restart: fix
`PUSH_TOKEN` and start it again. Rate limits (429 with `Retry-After`) and an unreachable
service hold the alerts in the outbox and try again.

## What the service sees

- **Account names never reach it.** Every XMPP address in an alert (`alice@example.org`,
  `ejabberd:alice`) becomes a pseudonym `[acct:1a2b3c]`: an HMAC under `pseudonym.key`, made
  on the first start and kept on the server (`vpsfort-push-bot pseudonym <address>` there
  tells which account is which). The same account always gets the same pseudonym.
- **The servers appear by their node ids** (`SERVER_NAMES`): their own addresses and host
  names in alerts become `xmpp`, `vpn`, ... (`nextcloud.example.org:443` becomes
  `nextcloud.xmpp:443`). Attackers' addresses, ports, countries and networks stay: that is
  what the alert is about.
- **Files go out encrypted as a whole** (OpenPGP, `OPENPGP_KEY`: a v4 RSA or Curve25519 key
  as OpenKeychain and iPGMail export it, SEIPD v1 with AES-256, no name inside): the
  service holds a file of some size and a neutral name. Open it on the phone with
  OpenKeychain (Android) or iPGMail (iPhone). Without a key, files wait and expire unsent.
- **The topic is the secret, on ntfy.** Whoever knows a topic's name reads it: pick a long
  random one, and on ntfy.sh or any server with access control give the bot an access token
  (`ntfy token add`) and keep the topic private. Gotify needs an application token; a webhook
  gets a Bearer token.
- Every request is HTTPS (plain HTTP only to localhost). Redirects are never followed: one
  would carry the message and the token elsewhere.

## How vpsfort and the bot meet

They share one directory, `/opt/vpsfort-push-bot/outbox` (root:vpsfort-push-bot 1770,
sticky), in vpsfort-xmpp-bot's file format (vpsfort's `src/botbox.rs`, the shared
`vpsfort-botlib`'s `outbox`): vpsfort writes a copy of each message to the first of
`[notify] admins` (every admin message when `admins` is empty or `xmpp = false`) as
`alert-<time>-<n>-<signature>.msg` (the signature is for vpsfort's own check, not the bot's); the bot looks every 5 seconds, claims one by renaming it to
`.<name>.sending`, sends it and deletes it, or renames it back to try again. The abuse
report job puts the weekly report there too when `[notify] push_outbox` (or
`ABUSE_REPORT_PUSH_OUTBOX`) is set; the bot looks every minute. There is no fallback on
vpsfort's side: vpsfort warns the admins its other ways when copies wait longer than
`bot_stuck_after`.

Check it as root: `vpsfort -c /etc/vpsfort/vpsfort.toml notify-test --push`.

## Install from a release bundle

As for the other crates (see vpsfort-tg-bot's README, "Install from a release bundle"): the
tag is `vpsfort-push-bot-v<version>`, the zip `vpsfort-push-bot-<version>-<commit>-<arch>.zip`;
unzip it on the server and run `sudo ./install.sh`. The first install doesn't start the bot:
continue with "Setup".

## Install from a package

The same release has a package per architecture, for the distribution's package manager instead of `install.sh`: `vpsfort-push-bot_<version>-1_<arch>.deb` (`amd64`, `arm64`, `armhf`; Debian, Ubuntu and their derivatives) `vpsfort-push-bot-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`, `armv7hl`; Fedora, RHEL and its rebuilds) and `vpsfort-push-bot-<version>-r0.<arch>.apk` (`x86_64`, `aarch64`, `armv7`; Alpine, with OpenRC: below), each with its `.sha256` and `.sigstore.json`, downloaded and verified as the bundle above (`--pattern "*.deb*"`, `"*.rpm*"` or `"*.apk*"`). CI keeps them for every commit as workflow artifacts, and `scripts/package.sh` builds them locally (`cargo install cargo-deb cargo-generate-rpm --locked` once, and python3 for the `.apk`, which `scripts/apk.py` at the repository's root writes; none needs dpkg, rpm or apk-tools, so it runs on macOS too; `--target aarch64-unknown-linux-musl` or `armv7-unknown-linux-musleabihf` for the ARM ones). Or from the signed apt and dnf repository on GitHub Pages, once it is set up (the repository README, "Deployment"), where `apt upgrade` and `dnf upgrade` then bring new versions.

```bash
sudo apt install ./vpsfort-push-bot_0.2.2-1_amd64.deb     # Fedora, RHEL:  sudo dnf install ./vpsfort-push-bot-0.2.2-1.x86_64.rpm
sudoedit /opt/vpsfort-push-bot/config.env                 # the first install put the template there
sudo systemctl enable --now vpsfort-push-bot
```

The package puts the same files in the same places as `install.sh` (`/opt/vpsfort-push-bot` with the binary and `config.env.example`, the user `vpsfort-push-bot`, `/var/log/vpsfort-push-bot`, the logrotate rule), except the unit, which is in `/usr/lib/systemd/system`. Its post-install step does what `install.sh` does apart from copying files: the user, `config.env` from the template the first time, the owners and modes, the outbox and the log directory; and it prints what is left to do ("Setup"). `dpkg-reconfigure vpsfort-push-bot` (rpm: `dnf reinstall ./vpsfort-push-bot-*.rpm`) runs that step again, e.g. after copying a key there. `apt remove vpsfort-push-bot` (`dnf remove`) stops the bot and keeps `/opt/vpsfort-push-bot`; `apt purge vpsfort-push-bot` removes it with the keys (rpm: by hand).

**Nothing starts on its own.** The first install puts the template in place and prints what to fill in; you enable the service once it is filled in. An upgrade keeps the config and restarts the service only if it was running and the config is filled in. **Over a bundle or `deploy.sh` install** the package takes over: the config and keys stay; the bundle's unit in `/etc/systemd/system` (it would shadow the package's) and its rollback files go, and the service is enabled again on the package's unit if it was (vpsfort's integrity watch reports the removed unit as a warning once). **Replacing the config:** when a terminal is there, the install asks whether to replace the config with the new template (the old one kept with the suffix `.old`); Enter, a timeout of a minute, no terminal or `DEBIAN_FRONTEND=noninteractive` keep it. `VPSFORT_PACKAGE_CONFIG=replace` (or `keep`) answers without asking. **Rollback** is installing the previous version's package (`apt install ./<old>.deb --allow-downgrades`, `dnf downgrade ./<old>.rpm`): there is no `.prev` file.

**Alpine (apk, OpenRC):** `apk add --allow-untrusted ./vpsfort-push-bot-<version>-r0.x86_64.apk` puts the same files in the same places, with the OpenRC script `/etc/init.d/vpsfort-push-bot` instead of the unit: the settings exported from `config.env` as `EnvironmentFile=` does, supervised by `supervise-daemon` and started again 5 seconds after a crash; systemd's sandboxing has no equivalent there. The package is unsigned, hence `--allow-untrusted`: `sha256sum -c` and the attestation verify it. Its install scripts are POSIX sh and do what the post-install step above does: the user, `config.env` from the template the first time, the owners and modes, the log directory; an upgrade restarts a running bot. Then `rc-update add vpsfort-push-bot default && rc-service vpsfort-push-bot start`. `apk del vpsfort-push-bot` stops it and keeps `/opt/vpsfort-push-bot`. Not yet run on an Alpine host: CI installs the package in an Alpine container.

## Setup

1. **The service.** ntfy: a topic with a long random name on your server or ntfy.sh, and
   an access token for the bot (`ntfy token add`, or a user and password). Gotify: an
   application (its token). A webhook: an HTTPS endpoint that takes a JSON `POST`.
2. **Deploy** from the Mac (runs `scripts/ci.sh` first, builds the static binary):
   ```bash
   ./deploy/deploy.sh          # to the relay node "tg"; name another host as the argument
   ```
   The first install creates the user, `/opt/vpsfort-push-bot` and `config.env` (from
   `deploy/config.env.example`, every option with a reasonable value). It doesn't start the
   bot while `PUSH_URL` is the placeholder.
3. **Fill in `config.env`** as root: `PUSH_KIND`, `PUSH_URL`, `PUSH_TOKEN` (or
   `PUSH_TOKEN_FILE`), `SERVER_NAMES`, `XMPP_DOMAINS`, and your OpenPGP public key as
   `OPENPGP_KEY` (`/opt/vpsfort-push-bot/admin.asc`, root:vpsfort-push-bot 640; as for
   vpsfort-tg-bot). Then:
   ```bash
   set -a; . /opt/vpsfort-push-bot/config.env; set +a
   /opt/vpsfort-push-bot/vpsfort-push-bot check        # the settings, the key, the outbox; sends nothing
   /opt/vpsfort-push-bot/vpsfort-push-bot send-test    # one test message to the service
   systemctl enable --now vpsfort-push-bot              # or: bash /opt/vpsfort-push-bot/install.sh again
   ```
4. **Tell vpsfort**, in `[notify]` of `/etc/vpsfort/vpsfort.toml` (deploy a vpsfort that
   knows the key first):
   ```toml
   push_outbox = "/opt/vpsfort-push-bot/outbox"
   push_user = "vpsfort-push-bot"
   ```
   then `systemctl restart vpsfort` and `vpsfort -c /etc/vpsfort/vpsfort.toml notify-test --push`.
   Adding `vpsfort-push-bot.service` to vpsfort's `[sources] services` gets an alert when it
   fails. On a server with ejabberd, leaving `admins` empty sends admin messages to the copy
   bots only (users are still warned over XMPP).

`install.sh rollback` goes back to the previous binary and unit. The host needs outgoing
HTTPS to the service; the service sees the host's address.

## Settings

All in `config.env` (`deploy/config.env.example` has each with a comment;
`vpsfort-push-bot --help` lists the matching flags):

| Variable | Default | |
|---|---|---|
| `PUSH_KIND` | `ntfy` | `ntfy`, `gotify` or `webhook` |
| `PUSH_URL` | | ntfy: the topic's URL; Gotify: the server's URL; webhook: the URL to POST to. https, or http to localhost |
| `PUSH_TOKEN` / `PUSH_TOKEN_FILE` | | ntfy: an access token (or the password of `PUSH_USER`); Gotify: the application token; webhook: a Bearer token. Empty: none |
| `PUSH_USER` | | ntfy with a user and password: the user |
| `XMPP_DOMAINS` | | a bare user name in an alert counts as on the first one |
| `SERVER_NAMES` | | `node=address,...,name; ...`: replaced by the node id in alerts |
| `OPENPGP_KEY` | | the admin's OpenPGP public key; files go out encrypted to it, or not at all |
| `ALERT_MAX_HOURS` | 24 | older alerts are dropped unsent |
| `OUTBOX_MAX_DAYS` | 7 | older files are deleted unsent |
| `OUTBOX_DIR` | `/opt/vpsfort-push-bot/outbox` | |
| `PSEUDONYM_KEY` | `/opt/vpsfort-push-bot/pseudonym.key` | |
| `LOG_DIR` | `/var/log/vpsfort-push-bot` | `bot.log`, 14 days |

Exit status 78 (the service refused the token, or a setting is wrong) is not restarted by the
unit. Fix `config.env` and start it again.

## Retention and what the bot keeps

- **On the service:** messages stay as the service keeps them (ntfy's cache, 12 hours by
  default on ntfy.sh; Gotify's database until deleted in the app; a webhook's own).
- **On the server:** `bot.log` (14 days: weekly rotation, one old copy), `pseudonym.key`, and
  outbox files until they are sent (or expire). No state file: nothing the bot sends is
  written anywhere else on the server.

| Path | Owner | Mode |
|---|---|---|
| `/opt/vpsfort-push-bot/` | root:vpsfort-push-bot | 1770 (sticky) |
| `config.env` (the token), `OPENPGP_KEY` | root:vpsfort-push-bot | 640 |
| `pseudonym.key` | vpsfort-push-bot | 600 |
| `outbox/` | root:vpsfort-push-bot | 1770; files vpsfort-push-bot 600 |
| `/var/log/vpsfort-push-bot/`, `bot.log` | vpsfort-push-bot | 700, 600 |

The unit is hardened like vpsfort-tg-bot's: no capabilities, a read-only system but its two
directories, IPv4 and IPv6 sockets only, no writable-executable memory, and 128 MB of memory
at most (`MemoryMax`).

## Build and test

```bash
./scripts/ci.sh            # fmt, clippy, tests, cargo audit, cargo deny, static Linux binary
```

The static build needs `rustup target add x86_64-unknown-linux-musl` (or the ARM targets) and
`rustup component add llvm-tools`, as the other crates. The outbox, the pseudonyms and server
names, the OpenPGP files and the log come from `../vpsfort-botlib`, shared with the Telegram,
mail, Signal and Matrix bots. `tests/fake_push.rs` runs the bot against a fake ntfy, Gotify
and webhook on 127.0.0.1: an alert with account names and server addresses replaced and its
priority, the report held back without a key and then sent encrypted (nothing of it in the
request, the admin's key opens it), a rate limit (429 `Retry-After`), a refused token
stopping the bot, a request refused for good dropped with a note, Gotify's once-a-day note
about files. `tests/gpg_interop.rs` decrypts the files with GnuPG when `gpg` is installed.
**Not yet tried against a real ntfy, Gotify or webhook.**

**Fuzzing.** `fuzz/` has three cargo-fuzz targets (code in `src/fuzzing.rs`): `alert_text`
(an outbox file to the message pieces: no account address, no server address or host name
left, pieces within the limits), `openpgp_key` (the key file: whatever is taken must encrypt,
with nothing in clear) and `server_names`. `tests/fuzz_smoke.rs` runs them on stable over
realistic inputs, the seeds in `fuzz/seeds/` and thousands of mutations
(`VPSFORT_PUSH_BOT_WRITE_SEEDS=1 cargo test --test fuzz_smoke` regenerates the seeds). The
real search needs nightly:

```bash
rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz --locked   # once
cargo +nightly fuzz run alert_text fuzz/corpus/alert_text fuzz/seeds/alert_text -- -max_total_time=600
```
