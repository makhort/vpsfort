# vpsfort-signal-bot

A Signal bot that brings vpsfort's admin messages to the admin's Signal account: the alerts,
the daily digest and the weekly abuse report. Signal encrypts every message end to end; the
bot adds a check that the other end is still the admin (the **safety number**), and when it
isn't, sends only files encrypted to the admin's OpenPGP key, or nothing. It does for Signal
what `vpsfort-tg-bot` does for Telegram on vpsfort's side, through the same kind of outbox:

- **A client only.** It uses an account of its own on Signal's servers through
  [signal-cli](https://github.com/AsamK/signal-cli), which it runs as its child process. No
  server runs here, nothing listens.
- **Send only.** It reads nothing people send it: no commands. The servers are managed over SSH.
- **No link to ejabberd.** It runs as its own user `vpsfort-signal-bot`.

vpsfort feeds it only when `[notify] signal_outbox` is set. Without it, nothing changes. It
can run next to the other bots, on any node; on the relay node (vpsfort's
`deploy/vpsfort-tg.toml`) the XMPP server never connects to Signal.

## Contents

1. [Why signal-cli](#why-signal-cli)
2. [What it sends](#what-it-sends)
3. [The safety number](#the-safety-number)
4. [How vpsfort and the bot meet](#how-vpsfort-and-the-bot-meet)
5. [signal-cli](#signal-cli)
6. [Install from a release bundle](#install-from-a-release-bundle)
7. [Install from a package](#install-from-a-package)
8. [Setup](#setup)
9. [Settings](#settings)
10. [Retention and what the bot keeps](#retention-and-what-the-bot-keeps)
11. [Build and test](#build-and-test)

## Why signal-cli

Signal's protocol libraries (libsignal, and presage on top of it) are AGPL-3.0, and Signal's
service (registration, sealed sender, its key servers) can't reasonably be reimplemented from
specifications, as vpsfort-xmpp-bot's OMEMO was. So the bot, which stays MIT, talks to
signal-cli (GPL-3.0, a separate program) over its JSON-RPC interface (`signal-cli jsonRpc` on
stdin and stdout, `src/rpc.rs`), and signal-cli does the Signal protocol. The bot holds no
Signal keys itself; signal-cli keeps them in its data directory (`SIGNAL_CLI_DATA`, the bot's
user only, mode 700).

## What it sends

| From vpsfort | In Signal |
|---|---|
| alerts, the daily digest | a message, the subject (first line) in bold |
| the weekly abuse report | an attachment (`abuse-report-<date>.txt`) |
| either, while the safety number isn't the pinned one | an attachment `message-<time>.txt.pgp` / `report-<time>.txt.pgp` encrypted to `OPENPGP_KEY`, with a neutral caption, and once a day a short message saying why |

With `SANITIZE=yes` alerts and digests also lose XMPP account names (pseudonyms) and the
servers' addresses (node ids), as on Telegram; off by default, since they are end-to-end
encrypted.

## The safety number

The first time the bot writes to the admin, it sends a message without content
(`vpsfort-signal-bot: connected...`): that makes the Signal session, so signal-cli knows the
admin's identity key before anything real goes out. The bot then **pins the safety number**
(the number the Signal app shows under the chat's "View safety number") in `state.json`, or
takes it from `ADMIN_SAFETY_NUMBER`, and logs it: compare it with your app.

Before each message it asks signal-cli for the admin's current identity:

- **the pinned safety number:** the message goes as a Signal message. If signal-cli had marked
  the identity untrusted (after a change you then confirmed with `ADMIN_SAFETY_NUMBER`), the
  bot tells signal-cli it is verified first.
- **another one** (you reinstalled Signal or changed phones, or someone took over your
  number): nothing readable goes to the new identity. The bot tells signal-cli to accept the
  new key for transport only, and sends each message and file as an attachment encrypted to
  `OPENPGP_KEY`, with one notice a day naming both safety numbers. Without `OPENPGP_KEY`,
  messages wait (alerts for `ALERT_MAX_HOURS`, files for `OUTBOX_MAX_DAYS`). It stays so until
  you check the new safety number in the app, set `ADMIN_SAFETY_NUMBER` to it in `config.env`
  and restart the bot.

The OpenPGP files are v4 / SEIPD v1 with AES-256 (what OpenKeychain on Android and iPGMail on
iPhone read), with a neutral name and caption.

## How vpsfort and the bot meet

They share one directory, `/opt/vpsfort-signal-bot/outbox` (root:vpsfort-signal-bot 1770,
sticky), in vpsfort-xmpp-bot's file format (`src/outbox.rs`, vpsfort's `src/botbox.rs`):
vpsfort writes a copy of each message to the first of `[notify] admins` (every admin message
when `admins` is empty or `xmpp = false`) as `alert-<time>-<n>.msg`; the bot looks every 5
seconds, claims one by renaming it to `.<name>.sending`, sends it and deletes it, or renames it
back to try again (30 s later; 5 minutes after Signal's rate limit). The abuse report job puts
the weekly report there too when `[notify] signal_outbox` (or `ABUSE_REPORT_SIGNAL_OUTBOX`) is
set; the bot looks every minute. There is no fallback on vpsfort's side: vpsfort warns the
admins its other ways when copies wait longer than `bot_stuck_after`.

Check it as root: `vpsfort -c /etc/vpsfort/vpsfort.toml notify-test --signal`.

## signal-cli

Install a current signal-cli on the node (Signal stops accepting old clients after a few
months: keep it updated). From its [releases](https://github.com/AsamK/signal-cli/releases):

- **x86_64:** the native build, `signal-cli-<version>-Linux-native.tar.gz`: one binary, no
  Java. Put it at `/usr/local/bin/signal-cli`.
- **ARM (aarch64, armv7):** the Java build, `signal-cli-<version>.tar.gz`, needs Java 21 or
  later and libsignal's native library for the architecture (signal-cli's wiki, "Provide
  native lib for libsignal"); point `SIGNAL_CLI` at its `bin/signal-cli`.

The unit allows writable-executable memory for the Java build's JIT (unlike the other bots'
units) and 1 GB of memory (`MemoryMax`; the other bots get 128 MB); otherwise it is hardened
the same way.

## Install from a release bundle

As for the other crates (see vpsfort-tg-bot's README, "Install from a release bundle"): the
tag is `vpsfort-signal-bot-v<version>`, the zip `vpsfort-signal-bot-<version>-<commit>-<arch>.zip`;
unzip it on the server and run `sudo ./install.sh`. The first install doesn't start the bot:
continue with step 3 below.

## Install from a package

The same release has a package per architecture, for the distribution's package manager instead of `install.sh`: `vpsfort-signal-bot_<version>-1_<arch>.deb` (`amd64`, `arm64`, `armhf`; Debian, Ubuntu and their derivatives) `vpsfort-signal-bot-<version>-1.<arch>.rpm` (`x86_64`, `aarch64`, `armv7hl`; Fedora, RHEL and its rebuilds) and `vpsfort-signal-bot-<version>-r0.<arch>.apk` (`x86_64`, `aarch64`, `armv7`; Alpine, with OpenRC: below), each with its `.sha256` and `.sigstore.json`, downloaded and verified as the bundle above (`--pattern "*.deb*"`, `"*.rpm*"` or `"*.apk*"`). CI keeps them for every commit as workflow artifacts, and `scripts/package.sh` builds them locally (`cargo install cargo-deb cargo-generate-rpm --locked` once, and python3 for the `.apk`, which `scripts/apk.py` at the repository's root writes; none needs dpkg, rpm or apk-tools, so it runs on macOS too; `--target aarch64-unknown-linux-musl` or `armv7-unknown-linux-musleabihf` for the ARM ones). Or from the signed apt and dnf repository on GitHub Pages, once it is set up (the repository README, "Deployment"), where `apt upgrade` and `dnf upgrade` then bring new versions.

```bash
sudo apt install ./vpsfort-signal-bot_0.3.0-1_amd64.deb     # Fedora, RHEL:  sudo dnf install ./vpsfort-signal-bot-0.3.0-1.x86_64.rpm
sudoedit /opt/vpsfort-signal-bot/config.env                 # the first install put the template there
sudo systemctl enable --now vpsfort-signal-bot
```

The package puts the same files in the same places as `install.sh` (`/opt/vpsfort-signal-bot` with the binary and `config.env.example`, the user `vpsfort-signal-bot`, `/var/log/vpsfort-signal-bot`, the logrotate rule), except the unit, which is in `/usr/lib/systemd/system`. Its post-install step does what `install.sh` does apart from copying files: the user, `config.env` from the template the first time, the owners and modes, the outbox and the log directory; and it prints what is left to do ("Setup": the numbers, your OpenPGP key, then signal-cli's registration as the bot's user (the install prints the commands; signal-cli itself is installed separately)). `dpkg-reconfigure vpsfort-signal-bot` (rpm: `dnf reinstall ./vpsfort-signal-bot-*.rpm`) runs that step again, e.g. after copying a key there. `apt remove vpsfort-signal-bot` (`dnf remove`) stops the bot and keeps `/opt/vpsfort-signal-bot`; `apt purge vpsfort-signal-bot` removes it with the state and keys (rpm: by hand).

**Nothing starts on its own.** The first install puts the template in place and prints what to fill in; you enable the service once it is filled in. An upgrade keeps the config and restarts the service only if it was running and the config is filled in. **Over a bundle or `deploy.sh` install** the package takes over: the config, state and keys stay; the bundle's unit in `/etc/systemd/system` (it would shadow the package's) and its rollback files go, and the service is enabled again on the package's unit if it was (vpsfort's integrity watch reports the removed unit as a warning once). **Replacing the config:** when a terminal is there, the install asks whether to replace the config with the new template (the old one kept with the suffix `.old`); Enter, a timeout of a minute, no terminal or `DEBIAN_FRONTEND=noninteractive` keep it. `VPSFORT_PACKAGE_CONFIG=replace` (or `keep`) answers without asking: `sudo VPSFORT_PACKAGE_CONFIG=replace apt install ./<file>.deb`. **Rollback** is installing the previous version's package (`apt install ./<old>.deb --allow-downgrades`, `dnf downgrade ./<old>.rpm`): there is no `.prev` file.

**Alpine (apk, OpenRC):** `apk add --allow-untrusted ./vpsfort-signal-bot-<version>-r0.x86_64.apk` puts the same files in the same places, with the OpenRC script `/etc/init.d/vpsfort-signal-bot` instead of the unit: the settings exported from `config.env` as `EnvironmentFile=` does, supervised by `supervise-daemon` and started again 5 seconds after a crash; systemd's sandboxing has no equivalent there. The package is unsigned, hence `--allow-untrusted`: `sha256sum -c` and the attestation verify it. Its install scripts are POSIX sh and do what the post-install step above does: the user, `config.env` from the template the first time, the owners and modes, the log directory; an upgrade restarts a running bot. Then `rc-update add vpsfort-signal-bot default && rc-service vpsfort-signal-bot start`. `apk del vpsfort-signal-bot` stops it and keeps `/opt/vpsfort-signal-bot`. Not yet run on an Alpine host: CI installs the package in an Alpine container.

## Setup

1. **A phone number for the bot** that can receive one SMS or call (not your own Signal
   number), or a Signal account of its own on a phone to link signal-cli to. Install
   signal-cli (above).
2. **Deploy** from the Mac (runs `scripts/ci.sh` first, builds the static binary):
   ```bash
   ./deploy/deploy.sh          # to the relay node "tg"; name another host as the argument
   ```
   The first install creates the user, `/opt/vpsfort-signal-bot` (with signal-cli's data
   directory) and `config.env`.
3. **Fill in `config.env`** as root (`SIGNAL_ACCOUNT`, `ADMIN`, your OpenPGP public key as
   `OPENPGP_KEY`, root:vpsfort-signal-bot 640) and run `bash install.sh` again. It prints the
   commands for the next step with the settings filled in. Register the bot's number, as the
   bot's user (the `signal-cli` subcommand runs signal-cli with the bot's data directory and
   account):
   ```bash
   runuser -u vpsfort-signal-bot -- env SIGNAL_ACCOUNT=+49... /opt/vpsfort-signal-bot/vpsfort-signal-bot signal-cli register --captcha 'signalcaptcha://...'
   runuser -u vpsfort-signal-bot -- env SIGNAL_ACCOUNT=+49... /opt/vpsfort-signal-bot/vpsfort-signal-bot signal-cli verify 123456
   ```
   The captcha token comes from <https://signalcaptchas.org/registration/generate.html>
   (signal-cli's wiki, "Registration with captcha"). Or link signal-cli as a device of the
   bot's own Signal account: `... signal-cli link -n vpsfort` prints a `sgnl://` link to open
   as a QR code (`qrencode -t ansiutf8 '<link>'`) in that account's app, under Linked devices.
   Optionally `... signal-cli updateProfile --given-name vpsfort`. Then
   `systemctl enable --now vpsfort-signal-bot` (or `bash install.sh` again).
4. **Check the safety number**: the first message pins it (`pinned the safety number` in
   `/var/log/vpsfort-signal-bot/bot.log`); compare it with the one your app shows for the
   bot's chat, or set `ADMIN_SAFETY_NUMBER` before the first message.
5. **Tell vpsfort**, in `[notify]` of `/etc/vpsfort/vpsfort.toml` (deploy a vpsfort that
   knows the key first):
   ```toml
   signal_outbox = "/opt/vpsfort-signal-bot/outbox"
   signal_user = "vpsfort-signal-bot"
   ```
   then `systemctl restart vpsfort` and `vpsfort ... notify-test --signal`. Adding
   `vpsfort-signal-bot.service` to vpsfort's `[sources] services` gets an alert when it fails.

`install.sh rollback` goes back to the previous binary and unit. Signal sees the host's
address; the host needs outgoing HTTPS to Signal's servers.

## Settings

All in `config.env` (`deploy/config.env.example` has each with a comment; `--help` lists the
matching flags):

| Variable | Default | |
|---|---|---|
| `SIGNAL_CLI` | `/usr/local/bin/signal-cli` | the program |
| `SIGNAL_CLI_DATA` | `/opt/vpsfort-signal-bot/signal-cli` | its data directory (700) |
| `SIGNAL_CLI_ARGS` | `--ignore-attachments --ignore-stories` | more arguments for `jsonRpc` |
| `SIGNAL_ACCOUNT` | | the bot's number |
| `ADMIN` | | your number or ACI: the only one the bot writes to |
| `ADMIN_SAFETY_NUMBER` | (pinned on first sight) | the safety number with you |
| `OPENPGP_KEY` | | your OpenPGP public key, for the fallback; without it messages wait |
| `SANITIZE` | no | yes: pseudonyms and node ids in alerts (`XMPP_DOMAINS`, `SERVER_NAMES`, `PSEUDONYM_KEY`) |
| `ALERT_MAX_HOURS` | 24 | older alerts are dropped unsent |
| `OUTBOX_MAX_DAYS` | 7 | older files are deleted unsent |
| `BOT_STATE_PATH` | `/opt/vpsfort-signal-bot/state.json` | |
| `OUTBOX_DIR` | `outbox` next to the state | |
| `LOG_DIR` | `/var/log/vpsfort-signal-bot` | `bot.log`, 14 days (signal-cli's own lines included) |

Exit status 78 (a setting is wrong, or signal-cli didn't start: the account isn't registered,
an option it doesn't know) is not restarted by the unit; the log has signal-cli's last lines.
When signal-cli stops later, the bot stops with exit 1 and systemd starts both again.

## Retention and what the bot keeps

- **On Signal:** messages stay in the chat until deleted (Signal's disappearing messages, set
  in your app for the chat, apply to the bot's messages too).
- **On the server:** `bot.log` (14 days), `state.json` (the pinned safety number), signal-cli's
  data directory (the account's keys and sessions, its contacts; signal-cli keeps no message
  history, and receives with attachments ignored), with
  `SANITIZE` the pseudonym key, and outbox files until they are sent or expire.

| Path | Owner | Mode |
|---|---|---|
| `/opt/vpsfort-signal-bot/` | root:vpsfort-signal-bot | 1770 (sticky) |
| `config.env`, `OPENPGP_KEY` | root:vpsfort-signal-bot | 640 |
| `state.json`, `pseudonym.key` | vpsfort-signal-bot | 600 |
| `signal-cli/` | vpsfort-signal-bot | 700 |
| `outbox/` | root:vpsfort-signal-bot | 1770; files vpsfort-signal-bot 600 |
| `/var/log/vpsfort-signal-bot/`, `bot.log` | vpsfort-signal-bot | 700, 600 |

## Build and test

```bash
./scripts/ci.sh            # fmt, clippy, tests, cargo audit, static Linux binary
```

The static build needs `rustup target add x86_64-unknown-linux-musl` (or the ARM targets) and
`rustup component add llvm-tools`, as the other crates. `tests/fake_signal_cli.rs` runs the
bot against a fake signal-cli on a pipe that keeps identities and trust as signal-cli does:
the first message without content, the safety number pinned, an alert with a bold subject, the
report as an attachment, a changed identity (nothing sent without an OpenPGP key; with one,
signal-cli told to accept the key, a notice, and files the admin's key opens, nothing readable
in any request), the new safety number confirmed with `ADMIN_SAFETY_NUMBER` (signal-cli
verifies it, messages again), Signal's rate limit, messages to the bot ignored, and signal-cli
going away. `src/cli.rs`'s tests start a program that exits at once and check its words reach
the error.

**Not yet tried with a real signal-cli or Signal account.** The JSON-RPC calls follow
signal-cli's documentation (`man signal-cli-jsonrpc`); `send`'s `textStyle` and `data:`
attachments need signal-cli 0.12 or later.

**Fuzzing.** `fuzz/` has cargo-fuzz targets (code in `src/fuzzing.rs`): `cli_line` (signal-cli's
output lines as replies to `send` and `listIdentities`: a safety number is always 60 digits)
and `alert_file` (outbox files). `tests/fuzz_smoke.rs` runs them on stable over realistic
inputs, `fuzz/seeds/` and thousands of mutations (`VPSFORT_SIGNAL_BOT_WRITE_SEEDS=1`
regenerates the seeds).

```bash
cargo +nightly fuzz run cli_line fuzz/corpus/cli_line fuzz/seeds/cli_line -- -max_total_time=600
```
