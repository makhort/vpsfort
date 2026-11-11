# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.7.2 - 2026-11-11

Installer hardening, after vpsfort's audit of 2026-11-10.

- `deploy.sh`: the command pasted into the root shell refuses a staging copy holding anything but regular files. A link left there by the SSH user passed the hash check through its target, which could be changed before `install.sh` ran as root (found by vpsfort's thirteenth audit, 2026-11-10).
- `scripts/ci.sh`: `VPSFORT_XMPP_BOT_SKIP_AUDIT=1` skips the licence check too, as its message says.

## 0.7.1 - 2026-11-08

Installer hardening, after vpsfort's audit of 2026-11-07.

- `install.sh` and the package's post-install step change the owner and mode of the bot's files (the state, the OMEMO store, `bot.log`, the trust list, the avatar, the OpenPGP key; the instances' too) only when they are regular files with one name. The directory is the bot's user's to write in, so a link planted under one of those names made root change the owner and mode of whatever it pointed at (found by vpsfort's audit of 2026-11-07). The other mode's files waiting in the outbox are given to the bot only when they have one name (`find -links 1`, `chown -h`), and the copy of `state.json` an upgrade keeps is made under a random name (`mktemp`), never through a link planted under the name made of the time.
- vpsfort's next release names its messages `alert-<time>-<n>-<signature>.msg`; the bot's matching (`alert-*.msg`) is unchanged.

## 0.7.0 - 2026-11-07

Several domains on one ejabberd.

- One admin bot per domain: `install.sh --instance <name>` sets up `vpsfort-xmpp-bot@<name>.service`, the same binary with its own config, state, OMEMO keys, outbox and log under `/opt/vpsfort-xmpp-bot/instances/<name>/` and `/var/log/vpsfort-xmpp-bot/<name>/`. Upgrades, rollbacks and the packages cover every instance; Alpine runs one as the link `vpsfort-xmpp-bot.<name>`.
- The admin may be an account on any domain of the server (read from `registered_vhosts` at the start), so one admin account runs all the bots; accounts on other servers still get no commands.
- A bot won't start (exit 78) on a state directory, OMEMO store or outbox that another running bot uses, and `install.sh` refuses two bots on one account or one directory.
- `/block_domain` refuses each of the server's domains, and `/online` lists only the bot's own domain's users.
- `config.env.example` leaves `BOT_STATE_PATH` and `LOG_DIR` to the defaults, which are the same as before.

## 0.6.1 - 2026-11-06

Fixes.

- The package's question whether to replace `config.env` is asked on the terminal itself, so it shows under dnf too: dnf held it back with the install's output, and the install looked hung for the question's minute before keeping the config.

## 0.6.0 - 2026-11-05

First public release.

- Delivers the daemon's alerts, digests and weekly abuse reports over XMPP, OMEMO-encrypted, to the admins; files as OpenPGP where OMEMO can't carry them.
- Admin mode answers the admins' commands; client mode copies another bot's outbox for relays and desktops.
- SCRAM-SHA-256-PLUS, direct TLS, a new client when a session can't be resumed, ban-safe reconnects.
- A first install on a clean host from the bundle's install.sh.
