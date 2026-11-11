# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.5.3 - 2026-11-11

Installer hardening, after vpsfort's audit of 2026-11-10.

- `deploy.sh`: the command pasted into the root shell refuses a staging copy holding anything but regular files. A link left there by the SSH user passed the hash check through its target, which could be changed before `install.sh` ran as root (found by vpsfort's thirteenth audit, 2026-11-10).
- `scripts/ci.sh`: `VPSFORT_TG_BOT_SKIP_AUDIT=1` skips the licence check too, as its message says.

## 0.5.2 - 2026-11-08

Installer hardening, after vpsfort's audit of 2026-11-07.

- `install.sh` and the package's post-install step change the owner and mode of the bot's files (the state, the pseudonym key, `bot.log`, the admin's OpenPGP key) only when they are regular files with one name. The directory is the bot's user's to write in, so a link planted under one of those names made root change the owner and mode of whatever it pointed at (found by vpsfort's audit of 2026-11-07).
- vpsfort's next release names its messages `alert-<time>-<n>-<signature>.msg`; the bot's matching (`alert-*.msg`) is unchanged.

## 0.5.1 - 2026-11-06

Fixes.

- The package's question whether to replace `config.env` is asked on the terminal itself, so it shows under dnf too: dnf held it back with the install's output, and the install looked hung for the question's minute before keeping the config.

## 0.5.0 - 2026-11-05

First public release.

- Delivers the daemon's alerts, digests and weekly abuse reports to Telegram, pseudonymized: accounts, addresses and names never leave the host in the clear; files go OpenPGP-encrypted.
- Sanitizing repeats until nothing changes, so nested or overlapping matches can't leak.
- Runs on a relay node of its own, as its own system user.
