# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.2.2 - 2026-11-08

Installer hardening, after vpsfort's audit of 2026-11-07.

- `install.sh` and the package's post-install step change the owner and mode of the bot's files (the pseudonym key, `bot.log`, the admin's OpenPGP key) only when they are regular files with one name. The directory is the bot's user's to write in, so a link planted under one of those names made root change the owner and mode of whatever it pointed at (found by vpsfort's audit of 2026-11-07).
- vpsfort's next release names its messages `alert-<time>-<n>-<signature>.msg`; the bot's matching (`alert-*.msg`) is unchanged.

## 0.2.1 - 2026-11-06

Fixes.

- The package's question whether to replace `config.env` is asked on the terminal itself, so it shows under dnf too: dnf held it back with the install's output, and the install looked hung for the question's minute before keeping the config.

## 0.2.0 - 2026-11-05

First public release.

- Delivers the daemon's alerts and digests to ntfy, Gotify or a webhook, sanitized; files go OpenPGP-encrypted.
- Built on the shared bot library (vpsfort-botlib), like the other bots.
