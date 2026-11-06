# Changelog

Each release's section is what its GitHub Release shows; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.2.1 - 2026-11-06

Fixes.

- The package's question whether to replace `config.env` is asked on the terminal itself, so it shows under dnf too: dnf held it back with the install's output, and the install looked hung for the question's minute before keeping the config.

## 0.2.0 - 2026-11-05

First public release.

- Delivers the daemon's alerts and digests to ntfy, Gotify or a webhook, sanitized; files go OpenPGP-encrypted.
- Built on the shared bot library (vpsfort-botlib), like the other bots.
